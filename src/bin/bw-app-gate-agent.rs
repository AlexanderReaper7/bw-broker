use anyhow::{anyhow, Result};
use bw_app_gate::{
    cache_key, decrypt_secret_in_process, parent_executable, prompt_pinentry, session_salt,
    socket_path, GetSecretRequest, SecretResponse, DEFAULT_TTL_SECS,
};
use std::collections::{HashMap, HashSet};
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::Pid;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

struct CacheEntry {
    secret_value: String,
    expires_at: u64,
}

struct Policy {
    allowed: HashMap<String, HashSet<String>>,
}

impl Policy {
    fn from_specs(specs: &[String]) -> Result<Self> {
        let mut allowed = HashMap::new();
        for spec in specs {
            let (app_path, secret_name) = spec
                .split_once('=')
                .ok_or_else(|| anyhow!("policy must use APP_PATH=SECRET_NAME"))?;
            if app_path.is_empty() || secret_name.is_empty() {
                return Err(anyhow!("policy app path and secret name cannot be empty"));
            }
            allowed
                .entry(app_path.to_string())
                .or_insert_with(HashSet::new)
                .insert(secret_name.to_string());
        }
        Ok(Self { allowed })
    }

    fn allows(&self, app_path: &str, secret_name: &str) -> bool {
        self.allowed
            .get(app_path)
            .is_some_and(|secrets| secrets.contains(secret_name))
    }
}

struct DaemonState {
    policy: Policy,
    salt: [u8; 32],
    cache: HashMap<String, CacheEntry>,
}

fn disable_tracing() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        const PR_SET_DUMPABLE: i32 = 4;
        let ret = unsafe { libc::prctl(PR_SET_DUMPABLE, 0) };
        if ret != 0 {
            return Err(anyhow!(
                "failed to disable debugger attachment: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_allows_only_declared_app_secret_pairs() {
        let policy = Policy::from_specs(&[
            "/usr/bin/editor=api-token".to_string(),
            "/usr/bin/editor=db-password".to_string(),
        ])
        .expect("policy should parse");

        assert!(policy.allows("/usr/bin/editor", "api-token"));
        assert!(policy.allows("/usr/bin/editor", "db-password"));
        assert!(!policy.allows("/usr/bin/editor", "root-password"));
        assert!(!policy.allows("/usr/bin/browser", "api-token"));
    }

    #[test]
    fn policy_rejects_malformed_specs() {
        assert!(Policy::from_specs(&["/usr/bin/editor".to_string()]).is_err());
        assert!(Policy::from_specs(&["=api-token".to_string()]).is_err());
        assert!(Policy::from_specs(&["/usr/bin/editor=".to_string()]).is_err());
    }
}

async fn get_cached_secret(
    state: &mut DaemonState,
    app_path: &str,
    secret_name: &str,
) -> Result<String> {
    if !state.policy.allows(app_path, secret_name) {
        return Err(anyhow!(
            "application '{}' is not authorized for secret '{}'",
            app_path,
            secret_name
        ));
    }

    let key = cache_key(&state.salt, app_path, secret_name);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if let Some(entry) = state.cache.get(&key) {
        if entry.expires_at > now {
            return Ok(entry.secret_value.clone());
        }
    }

    let password = prompt_pinentry(app_path, secret_name)?;
    let secret_value = decrypt_secret_in_process(password, secret_name).await?;
    state.cache.insert(
        key,
        CacheEntry {
            secret_value: secret_value.clone(),
            expires_at: now + DEFAULT_TTL_SECS,
        },
    );
    Ok(secret_value)
}

async fn handle_connection(stream: UnixStream, state: Arc<Mutex<DaemonState>>) -> Result<()> {
    let peer_pid = stream
        .peer_cred()?
        .pid()
        .ok_or_else(|| anyhow!("peer PID is unavailable on this platform"))?;
    let app_path = parent_executable(Pid::from_u32(peer_pid as u32))?;
    let (reader, mut writer) = stream.into_split();
    let mut line = String::new();
    BufReader::new(reader).read_line(&mut line).await?;

    let response = match serde_json::from_str::<GetSecretRequest>(&line) {
        Ok(request) => {
            let mut state = state.lock().await;
            match get_cached_secret(&mut state, &app_path, &request.secret_name).await {
                Ok(secret_value) => SecretResponse {
                    secret_value: Some(secret_value),
                    error: None,
                },
                Err(error) => SecretResponse {
                    secret_value: None,
                    error: Some(error.to_string()),
                },
            }
        }
        Err(error) => SecretResponse {
            secret_value: None,
            error: Some(format!("invalid request: {error}")),
        },
    };

    writer
        .write_all(serde_json::to_string(&response)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    disable_tracing()?;
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "--allow" {
        eprintln!("Usage: bw-app-gate-agent --allow APP_PATH=SECRET_NAME [...]");
        std::process::exit(if args.len() < 3 { 1 } else { 0 });
    }

    let policy = Policy::from_specs(&args[2..].to_vec())?;
    let path = socket_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    let state = Arc::new(Mutex::new(DaemonState {
        policy,
        salt: session_salt()?,
        cache: HashMap::new(),
    }));

    eprintln!("bw-app-gate-agent listening on {}", path.display());
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(stream, state).await {
                        eprintln!("request failed: {error:#}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                let _ = fs::remove_file(&path);
                return Ok(());
            }
        }
    }
}
