use anyhow::{anyhow, bail, Context, Result};
use bw_app_gate::cache::Cache;
use bw_app_gate::process::{self, app_label, Requester};
use bw_app_gate::prompt::Approval;
use bw_app_gate::secret_ref::SecretRef;
use bw_app_gate::vault::{self, SecretValue, UnlockError};
use bw_app_gate::{socket_path, Request, Response, MAX_REQUEST_BYTES, MAX_SECRETS_PER_REQUEST};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const USAGE: &str = "Usage: bw-app-gate-agent [--pinentry PROGRAM]";

/// Wrong master passwords accepted in one prompt before the request fails.
const PASSWORD_ATTEMPTS: usize = 3;

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

struct Agent {
    pinentry: String,
    cache: Mutex<Cache>,
    /// Held while a prompt is open, so only one dialog shows at a time. The cache lock is not held during the prompt.
    prompt: Mutex<()>,
}

/// Seconds on `CLOCK_BOOTTIME`, which unlike `Instant` keeps counting through suspend, so an idle timer also runs out while the machine sleeps.
fn now() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) };
    assert_eq!(result, 0, "CLOCK_BOOTTIME is unavailable");
    time.tv_sec as u64
}

impl Agent {
    async fn serve(
        &self,
        requester: &Requester,
        names: &[String],
    ) -> Result<Vec<Zeroizing<String>>> {
        if names.is_empty() || names.len() > MAX_SECRETS_PER_REQUEST {
            bail!("a request must name between 1 and {MAX_SECRETS_PER_REQUEST} secrets");
        }
        let secrets = names
            .iter()
            .map(|name| SecretRef::parse(name))
            .collect::<Result<Vec<_>>>()?;
        let instance = requester.instance;

        if self
            .cache
            .lock()
            .await
            .missing(instance, &secrets, now())
            .is_empty()
        {
            return self.read_cached(requester, &secrets).await;
        }

        let _prompt = self.prompt.lock().await;
        // Another request from the same instance may have filled the cache while this one waited for the prompt lock.
        let missing = self.cache.lock().await.missing(instance, &secrets, now());
        if !missing.is_empty() {
            let pinentry = self.pinentry.clone();
            let app = app_label(&requester.exe);
            let pid = instance.pid;
            let fetch_missing = missing.clone();
            let values = tokio::task::spawn_blocking(move || {
                approve_and_fetch(&Approval {
                    pinentry: &pinentry,
                    app: &app,
                    pid,
                    secrets: &fetch_missing,
                })
            })
            .await??;
            let mut cache = self.cache.lock().await;
            let now = now();
            for (secret, value) in missing.into_iter().zip(values) {
                cache.insert(instance, secret, value, now);
            }
        }
        self.read_cached(requester, &secrets).await
    }

    async fn read_cached(
        &self,
        requester: &Requester,
        secrets: &[SecretRef],
    ) -> Result<Vec<Zeroizing<String>>> {
        let mut cache = self.cache.lock().await;
        let now = now();
        secrets
            .iter()
            .map(|secret| {
                cache
                    .get(requester.instance, secret, now)
                    .ok_or_else(|| {
                        anyhow!("'{secret}' expired while the request was waiting; retry")
                    })?
                    .reveal()
            })
            .collect()
    }
}

/// Shows the prompt, unlocks the vault with the password and decrypts the secrets. Blocking: runs pinentry and the KDF.
fn approve_and_fetch(approval: &Approval) -> Result<Vec<SecretValue>> {
    let mut error = None;
    for _ in 0..PASSWORD_ATTEMPTS {
        let password = approval
            .ask(error)?
            .ok_or_else(|| anyhow!("denied by the user"))?;
        match vault::unlock(&password) {
            Ok(vault) => return vault.fetch(approval.secrets),
            Err(UnlockError::WrongPassword) => error = Some("Wrong master password"),
            Err(UnlockError::Other(error)) => return Err(error),
        }
    }
    bail!("wrong master password {PASSWORD_ATTEMPTS} times")
}

async fn read_request(stream: &mut UnixStream) -> Result<Request> {
    let mut line = Vec::new();
    let reader = BufReader::new(stream).take(MAX_REQUEST_BYTES as u64 + 1);
    tokio::pin!(reader);
    tokio::time::timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut line))
        .await
        .context("timed out reading the request")??;
    if line.len() > MAX_REQUEST_BYTES {
        bail!("request is longer than {MAX_REQUEST_BYTES} bytes");
    }
    serde_json::from_slice(&line).context("invalid request")
}

async fn handle_connection(agent: &Agent, mut stream: UnixStream) -> Result<()> {
    let credentials = stream.peer_cred()?;
    if credentials.uid() != unsafe { libc::getuid() } {
        bail!("connection from another user (uid {})", credentials.uid());
    }
    let peer_pid = credentials
        .pid()
        .ok_or_else(|| anyhow!("peer PID is unavailable"))?;

    let response = match process::find_requester(peer_pid as u32) {
        Ok(requester) => match read_request(&mut stream).await {
            Ok(request) => match agent.serve(&requester, &request.secrets).await {
                Ok(values) => {
                    Response::Secrets(values.iter().map(|value| value.to_string()).collect())
                }
                Err(error) => Response::Error(format!("{error:#}")),
            },
            Err(error) => Response::Error(format!("{error:#}")),
        },
        Err(error) => Response::Error(format!(
            "could not identify the requesting application: {error:#}"
        )),
    };

    let mut line = Zeroizing::new(serde_json::to_vec(&response)?);
    if let Response::Secrets(mut values) = response {
        values.iter_mut().for_each(zeroize::Zeroize::zeroize);
    }
    line.push(b'\n');
    stream.write_all(&line).await?;
    Ok(())
}

fn disable_tracing() -> Result<()> {
    const PR_SET_DUMPABLE: i32 = 4;
    if unsafe { libc::prctl(PR_SET_DUMPABLE, 0) } != 0 {
        bail!(
            "failed to disable debugger attachment: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Binds the socket, refusing to take it over from an agent that is still running.
fn bind_socket() -> Result<UnixListener> {
    let path = socket_path();
    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
        bail!(
            "another bw-app-gate-agent is already listening on {}",
            path.display()
        );
    }
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    // umask makes the socket 0600 from the moment it exists, with no window before set_permissions.
    let old_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(&path);
    unsafe { libc::umask(old_umask) };
    let listener = listener.with_context(|| format!("failed to bind {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn parse_args() -> Result<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok("pinentry".to_string()),
        [flag, program] if flag == "--pinentry" => Ok(program.clone()),
        [flag] if flag == "-h" || flag == "--help" => {
            println!("{USAGE}");
            std::process::exit(0);
        }
        _ => Err(anyhow!("{USAGE}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    disable_tracing()?;
    let pinentry = parse_args()?;
    let listener = bind_socket()?;
    let agent = Arc::new(Agent {
        pinentry,
        cache: Mutex::new(Cache::default()),
        prompt: Mutex::new(()),
    });

    let sweeper = agent.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            sweeper.cache.lock().await.sweep(now(), process::is_alive);
        }
    });

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    eprintln!("bw-app-gate-agent listening on {}", socket_path().display());
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let agent = agent.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(&agent, stream).await {
                        eprintln!("request failed: {error:#}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        }
    }
    let _ = std::fs::remove_file(socket_path());
    Ok(())
}
