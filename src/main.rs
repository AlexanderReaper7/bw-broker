use anyhow::{anyhow, Context, Result};
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, System};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    app_path: String,
    secret_name: String,
    secret_value: String,
    expires_at: u64,
}

fn get_cache_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/bw_app_gate.json"))
}

fn get_parent_app_info() -> Result<String> {
    let ppid = Pid::from_u32(unsafe { libc::getppid() } as u32);
    let mut sys = System::new();
    sys.refresh_processes();

    if let Some(process) = sys.process(ppid) {
        let exe_path = process
            .exe()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| process.name().to_string());
        Ok(exe_path)
    } else {
        Err(anyhow!("Failed to inspect calling process"))
    }
}

fn prompt_pinentry(app_path: &str, secret_name: &str) -> Result<String> {
    let mut input = PassphraseInput::with_binary("pinentry-gnome3")
        .context("Failed to initialize pinentry-gnome3")?;

    let description = format!(
        "Application '{}' requests secret '{}'",
        app_path, secret_name
    );
    input.with_title("Bitwarden Direct Gate");
    input.with_description(&description);
    input.with_prompt("Master Password:");

    input
        .interact()
        .map(|passphrase| passphrase.expose_secret().clone())
        .map_err(|error| anyhow!("Pinentry failed: {error}"))
}

fn session_salt() -> Result<[u8; 32]> {
    let mut salt = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut salt)?;
    Ok(salt)
}

fn cache_key(salt: &[u8], app_path: &str, secret_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(app_path.as_bytes());
    hasher.update(b":");
    hasher.update(secret_name.as_bytes());
    hex::encode(hasher.finalize())
}

async fn decrypt_secret_in_process(mut password: String, secret_name: &str) -> Result<String> {
    let cfg = rbw::config::Config::load()?;
    let email = cfg
        .email
        .as_deref()
        .ok_or_else(|| anyhow!("rbw config has no email"))?;
    let db = rbw::db::Db::load(&cfg.server_name(), email)?;
    let mut password_bytes = rbw::locked::Vec::new();
    password_bytes.extend(password.as_bytes().iter().copied());
    password.zeroize();

    let locked_password = rbw::locked::Password::new(password_bytes);
    let (master_key, organization_keys) = rbw::actions::unlock(
        email,
        &locked_password,
        db.kdf.ok_or_else(|| anyhow!("vault database has no KDF"))?,
        db.iterations
            .ok_or_else(|| anyhow!("vault database has no KDF iterations"))?,
        db.memory,
        db.parallelism,
        db.protected_key
            .as_deref()
            .ok_or_else(|| anyhow!("vault database has no protected key"))?,
        db.protected_private_key
            .as_deref()
            .ok_or_else(|| anyhow!("vault database has no protected private key"))?,
        &db.protected_org_keys,
    )?;

    let cipher = db
        .entries
        .into_iter()
        .find(|entry| {
            let base_key = entry
                .org_id
                .as_ref()
                .and_then(|org_id| organization_keys.get(org_id))
                .unwrap_or(&master_key);
            decrypt_entry_value(&entry.name, base_key, entry.key.as_deref())
                .map(|name| name == secret_name)
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow!("Secret '{}' not found in vault", secret_name))?;

    let base_key = cipher
        .org_id
        .as_ref()
        .and_then(|org_id| organization_keys.get(org_id))
        .unwrap_or(&master_key);
    let password_ciphertext = match cipher.data {
        rbw::db::EntryData::Login { password, .. } => password,
        _ => None,
    }
    .ok_or_else(|| anyhow!("No password entry on secret item"))?;

    decrypt_entry_value(&password_ciphertext, base_key, cipher.key.as_deref())
}

fn decrypt_entry_value(
    ciphertext: &str,
    base_key: &rbw::locked::Keys,
    entry_key: Option<&str>,
) -> Result<String> {
    let entry_key = entry_key
        .map(|ciphertext| {
            let cipher = rbw::cipherstring::CipherString::new(ciphertext)?;
            let key = cipher.decrypt_locked_symmetric(base_key)?;
            Ok::<_, anyhow::Error>(rbw::locked::Keys::new(key))
        })
        .transpose()?;
    let cipher = rbw::cipherstring::CipherString::new(ciphertext)?;
    let plaintext = cipher.decrypt_symmetric(base_key, entry_key.as_ref())?;
    Ok(String::from_utf8(plaintext)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || matches!(args[1].as_str(), "-h" | "--help") {
        eprintln!("Usage: bw-app-gate <secret_name> [ttl_seconds]");
        std::process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let secret_name = &args[1];
    let ttl_secs: u64 = args
        .get(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(900);
    let app_path = get_parent_app_info()?;
    let salt = session_salt()?;

    let cache_key = cache_key(&salt, &app_path, secret_name);

    let cache_path = get_cache_path();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut cache: HashMap<String, CacheEntry> = if cache_path.exists() {
        File::open(&cache_path)
            .ok()
            .and_then(|file| serde_json::from_reader(file).ok())
            .unwrap_or_default()
    } else {
        HashMap::new()
    };

    if let Some(entry) = cache.get(&cache_key) {
        if entry.expires_at > now {
            println!("{}", entry.secret_value);
            return Ok(());
        }
    }

    let password = prompt_pinentry(&app_path, secret_name)?;
    let secret_value = decrypt_secret_in_process(password, secret_name).await?;

    cache.insert(
        cache_key,
        CacheEntry {
            app_path,
            secret_name: secret_name.clone(),
            secret_value: secret_value.clone(),
            expires_at: now + ttl_secs,
        },
    );

    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(cache_path)
    {
        let _ = serde_json::to_writer(&mut file, &cache);
        let _ = file.flush();
    }

    println!("{}", secret_value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys(seed: u8) -> rbw::locked::Keys {
        let mut key_bytes = rbw::locked::Vec::new();
        key_bytes.extend(std::iter::repeat_n(seed, 64));
        rbw::locked::Keys::new(key_bytes)
    }

    #[test]
    fn cache_key_changes_with_session_salt() {
        let first = cache_key(&[1; 32], "/usr/bin/editor", "api-token");
        let second = cache_key(&[2; 32], "/usr/bin/editor", "api-token");

        assert_ne!(first, second);
    }

    #[test]
    fn cache_key_binds_caller_and_secret() {
        let salt = [7; 32];
        let caller_key = cache_key(&salt, "/usr/bin/editor", "api-token");
        let other_caller_key = cache_key(&salt, "/usr/bin/browser", "api-token");
        let other_secret_key = cache_key(&salt, "/usr/bin/editor", "db-password");

        assert_ne!(caller_key, other_caller_key);
        assert_ne!(caller_key, other_secret_key);
    }

    #[test]
    fn decrypt_entry_value_decrypts_direct_ciphertext() {
        let base_key = test_keys(11);
        let encrypted =
            rbw::cipherstring::CipherString::encrypt_symmetric(&base_key, b"plain secret")
                .expect("encryption should succeed")
                .to_string();

        let decrypted =
            decrypt_entry_value(&encrypted, &base_key, None).expect("decryption should succeed");

        assert_eq!(decrypted, "plain secret");
    }

    #[test]
    fn decrypt_entry_value_uses_entry_key() {
        let base_key = test_keys(13);
        let entry_key = test_keys(29);
        let mut entry_key_bytes = rbw::locked::Vec::new();
        entry_key_bytes.extend(
            entry_key
                .enc_key()
                .iter()
                .chain(entry_key.mac_key())
                .copied(),
        );
        let encrypted_entry_key =
            rbw::cipherstring::CipherString::encrypt_symmetric(&base_key, entry_key_bytes.data())
                .expect("entry key encryption should succeed")
                .to_string();
        let encrypted_value =
            rbw::cipherstring::CipherString::encrypt_symmetric(&entry_key, b"entry secret")
                .expect("value encryption should succeed")
                .to_string();

        let decrypted =
            decrypt_entry_value(&encrypted_value, &base_key, Some(&encrypted_entry_key))
                .expect("entry-key decryption should succeed");

        assert_eq!(decrypted, "entry secret");
    }
}
