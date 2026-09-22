use anyhow::{anyhow, Context, Result};
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use sysinfo::{Pid, System};
use zeroize::Zeroize;

pub const DEFAULT_TTL_SECS: u64 = 900;

#[derive(Deserialize, Serialize)]
pub struct GetSecretRequest {
    pub secret_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct SecretResponse {
    pub secret_value: Option<String>,
    pub error: Option<String>,
}

pub fn socket_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/run/user/{uid}/bw-app-gate.sock"))
}

pub fn process_executable(pid: Pid) -> Result<String> {
    let mut sys = System::new();
    sys.refresh_processes();

    if let Some(process) = sys.process(pid) {
        Ok(process
            .exe()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| process.name().to_string()))
    } else {
        Err(anyhow!("failed to inspect process"))
    }
}

pub fn parent_executable(pid: Pid) -> Result<String> {
    let mut sys = System::new();
    sys.refresh_processes();
    let process = sys
        .process(pid)
        .ok_or_else(|| anyhow!("failed to inspect client process"))?;
    let parent_pid = process
        .parent()
        .ok_or_else(|| anyhow!("failed to inspect client parent process"))?;
    process_executable(parent_pid)
}

pub fn prompt_pinentry(app_path: &str, secret_name: &str) -> Result<String> {
    let mut input = PassphraseInput::with_binary("pinentry-gnome3")
        .context("failed to initialize pinentry-gnome3")?;
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
        .map_err(|error| anyhow!("pinentry failed: {error}"))
}

pub fn session_salt() -> Result<[u8; 32]> {
    let mut salt = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut salt)?;
    Ok(salt)
}

pub fn cache_key(salt: &[u8], app_path: &str, secret_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(app_path.as_bytes());
    hasher.update(b":");
    hasher.update(secret_name.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn decrypt_secret_in_process(mut password: String, secret_name: &str) -> Result<String> {
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

    let entry = db
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
        .ok_or_else(|| anyhow!("secret '{}' not found in vault", secret_name))?;

    let base_key = entry
        .org_id
        .as_ref()
        .and_then(|org_id| organization_keys.get(org_id))
        .unwrap_or(&master_key);
    let password_ciphertext = match entry.data {
        rbw::db::EntryData::Login { password, .. } => password,
        _ => None,
    }
    .ok_or_else(|| anyhow!("no password entry on secret item"))?;

    decrypt_entry_value(&password_ciphertext, base_key, entry.key.as_deref())
}

pub fn decrypt_entry_value(
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
