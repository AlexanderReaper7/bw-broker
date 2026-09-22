//! Reading secrets from rbw's local vault copy.
//!
//! The vault is unlocked for one request and the keys are dropped with the `UnlockedVault`. Plaintext values stay in `rbw::locked::Vec`, which is mlocked and zeroed on drop.

use crate::secret_ref::{Field, SecretRef};
use anyhow::{anyhow, bail, Context, Result};
use rbw::cipherstring::CipherString;
use rbw::db::{Entry, EntryData};
use rbw::locked;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Capacity of `rbw::locked::Vec`. It is a fixed-size buffer and panics past this.
const LOCKED_CAPACITY: usize = 4096;

/// A decrypted value. A TOTP seed is kept as the seed, and each read turns it into the current code.
pub enum SecretValue {
    Plain(locked::Vec),
    TotpSeed(locked::Vec),
}

impl SecretValue {
    /// The text sent to the client. The returned copy is zeroed when dropped.
    pub fn reveal(&self) -> Result<Zeroizing<String>> {
        match self {
            Self::Plain(bytes) => Ok(Zeroizing::new(
                std::str::from_utf8(bytes.data())
                    .context("secret is not valid UTF-8")?
                    .to_string(),
            )),
            Self::TotpSeed(bytes) => totp_code(
                std::str::from_utf8(bytes.data()).context("TOTP seed is not valid UTF-8")?,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            ),
        }
    }
}

fn totp_code(seed: &str, unix_time: u64) -> Result<Zeroizing<String>> {
    let totp = if seed.starts_with("otpauth://") {
        totp_rs::Totp::from_url_unchecked(seed)
            .map_err(|error| anyhow!("invalid TOTP URL: {error}"))?
    } else if seed.starts_with("steam://") {
        bail!("Steam TOTP seeds are not supported");
    } else {
        let base32: Zeroizing<String> = Zeroizing::new(
            seed.chars()
                .filter(|c| !c.is_whitespace())
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let secret = totp_rs::Secret::try_from_base32(base32.as_str())
            .map_err(|error| anyhow!("invalid TOTP seed: {error}"))?;
        totp_rs::Builder::new()
            .with_secret(secret)
            .build_noncompliant()
    };
    Ok(Zeroizing::new(totp.generate(unix_time).to_string()))
}

pub struct UnlockedVault {
    entries: Vec<Entry>,
    master_key: locked::Keys,
    org_keys: std::collections::HashMap<String, locked::Keys>,
}

pub enum UnlockError {
    WrongPassword,
    Other(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for UnlockError {
    fn from(error: E) -> Self {
        Self::Other(error.into())
    }
}

/// Loads rbw's vault copy and derives the keys from the master password. This runs the account's KDF, which takes around a second.
pub fn unlock(password: &SecretString) -> Result<UnlockedVault, UnlockError> {
    let config = rbw::config::Config::load()
        .context("failed to load rbw config; run `rbw config set email ...`")?;
    let email = config
        .email
        .as_deref()
        .ok_or_else(|| anyhow!("rbw config has no email"))?;
    let db = rbw::db::Db::load(&config.server_name(), email)
        .context("failed to load rbw's vault copy; run `rbw login` and `rbw sync`")?;

    let mut password_bytes = locked::Vec::new();
    password_bytes.extend(password.expose_secret().bytes());
    let password = locked::Password::new(password_bytes);

    let unlocked = rbw::actions::unlock(
        email,
        &password,
        db.kdf.ok_or_else(|| anyhow!("vault copy has no KDF"))?,
        db.iterations
            .ok_or_else(|| anyhow!("vault copy has no KDF iterations"))?,
        db.memory,
        db.parallelism,
        db.protected_key
            .as_deref()
            .ok_or_else(|| anyhow!("vault copy has no protected key"))?,
        db.protected_private_key
            .as_deref()
            .ok_or_else(|| anyhow!("vault copy has no protected private key"))?,
        &db.protected_org_keys,
    );
    let (master_key, org_keys) = match unlocked {
        Ok(keys) => keys,
        Err(rbw::error::Error::IncorrectPassword { .. }) => return Err(UnlockError::WrongPassword),
        Err(error) => return Err(error.into()),
    };
    Ok(UnlockedVault {
        entries: db.entries,
        master_key,
        org_keys,
    })
}

impl UnlockedVault {
    /// Decrypts every requested secret. Fails as a whole if any one is missing.
    pub fn fetch(&self, secrets: &[SecretRef]) -> Result<Vec<SecretValue>> {
        secrets
            .iter()
            .map(|secret| self.fetch_one(secret))
            .collect()
    }

    fn fetch_one(&self, secret: &SecretRef) -> Result<SecretValue> {
        let entry = self.find_entry(&secret.item)?;
        let keys = self.entry_keys(entry)?;
        let missing = || {
            anyhow!(
                "item '{}' has no {}",
                secret.item,
                field_description(&secret.field)
            )
        };

        let ciphertext = match (&secret.field, &entry.data) {
            (Field::Password, EntryData::Login { password, .. }) => password.as_deref(),
            (Field::Username, EntryData::Login { username, .. })
            | (Field::Username, EntryData::Identity { username, .. }) => username.as_deref(),
            (Field::Totp, EntryData::Login { totp, .. }) => totp.as_deref(),
            (Field::Notes, _) => entry.notes.as_deref(),
            (Field::Custom(name), _) => self.custom_field(entry, &keys, name)?,
            _ => None,
        }
        .ok_or_else(missing)?;

        let value = decrypt_locked(ciphertext, &keys)?;
        Ok(match secret.field {
            Field::Totp => SecretValue::TotpSeed(value),
            _ => SecretValue::Plain(value),
        })
    }

    fn find_entry(&self, item: &str) -> Result<&Entry> {
        let mut matches = self.entries.iter().filter(|entry| {
            self.entry_keys(entry)
                .and_then(|keys| decrypt_plain(&entry.name, &keys))
                .is_ok_and(|name| name == item)
        });
        let entry = matches.next().ok_or_else(|| {
            anyhow!("no item named '{item}' in the vault copy; run `rbw sync` if it is new")
        })?;
        if matches.next().is_some() {
            bail!("more than one item is named '{item}'; rename one so the name is unique");
        }
        Ok(entry)
    }

    fn custom_field<'a>(
        &self,
        entry: &'a Entry,
        keys: &locked::Keys,
        name: &str,
    ) -> Result<Option<&'a str>> {
        let mut matches = entry.fields.iter().filter(|field| {
            field
                .name
                .as_deref()
                .is_some_and(|ciphertext| decrypt_plain(ciphertext, keys).is_ok_and(|n| n == name))
        });
        let Some(field) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            bail!("item has more than one field named '{name}'");
        }
        if field.linked_id.is_some() {
            bail!("field '{name}' is a linked field, which is not supported");
        }
        Ok(field.value.as_deref())
    }

    /// The key that decrypts an entry's values: its own key if it has one, else its organization's or the account's.
    fn entry_keys(&self, entry: &Entry) -> Result<locked::Keys> {
        let base = entry
            .org_id
            .as_ref()
            .and_then(|org_id| self.org_keys.get(org_id))
            .unwrap_or(&self.master_key);
        match entry.key.as_deref() {
            Some(entry_key) => Ok(locked::Keys::new(
                CipherString::new(entry_key)?.decrypt_locked_symmetric(base)?,
            )),
            None => Ok(base.clone()),
        }
    }
}

fn field_description(field: &Field) -> String {
    match field {
        Field::Password => "login password".into(),
        Field::Username => "username".into(),
        Field::Notes => "notes".into(),
        Field::Totp => "TOTP seed".into(),
        Field::Custom(name) => format!("field '{name}'"),
    }
}

/// Decrypts non-secret metadata such as item and field names into ordinary memory.
fn decrypt_plain(ciphertext: &str, keys: &locked::Keys) -> Result<String> {
    let plaintext = CipherString::new(ciphertext)?.decrypt_symmetric(keys, None)?;
    Ok(String::from_utf8(plaintext)?)
}

/// Decrypts a secret value into locked memory.
///
/// `decrypt_locked_symmetric` decrypts in place and leaves the PKCS#7 padding bytes in the buffer, so they are cut here. rbw has already checked the padding, so the last byte is a valid pad length.
pub fn decrypt_locked(ciphertext: &str, keys: &locked::Keys) -> Result<locked::Vec> {
    let cipher = CipherString::new(ciphertext)?;
    if let CipherString::Symmetric { ciphertext, .. } = &cipher {
        if ciphertext.len() > LOCKED_CAPACITY {
            bail!(
                "value is {} bytes; at most {LOCKED_CAPACITY} are supported",
                ciphertext.len()
            );
        }
    }
    let mut value = cipher.decrypt_locked_symmetric(keys)?;
    let padding = value.data().last().copied().map_or(0, usize::from);
    let length = value.data().len().saturating_sub(padding);
    value.truncate(length);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys(seed: u8) -> locked::Keys {
        let mut bytes = locked::Vec::new();
        bytes.extend(std::iter::repeat_n(seed, 64));
        locked::Keys::new(bytes)
    }

    fn encrypt(keys: &locked::Keys, plaintext: &[u8]) -> String {
        CipherString::encrypt_symmetric(keys, plaintext)
            .expect("encryption should succeed")
            .to_string()
    }

    #[test]
    fn decrypt_locked_strips_padding() {
        let keys = test_keys(11);
        // 16 bytes gets a full block of padding, 5 bytes gets 11.
        for plaintext in [&b"exactly 16 bytes"[..], b"short", b""] {
            let value = decrypt_locked(&encrypt(&keys, plaintext), &keys).expect("should decrypt");
            assert_eq!(value.data(), plaintext);
        }
    }

    #[test]
    fn decrypt_locked_rejects_oversized_values() {
        let keys = test_keys(11);
        let error = decrypt_locked(&encrypt(&keys, &[b'x'; 5000]), &keys)
            .err()
            .expect("should fail");
        assert!(error.to_string().contains("at most 4096"), "{error}");
    }

    #[test]
    fn entry_key_is_used_when_present() {
        let base = test_keys(13);
        let entry_key = test_keys(29);
        let encrypted_entry_key =
            encrypt(&base, &[entry_key.enc_key(), entry_key.mac_key()].concat());
        let vault = UnlockedVault {
            entries: vec![],
            master_key: base,
            org_keys: Default::default(),
        };
        let entry = Entry {
            id: "id".into(),
            org_id: None,
            folder: None,
            folder_id: None,
            name: encrypt(&entry_key, b"api"),
            data: EntryData::Login {
                username: None,
                password: Some(encrypt(&entry_key, b"hunter2")),
                totp: None,
                uris: vec![],
            },
            fields: vec![],
            notes: None,
            history: vec![],
            key: Some(encrypted_entry_key),
            master_password_reprompt: rbw::api::CipherRepromptType::None,
        };
        let vault = UnlockedVault {
            entries: vec![entry],
            ..vault
        };
        let values = vault
            .fetch(&[SecretRef::parse("api").unwrap()])
            .expect("should fetch");
        assert_eq!(values[0].reveal().unwrap().as_str(), "hunter2");
        assert!(vault
            .fetch(&[SecretRef::parse("api/notes").unwrap()])
            .is_err());
        assert!(vault.fetch(&[SecretRef::parse("other").unwrap()]).is_err());
    }

    /// RFC 6238 appendix B: seed "12345678901234567890", SHA-1, T = 59 gives 94287082, of which 6 digits are 287082.
    #[test]
    fn totp_matches_rfc_6238_vector() {
        let base32 = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        assert_eq!(totp_code(base32, 59).unwrap().as_str(), "287082");
        let url = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        assert_eq!(totp_code(url, 59).unwrap().as_str(), "94287082");
    }
}
