//! Reading secrets from rbw's local vault copy.
//!
//! The vault is unlocked for one request and the keys are dropped with the `UnlockedVault`. Plaintext values stay in `rbw::locked::Vec`, which is mlocked and zeroed on drop.

use crate::secret_ref::{Field, SecretRef};
use crate::Item;
use anyhow::{anyhow, bail, Context, Result};
use rbw::cipherstring::CipherString;
use rbw::db::{Entry, EntryData};
use rbw::locked;
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

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
        let entry = self.find_entry(&secret.item, secret.user.as_deref())?;
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

    /// The metadata of every item, for `list` and `search`. Items that fail to decrypt are left out, as in `find_entry`.
    pub fn index(&self) -> Index {
        Index(
            self.entries
                .iter()
                .filter_map(|entry| self.metadata(entry).ok())
                .collect(),
        )
    }

    /// Decrypts the metadata of one entry. Notes and hidden field values are left encrypted.
    fn metadata(&self, entry: &Entry) -> Result<Metadata> {
        let keys = self.entry_keys(entry)?;
        let plain = |ciphertext: Option<&str>| {
            ciphertext
                .map(|ciphertext| decrypt_plain(ciphertext, &keys))
                .transpose()
        };
        let (username, uris) = match &entry.data {
            EntryData::Login { username, uris, .. } => (
                plain(username.as_deref())?,
                uris.iter()
                    .map(|uri| decrypt_plain(&uri.uri, &keys))
                    .collect::<Result<_>>()?,
            ),
            EntryData::Identity { username, .. } => (plain(username.as_deref())?, Vec::new()),
            _ => (None, Vec::new()),
        };
        let mut fields = Vec::new();
        for field in &entry.fields {
            fields.extend(plain(field.name.as_deref())?);
            if field.ty == Some(rbw::api::FieldType::Text) {
                fields.extend(plain(field.value.as_deref())?);
            }
        }
        Ok(Metadata {
            name: decrypt_plain(&entry.name, &keys)?,
            username,
            uris,
            // Folder names are always encrypted with the account's own key, also on organization items.
            folder: entry
                .folder
                .as_deref()
                .map(|folder| decrypt_plain(folder, &self.master_key))
                .transpose()?,
            fields,
        })
    }

    /// The one item named `item`, narrowed to the one whose username is `user` when given.
    fn find_entry(&self, item: &str, user: Option<&str>) -> Result<&Entry> {
        let mut matches = self.entries.iter().filter(|entry| {
            self.entry_keys(entry).is_ok_and(|keys| {
                decrypt_plain(&entry.name, &keys).is_ok_and(|name| name == item)
                    && user.is_none_or(|user| has_username(entry, &keys, user))
            })
        });
        let described = match user {
            Some(user) => format!("named '{item}' with username '{user}'"),
            None => format!("named '{item}'"),
        };
        let entry = matches.next().ok_or_else(|| {
            anyhow!("no item {described} in the vault copy; run `rbw sync` if it is new")
        })?;
        if matches.next().is_some() {
            match user {
                Some(_) => bail!("more than one item is {described}; rename one so it is unique"),
                None => bail!("more than one item is {described}; pick one with '{item}[username]' or rename one"),
            }
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

/// The decrypted metadata of every item: what `list` and `search` read. The agent keeps one per instance after a password approval, so later queries only need a confirmation. It holds no values: notes and hidden fields stay encrypted in the vault copy.
#[derive(Default)]
pub struct Index(Vec<Metadata>);

impl Index {
    /// The items named exactly `item`.
    pub fn list(&self, item: &str) -> Vec<Item> {
        self.items(|metadata| metadata.name == item)
    }

    /// The items where every whitespace-separated word of `query` appears, ignoring case, in one of the searched metadata fields. See `Metadata::searched`.
    pub fn search(&self, query: &str) -> Result<Vec<Item>> {
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        if words.is_empty() {
            bail!("the search query is empty");
        }
        Ok(self.items(|metadata| {
            let searched: Vec<String> = metadata.searched().map(str::to_lowercase).collect();
            words
                .iter()
                .all(|word| searched.iter().any(|text| text.contains(word.as_str())))
        }))
    }

    /// Items whose metadata passes `keep`, sorted by gate name.
    fn items(&self, keep: impl Fn(&Metadata) -> bool) -> Vec<Item> {
        let mut items: Vec<Item> = self
            .0
            .iter()
            .filter(|metadata| keep(metadata))
            .map(|metadata| Item {
                name: SecretRef {
                    item: metadata.name.clone(),
                    user: metadata.username.clone(),
                    field: Field::Password,
                }
                .to_string(),
                uris: metadata.uris.clone(),
                folder: metadata.folder.clone(),
            })
            .collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items
    }
}

/// What `list` and `search` see of an item. Zeroed on drop, since the agent keeps it for up to `cache::IDLE_TTL_SECS` of idle time.
struct Metadata {
    name: String,
    username: Option<String>,
    uris: Vec<String>,
    folder: Option<String>,
    /// Custom field names, and the values of text fields. Hidden and boolean values are not included.
    fields: Vec<String>,
}

impl Drop for Metadata {
    fn drop(&mut self) {
        self.name.zeroize();
        self.username.zeroize();
        self.uris.zeroize();
        self.folder.zeroize();
        self.fields.zeroize();
    }
}

impl Metadata {
    /// The fields `search` matches against. Notes and hidden fields are not among them, because notes often hold secrets and a match would reveal part of one.
    fn searched(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str())
            .chain(self.username.as_deref())
            .chain(self.uris.iter().map(String::as_str))
            .chain(self.folder.as_deref())
            .chain(self.fields.iter().map(String::as_str))
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

/// Whether the login or identity username of `entry` is `user`. Compared in locked memory, since a username can itself be requested as a secret.
fn has_username(entry: &Entry, keys: &locked::Keys, user: &str) -> bool {
    let ciphertext = match &entry.data {
        EntryData::Login { username, .. } | EntryData::Identity { username, .. } => {
            username.as_deref()
        }
        _ => None,
    };
    ciphertext
        .and_then(|ciphertext| decrypt_locked(ciphertext, keys).ok())
        .is_some_and(|username| username.data() == user.as_bytes())
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

    fn login(keys: &locked::Keys, name: &str, username: &str, password: &str) -> Entry {
        Entry {
            id: name.into(),
            org_id: None,
            folder: None,
            folder_id: None,
            name: encrypt(keys, name.as_bytes()),
            data: EntryData::Login {
                username: Some(encrypt(keys, username.as_bytes())),
                password: Some(encrypt(keys, password.as_bytes())),
                totp: None,
                uris: vec![],
            },
            fields: vec![],
            notes: None,
            history: vec![],
            key: None,
            master_password_reprompt: rbw::api::CipherRepromptType::None,
        }
    }

    #[test]
    fn username_picks_among_same_named_items() {
        let keys = test_keys(17);
        let vault = UnlockedVault {
            entries: vec![
                login(&keys, "test", "username1", "1"),
                login(&keys, "test", "username2", "22"),
                login(&keys, "test", "username2", "333"),
                login(&keys, "solo", "username1", "4444"),
            ],
            master_key: test_keys(17),
            org_keys: Default::default(),
        };
        let fetch = |name: &str| {
            vault
                .fetch(&[SecretRef::parse(name).unwrap()])
                .map(|values| values[0].reveal().unwrap().to_string())
        };
        assert_eq!(fetch("test[username1]").unwrap(), "1");
        assert_eq!(fetch("solo").unwrap(), "4444");
        assert_eq!(fetch("solo[username1]").unwrap(), "4444");
        let ambiguous = fetch("test").unwrap_err().to_string();
        assert!(ambiguous.contains("'test[username]'"), "{ambiguous}");
        assert!(
            fetch("test[username2]").is_err(),
            "two items share username2"
        );
        assert!(fetch("test[nobody]").is_err());
        assert!(fetch("solo[username2]").is_err());
    }

    #[test]
    fn list_and_search_see_metadata_only() {
        let keys = test_keys(19);
        let text = |name: &str, value: &str, ty| rbw::db::Field {
            ty: Some(ty),
            name: Some(encrypt(&keys, name.as_bytes())),
            value: Some(encrypt(&keys, value.as_bytes())),
            linked_id: None,
        };
        let mut work = login(&keys, "GitHub", "alice@work.example", "pw1");
        if let EntryData::Login { uris, .. } = &mut work.data {
            uris.push(rbw::db::Uri {
                uri: encrypt(&keys, b"https://github.com/login"),
                match_type: None,
            });
        }
        work.folder = Some(encrypt(&keys, b"Work"));
        work.fields = vec![
            text("team", "platform", rbw::api::FieldType::Text),
            text("recovery", "hiddenword", rbw::api::FieldType::Hidden),
        ];
        work.notes = Some(encrypt(&keys, b"notesword"));
        let personal = login(&keys, "GitHub", "bob", "pw2");
        let other = login(&keys, "Other/site", "carol[x]", "pw3");
        let vault = UnlockedVault {
            entries: vec![work, personal, other],
            master_key: test_keys(19),
            org_keys: Default::default(),
        };
        let index = vault.index();
        let names = |items: Vec<Item>| items.into_iter().map(|item| item.name).collect::<Vec<_>>();

        assert_eq!(
            names(index.list("GitHub")),
            ["GitHub[alice@work.example]", "GitHub[bob]"]
        );
        assert_eq!(names(index.list("github")), Vec::<String>::new());
        let found = index.search("github work").unwrap();
        assert_eq!(found[0].uris, ["https://github.com/login"]);
        assert_eq!(found[0].folder.as_deref(), Some("Work"));
        assert_eq!(names(found), ["GitHub[alice@work.example]"]);
        assert_eq!(names(index.search("PLATFORM").unwrap()).len(), 1);
        assert_eq!(names(index.search("recovery").unwrap()).len(), 1);
        assert!(index.search("hiddenword").unwrap().is_empty());
        assert!(index.search("notesword").unwrap().is_empty());
        assert_eq!(names(index.search("github").unwrap()).len(), 2);
        assert_eq!(
            names(index.search("carol").unwrap()),
            [r"Other\/site[carol\[x\]]"]
        );
        assert!(index.search("  ").is_err());
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
