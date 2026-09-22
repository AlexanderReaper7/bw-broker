//! Parsing of secret names: `item` or `item/field`.
//!
//! `\` escapes the next character, so an item called `github.com/work` is written `github.com\/work`.

use anyhow::{anyhow, bail, Result};
use std::fmt;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Field {
    Password,
    Username,
    Notes,
    Totp,
    /// A custom field, matched by its name. The built-in names above win over a custom field with the same name.
    Custom(String),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SecretRef {
    pub item: String,
    pub field: Field,
}

impl SecretRef {
    pub fn parse(input: &str) -> Result<Self> {
        if input.chars().any(char::is_control) {
            bail!("secret name contains a control character");
        }

        let mut parts = vec![String::new()];
        let mut chars = input.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    let escaped = chars
                        .next()
                        .ok_or_else(|| anyhow!("secret name '{input}' ends with a lone '\\'"))?;
                    parts.last_mut().unwrap().push(escaped);
                }
                '/' => parts.push(String::new()),
                c => parts.last_mut().unwrap().push(c),
            }
        }

        let (item, field) = match parts.as_slice() {
            [item] => (item.clone(), Field::Password),
            [item, field] => (item.clone(), Field::from_name(field)),
            _ => bail!("secret name '{input}' has more than one unescaped '/'"),
        };
        if item.is_empty() {
            bail!("secret name '{input}' has an empty item name");
        }
        if field == Field::Custom(String::new()) {
            bail!("secret name '{input}' has an empty field name");
        }
        Ok(Self { item, field })
    }
}

impl Field {
    fn from_name(name: &str) -> Self {
        match name {
            "password" => Self::Password,
            "username" => Self::Username,
            "notes" => Self::Notes,
            "totp" => Self::Totp,
            other => Self::Custom(other.to_string()),
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Password => "password",
            Self::Username => "username",
            Self::Notes => "notes",
            Self::Totp => "totp",
            Self::Custom(name) => name,
        }
    }
}

fn write_escaped(f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    for c in text.chars() {
        if c == '/' || c == '\\' {
            f.write_str("\\")?;
        }
        write!(f, "{c}")?;
    }
    Ok(())
}

/// Writes the canonical form, which `parse` reads back to an equal value.
impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_escaped(f, &self.item)?;
        if self.field != Field::Password {
            f.write_str("/")?;
            write_escaped(f, self.field.name())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(input: &str) -> SecretRef {
        SecretRef::parse(input).expect("should parse")
    }

    #[test]
    fn bare_item_means_password() {
        assert_eq!(
            parsed("github-token"),
            SecretRef {
                item: "github-token".into(),
                field: Field::Password
            }
        );
    }

    #[test]
    fn builtin_and_custom_fields() {
        assert_eq!(parsed("gh/username").field, Field::Username);
        assert_eq!(parsed("gh/notes").field, Field::Notes);
        assert_eq!(parsed("gh/totp").field, Field::Totp);
        assert_eq!(parsed("gh/api key").field, Field::Custom("api key".into()));
    }

    #[test]
    fn escaped_slash_stays_in_item() {
        let secret = parsed(r"github.com\/work/username");
        assert_eq!(secret.item, "github.com/work");
        assert_eq!(secret.field, Field::Username);
    }

    #[test]
    fn rejects_malformed_names() {
        for input in ["", "/password", "a/b/c", "a/", "a\\", "a\nb"] {
            assert!(
                SecretRef::parse(input).is_err(),
                "{input:?} should be rejected"
            );
        }
    }

    #[test]
    fn display_round_trips() {
        for input in ["plain", r"a\/b", r"a\\b/c\/d", "x/totp"] {
            let secret = parsed(input);
            assert_eq!(parsed(&secret.to_string()), secret, "{input}");
        }
        assert_eq!(parsed("x/password").to_string(), "x");
    }
}
