//! Parsing of secret names: `item`, `item/field`, `item[user]` or `item[user]/field`.
//!
//! `[user]` picks, among items with the same name, the one whose username is `user`.
//!
//! `\` escapes the next character, so an item called `github.com/work` is written `github.com\/work`. `/`, `[` and `]` are special wherever they appear unescaped, and `[`/`]` are only valid as one trailing `[user]` on the item.

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
    /// The username that picks one item among several with the same name.
    pub user: Option<String>,
    pub field: Field,
}

/// A character of the input and whether it was escaped.
type Token = (char, bool);

fn collect(tokens: &[Token]) -> String {
    tokens.iter().map(|&(c, _)| c).collect()
}

fn is_unescaped(token: &Token, c: char) -> bool {
    *token == (c, false)
}

impl SecretRef {
    pub fn parse(input: &str) -> Result<Self> {
        if input.chars().any(char::is_control) {
            bail!("secret name contains a control character");
        }

        let mut parts: Vec<Vec<Token>> = vec![Vec::new()];
        let mut chars = input.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    let escaped = chars
                        .next()
                        .ok_or_else(|| anyhow!("secret name '{input}' ends with a lone '\\'"))?;
                    parts.last_mut().unwrap().push((escaped, true));
                }
                '/' => parts.push(Vec::new()),
                c => parts.last_mut().unwrap().push((c, false)),
            }
        }

        let (item_part, field) = match parts.as_slice() {
            [item] => (item, Field::Password),
            [item, field] => {
                if field
                    .iter()
                    .any(|token| is_unescaped(token, '[') || is_unescaped(token, ']'))
                {
                    bail!("secret name '{input}' has an unescaped '[' or ']' in the field name");
                }
                (item, Field::from_name(&collect(field)))
            }
            _ => bail!("secret name '{input}' has more than one unescaped '/'"),
        };
        let (item, user) = split_user(input, item_part)?;
        if item.is_empty() {
            bail!("secret name '{input}' has an empty item name");
        }
        if user.as_deref() == Some("") {
            bail!("secret name '{input}' has an empty username in '[]'");
        }
        if field == Field::Custom(String::new()) {
            bail!("secret name '{input}' has an empty field name");
        }
        Ok(Self { item, user, field })
    }
}

/// Splits `item[user]` into its item and username. Brackets anywhere but as one trailing pair are an error.
fn split_user(input: &str, tokens: &[Token]) -> Result<(String, Option<String>)> {
    let opens: Vec<usize> = (0..tokens.len())
        .filter(|&i| is_unescaped(&tokens[i], '['))
        .collect();
    let closes: Vec<usize> = (0..tokens.len())
        .filter(|&i| is_unescaped(&tokens[i], ']'))
        .collect();
    match (opens.as_slice(), closes.as_slice()) {
        ([], []) => Ok((collect(tokens), None)),
        ([open], [close]) if *close == tokens.len() - 1 && open < close => Ok((
            collect(&tokens[..*open]),
            Some(collect(&tokens[open + 1..*close])),
        )),
        _ => bail!(
            "secret name '{input}' has a misplaced '[' or ']'; a username goes last on the item as 'item[user]', other brackets need a '\\'"
        ),
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
        if matches!(c, '/' | '\\' | '[' | ']') {
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
        if let Some(user) = &self.user {
            f.write_str("[")?;
            write_escaped(f, user)?;
            f.write_str("]")?;
        }
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
                user: None,
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
    fn username_picks_among_same_named_items() {
        let secret = parsed("test[username1]");
        assert_eq!(secret.item, "test");
        assert_eq!(secret.user.as_deref(), Some("username1"));
        assert_eq!(secret.field, Field::Password);

        let secret = parsed("github[me@work.com]/api key");
        assert_eq!(secret.item, "github");
        assert_eq!(secret.user.as_deref(), Some("me@work.com"));
        assert_eq!(secret.field, Field::Custom("api key".into()));
    }

    #[test]
    fn escaped_brackets_are_literal() {
        let secret = parsed(r"a\[b\]");
        assert_eq!(secret.item, "a[b]");
        assert_eq!(secret.user, None);

        let secret = parsed(r"a\[1\][x\/y\]z]/f\[0\]");
        assert_eq!(secret.item, "a[1]");
        assert_eq!(secret.user.as_deref(), Some("x/y]z"));
        assert_eq!(secret.field, Field::Custom("f[0]".into()));
    }

    #[test]
    fn rejects_malformed_names() {
        for input in [
            "",
            "/password",
            "a/b/c",
            "a/",
            "a\\",
            "a\nb",
            "[user]",
            "a[]",
            "a[user",
            "a]",
            "a[u]x",
            "a[u][v]",
            "a[[u]",
            "a/f[0]",
        ] {
            assert!(
                SecretRef::parse(input).is_err(),
                "{input:?} should be rejected"
            );
        }
    }

    #[test]
    fn display_round_trips() {
        for input in [
            "plain",
            r"a\/b",
            r"a\\b/c\/d",
            "x/totp",
            "test[username1]",
            r"a\[1\][x\/y\]z]/f\[0\]",
        ] {
            let secret = parsed(input);
            assert_eq!(parsed(&secret.to_string()), secret, "{input}");
        }
        assert_eq!(parsed("x/password").to_string(), "x");
    }
}
