//! The pinentry dialog that asks the user to approve a request.

use anyhow::{anyhow, Result};
use pinentry::PassphraseInput;
use secrecy::SecretString;

/// Seconds before an unanswered prompt counts as a denial.
const TIMEOUT_SECS: u16 = 120;

pub struct Approval<'a> {
    pub pinentry: &'a str,
    pub app: &'a str,
    pub pid: u32,
    /// Hints from the requester that it can change itself: its working directory and the app that started it.
    pub cwd: Option<&'a str>,
    pub parent: Option<&'a str>,
    /// One line per thing asked for: a secret name, or what a `type`, `list` or `search` will do.
    pub wants: &'a [String],
}

impl Approval<'_> {
    pub fn description(&self) -> String {
        let list: String = self
            .wants
            .iter()
            .map(|want| format!("\n  {want}"))
            .collect();
        let cwd = self
            .cwd
            .map(|cwd| format!("\nin {cwd}"))
            .unwrap_or_default();
        let parent = self
            .parent
            .map(|parent| format!("\nstarted by {parent}"))
            .unwrap_or_default();
        format!(
            "{} (pid {}){cwd}{parent}\nwants:{list}\n\nEnter the master password to approve.",
            self.app, self.pid
        )
    }

    /// Shows the dialog. `Ok(None)` means the user cancelled or let it time out. `error` is shown above the input, for a retry after a wrong password.
    pub fn ask(&self, error: Option<&str>) -> Result<Option<SecretString>> {
        let description = self.description();
        let mut input = PassphraseInput::with_binary(self.pinentry)
            .ok_or_else(|| anyhow!("pinentry program '{}' not found", self.pinentry))?;
        input
            .with_title("bw-app-gate")
            .with_description(&description)
            .with_prompt("Master password:")
            .with_ok("Approve")
            .with_cancel("Deny")
            .with_timeout(TIMEOUT_SECS);
        if let Some(error) = error {
            input.with_error(error);
        }
        match input.interact() {
            Ok(password) => Ok(Some(password)),
            Err(pinentry::Error::Cancelled | pinentry::Error::Timeout) => Ok(None),
            Err(error) => Err(anyhow!("pinentry failed: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_lists_app_pid_and_secrets() {
        let wants = ["github-token".to_string(), "npm/notes".to_string()];
        let approval = Approval {
            pinentry: "pinentry",
            app: "claude-code/.claude-wrapped",
            pid: 42,
            cwd: Some("~/Projects/x"),
            parent: Some("nodejs-slim/node"),
            wants: &wants,
        };
        assert_eq!(
            approval.description(),
            "claude-code/.claude-wrapped (pid 42)\nin ~/Projects/x\nstarted by nodejs-slim/node\nwants:\n  github-token\n  npm/notes\n\nEnter the master password to approve."
        );
    }

    #[test]
    fn description_omits_unknown_hints() {
        let wants = ["a".to_string()];
        let approval = Approval {
            pinentry: "pinentry",
            app: "app",
            pid: 1,
            cwd: None,
            parent: None,
            wants: &wants,
        };
        assert_eq!(
            approval.description(),
            "app (pid 1)\nwants:\n  a\n\nEnter the master password to approve."
        );
    }
}
