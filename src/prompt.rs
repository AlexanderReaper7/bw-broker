//! The pinentry dialog that asks the user to approve a request.

use crate::secret_ref::SecretRef;
use anyhow::{anyhow, Result};
use pinentry::PassphraseInput;
use secrecy::SecretString;

/// Seconds before an unanswered prompt counts as a denial.
const TIMEOUT_SECS: u16 = 120;

pub struct Approval<'a> {
    pub pinentry: &'a str,
    pub app: &'a str,
    pub pid: u32,
    pub secrets: &'a [SecretRef],
}

impl Approval<'_> {
    pub fn description(&self) -> String {
        let list: String = self
            .secrets
            .iter()
            .map(|secret| format!("\n  {secret}"))
            .collect();
        format!(
            "{} (pid {}) wants:{list}\n\nEnter the master password to approve.",
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
        let secrets = [
            SecretRef::parse("github-token").unwrap(),
            SecretRef::parse("npm/notes").unwrap(),
        ];
        let approval = Approval {
            pinentry: "pinentry",
            app: "claude-code/.claude-wrapped",
            pid: 42,
            secrets: &secrets,
        };
        assert_eq!(
            approval.description(),
            "claude-code/.claude-wrapped (pid 42) wants:\n  github-token\n  npm/notes\n\nEnter the master password to approve."
        );
    }
}
