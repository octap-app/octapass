//! Errors and the exit codes scripts can rely on. The codes are documented in
//! `docs/platforms/cli.md`; never renumber them.

use octapass_desktop_vault::{ErrorCode, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Ok = 0,
    /// Anything without a code of its own.
    Error = 1,
    /// Bad arguments or input.
    Usage = 2,
    /// No account on this device, or the server session ended.
    SignedOut = 3,
    /// The vault is locked and no master password was given.
    Locked = 4,
    /// Wrong master password or Secret Key.
    InvalidCredentials = 5,
    /// No such item, field or vault.
    NotFound = 6,
    /// More than one item matches.
    Ambiguous = 7,
    /// The server couldn't be reached.
    ServerUnreachable = 8,
}

/// A failed command: the exit code and one line for stderr. Never contains secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub exit: Exit,
    pub message: String,
}

impl CliError {
    pub fn new(exit: Exit, message: impl Into<String>) -> Self {
        Self {
            exit,
            message: message.into(),
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Exit::Usage, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Exit::NotFound, message)
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::new(Exit::Error, message)
    }

    pub fn signed_out() -> Self {
        Self::new(
            Exit::SignedOut,
            "Not signed in. Run `octapass login` first.",
        )
    }

    pub fn locked() -> Self {
        Self::new(
            Exit::Locked,
            "The vault is locked. Run `octapass unlock`, or pass the master password with --password-stdin.",
        )
    }
}

impl From<VaultError> for CliError {
    fn from(error: VaultError) -> Self {
        let (exit, message) = match error.code {
            ErrorCode::InvalidCredentials => (
                Exit::InvalidCredentials,
                "Wrong master password or Secret Key.".into(),
            ),
            ErrorCode::InvalidSecretKey => (
                Exit::InvalidCredentials,
                "That isn't a valid Secret Key. It starts with OP1- and is on your Recovery Kit."
                    .into(),
            ),
            ErrorCode::SecretKeyRequired => (
                Exit::Usage,
                "This device doesn't have your Secret Key yet. Set OCTAPASS_SECRET_KEY or run `octapass login` in a terminal.".into(),
            ),
            ErrorCode::InsecureServerUrl => (
                Exit::Usage,
                "The server address must start with https:// (http:// only for localhost).".into(),
            ),
            ErrorCode::ServerUnreachable => (
                Exit::ServerUnreachable,
                "Couldn't reach the server. Check the address and your connection.".into(),
            ),
            ErrorCode::SessionExpired | ErrorCode::ReauthRequired => (
                Exit::SignedOut,
                "The server session ended. Run `octapass login` again.".into(),
            ),
            ErrorCode::AccountDeleted => (
                Exit::SignedOut,
                "This account was deleted. Its data is gone from this device too.".into(),
            ),
            ErrorCode::Locked => return Self::locked(),
            ErrorCode::NotFound => (Exit::NotFound, "Not found.".into()),
            ErrorCode::ReadOnlyVault => (
                Exit::Error,
                "You can only read this vault, not change it.".into(),
            ),
            ErrorCode::RateLimited => (
                Exit::Error,
                "Too many attempts. Wait a minute and try again.".into(),
            ),
            ErrorCode::ServerError => (
                Exit::Error,
                "The server had a problem. Try again later.".into(),
            ),
            ErrorCode::InvalidServiceAccountToken => (
                Exit::Usage,
                "OCTAPASS_SERVICE_ACCOUNT_TOKEN isn't a whole service account token.".into(),
            ),
            ErrorCode::ServiceAccountRefused | ErrorCode::ServiceAccountNeedsNewToken => {
                (Exit::InvalidCredentials, error.message)
            }
            _ => (Exit::Error, format!("Something went wrong ({}).", error.message)),
        };
        Self { exit, message }
    }
}

pub type Result<T, E = CliError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_errors_get_stable_exit_codes() {
        let exit = |code| CliError::from(VaultError::from(code)).exit;
        assert_eq!(
            exit(ErrorCode::InvalidCredentials),
            Exit::InvalidCredentials
        );
        assert_eq!(exit(ErrorCode::Locked), Exit::Locked);
        assert_eq!(exit(ErrorCode::NotFound), Exit::NotFound);
        assert_eq!(exit(ErrorCode::SessionExpired), Exit::SignedOut);
        assert_eq!(exit(ErrorCode::ServerUnreachable), Exit::ServerUnreachable);
        assert_eq!(exit(ErrorCode::Unexpected), Exit::Error);
        assert_eq!(Exit::ServerUnreachable as i32, 8);
    }
}
