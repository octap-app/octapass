//! The one error type every binding throws: `OctaPassError` in Swift, `OctaPassException` in
//! Kotlin. Variants the apps handle differently are typed; other core failures (malformed data, a
//! broken invariant) arrive as [`OctaPassError::Core`] with the core's stable code. No message
//! ever contains a secret.

use octapass_core::Error as CoreError;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum OctaPassError {
    /// Wrong master password or Secret Key (locally, or at the server's OPAQUE login).
    #[error("login failed")]
    LoginFailed,
    #[error("invalid Secret Key")]
    InvalidSecretKey,
    #[error("invalid recovery code")]
    InvalidRecoveryCode,
    /// The server asked for key derivation parameters weaker than the defaults (or absurdly
    /// large ones). Never retry with them.
    #[error("unsupported or unsafe key derivation parameters")]
    UnsupportedKdf,
    /// The device secret doesn't open this account. Turn device unlock off and on again.
    #[error("this device's unlock key doesn't open the account")]
    DeviceUnlockFailed,
    /// Device unlock is off, or the master password is due (every 14 days, plan 03).
    #[error("the master password is required")]
    PasswordRequired,
    /// The session was locked; unlock again.
    #[error("the vault is locked")]
    Locked,
    #[error("invalid TOTP secret or URI")]
    InvalidTotp,
    #[error("invalid generator options")]
    InvalidGeneratorOptions,
    #[error("invalid item")]
    InvalidItem,
    #[error("no such item")]
    ItemNotFound,
    /// The vault is read-only for this account, or there is no vault to save into.
    #[error("this vault can't be changed")]
    ReadOnlyVault,
    #[error("invalid URL")]
    InvalidUrl,
    /// The WebAuthn request is malformed (a `TypeError` for the relying party).
    #[error("invalid passkey request")]
    PasskeyInvalidRequest,
    /// The caller may not use this relying party id.
    #[error("this site can't use passkeys for that relying party")]
    PasskeyRpMismatch,
    #[error("passkeys aren't allowed in this frame")]
    PasskeyFrameNotAllowed,
    #[error("none of the requested passkey algorithms is supported")]
    PasskeyUnsupportedAlgorithm,
    /// A passkey in `excludeCredentials` is already saved (`InvalidStateError`).
    #[error("a passkey for this account already exists")]
    PasskeyExcluded,
    #[error("no matching passkey")]
    PasskeyNotFound,
    /// A one-shot flow (sign-up, a login step) was used twice.
    #[error("this flow has already finished")]
    FlowFinished,
    /// The local store file is missing, from another format version, or damaged. Sign in again
    /// to rebuild it.
    #[error("the local store can't be read")]
    InvalidStore,
    #[error("file error: {reason}")]
    Io { reason: String },
    /// The native `HttpClient` got no response (offline, TLS failure, timeout).
    #[error("network error: {reason}")]
    Network { reason: String },
    /// The server answered something that isn't the sync API.
    #[error("unexpected response from the server")]
    InvalidResponse,
    /// The access token expired or was revoked: refresh it, or sign in again.
    #[error("the session expired")]
    Unauthorized,
    /// The account was deleted on another device. Wipe this account's local data.
    #[error("the account was deleted")]
    AccountDeleted,
    #[error("an account with this email already exists")]
    AccountExists,
    #[error("wrong or expired verification code")]
    InvalidVerificationCode,
    /// Any other `application/problem+json` answer. Match on `problem_type`, never on the text.
    #[error("server error {status}: {problem_type}")]
    Server {
        status: u16,
        problem_type: String,
        detail: Option<String>,
    },
    /// Any other core failure, by its stable code (`malformed_ciphertext`, `key_mismatch` …).
    /// (Fields aren't called `message`: Kotlin exceptions already have one.)
    #[error("{reason}")]
    Core { code: String, reason: String },
}

pub type Result<T, E = OctaPassError> = core::result::Result<T, E>;

impl From<CoreError> for OctaPassError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::LoginFailed => Self::LoginFailed,
            CoreError::InvalidSecretKey => Self::InvalidSecretKey,
            CoreError::InvalidRecoveryCode => Self::InvalidRecoveryCode,
            CoreError::UnsupportedKdf => Self::UnsupportedKdf,
            CoreError::DeviceUnlockFailed => Self::DeviceUnlockFailed,
            CoreError::InvalidTotp => Self::InvalidTotp,
            CoreError::InvalidGeneratorOptions => Self::InvalidGeneratorOptions,
            CoreError::InvalidItem => Self::InvalidItem,
            CoreError::InvalidUrl => Self::InvalidUrl,
            CoreError::InvalidPasskeyRequest => Self::PasskeyInvalidRequest,
            CoreError::PasskeyRpMismatch => Self::PasskeyRpMismatch,
            CoreError::PasskeyFrameNotAllowed => Self::PasskeyFrameNotAllowed,
            CoreError::PasskeyUnsupportedAlgorithm => Self::PasskeyUnsupportedAlgorithm,
            CoreError::PasskeyExcluded => Self::PasskeyExcluded,
            CoreError::PasskeyNotFound => Self::PasskeyNotFound,
            // Not matched one by one, so new core variants (milestone 2 adds some) still compile.
            other => Self::Core {
                code: other.code().to_owned(),
                reason: other.to_string(),
            },
        }
    }
}

/// A foreign `HttpClient` threw something other than an `OctaPassError`.
impl From<uniffi::UnexpectedUniFFICallbackError> for OctaPassError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Network {
            reason: error.reason,
        }
    }
}

impl From<std::io::Error> for OctaPassError {
    fn from(error: std::io::Error) -> Self {
        Self::Io {
            reason: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_errors_keep_their_meaning() {
        assert_eq!(
            OctaPassError::from(CoreError::LoginFailed),
            OctaPassError::LoginFailed
        );
        assert_eq!(
            OctaPassError::from(CoreError::MalformedCiphertext),
            OctaPassError::Core {
                code: "malformed_ciphertext".into(),
                reason: "malformed ciphertext".into()
            }
        );
    }
}
