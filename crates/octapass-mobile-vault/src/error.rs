use octapass_ffi::OctaPassError;
use serde::Serialize;

/// The `VaultErrorCode`s of `packages/vault-client`, plus `unexpected` for everything the UI
/// can only call "something went wrong".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    InvalidCredentials,
    SecretKeyRequired,
    InvalidSecretKey,
    EmailTaken,
    InvalidEmail,
    InvalidVerificationCode,
    SignupExpired,
    /// A master password reset took too long, or had too many wrong codes: start over.
    ResetExpired,
    /// The recovery code doesn't open this account.
    InvalidRecoveryCode,
    SignupsClosed,
    InsecureServerUrl,
    ServerUnreachable,
    ServerError,
    RateLimited,
    SessionExpired,
    AccountDeleted,
    ReauthRequired,
    Locked,
    NotFound,
    ReadOnlyVault,
    UntrustedVault,
    InvalidImportFile,
    ImportPasswordRequired,
    WrongImportPassword,
    /// The file isn't a PNG, JPEG, WebP or GIF image (reading QR codes).
    InvalidImage,
    /// An import review that was finished, cancelled, or forgotten when the vault locked.
    ImportReviewExpired,
    EmailMismatch,
    DeviceUnlockUnsupported,
    DeviceUnlockCancelled,
    DeviceUnlockFailed,
    PasswordRequired,
    InvalidTwoStepCode,
    TwoStepExpired,
    /// The identity provider hasn't finished in the browser yet.
    SsoPending,
    /// An organisation policy forbids this.
    OrgPolicy,
    SecurityKeyUnsupported,
    QuotaExceeded,
    FileTooLarge,
    NoFileViewer,
    CameraUnavailable,
    /// A vault on this device only has no account: this needs Turn on sync.
    NeedsSync,
    /// A local vault's master password is too easy to guess (plan 03).
    WeakMasterPassword,
    /// The backup file is damaged, isn't one, or the password or recovery code doesn't open it.
    InvalidBackup,
    /// A local vault needs a name.
    InvalidName,
    Unexpected,
}

/// What a command fails with. The message is for logs and developers; it never contains secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct VaultError {
    pub code: ErrorCode,
    pub message: String,
}

pub type Result<T, E = VaultError> = std::result::Result<T, E>;

impl VaultError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn unexpected(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unexpected, message)
    }
}

impl From<ErrorCode> for VaultError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code, format!("{code:?}"))
    }
}

impl From<OctaPassError> for VaultError {
    fn from(error: OctaPassError) -> Self {
        use OctaPassError as E;
        let code = match &error {
            E::LoginFailed => ErrorCode::InvalidCredentials,
            E::InvalidSecretKey => ErrorCode::InvalidSecretKey,
            E::DeviceUnlockFailed => ErrorCode::DeviceUnlockFailed,
            E::PasswordRequired => ErrorCode::PasswordRequired,
            E::Locked => ErrorCode::Locked,
            E::ItemNotFound => ErrorCode::NotFound,
            E::ReadOnlyVault => ErrorCode::ReadOnlyVault,
            E::InvalidUrl => ErrorCode::InsecureServerUrl,
            E::Network { .. } => ErrorCode::ServerUnreachable,
            E::InvalidResponse => ErrorCode::ServerError,
            E::Unauthorized => ErrorCode::SessionExpired,
            E::AccountDeleted => ErrorCode::AccountDeleted,
            E::AccountExists => ErrorCode::EmailTaken,
            E::InvalidVerificationCode => ErrorCode::InvalidVerificationCode,
            E::InvalidRecoveryCode => ErrorCode::InvalidRecoveryCode,
            // The FFI passes the last segment of the problem type.
            E::Server {
                status,
                problem_type,
                ..
            } => match problem_type.as_str() {
                "rate-limited" => ErrorCode::RateLimited,
                "recovery-expired" => ErrorCode::ResetExpired,
                "invalid-second-factor" => ErrorCode::InvalidTwoStepCode,
                // Only a sign-in that can't show the second step meets this.
                "second-factor-required" => ErrorCode::SessionExpired,
                "sso-required" => ErrorCode::SessionExpired,
                "sso-pending" => ErrorCode::SsoPending,
                "org-policy" => ErrorCode::OrgPolicy,
                "signups-closed" | "invite-required" => ErrorCode::SignupsClosed,
                "reauth-required" => ErrorCode::ReauthRequired,
                "not-found" => ErrorCode::NotFound,
                "forbidden" => ErrorCode::ReadOnlyVault,
                "quota-exceeded" => ErrorCode::QuotaExceeded,
                "payload-too-large" => ErrorCode::FileTooLarge,
                _ if *status >= 500 => ErrorCode::ServerError,
                _ => ErrorCode::Unexpected,
            },
            // A shared vault whose grant didn't verify.
            E::Core { code, .. } if code == "invalid_grant" || code == "invalid_signature" => {
                ErrorCode::UntrustedVault
            }
            E::Core { code, .. } if code == "weak_master_password" => ErrorCode::WeakMasterPassword,
            E::Core { code, .. } if code == "invalid_backup" => ErrorCode::InvalidBackup,
            _ => ErrorCode::Unexpected,
        };
        Self::new(code, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_errors_become_the_ui_codes() {
        let code = |error: OctaPassError| VaultError::from(error).code;
        assert_eq!(
            code(OctaPassError::LoginFailed),
            ErrorCode::InvalidCredentials
        );
        assert_eq!(code(OctaPassError::AccountExists), ErrorCode::EmailTaken);
        assert_eq!(
            code(OctaPassError::Network {
                reason: "offline".into()
            }),
            ErrorCode::ServerUnreachable
        );
        assert_eq!(
            code(OctaPassError::Server {
                status: 429,
                problem_type: "rate-limited".into(),
                detail: None
            }),
            ErrorCode::RateLimited
        );
        assert_eq!(
            code(OctaPassError::Server {
                status: 401,
                problem_type: "invalid-second-factor".into(),
                detail: None
            }),
            ErrorCode::InvalidTwoStepCode
        );
        assert_eq!(
            code(OctaPassError::Server {
                status: 403,
                problem_type: "quota-exceeded".into(),
                detail: None
            }),
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            code(OctaPassError::Server {
                status: 413,
                problem_type: "payload-too-large".into(),
                detail: None
            }),
            ErrorCode::FileTooLarge
        );
        assert_eq!(
            code(OctaPassError::Core {
                code: "malformed_ciphertext".into(),
                reason: "malformed ciphertext".into()
            }),
            ErrorCode::Unexpected
        );
        assert_eq!(
            code(OctaPassError::Core {
                code: "invalid_grant".into(),
                reason: "this grant is for another vault or account".into()
            }),
            ErrorCode::UntrustedVault
        );
    }
}
