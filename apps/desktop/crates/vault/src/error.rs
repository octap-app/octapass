use serde::Serialize;

use crate::api::ApiError;
use octapass_api::problem::types;

/// The `VaultErrorCode`s of `packages/vault-client`, plus `unexpected` for everything the UI
/// can only call "something went wrong".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    /// A developer toolkit tool refused its input; the message holds the core's error code.
    ToolFailed,
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
    KeyLogMismatch,
    InvalidImportFile,
    ImportPasswordRequired,
    WrongImportPassword,
    InvalidImage,
    ImportReviewExpired,
    ScreenCaptureDenied,
    EmailMismatch,
    DeviceUnlockUnsupported,
    DeviceUnlockCancelled,
    DeviceUnlockFailed,
    PasswordRequired,
    AccountNotFound,
    NotAllowed,
    AlreadyExists,
    FamilyFull,
    WrongPassphrase,
    SshPassphraseRequired,
    SshPublicKeyOnly,
    UnsupportedSshKey,
    InvalidSshKey,
    InvalidShareLink,
    QuotaExceeded,
    FileTooLarge,
    InvalidTwoStepCode,
    TwoStepExpired,
    /// The identity provider hasn't finished in the browser yet.
    SsoPending,
    /// An organisation policy forbids this.
    OrgPolicy,
    SecurityKeyUnsupported,
    /// `OCTAPASS_SERVICE_ACCOUNT_TOKEN` isn't a whole token.
    InvalidServiceAccountToken,
    /// Revoked, expired, or the wrong key.
    ServiceAccountRefused,
    /// The token can't verify the vault's key: its creator has to issue a new one.
    ServiceAccountNeedsNewToken,
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

impl From<octapass_core::Error> for VaultError {
    fn from(error: octapass_core::Error) -> Self {
        use octapass_core::Error as Core;
        let code = match error {
            Core::LoginFailed => ErrorCode::InvalidCredentials,
            Core::InvalidSecretKey => ErrorCode::InvalidSecretKey,
            Core::DeviceUnlockFailed => ErrorCode::DeviceUnlockFailed,
            Core::InvalidImage => ErrorCode::InvalidImage,
            // A shared vault whose grant didn't verify.
            Core::InvalidGrant | Core::InvalidSignature => ErrorCode::UntrustedVault,
            Core::KeyLogMismatch => ErrorCode::KeyLogMismatch,
            Core::WrongPassphrase => ErrorCode::WrongPassphrase,
            Core::SshPassphraseRequired => ErrorCode::SshPassphraseRequired,
            Core::SshPublicKeyOnly => ErrorCode::SshPublicKeyOnly,
            Core::UnsupportedSshKey => ErrorCode::UnsupportedSshKey,
            Core::InvalidSshKey => ErrorCode::InvalidSshKey,
            Core::InvalidShareLink => ErrorCode::InvalidShareLink,
            Core::WeakMasterPassword => ErrorCode::WeakMasterPassword,
            Core::InvalidBackup => ErrorCode::InvalidBackup,
            _ => ErrorCode::Unexpected,
        };
        Self::new(code, error.code())
    }
}

/// On sharing calls a 403 means the role or relationship doesn't allow it, not that a vault is
/// read-only.
pub(crate) fn not_allowed(error: VaultError) -> VaultError {
    match error.code {
        ErrorCode::ReadOnlyVault => VaultError::new(ErrorCode::NotAllowed, error.message),
        _ => error,
    }
}

impl From<octapass_device_unlock::Error> for VaultError {
    fn from(error: octapass_device_unlock::Error) -> Self {
        use octapass_device_unlock::Error as Unlock;
        let code = match error {
            Unlock::Cancelled => ErrorCode::DeviceUnlockCancelled,
            Unlock::NoDeviceLock | Unlock::Unavailable => ErrorCode::DeviceUnlockUnsupported,
            Unlock::Denied | Unlock::NotEnrolled | Unlock::Platform(_) => {
                ErrorCode::DeviceUnlockFailed
            }
        };
        Self::new(code, error.to_string())
    }
}

/// Server problems the UI has a message for; anything else is unexpected.
impl From<ApiError> for VaultError {
    fn from(error: ApiError) -> Self {
        let code = match &error {
            ApiError::Network(_) => ErrorCode::ServerUnreachable,
            ApiError::Problem { problem, .. } => match problem.problem_type.as_str() {
                types::LOGIN_FAILED => ErrorCode::InvalidCredentials,
                types::INVALID_SECOND_FACTOR => ErrorCode::InvalidTwoStepCode,
                // Only an automatic sign-in (a session that expired) meets this: the user signs
                // in again, and that sign-in asks for the second step.
                types::SECOND_FACTOR_REQUIRED => ErrorCode::SessionExpired,
                // The same for an expired session of an account that signs in with SSO.
                types::SSO_REQUIRED => ErrorCode::SessionExpired,
                types::SSO_PENDING => ErrorCode::SsoPending,
                types::ORG_POLICY => ErrorCode::OrgPolicy,
                types::ACCOUNT_EXISTS => ErrorCode::EmailTaken,
                types::INVALID_VERIFICATION_CODE => ErrorCode::InvalidVerificationCode,
                types::RECOVERY_EXPIRED => ErrorCode::ResetExpired,
                types::SIGNUPS_CLOSED | types::INVITE_REQUIRED => ErrorCode::SignupsClosed,
                types::NOT_FOUND => ErrorCode::NotFound,
                types::FORBIDDEN => ErrorCode::ReadOnlyVault,
                types::RATE_LIMITED => ErrorCode::RateLimited,
                types::UNAUTHORIZED => ErrorCode::SessionExpired,
                types::ACCOUNT_DELETED => ErrorCode::AccountDeleted,
                types::REAUTH_REQUIRED => ErrorCode::ReauthRequired,
                types::QUOTA_EXCEEDED => ErrorCode::QuotaExceeded,
                types::ALREADY_EXISTS => ErrorCode::AlreadyExists,
                types::FAMILY_FULL => ErrorCode::FamilyFull,
                types::PAYLOAD_TOO_LARGE => ErrorCode::FileTooLarge,
                types::UNAVAILABLE | types::INTERNAL => ErrorCode::ServerError,
                _ => ErrorCode::Unexpected,
            },
            ApiError::Unexpected { status } if *status >= 500 => ErrorCode::ServerError,
            ApiError::Unexpected { .. } => ErrorCode::Unexpected,
        };
        Self::new(code, error.to_string())
    }
}

pub type Result<T, E = VaultError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use octapass_api::Problem;
    use serde_json::json;

    use super::*;

    fn problem(problem_type: &str) -> ApiError {
        ApiError::Problem {
            status: 400,
            problem: Box::new(Problem {
                problem_type: problem_type.into(),
                title: "t".into(),
                status: 400,
                detail: None,
                current: None,
                second_factor: None,
                sso: None,
                vault_ids: Vec::new(),
            }),
        }
    }

    #[test]
    fn serialises_as_the_ui_expects() {
        assert_eq!(
            serde_json::to_value(VaultError::from(ErrorCode::DeviceUnlockCancelled)).unwrap(),
            json!({ "code": "deviceUnlockCancelled", "message": "DeviceUnlockCancelled" })
        );
        assert_eq!(
            serde_json::to_value(ErrorCode::InvalidTwoStepCode).unwrap(),
            json!("invalidTwoStepCode")
        );
    }

    #[test]
    fn server_problems_map_to_ui_codes() {
        let code = |error| VaultError::from(error).code;
        assert_eq!(
            code(problem(types::LOGIN_FAILED)),
            ErrorCode::InvalidCredentials
        );
        assert_eq!(code(problem(types::ACCOUNT_EXISTS)), ErrorCode::EmailTaken);
        assert_eq!(
            code(problem(types::INVALID_SECOND_FACTOR)),
            ErrorCode::InvalidTwoStepCode
        );
        assert_eq!(
            code(problem(types::SECOND_FACTOR_REQUIRED)),
            ErrorCode::SessionExpired
        );
        assert_eq!(
            code(problem(types::INVITE_REQUIRED)),
            ErrorCode::SignupsClosed
        );
        assert_eq!(code(problem(types::INTERNAL)), ErrorCode::ServerError);
        assert_eq!(code(problem(types::FAMILY_FULL)), ErrorCode::FamilyFull);
        assert_eq!(
            code(problem(types::ALREADY_EXISTS)),
            ErrorCode::AlreadyExists
        );
        assert_eq!(
            not_allowed(VaultError::from(problem(types::FORBIDDEN))).code,
            ErrorCode::NotAllowed
        );
        assert_eq!(
            code(problem(types::ACCOUNT_DELETED)),
            ErrorCode::AccountDeleted
        );
        assert_eq!(
            code(problem(types::METHOD_NOT_ALLOWED)),
            ErrorCode::Unexpected
        );
        assert_eq!(
            code(ApiError::Network("refused".into())),
            ErrorCode::ServerUnreachable
        );
    }

    #[test]
    fn core_and_device_errors_map_to_ui_codes() {
        assert_eq!(
            VaultError::from(octapass_core::Error::LoginFailed).code,
            ErrorCode::InvalidCredentials
        );
        assert_eq!(
            VaultError::from(octapass_core::Error::InvalidImage).code,
            ErrorCode::InvalidImage
        );
        assert_eq!(
            VaultError::from(octapass_core::Error::WrongPassphrase).code,
            ErrorCode::WrongPassphrase
        );
        assert_eq!(
            VaultError::from(octapass_device_unlock::Error::Cancelled).code,
            ErrorCode::DeviceUnlockCancelled
        );
        assert_eq!(
            VaultError::from(octapass_device_unlock::Error::NoDeviceLock).code,
            ErrorCode::DeviceUnlockUnsupported
        );
    }
}
