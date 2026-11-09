//! The one error every call throws: `VaultError.Failed(code:reason:)` in Swift,
//! `VaultException.Failed` in Kotlin. `code` is the web vault's `VaultErrorCode`, so the apps show
//! the same message for it (`errors.<code>` in the catalog, see [`error_code_name`]). `reason` is
//! for logs and developers and never contains a secret. (Not called `message`: Kotlin exceptions
//! already have one.)

use octapass_ffi::OctaPassError;
use octapass_mobile_vault::ErrorCode as Code;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, uniffi::Enum)]
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
    InvalidImportFile,
    ImportPasswordRequired,
    WrongImportPassword,
    EmailMismatch,
    DeviceUnlockUnsupported,
    DeviceUnlockCancelled,
    DeviceUnlockFailed,
    PasswordRequired,
    AccountNotFound,
    NotAllowed,
    AlreadyExists,
    FamilyFull,
    QuotaExceeded,
    UntrustedVault,
    WrongPassphrase,
    /// A protected SSH key: ask for its passphrase and read it again.
    SshPassphraseRequired,
    InvalidSshKey,
    UnsupportedSshKey,
    /// A `.pub` file where a private key was expected.
    SshPublicKeyOnly,
    InvalidShareLink,
    FileTooLarge,
    InvalidTwoStepCode,
    TwoStepExpired,
    /// The identity provider hasn't finished in the browser yet.
    SsoPending,
    /// An organisation policy forbids this.
    OrgPolicy,
    /// This would leave organisation vaults with nobody able to manage them: ask, then try again
    /// with `orphanVaults`.
    OrgVaultOrphaned,
    /// The identity provider settings don't work (the server's reason is in `reason`).
    SsoConfig,
    SecurityKeyCancelled,
    SecurityKeyUnsupported,
    MaskedEmailNotSetUp,
    MaskedEmailBlocked,
    MaskedEmailToken,
    MaskedEmailRateLimited,
    MaskedEmailUnreachable,
    MaskedEmailFailed,
    NoFileViewer,
    CameraUnavailable,
    /// Not a PNG, JPEG, WebP or GIF image (reading QR codes).
    InvalidImage,
    /// The import review was finished, cancelled or forgotten (the vault locked).
    ImportReviewExpired,
    /// A vault on this device only has no account: this needs Turn on sync.
    NeedsSync,
    /// A local vault's master password is too easy to guess (`localCapabilities().minScore`).
    WeakMasterPassword,
    /// A backup file that's damaged, isn't one, or doesn't open with that password or code.
    InvalidBackup,
    /// A local vault needs a name.
    InvalidName,
    /// A draft that doesn't pass `validateDraft`, or an argument out of range.
    InvalidInput,
    /// Anything the UI can only call "something went wrong".
    Unexpected,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    #[error("{code:?}: {reason}")]
    Failed { code: ErrorCode, reason: String },
}

pub type Result<T, E = VaultError> = std::result::Result<T, E>;

impl VaultError {
    pub fn new(code: ErrorCode, reason: impl Into<String>) -> Self {
        Self::Failed {
            code,
            reason: reason.into(),
        }
    }

    pub fn unexpected(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unexpected, message)
    }

    pub fn code(&self) -> ErrorCode {
        let Self::Failed { code, .. } = self;
        *code
    }
}

impl From<ErrorCode> for VaultError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code, error_code_name(code))
    }
}

/// The code as the web vault writes it (`invalidCredentials`): the key of its message in the
/// strings catalog (`errors.<name>`).
#[uniffi::export]
pub fn error_code_name(code: ErrorCode) -> String {
    let debug = format!("{code:?}");
    let mut chars = debug.chars();
    chars
        .next()
        .map(|first| first.to_ascii_lowercase().to_string() + chars.as_str())
        .unwrap_or_default()
}

impl From<octapass_mobile_vault::VaultError> for VaultError {
    fn from(error: octapass_mobile_vault::VaultError) -> Self {
        let code = match error.code {
            Code::InvalidCredentials => ErrorCode::InvalidCredentials,
            Code::SecretKeyRequired => ErrorCode::SecretKeyRequired,
            Code::InvalidSecretKey => ErrorCode::InvalidSecretKey,
            Code::EmailTaken => ErrorCode::EmailTaken,
            Code::InvalidEmail => ErrorCode::InvalidEmail,
            Code::InvalidVerificationCode => ErrorCode::InvalidVerificationCode,
            Code::SignupExpired => ErrorCode::SignupExpired,
            Code::ResetExpired => ErrorCode::ResetExpired,
            Code::InvalidRecoveryCode => ErrorCode::InvalidRecoveryCode,
            Code::SignupsClosed => ErrorCode::SignupsClosed,
            Code::InsecureServerUrl => ErrorCode::InsecureServerUrl,
            Code::ServerUnreachable => ErrorCode::ServerUnreachable,
            Code::ServerError => ErrorCode::ServerError,
            Code::RateLimited => ErrorCode::RateLimited,
            Code::SessionExpired => ErrorCode::SessionExpired,
            Code::AccountDeleted => ErrorCode::AccountDeleted,
            Code::ReauthRequired => ErrorCode::ReauthRequired,
            Code::Locked => ErrorCode::Locked,
            Code::NotFound => ErrorCode::NotFound,
            Code::ReadOnlyVault => ErrorCode::ReadOnlyVault,
            Code::UntrustedVault => ErrorCode::UntrustedVault,
            Code::InvalidImportFile => ErrorCode::InvalidImportFile,
            Code::ImportPasswordRequired => ErrorCode::ImportPasswordRequired,
            Code::WrongImportPassword => ErrorCode::WrongImportPassword,
            Code::EmailMismatch => ErrorCode::EmailMismatch,
            Code::DeviceUnlockUnsupported => ErrorCode::DeviceUnlockUnsupported,
            Code::DeviceUnlockCancelled => ErrorCode::DeviceUnlockCancelled,
            Code::DeviceUnlockFailed => ErrorCode::DeviceUnlockFailed,
            Code::PasswordRequired => ErrorCode::PasswordRequired,
            Code::InvalidTwoStepCode => ErrorCode::InvalidTwoStepCode,
            Code::TwoStepExpired => ErrorCode::TwoStepExpired,
            Code::SsoPending => ErrorCode::SsoPending,
            Code::OrgPolicy => ErrorCode::OrgPolicy,
            Code::SecurityKeyUnsupported => ErrorCode::SecurityKeyUnsupported,
            Code::QuotaExceeded => ErrorCode::QuotaExceeded,
            Code::FileTooLarge => ErrorCode::FileTooLarge,
            Code::NoFileViewer => ErrorCode::NoFileViewer,
            Code::CameraUnavailable => ErrorCode::CameraUnavailable,
            Code::NeedsSync => ErrorCode::NeedsSync,
            Code::WeakMasterPassword => ErrorCode::WeakMasterPassword,
            Code::InvalidBackup => ErrorCode::InvalidBackup,
            Code::InvalidName => ErrorCode::InvalidName,
            Code::InvalidImage => ErrorCode::InvalidImage,
            Code::ImportReviewExpired => ErrorCode::ImportReviewExpired,
            Code::Unexpected => ErrorCode::Unexpected,
        };
        Self::new(code, error.message)
    }
}

impl From<OctaPassError> for VaultError {
    fn from(error: OctaPassError) -> Self {
        match &error {
            // Grants and emergency releases that don't verify, as the web vault reports them.
            OctaPassError::Core { code, .. }
                if code == "invalid_signature" || code == "invalid_grant" =>
            {
                Self::new(ErrorCode::UntrustedVault, error.to_string())
            }
            OctaPassError::Core { code, .. } if code == "wrong_passphrase" => {
                Self::new(ErrorCode::WrongPassphrase, error.to_string())
            }
            OctaPassError::Core { code, .. } if code == "ssh_passphrase_required" => {
                Self::new(ErrorCode::SshPassphraseRequired, error.to_string())
            }
            OctaPassError::Core { code, .. } if code == "invalid_ssh_key" => {
                Self::new(ErrorCode::InvalidSshKey, error.to_string())
            }
            OctaPassError::Core { code, .. } if code == "unsupported_ssh_key" => {
                Self::new(ErrorCode::UnsupportedSshKey, error.to_string())
            }
            OctaPassError::Core { code, .. } if code == "ssh_public_key_only" => {
                Self::new(ErrorCode::SshPublicKeyOnly, error.to_string())
            }
            OctaPassError::Core { code, .. } if code == "invalid_share_link" => {
                Self::new(ErrorCode::InvalidShareLink, error.to_string())
            }
            OctaPassError::Server {
                problem_type,
                status,
                ..
            } => {
                let code = match problem_type.as_str() {
                    "already-exists" => Some(ErrorCode::AlreadyExists),
                    "family-full" => Some(ErrorCode::FamilyFull),
                    "org-vault-orphaned" => Some(ErrorCode::OrgVaultOrphaned),
                    "sso-config" => Some(ErrorCode::SsoConfig),
                    "account-exists" => Some(ErrorCode::EmailTaken),
                    "login-failed" => Some(ErrorCode::InvalidCredentials),
                    _ if *status >= 500 => Some(ErrorCode::ServerError),
                    _ => None,
                };
                match code {
                    Some(code) => Self::new(code, error.to_string()),
                    None => octapass_mobile_vault::VaultError::from(error).into(),
                }
            }
            _ => octapass_mobile_vault::VaultError::from(error).into(),
        }
    }
}

impl From<octapass_core::Error> for VaultError {
    fn from(error: octapass_core::Error) -> Self {
        OctaPassError::from(error).into()
    }
}

/// A callback the app implements failed in a way it didn't declare.
impl From<uniffi::UnexpectedUniFFICallbackError> for VaultError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::unexpected(error.reason)
    }
}

/// On sharing calls a 403 means the role or relationship doesn't allow it, not that a vault is
/// read-only.
pub(crate) fn not_allowed(error: VaultError) -> VaultError {
    match error.code() {
        ErrorCode::ReadOnlyVault => ErrorCode::NotAllowed.into(),
        _ => error,
    }
}

pub(crate) fn require(condition: bool, code: ErrorCode) -> Result<()> {
    if condition { Ok(()) } else { Err(code.into()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_have_the_web_vault_names() {
        assert_eq!(
            error_code_name(ErrorCode::InvalidCredentials),
            "invalidCredentials"
        );
        assert_eq!(
            error_code_name(ErrorCode::MaskedEmailRateLimited),
            "maskedEmailRateLimited"
        );
    }

    #[test]
    fn server_problems_and_core_errors_become_codes() {
        let code = |error: OctaPassError| VaultError::from(error).code();
        let server = |status, problem: &str| OctaPassError::Server {
            status,
            problem_type: problem.into(),
            detail: None,
        };
        assert_eq!(
            code(server(409, "already-exists")),
            ErrorCode::AlreadyExists
        );
        assert_eq!(code(server(409, "family-full")), ErrorCode::FamilyFull);
        assert_eq!(
            code(server(409, "org-vault-orphaned")),
            ErrorCode::OrgVaultOrphaned
        );
        assert_eq!(code(server(400, "sso-config")), ErrorCode::SsoConfig);
        assert_eq!(code(server(403, "forbidden")), ErrorCode::ReadOnlyVault);
        assert_eq!(code(server(503, "whatever")), ErrorCode::ServerError);
        assert_eq!(code(OctaPassError::Locked), ErrorCode::Locked);
        assert_eq!(
            code(OctaPassError::Core {
                code: "invalid_signature".into(),
                reason: String::new()
            }),
            ErrorCode::UntrustedVault
        );
        assert_eq!(
            not_allowed(VaultError::from(server(403, "forbidden"))).code(),
            ErrorCode::NotAllowed
        );
    }
}
