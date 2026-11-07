use thiserror::Error;

/// Every failure the core can report.
///
/// Messages are fixed strings: they never include secrets, plaintext or key material, so they
/// are safe to log and to show to users.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("invalid base64url data")]
    InvalidBase64,
    #[error("the key log doesn't back up this account's keys")]
    KeyLogMismatch,
    #[error("not a whole service account token")]
    InvalidServiceAccountToken,
    #[error("a service account's name is 1 to 64 characters")]
    InvalidServiceAccountName,
    #[error("invalid Secret Key")]
    InvalidSecretKey,
    #[error("invalid recovery code")]
    InvalidRecoveryCode,
    #[error("unsupported or unsafe key derivation parameters")]
    UnsupportedKdf,
    #[error("key derivation failed")]
    KdfFailed,
    #[error("malformed ciphertext")]
    MalformedCiphertext,
    #[error("unsupported ciphertext version")]
    UnsupportedVersion,
    #[error("ciphertext was encrypted with a different key")]
    WrongKey,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("malformed key material")]
    InvalidKey,
    #[error("account public keys do not match the private keys")]
    KeyMismatch,
    #[error("malformed OPAQUE message")]
    InvalidOpaqueMessage,
    #[error("OPAQUE protocol failure")]
    OpaqueProtocol,
    #[error("login failed")]
    LoginFailed,
    #[error("this device's unlock key doesn't open the account")]
    DeviceUnlockFailed,
    #[error("invalid passkey request")]
    InvalidPasskeyRequest,
    #[error("this site can't use passkeys for that relying party")]
    PasskeyRpMismatch,
    #[error("passkeys aren't allowed in this frame")]
    PasskeyFrameNotAllowed,
    #[error("none of the requested passkey algorithms is supported")]
    PasskeyUnsupportedAlgorithm,
    #[error("a passkey for this account already exists")]
    PasskeyExcluded,
    #[error("no matching passkey")]
    PasskeyNotFound,
    #[error("vault key is not open in this session")]
    VaultNotOpen,
    #[error("invalid vault or item id")]
    InvalidId,
    #[error("invalid item JSON")]
    InvalidItem,
    #[error("invalid account bundle")]
    InvalidAccountBundle,
    #[error("invalid TOTP secret or URI")]
    InvalidTotp,
    #[error("invalid generator options")]
    InvalidGeneratorOptions,
    #[error("the file is not in the chosen import format")]
    InvalidImportFile,
    #[error("this export is protected by a password")]
    ImportPasswordRequired,
    #[error("wrong password for this export")]
    WrongImportPassword,
    #[error("this kind of export can't be imported")]
    UnsupportedImport,
    /// The file is OpenPGP-encrypted and this build has no OpenPGP (the `pgp` feature): a build
    /// with it can read the file.
    #[error("this build can't open OpenPGP-encrypted files")]
    PgpUnavailable,
    #[error("invalid URL")]
    InvalidUrl,
    #[error("invalid password rules")]
    InvalidPasswordRules,
    #[error("malformed local vault")]
    InvalidLocalVault,
    #[error("malformed or unsupported backup file")]
    InvalidBackup,
    #[error("this vault also needs the device's hardware secret")]
    HardwareSecretRequired,
    #[error("the master password is too weak for a vault that isn't bound to a device chip")]
    WeakMasterPassword,
    #[error("no item with this id")]
    ItemNotFound,
    #[error("signature doesn't verify")]
    InvalidSignature,
    #[error("this grant is for another vault or account")]
    InvalidGrant,
    #[error("this share link's key doesn't open it")]
    InvalidShareLink,
    #[error("wrong or missing passphrase")]
    WrongPassphrase,
    #[error("an export is written as items, then files, then the end")]
    InvalidExport,
    #[error("the image can't be read")]
    InvalidImage,
    #[error("not an SSH private key, or it's damaged")]
    InvalidSshKey,
    #[error("this kind of SSH key or key file can't be read or converted")]
    UnsupportedSshKey,
    #[error("this SSH key is protected by a passphrase")]
    SshPassphraseRequired,
    #[error("this is an SSH public key, not the private key")]
    SshPublicKeyOnly,
    #[error("this SSH key can't sign this way")]
    SshSignatureRefused,
    #[error("not an OpenPGP private key, or it's damaged")]
    InvalidGpgKey,
    // Developer toolkit (plan 16).
    #[error("this tool doesn't exist in this build")]
    UnknownTool,
    #[error("invalid tool input")]
    InvalidToolInput,
    #[error("the text can't be decoded in this format")]
    InvalidEncoding,
    #[error("this algorithm isn't supported")]
    UnsupportedAlgorithm,
    #[error("these cost settings are outside the safe range")]
    InvalidHashParameters,
    #[error("not a key in a format this tool reads, or it's damaged")]
    InvalidKeyFile,
    #[error("this file holds a public key, and this needs the private key")]
    PrivateKeyRequired,
    #[error("the key doesn't fit this algorithm")]
    KeyAlgorithmMismatch,
    #[error("not a JWT, JWS or JWE")]
    InvalidToken,
    #[error("no key in the set matches this token")]
    NoMatchingKey,
    #[error("not a certificate or certificate request, or it's damaged")]
    InvalidCertificate,
    #[error("the certificate and private key don't match")]
    CertificateKeyMismatch,
    #[error("not a PKCS#12 file, or the password is wrong")]
    InvalidPkcs12,
    #[error("this CA can't issue for that name")]
    NameNotPermitted,
    #[error("invalid ACME response")]
    InvalidAcme,
    #[error("the save inbox is full: unlock to save more")]
    InboxFull,
}

impl Error {
    /// A stable, machine-readable code for this error, for clients that map errors to messages.
    pub fn code(self) -> &'static str {
        match self {
            Error::InvalidBase64 => "invalid_base64",
            Error::KeyLogMismatch => "key_log_mismatch",
            Error::InvalidSecretKey => "invalid_secret_key",
            Error::InvalidRecoveryCode => "invalid_recovery_code",
            Error::UnsupportedKdf => "unsupported_kdf",
            Error::KdfFailed => "kdf_failed",
            Error::MalformedCiphertext => "malformed_ciphertext",
            Error::UnsupportedVersion => "unsupported_version",
            Error::WrongKey => "wrong_key",
            Error::DecryptionFailed => "decryption_failed",
            Error::EncryptionFailed => "encryption_failed",
            Error::InvalidKey => "invalid_key",
            Error::KeyMismatch => "key_mismatch",
            Error::InvalidOpaqueMessage => "invalid_opaque_message",
            Error::OpaqueProtocol => "opaque_protocol",
            Error::LoginFailed => "login_failed",
            Error::DeviceUnlockFailed => "device_unlock_failed",
            Error::InvalidPasskeyRequest => "invalid_passkey_request",
            Error::PasskeyRpMismatch => "passkey_rp_mismatch",
            Error::PasskeyFrameNotAllowed => "passkey_frame_not_allowed",
            Error::PasskeyUnsupportedAlgorithm => "passkey_unsupported_algorithm",
            Error::PasskeyExcluded => "passkey_excluded",
            Error::PasskeyNotFound => "passkey_not_found",
            Error::VaultNotOpen => "vault_not_open",
            Error::InvalidId => "invalid_id",
            Error::InvalidItem => "invalid_item",
            Error::InvalidAccountBundle => "invalid_account_bundle",
            Error::InvalidTotp => "invalid_totp",
            Error::InvalidGeneratorOptions => "invalid_generator_options",
            Error::InvalidImportFile => "invalid_import_file",
            Error::ImportPasswordRequired => "import_password_required",
            Error::WrongImportPassword => "wrong_import_password",
            Error::UnsupportedImport => "unsupported_import",
            Error::PgpUnavailable => "pgp_unavailable",
            Error::InvalidUrl => "invalid_url",
            Error::InvalidPasswordRules => "invalid_password_rules",
            Error::InvalidLocalVault => "invalid_local_vault",
            Error::InvalidBackup => "invalid_backup",
            Error::HardwareSecretRequired => "hardware_secret_required",
            Error::WeakMasterPassword => "weak_master_password",
            Error::ItemNotFound => "item_not_found",
            Error::InvalidSignature => "invalid_signature",
            Error::InvalidGrant => "invalid_grant",
            Error::InvalidShareLink => "invalid_share_link",
            Error::WrongPassphrase => "wrong_passphrase",
            Error::InvalidExport => "invalid_export",
            Error::InvalidImage => "invalid_image",
            Error::InvalidSshKey => "invalid_ssh_key",
            Error::UnsupportedSshKey => "unsupported_ssh_key",
            Error::SshPassphraseRequired => "ssh_passphrase_required",
            Error::SshPublicKeyOnly => "ssh_public_key_only",
            Error::InvalidServiceAccountToken => "invalid_service_account_token",
            Error::InvalidServiceAccountName => "invalid_service_account_name",
            Error::SshSignatureRefused => "ssh_signature_refused",
            Error::InvalidGpgKey => "invalid_gpg_key",
            Error::UnknownTool => "unknown_tool",
            Error::InvalidToolInput => "invalid_tool_input",
            Error::InvalidEncoding => "invalid_encoding",
            Error::UnsupportedAlgorithm => "unsupported_algorithm",
            Error::InvalidHashParameters => "invalid_hash_parameters",
            Error::InvalidKeyFile => "invalid_key_file",
            Error::PrivateKeyRequired => "private_key_required",
            Error::KeyAlgorithmMismatch => "key_algorithm_mismatch",
            Error::InvalidToken => "invalid_token",
            Error::NoMatchingKey => "no_matching_key",
            Error::InvalidCertificate => "invalid_certificate",
            Error::CertificateKeyMismatch => "certificate_key_mismatch",
            Error::InvalidPkcs12 => "invalid_pkcs12",
            Error::NameNotPermitted => "name_not_permitted",
            Error::InvalidAcme => "invalid_acme",
            Error::InboxFull => "inbox_full",
        }
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
