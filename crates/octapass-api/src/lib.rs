//! Request and response types for the Octa Pass sync API v1.
//!
//! Every type serialises as camelCase JSON. Binary values (salts, OPAQUE
//! messages, ciphertext envelopes, keys) are base64url strings without padding.
//! The server stores and returns ciphertext only.

use serde::{Deserialize, Serialize};

pub mod problem;

pub use problem::Problem;

/// The API version served under `/v1`.
pub const API_VERSION: u32 = 1;

/// Whether new accounts can be created on a server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum SignupMode {
    Open,
    Invite,
    Closed,
}

/// `GET /v1/server-info`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub api_version: u32,
    pub signups: SignupMode,
    /// Phones can register for pushes (`PUT /v1/devices/current/push`): the server is set up with
    /// a push relay and registered with it.
    pub push_relay: bool,
    /// This server has its own masked email service: the routes under `/v1/masked-email` work.
    /// Absent on older servers.
    #[serde(default)]
    pub masked_email_relay: bool,
    /// An HIBP key is set, so `POST /v1/health/breach-email` answers.
    #[serde(default)]
    pub email_breach_checks: bool,
}

/// One address on the server's masked email service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct MaskedEmailAlias {
    pub id: String,
    /// The whole address, `id@domain`.
    pub address: String,
    pub enabled: bool,
    /// The service stopped forwarding after bounces or spam reports. Setting `enabled` to true
    /// starts it again.
    pub paused: bool,
    /// Messages forwarded to the account's email.
    pub forwarded: i64,
    /// Messages refused: blocked senders and failed sender checks.
    pub blocked: i64,
    /// Replies sent out through the alias.
    pub replied: i64,
    pub created_at: String,
}

/// `GET /v1/masked-email/aliases`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct MaskedEmailAliases {
    pub aliases: Vec<MaskedEmailAlias>,
    pub max_aliases: i64,
    pub domain: String,
}

/// `PATCH /v1/masked-email/aliases/{id}`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SetMaskedEmailEnabled {
    pub enabled: bool,
}

/// `POST /v1/masked-email/aliases/{id}/block` and `/unblock`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct MaskedEmailSender {
    pub sender: String,
}

/// `POST /v1/health/breach-email`. In the body so the address stays out of URLs and logs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BreachEmailRequest {
    pub email: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct BreachEmailResponse {
    pub breaches: Vec<EmailBreach>,
}

/// A breach, from Have I Been Pwned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct EmailBreach {
    /// HIBP's stable name for it.
    pub name: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breach_date: Option<String>,
    #[serde(default)]
    pub data_classes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum KdfAlgorithm {
    Argon2id,
}

/// Password KDF parameters, stored per account so they can be raised later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// `POST /v1/auth/prelogin`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PreloginRequest {
    pub email: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: KdfParams,
    /// base64url, 16 bytes. Unknown emails get a deterministic fake salt.
    pub account_salt: String,
}

/// `POST /v1/auth/register/start`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RegisterStartRequest {
    pub email: String,
    /// base64url OPAQUE `RegistrationRequest`.
    pub registration_request: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RegisterStartResponse {
    /// base64url OPAQUE `RegistrationResponse`.
    pub registration_response: String,
    pub verification_required: bool,
    /// Only present when the server runs in dev mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_verification_code: Option<String>,
}

/// The encrypted account keys and public keys. Nothing in it is readable by
/// the server except the email, KDF parameters, salt and public keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountBundle {
    /// Present in responses, ignored in requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    pub email: String,
    pub kdf: KdfParams,
    /// base64url, 16 bytes.
    pub account_salt: String,
    /// Ciphertext envelope: the Account Symmetric Key sealed by the Account Unlock Key.
    pub wrapped_ask: String,
    /// base64url X25519 public key (32 bytes).
    pub public_enc_key: String,
    /// base64url Ed25519 public key (32 bytes).
    pub public_sign_key: String,
    /// Ciphertext envelope: the account private keys sealed by the ASK.
    pub wrapped_private_keys: String,
    /// Ciphertext envelope: the ASK sealed by the recovery code.
    pub recovery_wrapped_ask: String,
    /// Ciphertext envelope: the ML-KEM-768 seed sealed by the ASK. Set by `POST
    /// /v1/transparency/publish`, ignored in sign-up requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_pq_private_key: Option<String>,
    /// The account's signed key record. Set by `POST /v1/transparency/publish`, ignored in
    /// sign-up requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_record: Option<KeyRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct NewPersonalVault {
    /// UUIDv7 generated by the client.
    pub id: String,
    /// Ciphertext envelope: the vault key sealed by the ASK.
    pub wrapped_vault_key: String,
}

/// `POST /v1/auth/register/finish`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishRequest {
    pub email: String,
    /// The 6-digit code sent by email.
    pub verification_code: String,
    /// base64url OPAQUE `RegistrationUpload`.
    pub registration_upload: String,
    pub account: AccountBundle,
    pub personal_vault: NewPersonalVault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RegisterFinishResponse {
    pub account_id: String,
}

/// `POST /v1/auth/login/start`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct LoginStartRequest {
    pub email: String,
    /// base64url OPAQUE `CredentialRequest`.
    pub credential_request: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct LoginStartResponse {
    /// Opaque handle for `login/finish`, valid for 30 seconds.
    pub login_id: String,
    /// base64url OPAQUE `CredentialResponse`.
    pub credential_response: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    /// Shown to the user in their device list. At most 64 characters.
    pub name: String,
    /// For example `web`, `macos`, `ios`. At most 32 characters.
    pub platform: String,
}

/// `POST /v1/auth/login/finish`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct LoginFinishRequest {
    pub login_id: String,
    /// base64url OPAQUE `CredentialFinalization`.
    pub credential_finalization: String,
    pub device: DeviceInfo,
    /// From an earlier sign-in on this device. A valid one skips two-step sign-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_device_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct LoginFinishResponse {
    pub access_token: String,
    pub refresh_token: String,
    /// Access token lifetime in seconds.
    pub expires_in: u64,
    pub account: AccountBundle,
    /// Keep it with the session and send it on the next sign-in from this device, so that sign-in
    /// skips the second step. Replaces any token sent with the login. It works only while this
    /// device is still in the account's device list (not signed out, session not lapsed), for at
    /// most 30 days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_device_token: Option<String>,
}

/// A way to finish two-step sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SecondFactorMethod {
    /// A 6-digit code from an authenticator app (RFC 6238: SHA-1, 30 seconds).
    Totp,
    /// A security key or passkey registered for this account.
    Webauthn,
    /// One of the single-use recovery codes.
    RecoveryCode,
}

/// WebAuthn `PublicKeyCredentialRequestOptions` for the second step, binary values as base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnRequestOptions {
    pub challenge: String,
    pub rp_id: String,
    /// Credential ids of the account's security keys.
    pub allow_credentials: Vec<String>,
    /// Milliseconds.
    pub timeout: u64,
    /// `discouraged`: the password already ran, the key only proves possession.
    pub user_verification: String,
}

/// The `secondFactor` member of a `second-factor-required` problem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SecondFactorChallenge {
    /// For `login/second-factor`. Single use, valid for `expiresIn` seconds.
    pub challenge_id: String,
    pub methods: Vec<SecondFactorMethod>,
    /// Present when `methods` includes `webauthn`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebAuthnRequestOptions>,
    pub expires_in: u64,
}

/// A WebAuthn assertion (`AuthenticatorAssertionResponse`), binary values as base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnAssertion {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// `POST /v1/auth/login/second-factor`: exactly one of `totpCode`, `recoveryCode` and `webauthn`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SecondFactorRequest {
    pub challenge_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_code: Option<String>,
    /// Spaces, dashes and case don't matter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebAuthnAssertion>,
}

/// `POST /v1/auth/refresh`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
    /// The previous refresh token stops working. Presenting it again revokes the session.
    pub refresh_token: String,
    pub expires_in: u64,
    /// No longer sent: a device is trusted only from its own sign-in. Kept so older clients and
    /// servers still understand each other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_device_token: Option<String>,
}

/// What a reauth token may be used for. Each token works for one purpose, once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ReauthPurpose {
    DeleteAccount,
    /// A new master password: `PUT /v1/account/password`.
    ChangePassword,
    /// Turning two-step sign-in on or off, adding or removing a method, new recovery codes.
    TwoStep,
    /// A new Secret Key: `PUT /v1/account/secret-key`.
    RotateSecretKey,
    /// The contact's own reauth before `POST /v1/emergency-contacts/{id}/takeover`.
    EmergencyTakeover,
    /// Deleting an organisation or one of its vaults.
    Organisation,
}

impl ReauthPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeleteAccount => "delete-account",
            Self::ChangePassword => "change-password",
            Self::TwoStep => "two-step",
            Self::RotateSecretKey => "rotate-secret-key",
            Self::EmergencyTakeover => "emergency-takeover",
            Self::Organisation => "organisation",
        }
    }
}

/// `POST /v1/auth/reauth/start`: a fresh OPAQUE login by a signed-in user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ReauthStartRequest {
    /// base64url OPAQUE `CredentialRequest`.
    pub credential_request: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ReauthStartResponse {
    pub reauth_id: String,
    /// base64url OPAQUE `CredentialResponse`.
    pub credential_response: String,
}

/// `POST /v1/auth/reauth/finish`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ReauthFinishRequest {
    pub reauth_id: String,
    /// base64url OPAQUE `CredentialFinalization`.
    pub credential_finalization: String,
    pub purpose: ReauthPurpose,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ReauthFinishResponse {
    /// Send as the `X-Reauth-Token` header. Single use.
    pub reauth_token: String,
    /// Lifetime in seconds (300).
    pub expires_in: u64,
}

/// The header that carries a reauth token.
pub const REAUTH_TOKEN_HEADER: &str = "x-reauth-token";

/// `DELETE /v1/account`, with the `X-Reauth-Token` header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteAccountRequest {
    /// Must equal the account email (compared after trimming and lowercasing).
    pub confirm_email: String,
}

/// The password-dependent part of the account bundle, as a master password change or reset
/// replaces it. The ASK itself stays the same, so nothing else is re-encrypted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CredentialsUpdate {
    pub kdf: KdfParams,
    /// base64url, 16 bytes. A new one with every change.
    pub account_salt: String,
    /// Ciphertext envelope: the ASK sealed by the new Account Unlock Key.
    pub wrapped_ask: String,
    /// Ciphertext envelope: the ASK sealed by a new recovery code. Required by a reset, which
    /// always replaces the recovery code; optional for a change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_ask: Option<String>,
}

/// `POST /v1/account/password/registration` and `POST /v1/auth/recover/registration`: the OPAQUE
/// registration for the new master password. Nothing is stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PasswordRegistrationRequest {
    /// Only for `recover/registration`: the reset it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<String>,
    /// base64url OPAQUE `RegistrationRequest`.
    pub registration_request: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PasswordRegistrationResponse {
    /// base64url OPAQUE `RegistrationResponse`.
    pub registration_response: String,
}

/// `PUT /v1/account/password`, with the `X-Reauth-Token` header (purpose `change-password`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    /// base64url OPAQUE `RegistrationUpload` for the new master password.
    pub registration_upload: String,
    pub account: CredentialsUpdate,
}

/// `POST /v1/emergency-contacts/{id}/takeover`, with the `X-Reauth-Token` header of the contact's
/// own account (purpose `emergency-takeover`). See plan 06, "Takeover design".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct EmergencyTakeoverRequest {
    /// base64url OPAQUE `RegistrationUpload` for the grantor's new master password.
    pub registration_upload: String,
    /// `recoveryWrappedAsk` is required: a takeover always replaces the recovery code.
    pub account: CredentialsUpdate,
    /// base64url Ed25519 signature by the grantor's signing key over
    /// `"openpass/v1/emergency-takeover" ‖ 0x00 ‖` length-prefixed `recordId, grantorId,
    /// contactId, currentAccountSalt, registrationUpload, accountSalt, wrappedAsk,
    /// recoveryWrappedAsk`.
    pub signature: String,
}

/// `POST /v1/emergency-contacts/{id}/takeover/registration`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TakeoverRegistrationRequest {
    /// base64url OPAQUE `RegistrationRequest`.
    pub registration_request: String,
}

/// `POST /v1/auth/recover/start`: a master password reset with the recovery code begins with a
/// code sent to the account's email.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RecoverStartRequest {
    pub email: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RecoverStartResponse {
    /// Names this reset in the next calls. Returned whether or not the email has an account.
    pub recovery_id: String,
    /// Only present when the server runs in dev mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev_verification_code: Option<String>,
}

/// `POST /v1/auth/recover/verify`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RecoverVerifyRequest {
    pub recovery_id: String,
    /// The 6-digit code sent by email.
    pub verification_code: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RecoverVerifyResponse {
    /// The account bundle: the recovery code unwraps its `recoveryWrappedAsk` on the device.
    pub account: AccountBundle,
    /// base64url, 32 bytes. Signed in `recover/finish`.
    pub challenge: String,
}

/// `POST /v1/auth/recover/finish`. The account's sessions all end; sign in with the new master
/// password afterwards (with the second step, if two-step sign-in is on).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RecoverFinishRequest {
    pub recovery_id: String,
    /// base64url OPAQUE `RegistrationUpload` for the new master password.
    pub registration_upload: String,
    /// Must include `recoveryWrappedAsk`.
    pub account: CredentialsUpdate,
    /// base64url Ed25519 signature by the account's signing key over
    /// `"openpass/v1/account-recovery" ‖ 0x00` and then, each as a u32 big-endian length and its
    /// UTF-8 bytes: accountId, challenge, registrationUpload, accountSalt, wrappedAsk,
    /// recoveryWrappedAsk. Proves the device opened the account key.
    pub signature: String,
}

/// A security key or passkey registered for two-step sign-in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SecurityKeyRecord {
    pub id: String,
    pub name: String,
    /// RFC 3339 timestamp.
    pub created_at: String,
    /// RFC 3339 timestamp of the last sign-in with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

/// `GET /v1/account/two-step`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TwoStepStatus {
    /// Whether signing in on a new device asks for a second step.
    pub enabled: bool,
    /// Empty when two-step sign-in is off.
    pub methods: Vec<SecondFactorMethod>,
    pub security_keys: Vec<SecurityKeyRecord>,
    pub recovery_codes_left: u32,
    /// The WebAuthn relying party id security keys are registered for.
    pub rp_id: String,
}

/// `POST /v1/account/two-step/totp`: a new authenticator secret, not active until confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TotpSetupResponse {
    pub setup_id: String,
    /// Base32 (RFC 4648, no padding), for typing into an authenticator app.
    pub secret: String,
    /// `otpauth://totp/…`, for the QR code.
    pub otpauth_uri: String,
    /// Seconds until the setup expires.
    pub expires_in: u64,
}

/// `POST /v1/account/two-step/totp/confirm`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TotpConfirmRequest {
    pub setup_id: String,
    /// The current code from the authenticator app.
    pub code: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct TotpConfirmResponse {
    /// Only when this turned two-step sign-in on: shown once, never retrievable again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
}

/// `POST /v1/account/two-step/recovery-codes`: replaces every earlier code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnRelyingParty {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnUser {
    /// base64url, random per account (not the account id).
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// WebAuthn `PublicKeyCredentialCreationOptions`, binary values as base64url. Attestation is
/// `none`; ES256 (-7) and Ed25519 (-8) keys are accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnCreationOptions {
    pub challenge: String,
    pub rp: WebAuthnRelyingParty,
    pub user: WebAuthnUser,
    /// COSE algorithm ids, in order of preference.
    pub algorithms: Vec<i64>,
    /// Credential ids already registered, so the same key isn't added twice.
    pub exclude_credentials: Vec<String>,
    /// Milliseconds.
    pub timeout: u64,
}

/// `POST /v1/account/two-step/security-keys/options`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SecurityKeyOptionsResponse {
    pub setup_id: String,
    pub public_key: WebAuthnCreationOptions,
}

/// `POST /v1/account/two-step/security-keys`: the `AuthenticatorAttestationResponse`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AddSecurityKeyRequest {
    pub setup_id: String,
    /// At most 64 characters.
    pub name: String,
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum VaultType {
    Personal,
    Shared,
    Family,
}

/// What a member may do. Each role includes the ones below it: `read` views, `write` also
/// edits items, `manage` also adds and removes members and rotates the key, `owner` also grants
/// and removes owners. A vault is deleted with its last owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum VaultRole {
    Read,
    Write,
    Manage,
    Owner,
}

impl VaultRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Manage => "manage",
            Self::Owner => "owner",
        }
    }

    pub fn parse(role: &str) -> Option<Self> {
        match role {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "manage" => Some(Self::Manage),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct VaultRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub vault_type: VaultType,
    /// Increases by one on every change to the vault's items. In a sync
    /// response it's the revision the response is complete up to: the
    /// current one unless `hasMore` is set.
    pub revision: u64,
    /// Personal vaults: the vault key sealed by the ASK. Shared and family vaults: the key sealed
    /// to this account's X25519 key, as signed in `grant`.
    pub wrapped_vault_key: String,
    pub role: VaultRole,
    /// Shared and family vaults: base64url key id of the current vault key. Item writes whose
    /// `encryptedItemKey` was wrapped under another key are refused with `vault-key-changed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Shared and family vaults: the rest of this account's signed grant. Verify it against
    /// `granterPublicSignKey` before using the vault key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<VaultGrant>,
    /// The organisation this shared vault belongs to. It opens like any shared vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

/// The signature half of a grant. With the vault id, this account's id, `role` and
/// `wrappedVaultKey` from the `VaultRecord`, it is the whole signed grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct VaultGrant {
    pub granted_by: String,
    /// base64url Ed25519 public key of the granter, as it was when they signed. Compare its
    /// fingerprint out of band before trusting it.
    pub granter_public_sign_key: String,
    /// Unix milliseconds, as signed.
    pub granted_at: u64,
    /// base64url Ed25519 signature.
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ItemRecord {
    pub id: String,
    pub vault_id: String,
    /// The vault revision of the item's last change.
    pub revision: u64,
    pub encrypted_item_key: String,
    pub overview: String,
    pub details: String,
    /// RFC 3339 timestamp.
    pub updated_at: String,
    /// RFC 3339 timestamp. Set while the item is in the trash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

/// A permanently removed item. Kept for 90 days so other devices learn about it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeletedItem {
    pub vault_id: String,
    pub item_id: String,
    pub revision: u64,
}

/// `GET /v1/sync`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    /// Every vault the account can access, with its current revision.
    pub vaults: Vec<VaultRecord>,
    /// Items changed after the requested revision, including items in the trash.
    pub items: Vec<ItemRecord>,
    pub deleted: Vec<DeletedItem>,
    /// The response stopped at a page limit. Store the vault revisions and
    /// sync again with them as `since`.
    #[serde(default)]
    pub has_more: bool,
}

/// `PUT /v1/vaults/{vaultId}/items/{itemId}`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PutItemRequest {
    /// Ciphertext envelope: the item key sealed by the vault key.
    pub encrypted_item_key: String,
    /// Ciphertext envelope of the item overview.
    pub overview: String,
    /// Ciphertext envelope of the item details.
    pub details: String,
    /// The write is bookkeeping, not an edit (a one-time code's counter moving): the version it
    /// replaces isn't added to the item's history.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub skip_history: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RevisionResponse {
    pub revision: u64,
}

/// One past version of an item, as it was before an edit. Opened with the item's current key: an
/// edit keeps the key, and rotating the vault key only re-wraps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ItemRevision {
    /// The vault revision this version was written at.
    pub revision: u64,
    /// Ciphertext envelope of the overview.
    pub overview: String,
    /// Ciphertext envelope of the details.
    pub details: String,
    /// RFC 3339 timestamp: when this version was written.
    pub updated_at: String,
}

/// `GET /v1/vaults/{vaultId}/items/{itemId}/history`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ItemHistoryResponse {
    /// Newest first, at most 10.
    pub revisions: Vec<ItemRevision>,
}

/// An encrypted file kept with an item. Its name, type, size and key are in the
/// item's encrypted details; the server knows only the stored size.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRecord {
    pub id: String,
    pub vault_id: String,
    pub item_id: String,
    /// Stored (encrypted) bytes, as counted against the quota.
    pub size: u64,
    /// RFC 3339 timestamp.
    pub created_at: String,
}

/// `GET /v1/vaults/{vaultId}/items/{itemId}/attachments`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AttachmentsResponse {
    pub attachments: Vec<AttachmentRecord>,
}

/// `GET /v1/account/usage`: what the vaults the account owns hold (trash
/// included), and the server's limits. Shared vaults count against their owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct UsageResponse {
    pub items: u64,
    pub max_items: u64,
    /// Stored bytes of item ciphertext.
    pub item_bytes: u64,
    pub max_item_bytes: u64,
    /// Stored bytes of attachments.
    pub attachment_bytes: u64,
    pub max_attachment_bytes: u64,
    /// The largest single attachment, as stored (encrypted).
    pub max_file_bytes: u64,
}

/// The precondition on a batch operation: a revision, or `"*"` for any revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(untagged)]
pub enum IfMatch {
    Revision(u64),
    Any(AnyRevision),
}

/// The literal `"*"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum AnyRevision {
    #[serde(rename = "*")]
    Any,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum BatchOp {
    Put,
    Delete,
    Restore,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct BatchOperation {
    pub op: BatchOp,
    pub vault_id: String,
    pub item_id: String,
    /// `put`: omit to create, a revision to update, `"*"` to update whatever is
    /// stored. `delete`: required, a revision or `"*"`. `restore`: ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_match: Option<IfMatch>,
    /// Required for `put`, ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<PutItemRequest>,
}

/// `POST /v1/batch`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct BatchRequest {
    /// At most 1,000, each item at most once.
    pub operations: Vec<BatchOperation>,
}

/// The outcome of one operation, in request order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct BatchResult {
    pub item_id: String,
    /// The HTTP status the single-item endpoint would have answered.
    pub status: u16,
    /// Set when `status` is 200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    /// Set when the operation failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<Problem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct BatchResponse {
    pub results: Vec<BatchResult>,
}

/// A member's sealed and signed copy of a vault key, made on the granter's device. The server
/// checks its shape and who may grant what, but can't open it or check the signature's meaning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub vault_id: String,
    pub recipient_account_id: String,
    pub role: VaultRole,
    /// The vault key sealed to the recipient: 105 bytes, base64url.
    pub wrapped_vault_key: String,
    /// Must be the signed-in account.
    pub granted_by: String,
    /// Unix milliseconds.
    pub granted_at: u64,
    /// base64url Ed25519 signature (64 bytes).
    pub signature: String,
}

/// `POST /v1/vaults`: a shared vault and the owner's own grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultRequest {
    /// UUIDv7 generated by the client.
    pub id: String,
    /// base64url key id (16 bytes) of the vault key.
    pub key_id: String,
    /// Role `owner`, to the signed-in account, by the signed-in account.
    pub grant: Grant,
}

/// A vault member, with the public keys other members seal to and verify against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct MemberRecord {
    pub account_id: String,
    pub email: String,
    pub role: VaultRole,
    pub public_enc_key: String,
    pub public_sign_key: String,
    /// The member's signed key record, which carries their ML-KEM key. Absent until one of the
    /// member's devices publishes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_record: Option<KeyRecord>,
    /// Six groups of four digits. Clients compute it themselves from the keys: a server could
    /// lie about both.
    pub fingerprint: String,
    /// Absent for a personal vault's owner, who holds no grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    /// RFC 3339 timestamp.
    pub added_at: String,
}

/// `GET /v1/vaults/{vaultId}/members`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct MembersResponse {
    pub members: Vec<MemberRecord>,
}

/// `POST /v1/vaults/{vaultId}/members` and `POST /v1/families/{familyId}/invites`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct InviteRequest {
    pub email: String,
    /// For the account `GET /v1/accounts/lookup` returned for that email.
    pub grant: Grant,
    /// base64url key id of the vault key the grant seals. When given, a key rotated since
    /// fails with `vault-key-changed`, so no grant of an old key is stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

/// An item's re-wrapped item key, in a key rotation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ItemKeyUpdate {
    pub item_id: String,
    pub encrypted_item_key: String,
}

/// `POST /v1/vaults/{vaultId}/rotate`: a new vault key, in one transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RotateVaultRequest {
    /// The vault revision the client synced to. Anything newer fails with `vault-changed`.
    pub revision: u64,
    /// base64url key id of the new vault key.
    pub key_id: String,
    /// Exactly one per current member, with the member's current role.
    pub grants: Vec<Grant>,
    /// Every item in the vault, trash included, wrapped under the new key.
    pub items: Vec<ItemKeyUpdate>,
    /// A personal vault only, which has no grants: the new key wrapped by the account key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_vault_key: Option<String>,
    /// Family vaults: a grant of the new key for each pending invite to keep, with the
    /// invite's role. Pending invites left out are cancelled, so none keeps the old key.
    #[serde(default)]
    pub invites: Vec<Grant>,
    /// A grant of the new key for each active service account (`recipientAccountId` is its id,
    /// with its role). One left out can no longer read the vault and needs a new token.
    #[serde(default)]
    pub service_grants: Vec<Grant>,
}

/// `POST /v1/vaults/{vaultId}/service-accounts`. Everything was made on the creator's device; the
/// token isn't here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateServiceAccountRequest {
    pub id: String,
    /// base64url X25519 public key, 32 bytes.
    pub public_enc_key: String,
    /// base64url Ed25519 public key, 32 bytes.
    pub public_sign_key: String,
    /// The name, sealed so that only the creator can read it.
    pub encrypted_name: String,
    /// `recipientAccountId` is the service account's id. Role `read` or `write`.
    pub grant: Grant,
    /// base64url id of the vault key the grant seals.
    pub key_id: String,
    /// RFC 3339. Left out, it lasts until it's revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// A service account, as `GET /v1/vaults/{vaultId}/service-accounts` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountRecord {
    pub id: String,
    pub vault_id: String,
    pub created_by: String,
    pub role: VaultRole,
    pub public_enc_key: String,
    pub encrypted_name: String,
    /// The account that signed its current grant. When that isn't `createdBy`, the token can't
    /// verify the grant and a new one is needed.
    pub granted_by: String,
    /// RFC 3339 timestamp.
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountsResponse {
    pub service_accounts: Vec<ServiceAccountRecord>,
}

/// `POST /v1/service-accounts/challenge`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountChallengeRequest {
    pub service_account_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountChallengeResponse {
    /// base64url, single use, good for a minute.
    pub challenge: String,
}

/// `POST /v1/service-accounts/session`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountSessionRequest {
    pub service_account_id: String,
    pub challenge: String,
    /// base64url Ed25519 signature over the auth message (plan 03).
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountSessionResponse {
    pub access_token: String,
    /// Seconds.
    pub expires_in: u64,
}

/// `GET /v1/accounts/lookup?email=`: what a client needs to seal a key to an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct AccountLookupResponse {
    pub account_id: String,
    pub email: String,
    pub public_enc_key: String,
    pub public_sign_key: String,
    /// The account's signed key record, which carries its ML-KEM key. Absent until one of the
    /// account's devices publishes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_record: Option<KeyRecord>,
    /// Six groups of four digits, for display. Clients should compute their own from the keys.
    pub fingerprint: String,
}

/// What an account says about its own public keys, signed by its Ed25519 key. Its hash is what
/// the key log holds. See `docs/developers/sync-api.md`, "Key log".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyRecord {
    /// base64url id of the log this record is for.
    pub log_id: String,
    pub account_id: String,
    /// base64url label of the account's email (32 bytes).
    pub label: String,
    pub public_enc_key: String,
    pub public_sign_key: String,
    /// base64url ML-KEM-768 encapsulation key (1,184 bytes).
    pub public_pq_key: String,
    /// Unix milliseconds.
    pub created_at: u64,
    /// base64url Ed25519 signature by `publicSignKey`.
    pub signature: String,
}

/// The log's public keys, which clients pin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogIdentity {
    /// base64url Ed25519 public key that signs heads.
    pub sign_key: String,
    /// base64url ristretto255 element: the VOPRF public key behind labels.
    pub oprf_key: String,
}

/// A signed tree head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogHead {
    pub tree_size: u64,
    /// base64url SHA-256.
    pub root_hash: String,
    /// Unix milliseconds.
    pub timestamp: u64,
    /// base64url Ed25519 signature.
    pub signature: String,
}

/// The witnesses a key log sends its checkpoints to (plan 03, "Witnesses").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogWitnessPolicy {
    /// C2SP verifier keys (`name+id+base64`), Ed25519 cosignature/v1.
    pub witnesses: Vec<String>,
    /// How many of them must have cosigned.
    pub quorum: u32,
}

/// The newest checkpoint a quorum of witnesses cosigned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogWitnessed {
    /// A C2SP checkpoint as a signed note: the log's signature, then the witnesses'.
    pub checkpoint: String,
    /// RFC 9162 consistency proof from the checkpoint's size to `head`, base64url hashes.
    pub consistency: Vec<String>,
}

/// `GET /v1/transparency/head?since=`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogHeadResponse {
    pub log: KeyLogIdentity,
    pub head: KeyLogHead,
    /// RFC 9162 consistency proof from the size in `since` to this head, base64url hashes.
    pub consistency: Vec<String>,
    /// Absent when the log has no witnesses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<KeyLogWitnessPolicy>,
    /// Absent until a quorum of witnesses has cosigned a checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnessed: Option<KeyLogWitnessed>,
}

/// A label's latest record and its audit path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogEntry {
    pub leaf_index: u64,
    pub record: KeyRecord,
    /// RFC 9162 audit path to `head`, base64url hashes.
    pub inclusion: Vec<String>,
}

/// `GET /v1/transparency/proof?label=&since=`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogProofResponse {
    pub log: KeyLogIdentity,
    pub head: KeyLogHead,
    pub consistency: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<KeyLogWitnessPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnessed: Option<KeyLogWitnessed>,
    /// Absent when nothing is logged under the label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<KeyLogEntry>,
}

/// `GET /v1/transparency/entries?start=&end=`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogEntriesResponse {
    pub start: u64,
    /// The perfect subtrees covering every leaf before `start`, largest first, base64url.
    pub frontier: Vec<String>,
    /// base64url concatenation of 64-byte leaves.
    pub leaves: String,
}

/// `POST /v1/transparency/label`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogLabelRequest {
    /// base64url blinded element (RFC 9497 VOPRF, ristretto255-SHA512).
    pub blinded: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct KeyLogLabelResponse {
    pub evaluated: String,
    pub proof: String,
}

/// `POST /v1/transparency/publish`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PublishKeysRequest {
    pub record: KeyRecord,
    /// Ciphertext envelope: the ML-KEM-768 seed sealed by the ASK.
    pub wrapped_pq_private_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PublishKeysResponse {
    pub leaf_index: u64,
}

/// `POST /v1/families`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateFamilyRequest {
    /// UUIDv7 generated by the client.
    pub id: String,
    /// The shared Family vault, created with the family.
    pub vault: CreateVaultRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum FamilyRole {
    Organiser,
    Member,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FamilyMember {
    pub account_id: String,
    pub email: String,
    pub role: FamilyRole,
    /// RFC 3339 timestamp.
    pub joined_at: String,
}

/// An invitation that hasn't been accepted yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FamilyInvite {
    pub family_id: String,
    pub account_id: String,
    pub email: String,
    pub organiser_email: String,
    /// RFC 3339 timestamp.
    pub invited_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FamilyRecord {
    pub id: String,
    pub organiser_id: String,
    /// The shared Family vault.
    pub vault_id: String,
    /// Members plus pending invites can't go over this.
    pub max_members: u32,
    pub members: Vec<FamilyMember>,
    /// Pending invites. Only the organiser sees them.
    pub invites: Vec<FamilyInvite>,
    /// RFC 3339 timestamp.
    pub created_at: String,
}

/// `GET /v1/families`: the family the account belongs to, and invitations to others.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct FamiliesResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<FamilyRecord>,
    pub invitations: Vec<FamilyInvite>,
}

/// `POST /v1/share-links`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateShareLinkRequest {
    /// The encrypted item snapshot. Its key stays in the link's `#` fragment.
    pub ciphertext: String,
    /// RFC 3339 timestamp, 1 hour to 30 days from now.
    pub expires_at: String,
    /// 1 to 100.
    pub max_views: u32,
    /// Whether the viewer also needs the access passphrase (the ciphertext says so too).
    pub passphrase_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateShareLinkResponse {
    /// Random and unguessable, for `/s/<id>#<key>`.
    pub id: String,
    pub expires_at: String,
}

/// `GET /v1/share-links/{id}`: counts as a view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ShareLinkResponse {
    pub ciphertext: String,
    pub passphrase_required: bool,
    pub expires_at: String,
    /// After this view. At 0 the link is already gone.
    pub views_left: u32,
}

/// One of the signed-in account's share links, without its ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ShareLinkRecord {
    pub id: String,
    pub expires_at: String,
    pub max_views: u32,
    pub views: u32,
    pub passphrase_required: bool,
    pub created_at: String,
}

/// `GET /v1/share-links`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ShareLinksResponse {
    pub links: Vec<ShareLinkRecord>,
}

/// What the emergency contact gets once access is released.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum EmergencyScope {
    /// The grantor's account key, and with it every vault the grantor can open.
    Account,
    /// One vault the grantor owns.
    #[serde(rename_all = "camelCase")]
    Vault { vault_id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum EmergencyAccessLevel {
    /// Read the items in scope.
    View,
    /// Also reset the grantor's master password. Account scope only.
    Takeover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum EmergencyStatus {
    /// Set up; nothing requested.
    Idle,
    /// The contact asked; the waiting period is running.
    Requested,
    /// The sealed key is available to the contact.
    Released,
}

/// `POST /v1/emergency-contacts`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateEmergencyContactRequest {
    pub contact_account_id: String,
    /// The ASK, or the vault key, sealed to the contact (context `emergency:…`).
    pub sealed_key: String,
    pub scope: EmergencyScope,
    pub access_level: EmergencyAccessLevel,
    /// 1 to 30.
    pub wait_days: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct EmergencyContactRecord {
    pub id: String,
    pub grantor_id: String,
    pub grantor_email: String,
    pub contact_id: String,
    pub contact_email: String,
    pub scope: EmergencyScope,
    pub access_level: EmergencyAccessLevel,
    pub wait_days: u32,
    pub status: EmergencyStatus,
    /// RFC 3339 timestamps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<String>,
    /// When a pending request releases the key unless the grantor denies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub releases_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<String>,
    pub created_at: String,
    /// A vault scope only: the vault's key was rotated, so the sealed key opens nothing new until
    /// the grantor renews it with `PUT /v1/emergency-contacts/{id}/key`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub key_stale: bool,
    /// The family's organiser holds this record: `takeover` access, and no reading.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub organiser_recovery: bool,
}

/// `PUT /v1/emergency-contacts/{id}/key`: the grantor seals a vault's current key to the contact
/// again, after a rotation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RenewEmergencyKeyRequest {
    /// The vault key sealed to the contact (context `emergency:…:vault:…`).
    pub sealed_key: String,
    /// base64url key id of the vault key it seals. A key rotated since fails with
    /// `vault-key-changed`.
    pub key_id: String,
}

/// `POST /v1/families/{familyId}/organiser-recovery`: a member lets the family's organiser help
/// recover their account. The server takes the rest from the family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrganiserRecoveryRequest {
    /// The member's ASK sealed to the organiser (context `emergency:<member>:<organiser>:ask`).
    pub sealed_key: String,
    /// 1 to 30.
    pub wait_days: u32,
}

/// `GET /v1/emergency-contacts`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct EmergencyContactsResponse {
    /// Contacts this account chose.
    pub granted: Vec<EmergencyContactRecord>,
    /// Accounts that chose this account as their contact.
    pub received: Vec<EmergencyContactRecord>,
}

/// `GET /v1/emergency-contacts/{id}/release`: for the contact, once released.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct EmergencyReleaseResponse {
    pub contact: EmergencyContactRecord,
    pub sealed_key: String,
    /// Account scope only: the grantor's bundle, whose private keys the released ASK opens.
    /// A vault scope gets nothing that could open the grantor's other vaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grantor: Option<AccountBundle>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum SecurityEventType {
    EmergencyContactAdded,
    EmergencyContactRemoved,
    EmergencyAccessRequested,
    EmergencyAccessDenied,
    EmergencyAccessApproved,
    EmergencyAccessReleased,
    TwoStepEnabled,
    TwoStepDisabled,
    /// The authenticator app was replaced while two-step sign-in stayed on.
    AuthenticatorChanged,
    SecurityKeyAdded,
    SecurityKeyRemoved,
    RecoveryCodesRenewed,
    /// A sign-in used a recovery code.
    RecoveryCodeUsed,
    /// Too many wrong second-step codes: the second step is paused for a while.
    TwoStepLocked,
    /// Every other device has to do the second step at its next sign-in.
    TrustedDevicesForgotten,
    /// A new master password, set while signed in. Every other device was signed out.
    PasswordChanged,
    /// The master password was reset with the recovery code. Every device was signed out.
    PasswordReset,
    /// A device saved an export of the vault (`POST /v1/security-log/exports`).
    VaultExported,
    /// A new Secret Key, set while signed in. Every other device was signed out.
    SecretKeyRotated,
    /// This account gave a vault a new key.
    VaultKeyRotated,
    /// An emergency contact, or the family organiser, set a new master password and Secret Key
    /// for this account. Every device was signed out.
    EmergencyTakeover,
    /// This account let its family's organiser help recover it.
    OrganiserRecoveryEnabled,
    /// That permission ended: the member turned it off, or left the family.
    OrganiserRecoveryDisabled,
    /// A person made a service account for a shared vault.
    ServiceAccountCreated,
    /// A service account was revoked.
    ServiceAccountRevoked,
    /// A service account fetched its vault.
    ServiceAccountRead,
    /// A service account saved an item.
    ServiceAccountWrote,
    /// A revoked or expired token proved itself and was refused: it's still in use somewhere.
    ServiceAccountDenied,
    /// Octa Pass Connect handed a secret to a local program. What, and to which program, is in
    /// `sealedDetail`, which only the account can open.
    ConnectSecretRead,
}

impl SecurityEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmergencyContactAdded => "emergency-contact-added",
            Self::EmergencyContactRemoved => "emergency-contact-removed",
            Self::EmergencyAccessRequested => "emergency-access-requested",
            Self::EmergencyAccessDenied => "emergency-access-denied",
            Self::EmergencyAccessApproved => "emergency-access-approved",
            Self::EmergencyAccessReleased => "emergency-access-released",
            Self::TwoStepEnabled => "two-step-enabled",
            Self::TwoStepDisabled => "two-step-disabled",
            Self::AuthenticatorChanged => "authenticator-changed",
            Self::SecurityKeyAdded => "security-key-added",
            Self::SecurityKeyRemoved => "security-key-removed",
            Self::RecoveryCodesRenewed => "recovery-codes-renewed",
            Self::RecoveryCodeUsed => "recovery-code-used",
            Self::TwoStepLocked => "two-step-locked",
            Self::TrustedDevicesForgotten => "trusted-devices-forgotten",
            Self::PasswordChanged => "password-changed",
            Self::PasswordReset => "password-reset",
            Self::VaultExported => "vault-exported",
            Self::SecretKeyRotated => "secret-key-rotated",
            Self::VaultKeyRotated => "vault-key-rotated",
            Self::EmergencyTakeover => "emergency-takeover",
            Self::OrganiserRecoveryEnabled => "organiser-recovery-enabled",
            Self::OrganiserRecoveryDisabled => "organiser-recovery-disabled",
            Self::ServiceAccountCreated => "service-account-created",
            Self::ServiceAccountRevoked => "service-account-revoked",
            Self::ServiceAccountRead => "service-account-read",
            Self::ServiceAccountWrote => "service-account-wrote",
            Self::ServiceAccountDenied => "service-account-denied",
            Self::ConnectSecretRead => "connect-secret-read",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::EmergencyContactAdded,
            Self::EmergencyContactRemoved,
            Self::EmergencyAccessRequested,
            Self::EmergencyAccessDenied,
            Self::EmergencyAccessApproved,
            Self::EmergencyAccessReleased,
            Self::TwoStepEnabled,
            Self::TwoStepDisabled,
            Self::AuthenticatorChanged,
            Self::SecurityKeyAdded,
            Self::SecurityKeyRemoved,
            Self::RecoveryCodesRenewed,
            Self::RecoveryCodeUsed,
            Self::TwoStepLocked,
            Self::TrustedDevicesForgotten,
            Self::PasswordChanged,
            Self::PasswordReset,
            Self::VaultExported,
            Self::SecretKeyRotated,
            Self::VaultKeyRotated,
            Self::EmergencyTakeover,
            Self::OrganiserRecoveryEnabled,
            Self::OrganiserRecoveryDisabled,
            Self::ServiceAccountCreated,
            Self::ServiceAccountRevoked,
            Self::ServiceAccountRead,
            Self::ServiceAccountWrote,
            Self::ServiceAccountDenied,
            Self::ConnectSecretRead,
        ]
        .into_iter()
        .find(|event| event.as_str() == value)
    }
}

/// An entry in the account's own security log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    #[serde(rename = "type")]
    pub event_type: SecurityEventType,
    /// RFC 3339 timestamp.
    pub created_at: String,
    /// The other account involved, while it exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_account_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency_contact_id: Option<String>,
    /// `vault-exported`: the device's name and platform when it exported, kept after it signs out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_format: Option<ExportFormat>,
    /// Whether the file holds the vault's attachments (only the encrypted export does).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_attachments: Option<bool>,
    /// The `service-account-*` entries: which one. Its name is in the service account's record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_id: Option<String>,
    /// `connect-secret-read`: an envelope only the account can open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_detail: Option<String>,
}

/// The export formats clients offer (plan 07).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ExportFormat {
    Json,
    Csv,
    /// FIDO Credential Exchange Format, to a file or straight to another app.
    Cxf,
    /// Everything with the attachments, under a password chosen for the export.
    Encrypted,
}

impl ExportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Cxf => "cxf",
            Self::Encrypted => "encrypted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Self::Json, Self::Csv, Self::Cxf, Self::Encrypted]
            .into_iter()
            .find(|format| format.as_str() == value)
    }
}

/// `POST /v1/security-log/exports`: what a client sends once the user saved an export. Nothing
/// from the vault, only the format and whether the attachments went with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct VaultExportedRequest {
    pub format: ExportFormat,
    pub attachments: bool,
}

/// `POST /v1/security-log/connect`: what Octa Pass Connect handed out, one blob per secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct ConnectEventsRequest {
    /// Envelopes sealed under the account key, at most 100 in one request. The server can't read
    /// them. Each holds the time it happened, so a late upload still says when.
    pub sealed_details: Vec<String>,
}

/// `GET /v1/security-log`: newest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SecurityLogResponse {
    pub events: Vec<SecurityEvent>,
}

/// A signed-in device, as listed by `GET /v1/devices`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    pub platform: String,
    /// RFC 3339 timestamp of the sign-in.
    pub created_at: String,
    /// RFC 3339 timestamp. Updated on token refresh and WebSocket sign-in.
    pub last_seen_at: String,
    /// Whether this is the device making the request.
    pub current: bool,
}

/// `PATCH /v1/devices/current`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RenameDeviceRequest {
    /// At most 64 characters.
    pub name: String,
}

/// Which service delivers a phone's pushes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    /// Apple Push Notification service: the device token in hex.
    Apns,
    /// Firebase Cloud Messaging: the registration token.
    Fcm,
}

/// `PUT /v1/devices/current/push`: where this device can be woken up. A push names no account,
/// vault or item; it says only `sync` or `alert`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct PushTokenRequest {
    pub platform: PushPlatform,
    /// At most 4096 characters: hex for APNs; letters, digits, `-`, `_` and `:` for FCM.
    pub token: String,
    /// APNs only: a development build, reached through Apple's sandbox.
    #[serde(default)]
    pub sandbox: bool,
}

/// A message from the client on `GET /v1/ws`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ClientMessage {
    /// First message on a connection, and again after every token refresh.
    #[serde(rename_all = "camelCase")]
    Auth { access_token: String },
}

/// A message from the server on `GET /v1/ws`. Never carries item data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ServerMessage {
    /// The access token was accepted. Send a new `auth` before it expires.
    #[serde(rename_all = "camelCase")]
    Authenticated { expires_in: u64 },
    /// A vault the account can access changed. Sync it if `revision` is newer
    /// than the one you have.
    #[serde(rename_all = "camelCase")]
    VaultChanged { vault_id: String, revision: u64 },
    /// Members of a vault were added or removed, or its key was rotated. Sync: a vault that is
    /// gone from the sync response is one this account can no longer access.
    #[serde(rename_all = "camelCase")]
    MembershipChanged { vault_id: String },
    /// The account was deleted. Wipe local data; the server closes the connection.
    AccountDeleted,
    /// This device was signed out. The server closes the connection.
    SessionRevoked,
}

/// WebSocket close code: the connection isn't (or is no longer) authenticated.
pub const WS_CLOSE_UNAUTHORIZED: u16 = 4401;
/// WebSocket close code: the client broke the protocol.
pub const WS_CLOSE_PROTOCOL: u16 = 4400;

/// What a member can do in an organisation. Roles live on the server and open nothing: vault keys
/// reach people only through grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum OrgRole {
    Member,
    /// Manages members, invites, groups and vault links.
    Admin,
    /// Also manages policies, SSO and roles. Entitled to every organisation vault.
    Owner,
}

impl OrgRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    pub fn parse(role: &str) -> Option<Self> {
        match role {
            "member" => Some(Self::Member),
            "admin" => Some(Self::Admin),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }
}

/// An organisation's rules for its members. A policy restricts; it never moves a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgPolicies {
    /// Enforced by the server: organisation vaults are withheld from a member without two-step
    /// sign-in, who also can't turn it off.
    pub require_two_step: bool,
    /// Enforced by the server: members sign in through the identity provider after their master
    /// password. Owners are exempt, so a broken provider can't lock the organisation out.
    pub require_sso: bool,
    /// How many hours a sign-in with SSO lasts, 1 to 8760; 0 checks only at sign-in.
    pub sso_max_age_hours: u32,
    /// Enforced by the server: members can't create share links.
    pub disable_share_links: bool,
    /// Enforced by the server: members can't add emergency contacts, and existing contacts don't
    /// reach organisation vaults.
    pub disable_emergency_access: bool,
    /// Applied by clients: exports leave out organisation vaults. A modified client can ignore it.
    pub disable_export: bool,
    /// Applied by clients: the longest auto-lock a member may choose, in minutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_auto_lock_minutes: Option<u32>,
    /// Applied by clients when a master password is set. The server never sees the password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_password_length: Option<u32>,
}

impl Default for OrgPolicies {
    fn default() -> Self {
        Self {
            require_two_step: false,
            require_sso: false,
            sso_max_age_hours: 168,
            disable_share_links: false,
            disable_emergency_access: false,
            disable_export: false,
            max_auto_lock_minutes: None,
            min_password_length: None,
        }
    }
}

/// `POST /v1/orgs`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgRequest {
    /// UUIDv7 generated by the client.
    pub id: String,
    /// Plaintext metadata, visible to the server. At most 64 characters.
    pub name: String,
}

/// `PATCH /v1/orgs/{orgId}`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RenameOrgRequest {
    pub name: String,
}

/// `DELETE /v1/orgs/{orgId}`, with the `X-Reauth-Token` header (purpose `organisation`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct DeleteOrgRequest {
    /// Must equal the organisation's name.
    pub confirm_name: String,
}

/// The signed-in member's view of their organisation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgRecord {
    pub id: String,
    pub name: String,
    /// The signed-in account's role.
    pub role: OrgRole,
    pub policies: OrgPolicies,
    pub member_count: u64,
    /// Whether this member is breaking a policy, so organisation vaults are withheld.
    pub access_withheld: bool,
    pub created_at: String,
}

/// An invitation the signed-in account received. `policies` are what joining agrees to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgInvitation {
    pub id: String,
    pub org_id: String,
    pub org_name: String,
    pub role: OrgRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invited_by: Option<String>,
    pub policies: OrgPolicies,
    pub invited_at: String,
    pub expires_at: String,
}

/// `GET /v1/orgs`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgsResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organisation: Option<OrgRecord>,
    pub invitations: Vec<OrgInvitation>,
}

/// A member, as admins see them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgMemberRecord {
    pub account_id: String,
    pub email: String,
    pub role: OrgRole,
    /// Whether two-step sign-in is on.
    pub two_step: bool,
    /// Whether this member has signed in through the identity provider.
    pub sso_linked: bool,
    pub joined_at: String,
}

/// A pending invite, as admins see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgInviteRecord {
    pub id: String,
    pub email: String,
    pub role: OrgRole,
    pub invited_at: String,
    pub expires_at: String,
}

/// `GET /v1/orgs/{orgId}/members`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgMembersResponse {
    pub members: Vec<OrgMemberRecord>,
    pub invites: Vec<OrgInviteRecord>,
}

/// `POST /v1/orgs/{orgId}/invites`. The answer is the same whether or not the email has an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgInviteRequest {
    pub email: String,
    /// `member` or `admin`. Owners are made from members, by an owner.
    pub role: OrgRole,
}

/// `PATCH /v1/orgs/{orgId}/members/{accountId}`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgMemberUpdate {
    pub role: OrgRole,
}

/// `POST /v1/orgs/{orgId}/groups`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgGroupRequest {
    /// UUIDv7 generated by the client.
    pub id: String,
    /// Plaintext metadata, visible to the server. At most 64 characters.
    pub name: String,
}

/// `PATCH /v1/orgs/{orgId}/groups/{groupId}`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct RenameOrgGroupRequest {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgGroupRecord {
    pub id: String,
    pub name: String,
    /// Account ids.
    pub members: Vec<String>,
    pub created_at: String,
}

/// `GET /v1/orgs/{orgId}/groups`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgGroupsResponse {
    pub groups: Vec<OrgGroupRecord>,
}

/// A group's access to a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgVaultGroup {
    pub group_id: String,
    pub role: VaultRole,
}

/// `PUT /v1/orgs/{orgId}/vaults/{vaultId}/groups/{groupId}`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgVaultGroupUpdate {
    /// `read`, `write` or `manage`.
    pub role: VaultRole,
}

/// An organisation vault, as admins see it. Its name is encrypted in the vault, so an admin who
/// isn't a member sees only the id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgVaultRecord {
    pub id: String,
    pub groups: Vec<OrgVaultGroup>,
    pub member_count: u64,
    /// Members who can grant access and rotate the key. At 0 nobody can, and it can only be deleted.
    pub manager_count: u64,
    /// The signed-in account's role, if it's a member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<VaultRole>,
    /// Someone lost access and the key hasn't been rotated yet.
    pub rotation_pending: bool,
    pub created_at: String,
}

/// `GET /v1/orgs/{orgId}/vaults`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgVaultsResponse {
    pub vaults: Vec<OrgVaultRecord>,
}

/// Someone a vault's key should be sealed to. This list comes from the server, so a client shows
/// it to a person, with a fingerprint it computes itself, before sealing anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgPendingGrant {
    pub account_id: String,
    pub email: String,
    pub role: VaultRole,
    /// base64url X25519 public key.
    pub public_enc_key: String,
    /// base64url Ed25519 public key.
    pub public_sign_key: String,
    /// The account's signed key record, which carries their ML-KEM key, so the grant can be
    /// hybrid and checked against the key log. Absent until one of their devices publishes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_record: Option<KeyRecord>,
    /// Replaces a grant with a lower role.
    pub upgrade: bool,
}

/// What a vault is waiting for from a key holder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgVaultAccessPlan {
    pub vault_id: String,
    /// Whether the signed-in account holds this vault's key and may manage it. When false, the
    /// lists say what's waiting, and a vault manager has to apply it.
    pub can_apply: bool,
    /// base64url id of the current vault key; send it back with the grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    pub grants: Vec<OrgPendingGrant>,
    /// The key should be rotated: someone lost access.
    pub rotate: bool,
}

/// `GET /v1/orgs/{orgId}/access`: only vaults with something waiting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgAccessResponse {
    pub vaults: Vec<OrgVaultAccessPlan>,
}

/// `POST /v1/orgs/{orgId}/vaults/{vaultId}/grants`: grants made on the key holder's device after a
/// person reviewed them. Each must match what the organisation entitles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgVaultGrantsRequest {
    /// base64url key id of the vault key the grants seal.
    pub key_id: String,
    pub grants: Vec<Grant>,
}

/// `PUT /v1/orgs/{orgId}/sso`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgSsoRequest {
    /// The provider's issuer URL. Its discovery document is fetched and checked.
    pub issuer: String,
    pub client_id: String,
    /// Sealed under the server secret. Leave out for a public client, or to keep the stored one
    /// when only the other fields change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

/// `GET /v1/orgs/{orgId}/sso`. The client secret never comes back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgSsoRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub has_client_secret: bool,
    /// When a test sign-in last finished with these settings. `requireSso` needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tested_at: Option<String>,
    /// The redirect URI to register at the provider.
    pub callback_url: String,
    /// Which protocol the saved settings use; absent when there are none. `issuer` and
    /// `clientId` are OpenID Connect's; `saml` is SAML's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<SsoProtocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml: Option<OrgSamlIdpRecord>,
    /// What to register at a SAML identity provider, whatever is saved now.
    #[serde(default)]
    pub saml_service_provider: OrgSamlServiceProvider,
}

/// The protocol of an organisation's SSO step. Either way it runs after the master password and
/// decides only whether the sign-in may go on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum SsoProtocol {
    Oidc,
    Saml,
}

impl SsoProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml => "saml",
        }
    }
}

/// `PUT /v1/orgs/{orgId}/sso/saml`: the identity provider's metadata, or its three fields. Saving
/// replaces OpenID Connect settings, if any, and needs a new test sign-in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgSamlRequest {
    /// The IdP's metadata XML (`EntityDescriptor`). It isn't fetched from a URL: paste it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_xml: Option<String>,
    /// Without metadata: the IdP's entity id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    /// Without metadata: its HTTP-Redirect single sign-on URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso_url: Option<String>,
    /// Without metadata: its signing certificates, PEM or base64 DER, 1 to 4 (more than one while
    /// it rolls its key over).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<String>,
}

/// A signing certificate an organisation pinned for SAML.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgSamlCertificate {
    /// SHA-256 of the DER, colon-separated hex, as identity providers show it.
    pub sha256: String,
    /// When the certificate says it expires. Only its key is used, so this is for the admin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

/// An organisation's SAML identity provider.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgSamlIdpRecord {
    pub entity_id: String,
    pub sso_url: String,
    pub certificates: Vec<OrgSamlCertificate>,
}

/// This server as a SAML service provider for one organisation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgSamlServiceProvider {
    pub entity_id: String,
    /// The assertion consumer service (HTTP-POST binding).
    pub acs_url: String,
    /// The SP metadata, for providers that import it.
    pub metadata_url: String,
}

/// A SCIM bearer token, without the token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgScimTokenRecord {
    pub id: String,
    pub name: String,
    /// The email of the owner who made it, unless that account is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

/// `GET /v1/orgs/{orgId}/scim`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgScimResponse {
    /// The SCIM 2.0 base URL to give the identity provider.
    pub base_url: String,
    pub tokens: Vec<OrgScimTokenRecord>,
}

/// `POST /v1/orgs/{orgId}/scim/tokens`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreateScimTokenRequest {
    /// For telling tokens apart, at most 64 characters.
    pub name: String,
}

/// A new SCIM token. `secret` is shown once: the server keeps only its hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct CreatedScimToken {
    pub token: OrgScimTokenRecord,
    pub secret: String,
}

/// `POST /v1/orgs/{orgId}/sso/test`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgSsoTestResponse {
    /// Open in a browser.
    pub url: String,
    pub expires_in: u64,
}

/// The `sso` member of an `sso-required` problem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SsoChallenge {
    /// For `login/sso`. Keep it on the device: it isn't the same as the browser URL.
    pub challenge_id: String,
    /// Open in a browser. The provider's page, then a page showing a 6-digit code.
    pub url: String,
    pub org_name: String,
    pub expires_in: u64,
}

/// `POST /v1/auth/login/sso`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct SsoLoginRequest {
    pub challenge_id: String,
    /// The 6-digit code the browser page showed.
    pub code: String,
}

/// An entry in the admin activity log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgEvent {
    pub id: String,
    /// A stable kebab-case name, for example `member-removed`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The email of who did it, unless that account is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// What it was done to: an email, a group's name or a vault id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub created_at: String,
}

/// `GET /v1/orgs/{orgId}/events`: newest first, kept a year.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
pub struct OrgEventsResponse {
    pub events: Vec<OrgEvent>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn vault_record_uses_type_key() {
        let record = VaultRecord {
            id: "v".into(),
            vault_type: VaultType::Personal,
            revision: 3,
            wrapped_vault_key: "k".into(),
            role: VaultRole::Owner,
            key_id: None,
            grant: None,
            org_id: None,
        };
        assert_eq!(
            serde_json::to_value(record).unwrap(),
            json!({ "id": "v", "type": "personal", "revision": 3, "wrappedVaultKey": "k", "role": "owner" })
        );
    }

    #[test]
    fn roles_are_ordered_and_round_trip() {
        assert!(VaultRole::Read < VaultRole::Write);
        assert!(VaultRole::Manage < VaultRole::Owner);
        for role in [
            VaultRole::Read,
            VaultRole::Write,
            VaultRole::Manage,
            VaultRole::Owner,
        ] {
            assert_eq!(VaultRole::parse(role.as_str()), Some(role));
            assert_eq!(serde_json::to_value(role).unwrap(), json!(role.as_str()));
        }
        assert_eq!(VaultRole::parse("admin"), None);
    }

    #[test]
    fn emergency_scope_is_tagged() {
        assert_eq!(
            serde_json::to_value(EmergencyScope::Vault {
                vault_id: "v".into()
            })
            .unwrap(),
            json!({ "type": "vault", "vaultId": "v" })
        );
        let scope: EmergencyScope = serde_json::from_value(json!({ "type": "account" })).unwrap();
        assert_eq!(scope, EmergencyScope::Account);
    }

    #[test]
    fn security_event_types_round_trip() {
        let event = SecurityEventType::EmergencyAccessReleased;
        assert_eq!(serde_json::to_value(event).unwrap(), json!(event.as_str()));
        assert_eq!(SecurityEventType::parse(event.as_str()), Some(event));
        assert_eq!(SecurityEventType::parse("nope"), None);
    }

    #[test]
    fn reauth_purpose_is_kebab_case() {
        assert_eq!(
            serde_json::to_value(ReauthPurpose::DeleteAccount).unwrap(),
            json!("delete-account")
        );
        assert_eq!(ReauthPurpose::DeleteAccount.as_str(), "delete-account");
    }

    #[test]
    fn optional_fields_are_omitted() {
        let response = RegisterStartResponse {
            registration_response: "r".into(),
            verification_required: true,
            dev_verification_code: None,
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({ "registrationResponse": "r", "verificationRequired": true })
        );
    }

    #[test]
    fn account_bundle_accepts_missing_account_id() {
        let bundle: AccountBundle = serde_json::from_value(json!({
            "email": "a@example.com",
            "kdf": { "algorithm": "argon2id", "memoryKib": 65536, "iterations": 3, "parallelism": 1 },
            "accountSalt": "s",
            "wrappedAsk": "w",
            "publicEncKey": "e",
            "publicSignKey": "p",
            "wrappedPrivateKeys": "k",
            "recoveryWrappedAsk": "r"
        }))
        .unwrap();
        assert_eq!(bundle.account_id, None);
        assert_eq!(bundle.kdf.memory_kib, 65536);
    }

    #[test]
    fn if_match_is_a_number_or_star() {
        let op: BatchOperation = serde_json::from_value(json!({
            "op": "delete", "vaultId": "v", "itemId": "i", "ifMatch": "*"
        }))
        .unwrap();
        assert_eq!(op.if_match, Some(IfMatch::Any(AnyRevision::Any)));
        let op: BatchOperation = serde_json::from_value(json!({
            "op": "put", "vaultId": "v", "itemId": "i", "ifMatch": 4,
            "item": { "encryptedItemKey": "k", "overview": "o", "details": "d" }
        }))
        .unwrap();
        assert_eq!(op.if_match, Some(IfMatch::Revision(4)));
        assert!(
            serde_json::from_value::<BatchOperation>(json!({
                "op": "delete", "vaultId": "v", "itemId": "i", "ifMatch": "4"
            }))
            .is_err()
        );
    }

    #[test]
    fn websocket_messages_are_tagged() {
        let auth: ClientMessage =
            serde_json::from_value(json!({ "type": "auth", "accessToken": "t" })).unwrap();
        assert_eq!(
            auth,
            ClientMessage::Auth {
                access_token: "t".into()
            }
        );
        assert_eq!(
            serde_json::to_value(ServerMessage::VaultChanged {
                vault_id: "v".into(),
                revision: 3
            })
            .unwrap(),
            json!({ "type": "vault-changed", "vaultId": "v", "revision": 3 })
        );
        assert_eq!(
            serde_json::to_value(ServerMessage::SessionRevoked).unwrap(),
            json!({ "type": "session-revoked" })
        );
    }
}
