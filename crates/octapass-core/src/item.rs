//! The plaintext item model (mirrors the TypeScript types in `packages/vault-client`).
//!
//! An item is split into an **overview** (what lists and autofill matching need) and **details**
//! (everything else); each is encrypted separately. Both carry `schemaVersion`. Fields this
//! version doesn't know are kept in `extra` and written back untouched, so older clients never
//! drop data written by newer ones.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::tools::totp::{hotp_counter, newest_hotp, with_hotp_counter};

pub const SCHEMA_VERSION: u32 = 1;

fn schema_version() -> u32 {
    SCHEMA_VERSION
}

/// `login | secureNote | card | identity | password | document | wifi | sshKey | maskedEmailProvider |
/// environment | certificate | key | bankAccount | apiCredential | softwareLicense | idDocument |
/// cryptoWallet | database | custom | customTemplate`, or a type from a newer client.
/// `maskedEmailProvider` holds the token for a masked email service, and `customTemplate` the
/// fields of a user's own item type; apps keep both out of item lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ItemType {
    Login,
    SecureNote,
    Card,
    Identity,
    Password,
    Document,
    Wifi,
    SshKey,
    MaskedEmailProvider,
    // Environments (plan 16): `.env` files and environment variables.
    Environment,
    /// The user's own equivalent domains: a setting, kept out of item lists like
    /// `maskedEmailProvider` (see [`EquivalentDomainsDetails`]).
    EquivalentDomains,
    // Developer toolkit (plan 16): TLS certificates, and keys that aren't SSH keys.
    Certificate,
    Key,
    // The field table for the types below is in `crate::item_fields`.
    BankAccount,
    ApiCredential,
    SoftwareLicense,
    IdDocument,
    CryptoWallet,
    Database,
    Custom,
    CustomTemplate,
    Other(String),
}

impl From<String> for ItemType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "login" => ItemType::Login,
            "secureNote" => ItemType::SecureNote,
            "card" => ItemType::Card,
            "identity" => ItemType::Identity,
            "password" => ItemType::Password,
            "document" => ItemType::Document,
            "wifi" => ItemType::Wifi,
            "sshKey" => ItemType::SshKey,
            "maskedEmailProvider" => ItemType::MaskedEmailProvider,
            "environment" => ItemType::Environment,
            "equivalentDomains" => ItemType::EquivalentDomains,
            "certificate" => ItemType::Certificate,
            "key" => ItemType::Key,
            "bankAccount" => ItemType::BankAccount,
            "apiCredential" => ItemType::ApiCredential,
            "softwareLicense" => ItemType::SoftwareLicense,
            "idDocument" => ItemType::IdDocument,
            "cryptoWallet" => ItemType::CryptoWallet,
            "database" => ItemType::Database,
            "custom" => ItemType::Custom,
            "customTemplate" => ItemType::CustomTemplate,
            _ => ItemType::Other(value),
        }
    }
}

impl From<ItemType> for String {
    fn from(value: ItemType) -> Self {
        match value {
            ItemType::Login => "login".into(),
            ItemType::SecureNote => "secureNote".into(),
            ItemType::Card => "card".into(),
            ItemType::Identity => "identity".into(),
            ItemType::Password => "password".into(),
            ItemType::Document => "document".into(),
            ItemType::Wifi => "wifi".into(),
            ItemType::SshKey => "sshKey".into(),
            ItemType::MaskedEmailProvider => "maskedEmailProvider".into(),
            ItemType::Environment => "environment".into(),
            ItemType::EquivalentDomains => "equivalentDomains".into(),
            ItemType::Certificate => "certificate".into(),
            ItemType::Key => "key".into(),
            ItemType::BankAccount => "bankAccount".into(),
            ItemType::ApiCredential => "apiCredential".into(),
            ItemType::SoftwareLicense => "softwareLicense".into(),
            ItemType::IdDocument => "idDocument".into(),
            ItemType::CryptoWallet => "cryptoWallet".into(),
            ItemType::Database => "database".into(),
            ItemType::Custom => "custom".into(),
            ItemType::CustomTemplate => "customTemplate".into(),
            ItemType::Other(other) => other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemOverview {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    pub title: String,
    #[serde(rename = "type")]
    pub item_type: ItemType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,
    /// When the item was first saved, in the app it was imported from (RFC 3339). Apps show it
    /// instead of the sync record's `createdAt`, which is when it reached Octa Pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// When the item last changed in the app it was imported from (RFC 3339). Shown instead of the
    /// sync record's `updatedAt` until the item is edited here, which drops it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// When the item was last used to sign in or fill (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    /// The app and id the item was imported from, so importing the same file again updates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_from: Option<ImportedFrom>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Where an imported item came from: the import source (`firefox`, `bitwarden-json`, …) and the
/// item's id in that app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedFrom {
    pub source: String,
    pub id: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    pub rp_id: String,
    pub user_name: String,
    pub created_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupCode {
    pub code: String,
    pub used: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A site's security question. The answer is a secret: apps hide it like a password, and the
/// generator can make a random one, which is safer than a true one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityQuestion {
    pub question: String,
    pub answer: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Where a recovery email or phone came from: `kind` is `identity` (with `itemId`) or `alias` (a
/// masked email, with `provider` and the provider's `aliasId`). Kept loose so new kinds round-trip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverySource {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_id: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Boxed, like `phone_source`, so a login's details stay close to the other types' size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_source: Option<Box<RecoverySource>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone_source: Option<Box<RecoverySource>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_codes: Option<Vec<BackupCode>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_questions: Option<Vec<SecurityQuestion>>,
    /// `totp | sms | email | key | passkey | none`; kept as a string so new methods round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub two_factor_method: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomField {
    pub label: String,
    pub value: String,
    pub hidden: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Details of `login` items, and of `password` items (which use the same fields).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// An `otpauth://` URI or a bare base32 secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkeys: Option<Vec<Passkey>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Vec<PasswordHistoryEntry>>,
    /// When the password was set (RFC 3339), from the app it was imported from. Apps show the
    /// later of this and the newest password history entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_changed_at: Option<String>,
    /// The realm of a site's HTTP authentication prompt (`WWW-Authenticate: Basic realm="…"`), for
    /// logins saved from that prompt rather than a form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_realm: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    pub notes: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    /// `MM/YY`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A file kept with an item (see [`crate::attachment`]). Any item's details can list them under
/// `attachments`; a `document` item is one file plus notes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    /// A UUID, also the file's id on the server.
    pub id: String,
    /// The file name.
    pub name: String,
    /// The media type, e.g. `application/pdf`; empty when unknown.
    #[serde(rename = "type")]
    pub media_type: String,
    /// Plaintext bytes.
    pub size: u64,
    /// The file key, wrapped by the item key.
    pub key: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// The document's file comes first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<Attachment>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A Wi-Fi network. The list subtitle is the network name, so apps can mark the network the device
/// is on, or sees, without opening the details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// The network name (SSID), exactly as broadcast.
    pub ssid: String,
    /// `open | wep | wpa | wpaWpa2 | wpa2 | wpa2Wpa3 | wpa3 | wpa2Enterprise | wpa3Enterprise`, or
    /// a newer one. Open networks have no password.
    pub security: String,
    /// The pre-shared key (Personal, WEP), or the user's password on an Enterprise network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// The network doesn't broadcast its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
    /// Enterprise: `peap | ttls | tls | pwd | leap | fast`, or a newer one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eap_method: Option<String>,
    /// Enterprise, PEAP and TTLS: the inner method, `mschapv2 | gtc | pap | chap | mschap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Enterprise: the outer (anonymous) identity, when it differs from the username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Enterprise: the domain the server's certificate must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_domain: Option<String>,
    /// Enterprise: the CA certificate (PEM) that signed the server's certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificate: Option<String>,
    /// The network shows a sign-in page (captive portal) after joining.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captive_portal: Option<bool>,
    /// Set up by an organisation (on Apple devices: installed by a configuration profile or MDM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    /// A phone's or tablet's Personal Hotspot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hotspot: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Vec<PasswordHistoryEntry>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An SSH key (see [`crate::tools::ssh`]). The list subtitle is the fingerprint. Every field is
/// optional so keys from other apps can be kept even when they only have some of them; keys made or
/// read here have the first four.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`), without a passphrase: the vault
    /// encrypts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// The public key without its comment: `ssh-ed25519 AAAA…`. The `authorized_keys` line is this,
    /// a space and the comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// The SSH algorithm name: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, `ssh-dss`,
    /// `sk-ssh-ed25519@openssh.com`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// `SHA256:…`, as `ssh-keygen -l -E sha256` shows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The key's comment, usually `user@host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Protects copies written out of the vault (offered when exporting); the stored key has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A masked email service the user connected with their own API token. Calls to the provider go
/// straight from the device; the token never reaches the sync server unencrypted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaskedEmailProviderDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// `simplelogin | addy | firefoxRelay | fastmail | duckduckgo | forwardEmail`, or a newer one.
    pub provider: String,
    pub token: String,
    /// A self-hosted server (SimpleLogin, addy.io).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// The domain new aliases are made on (addy.io, Forward Email).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The user's own equivalent domains (plan 01), so a login for one is offered on the others. One
/// hidden `equivalentDomains` item in a personal vault; if two devices each made one before they
/// synced, matching reads both ([`crate::matching::user_equivalents`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivalentDomainsDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// Groups of registrable domains the user treats as one site.
    #[serde(default)]
    pub groups: Vec<Vec<String>>,
    /// Built-in groups turned off, each named by its first domain, so the built-in list can grow
    /// without turning a removed group back on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_defaults: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn concealed_by_default() -> bool {
    true
}

/// One variable of an environment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentVariable {
    /// Letters, digits and `_`, not starting with a digit ([`crate::environment::valid_key`]).
    pub key: String,
    /// The value, or an `octapass://<vault>/<item>/<field>` reference to another item's field.
    pub value: String,
    /// Hidden until revealed, like a password. New variables are concealed.
    #[serde(default = "concealed_by_default")]
    pub concealed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl EnvironmentVariable {
    /// A concealed variable without a note.
    pub fn new(key: String, value: String) -> Self {
        Self {
            key,
            value,
            concealed: true,
            note: None,
            extra: Map::new(),
        }
    }
}

/// A set of environment variables: one app's `.env` file for one stage, or a single variable.
///
/// `project` groups the stages of one app; an environment of a project without a `stage` is the
/// project's shared set, loaded before (and overridden by) each stage's. Both are optional. See
/// [`crate::environment`] for the rules and the `.env` reader and writer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// A short identifier such as `shop-api`: letters, digits, `-` and `_`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// How the project is shown, when it isn't the identifier itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    /// `development | staging | production | testing | preview | local`, or a custom name (letters,
    /// digits, `-` and `_`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// In the order they're shown and written to files. Each name is used once.
    #[serde(default)]
    pub variables: Vec<EnvironmentVariable>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A TLS certificate with its key and chain (plan 16). `certificate` is the source of truth; the
/// fields after `private_key` are read out of it so lists and reminders needn't parse it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// PEM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// The certificates up to the root, PEM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<String>,
    /// PKCS#8 PEM, without a passphrase: the vault encrypts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sans: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// RFC 3339. Drives renewal reminders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// `RSA 2048`, `ECDSA P-256`, `Ed25519`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// SHA-256 of the certificate, in colon-separated hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_ca: Option<bool>,
    /// `selfSigned | localCa | acme | imported`; kept as a string so new sources round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// ACME: the CA, names, challenge and account key, to renew without asking again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A bank account. Every field is optional, so accounts from other apps keep what they have.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BankAccountDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bank_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_holder: Option<String>,
    /// `checking | savings | business | other`, or the words another app used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iban: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    /// A routing, sort or branch code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_number: Option<String>,
    /// The SWIFT code (BIC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swift: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A key that isn't an SSH key (plan 16): JWT signing keys, OpenPGP keys, age keys. Every part is
/// optional, so keys from other apps can be kept with what they have.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// `jwt | openpgp | age | asymmetric`; kept as a string so new kinds round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// `RS256`, `EdDSA`, `ed25519`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// HMAC secrets, which have no public half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// The key as a JWK. Secret: it holds the private parts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<String>,
    /// Public parts only: what gets published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// OpenPGP: `Name <email>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Protects copies written out of the vault; the stored key has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An API key or token for a service.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiCredentialDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// `apiKey | bearerToken | oauth | jwt | basicAuth | other`, or the words another app used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// `YYYY-MM-DD`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A software licence.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftwareLicenseDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub licensed_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_number: Option<String>,
    /// `YYYY-MM-DD`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_date: Option<String>,
    /// `YYYY-MM-DD`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A passport, driver's licence or national ID. Scans are the item's `attachments`, kept in `extra`
/// as on every other type.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdDocumentDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// `passport | driverLicense | nationalId | other`, or the words another app used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// `YYYY-MM-DD`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_date: Option<String>,
    /// Who issued it: an authority, a state or a ministry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// `YYYY-MM-DD`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_date: Option<String>,
    /// `YYYY-MM-DD`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One receiving address of a crypto wallet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletAddress {
    /// `bitcoin | ethereum`, or the name of another chain.
    pub network: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A crypto wallet. The seed phrase and passphrase are never shown as a QR code: only addresses are.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoWalletDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_phrase: Option<String>,
    /// The optional BIP-39 passphrase (the "25th word").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<WalletAddress>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A database or server. The connection string usually holds the password, so it's a secret too.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// `postgresql | mysql | sqlServer | oracle | mongodb | redis | sqlite | server | other`, or the
    /// words another app used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Text, as typed: other apps export ports that aren't numbers, and those are kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_string: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_fields: Option<Vec<CustomField>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_history: Option<Vec<PasswordHistoryEntry>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn text_field_kind() -> String {
    "text".into()
}

/// A field of a custom item. `kind` is `text | hidden | multiline | url | date | email | phone | totp`
/// (plan 01's custom field kinds), or a newer one, which apps treat as hidden.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedField {
    pub label: String,
    #[serde(default)]
    pub value: String,
    #[serde(default = "text_field_kind")]
    pub kind: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An item of the user's own type. The template's fields are copied in when it's made, so the item
/// stays whole if its template later changes or is deleted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    /// The `customTemplate` item this was made from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    /// That template's name when this was made, shown as the list subtitle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_name: Option<String>,
    #[serde(default)]
    pub fields: Vec<TypedField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A user's own item type: the labels and kinds of its fields, with no values. Its title is the
/// type's name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomTemplateDetails {
    #[serde(default = "schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub fields: Vec<TemplateField>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A field of a custom template; `kind` as in [`TypedField`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateField {
    pub label: String,
    #[serde(default = "text_field_kind")]
    pub kind: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Item details, typed by the overview's `type`. Types this version doesn't know stay raw JSON.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ItemDetails {
    Login(LoginDetails),
    SecureNote(SecureNoteDetails),
    Card(CardDetails),
    Identity(IdentityDetails),
    Document(DocumentDetails),
    Wifi(WifiDetails),
    SshKey(SshKeyDetails),
    MaskedEmailProvider(MaskedEmailProviderDetails),
    Environment(EnvironmentDetails),
    EquivalentDomains(EquivalentDomainsDetails),
    Certificate(CertificateDetails),
    Key(KeyDetails),
    BankAccount(BankAccountDetails),
    ApiCredential(ApiCredentialDetails),
    SoftwareLicense(SoftwareLicenseDetails),
    IdDocument(IdDocumentDetails),
    CryptoWallet(CryptoWalletDetails),
    Database(DatabaseDetails),
    Custom(CustomDetails),
    CustomTemplate(CustomTemplateDetails),
    Other(Map<String, Value>),
}

impl ItemDetails {
    pub fn from_value(item_type: &ItemType, value: Value) -> Result<Self> {
        let invalid = |_| Error::InvalidItem;
        Ok(match item_type {
            ItemType::Login | ItemType::Password => {
                ItemDetails::Login(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::SecureNote => {
                ItemDetails::SecureNote(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::Card => ItemDetails::Card(serde_json::from_value(value).map_err(invalid)?),
            ItemType::Identity => {
                ItemDetails::Identity(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::Document => {
                ItemDetails::Document(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::Wifi => ItemDetails::Wifi(serde_json::from_value(value).map_err(invalid)?),
            ItemType::SshKey => {
                ItemDetails::SshKey(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::MaskedEmailProvider => {
                ItemDetails::MaskedEmailProvider(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::Environment => {
                let details: EnvironmentDetails = serde_json::from_value(value).map_err(invalid)?;
                crate::environment::validate_details(&details).map_err(|_| Error::InvalidItem)?;
                ItemDetails::Environment(details)
            }
            ItemType::EquivalentDomains => {
                ItemDetails::EquivalentDomains(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::Certificate => {
                ItemDetails::Certificate(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::Key => ItemDetails::Key(serde_json::from_value(value).map_err(invalid)?),
            ItemType::BankAccount => {
                ItemDetails::BankAccount(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::ApiCredential => {
                ItemDetails::ApiCredential(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::SoftwareLicense => {
                ItemDetails::SoftwareLicense(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::IdDocument => {
                ItemDetails::IdDocument(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::CryptoWallet => {
                ItemDetails::CryptoWallet(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::Database => {
                ItemDetails::Database(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::Custom => {
                ItemDetails::Custom(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::CustomTemplate => {
                ItemDetails::CustomTemplate(serde_json::from_value(value).map_err(invalid)?)
            }
            ItemType::Other(_) => {
                ItemDetails::Other(serde_json::from_value(value).map_err(invalid)?)
            }
        })
    }
}

/// The edit that makes a past version current, on the JSON of the item as it is and of the
/// version. Only what the item said comes back: passkeys stay (an old list could drop one the site
/// still expects), the favourite and pinned flags stay, the password history keeps growing, and a counter-based
/// code never moves backwards, because the site won't take its old codes again. Attachments are
/// kept by the save itself.
pub fn restored_version(
    current_overview: &Value,
    current_details: &Value,
    version_overview: &Value,
    version_details: &Value,
) -> (Value, Value) {
    let keep = |target: &mut Value, from: &Value, field: &str| {
        let Some(object) = target.as_object_mut() else {
            return;
        };
        match from.get(field) {
            Some(value) => object.insert(field.to_string(), value.clone()),
            None => object.remove(field),
        };
    };
    let (mut overview, mut details) = (version_overview.clone(), version_details.clone());
    keep(&mut overview, current_overview, "favorite");
    keep(&mut overview, current_overview, "pinned");
    let login = |value: &Value| {
        matches!(
            value.get("type").and_then(Value::as_str),
            Some("login" | "password")
        )
    };
    if login(version_overview) && login(current_overview) {
        keep(&mut details, current_details, "passkeys");
        keep(&mut details, current_details, "passwordHistory");
        let totp = |details: &Value| {
            details
                .get("totp")
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        if let (Some(old), Some(now)) = (totp(version_details), totp(current_details))
            && let (Ok(before), Ok(after)) = (hotp_counter(&old), hotp_counter(&now))
            && after > before
            && let Ok(moved) = with_hotp_counter(&old, after)
        {
            details["totp"] = Value::String(moved.to_string());
        }
    }
    (overview, details)
}

/// Two versions of a login that differ only in a counter-based code's counter, as one: a code used
/// on a phone offline while another device got there first is no edit conflict, so it needs no
/// conflicting copy. `None` for anything else.
pub fn merge_hotp_counter(local: &Item, server: &Item) -> Option<Item> {
    let ItemDetails::Login(theirs) = &server.details else {
        return None;
    };
    let mut same = local.clone();
    if let ItemDetails::Login(login) = &mut same.details {
        login.totp.clone_from(&theirs.totp);
    }
    (same == *server).then(|| with_newest_hotp(local, server))?
}

/// The server's version of a login with the higher of the two counters: for a local change known
/// to be only a counter moving, whatever else the server's version changed. `None` unless both
/// hold the same HOTP setup.
pub fn with_newest_hotp(local: &Item, server: &Item) -> Option<Item> {
    let (ItemDetails::Login(mine), ItemDetails::Login(theirs)) = (&local.details, &server.details)
    else {
        return None;
    };
    let newest = newest_hotp(mine.totp.as_deref()?, theirs.totp.as_deref()?)?.to_string();
    let mut merged = server.clone();
    if let ItemDetails::Login(login) = &mut merged.details {
        login.totp = Some(newest);
    }
    Some(merged)
}

/// A whole plaintext item: `{ "overview": {…}, "details": {…} }`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Item {
    pub overview: ItemOverview,
    pub details: ItemDetails,
}

/// As [`Item::from_json`]: details typed by `overview.type`.
impl<'de> Deserialize<'de> for Item {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            overview: ItemOverview,
            details: Value,
        }
        let raw = Raw::deserialize(deserializer)?;
        Self::from_parts(raw.overview, raw.details).map_err(serde::de::Error::custom)
    }
}

impl Item {
    /// Parses and validates `{ overview, details }`, typing details by `overview.type`.
    pub fn from_json(json: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Raw {
            overview: ItemOverview,
            details: Value,
        }
        let raw: Raw = serde_json::from_str(json).map_err(|_| Error::InvalidItem)?;
        Self::from_parts(raw.overview, raw.details)
    }

    pub fn from_parts(overview: ItemOverview, details: Value) -> Result<Self> {
        let details = ItemDetails::from_value(&overview.item_type, details)?;
        Ok(Self { overview, details })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("items serialize infallibly")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn login_round_trips_with_unknown_fields() {
        let input = json!({
            "overview": {
                "schemaVersion": 1, "title": "GitHub", "type": "login", "urls": ["https://github.com"], "favorite": true, "iconHint": "gh",
                "createdAt": "2020-01-01T00:00:00Z", "updatedAt": "2021-01-01T00:00:00Z", "lastUsedAt": "2022-01-01T00:00:00Z",
                "importedFrom": { "source": "firefox", "id": "{0b9e}", "later": 1 }
            },
            "details": {
                "schemaVersion": 1, "username": "octo", "password": "pw", "totp": "JBSWY3DPEHPK3PXP",
                "passkeys": [{ "rpId": "github.com", "userName": "octo", "createdAt": "2026-10-23T00:00:00Z", "future": 1 }],
                "recovery": {
                    "email": "me@alias.test", "emailSource": { "kind": "alias", "provider": "simplelogin", "aliasId": "42", "note": 1 },
                    "phone": "+962700000000", "phoneSource": { "kind": "identity", "itemId": "0192f0c8-1c2d-7a00-8000-0000000000aa" },
                    "backupCodes": [{ "code": "a1", "used": false }], "twoFactorMethod": "totp"
                },
                "customFields": [{ "label": "PIN", "value": "1234", "hidden": true }],
                "passwordHistory": [{ "password": "old", "changedAt": "2026-01-01T00:00:00Z" }],
                "passwordChangedAt": "2026-01-01T00:00:00Z", "httpRealm": "Router",
                "somethingNew": { "nested": [1, 2, 3] }
            }
        });
        let item = Item::from_json(&input.to_string()).unwrap();
        assert!(matches!(item.details, ItemDetails::Login(_)));
        assert_eq!(
            serde_json::from_str::<Value>(&item.to_json()).unwrap(),
            input
        );
    }

    #[test]
    fn schema_version_defaults_to_one() {
        let item = Item::from_json(
            r#"{"overview":{"title":"n","type":"secureNote"},"details":{"notes":"hi"}}"#,
        )
        .unwrap();
        let out: Value = serde_json::from_str(&item.to_json()).unwrap();
        assert_eq!(out["overview"]["schemaVersion"], 1);
        assert_eq!(out["details"]["schemaVersion"], 1);
    }

    #[test]
    fn every_type_round_trips() {
        for (kind, details) in [
            (
                "card",
                json!({ "schemaVersion": 1, "cardholder": "A", "number": "4111", "expiry": "01/30", "cvv": "123", "pin": "0000", "brand": "visa" }),
            ),
            (
                "identity",
                json!({ "schemaVersion": 1, "firstName": "A", "address": { "city": "Amman", "postalCode": "11118", "x": true }, "birthDate": "2000-01-01" }),
            ),
            ("password", json!({ "schemaVersion": 1, "password": "pw" })),
            (
                "document",
                json!({ "schemaVersion": 1, "notes": "signed copy", "attachments": [{ "id": "0192f0c8-1c2d-7a00-8000-0000000000cc", "name": "lease.pdf", "type": "application/pdf", "size": 1234, "key": "AQ", "pages": 3 }] }),
            ),
            (
                "login",
                json!({ "schemaVersion": 1, "username": "u", "attachments": [{ "id": "a", "name": "id.png", "type": "image/png", "size": 1, "key": "AQ" }] }),
            ),
            (
                "wifi",
                json!({ "schemaVersion": 1, "ssid": "Rahman-5G", "security": "wpa2Wpa3", "password": "pw", "hidden": true, "captivePortal": false, "managed": true, "hotspot": false, "notes": "router in the hall", "customFields": [{ "label": "Band", "value": "5 GHz", "hidden": false }], "passwordHistory": [{ "password": "old", "changedAt": "2026-01-01T00:00:00Z" }], "future": 1 }),
            ),
            (
                "wifi",
                json!({ "schemaVersion": 1, "ssid": "Corp", "security": "wpa3Enterprise", "eapMethod": "peap", "phase2": "mschapv2", "username": "u", "password": "p", "identity": "anonymous", "serverDomain": "radius.example.com", "caCertificate": "-----BEGIN CERTIFICATE-----" }),
            ),
            (
                "wifi",
                json!({ "schemaVersion": 1, "ssid": "Cafe", "security": "open" }),
            ),
            (
                "maskedEmailProvider",
                json!({ "schemaVersion": 1, "provider": "addy", "token": "t0k", "baseUrl": "https://addy.example", "domain": "anonaddy.me", "future": true }),
            ),
            (
                "environment",
                json!({ "schemaVersion": 1, "project": "shop-api", "projectName": "Shop API", "stage": "production", "variables": [{ "key": "DATABASE_URL", "value": "postgres://db", "concealed": true, "note": "primary" }, { "key": "PORT", "value": "8080", "concealed": false, "later": 1 }], "notes": "n", "future": true }),
            ),
            (
                "sshKey",
                json!({ "schemaVersion": 1, "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n…", "publicKey": "ssh-ed25519 AAAAC3Nza", "keyType": "ssh-ed25519", "fingerprint": "SHA256:cw5Z", "comment": "me@laptop", "passphrase": "pw", "notes": "deploy", "customFields": [{ "label": "Host", "value": "git.example", "hidden": false }], "future": 1 }),
            ),
            ("sshKey", json!({ "schemaVersion": 1 })),
            (
                "bankAccount",
                json!({ "schemaVersion": 1, "bankName": "Example Bank", "accountHolder": "Ada", "accountType": "savings", "iban": "DE89370400440532013000", "accountNumber": "0532013000", "routingNumber": "37040044", "swift": "COBADEFFXXX", "branch": "Main", "pin": "0000", "notes": "n", "customFields": [{ "label": "Online ID", "value": "x", "hidden": false }], "future": 1 }),
            ),
            (
                "apiCredential",
                json!({ "schemaVersion": 1, "credentialType": "bearerToken", "username": "ci", "key": "AKIA", "secret": "s", "host": "api.example.com", "expiryDate": "2030-01-31", "notes": "n", "future": 1 }),
            ),
            (
                "softwareLicense",
                json!({ "schemaVersion": 1, "product": "Editor", "version": "4", "licenseKey": "AAAA-BBBB", "licensedTo": "Ada", "email": "a@example.com", "publisher": "Acme", "orderNumber": "42", "purchaseDate": "2026-01-01", "expiryDate": "2027-01-01", "future": 1 }),
            ),
            (
                "idDocument",
                json!({ "schemaVersion": 1, "documentType": "passport", "number": "X1234", "fullName": "Ada L", "birthDate": "1990-12-10", "issuer": "Ministry", "country": "JO", "issueDate": "2020-01-01", "expiryDate": "2030-01-01", "attachments": [{ "id": "a", "name": "scan.png", "type": "image/png", "size": 1, "key": "AQ" }], "future": 1 }),
            ),
            (
                "cryptoWallet",
                json!({ "schemaVersion": 1, "walletName": "Hardware", "seedPhrase": "abandon ability", "passphrase": "p", "addresses": [{ "network": "bitcoin", "address": "bc1qxy", "label": "Savings", "later": 1 }, { "network": "ethereum", "address": "0xabc" }], "future": 1 }),
            ),
            (
                "database",
                json!({ "schemaVersion": 1, "databaseType": "postgresql", "host": "db.example.com", "port": "5432", "database": "shop", "username": "app", "password": "pw", "connectionString": "postgres://app:pw@db/shop", "passwordHistory": [{ "password": "old", "changedAt": "2026-01-01T00:00:00Z" }], "future": 1 }),
            ),
            (
                "custom",
                json!({ "schemaVersion": 1, "templateId": "t1", "templateName": "Library card", "fields": [{ "label": "Member", "value": "42", "kind": "text" }, { "label": "PIN", "value": "1", "kind": "hidden", "later": 1 }], "notes": "n", "future": 1 }),
            ),
            (
                "customTemplate",
                json!({ "schemaVersion": 1, "fields": [{ "label": "Member", "kind": "text" }, { "label": "PIN", "kind": "hidden", "later": 1 }], "future": 1 }),
            ),
            ("vehicle", json!({ "schemaVersion": 3, "plate": "XYZ" })),
        ] {
            let input = json!({ "overview": { "schemaVersion": 1, "title": "t", "type": kind }, "details": details });
            let item = Item::from_json(&input.to_string()).unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&item.to_json()).unwrap(),
                input,
                "{kind}"
            );
        }
    }

    #[test]
    fn environment_variables_are_concealed_unless_marked() {
        let item = Item::from_json(
            r#"{"overview":{"title":"One key","type":"environment"},"details":{"variables":[{"key":"API_KEY","value":"k"}]}}"#,
        )
        .unwrap();
        let ItemDetails::Environment(details) = item.details else {
            panic!("not an environment");
        };
        assert!(details.variables[0].concealed);
        assert_eq!((details.project, details.stage), (None, None));
    }

    #[test]
    fn invalid_items_are_rejected() {
        for bad in [
            "{}",
            r#"{"overview":{"type":"login"},"details":{}}"#,
            r#"{"overview":{"title":"t","type":"secureNote"},"details":{}}"#,
            r#"{"overview":{"title":"t","type":"login"},"details":{"username":5}}"#,
            r#"{"overview":{"title":"t","type":"document"},"details":{"attachments":[{"id":"a"}]}}"#,
            r#"{"overview":{"title":"t","type":"maskedEmailProvider"},"details":{"provider":"addy"}}"#,
            r#"{"overview":{"title":"t","type":"wifi"},"details":{"security":"open"}}"#,
            r#"{"overview":{"title":"t","type":"wifi"},"details":{"ssid":"x"}}"#,
            r#"{"overview":{"title":"t","type":"wifi"},"details":{"ssid":"x","security":"wpa2","hidden":"yes"}}"#,
            r#"{"overview":{"title":"t","type":"login"},"details":{"recovery":{"emailSource":{"itemId":"x"}}}}"#,
            r#"{"overview":{"title":"t","type":"environment"},"details":{"variables":[{"key":"1A","value":"x"}]}}"#,
            r#"{"overview":{"title":"t","type":"environment"},"details":{"variables":[{"key":"A","value":"x"},{"key":"A","value":"y"}]}}"#,
            r#"{"overview":{"title":"t","type":"environment"},"details":{"variables":[{"key":"A"}]}}"#,
            r#"{"overview":{"title":"t","type":"environment"},"details":{"project":"shop api"}}"#,
            r#"{"overview":{"title":"t","type":"environment"},"details":{"stage":"prod:1"}}"#,
            r#"{"overview":{"title":"t","type":"sshKey"},"details":{"privateKey":5}}"#,
            r#"{"overview":{"title":"t","type":"bankAccount"},"details":{"iban":5}}"#,
            r#"{"overview":{"title":"t","type":"cryptoWallet"},"details":{"addresses":[{"network":"bitcoin"}]}}"#,
            r#"{"overview":{"title":"t","type":"database"},"details":{"port":5432}}"#,
            r#"{"overview":{"title":"t","type":"custom"},"details":{"fields":[{"value":"x"}]}}"#,
            r#"{"overview":{"title":"t","type":"customTemplate"},"details":{"fields":[{"kind":"text"}]}}"#,
        ] {
            assert_eq!(
                Item::from_json(bad).unwrap_err(),
                Error::InvalidItem,
                "{bad}"
            );
        }
    }
}

#[cfg(test)]
mod version_tests {
    use serde_json::json;

    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn login(totp: &str, notes: &str) -> Item {
        Item::from_parts(
            serde_json::from_value(json!({ "title": "Bank", "type": "login" })).unwrap(),
            json!({ "username": "ada", "totp": totp, "notes": notes }),
        )
        .unwrap()
    }

    fn hotp(counter: u64) -> String {
        format!("otpauth://hotp/Bank:ada?secret={SECRET}&counter={counter}")
    }

    #[test]
    fn a_version_comes_back_without_undoing_what_it_shouldnt() {
        let current = (
            json!({ "title": "New", "type": "login", "favorite": true, "pinned": true }),
            json!({
                "password": "new",
                "totp": hotp(9),
                "passkeys": [{ "rpId": "a.example", "userName": "ada", "createdAt": "x" }],
                "passwordHistory": [{ "password": "older", "changedAt": "y" }],
            }),
        );
        let version = (
            json!({ "title": "Old", "type": "login" }),
            json!({ "password": "old", "totp": hotp(3), "notes": "then" }),
        );
        let (overview, details) = restored_version(&current.0, &current.1, &version.0, &version.1);
        assert_eq!(overview["title"], "Old");
        assert_eq!(overview["favorite"], true);
        assert_eq!(overview["pinned"], true);
        assert_eq!(details["password"], "old");
        assert_eq!(details["notes"], "then");
        assert_eq!(details["passkeys"], current.1["passkeys"]);
        assert_eq!(details["passwordHistory"], current.1["passwordHistory"]);
        assert_eq!(hotp_counter(details["totp"].as_str().unwrap()), Ok(9));
    }

    #[test]
    fn a_favourite_set_only_in_the_version_doesnt_come_back() {
        let (overview, _) = restored_version(
            &json!({ "title": "New", "type": "secureNote" }),
            &json!({ "notes": "new" }),
            &json!({ "title": "Old", "type": "secureNote", "favorite": true, "pinned": true }),
            &json!({ "notes": "old" }),
        );
        assert!(overview.get("favorite").is_none());
        assert!(overview.get("pinned").is_none());
    }

    #[test]
    fn a_counter_alone_merges_and_anything_else_doesnt() {
        let merged = merge_hotp_counter(&login(&hotp(8), "n"), &login(&hotp(5), "n")).unwrap();
        let ItemDetails::Login(details) = &merged.details else {
            panic!()
        };
        assert_eq!(hotp_counter(details.totp.as_deref().unwrap()), Ok(8));
        // The server moved further than this phone: its counter stands.
        let merged = merge_hotp_counter(&login(&hotp(2), "n"), &login(&hotp(5), "n")).unwrap();
        let ItemDetails::Login(details) = &merged.details else {
            panic!()
        };
        assert_eq!(hotp_counter(details.totp.as_deref().unwrap()), Ok(5));
        assert!(merge_hotp_counter(&login(&hotp(8), "mine"), &login(&hotp(5), "theirs")).is_none());
        // Known to be a counter move: the server's other edits stand, with the higher counter.
        let merged = with_newest_hotp(&login(&hotp(8), "old"), &login(&hotp(5), "theirs")).unwrap();
        let ItemDetails::Login(details) = &merged.details else {
            panic!()
        };
        assert_eq!(details.notes.as_deref(), Some("theirs"));
        assert_eq!(hotp_counter(details.totp.as_deref().unwrap()), Ok(8));
    }
}
