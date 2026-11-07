//! Items as Swift and Kotlin types, one per item type, instead of the JSON the store keeps.
//!
//! A save starts from the stored JSON and writes only the fields the apps edit, so fields from a
//! newer client (and the ones edited elsewhere, like passkeys and the password history) are
//! written back untouched, as the item model requires. Cleaning and validation are the web
//! vault's (`apps/web/src/screens/vault/editorModel.ts`): values are trimmed (secrets aren't),
//! empty fields dropped, and the list subtitle filled in.

use std::collections::HashMap;

use octapass_core::item::{ItemDetails as CoreDetails, ItemOverview, ItemType as CoreType};
use octapass_mobile_vault::model::Item as StoredItem;
use serde_json::{Map, Value, json};

use crate::environments::EnvironmentDetails;
use crate::error::{ErrorCode, Result, VaultError};
use crate::qr::{self, WifiNetwork};
use crate::ssh::SshKeyDetails;
pub(crate) use crate::structured::{self, StructuredDetails};

/// Items of this type hold a shared vault's name. They're never listed as items.
pub(crate) use octapass_mobile_vault::model::VAULT_INFO_TYPE;
/// Settings rather than things to list: shown only when a filter asks for the type.
const HIDDEN_TYPES: [&str; 7] = [
    "maskedEmailProvider",
    octapass_mobile_vault::health::HEALTH_SETTINGS_TYPE,
    "equivalentDomains",
    crate::usage::USAGE_STATS_TYPE,
    "customTemplate",
    "fileSafe",
    VAULT_INFO_TYPE,
];
/// Leading or trailing spaces can be part of a secret, so these are kept exactly as typed.
const VERBATIM: [&str; 6] = ["password", "value", "cvv", "pin", "answer", "passphrase"];

#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum ItemType {
    Login,
    Password,
    SecureNote,
    Card,
    Identity,
    Document,
    Wifi,
    SshKey,
    Environment,
    MaskedEmailProvider,
    BankAccount,
    ApiCredential,
    SoftwareLicense,
    IdDocument,
    CryptoWallet,
    Database,
    /// An item of the user's own type.
    Custom,
    /// A user's own item type: field names and kinds, no values. Kept out of lists.
    CustomTemplate,
    /// A type from a newer client, by its name.
    Other {
        name: String,
    },
}

impl ItemType {
    pub fn name(&self) -> &str {
        match self {
            Self::Login => "login",
            Self::Password => "password",
            Self::SecureNote => "secureNote",
            Self::Card => "card",
            Self::Identity => "identity",
            Self::Document => "document",
            Self::Wifi => "wifi",
            Self::SshKey => "sshKey",
            Self::Environment => "environment",
            Self::MaskedEmailProvider => "maskedEmailProvider",
            Self::BankAccount => "bankAccount",
            Self::ApiCredential => "apiCredential",
            Self::SoftwareLicense => "softwareLicense",
            Self::IdDocument => "idDocument",
            Self::CryptoWallet => "cryptoWallet",
            Self::Database => "database",
            Self::Custom => "custom",
            Self::CustomTemplate => "customTemplate",
            Self::Other { name } => name,
        }
    }

    pub fn parse(name: &str) -> Self {
        match name {
            "login" => Self::Login,
            "password" => Self::Password,
            "secureNote" => Self::SecureNote,
            "card" => Self::Card,
            "identity" => Self::Identity,
            "document" => Self::Document,
            "wifi" => Self::Wifi,
            "sshKey" => Self::SshKey,
            "environment" => Self::Environment,
            "maskedEmailProvider" => Self::MaskedEmailProvider,
            "bankAccount" => Self::BankAccount,
            "apiCredential" => Self::ApiCredential,
            "softwareLicense" => Self::SoftwareLicense,
            "idDocument" => Self::IdDocument,
            "cryptoWallet" => Self::CryptoWallet,
            "database" => Self::Database,
            "custom" => Self::Custom,
            "customTemplate" => Self::CustomTemplate,
            other => Self::Other { name: other.into() },
        }
    }

    pub fn is_login_like(&self) -> bool {
        matches!(self, Self::Login | Self::Password)
    }
}

/// A file kept with an item. Added and removed with `addAttachment` and `removeAttachment`,
/// never by editing.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Attachment {
    pub id: String,
    pub name: String,
    /// The media type, like `application/pdf`; empty when unknown.
    pub media_type: String,
    /// Bytes before encryption.
    pub size: u64,
    /// Saved on this phone and waiting to upload.
    pub pending: bool,
}

/// A passkey saved by the AutoFill extension or a browser. Shown, never edited.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Passkey {
    pub rp_id: String,
    pub user_name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CustomField {
    pub label: String,
    pub value: String,
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub changed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BackupCode {
    pub code: String,
    pub used: bool,
}

/// A site's security question. The answer is hidden like a password.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityQuestion {
    pub question: String,
    pub answer: String,
}

/// Where a recovery email or phone came from: `kind` `identity` (with `itemId`) or `alias` (a
/// masked email, with `provider` and `aliasId`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoverySource {
    pub kind: String,
    pub item_id: Option<String>,
    pub provider: Option<String>,
    pub alias_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryInfo {
    pub email: Option<String>,
    pub email_source: Option<RecoverySource>,
    pub phone: Option<String>,
    pub phone_source: Option<RecoverySource>,
    pub backup_codes: Vec<BackupCode>,
    pub security_questions: Vec<SecurityQuestion>,
    /// `totp`, `sms`, `email`, `key`, `passkey` or `none`; a newer client may write others.
    pub two_factor_method: Option<String>,
}

/// Logins and passwords.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct LoginDetails {
    pub username: Option<String>,
    pub password: Option<String>,
    /// An `otpauth://` URI or a bare base32 secret.
    pub totp: Option<String>,
    pub notes: Option<String>,
    /// Read-only.
    pub passkeys: Vec<Passkey>,
    pub recovery: Option<RecoveryInfo>,
    pub custom_fields: Vec<CustomField>,
    /// Newest first. Read-only: a save moves a changed password here.
    pub password_history: Vec<PasswordHistoryEntry>,
    /// The realm of a site's HTTP sign-in prompt, for logins used there rather than in a form.
    #[uniffi(default)]
    pub http_realm: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct SecureNoteDetails {
    pub notes: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct CardDetails {
    pub cardholder: Option<String>,
    pub number: Option<String>,
    /// `MM/YY`
    pub expiry: Option<String>,
    pub cvv: Option<String>,
    pub pin: Option<String>,
    /// Filled in from the number when empty.
    pub brand: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct Address {
    pub line1: Option<String>,
    pub line2: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct IdentityDetails {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<Address>,
    /// `YYYY-MM-DD`
    pub birth_date: Option<String>,
    pub notes: Option<String>,
}

/// One file (the item's first attachment) plus notes.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct DocumentDetails {
    pub notes: Option<String>,
}

/// A Wi-Fi network (plan 01, Wi-Fi). The editor shows the Enterprise fields only for the
/// Enterprise kinds, and a save drops the ones the security type doesn't use, as the web vault's
/// editor does.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WifiDetails {
    /// The network name, exactly as broadcast: spaces at either end are kept.
    pub ssid: String,
    /// `wpa2`, `wpa2Wpa3`, `wpa3`, `wpaWpa2`, `wpa`, `wep`, `open`, `wpa2Enterprise` or
    /// `wpa3Enterprise` (`WIFI_SECURITIES`), or a newer one.
    pub security: String,
    /// The shared password (Personal, WEP), or the user's own on an Enterprise network.
    pub password: Option<String>,
    /// The network doesn't broadcast its name.
    pub hidden: bool,
    /// Enterprise: `peap`, `ttls`, `tls`, `pwd`, `leap` or `fast`.
    pub eap_method: Option<String>,
    /// Enterprise, PEAP and TTLS: `mschapv2`, `gtc`, `pap`, `chap` or `mschap`.
    pub phase2: Option<String>,
    pub username: Option<String>,
    /// Enterprise: the outer (anonymous) identity, when it differs from the username.
    pub identity: Option<String>,
    /// Enterprise: the domain the server's certificate must match.
    pub server_domain: Option<String>,
    /// Enterprise: the CA certificate (PEM) that signed the server's certificate.
    pub ca_certificate: Option<String>,
    /// Shows a sign-in page after joining, as in hotels and airports.
    pub captive_portal: bool,
    /// Set up by an organisation: the user's own note, not the system's state.
    pub managed: bool,
    /// A phone's or tablet's Personal Hotspot.
    pub hotspot: bool,
    pub notes: Option<String>,
    pub custom_fields: Vec<CustomField>,
    /// Newest first. Read-only.
    pub password_history: Vec<PasswordHistoryEntry>,
}

impl Default for WifiDetails {
    fn default() -> Self {
        Self {
            ssid: String::new(),
            security: "wpa2".into(),
            password: None,
            hidden: false,
            eap_method: None,
            phase2: None,
            username: None,
            identity: None,
            server_domain: None,
            ca_certificate: None,
            captive_portal: false,
            managed: false,
            hotspot: false,
            notes: None,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
        }
    }
}

/// The security types in the order the editor offers them.
pub const WIFI_SECURITIES: [&str; 9] = [
    "wpa2",
    "wpa2Wpa3",
    "wpa3",
    "wpaWpa2",
    "wpa",
    "wep",
    "open",
    "wpa2Enterprise",
    "wpa3Enterprise",
];
pub const WIFI_EAP_METHODS: [&str; 6] = ["peap", "ttls", "tls", "pwd", "leap", "fast"];
pub const WIFI_PHASE2: [&str; 5] = ["mschapv2", "gtc", "pap", "chap", "mschap"];

pub(crate) fn is_enterprise(security: &str) -> bool {
    matches!(security, "wpa2Enterprise" | "wpa3Enterprise")
}

/// Open networks have no password; every other kind does.
pub(crate) fn has_password(security: &str) -> bool {
    security != "open"
}

/// The editor's choices: security types, EAP methods and inner methods, in the order shown.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct WifiChoices {
    pub securities: Vec<String>,
    pub eap_methods: Vec<String>,
    pub phase2: Vec<String>,
}

#[uniffi::export]
pub fn wifi_choices() -> WifiChoices {
    let list = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect();
    WifiChoices {
        securities: list(&WIFI_SECURITIES),
        eap_methods: list(&WIFI_EAP_METHODS),
        phase2: list(&WIFI_PHASE2),
    }
}

/// A connected masked email provider. Its token never leaves Rust; connect and disconnect
/// providers with the masked email calls.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MaskedEmailProviderDetails {
    pub provider: String,
    pub base_url: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ItemDetails {
    Login {
        login: LoginDetails,
    },
    Password {
        login: LoginDetails,
    },
    SecureNote {
        note: SecureNoteDetails,
    },
    Card {
        card: CardDetails,
    },
    Identity {
        identity: IdentityDetails,
    },
    Document {
        document: DocumentDetails,
    },
    Wifi {
        wifi: WifiDetails,
    },
    SshKey {
        key: SshKeyDetails,
    },
    Environment {
        environment: EnvironmentDetails,
    },
    MaskedEmailProvider {
        provider: MaskedEmailProviderDetails,
    },
    /// A bank account, API credential, software licence, ID document, crypto wallet, database,
    /// custom item or custom template. `fieldSpecs` says what each one holds, so the apps have one
    /// editor and one detail screen for all of them.
    Structured {
        item_type: ItemType,
        structured: StructuredDetails,
    },
    /// A type from a newer client: its details as JSON, written back as they are.
    Other {
        item_type: String,
        json: String,
    },
}

impl ItemDetails {
    pub fn item_type(&self) -> ItemType {
        match self {
            Self::Login { .. } => ItemType::Login,
            Self::Password { .. } => ItemType::Password,
            Self::SecureNote { .. } => ItemType::SecureNote,
            Self::Card { .. } => ItemType::Card,
            Self::Identity { .. } => ItemType::Identity,
            Self::Document { .. } => ItemType::Document,
            Self::Wifi { .. } => ItemType::Wifi,
            Self::SshKey { .. } => ItemType::SshKey,
            Self::Environment { .. } => ItemType::Environment,
            Self::MaskedEmailProvider { .. } => ItemType::MaskedEmailProvider,
            Self::Structured { item_type, .. } => item_type.clone(),
            Self::Other { item_type, .. } => ItemType::parse(item_type),
        }
    }

    fn login(&self) -> Option<&LoginDetails> {
        match self {
            Self::Login { login } | Self::Password { login } => Some(login),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Item {
    pub id: String,
    pub vault_id: String,
    /// Pass it back in the draft: an edit of an older revision is saved as a conflicting copy.
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
    /// In the trash since.
    pub deleted_at: Option<String>,
    pub item_type: ItemType,
    pub title: String,
    pub subtitle: Option<String>,
    pub urls: Vec<String>,
    /// Per-website match modes (`URL_MATCH_MODES`), keyed by the URL as written in `urls`. A URL
    /// that isn't here matches by `subdomains`.
    pub url_match: HashMap<String, String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub details: ItemDetails,
    pub attachments: Vec<Attachment>,
    /// The Wi-Fi network a password or login describes (plan 14): offer Connect and its QR code.
    pub wifi: Option<WifiNetwork>,
    /// The dates to show (`itemDates`): those from the app it was imported from where it has
    /// them, else the sync record's.
    #[uniffi(default)]
    pub shown_created_at: Option<String>,
    #[uniffi(default)]
    pub shown_updated_at: Option<String>,
    /// From the app it was imported from.
    #[uniffi(default)]
    pub last_used_at: Option<String>,
    /// The later of the imported date and the newest password history entry, for an item with a
    /// password.
    #[uniffi(default)]
    pub password_changed_at: Option<String>,
    /// Listed under Pinned, a list of its own apart from the favourites.
    #[uniffi(default = false)]
    pub pinned: bool,
}

/// A past version of an item, from its encrypted history. `item` holds what it said then; the
/// files listed are the item's current ones, because versions don't keep files.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemVersion {
    pub revision: u64,
    /// When this version was saved.
    pub updated_at: String,
    pub item: Item,
}

impl ItemVersion {
    pub(crate) fn new(
        current: &StoredItem,
        version: octapass_mobile_vault::vault::ItemVersion,
    ) -> Self {
        let then = StoredItem {
            overview: version.overview,
            details: version.details,
            ..current.clone()
        };
        Self {
            revision: version.revision,
            updated_at: version.updated_at,
            item: Item::from(&then),
        }
    }
}

/// A counter-based code. Each one is made once, when the user asks.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HotpCode {
    pub code: String,
    /// The counter it was made from. The item's counter has already moved past it.
    pub counter: u64,
}

/// What Settings → Equivalent domains shows.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EquivalentDomains {
    /// The user's own groups of registrable domains.
    pub groups: Vec<Vec<String>>,
    /// The built-in groups, for turning them off.
    pub defaults: Vec<Vec<String>>,
    /// Built-in groups turned off, each named by its first domain.
    pub excluded_defaults: Vec<String>,
    /// What a save refused: public suffixes, addresses, anything that isn't a domain.
    pub rejected: Vec<String>,
}

impl From<octapass_mobile_vault::vault::EquivalentDomains> for EquivalentDomains {
    fn from(list: octapass_mobile_vault::vault::EquivalentDomains) -> Self {
        Self {
            groups: list.groups,
            defaults: list.defaults,
            excluded_defaults: list.excluded_defaults,
            rejected: list.rejected,
        }
    }
}

/// A list row: the overview plus flags from the details, never secrets.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    pub vault_id: String,
    pub item_type: ItemType,
    pub title: String,
    pub subtitle: Option<String>,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_totp: bool,
    pub has_passkey: bool,
    pub attachment_count: u32,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    /// The website a login is combined under in site rows (`siteOf`): the host of its first URL.
    pub site: Option<String>,
    /// The domain its website icon is asked for (`iconDomain`): the registrable domain of its
    /// first URL, for any item with one.
    pub icon_domain: Option<String>,
    /// An environment's project and stage.
    #[uniffi(default)]
    pub project: Option<String>,
    #[uniffi(default)]
    pub stage: Option<String>,
    /// An environment's variable names (never their values): searched, and compared across
    /// stages.
    #[uniffi(default)]
    pub variable_keys: Vec<String>,
    #[uniffi(default = false)]
    pub pinned: bool,
}

/// What `saveItem` takes. No `id` for a new item; `revision` is the one the edit started from.
/// The type comes from `details`; an item keeps its type.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub revision: Option<u64>,
    pub title: String,
    pub subtitle: Option<String>,
    pub urls: Vec<String>,
    /// As in `Item`. Modes of URLs no longer in `urls`, and `subdomains` (the default), aren't
    /// saved.
    pub url_match: HashMap<String, String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub details: ItemDetails,
    #[uniffi(default = false)]
    pub pinned: bool,
}

/// The website match modes, in the order to offer them: the default (this host, the domains above
/// it and the hosts below it), every part of the registrable domain, the same host and port, pages
/// under this address, a regular expression over the page's address, never.
#[uniffi::export]
pub fn url_match_modes() -> Vec<String> {
    [
        "subdomains",
        "baseDomain",
        "host",
        "startsWith",
        "regex",
        "never",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// `urls` with each website once, the first of each staying: what the item view lists. Two URLs
/// are one website when autofill would offer the login on the same pages (`same_website` in
/// octapass-core: by default the same host, whatever the scheme, port, path or `www.`). `url_match`
/// is the item's, keyed by the URL as written.
#[uniffi::export]
pub fn unique_websites(urls: Vec<String>, url_match: HashMap<String, String>) -> Vec<String> {
    let modes = octapass_core::matching::websites::modes_of(Some(&Value::Object(
        url_match
            .into_iter()
            .map(|(url, mode)| (url, Value::String(mode)))
            .collect(),
    )));
    octapass_core::matching::unique_websites(&urls, &modes)
}

/// A field `validateDraft` refuses, with the catalog key of the message to show under it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FieldError {
    /// `title`, `urls.1`, `totp`, `recovery.email`, `expiry`, `number`, `email`.
    pub field: String,
    /// Like `validation.titleRequired`.
    pub message_key: String,
}

// ---------- Reading ----------

pub(crate) fn text(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn texts(map: &Map<String, Value>, key: &str) -> Vec<String> {
    map.get(key)
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

pub(crate) fn type_of(item: &StoredItem) -> String {
    item.overview
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

pub(crate) fn is_vault_info(item: &StoredItem) -> bool {
    item.is_vault_info()
}

/// `https://example.com` for `https://www.Example.com/login?x`: the scheme, the host without
/// `www.` and the port, as the importer and the web vault's `loginOrigin` compare logins.
fn login_origin(url: &str) -> Option<String> {
    let url = url.trim();
    if url.is_empty() || url.contains(char::is_whitespace) {
        return None;
    }
    let has_scheme = url.split_once("://").is_some_and(|(scheme, _)| {
        scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    });
    let parsed = if has_scheme {
        url::Url::parse(url)
    } else {
        url::Url::parse(&format!("https://{url}"))
    }
    .ok()?;
    let host = parsed.host_str()?.trim_end_matches('.').to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    if host.is_empty() {
        return None;
    }
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    Some(format!("{}://{host}{port}", parsed.scheme()))
}

/// Whether `item` is the login `draft`, a new one, would add again: a website on the same site
/// and the same username, ignoring case. A login without a website isn't compared. As the web
/// vault's `isSameLogin` (`packages/vault-client/src/duplicates.ts`).
pub(crate) fn is_same_login(item: &StoredItem, draft: &ItemDraft) -> bool {
    let ItemDetails::Login { login } = &draft.details else {
        return false;
    };
    if draft.id.is_some() || item.deleted_at.is_some() || type_of(item) != "login" {
        return false;
    }
    let wanted: Vec<String> = draft.urls.iter().filter_map(|u| login_origin(u)).collect();
    let theirs = item
        .overview
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(login_origin);
    let user = |name: Option<&str>| name.unwrap_or_default().trim().to_lowercase();
    let same_user = user(item.details.get("username").and_then(Value::as_str))
        == user(login.username.as_deref());
    same_user && theirs.into_iter().any(|origin| wanted.contains(&origin))
}

/// Listed unless asked for by type.
pub(crate) fn is_hidden_type(name: &str) -> bool {
    HIDDEN_TYPES.contains(&name)
}

pub(crate) fn attachments(details: &Value) -> Vec<Attachment> {
    details
        .get("attachments")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|entry| {
                    let entry = object(entry);
                    Attachment {
                        id: text(&entry, "id").unwrap_or_default(),
                        name: text(&entry, "name").unwrap_or_default(),
                        media_type: text(&entry, "type").unwrap_or_default(),
                        size: entry.get("size").and_then(Value::as_u64).unwrap_or(0),
                        pending: entry.get("pending") == Some(&Value::Bool(true)),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn recovery_source(source: &octapass_core::item::RecoverySource) -> RecoverySource {
    RecoverySource {
        kind: source.kind.clone(),
        item_id: source.item_id.clone(),
        provider: source.provider.clone(),
        alias_id: source.alias_id.clone(),
    }
}

fn login_details(login: octapass_core::item::LoginDetails) -> LoginDetails {
    LoginDetails {
        username: login.username,
        password: login.password,
        totp: login.totp,
        notes: login.notes,
        passkeys: login
            .passkeys
            .unwrap_or_default()
            .into_iter()
            .map(|p| Passkey {
                rp_id: p.rp_id,
                user_name: p.user_name,
                created_at: p.created_at,
            })
            .collect(),
        recovery: login.recovery.map(|r| RecoveryInfo {
            email: r.email,
            email_source: r.email_source.as_deref().map(recovery_source),
            phone: r.phone,
            phone_source: r.phone_source.as_deref().map(recovery_source),
            backup_codes: r
                .backup_codes
                .unwrap_or_default()
                .into_iter()
                .map(|c| BackupCode {
                    code: c.code,
                    used: c.used,
                })
                .collect(),
            security_questions: r
                .security_questions
                .unwrap_or_default()
                .into_iter()
                .map(|q| SecurityQuestion {
                    question: q.question,
                    answer: q.answer,
                })
                .collect(),
            two_factor_method: r.two_factor_method,
        }),
        custom_fields: login
            .custom_fields
            .unwrap_or_default()
            .into_iter()
            .map(|f| CustomField {
                label: f.label,
                value: f.value,
                hidden: f.hidden,
            })
            .collect(),
        password_history: login
            .password_history
            .unwrap_or_default()
            .into_iter()
            .map(|h| PasswordHistoryEntry {
                password: h.password,
                changed_at: h.changed_at,
            })
            .collect(),
        http_realm: login.http_realm,
    }
}

/// When a login's or network's password last changed (`itemDates`).
fn password_changed_at(item_type: &str, details: &Value) -> Option<String> {
    if !matches!(item_type, "login" | "password" | "wifi") {
        return None;
    }
    let details = object(details);
    text(&details, "password").filter(|p| !p.is_empty())?;
    let history = details.get("passwordHistory").and_then(Value::as_array);
    text(&details, "passwordChangedAt")
        .into_iter()
        .chain(
            history
                .into_iter()
                .flatten()
                .filter_map(|entry| entry.get("changedAt")?.as_str().map(str::to_owned)),
        )
        .filter(|date| crate::list::is_date(date))
        .max_by_key(|date| crate::list::millis(date))
}

/// The typed details of stored JSON. JSON the item model refuses comes back as `Other`.
pub(crate) fn details_of(item_type: &str, details: &Value) -> ItemDetails {
    let other = || ItemDetails::Other {
        item_type: item_type.to_owned(),
        json: details.to_string(),
    };
    let Ok(typed) = CoreDetails::from_value(&CoreType::from(item_type.to_owned()), details.clone())
    else {
        return other();
    };
    match typed {
        CoreDetails::Login(login) if item_type == "password" => ItemDetails::Password {
            login: login_details(login),
        },
        CoreDetails::Login(login) => ItemDetails::Login {
            login: login_details(login),
        },
        CoreDetails::SecureNote(note) => ItemDetails::SecureNote {
            note: SecureNoteDetails { notes: note.notes },
        },
        CoreDetails::Card(card) => ItemDetails::Card {
            card: CardDetails {
                cardholder: card.cardholder,
                number: card.number,
                expiry: card.expiry,
                cvv: card.cvv,
                pin: card.pin,
                brand: card.brand,
                notes: card.notes,
            },
        },
        CoreDetails::Identity(identity) => ItemDetails::Identity {
            identity: IdentityDetails {
                first_name: identity.first_name,
                last_name: identity.last_name,
                email: identity.email,
                phone: identity.phone,
                address: identity.address.map(|a| Address {
                    line1: a.line1,
                    line2: a.line2,
                    city: a.city,
                    region: a.region,
                    postal_code: a.postal_code,
                    country: a.country,
                }),
                birth_date: identity.birth_date,
                notes: identity.notes,
            },
        },
        CoreDetails::Document(document) => ItemDetails::Document {
            document: DocumentDetails {
                notes: document.notes,
            },
        },
        CoreDetails::Wifi(wifi) => ItemDetails::Wifi {
            wifi: WifiDetails {
                ssid: wifi.ssid,
                security: wifi.security,
                password: wifi.password,
                hidden: wifi.hidden == Some(true),
                eap_method: wifi.eap_method,
                phase2: wifi.phase2,
                username: wifi.username,
                identity: wifi.identity,
                server_domain: wifi.server_domain,
                ca_certificate: wifi.ca_certificate,
                captive_portal: wifi.captive_portal == Some(true),
                managed: wifi.managed == Some(true),
                hotspot: wifi.hotspot == Some(true),
                notes: wifi.notes,
                custom_fields: wifi
                    .custom_fields
                    .unwrap_or_default()
                    .into_iter()
                    .map(|f| CustomField {
                        label: f.label,
                        value: f.value,
                        hidden: f.hidden,
                    })
                    .collect(),
                password_history: wifi
                    .password_history
                    .unwrap_or_default()
                    .into_iter()
                    .map(|h| PasswordHistoryEntry {
                        password: h.password,
                        changed_at: h.changed_at,
                    })
                    .collect(),
            },
        },
        CoreDetails::MaskedEmailProvider(provider) => ItemDetails::MaskedEmailProvider {
            provider: MaskedEmailProviderDetails {
                provider: provider.provider,
                base_url: provider.base_url,
                domain: provider.domain,
            },
        },
        CoreDetails::SshKey(key) => ItemDetails::SshKey {
            key: crate::ssh::details_from_core(key),
        },
        CoreDetails::Environment(environment) => ItemDetails::Environment {
            environment: crate::environments::details_from_core(environment),
        },
        CoreDetails::BankAccount(_)
        | CoreDetails::ApiCredential(_)
        | CoreDetails::SoftwareLicense(_)
        | CoreDetails::IdDocument(_)
        | CoreDetails::CryptoWallet(_)
        | CoreDetails::Database(_)
        | CoreDetails::Custom(_)
        | CoreDetails::CustomTemplate(_) => ItemDetails::Structured {
            item_type: ItemType::parse(item_type),
            structured: structured::read(item_type, details),
        },
        // Native certificate and key screens come in a later wave; until then they
        // round-trip as JSON.
        CoreDetails::EquivalentDomains(_)
        | CoreDetails::Certificate(_)
        | CoreDetails::Key(_)
        | CoreDetails::Other(_) => other(),
    }
}

impl From<&StoredItem> for Item {
    fn from(item: &StoredItem) -> Self {
        let overview = object(&item.overview);
        let item_type = type_of(item);
        let details = details_of(&item_type, &item.details);
        let wifi = match &details {
            ItemDetails::Wifi { wifi } => qr::network_of(wifi),
            _ => details.login().and_then(|login| {
                qr::wifi_network(login.password.as_deref(), &login.custom_fields)
            }),
        };
        Self {
            id: item.id.clone(),
            vault_id: item.vault_id.clone(),
            revision: item.revision,
            created_at: item.created_at.clone(),
            updated_at: item.updated_at.clone(),
            deleted_at: item.deleted_at.clone(),
            item_type: ItemType::parse(&item_type),
            title: text(&overview, "title").unwrap_or_default(),
            subtitle: text(&overview, "subtitle"),
            urls: texts(&overview, "urls"),
            url_match: url_modes(&overview),
            tags: texts(&overview, "tags"),
            favorite: overview.get("favorite") == Some(&Value::Bool(true)),
            attachments: attachments(&item.details),
            details,
            wifi,
            shown_created_at: text(&overview, "createdAt").or(Some(item.created_at.clone())),
            shown_updated_at: text(&overview, "updatedAt").or(Some(item.updated_at.clone())),
            last_used_at: text(&overview, "lastUsedAt"),
            password_changed_at: password_changed_at(&item_type, &item.details),
            pinned: overview.get("pinned") == Some(&Value::Bool(true)),
        }
    }
}

impl From<&StoredItem> for ItemSummary {
    fn from(item: &StoredItem) -> Self {
        let overview = object(&item.overview);
        let item_type = ItemType::parse(&type_of(item));
        let details = object(&item.details);
        let login = item_type.is_login_like();
        let urls = texts(&overview, "urls");
        let environment = item_type == ItemType::Environment;
        Self {
            project: text(&details, "project").filter(|_| environment),
            stage: text(&details, "stage").filter(|_| environment),
            variable_keys: details
                .get("variables")
                .and_then(Value::as_array)
                .filter(|_| environment)
                .map(|list| {
                    list.iter()
                        .filter_map(|v| v.get("key").and_then(Value::as_str).map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            id: item.id.clone(),
            vault_id: item.vault_id.clone(),
            title: text(&overview, "title").unwrap_or_default(),
            subtitle: text(&overview, "subtitle"),
            site: (item_type == ItemType::Login)
                .then(|| urls.first().and_then(|url| crate::list::site_host(url)))
                .flatten(),
            icon_domain: crate::icons::icon_domain_of(&urls),
            urls,
            tags: texts(&overview, "tags"),
            favorite: overview.get("favorite") == Some(&Value::Bool(true)),
            pinned: overview.get("pinned") == Some(&Value::Bool(true)),
            has_totp: login && text(&details, "totp").is_some_and(|t| !t.is_empty()),
            has_passkey: login
                && details
                    .get("passkeys")
                    .and_then(Value::as_array)
                    .is_some_and(|p| !p.is_empty()),
            attachment_count: attachments(&item.details).len() as u32,
            created_at: item.created_at.clone(),
            updated_at: item.updated_at.clone(),
            deleted_at: item.deleted_at.clone(),
            item_type,
        }
    }
}

/// An empty draft of `item_type` in `vault_id`, for the "new item" editor.
#[uniffi::export]
pub fn new_item_draft(item_type: ItemType, vault_id: String) -> ItemDraft {
    let details = match item_type {
        ItemType::Login => ItemDetails::Login {
            login: LoginDetails::default(),
        },
        ItemType::Password => ItemDetails::Password {
            login: LoginDetails::default(),
        },
        ItemType::SecureNote => ItemDetails::SecureNote {
            note: SecureNoteDetails::default(),
        },
        ItemType::Card => ItemDetails::Card {
            card: CardDetails::default(),
        },
        ItemType::Identity => ItemDetails::Identity {
            identity: IdentityDetails::default(),
        },
        ItemType::Document => ItemDetails::Document {
            document: DocumentDetails::default(),
        },
        ItemType::Wifi => ItemDetails::Wifi {
            wifi: WifiDetails::default(),
        },
        ItemType::SshKey => ItemDetails::SshKey {
            key: SshKeyDetails::default(),
        },
        ItemType::Environment => ItemDetails::Environment {
            environment: EnvironmentDetails::default(),
        },
        ItemType::BankAccount
        | ItemType::ApiCredential
        | ItemType::SoftwareLicense
        | ItemType::IdDocument
        | ItemType::CryptoWallet
        | ItemType::Database
        | ItemType::Custom
        | ItemType::CustomTemplate => ItemDetails::Structured {
            item_type: item_type.clone(),
            structured: StructuredDetails::default(),
        },
        ItemType::MaskedEmailProvider | ItemType::Other { .. } => ItemDetails::Other {
            item_type: item_type.name().to_owned(),
            json: "{\"schemaVersion\":1}".into(),
        },
    };
    ItemDraft {
        id: None,
        vault_id,
        revision: None,
        title: String::new(),
        subtitle: None,
        urls: Vec::new(),
        url_match: HashMap::new(),
        tags: Vec::new(),
        favorite: false,
        details,
        pinned: false,
    }
}

/// The editor's starting point for an existing item.
#[uniffi::export]
pub fn item_draft(item: Item) -> ItemDraft {
    ItemDraft {
        id: Some(item.id),
        vault_id: item.vault_id,
        revision: Some(item.revision),
        title: item.title,
        subtitle: item.subtitle,
        urls: item.urls,
        url_match: item.url_match,
        tags: item.tags,
        favorite: item.favorite,
        details: item.details,
        pinned: item.pinned,
    }
}

fn url_modes(overview: &Map<String, Value>) -> HashMap<String, String> {
    overview
        .get("urlMatch")
        .and_then(Value::as_object)
        .map(|modes| {
            modes
                .iter()
                .filter_map(|(url, mode)| Some((url.clone(), mode.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

// ---------- Validation ----------

fn looks_like_url(value: &str) -> bool {
    let has_scheme = value
        .split_once("://")
        .is_some_and(|(scheme, _)| is_scheme(scheme));
    let text = if has_scheme {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    url::Url::parse(&text)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .is_some_and(|host| host.contains('.') || host == "localhost")
}

fn is_scheme(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
}

/// An email address as the account forms take it: trimmed, in lower case.
#[uniffi::export]
pub fn normalize_email(email: String) -> String {
    email.trim().to_lowercase()
}

/// The web vault's email check, for the account forms (after `normalizeEmail`) and fields.
#[uniffi::export(name = "isValidEmail")]
pub fn valid_email(email: String) -> bool {
    is_valid_email(&email)
}

pub(crate) fn is_valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    let clean = |part: &str| !part.is_empty() && !part.chars().any(char::is_whitespace);
    clean(local)
        && clean(domain)
        && !domain.contains('@')
        && domain
            .split_once('.')
            .is_some_and(|(name, rest)| !name.is_empty() && !rest.is_empty())
}

fn is_valid_totp(totp: &str) -> bool {
    use octapass_core::tools::totp::{is_hotp, totp_code};
    is_hotp(totp) || totp_code(totp, 0).is_ok()
}

fn trimmed(value: &Option<String>) -> &str {
    value.as_deref().map(str::trim).unwrap_or_default()
}

/// Field errors, empty when the draft can be saved (`validateDraft` in the web vault).
#[uniffi::export]
pub fn validate_draft(draft: ItemDraft) -> Vec<FieldError> {
    let mut errors = Vec::new();
    let mut fail = |field: String, key: &str| {
        errors.push(FieldError {
            field,
            // A key with a group of its own, like `env.invalidKey`, stays as it is.
            message_key: if key.contains('.') {
                key.to_owned()
            } else {
                format!("validation.{key}")
            },
        })
    };
    // A network without a title is named after itself, an SSH key after its comment.
    let named = match &draft.details {
        ItemDetails::Wifi { wifi } => !wifi.ssid.trim().is_empty(),
        ItemDetails::SshKey { key } => !trimmed(&key.comment).is_empty(),
        _ => false,
    };
    if draft.title.trim().is_empty() && !named {
        fail("title".into(), "titleRequired");
    }
    match &draft.details {
        ItemDetails::Login { login } | ItemDetails::Password { login } => {
            for (i, url) in draft.urls.iter().enumerate() {
                if url.trim().is_empty() {
                    continue;
                }
                if draft.url_match.get(url).map(String::as_str) == Some("regex") {
                    if !octapass_core::matching::is_valid_pattern(url.trim()) {
                        fail(format!("urls.{i}"), "regex");
                    }
                } else if !looks_like_url(url.trim()) {
                    fail(format!("urls.{i}"), "url");
                }
            }
            let totp = trimmed(&login.totp);
            if !totp.is_empty() && !is_valid_totp(totp) {
                fail("totp".into(), "totp");
            }
            let email = login
                .recovery
                .as_ref()
                .map(|r| trimmed(&r.email))
                .unwrap_or_default();
            if !email.is_empty() && !is_valid_email(email) {
                fail("recovery.email".into(), "email");
            }
        }
        ItemDetails::Card { card } => {
            let expiry = trimmed(&card.expiry);
            if !expiry.is_empty() && !is_expiry(expiry) {
                fail("expiry".into(), "expiry");
            }
            let number = trimmed(&card.number);
            let digits_ok = (12..=23).contains(&number.chars().count())
                && number
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == ' ' || c == '-');
            if !number.is_empty() && !digits_ok {
                fail("number".into(), "cardNumber");
            }
        }
        ItemDetails::Identity { identity } => {
            let email = trimmed(&identity.email);
            if !email.is_empty() && !is_valid_email(email) {
                fail("email".into(), "email");
            }
        }
        ItemDetails::Wifi { wifi } => {
            if wifi.ssid.trim().is_empty() {
                fail("ssid".into(), "ssidRequired");
            }
            let password = wifi.password.as_deref().unwrap_or_default();
            let security = wifi.security.as_str();
            if !password.is_empty() && security == "wep" && !is_wep_key(password) {
                fail("password".into(), "wepKey");
            }
            if !password.is_empty()
                && has_password(security)
                && security != "wep"
                && !is_enterprise(security)
                && !is_wpa_password(password)
            {
                fail("password".into(), "wpaPassword");
            }
        }
        ItemDetails::SshKey { key } => {
            if key.private_key.as_deref().unwrap_or_default().is_empty() {
                fail("privateKey".into(), "sshKeyRequired");
            }
        }
        ItemDetails::Environment { environment } => {
            for (i, variable) in environment.variables.iter().enumerate() {
                let key = variable.key.trim();
                if key.is_empty() && variable.value.is_empty() {
                    continue;
                }
                if !octapass_core::environment::valid_key(key) {
                    fail(format!("variables.{i}.key"), "env.invalidKey");
                } else if environment.variables[..i]
                    .iter()
                    .any(|one| one.key.trim() == key)
                {
                    fail(format!("variables.{i}.key"), "env.duplicateKey");
                }
            }
            let project = trimmed(&environment.project);
            if !project.is_empty() && !octapass_core::environment::valid_project(project) {
                fail("project".into(), "env.invalidProject");
            }
            let stage = trimmed(&environment.stage);
            if !stage.is_empty() && !octapass_core::environment::valid_stage(stage) {
                fail("stage".into(), "env.invalidStage");
            }
        }
        ItemDetails::Structured {
            item_type,
            structured,
        } => {
            for (field, message) in structured::validate(item_type.name(), structured) {
                fail(field, message);
            }
        }
        _ => {}
    }
    errors
}

/// WPA Personal: a passphrase of 8 to 63 characters, or the raw key as 64 hex digits.
fn is_wpa_password(password: &str) -> bool {
    let length = password.chars().count();
    (8..=63).contains(&length)
        || (password.len() == 64 && password.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_wep_key(key: &str) -> bool {
    let length = key.chars().count();
    length == 5
        || length == 13
        || ((key.len() == 10 || key.len() == 26) && key.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `MM/YY`
fn is_expiry(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 5
        && bytes[2] == b'/'
        && bytes[..2].iter().chain(&bytes[3..]).all(u8::is_ascii_digit)
        && matches!(
            &text[..2],
            "01" | "02" | "03" | "04" | "05" | "06" | "07" | "08" | "09" | "10" | "11" | "12"
        )
}

/// The card's brand from its number, as the web vault's editor guesses it.
pub(crate) fn card_brand(number: &str) -> Option<&'static str> {
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| digits.starts_with(p));
    if digits.starts_with('4') {
        Some("Visa")
    } else if starts(&[
        "51", "52", "53", "54", "55", "22", "23", "24", "25", "26", "27",
    ]) {
        Some("Mastercard")
    } else if starts(&["34", "37"]) {
        Some("American Express")
    } else if starts(&["6011", "65"]) {
        Some("Discover")
    } else {
        None
    }
}

// ---------- Writing ----------

/// Sets `key` to the trimmed text (as typed for secrets), or removes it when empty.
pub(crate) fn set_text(map: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    let value = value.as_deref().unwrap_or_default();
    let value = if VERBATIM.contains(&key) {
        value
    } else {
        value.trim()
    };
    if value.is_empty() {
        map.remove(key);
    } else {
        map.insert(key.into(), Value::String(value.into()));
    }
}

/// A list of objects edited in place: entry `i` starts from the stored entry `i`, so fields this
/// version doesn't know stay with it. Empty entries are dropped; so is the list when empty.
pub(crate) fn set_list<T>(
    map: &mut Map<String, Value>,
    key: &str,
    entries: &[T],
    write: impl Fn(&mut Map<String, Value>, &T),
    keep: impl Fn(&Map<String, Value>) -> bool,
) {
    let stored: Vec<Value> = map
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let list: Vec<Value> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, entry)| {
            let mut fields = stored.get(i).map(object).unwrap_or_default();
            write(&mut fields, entry);
            keep(&fields).then_some(Value::Object(fields))
        })
        .collect();
    if list.is_empty() {
        map.remove(key);
    } else {
        map.insert(key.into(), Value::Array(list));
    }
}

fn source_value(source: &RecoverySource, stored: Option<&Value>) -> Value {
    let mut fields = stored
        .filter(|s| s.get("kind").and_then(Value::as_str) == Some(source.kind.as_str()))
        .map(object)
        .unwrap_or_default();
    fields.insert("kind".into(), Value::String(source.kind.clone()));
    set_text(&mut fields, "itemId", &source.item_id);
    set_text(&mut fields, "provider", &source.provider);
    set_text(&mut fields, "aliasId", &source.alias_id);
    Value::Object(fields)
}

fn write_recovery(details: &mut Map<String, Value>, recovery: &Option<RecoveryInfo>) {
    let mut fields = details.get("recovery").map(object).unwrap_or_default();
    let recovery = recovery.clone().unwrap_or_default();
    set_text(&mut fields, "email", &recovery.email);
    set_text(&mut fields, "phone", &recovery.phone);
    set_text(&mut fields, "twoFactorMethod", &recovery.two_factor_method);
    for (key, value, source) in [
        ("emailSource", &recovery.email, &recovery.email_source),
        ("phoneSource", &recovery.phone, &recovery.phone_source),
    ] {
        // A link means nothing without the value it came from.
        match source.as_ref().filter(|_| !trimmed(value).is_empty()) {
            Some(source) => {
                let value = source_value(source, fields.get(key));
                fields.insert(key.into(), value);
            }
            None => {
                fields.remove(key);
            }
        }
    }
    set_list(
        &mut fields,
        "backupCodes",
        &recovery.backup_codes,
        |entry, code| {
            entry.insert("code".into(), Value::String(code.code.trim().into()));
            entry.insert("used".into(), Value::Bool(code.used));
        },
        |entry| {
            entry
                .get("code")
                .and_then(Value::as_str)
                .is_some_and(|c| !c.is_empty())
        },
    );
    set_list(
        &mut fields,
        "securityQuestions",
        &recovery.security_questions,
        |entry, question| {
            entry.insert(
                "question".into(),
                Value::String(question.question.trim().into()),
            );
            entry.insert("answer".into(), Value::String(question.answer.clone()));
        },
        |entry| {
            ["question", "answer"].iter().any(|key| {
                entry
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.is_empty())
            })
        },
    );
    if fields.is_empty() {
        details.remove("recovery");
    } else {
        details.insert("recovery".into(), Value::Object(fields));
    }
}

fn write_login(details: &mut Map<String, Value>, login: &LoginDetails) {
    for (key, value) in [
        ("username", &login.username),
        ("password", &login.password),
        ("totp", &login.totp),
        ("notes", &login.notes),
        ("httpRealm", &login.http_realm),
    ] {
        set_text(details, key, value);
    }
    write_recovery(details, &login.recovery);
    write_custom_fields(details, &login.custom_fields);
}

fn set_flag(map: &mut Map<String, Value>, key: &str, on: bool) {
    if on {
        map.insert(key.into(), Value::Bool(true));
    } else {
        map.remove(key);
    }
}

fn write_wifi(details: &mut Map<String, Value>, wifi: &WifiDetails) {
    // Required, so kept even while empty; exactly as typed.
    details.insert("ssid".into(), Value::String(wifi.ssid.clone()));
    let security = wifi.security.trim();
    details.insert("security".into(), Value::String(security.into()));
    let password = wifi.password.clone().filter(|_| has_password(security));
    set_text(details, "password", &password);
    // Off switches and settings another security type doesn't use aren't kept.
    for (key, on) in [
        ("hidden", wifi.hidden),
        ("captivePortal", wifi.captive_portal),
        ("managed", wifi.managed),
        ("hotspot", wifi.hotspot),
    ] {
        set_flag(details, key, on);
    }
    let enterprise = is_enterprise(security);
    let keep = |value: &Option<String>| value.clone().filter(|_| enterprise);
    let eap = keep(&wifi.eap_method);
    let inner = matches!(trimmed(&eap), "peap" | "ttls");
    for (key, value) in [
        ("eapMethod", eap.clone()),
        (
            "phase2",
            wifi.phase2.clone().filter(|_| enterprise && inner),
        ),
        ("username", keep(&wifi.username)),
        ("identity", keep(&wifi.identity)),
        ("serverDomain", keep(&wifi.server_domain)),
        ("caCertificate", keep(&wifi.ca_certificate)),
        ("notes", wifi.notes.clone()),
    ] {
        set_text(details, key, &value);
    }
    write_custom_fields(details, &wifi.custom_fields);
}

pub(crate) fn write_custom_fields(details: &mut Map<String, Value>, fields: &[CustomField]) {
    set_list(
        details,
        "customFields",
        fields,
        |entry, field| {
            entry.insert("label".into(), Value::String(field.label.trim().into()));
            entry.insert("value".into(), Value::String(field.value.clone()));
            entry.insert("hidden".into(), Value::Bool(field.hidden));
        },
        |entry| {
            ["label", "value"].iter().any(|k| {
                entry
                    .get(*k)
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
            })
        },
    );
}

fn write_ssh_key(details: &mut Map<String, Value>, key: &SshKeyDetails) {
    // As the core wrote them: a private key ends with a line break.
    for (name, value) in [
        ("privateKey", &key.private_key),
        ("publicKey", &key.public_key),
        ("keyType", &key.key_type),
        ("fingerprint", &key.fingerprint),
    ] {
        match value.as_deref().filter(|v| !v.is_empty()) {
            Some(value) => details.insert(name.into(), Value::String(value.into())),
            None => details.remove(name),
        };
    }
    for (name, value) in [
        ("comment", &key.comment),
        ("passphrase", &key.passphrase),
        ("notes", &key.notes),
    ] {
        set_text(details, name, value);
    }
    write_custom_fields(details, &key.custom_fields);
}

fn write_environment(details: &mut Map<String, Value>, environment: &EnvironmentDetails) {
    for (key, value) in [
        ("project", &environment.project),
        ("projectName", &environment.project_name),
        ("stage", &environment.stage),
        ("notes", &environment.notes),
    ] {
        set_text(details, key, value);
    }
    // Reordering is allowed, so a variable finds what it had by name, not by place.
    let stored: Vec<Value> = details
        .get("variables")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let variables: Vec<Value> = environment
        .variables
        .iter()
        .filter(|variable| !variable.key.trim().is_empty() || !variable.value.is_empty())
        .map(|variable| {
            let key = variable.key.trim();
            let mut fields = stored
                .iter()
                .find(|entry| entry.get("key").and_then(Value::as_str) == Some(key))
                .map(object)
                .unwrap_or_default();
            fields.insert("key".into(), Value::String(key.into()));
            fields.insert("value".into(), Value::String(variable.value.clone()));
            fields.insert("concealed".into(), Value::Bool(variable.concealed));
            set_text(&mut fields, "note", &variable.note);
            Value::Object(fields)
        })
        .collect();
    details.insert("variables".into(), Value::Array(variables));
}

/// The details JSON to save: the stored details (when the type is unchanged) with the edited
/// fields written over them.
fn details_json(stored: Option<&StoredItem>, details: &ItemDetails) -> Result<Value> {
    if let ItemDetails::Other { json, .. } = details {
        return serde_json::from_str(json)
            .map_err(|_| VaultError::new(ErrorCode::InvalidInput, "the details aren't JSON"));
    }
    let item_type = details.item_type();
    let mut map = stored
        .filter(|item| type_of(item) == item_type.name())
        .map(|item| object(&item.details))
        .unwrap_or_default();
    map.insert("schemaVersion".into(), json!(1));
    match details {
        ItemDetails::Login { login } | ItemDetails::Password { login } => {
            write_login(&mut map, login);
        }
        ItemDetails::SecureNote { note } => {
            map.insert("notes".into(), Value::String(note.notes.trim().into()));
        }
        ItemDetails::Card { card } => {
            for (key, value) in [
                ("cardholder", &card.cardholder),
                ("number", &card.number),
                ("expiry", &card.expiry),
                ("cvv", &card.cvv),
                ("pin", &card.pin),
                ("brand", &card.brand),
                ("notes", &card.notes),
            ] {
                set_text(&mut map, key, value);
            }
            if let Some(number) = map.get("number").and_then(Value::as_str)
                && !map.contains_key("brand")
                && let Some(brand) = card_brand(number)
            {
                map.insert("brand".into(), Value::String(brand.into()));
            }
        }
        ItemDetails::Identity { identity } => {
            for (key, value) in [
                ("firstName", &identity.first_name),
                ("lastName", &identity.last_name),
                ("email", &identity.email),
                ("phone", &identity.phone),
                ("birthDate", &identity.birth_date),
                ("notes", &identity.notes),
            ] {
                set_text(&mut map, key, value);
            }
            let mut address = map.get("address").map(object).unwrap_or_default();
            let given = identity.address.clone().unwrap_or_default();
            for (key, value) in [
                ("line1", &given.line1),
                ("line2", &given.line2),
                ("city", &given.city),
                ("region", &given.region),
                ("postalCode", &given.postal_code),
                ("country", &given.country),
            ] {
                set_text(&mut address, key, value);
            }
            if address.is_empty() {
                map.remove("address");
            } else {
                map.insert("address".into(), Value::Object(address));
            }
        }
        ItemDetails::Document { document } => set_text(&mut map, "notes", &document.notes),
        ItemDetails::Wifi { wifi } => write_wifi(&mut map, wifi),
        ItemDetails::SshKey { key } => write_ssh_key(&mut map, key),
        ItemDetails::Environment { environment } => write_environment(&mut map, environment),
        ItemDetails::Structured {
            item_type,
            structured,
        } => structured::write(item_type.name(), &mut map, structured),
        // Never edited: masked email connects and disconnects these.
        ItemDetails::MaskedEmailProvider { .. } => {
            let stored = stored.ok_or(ErrorCode::InvalidInput)?;
            return Ok(stored.details.clone());
        }
        ItemDetails::Other { .. } => unreachable!("returned above"),
    }
    Ok(Value::Object(map))
}

/// A sensible list subtitle, unless the user's own subtitle is something custom.
fn subtitle_for(draft: &ItemDraft, stored: Option<&StoredItem>, details: &Value) -> Option<String> {
    let current = draft
        .subtitle
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let detail = |key: &str| details.get(key).and_then(Value::as_str).map(str::to_owned);
    match draft.details.item_type() {
        ItemType::Login => {
            let before = stored
                .filter(|item| type_of(item) == "login")
                .and_then(|item| item.details.get("username"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let username = detail("username");
            match current {
                None => username,
                Some(current) if Some(&current) == before.as_ref() => username,
                current => current,
            }
        }
        ItemType::Card => {
            if let Some(current) = &current
                && !ends_like_card(current)
            {
                return Some(current.clone());
            }
            let digits: String = detail("number")
                .unwrap_or_default()
                .chars()
                .filter(char::is_ascii_digit)
                .collect();
            if digits.len() >= 4 {
                let brand = detail("brand")
                    .or_else(|| card_brand(&digits).map(str::to_owned))
                    .unwrap_or_else(|| "Card".into());
                Some(format!("{brand} ending {}", &digits[digits.len() - 4..]))
            } else {
                current
            }
        }
        // Always the network name: the apps find the network the device is on by it.
        ItemType::Wifi => detail("ssid").filter(|s| !s.is_empty()),
        ItemType::SshKey => detail("fingerprint").or(current),
        ItemType::Environment => {
            let parts: Vec<String> = [
                detail("projectName").or_else(|| detail("project")),
                detail("stage"),
            ]
            .into_iter()
            .flatten()
            .collect();
            if parts.is_empty() {
                current
            } else {
                Some(parts.join(" · "))
            }
        }
        ItemType::Identity => current.or_else(|| {
            let name = [detail("firstName"), detail("lastName")]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            (!name.is_empty()).then_some(name)
        }),
        other => octapass_core::item_fields::subtitle_key(other.name())
            .and_then(detail)
            .filter(|value| !value.is_empty())
            .or(current),
    }
}

/// `… ending 1234`, the subtitle the editor writes for cards.
fn ends_like_card(subtitle: &str) -> bool {
    subtitle
        .rsplit_once(" ending ")
        .is_some_and(|(_, last)| last.len() == 4 && last.bytes().all(|b| b.is_ascii_digit()))
}

/// The overview and details JSON to save for `draft`, cleaned as the web vault's editor cleans
/// them. `stored` is the item as stored, for an edit.
pub(crate) fn draft_json(draft: &ItemDraft, stored: Option<&StoredItem>) -> Result<(Value, Value)> {
    let errors = validate_draft(draft.clone());
    if !errors.is_empty() {
        let fields: Vec<&str> = errors.iter().map(|e| e.field.as_str()).collect();
        return Err(VaultError::new(
            ErrorCode::InvalidInput,
            format!("check {}", fields.join(", ")),
        ));
    }
    let item_type = draft.details.item_type();
    let details = details_json(stored, &draft.details)?;
    let mut overview = stored
        .map(|item| object(&item.overview))
        .unwrap_or_default();
    overview.insert("schemaVersion".into(), json!(1));
    overview.insert("type".into(), Value::String(item_type.name().into()));
    let title = match &draft.details {
        ItemDetails::Wifi { wifi } if draft.title.trim().is_empty() => wifi.ssid.trim(),
        ItemDetails::SshKey { key } if draft.title.trim().is_empty() => trimmed(&key.comment),
        _ => draft.title.trim(),
    };
    overview.insert("title".into(), Value::String(title.into()));
    let urls: Vec<Value> = draft
        .urls
        .iter()
        .map(|u| u.trim())
        .filter(|u| !u.is_empty())
        .map(|u| Value::String(u.into()))
        .collect();
    let mut tags: Vec<String> = Vec::new();
    for tag in draft
        .tags
        .iter()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
    {
        if !tags.iter().any(|t| t == tag) {
            tags.push(tag.into());
        }
    }
    for (key, list) in [
        ("urls", urls),
        ("tags", tags.into_iter().map(Value::String).collect()),
    ] {
        if list.is_empty() {
            overview.remove(key);
        } else {
            overview.insert(key.into(), Value::Array(list));
        }
    }
    // Keyed by the URL as written, so only saved URLs keep a mode; the default isn't stored.
    let modes: Map<String, Value> = draft
        .url_match
        .iter()
        .filter(|(_, mode)| mode.as_str() != "subdomains")
        .map(|(url, mode)| (url.trim().to_owned(), Value::String(mode.clone())))
        .filter(|(url, _)| {
            overview
                .get("urls")
                .and_then(Value::as_array)
                .is_some_and(|urls| urls.iter().any(|saved| saved.as_str() == Some(url)))
        })
        .collect();
    if modes.is_empty() {
        overview.remove("urlMatch");
    } else {
        overview.insert("urlMatch".into(), Value::Object(modes));
    }
    // A site written twice (`https://a.example`, `a.example/login`) is saved once.
    octapass_core::matching::websites::dedupe_overview_json(&mut overview);
    if draft.favorite {
        overview.insert("favorite".into(), Value::Bool(true));
    } else {
        overview.remove("favorite");
    }
    if draft.pinned {
        overview.insert("pinned".into(), Value::Bool(true));
    } else {
        overview.remove("pinned");
    }
    match subtitle_for(draft, stored, &details) {
        Some(subtitle) => overview.insert("subtitle".into(), Value::String(subtitle)),
        None => overview.remove("subtitle"),
    };
    // The core checks the result against the item model before anything is encrypted.
    let parsed: std::result::Result<ItemOverview, _> =
        serde_json::from_value(Value::Object(overview.clone()));
    parsed.map_err(|_| VaultError::new(ErrorCode::InvalidInput, "invalid overview"))?;
    Ok((Value::Object(overview), details))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qr::WifiNetwork;

    fn stored(overview: Value, details: Value) -> StoredItem {
        StoredItem {
            id: "0190a6c4-7d00-7000-8000-000000000001".into(),
            vault_id: "v".into(),
            revision: 3,
            created_at: "2024-07-12T11:46:53.312Z".into(),
            updated_at: "2026-10-24T08:00:00Z".into(),
            deleted_at: None,
            overview,
            details,
        }
    }

    fn login_draft(login: LoginDetails) -> ItemDraft {
        ItemDraft {
            title: " GitHub ".into(),
            urls: vec![" https://github.com ".into(), "  ".into()],
            tags: vec!["work".into(), " work ".into(), "".into()],
            ..new_item_draft(ItemType::Login, "v".into())
        }
        .with_details(ItemDetails::Login { login })
    }

    impl ItemDraft {
        fn with_details(self, details: ItemDetails) -> Self {
            Self { details, ..self }
        }
    }

    #[test]
    fn a_new_login_for_a_saved_site_and_username_is_the_same_login() {
        let saved = stored(
            json!({ "title": "GitHub", "type": "login", "urls": ["https://github.com/login"] }),
            json!({ "username": "Octocat", "password": "pw" }),
        );
        let draft = |urls: &[&str], username: Option<&str>| ItemDraft {
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            ..login_draft(LoginDetails {
                username: username.map(str::to_owned),
                ..LoginDetails::default()
            })
        };
        assert!(is_same_login(
            &saved,
            &draft(&["www.github.com/session"], Some(" octocat"))
        ));
        assert!(!is_same_login(
            &saved,
            &draft(&["github.com"], Some("someone"))
        ));
        assert!(!is_same_login(
            &saved,
            &draft(&["gist.github.com"], Some("octocat"))
        ));
        assert!(!is_same_login(
            &saved,
            &draft(&["http://github.com"], Some("octocat"))
        ));
        assert!(!is_same_login(&saved, &draft(&[], Some("octocat"))));
        // An edit, an item in the trash and another type are never "the same login".
        let edit = ItemDraft {
            id: Some(saved.id.clone()),
            ..draft(&["github.com"], Some("octocat"))
        };
        assert!(!is_same_login(&saved, &edit));
        let trashed = StoredItem {
            deleted_at: Some("2026-11-01T00:00:00Z".into()),
            ..saved.clone()
        };
        assert!(!is_same_login(
            &trashed,
            &draft(&["github.com"], Some("octocat"))
        ));
        let note = stored(
            json!({ "title": "GitHub", "type": "secureNote", "urls": ["https://github.com"] }),
            json!({ "username": "octocat" }),
        );
        assert!(!is_same_login(
            &note,
            &draft(&["github.com"], Some("octocat"))
        ));
        // Two logins without a username for the same site are the same login.
        let router = stored(
            json!({ "title": "Router", "type": "login", "urls": ["http://router.local:8080"] }),
            json!({ "password": "pw" }),
        );
        assert!(is_same_login(
            &router,
            &draft(&["http://router.local:8080/admin"], None)
        ));
        assert_eq!(
            login_origin("androidapp://com.example.app").as_deref(),
            Some("androidapp://com.example.app")
        );
    }

    #[test]
    fn a_save_keeps_unknown_and_read_only_fields() {
        let item = stored(
            json!({ "schemaVersion": 1, "type": "login", "title": "GitHub", "iconHint": "gh" }),
            json!({
                "schemaVersion": 1, "username": "octo", "password": "old",
                "passkeys": [{ "rpId": "github.com", "userName": "octo", "createdAt": "t" }],
                "passwordHistory": [{ "password": "older", "changedAt": "t0" }],
                "customFields": [{ "label": "PIN", "value": "1", "hidden": true, "future": 7 }],
                "autoType": { "sequence": "{PASSWORD}" },
                "recovery": { "email": "a@b.co", "emailSource": { "kind": "alias", "provider": "addy", "aliasId": "9", "note": 1 } },
                "somethingNew": [1, 2]
            }),
        );
        let mut draft = item_draft(Item::from(&item));
        let ItemDetails::Login { login } = &mut draft.details else {
            panic!("a login");
        };
        login.password = Some(" new ".into());
        login.custom_fields[0].value = "2".into();
        let (overview, details) = draft_json(&draft, Some(&item)).unwrap();
        assert_eq!(overview["iconHint"], "gh");
        assert_eq!(overview["subtitle"], "octo");
        assert_eq!(details["password"], " new ", "secrets are kept as typed");
        assert_eq!(details["somethingNew"], json!([1, 2]));
        assert_eq!(details["autoType"]["sequence"], "{PASSWORD}");
        assert_eq!(details["passkeys"][0]["rpId"], "github.com");
        assert_eq!(details["passwordHistory"][0]["password"], "older");
        assert_eq!(
            details["customFields"],
            json!([{ "label": "PIN", "value": "2", "hidden": true, "future": 7 }])
        );
        assert_eq!(details["recovery"]["emailSource"]["note"], 1);
    }

    #[test]
    fn drafts_are_cleaned_like_the_web_editor() {
        let draft = login_draft(LoginDetails {
            username: Some("  ada ".into()),
            notes: Some("   ".into()),
            custom_fields: vec![CustomField {
                label: " ".into(),
                value: String::new(),
                hidden: false,
            }],
            recovery: Some(RecoveryInfo {
                email: Some(String::new()),
                email_source: Some(RecoverySource {
                    kind: "identity".into(),
                    item_id: Some("x".into()),
                    provider: None,
                    alias_id: None,
                }),
                ..RecoveryInfo::default()
            }),
            ..LoginDetails::default()
        });
        let (overview, details) = draft_json(&draft, None).unwrap();
        assert_eq!(
            overview,
            json!({ "schemaVersion": 1, "type": "login", "title": "GitHub", "urls": ["https://github.com"], "tags": ["work"], "subtitle": "ada" })
        );
        assert_eq!(details, json!({ "schemaVersion": 1, "username": "ada" }));
    }

    #[test]
    fn a_site_written_twice_is_saved_and_listed_once() {
        let draft = ItemDraft {
            urls: vec![
                "https://saasify.example.com".into(),
                "https://saasify.example.com/".into(),
                "saasify.example.com/login".into(),
                "https://other.example".into(),
            ],
            url_match: [
                ("https://saasify.example.com".to_owned(), "host".to_owned()),
                ("saasify.example.com/login".to_owned(), "never".to_owned()),
            ]
            .into(),
            ..login_draft(LoginDetails::default())
        };
        let (overview, _) = draft_json(&draft, None).unwrap();
        assert_eq!(
            overview["urls"],
            json!(["https://saasify.example.com", "https://other.example"])
        );
        assert_eq!(
            overview["urlMatch"],
            json!({ "https://saasify.example.com": "host" })
        );
        assert_eq!(
            unique_websites(draft.urls.clone(), draft.url_match.clone()),
            ["https://saasify.example.com", "https://other.example"]
        );
    }

    #[test]
    fn cards_get_a_brand_and_a_subtitle() {
        let draft = ItemDraft {
            title: "Visa".into(),
            ..new_item_draft(ItemType::Card, "v".into())
        }
        .with_details(ItemDetails::Card {
            card: CardDetails {
                number: Some("4111 1111 1111 1234".into()),
                ..CardDetails::default()
            },
        });
        let (overview, details) = draft_json(&draft, None).unwrap();
        assert_eq!(details["brand"], "Visa");
        assert_eq!(overview["subtitle"], "Visa ending 1234");
    }

    #[test]
    fn validation_matches_the_web_editor() {
        let mut draft = login_draft(LoginDetails {
            totp: Some("not base32 !".into()),
            recovery: Some(RecoveryInfo {
                email: Some("nope".into()),
                ..RecoveryInfo::default()
            }),
            ..LoginDetails::default()
        });
        draft.title = " ".into();
        draft.urls = vec!["github.com".into(), "not a url".into()];
        let fields: Vec<String> = validate_draft(draft.clone())
            .into_iter()
            .map(|e| e.field)
            .collect();
        assert_eq!(fields, ["title", "urls.1", "totp", "recovery.email"]);
        assert_eq!(
            draft_json(&draft, None).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let card = new_item_draft(ItemType::Card, "v".into()).with_details(ItemDetails::Card {
            card: CardDetails {
                expiry: Some("13/30".into()),
                number: Some("12ab".into()),
                ..CardDetails::default()
            },
        });
        let keys: Vec<String> = validate_draft(card)
            .into_iter()
            .map(|e| e.message_key)
            .collect();
        assert_eq!(
            keys,
            [
                "validation.titleRequired",
                "validation.expiry",
                "validation.cardNumber"
            ]
        );
    }

    #[test]
    fn every_type_reads_back_typed() {
        for (kind, details) in [
            ("secureNote", json!({ "schemaVersion": 1, "notes": "hi" })),
            (
                "card",
                json!({ "schemaVersion": 1, "number": "4111 1111 1111 1111", "brand": "Visa" }),
            ),
            (
                "identity",
                json!({ "schemaVersion": 1, "firstName": "Ada", "address": { "city": "Amman" } }),
            ),
            ("password", json!({ "schemaVersion": 1, "password": "pw" })),
            (
                "document",
                json!({ "schemaVersion": 1, "attachments": [{ "id": "a", "name": "lease.pdf", "type": "application/pdf", "size": 3, "key": "k", "pending": true }] }),
            ),
            (
                "maskedEmailProvider",
                json!({ "schemaVersion": 1, "provider": "addy", "token": "t", "domain": "anonaddy.me" }),
            ),
            (
                "wifi",
                json!({ "schemaVersion": 1, "ssid": " Cafe ", "security": "wpa2Enterprise", "password": "pw", "eapMethod": "peap", "phase2": "mschapv2", "username": "ada", "hidden": true, "notes": "2nd floor", "passwordHistory": [{ "password": "old", "changedAt": "2026-01-01T00:00:00Z" }] }),
            ),
            (
                "sshKey",
                json!({ "schemaVersion": 1, "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n", "publicKey": "ssh-ed25519 AAAA", "keyType": "ssh-ed25519", "fingerprint": "SHA256:x", "comment": "me@phone", "passphrase": " kept ", "notes": "deploy", "customFields": [{ "label": "Host", "value": "git.example", "hidden": false }], "future": 1 }),
            ),
            (
                "environment",
                json!({ "schemaVersion": 1, "project": "shop-api", "projectName": "Shop", "stage": "production", "notes": "live", "variables": [{ "key": "API_KEY", "value": " x ", "concealed": true, "note": "billing", "future": 2 }, { "key": "DEBUG", "value": "0", "concealed": false }], "future": 1 }),
            ),
            (
                "bankAccount",
                json!({ "schemaVersion": 1, "bankName": "Example", "iban": "DE89370400440532013000", "pin": " 0000 ", "notes": "n", "customFields": [{ "label": "x", "value": "y", "hidden": true }], "future": 1 }),
            ),
            (
                "apiCredential",
                json!({ "schemaVersion": 1, "credentialType": "bearerToken", "key": "k", "secret": "s", "host": "api.example.com", "expiryDate": "2030-01-31" }),
            ),
            (
                "softwareLicense",
                json!({ "schemaVersion": 1, "product": "Editor", "licenseKey": "AAAA-BBBB", "purchaseDate": "2026-01-01" }),
            ),
            (
                "idDocument",
                json!({ "schemaVersion": 1, "documentType": "passport", "number": "X1", "expiryDate": "2030-01-01", "attachments": [{ "id": "a", "name": "scan.png", "type": "image/png", "size": 3, "key": "k" }] }),
            ),
            (
                "cryptoWallet",
                json!({ "schemaVersion": 1, "walletName": "Cold", "seedPhrase": " abandon ability ", "addresses": [{ "network": "bitcoin", "address": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "label": "Savings", "later": 1 }] }),
            ),
            (
                "database",
                json!({ "schemaVersion": 1, "databaseType": "postgresql", "host": "db.example.com", "port": "5432", "password": "pw", "connectionString": "postgres://x", "passwordHistory": [{ "password": "old", "changedAt": "2026-01-01T00:00:00Z" }] }),
            ),
            (
                "custom",
                json!({ "schemaVersion": 1, "templateId": "t", "templateName": "Library", "fields": [{ "label": "PIN", "value": " 1 ", "kind": "hidden", "later": 1 }], "notes": "n" }),
            ),
            (
                "customTemplate",
                json!({ "schemaVersion": 1, "fields": [{ "label": "PIN", "kind": "hidden" }] }),
            ),
            (
                "customTemplate",
                json!({ "schemaVersion": 1, "fields": [] }),
            ),
            ("vehicle", json!({ "schemaVersion": 3, "plate": "XYZ" })),
        ] {
            let item = Item::from(&stored(
                json!({ "schemaVersion": 1, "type": kind, "title": "t" }),
                details.clone(),
            ));
            assert_eq!(item.item_type.name(), kind);
            assert_eq!(item.details.item_type().name(), kind);
            let (_, written) = draft_json(
                &item_draft(item.clone()),
                Some(&stored(
                    json!({ "schemaVersion": 1, "type": kind, "title": "t" }),
                    details.clone(),
                )),
            )
            .unwrap();
            assert_eq!(written, details, "{kind} round-trips");
            if kind == "document" {
                assert_eq!(item.attachments.len(), 1);
                assert!(item.attachments[0].pending);
            }
        }
    }

    fn structured_draft(item_type: ItemType, structured: StructuredDetails) -> ItemDraft {
        ItemDraft {
            title: "T".into(),
            details: ItemDetails::Structured {
                item_type: item_type.clone(),
                structured,
            },
            ..new_item_draft(item_type, "v".into())
        }
    }

    fn value(key: &str, value: &str) -> crate::structured::FieldValue {
        crate::structured::FieldValue {
            key: key.into(),
            value: value.into(),
        }
    }

    #[test]
    fn new_types_validate_as_the_web_vault_does() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../octapass-core/tests/vectors/item-fields.json"
        ))
        .unwrap();
        for case in vectors["validate"].as_array().unwrap() {
            let kind = case["type"].as_str().unwrap();
            let values = case["details"]
                .as_object()
                .unwrap()
                .iter()
                .filter_map(|(key, text)| text.as_str().map(|text| value(key, text)))
                .collect();
            let addresses = case["details"]["addresses"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|entry| crate::structured::WalletAddress {
                    network: entry["network"].as_str().unwrap().into(),
                    address: entry["address"].as_str().unwrap().into(),
                    label: None,
                })
                .collect();
            let draft = structured_draft(
                ItemType::parse(kind),
                StructuredDetails {
                    values,
                    addresses,
                    ..StructuredDetails::default()
                },
            );
            let found: Vec<Value> = validate_draft(draft)
                .into_iter()
                .map(|e| json!([e.field, e.message_key.trim_start_matches("validation.")]))
                .collect();
            assert_eq!(json!(found), case["errors"], "{case}");
        }
    }

    #[test]
    fn subtitles_of_new_types_never_hold_secrets() {
        let draft = structured_draft(
            ItemType::CryptoWallet,
            StructuredDetails {
                values: vec![value("seedPhrase", "abandon ability")],
                ..StructuredDetails::default()
            },
        );
        let (overview, details) = draft_json(&draft, None).unwrap();
        assert!(overview.get("subtitle").is_none());
        assert_eq!(details["seedPhrase"], "abandon ability");
        let draft = structured_draft(
            ItemType::Database,
            StructuredDetails {
                values: vec![value("host", " db.example.com "), value("password", " p ")],
                ..StructuredDetails::default()
            },
        );
        let (overview, details) = draft_json(&draft, None).unwrap();
        assert_eq!(overview["subtitle"], "db.example.com");
        assert_eq!(details["password"], " p ", "secrets stay as typed");
    }

    #[test]
    fn templates_never_keep_values() {
        use crate::structured::{TypedField, fields_from_template, template_from_item};
        let item = StructuredDetails {
            fields: vec![
                TypedField {
                    label: " PIN ".into(),
                    value: "1234".into(),
                    kind: "hidden".into(),
                },
                TypedField {
                    label: String::new(),
                    value: "stray".into(),
                    kind: "text".into(),
                },
            ],
            notes: Some("private".into()),
            ..StructuredDetails::default()
        };
        let template = template_from_item(item);
        assert_eq!(template.notes, None);
        assert_eq!(
            template.fields,
            [TypedField {
                label: "PIN".into(),
                value: String::new(),
                kind: "hidden".into()
            }]
        );
        let (_, details) = draft_json(
            &structured_draft(ItemType::CustomTemplate, template.clone()),
            None,
        )
        .unwrap();
        assert_eq!(
            details["fields"],
            json!([{ "label": "PIN", "kind": "hidden" }])
        );
        assert_eq!(fields_from_template(template)[0].value, "");
    }

    #[test]
    fn summaries_never_carry_secrets() {
        let item = stored(
            json!({ "type": "login", "title": "a", "favorite": true }),
            json!({ "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP" }),
        );
        let summary = ItemSummary::from(&item);
        assert!(summary.has_totp && summary.favorite && !summary.has_passkey);
        assert!(!format!("{summary:?}").contains("hunter2"));
    }

    fn wifi_draft(wifi: WifiDetails) -> ItemDraft {
        new_item_draft(ItemType::Wifi, "v".into()).with_details(ItemDetails::Wifi { wifi })
    }

    #[test]
    fn wifi_drafts_are_cleaned_like_the_web_editor() {
        let draft = wifi_draft(WifiDetails {
            ssid: " Home ".into(),
            security: "open".into(),
            password: Some("leftover".into()),
            eap_method: Some("peap".into()),
            username: Some("ada".into()),
            hidden: true,
            managed: false,
            ..WifiDetails::default()
        });
        let (overview, details) = draft_json(&draft, None).unwrap();
        // Named after the network; the subtitle is always its name.
        assert_eq!(overview["title"], "Home");
        assert_eq!(overview["type"], "wifi");
        assert_eq!(overview["subtitle"], " Home ");
        assert_eq!(details["ssid"], " Home ");
        assert_eq!(details["hidden"], true);
        for gone in ["password", "eapMethod", "username", "managed"] {
            assert!(details.get(gone).is_none(), "{gone}");
        }
        let enterprise = wifi_draft(WifiDetails {
            ssid: "Office".into(),
            security: "wpa2Enterprise".into(),
            eap_method: Some("tls".into()),
            phase2: Some("mschapv2".into()),
            username: Some("ada".into()),
            ..WifiDetails::default()
        });
        let (_, details) = draft_json(&enterprise, None).unwrap();
        assert_eq!(details["eapMethod"], "tls");
        // Only PEAP and TTLS have an inner method.
        assert!(details.get("phase2").is_none());
    }

    #[test]
    fn wifi_validation_matches_the_web_editor() {
        let errors = |wifi: WifiDetails| -> Vec<String> {
            validate_draft(wifi_draft(wifi))
                .into_iter()
                .map(|e| e.message_key)
                .collect()
        };
        assert_eq!(
            errors(WifiDetails::default()),
            ["validation.titleRequired", "validation.ssidRequired"]
        );
        let named = |security: &str, password: &str| WifiDetails {
            ssid: "Home".into(),
            security: security.into(),
            password: Some(password.into()),
            ..WifiDetails::default()
        };
        assert_eq!(errors(named("wpa2", "short")), ["validation.wpaPassword"]);
        assert!(errors(named("wpa2", "long enough")).is_empty());
        assert!(errors(named("wpa2", &"a".repeat(64))).is_empty());
        assert_eq!(errors(named("wep", "abcd")), ["validation.wepKey"]);
        assert!(errors(named("wep", "abcde")).is_empty());
        assert!(errors(named("wpa2Enterprise", "x")).is_empty());
        let item = Item::from(&stored(
            json!({ "type": "wifi", "title": "Home" }),
            json!({ "ssid": "Home", "security": "wpa3", "password": "secret12", "hidden": true }),
        ));
        assert_eq!(
            item.wifi,
            Some(WifiNetwork {
                ssid: "Home".into(),
                password: Some("secret12".into()),
                security: crate::qr::WifiSecurity::Wpa,
                hidden: true,
            })
        );
    }

    #[test]
    fn summaries_name_their_site_and_icon() {
        let login = ItemSummary::from(&stored(
            json!({ "type": "login", "title": "a", "urls": ["https://www.accounts.google.com/x"] }),
            json!({}),
        ));
        assert_eq!(login.site.as_deref(), Some("accounts.google.com"));
        assert_eq!(login.icon_domain.as_deref(), Some("google.com"));
        let card = ItemSummary::from(&stored(
            json!({ "type": "card", "title": "a", "urls": ["https://bank.com"] }),
            json!({}),
        ));
        assert_eq!(card.site, None);
        assert_eq!(card.icon_domain.as_deref(), Some("bank.com"));
    }

    fn environment_draft(environment: EnvironmentDetails) -> ItemDraft {
        ItemDraft {
            title: "Shop".into(),
            ..new_item_draft(ItemType::Environment, "v".into())
        }
        .with_details(ItemDetails::Environment { environment })
    }

    fn variable(key: &str, value: &str) -> crate::environments::EnvironmentVariable {
        crate::environments::EnvironmentVariable {
            key: key.into(),
            value: value.into(),
            concealed: true,
            note: None,
        }
    }

    #[test]
    fn environment_drafts_are_cleaned_like_the_web_editor() {
        let draft = environment_draft(EnvironmentDetails {
            project: Some(" shop-api ".into()),
            stage: Some("staging".into()),
            variables: vec![
                variable(" API_KEY ", " spaced "),
                variable("", ""),
                variable("DEBUG", "1"),
            ],
            ..EnvironmentDetails::default()
        });
        assert!(validate_draft(draft.clone()).is_empty());
        let (overview, details) = draft_json(&draft, None).unwrap();
        assert_eq!(overview["subtitle"], "shop-api · staging");
        assert_eq!(details["project"], "shop-api");
        assert_eq!(
            details["variables"],
            json!([
                { "key": "API_KEY", "value": " spaced ", "concealed": true },
                { "key": "DEBUG", "value": "1", "concealed": true },
            ])
        );
        let (_, empty) =
            draft_json(&environment_draft(EnvironmentDetails::default()), None).unwrap();
        assert_eq!(empty, json!({ "schemaVersion": 1, "variables": [] }));
    }

    #[test]
    fn environment_validation_matches_the_web_editor() {
        let keys = |environment: EnvironmentDetails| -> Vec<(String, String)> {
            validate_draft(environment_draft(environment))
                .into_iter()
                .map(|e| (e.field, e.message_key))
                .collect()
        };
        let pair = |field: &str, key: &str| (field.to_owned(), key.to_owned());
        assert_eq!(
            keys(EnvironmentDetails {
                project: Some("shop api".into()),
                stage: Some("prod:1".into()),
                variables: vec![variable("1A", "x"), variable("B", "x"), variable(" B", "y")],
                ..EnvironmentDetails::default()
            }),
            [
                pair("variables.0.key", "env.invalidKey"),
                pair("variables.2.key", "env.duplicateKey"),
                pair("project", "env.invalidProject"),
                pair("stage", "env.invalidStage"),
            ]
        );
        assert_eq!(
            keys(EnvironmentDetails {
                variables: vec![variable("", "a value without a name")],
                ..EnvironmentDetails::default()
            }),
            [pair("variables.0.key", "env.invalidKey")]
        );
    }

    #[test]
    fn a_reordered_variable_keeps_what_a_newer_client_wrote() {
        let item = stored(
            json!({ "type": "environment", "title": "t" }),
            json!({ "schemaVersion": 1, "variables": [
                { "key": "A", "value": "1", "concealed": true, "future": "a" },
                { "key": "B", "value": "2", "concealed": false, "future": "b" },
            ] }),
        );
        let mut draft = item_draft(Item::from(&item));
        let ItemDetails::Environment { environment } = &mut draft.details else {
            panic!("an environment");
        };
        environment.variables.reverse();
        let (_, details) = draft_json(&draft, Some(&item)).unwrap();
        assert_eq!(details["variables"][0]["key"], "B");
        assert_eq!(details["variables"][0]["future"], "b");
        assert_eq!(details["variables"][1]["future"], "a");
    }

    fn ssh_draft(key: SshKeyDetails) -> ItemDraft {
        new_item_draft(ItemType::SshKey, "v".into()).with_details(ItemDetails::SshKey { key })
    }

    #[test]
    fn ssh_keys_are_named_after_their_comment_and_need_a_key() {
        let keys = |key: SshKeyDetails| -> Vec<String> {
            validate_draft(ssh_draft(key))
                .into_iter()
                .map(|e| e.message_key)
                .collect()
        };
        assert_eq!(
            keys(SshKeyDetails::default()),
            ["validation.titleRequired", "validation.sshKeyRequired"]
        );
        let key = SshKeyDetails {
            private_key: Some("key\n".into()),
            fingerprint: Some("SHA256:abc".into()),
            comment: Some(" me@phone ".into()),
            ..SshKeyDetails::default()
        };
        assert!(keys(key.clone()).is_empty());
        let (overview, details) = draft_json(&ssh_draft(key), None).unwrap();
        assert_eq!(overview["title"], "me@phone");
        assert_eq!(overview["subtitle"], "SHA256:abc");
        assert_eq!(details["privateKey"], "key\n", "kept as the core wrote it");
        assert_eq!(details["comment"], "me@phone");
    }

    #[test]
    fn dates_prefer_the_imported_ones_and_the_newest_password_change() {
        let item = Item::from(&stored(
            json!({ "type": "login", "title": "a", "createdAt": "2020-01-01T00:00:00Z", "lastUsedAt": "2026-02-02T00:00:00Z" }),
            json!({ "password": "p", "passwordChangedAt": "2024-01-01T00:00:00Z", "httpRealm": "Router",
                "passwordHistory": [{ "password": "o", "changedAt": "2025-05-05T00:00:00Z" }, { "password": "x", "changedAt": "not a date" }] }),
        ));
        assert_eq!(
            item.shown_created_at.as_deref(),
            Some("2020-01-01T00:00:00Z")
        );
        assert_eq!(
            item.shown_updated_at.as_deref(),
            Some("2026-10-24T08:00:00Z")
        );
        assert_eq!(item.last_used_at.as_deref(), Some("2026-02-02T00:00:00Z"));
        assert_eq!(
            item.password_changed_at.as_deref(),
            Some("2025-05-05T00:00:00Z")
        );
        let ItemDetails::Login { login } = &item.details else {
            panic!("a login");
        };
        assert_eq!(login.http_realm.as_deref(), Some("Router"));
        let no_password = Item::from(&stored(
            json!({ "type": "login", "title": "a" }),
            json!({ "passwordHistory": [{ "password": "o", "changedAt": "2025-05-05T00:00:00Z" }] }),
        ));
        assert_eq!(no_password.password_changed_at, None);
    }

    #[test]
    fn summaries_carry_environment_names_but_no_values() {
        let summary = ItemSummary::from(&stored(
            json!({ "type": "environment", "title": "Shop" }),
            json!({ "project": "shop", "stage": "production", "variables": [{ "key": "API_KEY", "value": "s3cret" }] }),
        ));
        assert_eq!(summary.project.as_deref(), Some("shop"));
        assert_eq!(summary.stage.as_deref(), Some("production"));
        assert_eq!(summary.variable_keys, ["API_KEY"]);
        assert!(!format!("{summary:?}").contains("s3cret"));
    }

    #[test]
    fn account_emails_are_checked_like_the_web() {
        assert_eq!(
            normalize_email(" Ada@Example.COM ".into()),
            "ada@example.com"
        );
        assert!(valid_email("ada@example.com".into()));
        assert!(!valid_email("ada@example".into()));
        assert!(!valid_email("ada example.com".into()));
    }
}
