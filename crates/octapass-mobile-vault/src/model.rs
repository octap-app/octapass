//! The shapes the UI exchanges with the vault, as in `packages/vault-client/src/types.ts`.
//! Overview and details stay JSON values end to end, so fields this version doesn't know about
//! round-trip untouched.

use std::collections::HashMap;

use octapass_api::{VaultRecord, VaultRole, VaultType};
use octapass_core::item::{Item as CoreItem, ItemOverview};
use octapass_ffi::{DecryptedItem, SecondFactorMethod};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::{ErrorCode, Result, VaultError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionStatus {
    SignedOut,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionState {
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RememberedAccount {
    pub email: String,
    pub server_url: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKit {
    pub email: String,
    pub server_url: String,
    pub secret_key: String,
    pub recovery_code: String,
    pub created_at: String,
}

/// A kit from a change that may keep the recovery code: without one, the old kit's still works.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewRecoveryKit {
    pub email: String,
    pub server_url: String,
    pub secret_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_code: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignupStarted {
    pub signup_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_verification_code: Option<String>,
}

/// A master password reset that emailed its code (`startPasswordReset`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetStarted {
    pub reset_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_verification_code: Option<String>,
}

/// What `finishPasswordReset` ended with: the new Recovery Kit, and how signing in went. No
/// `signIn` when signing in failed afterwards: the password is set, so sign in by hand.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordResetResult {
    pub recovery_kit: RecoveryKit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in: Option<SignInResult>,
}

/// What `sign_in` ended with (`SignInResult`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum SignInResult {
    SignedIn,
    /// The password and Secret Key were right; finish with `finish_two_step`.
    TwoStepRequired {
        methods: Vec<TwoStepMethod>,
    },
    /// The password and Secret Key were right, and the account's organisation requires single
    /// sign-on: open `url` in a browser and finish with `finish_sso` and the code it ends on.
    SsoRequired {
        url: String,
        #[serde(rename = "orgName")]
        org_name: String,
    },
}

/// A way to finish two-step sign-in that this app can offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TwoStepMethod {
    Totp,
    SecurityKey,
    RecoveryCode,
}

impl TwoStepMethod {
    /// Security keys only work where WebAuthn runs for the server's relying party (the web
    /// vault's host), never in the app's web view, so they're left out.
    pub fn offered(methods: &[SecondFactorMethod]) -> Vec<Self> {
        methods
            .iter()
            .filter_map(|method| match method {
                SecondFactorMethod::Totp => Some(Self::Totp),
                SecondFactorMethod::RecoveryCode => Some(Self::RecoveryCode),
                SecondFactorMethod::SecurityKey => None,
            })
            .collect()
    }
}

/// `TwoStepProof`
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "method", rename_all = "camelCase")]
pub enum TwoStepProof {
    Totp { code: String },
    RecoveryCode { code: String },
    SecurityKey,
}

/// `SecurityKeyInfo`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityKeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

/// `TwoStepStatus`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoStepStatus {
    pub enabled: bool,
    pub security_keys: Vec<SecurityKeyInfo>,
    pub recovery_codes_left: u32,
    /// Always false here: see [`TwoStepMethod::offered`]. Existing keys can still be removed.
    pub security_keys_supported: bool,
}

impl From<octapass_ffi::TwoStepStatus> for TwoStepStatus {
    fn from(status: octapass_ffi::TwoStepStatus) -> Self {
        Self {
            enabled: status.enabled,
            security_keys: status
                .security_keys
                .into_iter()
                .map(|key| SecurityKeyInfo {
                    id: key.id,
                    name: key.name,
                    created_at: key.created_at,
                    last_used_at: key.last_used_at,
                })
                .collect(),
            recovery_codes_left: status.recovery_codes_left,
            security_keys_supported: false,
        }
    }
}

/// `TotpSetup`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetup {
    pub secret: String,
    pub otpauth_uri: String,
}

/// What confirming a new authenticator returns.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpConfirmed {
    /// Only when this turned two-step sign-in on: shown once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub api_version: u32,
    pub signups: &'static str,
    pub push_relay: bool,
    pub email_breach_checks: bool,
}

impl From<octapass_ffi::ServerInfo> for ServerInfo {
    fn from(info: octapass_ffi::ServerInfo) -> Self {
        use octapass_ffi::SignupMode;
        Self {
            name: info.name,
            version: info.version,
            api_version: info.api_version,
            signups: match info.signups {
                SignupMode::Open => "open",
                SignupMode::Invite => "invite",
                SignupMode::Closed => "closed",
            },
            push_relay: info.push_relay,
            email_breach_checks: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vault {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub vault_type: VaultType,
    pub role: VaultRole,
    /// A shared or family vault whose grant didn't verify: its key isn't used, so it has no
    /// items here, and the UI warns instead.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub untrusted: bool,
}

/// The server keeps no vault metadata, so a shared vault's name is an encrypted record of this
/// type inside the vault, which every member can read (plan 15, History). It's never listed.
pub const VAULT_INFO_TYPE: &str = "vaultInfo";

impl Vault {
    /// `names` from [`vault_names`]; vaults without one get their type's name.
    pub fn new(record: &VaultRecord, names: &HashMap<String, String>, untrusted: bool) -> Self {
        Self {
            id: record.id.clone(),
            name: names
                .get(&record.id)
                .cloned()
                .unwrap_or_else(|| default_vault_name(record.vault_type).into()),
            vault_type: record.vault_type,
            role: record.role,
            untrusted,
        }
    }
}

/// As the web vault names them.
pub fn default_vault_name(vault_type: VaultType) -> &'static str {
    match vault_type {
        VaultType::Personal => "Personal",
        VaultType::Shared => "Shared vault",
        VaultType::Family => "Family",
    }
}

/// Each vault's name record, the newest if two members renamed it at once.
pub fn vault_names(items: &[Item]) -> HashMap<String, String> {
    let mut found: HashMap<String, (u64, String)> = HashMap::new();
    for item in items
        .iter()
        .filter(|item| item.is_vault_info() && item.deleted_at.is_none())
    {
        let title = item.title().to_owned();
        if title.is_empty() {
            continue;
        }
        let newer = found
            .get(&item.vault_id)
            .is_none_or(|(revision, _)| item.revision > *revision);
        if newer {
            found.insert(item.vault_id.clone(), (item.revision, title));
        }
    }
    found
        .into_iter()
        .map(|(id, (_, name))| (id, name))
        .collect()
}

/// A decrypted item.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    pub vault_id: String,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    pub overview: Value,
    pub details: Value,
}

impl From<&DecryptedItem> for Item {
    fn from(decrypted: &DecryptedItem) -> Self {
        let record = &decrypted.record;
        Self {
            id: record.id.clone(),
            vault_id: record.vault_id.clone(),
            revision: record.revision,
            created_at: created_at(&record.id).unwrap_or_else(|| record.updated_at.clone()),
            updated_at: record.updated_at.clone(),
            deleted_at: record.deleted_at.clone(),
            overview: serde_json::to_value(&decrypted.item.overview).expect("items serialize"),
            details: serde_json::to_value(&decrypted.item.details).expect("items serialize"),
        }
    }
}

impl Item {
    pub fn is_login_like(&self) -> bool {
        is_login_like(&self.overview)
    }

    pub fn detail(&self, field: &str) -> Option<&str> {
        self.details
            .get(field)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
    }

    pub fn title(&self) -> &str {
        self.overview
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// A shared vault's name record ([`VAULT_INFO_TYPE`]), not an item to list.
    pub fn is_vault_info(&self) -> bool {
        self.overview.get("type").and_then(Value::as_str) == Some(VAULT_INFO_TYPE)
    }
}

/// What `saveItem` accepts: no id for a new item, and the revision an edit started from.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDraft {
    pub id: Option<String>,
    pub vault_id: String,
    pub revision: Option<u64>,
    pub overview: Value,
    pub details: Value,
}

impl ItemDraft {
    /// Validates the draft against the item model before anything is encrypted.
    pub fn to_core(&self) -> Result<CoreItem> {
        let overview: ItemOverview = serde_json::from_value(self.overview.clone())
            .map_err(|_| VaultError::unexpected("invalid item overview"))?;
        CoreItem::from_parts(overview, self.details.clone())
            .map_err(|error| VaultError::unexpected(error.code()))
    }

    /// Attachments change only through the attachment calls: a draft keeps the stored item's
    /// list (none for a new item or a copy, which couldn't open the files), whatever it came with.
    pub fn with_attachments_of(mut self, previous: Option<&Item>) -> Self {
        let Some(details) = self.details.as_object_mut() else {
            return self;
        };
        match previous.and_then(|previous| previous.details.get("attachments")) {
            Some(list) => details.insert("attachments".into(), list.clone()),
            None => details.remove("attachments"),
        };
        self
    }

    pub fn with_title_suffix(mut self, suffix: &str) -> Self {
        if let Some(title) = self.overview.get_mut("title") {
            *title = Value::String(format!("{}{suffix}", title.as_str().unwrap_or_default()));
        }
        self
    }

    /// An edit of `previous`. Keeps the previous password in `passwordHistory` (newest first, at
    /// most 20) when a login's or Wi-Fi network's password changes, unless the draft has already
    /// added it (as an import does). Drops the date the item last changed in the app it was
    /// imported from (`overview.updatedAt`) unless the draft sets a new one: it changed here now.
    pub fn with_password_history(mut self, previous: &Item, now: &str) -> Self {
        let imported = previous.overview.get("updatedAt");
        if imported.is_some()
            && self.overview.get("updatedAt") == imported
            && let Some(overview) = self.overview.as_object_mut()
        {
            overview.remove("updatedAt");
        }
        if !keeps_password_history(&previous.overview) || !keeps_password_history(&self.overview) {
            return self;
        }
        let Some(before) = previous.detail("password") else {
            return self;
        };
        if self.details.get("password").and_then(Value::as_str) == Some(before) {
            return self;
        }
        let lists = |details: &Value| {
            details
                .get("passwordHistory")
                .and_then(Value::as_array)
                .is_some_and(|history| history.iter().any(|entry| entry["password"] == before))
        };
        if lists(&self.details) && !lists(&previous.details) {
            return self;
        }
        let entry = serde_json::json!({ "password": before, "changedAt": now });
        let Some(details) = self.details.as_object_mut() else {
            return self;
        };
        let mut history = match details.remove("passwordHistory") {
            Some(Value::Array(history)) => history,
            _ => Vec::new(),
        };
        history.insert(0, entry);
        history.truncate(20);
        details.insert("passwordHistory".into(), Value::Array(history));
        self
    }
}

/// A list row: the overview plus flags computed from the details. Never secrets.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    pub id: String,
    pub vault_id: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    pub favorite: bool,
    pub pinned: bool,
    pub has_totp: bool,
    pub has_passkey: bool,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

impl From<&Item> for ItemSummary {
    fn from(item: &Item) -> Self {
        let overview = item.overview.as_object().cloned().unwrap_or_default();
        let strings = |key: &str| -> Option<Vec<String>> {
            serde_json::from_value(overview.get(key)?.clone()).ok()
        };
        let login = item.is_login_like();
        Self {
            id: item.id.clone(),
            vault_id: item.vault_id.clone(),
            item_type: string(&overview, "type").unwrap_or_default(),
            title: string(&overview, "title").unwrap_or_default(),
            subtitle: string(&overview, "subtitle"),
            urls: strings("urls"),
            tags: strings("tags"),
            favorite: overview.get("favorite") == Some(&Value::Bool(true)),
            pinned: overview.get("pinned") == Some(&Value::Bool(true)),
            has_totp: login && item.detail("totp").is_some(),
            has_passkey: login
                && item
                    .details
                    .get("passkeys")
                    .and_then(Value::as_array)
                    .is_some_and(|passkeys| !passkeys.is_empty()),
            created_at: item.created_at.clone(),
            updated_at: item.updated_at.clone(),
            deleted_at: item.deleted_at.clone(),
        }
    }
}

fn string(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key).and_then(Value::as_str).map(str::to_owned)
}

pub fn is_login_like(overview: &Value) -> bool {
    matches!(
        overview.get("type").and_then(Value::as_str),
        Some("login" | "password")
    )
}

fn keeps_password_history(overview: &Value) -> bool {
    is_login_like(overview)
        || matches!(
            overview.get("type").and_then(Value::as_str),
            Some("wifi" | "database")
        )
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSummary {
    pub email: String,
    pub item_count: usize,
    pub vault_count: usize,
    pub device_count: usize,
    pub shared_vaults_owned: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockMethods {
    pub device_unlock_supported: bool,
    pub device_unlock_enabled: bool,
    pub label: String,
    /// `ios`, `android` or `macos`: the UI names the device's lock by it.
    pub platform: &'static str,
    pub password_required: bool,
}

/// Stay unlocked while logged in to this phone (plan 18), as Settings and the app's start need it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StayUnlockedStatus {
    /// The phone has a passcode (or Face ID, Touch ID, a fingerprint): without one it can't stay
    /// unlocked and locks as before.
    pub available: bool,
    /// The current account has a stay-unlocked key on this phone.
    pub enrolled: bool,
    /// The 14-day master password check is due: the key won't open the vault until the master
    /// password unlocks it once.
    pub password_required: bool,
}

/// `StorageUsage` in `packages/vault-client`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageUsage {
    pub attachment_bytes: u64,
    pub max_attachment_bytes: u64,
    pub max_file_bytes: u64,
}

/// Where the phone's own pickers take a file from (`FileSource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FileSource {
    Files,
    Photos,
    Camera,
}

/// A file the system picker copied into the app's private storage, until it's attached or
/// discarded (`PickedFile`). The web view only sees this description, never the contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PickedFile {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub media_type: String,
    pub size: u64,
}

pub fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC times format as RFC 3339")
}

/// Items get UUIDv7 ids when they're created, so the id carries the creation time.
fn created_at(id: &str) -> Option<String> {
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || hex.as_bytes()[12] != b'7' {
        return None;
    }
    let ms = i128::from(u64::from_str_radix(&hex[..12], 16).ok()?);
    OffsetDateTime::from_unix_timestamp_nanos(ms * 1_000_000)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

pub fn require(condition: bool, code: ErrorCode) -> Result<()> {
    if condition { Ok(()) } else { Err(code.into()) }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn item(overview: Value, details: Value) -> Item {
        Item {
            id: "0190a6c4-7d00-7000-8000-000000000001".into(),
            vault_id: "v".into(),
            revision: 3,
            created_at: String::new(),
            updated_at: "2026-10-24T08:00:00Z".into(),
            deleted_at: None,
            overview,
            details,
        }
    }

    #[test]
    fn creation_time_comes_from_the_uuidv7() {
        assert_eq!(
            created_at("0190a6c4-7d00-7000-8000-000000000001").as_deref(),
            Some("2024-07-12T11:46:53.312Z")
        );
        assert_eq!(created_at("0190a6c4-7d00-4000-8000-000000000001"), None);
        assert_eq!(created_at("nope"), None);
    }

    #[test]
    fn summaries_flag_codes_and_passkeys_without_secrets() {
        let login = item(
            json!({ "schemaVersion": 1, "type": "login", "title": "GitHub", "urls": ["https://github.com"], "favorite": true }),
            json!({ "schemaVersion": 1, "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP", "passkeys": [{ "rpId": "github.com", "userName": "a", "createdAt": "x" }] }),
        );
        let summary = ItemSummary::from(&login);
        assert!(summary.has_totp && summary.has_passkey && summary.favorite);
        // Lists sort by date added, which comes from the id rather than the details.
        assert_eq!(summary.created_at, login.created_at);
        assert!(
            serde_json::to_string(&summary)
                .unwrap()
                .contains("\"createdAt\"")
        );
        assert!(!serde_json::to_string(&summary).unwrap().contains("hunter2"));

        let note = item(
            json!({ "schemaVersion": 1, "type": "secureNote", "title": "Note" }),
            json!({ "schemaVersion": 1, "notes": "", "totp": "JBSWY3DPEHPK3PXP" }),
        );
        assert!(!ItemSummary::from(&note).has_totp, "only logins have codes");
    }

    #[test]
    fn a_changed_password_moves_into_the_history() {
        let previous = item(
            json!({ "type": "login", "title": "a" }),
            json!({ "password": "old" }),
        );
        let draft = ItemDraft {
            id: Some(previous.id.clone()),
            vault_id: "v".into(),
            revision: Some(3),
            overview: json!({ "type": "login", "title": "a" }),
            details: json!({ "password": "new", "extra": 1 }),
        };
        let saved = draft.with_password_history(&previous, "t1");
        assert_eq!(
            saved.details["passwordHistory"],
            json!([{ "password": "old", "changedAt": "t1" }])
        );
        assert_eq!(saved.details["extra"], 1);
    }

    #[test]
    fn an_edit_drops_the_imported_change_date() {
        let previous = item(
            json!({ "type": "login", "title": "a", "updatedAt": "2020-01-01T00:00:00Z", "createdAt": "2019-01-01T00:00:00Z" }),
            json!({ "password": "old" }),
        );
        let draft = |overview: Value, details: Value| ItemDraft {
            id: Some(previous.id.clone()),
            vault_id: "v".into(),
            revision: Some(3),
            overview,
            details,
        };
        let edited = draft(previous.overview.clone(), json!({ "password": "new" }))
            .with_password_history(&previous, "t1");
        assert!(edited.overview.get("updatedAt").is_none());
        assert_eq!(edited.overview["createdAt"], "2019-01-01T00:00:00Z");
        // An import that brings a new date and its own history keeps both.
        let imported = draft(
            json!({ "type": "login", "title": "a", "updatedAt": "2021-01-01T00:00:00Z" }),
            json!({ "password": "new", "passwordHistory": [{ "password": "old", "changedAt": "2021-01-01T00:00:00Z" }] }),
        )
        .with_password_history(&previous, "t1");
        assert_eq!(imported.overview["updatedAt"], "2021-01-01T00:00:00Z");
        assert_eq!(
            imported.details["passwordHistory"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn wifi_networks_keep_their_old_passwords() {
        let wifi = json!({ "type": "wifi", "title": "Home" });
        let previous = item(
            wifi.clone(),
            json!({ "ssid": "Home", "security": "wpa2", "password": "old" }),
        );
        let draft = ItemDraft {
            id: Some(previous.id.clone()),
            vault_id: "v".into(),
            revision: Some(1),
            overview: wifi,
            details: json!({ "ssid": "Home", "security": "wpa2", "password": "new" }),
        };
        let saved = draft.with_password_history(&previous, "t1");
        assert_eq!(
            saved.details["passwordHistory"],
            json!([{ "password": "old", "changedAt": "t1" }])
        );
    }

    #[test]
    fn drafts_keep_the_stored_attachment_list() {
        let file = json!([{ "id": "a", "name": "lease.pdf", "type": "application/pdf", "size": 3, "key": "k" }]);
        let stored = item(
            json!({ "type": "document", "title": "Lease" }),
            json!({ "attachments": file }),
        );
        let draft = ItemDraft {
            id: Some(stored.id.clone()),
            vault_id: "v".into(),
            revision: Some(3),
            overview: stored.overview.clone(),
            details: json!({ "notes": "edited" }),
        };
        let kept = draft.clone().with_attachments_of(Some(&stored));
        assert_eq!(
            kept.details,
            json!({ "notes": "edited", "attachments": file })
        );
        let copy = ItemDraft {
            details: json!({ "attachments": file }),
            ..draft
        };
        assert_eq!(copy.with_attachments_of(None).details, json!({}));
    }
}
