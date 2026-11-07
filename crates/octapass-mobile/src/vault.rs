//! `OctaPassVault`: everything the native apps' screens do, over the mobile vault
//! (`crates/octapass-mobile-vault`), which keeps the account in the store the autofill extensions
//! share. It mirrors the web vault's `VaultService` (`packages/vault-client/src/types.ts`), with
//! the same error codes.
//!
//! Calls that block (Argon2id, the network, the device-lock prompt, file encryption) are `async`
//! and run on a thread of their own; the rest return at once and are safe on the main thread.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use octapass_api::{DeviceRecord, SecurityLogResponse};
use octapass_ffi::DeviceInfo;
use octapass_mobile_vault::model::{
    Item as StoredItem, ItemDraft as StoredDraft, SessionStatus as VaultStatus,
};
use octapass_mobile_vault::native::ReceivedCredentials;
use octapass_mobile_vault::{Config, Event, Vault as MobileVault};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use crate::api::{Api, Method, Server, segment};
use crate::background::background;
use crate::emergency::{
    EmergencyAccessLevel, EmergencyContact, EmergencyContacts, EmergencyScope, EmergencyVaultView,
};
use crate::error::{ErrorCode, Result, VaultError, not_allowed, require};
use crate::health::{EmailBreachCheck, HealthReport, build_report};
use crate::icons::SiteIcons;
use crate::items::{
    EquivalentDomains, HotpCode, Item, ItemDraft, ItemSummary, ItemVersion, draft_json,
    is_vault_info, item_draft,
};
use crate::links::{
    CreatedShareLink, ShareLinkEnvelope, ShareLinkInfo, ShareLinkOptions, SharedItem,
};
use crate::list::{
    ItemFilter, ListArrangement, ListGrouping, ListSection, ListSort, arrange, matches_filter,
    resolve_arrangement, sort_items,
};
use crate::local::{self, AUTO_LOCK_CHOICES, Settings};
use crate::masked_email::{MaskedAlias, MaskedEmailConnection, ProviderHttp, Ureq};
use crate::platform::{Bridge, NativePlatform, VaultObserver};
use octapass_mobile_vault::vault::EquivalentDomainsInput;

use crate::sharing::{
    AccountLookup, FamilyState, Fingerprint, SharedVaults, Vault, VaultMember, VaultRole,
    VaultType, list_vaults,
};
use crate::ssh::{self, SshKeyDetails, SshKeyKind, SshKeyMaterial};
use crate::tools::{StrengthEstimate, estimate};
use crate::transfer::{
    self, CodeLink, ExportFormat, ImportReview, ImportSource, ImportSummary, ReceivedPreview,
};
use crate::watch::{self, WatchSource};
use crate::usage::{ItemUse, SmartList, USAGE_SAVE_DELAY, Usage, add_uses};

/// How often the auto-lock timer looks at the clock.
const AUTO_LOCK_TICK: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DevicePlatform {
    Ios,
    Android,
    /// The native Mac app (plan 19), on the same API as the phones.
    Macos,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultConfig {
    /// The App Group container (iOS) or the app's `no_backup` storage (Android), shared with the
    /// autofill extensions. The account's store and `accounts.json` live here.
    pub data_dir: String,
    /// The app's own private storage for decrypted files on their way to the viewer or the share
    /// sheet. Never shared with the extensions; emptied on lock and when the app starts.
    pub temp_dir: String,
    /// How this phone appears in the account's device list.
    pub device_name: String,
    pub platform: DevicePlatform,
    #[uniffi(default = "https://api.pwnedpasswords.com")]
    pub pwned_passwords_url: String,
    /// Where share links open.
    #[uniffi(default = "https://vault.octap.app")]
    pub web_vault_url: String,
    /// The hosted service, which share links on it don't name.
    #[uniffi(default = "https://vault.octap.app")]
    pub default_server_url: String,
    /// The app's own cache folder for website icons (iOS Caches, Android `cacheDir`). Empty keeps
    /// them in memory only for as long as the server answers; they're never in `data_dir`.
    #[uniffi(default = "")]
    pub cache_dir: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SessionStatus {
    SignedOut,
    Locked,
    Unlocked,
}

/// An account whose Secret Key is on this phone, so signing in needs only the password.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RememberedAccount {
    pub email: String,
    pub server_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SessionSnapshot {
    pub status: SessionStatus,
    pub email: Option<String>,
    pub server_url: Option<String>,
    pub remembered_accounts: Vec<RememberedAccount>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SignupMode {
    Open,
    Invite,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub api_version: u32,
    pub signups: SignupMode,
    pub push_relay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SignupStarted {
    pub signup_id: String,
    /// Development servers only: the code the email would carry.
    pub dev_verification_code: Option<String>,
}

/// Shown once at sign-up for the user to keep. Made on the phone, never on the server.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryKit {
    pub email: String,
    pub server_url: String,
    pub secret_key: String,
    pub recovery_code: String,
    pub created_at: String,
}

/// A kit from a change that may keep the recovery code (`rotateSecretKey`): without one, the old
/// kit's still works. Show it once.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NewRecoveryKit {
    pub email: String,
    pub server_url: String,
    pub secret_key: String,
    pub recovery_code: Option<String>,
    pub created_at: String,
}

/// A master password reset that emailed its code (`startPasswordReset`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordResetStarted {
    pub reset_id: String,
    /// Development servers only: the code the email would carry.
    pub dev_verification_code: Option<String>,
}

/// What `finishPasswordReset` ended with: the new Recovery Kit, and how signing in went.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordResetResult {
    pub recovery_kit: RecoveryKit,
    /// `None` when signing in afterwards failed: the password is set, so sign in by hand.
    pub sign_in: Option<SignInResult>,
}

/// What a new device scans to fill in the email, server and Secret Key: the Recovery Kit's QR
/// code (`setupUri` in the web vault). Never the recovery code.
#[uniffi::export]
pub fn recovery_kit_setup_uri(kit: RecoveryKit) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("email", &kit.email)
        .append_pair("server", &kit.server_url)
        .append_pair("secretKey", &kit.secret_key)
        .finish();
    format!("octapass://setup?{query}")
}

/// A way to finish two-step sign-in that the apps offer. Security keys work only where WebAuthn
/// runs for the server's relying party (the web vault), so they never come up here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TwoStepMethod {
    Totp,
    SecurityKey,
    RecoveryCode,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum SignInResult {
    SignedIn,
    /// The password and Secret Key were right; finish with `finishTwoStep`.
    TwoStepRequired {
        methods: Vec<TwoStepMethod>,
    },
    /// The password and Secret Key were right, and the account's organisation requires single
    /// sign-on: open `url` in a browser and finish with `finishSso` and the code it ends on.
    SsoRequired {
        url: String,
        org_name: String,
    },
}

/// A sign-in waiting for its second step, for a screen opened again meanwhile.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PendingTwoStep {
    Required {
        methods: Vec<TwoStepMethod>,
    },
    /// Too slow: sign in again.
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum TwoStepProof {
    Totp { code: String },
    RecoveryCode { code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyInfo {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TwoStepStatus {
    pub enabled: bool,
    /// Added in a browser; the apps can remove them.
    pub security_keys: Vec<SecurityKeyInfo>,
    pub recovery_codes_left: u32,
    /// Always false in the apps.
    pub security_keys_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpSetup {
    /// Base32, to type into an authenticator app.
    pub secret: String,
    /// `otpauth://totp/…`, for the QR code.
    pub otpauth_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AccountSummary {
    pub email: String,
    pub item_count: u32,
    pub vault_count: u32,
    pub device_count: u32,
    /// Shared vaults this user alone owns: deleting the account deletes them for every member.
    pub shared_vaults_owned: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UnlockMethods {
    pub device_unlock_supported: bool,
    pub device_unlock_enabled: bool,
    /// The device lock's English name ("Face ID"); the UI translates it.
    pub label: String,
    /// The 14-day master password check is due (plan 03).
    pub password_required: bool,
}

/// What the account's vaults hold on its server, and the server's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct StorageUsage {
    /// Stored (encrypted) bytes of attachments, the trash included.
    pub attachment_bytes: u64,
    pub max_attachment_bytes: u64,
    /// The largest file the server takes, as stored.
    pub max_file_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SyncStatus {
    Idle,
    Syncing,
    /// The last sync failed (offline, say); the vault keeps working from this phone.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SyncState {
    pub status: SyncStatus,
    pub last_synced_at: Option<String>,
    /// Why the last sync failed.
    pub error: Option<ErrorCode>,
    /// Changes saved here (or by an autofill extension) waiting to upload.
    pub pending_changes: bool,
    /// Attachments waiting to upload, and their size.
    pub pending_files: u32,
    pub pending_bytes: u64,
}

/// A signed-in device, from the server's list.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Device {
    pub id: String,
    pub name: String,
    /// What the client said it is: `web`, `extension`, `ios`, `android`, `mac`, …
    pub platform: String,
    pub created_at: String,
    pub last_seen_at: String,
    /// This phone.
    pub current: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityEvent {
    /// Like `two-step-enabled` or `emergency-access-requested`: the catalog names each one.
    pub event_type: String,
    pub created_at: String,
    pub other_account_email: Option<String>,
    pub emergency_contact_id: Option<String>,
    /// `vault-exported`: the device as it was named when it exported, even after it signed out.
    pub device_name: Option<String>,
    pub device_platform: Option<String>,
    pub export_format: Option<ExportFormat>,
    /// Whether the file held the attachments (only the encrypted export does).
    pub export_attachments: Option<bool>,
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

pub(crate) fn now_text() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC times format as RFC 3339")
}

/// Items get UUIDv7 ids when they're created, so the id carries the creation time.
pub(crate) fn created_at(id: &str) -> Option<String> {
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

/// What the feature modules work with, for one call.
pub(crate) struct Ctx<'a> {
    pub vault: &'a MobileVault,
    pub api: &'a Api,
    pub shared: &'a SharedVaults,
    pub provider_http: &'a dyn ProviderHttp,
    pub observer: &'a dyn VaultObserver,
    pub web_vault_url: &'a str,
    pub default_server_url: &'a str,
}

impl Ctx<'_> {
    pub(crate) fn sharing_changed(&self) {
        self.observer.sharing_changed();
    }
}

/// The sync status, and the changes waiting to upload as last seen.
struct SyncTracker {
    state: Mutex<SyncState>,
    observer: Arc<dyn VaultObserver>,
}

impl SyncTracker {
    fn update(&self, change: impl FnOnce(&mut SyncState)) {
        let state = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let before = state.clone();
            change(&mut state);
            (*state != before).then(|| state.clone())
        };
        if let Some(state) = state {
            self.observer.sync_changed(state);
        }
    }

    fn get(&self) -> SyncState {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

fn snapshot(snapshot: octapass_mobile_vault::SessionSnapshot) -> SessionSnapshot {
    SessionSnapshot {
        status: match snapshot.session.status {
            VaultStatus::SignedOut => SessionStatus::SignedOut,
            VaultStatus::Locked => SessionStatus::Locked,
            VaultStatus::Unlocked => SessionStatus::Unlocked,
        },
        email: snapshot.session.email,
        server_url: snapshot.session.server_url,
        remembered_accounts: snapshot
            .remembered_accounts
            .into_iter()
            .map(|account| RememberedAccount {
                email: account.email,
                server_url: account.server_url,
            })
            .collect(),
    }
}

fn methods(methods: Vec<octapass_mobile_vault::model::TwoStepMethod>) -> Vec<TwoStepMethod> {
    use octapass_mobile_vault::model::TwoStepMethod as M;
    methods
        .into_iter()
        .map(|method| match method {
            M::Totp => TwoStepMethod::Totp,
            M::SecurityKey => TwoStepMethod::SecurityKey,
            M::RecoveryCode => TwoStepMethod::RecoveryCode,
        })
        .collect()
}

fn sign_in_result(result: octapass_mobile_vault::model::SignInResult) -> SignInResult {
    use octapass_mobile_vault::model::SignInResult as R;
    match result {
        R::SignedIn => SignInResult::SignedIn,
        R::TwoStepRequired { methods: offered } => SignInResult::TwoStepRequired {
            methods: methods(offered),
        },
        R::SsoRequired { url, org_name } => SignInResult::SsoRequired { url, org_name },
    }
}

pub(crate) fn recovery_kit(kit: octapass_mobile_vault::model::RecoveryKit) -> RecoveryKit {
    RecoveryKit {
        email: kit.email,
        server_url: kit.server_url,
        secret_key: kit.secret_key,
        recovery_code: kit.recovery_code,
        created_at: kit.created_at,
    }
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[derive(uniffi::Object)]
pub struct OctaPassVault {
    pub(crate) vault: Arc<MobileVault>,
    api: Api,
    provider_http: Box<dyn ProviderHttp>,
    shared: SharedVaults,
    observer: Arc<dyn VaultObserver>,
    sync: Arc<SyncTracker>,
    settings: Mutex<Settings>,
    config: VaultConfig,
    last_activity: Mutex<Instant>,
    icons: SiteIcons,
    /// Uses counted but not saved yet (`recordItemUse`), and whether a save is on its way.
    uses: Mutex<PendingUses>,
    /// The user locked the vault ("Lock now"): stay unlocked (plan 18) doesn't open it again by
    /// itself until the user unlocks it once. In memory only, so a restarted app opens unlocked.
    pub(crate) held: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct PendingUses {
    uses: Usage,
    scheduled: bool,
}

/// Rust-only: what the async exports run on a vault thread.
impl OctaPassVault {
    pub(crate) fn run<T: Send + 'static>(
        self: &Arc<Self>,
        work: impl FnOnce(&Arc<Self>) -> Result<T> + Send + 'static,
    ) -> impl Future<Output = Result<T>> + Send + 'static {
        let this = Arc::clone(self);
        background(move || work(&this))
    }

    fn write_opened(&self, name: &str, bytes: &[u8]) -> Result<String> {
        let path = self.vault.new_opened_path(name)?;
        std::fs::write(&path, bytes)
            .map_err(|error| VaultError::unexpected(format!("files: {error}")))?;
        Ok(path_text(&path))
    }

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            vault: &self.vault,
            api: &self.api,
            shared: &self.shared,
            provider_http: &*self.provider_http,
            observer: &*self.observer,
            web_vault_url: &self.config.web_vault_url,
            default_server_url: &self.config.default_server_url,
        }
    }

    fn settings_guard(&self) -> MutexGuard<'_, Settings> {
        self.settings.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn pending_uses(&self) -> MutexGuard<'_, PendingUses> {
        self.uses.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Saves the uses counted so far. A failed save keeps them for the next one; a locked
    /// vault forgets them.
    fn save_pending_uses(&self) -> Result<()> {
        let uses = {
            let mut pending = self.pending_uses();
            pending.scheduled = false;
            std::mem::take(&mut pending.uses)
        };
        if uses.is_empty() || !self.is_unlocked() {
            return Ok(());
        }
        let saved = self
            .personal_vault_id()
            .and_then(|personal| self.ctx().save_uses(&personal, &uses));
        match saved {
            Ok(()) => self.refresh_pending(),
            Err(_) => add_uses(&mut self.pending_uses().uses, &uses),
        }
        saved
    }

    fn is_unlocked(&self) -> bool {
        self.vault.snapshot().session.status == VaultStatus::Unlocked
    }

    pub(crate) fn touch(&self) {
        *self.last_activity.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
    }

    /// Locks once the vault has been idle for the auto-lock time.
    fn check_auto_lock(&self) {
        let minutes = self.settings_guard().auto_lock_minutes;
        let idle = self
            .last_activity
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .elapsed();
        if minutes > 0
            && idle >= Duration::from_secs(u64::from(minutes) * 60)
            && self.is_unlocked()
            && !self.stays_unlocked()
        {
            self.vault.lock();
        }
    }

    /// Changes waiting to upload, as the sync status shows them.
    fn refresh_pending(&self) {
        let Ok(access) = self.vault.access() else {
            return;
        };
        let pending = access.store().has_pending_changes();
        let outbox = access.outbox_status();
        self.sync.update(|state| {
            state.pending_changes = pending;
            state.pending_files = outbox.files as u32;
            state.pending_bytes = outbox.bytes;
        });
    }

    /// Uploads what was saved here and pulls what changed elsewhere.
    fn sync_now(&self) -> Result<()> {
        self.sync.update(|state| state.status = SyncStatus::Syncing);
        let result = self.vault.sync();
        if let Ok(access) = self.vault.access() {
            self.shared.open(&access);
        }
        match &result {
            Ok(()) => self.sync.update(|state| {
                state.status = SyncStatus::Idle;
                state.error = None;
                state.last_synced_at = Some(now_text());
            }),
            Err(error) => {
                let code = VaultError::from(error.clone()).code();
                self.sync.update(|state| {
                    state.status = SyncStatus::Failed;
                    state.error = Some(code);
                });
            }
        }
        self.refresh_pending();
        Ok(result?)
    }

    /// A sync nobody waits for, after an unlock or when the app comes back.
    fn sync_soon(self: &Arc<Self>) {
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            if this.is_unlocked() {
                let _ = this.sync_now();
            }
        });
    }

    pub(crate) fn after_unlock(self: &Arc<Self>) {
        self.touch();
        if let Ok(access) = self.vault.access() {
            self.shared.open(&access);
        }
        self.sync_soon();
    }

    /// Every listable item: not a vault's name record, not in a vault whose grant didn't
    /// verify.
    fn visible_items(&self) -> Result<Vec<StoredItem>> {
        let access = self.vault.access()?;
        let untrusted = self.shared.open(&access);
        drop(access);
        let mut items = self.vault.all_items()?;
        items.retain(|item| !is_vault_info(item) && !untrusted.contains(&item.vault_id));
        Ok(items)
    }

    fn vaults(&self) -> Result<Vec<Vault>> {
        let access = self.vault.access()?;
        self.shared.open(&access);
        let items = self.vault.all_items()?;
        Ok(list_vaults(&self.ctx(), &access, &items))
    }

    fn personal_vault_id(&self) -> Result<String> {
        self.vaults()?
            .into_iter()
            .find(|vault| vault.vault_type == VaultType::Personal)
            .map(|vault| vault.id)
            .ok_or_else(|| ErrorCode::NotFound.into())
    }

    fn summaries(&self, filter: &ItemFilter) -> Result<Vec<ItemSummary>> {
        Ok(self
            .visible_items()?
            .iter()
            .map(ItemSummary::from)
            .filter(|summary| matches_filter(summary, filter))
            .collect())
    }

    /// What the watch should have now: the codes, or a clear when the vault is locked or the
    /// setting is off. Never counts as activity: a watch asking can't keep the vault unlocked.
    fn watch_json(&self, now_ms: u64) -> Result<String> {
        if !self.settings_guard().show_codes_on_watch || !self.is_unlocked() {
            return Ok(watch::clear_json(now_ms));
        }
        let items = self.visible_items()?;
        let filter = ItemFilter {
            totp: true,
            ..ItemFilter::default()
        };
        let mut summaries: Vec<ItemSummary> = items
            .iter()
            .map(ItemSummary::from)
            .filter(|summary| matches_filter(summary, &filter))
            .collect();
        sort_items(&mut summaries, ListSort::Name);
        // Stable: favourites first, each group in name order.
        summaries.sort_by_key(|summary| !summary.favorite);
        let sources: Vec<WatchSource> = summaries
            .into_iter()
            .filter_map(|summary| {
                let stored = items.iter().find(|item| item.id == summary.id)?;
                let totp = stored.details.get("totp")?.as_str()?;
                Some(WatchSource {
                    item_id: summary.id,
                    title: summary.title,
                    favorite: summary.favorite,
                    totp: Zeroizing::new(totp.to_string()),
                })
            })
            .collect();
        Ok(watch::bundle_json(&sources, now_ms))
    }

    fn item(&self, id: &str) -> Result<Item> {
        let item = self.vault.get_item(id)?;
        require(!is_vault_info(&item), ErrorCode::NotFound)?;
        Ok(Item::from(&item))
    }

    fn save(&self, draft: &ItemDraft) -> Result<Item> {
        let stored = match &draft.id {
            Some(id) => Some(self.vault.get_item(id)?),
            None => None,
        };
        let (overview, details) = draft_json(draft, stored.as_ref())?;
        let saved = self.vault.save_item(StoredDraft {
            id: draft.id.clone(),
            vault_id: draft.vault_id.clone(),
            revision: draft.revision,
            overview,
            details,
        })?;
        self.refresh_pending();
        Ok(Item::from(&saved))
    }

    /// Forgets what this phone noted for the current account (fingerprints, share links).
    fn forget_notes_for(&self, before: &SessionSnapshot) {
        if let (Some(email), Some(server_url)) = (&before.email, &before.server_url) {
            let account = octapass_mobile_vault::accounts::Account::new(server_url, email);
            local::forget_notes(Path::new(&self.config.data_dir), &account.tag);
        }
    }

    fn server_call<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<T> {
        let access = self.vault.access()?;
        Server {
            api: &self.api,
            access: &access,
        }
        .call(method, path, body)
    }

    fn start_auto_lock(self: &Arc<Self>) {
        let this: Weak<Self> = Arc::downgrade(self);
        let _ = std::thread::Builder::new()
            .name("octapass-auto-lock".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(AUTO_LOCK_TICK);
                    match this.upgrade() {
                        Some(vault) => vault.check_auto_lock(),
                        None => return,
                    }
                }
            });
    }
}

#[uniffi::export]
impl OctaPassVault {
    /// Opens the vault for the accounts this phone remembers. Starts locked (or signed out).
    #[uniffi::constructor]
    pub fn new(
        config: VaultConfig,
        platform: Arc<dyn NativePlatform>,
        observer: Arc<dyn VaultObserver>,
    ) -> Result<Arc<Self>> {
        let sync = Arc::new(SyncTracker {
            state: Mutex::new(SyncState {
                status: SyncStatus::Idle,
                last_synced_at: None,
                error: None,
                pending_changes: false,
                pending_files: 0,
                pending_bytes: 0,
            }),
            observer: Arc::clone(&observer),
        });
        let (events, tracker) = (Arc::clone(&observer), Arc::clone(&sync));
        // Every unlock, whatever opened it, gives stay unlocked its key (plan 18).
        let hook: Arc<std::sync::OnceLock<Weak<Self>>> = Arc::default();
        let unlocked_hook = Arc::clone(&hook);
        let was_unlocked = std::sync::atomic::AtomicBool::new(false);
        let platform_name = match config.platform {
            DevicePlatform::Ios => "ios",
            DevicePlatform::Android => "android",
            DevicePlatform::Macos => "macos",
        };
        let vault = MobileVault::new(
            Config {
                data_dir: config.data_dir.clone().into(),
                temp_dir: config.temp_dir.clone().into(),
                device: DeviceInfo {
                    name: config.device_name.clone(),
                    platform: platform_name.into(),
                },
                pwned_passwords_url: config.pwned_passwords_url.clone(),
            },
            Arc::new(Bridge(platform)),
            Box::new(move |event| match event {
                Event::Session(state) => {
                    let unlocked = state.session.status == VaultStatus::Unlocked;
                    let opened = unlocked
                        && !was_unlocked.swap(true, std::sync::atomic::Ordering::SeqCst);
                    if !unlocked {
                        was_unlocked.store(false, std::sync::atomic::Ordering::SeqCst);
                    }
                    events.session_changed(snapshot(state));
                    if let Some(this) = opened
                        .then(|| unlocked_hook.get().and_then(Weak::upgrade))
                        .flatten()
                    {
                        this.after_any_unlock();
                    }
                }
                Event::ItemsChanged => events.items_changed(),
                Event::SyncFailed { .. } => tracker.update(|state| {
                    state.status = SyncStatus::Failed;
                    state.error.get_or_insert(ErrorCode::ServerUnreachable);
                }),
            }),
        )?;
        let user_agent = format!("OctaPass-{platform_name}/{}", env!("CARGO_PKG_VERSION"));
        let this = Arc::new(Self {
            settings: Mutex::new(local::load_settings(Path::new(&config.data_dir))),
            vault,
            api: Api::new(&user_agent),
            provider_http: Box::new(Ureq::new()),
            shared: SharedVaults,
            observer,
            sync,
            icons: SiteIcons::new(&config.cache_dir),
            config,
            last_activity: Mutex::new(Instant::now()),
            uses: Mutex::new(PendingUses::default()),
            held: std::sync::atomic::AtomicBool::new(false),
        });
        let _ = hook.set(Arc::downgrade(&this));
        this.start_auto_lock();
        Ok(this)
    }

    // ---------- Session and account ----------

    /// The session and the accounts this phone remembers. Fast: call it anywhere.
    pub fn snapshot(&self) -> SessionSnapshot {
        snapshot(self.vault.snapshot())
    }

    pub async fn server_info(self: Arc<Self>, server_url: String) -> Result<ServerInfo> {
        self.run(move |this| {
            let info = this.vault.server_info(&server_url)?;
            Ok(ServerInfo {
                name: info.name,
                version: info.version,
                api_version: info.api_version,
                signups: match info.signups {
                    "invite" => SignupMode::Invite,
                    "closed" => SignupMode::Closed,
                    _ => SignupMode::Open,
                },
                push_relay: info.push_relay,
            })
        })
        .await
    }

    /// Makes the account's keys on this phone (Argon2id) and asks the server for an email code.
    pub async fn start_signup(
        self: Arc<Self>,
        server_url: String,
        email: String,
        password: String,
    ) -> Result<SignupStarted> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            let started = this.vault.start_signup(&server_url, &email, password)?;
            Ok(SignupStarted {
                signup_id: started.signup_id,
                dev_verification_code: started.dev_verification_code,
            })
        })
        .await
    }

    /// Finishes sign-up and signs in. A wrong code can be tried again.
    pub async fn finish_signup(
        self: Arc<Self>,
        signup_id: String,
        verification_code: String,
    ) -> Result<RecoveryKit> {
        self.run(move |this| {
            let kit = this.vault.finish_signup(&signup_id, &verification_code)?;
            this.touch();
            this.sync
                .update(|state| state.last_synced_at = Some(now_text()));
            Ok(recovery_kit(kit))
        })
        .await
    }

    /// `secret_key` is needed for an account this phone doesn't remember.
    pub async fn sign_in(
        self: Arc<Self>,
        server_url: String,
        email: String,
        password: String,
        secret_key: Option<String>,
    ) -> Result<SignInResult> {
        let (password, secret_key) = (Zeroizing::new(password), secret_key.map(Zeroizing::new));
        self.run(move |this| {
            let result = this
                .vault
                .sign_in(&server_url, &email, password, secret_key)?;
            let result = sign_in_result(result);
            if result == SignInResult::SignedIn {
                this.after_unlock();
            }
            Ok(result)
        })
        .await
    }

    /// Finishes the SSO step. It can end in `TwoStepRequired`. A wrong code fails with
    /// `invalidTwoStepCode`, a browser that hasn't finished with `ssoPending`; `twoStepExpired`
    /// means signing in again from the start.
    pub async fn finish_sso(self: Arc<Self>, code: String) -> Result<SignInResult> {
        self.run(move |this| {
            let result = sign_in_result(this.vault.finish_sso(&code)?);
            if result == SignInResult::SignedIn {
                this.after_unlock();
            }
            Ok(result)
        })
        .await
    }

    /// A wrong code fails with `invalidTwoStepCode` (try again); `twoStepExpired` means signing
    /// in again from the start.
    pub async fn finish_two_step(self: Arc<Self>, proof: TwoStepProof) -> Result<()> {
        self.run(move |this| {
            use octapass_mobile_vault::model::TwoStepProof as P;
            this.vault.finish_two_step(match proof {
                TwoStepProof::Totp { code } => P::Totp { code },
                TwoStepProof::RecoveryCode { code } => P::RecoveryCode { code },
            })?;
            this.after_unlock();
            Ok(())
        })
        .await
    }

    pub fn pending_two_step(&self) -> Option<PendingTwoStep> {
        use octapass_mobile_vault::vault::TwoStepPending as P;
        self.vault.pending_two_step().map(|pending| match pending {
            P::Required { methods: offered } => PendingTwoStep::Required {
                methods: methods(offered),
            },
            P::Expired => PendingTwoStep::Expired,
        })
    }

    /// "Start over".
    pub fn cancel_two_step(&self) {
        self.vault.cancel_two_step();
    }

    /// Zeroes the keys and deletes every decrypted file. Fast. With stay unlocked on, the vault
    /// stays locked until the user unlocks it (or the app starts again).
    pub fn lock(&self) {
        self.held.store(true, std::sync::atomic::Ordering::SeqCst);
        self.pending_uses().uses.clear();
        self.vault.lock();
    }

    pub async fn unlock(self: Arc<Self>, password: String) -> Result<()> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            this.vault.unlock(password)?;
            this.after_unlock();
            Ok(())
        })
        .await
    }

    /// Asks for Face ID / the fingerprint or the passcode. Fails with `passwordRequired` when
    /// device unlock is off or the 14-day master password check is due.
    pub async fn unlock_with_device(self: Arc<Self>) -> Result<()> {
        self.run(move |this| {
            this.vault.unlock_with_device()?;
            this.after_unlock();
            Ok(())
        })
        .await
    }

    /// Signs out here: the server forgets this phone, and the store, the Keychain items and the
    /// AutoFill suggestions go.
    pub async fn sign_out(self: Arc<Self>) -> Result<()> {
        self.run(move |this| {
            let before = this.snapshot();
            this.vault.sign_out()?;
            this.forget_notes_for(&before);
            this.icons.clear();
            Ok(())
        })
        .await
    }

    /// The Secret Key stored on this phone, for a signed-in user to find again. Unlocked only.
    pub async fn secret_key(self: Arc<Self>) -> Result<String> {
        self.run(|this| Ok(this.vault.secret_key()?)).await
    }

    pub async fn account_summary(self: Arc<Self>) -> Result<AccountSummary> {
        self.run(|this| {
            let summary = this.vault.account_summary()?;
            let vaults = this.vaults()?;
            let items = this.summaries(&ItemFilter::default())?;
            Ok(AccountSummary {
                email: summary.email,
                item_count: items.len() as u32,
                vault_count: vaults.len() as u32,
                device_count: summary.device_count as u32,
                shared_vaults_owned: this.ctx().shared_vaults_owned(&vaults)?,
            })
        })
        .await
    }

    /// Checks the master password with the server, deletes everything there, wipes this
    /// phone's copy and signs out.
    pub async fn delete_account(
        self: Arc<Self>,
        confirm_email: String,
        password: String,
    ) -> Result<()> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            let before = this.snapshot();
            this.vault.delete_account(&confirm_email, password)?;
            this.forget_notes_for(&before);
            this.icons.clear();
            Ok(())
        })
        .await
    }

    // ---------- Master password ----------

    /// A new master password, after checking the current one (`invalidCredentials` when it's
    /// wrong). The Secret Key and recovery code stay; every other device is signed out, and
    /// device unlock has to be turned on again.
    pub async fn change_master_password(
        self: Arc<Self>,
        current_password: String,
        new_password: String,
    ) -> Result<()> {
        let (current_password, new_password) = (
            Zeroizing::new(current_password),
            Zeroizing::new(new_password),
        );
        self.run(move |this| {
            this.vault
                .change_master_password(current_password, new_password)?;
            this.touch();
            Ok(())
        })
        .await
    }

    /// A new Secret Key with the same master password (`invalidCredentials` when it's wrong). The
    /// recovery code stays unless `new_recovery_code` is set; every other device is signed out,
    /// and device unlock has to be turned on again. Show the kit before anything else: it's the
    /// only copy of the new key off this device.
    pub async fn rotate_secret_key(
        self: Arc<Self>,
        password: String,
        new_recovery_code: bool,
    ) -> Result<NewRecoveryKit> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            let kit = this.vault.rotate_secret_key(password, new_recovery_code)?;
            this.touch();
            Ok(NewRecoveryKit {
                email: kit.email,
                server_url: kit.server_url,
                secret_key: kit.secret_key,
                recovery_code: kit.recovery_code,
                created_at: kit.created_at,
            })
        })
        .await
    }

    /// Starts a reset with the recovery code: emails a code. The answer is the same for an email
    /// without an account.
    pub async fn start_password_reset(
        self: Arc<Self>,
        server_url: String,
        email: String,
    ) -> Result<PasswordResetStarted> {
        self.run(move |this| {
            let started = this.vault.start_password_reset(&server_url, &email)?;
            Ok(PasswordResetStarted {
                reset_id: started.reset_id,
                dev_verification_code: started.dev_verification_code,
            })
        })
        .await
    }

    /// Checks the emailed code: `invalidVerificationCode` to try again, `resetExpired` to start
    /// over.
    pub async fn verify_password_reset(
        self: Arc<Self>,
        reset_id: String,
        verification_code: String,
    ) -> Result<()> {
        self.run(move |this| {
            this.vault
                .verify_password_reset(&reset_id, &verification_code)?;
            Ok(())
        })
        .await
    }

    /// Opens the account key with the recovery code (`invalidRecoveryCode` when it doesn't), sets
    /// the new master password and signs in. Show the new Recovery Kit: the recovery code is
    /// always new, and so is the Secret Key unless this phone remembers the account.
    pub async fn finish_password_reset(
        self: Arc<Self>,
        reset_id: String,
        recovery_code: String,
        password: String,
    ) -> Result<PasswordResetResult> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            let result = this
                .vault
                .finish_password_reset(&reset_id, &recovery_code, password)?;
            if this.is_unlocked() {
                this.after_unlock();
            }
            Ok(PasswordResetResult {
                recovery_kit: recovery_kit(result.recovery_kit),
                sign_in: result.sign_in.map(sign_in_result),
            })
        })
        .await
    }

    /// Drops a reset in progress: "Start over".
    pub fn cancel_password_reset(&self, reset_id: String) {
        self.vault.cancel_password_reset(&reset_id);
    }

    // ---------- Two-step sign-in settings ----------

    pub async fn two_step_status(self: Arc<Self>) -> Result<TwoStepStatus> {
        self.run(|this| {
            let status = this.vault.two_step_status()?;
            Ok(TwoStepStatus {
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
                security_keys_supported: status.security_keys_supported,
            })
        })
        .await
    }

    /// Starts adding (or replacing) the authenticator app. Nothing changes until
    /// `confirmTotpSetup`.
    pub async fn start_totp_setup(self: Arc<Self>, password: String) -> Result<TotpSetup> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            let setup = this.vault.start_totp_setup(password)?;
            Ok(TotpSetup {
                secret: setup.secret,
                otpauth_uri: setup.otpauth_uri,
            })
        })
        .await
    }

    /// Turns two-step sign-in on, returning the recovery codes to show once, or swaps the
    /// authenticator (no codes). A wrong code fails with `invalidTwoStepCode`.
    pub async fn confirm_totp_setup(self: Arc<Self>, code: String) -> Result<Option<Vec<String>>> {
        self.run(move |this| Ok(this.vault.confirm_totp_setup(&code)?.recovery_codes))
            .await
    }

    /// Replaces every recovery code. Show the new ones once.
    pub async fn renew_recovery_codes(self: Arc<Self>, password: String) -> Result<Vec<String>> {
        let password = Zeroizing::new(password);
        self.run(move |this| Ok(this.vault.renew_recovery_codes(password)?))
            .await
    }

    /// The authenticator, security keys and recovery codes are removed.
    pub async fn disable_two_step(self: Arc<Self>, password: String) -> Result<()> {
        let password = Zeroizing::new(password);
        self.run(move |this| Ok(this.vault.disable_two_step(password)?))
            .await
    }

    pub async fn remove_security_key(self: Arc<Self>, id: String, password: String) -> Result<()> {
        let password = Zeroizing::new(password);
        self.run(move |this| Ok(this.vault.remove_security_key(&id, password)?))
            .await
    }

    /// Every other device asks for the second step at its next sign-in. Their sessions stay.
    pub async fn forget_trusted_devices(self: Arc<Self>) -> Result<()> {
        self.run(|this| {
            this.server_call::<()>(Method::Delete, "v1/account/two-step/trusted-devices", None)
        })
        .await
    }

    // ---------- Device unlock ----------

    pub async fn unlock_methods(self: Arc<Self>) -> Result<UnlockMethods> {
        self.run(|this| {
            let methods = this.vault.unlock_methods();
            Ok(UnlockMethods {
                device_unlock_supported: methods.device_unlock_supported,
                device_unlock_enabled: methods.device_unlock_enabled,
                label: methods.label,
                password_required: methods.password_required,
            })
        })
        .await
    }

    pub async fn enable_device_unlock(self: Arc<Self>) -> Result<()> {
        self.run(|this| Ok(this.vault.enable_device_unlock()?))
            .await
    }

    pub async fn disable_device_unlock(self: Arc<Self>) -> Result<()> {
        self.run(|this| Ok(this.vault.disable_device_unlock()?))
            .await
    }

    /// Checks it's still the owner before a secret is shown as a QR code (plan 01): the master
    /// password if given, otherwise the device lock.
    pub async fn confirm_user(self: Arc<Self>, password: Option<String>) -> Result<()> {
        let password = password.map(Zeroizing::new);
        self.run(move |this| Ok(this.vault.confirm_user(password)?))
            .await
    }

    // ---------- SSH keys ----------

    /// A new key. RSA can take a few seconds on a phone. `withSshKey` puts it in a draft.
    pub async fn generate_ssh_key(
        self: Arc<Self>,
        kind: SshKeyKind,
        comment: String,
    ) -> Result<SshKeyMaterial> {
        self.run(move |_| ssh::generate(kind, &comment)).await
    }

    /// Reads a private key in OpenSSH, PEM or PKCS#8 form. A protected key without its passphrase
    /// fails with `sshPassphraseRequired`, a wrong one with `wrongPassphrase`.
    pub async fn read_ssh_key(
        self: Arc<Self>,
        text: String,
        passphrase: Option<String>,
    ) -> Result<SshKeyMaterial> {
        let (text, passphrase) = (Zeroizing::new(text), passphrase.map(Zeroizing::new));
        self.run(move |_| ssh::read(&text, passphrase.as_ref().map(|p| p.as_str())))
            .await
    }

    /// Writes a private key to a file for the share sheet, encrypted with `passphrase` when
    /// there is one, and returns its path. Call `closeAttachment` with it afterwards. The app
    /// checks it's the owner first (`confirmUser`).
    pub async fn export_ssh_key(
        self: Arc<Self>,
        details: SshKeyDetails,
        file_name: String,
        passphrase: Option<String>,
    ) -> Result<String> {
        let passphrase = passphrase.map(Zeroizing::new);
        self.run(move |this| {
            let private_key = details.private_key.as_deref().unwrap_or_default();
            let comment = details.comment.as_deref().unwrap_or_default();
            let text = Zeroizing::new(ssh::write(
                private_key,
                comment,
                passphrase.as_ref().map(|p| p.as_str()),
            )?);
            this.write_opened(&file_name, text.as_bytes())
        })
        .await
    }

    /// Writes text to a named file for the share sheet (a public key, an environment's `.env`)
    /// and returns its path. Call `closeAttachment` with it afterwards.
    pub async fn write_share_file(
        self: Arc<Self>,
        file_name: String,
        text: String,
    ) -> Result<String> {
        let text = Zeroizing::new(text);
        self.run(move |this| this.write_opened(&file_name, text.as_bytes()))
            .await
    }

    // ---------- Vaults and items ----------

    /// The personal vault first, then the family vault, then shared vaults by name.
    pub async fn list_vaults(self: Arc<Self>) -> Result<Vec<Vault>> {
        self.run(|this| this.vaults()).await
    }

    pub async fn list_items(self: Arc<Self>, filter: ItemFilter) -> Result<Vec<ItemSummary>> {
        self.run(move |this| this.summaries(&filter)).await
    }

    /// How many items each list of the sidebar holds, by list: `all`, `favorites`, `pinned`,
    /// `passkeys`, `codes`, `trash`, each type's name, and `v-<vault id>` (`useCounts` in the web
    /// vault).
    pub async fn item_counts(self: Arc<Self>) -> Result<HashMap<String, u32>> {
        self.run(|this| {
            let all = this.summaries(&ItemFilter::default())?;
            let trash = this.summaries(&ItemFilter {
                trash: true,
                ..ItemFilter::default()
            })?;
            Ok(crate::list::counts(&all, trash.len()))
        })
        .await
    }

    /// The list the item screen shows: filtered, sorted and in sections, as the web vault does.
    /// With `combine_sites`, each section's `entries` show two or more logins for the same
    /// website as one row (the `combineSites` setting, in lists `offersSiteRows` names).
    #[uniffi::method(default(combine_sites = false))]
    pub async fn arrange_items(
        self: Arc<Self>,
        filter: ItemFilter,
        sort: ListSort,
        grouping: ListGrouping,
        combine_sites: bool,
    ) -> Result<Vec<ListSection>> {
        self.run(move |this| {
            let order: Vec<String> = this.vaults()?.into_iter().map(|vault| vault.id).collect();
            Ok(arrange(
                this.summaries(&filter)?,
                sort,
                grouping,
                &order,
                combine_sites,
            ))
        })
        .await
    }

    /// Files still waiting to upload are marked `pending`.
    pub async fn get_item(self: Arc<Self>, id: String) -> Result<Item> {
        self.run(move |this| this.item(&id)).await
    }

    /// The login already saved that `draft`, a new login, would add again: one in any vault the
    /// app shows, not in the trash, for a website on the same site and with the same username
    /// (the web vault's editor asks before saving such a copy). `None` for an edit, another type
    /// or a login without a website.
    pub async fn same_login(self: Arc<Self>, draft: ItemDraft) -> Result<Option<ItemSummary>> {
        self.run(move |this| {
            Ok(this
                .visible_items()?
                .iter()
                .find(|item| crate::items::is_same_login(item, &draft))
                .map(ItemSummary::from))
        })
        .await
    }

    /// Creates or updates. Checks the draft as `validateDraft` does (`invalidInput`). An edit
    /// of an older revision is saved as a conflicting copy instead of overwriting.
    pub async fn save_item(self: Arc<Self>, draft: ItemDraft) -> Result<Item> {
        self.run(move |this| this.save(&draft)).await
    }

    /// The item's past versions, newest first (at most 10). They come from the server, so this
    /// needs the network. Files aren't part of a version.
    pub async fn item_versions(self: Arc<Self>, id: String) -> Result<Vec<ItemVersion>> {
        self.run(move |this| {
            let current = this.vault.get_item(&id)?;
            Ok(this
                .vault
                .item_versions(&id)?
                .into_iter()
                .map(|version| ItemVersion::new(&current, version))
                .collect())
        })
        .await
    }

    /// Makes a past version current, as an ordinary edit: what it replaces joins the history.
    pub async fn restore_item_version(self: Arc<Self>, id: String, revision: u64) -> Result<Item> {
        self.run(move |this| {
            this.vault.restore_item_version(&id, revision)?;
            this.item(&id)
        })
        .await
    }

    /// Saves the moved counter of a login's counter-based code, then gives the code. Works
    /// offline: the counter uploads with the next sync.
    pub async fn next_hotp_code(self: Arc<Self>, id: String) -> Result<HotpCode> {
        self.run(move |this| {
            let code = this.vault.next_hotp_code(&id)?;
            Ok(HotpCode {
                code: code.code,
                counter: code.counter,
            })
        })
        .await
    }

    /// Brings a counter-based code back in step with the site. Not an edit: no history entry.
    pub async fn set_hotp_counter(self: Arc<Self>, id: String, counter: u64) -> Result<Item> {
        self.run(move |this| {
            this.vault.set_hotp_counter(&id, counter)?;
            this.item(&id)
        })
        .await
    }

    pub async fn equivalent_domains(self: Arc<Self>) -> Result<EquivalentDomains> {
        self.run(move |this| Ok(this.vault.equivalent_domains()?.into()))
            .await
    }

    /// Saves the list; `rejected` says what wasn't added (public suffixes, addresses, anything
    /// that isn't a domain).
    pub async fn save_equivalent_domains(
        self: Arc<Self>,
        groups: Vec<Vec<String>>,
        excluded_defaults: Vec<String>,
    ) -> Result<EquivalentDomains> {
        self.run(move |this| {
            let saved = this.vault.save_equivalent_domains(EquivalentDomainsInput {
                groups,
                excluded_defaults,
            })?;
            Ok(saved.into())
        })
        .await
    }

    /// Saves what a developer tool made: `{ overview, details }` from the core's `item.certificate`
    /// or `item.key`, which the typed drafts above don't carry. Returns the new item's id.
    pub async fn save_tool_item(
        self: Arc<Self>,
        vault_id: String,
        draft_json: String,
    ) -> Result<String> {
        self.run(move |this| {
            let invalid = || VaultError::new(ErrorCode::InvalidInput, "invalid item");
            let draft: serde_json::Value =
                serde_json::from_str(&draft_json).map_err(|_| invalid())?;
            let saved = this.vault.save_item(StoredDraft {
                id: None,
                vault_id,
                revision: None,
                overview: draft.get("overview").cloned().ok_or_else(invalid)?,
                details: draft.get("details").cloned().ok_or_else(invalid)?,
            })?;
            this.refresh_pending();
            Ok(saved.id)
        })
        .await
    }

    pub async fn set_favorite(self: Arc<Self>, id: String, favorite: bool) -> Result<Item> {
        self.run(move |this| {
            let mut draft = item_draft(this.item(&id)?);
            draft.favorite = favorite;
            this.save(&draft)
        })
        .await
    }

    /// Pins or unpins an item: pinned items are listed under Pinned.
    pub async fn set_pinned(self: Arc<Self>, id: String, pinned: bool) -> Result<Item> {
        self.run(move |this| {
            let mut draft = item_draft(this.item(&id)?);
            draft.pinned = pinned;
            this.save(&draft)
        })
        .await
    }

    /// Counts a use of the item, for Frequently used and Recently used: one of its fields
    /// copied, filled in, or its website opened. Uses are saved together a few seconds later,
    /// in a hidden, encrypted vault item; `flushItemUses` saves them at once.
    pub fn record_item_use(self: Arc<Self>, id: String) {
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("UTC times format as RFC 3339");
        let schedule = {
            let mut pending = self.pending_uses();
            let one = HashMap::from([(
                id,
                ItemUse {
                    count: 1,
                    last_used_at: now,
                },
            )]);
            add_uses(&mut pending.uses, &one);
            !std::mem::replace(&mut pending.scheduled, true)
        };
        if schedule {
            let this = Arc::clone(&self);
            std::thread::spawn(move || {
                std::thread::sleep(USAGE_SAVE_DELAY);
                let _ = this.save_pending_uses();
            });
        }
    }

    /// Saves the uses waiting to be saved now: call it when the app goes to the background.
    pub async fn flush_item_uses(self: Arc<Self>) -> Result<()> {
        self.run(|this| this.save_pending_uses()).await
    }

    /// A list that keeps an order of its own: Recently created, Frequently used, Recently used
    /// or Recently modified, at most 50 items, with uses not saved yet counted. A `query` looks
    /// through what the list shows.
    pub async fn smart_list(
        self: Arc<Self>,
        list: SmartList,
        query: Option<String>,
    ) -> Result<Vec<ItemSummary>> {
        self.run(move |this| {
            let items = this.summaries(&ItemFilter::default())?;
            let mut usage = match list {
                SmartList::Frequent | SmartList::Used => this.ctx().usage()?,
                SmartList::Created | SmartList::Changed => Usage::new(),
            };
            add_uses(&mut usage, &this.pending_uses().uses);
            Ok(crate::usage::smart_list(
                items,
                list,
                &usage,
                query.as_deref(),
            ))
        })
        .await
    }

    /// Moves an item to the trash. The trash lives on the server, so this needs the network.
    pub async fn delete_item(self: Arc<Self>, id: String) -> Result<()> {
        self.run(move |this| Ok(this.vault.delete_item(&id)?)).await
    }

    pub async fn restore_item(self: Arc<Self>, id: String) -> Result<()> {
        self.run(move |this| Ok(this.vault.restore_item(&id)?))
            .await
    }

    /// Moves an item to another vault: a copy there (files included), the original to the trash.
    pub async fn move_item(self: Arc<Self>, id: String, to_vault_id: String) -> Result<Item> {
        self.run(move |this| Ok(Item::from(&this.ctx().move_item(&id, &to_vault_id)?)))
            .await
    }

    pub async fn copy_item(self: Arc<Self>, id: String, to_vault_id: String) -> Result<Item> {
        self.run(move |this| Ok(Item::from(&this.ctx().copy_item(&id, &to_vault_id)?)))
            .await
    }

    // ---------- Attachments ----------

    /// Encrypts the file the app's picker copied to `path` into the account's outbox and lists
    /// it on the item at once; it uploads when it can, offline too. The app deletes its copy.
    /// Fails with `fileTooLarge` or `quotaExceeded` when the server's limits say so.
    pub async fn add_attachment(
        self: Arc<Self>,
        item_id: String,
        path: String,
        name: String,
        media_type: String,
    ) -> Result<Item> {
        self.run(move |this| {
            let item = this
                .vault
                .attach_file(&item_id, Path::new(&path), &name, &media_type)?;
            this.refresh_pending();
            Ok(Item::from(&item))
        })
        .await
    }

    /// Decrypts a file into the app's private storage and returns its path, for Quick Look or
    /// another app. Delete it with `closeAttachment` when the viewer closes; locking deletes it
    /// anyway.
    pub async fn open_attachment(
        self: Arc<Self>,
        item_id: String,
        attachment_id: String,
    ) -> Result<String> {
        self.run(move |this| {
            Ok(path_text(
                &this.vault.open_attachment_file(&item_id, &attachment_id)?,
            ))
        })
        .await
    }

    /// Deletes a file `openAttachment`, `exportVault`, `exportLocalBackup` or
    /// `openEmergencyAttachment` returned.
    pub fn close_attachment(&self, path: String) {
        self.vault.delete_opened(Path::new(&path));
    }

    pub async fn remove_attachment(
        self: Arc<Self>,
        item_id: String,
        attachment_id: String,
    ) -> Result<Item> {
        self.run(move |this| {
            let item = this.vault.remove_attachment(&item_id, &attachment_id)?;
            this.refresh_pending();
            Ok(Item::from(&item))
        })
        .await
    }

    pub async fn storage_usage(self: Arc<Self>) -> Result<StorageUsage> {
        self.run(|this| {
            let usage = this.vault.storage_usage()?;
            Ok(StorageUsage {
                attachment_bytes: usage.attachment_bytes,
                max_attachment_bytes: usage.max_attachment_bytes,
                max_file_bytes: usage.max_file_bytes,
            })
        })
        .await
    }

    // ---------- Sync ----------

    /// Uploads what was saved here (by the app or an autofill extension) and the files waiting
    /// to go up, then pulls what changed elsewhere.
    pub async fn sync(self: Arc<Self>) -> Result<()> {
        self.run(|this| this.sync_now()).await
    }

    pub fn sync_state(&self) -> SyncState {
        self.sync.get()
    }

    // ---------- Tools ----------

    /// The strength meter. The account's email counts against passwords that contain it.
    pub fn estimate_strength(&self, password: String) -> StrengthEstimate {
        let email = self.vault.snapshot().session.email.unwrap_or_default();
        let local = email.split('@').next().unwrap_or_default().to_owned();
        let inputs: Vec<&str> = [email.as_str(), local.as_str()]
            .into_iter()
            .filter(|input| !input.is_empty())
            .collect();
        estimate(&Zeroizing::new(password), &inputs)
    }

    /// How often the password appears in Pwned Passwords; 0 is none. Only the first five hex
    /// characters of its SHA-1 leave the phone.
    pub async fn check_breached(self: Arc<Self>, password: String) -> Result<u64> {
        let password = Zeroizing::new(password);
        self.run(move |this| Ok(this.vault.check_breached(&password)?))
            .await
    }

    /// The security dashboard and recovery map. Looks passwords up in Pwned Passwords.
    pub async fn health_report(self: Arc<Self>) -> Result<HealthReport> {
        self.run(|this| {
            let access = this.vault.access()?;
            this.shared.open(&access);
            drop(access);
            Ok(build_report(
                &this.vault.health_inputs()?,
                OffsetDateTime::now_utc(),
            ))
        })
        .await
    }

    /// The new password for a login, from Health's "Change password". The old one goes to the
    /// password history, as in any edit, so nothing is lost if the site's change didn't finish.
    pub async fn update_password(self: Arc<Self>, item_id: String, password: String) -> Result<()> {
        let password = Zeroizing::new(password);
        self.run(move |this| {
            let item = this.vault.get_item(&item_id)?;
            let mut details = item.details;
            details["password"] = serde_json::Value::String(password.to_string());
            this.vault.save_item(StoredDraft {
                id: Some(item.id),
                vault_id: item.vault_id,
                revision: Some(item.revision),
                overview: item.overview,
                details,
            })?;
            Ok(())
        })
        .await
    }

    /// Hides warnings on every device, with the `warning` keys from the report. Stored in a
    /// hidden, encrypted vault item.
    pub async fn dismiss_health_warnings(self: Arc<Self>, warnings: Vec<String>) -> Result<()> {
        self.run(move |this| {
            let personal = this.personal_vault_id()?;
            this.ctx().dismiss_health_warnings(&personal, &warnings)
        })
        .await
    }

    pub async fn restore_health_warnings(self: Arc<Self>, warnings: Vec<String>) -> Result<()> {
        self.run(move |this| {
            let personal = this.personal_vault_id()?;
            this.ctx().restore_health_warnings(&personal, &warnings)
        })
        .await
    }

    /// Opt-in: while on, the account email and aliases go to the server and on to Have I Been
    /// Pwned. The UI says so before this is called. Off forgets the results.
    pub async fn set_email_breach_alerts(self: Arc<Self>, enabled: bool) -> Result<()> {
        self.run(move |this| {
            let personal = this.personal_vault_id()?;
            this.ctx().set_email_breach_alerts(&personal, enabled)
        })
        .await
    }

    /// Whether this account's server has an HIBP key, so alerts can be turned on.
    pub async fn email_breach_checks_available(self: Arc<Self>) -> Result<bool> {
        self.run(|this| {
            let info: octapass_api::ServerInfo =
                this.server_call(Method::Get, "v1/server-info", None)?;
            Ok(info.email_breach_checks)
        })
        .await
    }

    /// Sends the addresses only when alerts are on and a day has passed, or `force`.
    pub async fn check_email_breaches(self: Arc<Self>, force: bool) -> Result<EmailBreachCheck> {
        self.run(move |this| {
            let personal = this.personal_vault_id()?;
            let email = this.vault.snapshot().session.email;
            this.ctx()
                .check_email_breaches(&personal, email.as_deref(), force)
        })
        .await
    }

    // ---------- Masked email ----------

    pub async fn masked_email_connections(self: Arc<Self>) -> Result<Vec<MaskedEmailConnection>> {
        self.run(|this| this.ctx().masked_email_connections()).await
    }

    /// Stores the provider's token in the personal vault. Doesn't call the provider.
    pub async fn connect_masked_email(
        self: Arc<Self>,
        provider: String,
        token: String,
        base_url: Option<String>,
        domain: Option<String>,
    ) -> Result<MaskedEmailConnection> {
        let token = Zeroizing::new(token);
        self.run(move |this| {
            let personal = this.personal_vault_id()?;
            this.ctx().connect_masked_email(
                &provider,
                &token,
                base_url.as_deref(),
                domain.as_deref(),
                &personal,
            )
        })
        .await
    }

    /// Moves the token's item to the trash. Aliases made with it keep working.
    pub async fn disconnect_masked_email(self: Arc<Self>, item_id: String) -> Result<()> {
        self.run(move |this| this.ctx().disconnect_masked_email(&item_id))
            .await
    }

    /// Turns an alias on or off at its provider.
    pub async fn set_alias_enabled(
        self: Arc<Self>,
        provider: String,
        alias_id: String,
        email: String,
        enabled: bool,
    ) -> Result<()> {
        self.run(move |this| {
            this.ctx()
                .set_alias_enabled(&provider, &alias_id, &email, enabled)
        })
        .await
    }

    /// Deletes an alias at its provider and unlinks it from these logins, which keep the address.
    pub async fn delete_alias(
        self: Arc<Self>,
        provider: String,
        alias_id: String,
        email: String,
        login_ids: Vec<String>,
    ) -> Result<()> {
        self.run(move |this| {
            this.ctx()
                .delete_alias(&provider, &alias_id, &email, &login_ids)
        })
        .await
    }

    /// A new alias for `site` (a URL or host) from the given connection, or the first one.
    pub async fn create_alias(
        self: Arc<Self>,
        site: String,
        connection_id: Option<String>,
    ) -> Result<MaskedAlias> {
        self.run(move |this| this.ctx().create_alias(&site, connection_id.as_deref()))
            .await
    }

    // ---------- Sharing ----------

    /// The account's own fingerprint, to read out to people sharing with it.
    pub async fn my_fingerprint(self: Arc<Self>) -> Result<Fingerprint> {
        self.run(|this| this.ctx().my_fingerprint()).await
    }

    /// Fails with `accountNotFound` when the email has no account.
    pub async fn lookup_account(self: Arc<Self>, email: String) -> Result<AccountLookup> {
        self.run(move |this| this.ctx().lookup_account(&email))
            .await
    }

    /// Remembers that the user compared this account's fingerprint with its owner.
    pub async fn mark_verified(self: Arc<Self>, account: AccountLookup) -> Result<()> {
        self.run(move |this| {
            this.ctx()
                .mark_verified(&account.account_id, &account.fingerprint)
        })
        .await
    }

    pub async fn create_vault(self: Arc<Self>, name: String) -> Result<Vault> {
        self.run(move |this| this.ctx().create_vault(&name)).await
    }

    pub async fn rename_vault(self: Arc<Self>, vault_id: String, name: String) -> Result<()> {
        self.run(move |this| this.ctx().rename_vault(&vault_id, &name))
            .await
    }

    /// With fingerprints computed on this phone.
    pub async fn list_members(self: Arc<Self>, vault_id: String) -> Result<Vec<VaultMember>> {
        self.run(move |this| this.ctx().list_members(&vault_id))
            .await
    }

    /// Invites `account` (from `lookupAccount`, after the user compared its fingerprint).
    pub async fn add_member(
        self: Arc<Self>,
        vault_id: String,
        account: AccountLookup,
        role: VaultRole,
    ) -> Result<()> {
        self.run(move |this| this.ctx().add_member(&vault_id, &account, role))
            .await
    }

    pub async fn change_role(
        self: Arc<Self>,
        vault_id: String,
        account_id: String,
        role: VaultRole,
    ) -> Result<()> {
        self.run(move |this| this.ctx().change_role(&vault_id, &account_id, role))
            .await
    }

    /// Removes the member, then gives the vault a new key so what they kept stops working.
    pub async fn remove_member(
        self: Arc<Self>,
        vault_id: String,
        account_id: String,
    ) -> Result<()> {
        self.run(move |this| this.ctx().remove_member(&vault_id, &account_id))
            .await
    }

    pub async fn leave_vault(self: Arc<Self>, vault_id: String) -> Result<()> {
        self.run(move |this| this.ctx().leave_vault(&vault_id))
            .await
    }

    pub async fn get_family(self: Arc<Self>) -> Result<FamilyState> {
        self.run(|this| this.ctx().get_family()).await
    }

    /// Creates a family and its shared Family vault, organised by the user.
    pub async fn create_family(self: Arc<Self>) -> Result<()> {
        self.run(|this| this.ctx().create_family()).await
    }

    pub async fn invite_to_family(self: Arc<Self>, account: AccountLookup) -> Result<()> {
        self.run(move |this| this.ctx().invite_to_family(&account))
            .await
    }

    pub async fn accept_family_invite(self: Arc<Self>, family_id: String) -> Result<()> {
        self.run(move |this| this.ctx().accept_family_invite(&family_id))
            .await
    }

    pub async fn decline_family_invite(self: Arc<Self>, family_id: String) -> Result<()> {
        self.run(move |this| this.ctx().decline_family_invite(&family_id))
            .await
    }

    /// Organiser: cancels a pending invite.
    pub async fn cancel_family_invite(self: Arc<Self>, account_id: String) -> Result<()> {
        self.run(move |this| this.ctx().cancel_family_invite(&account_id))
            .await
    }

    /// Organiser: removes a member, then rotates the Family vault key.
    pub async fn remove_family_member(self: Arc<Self>, account_id: String) -> Result<()> {
        self.run(move |this| this.ctx().remove_family_member(&account_id))
            .await
    }

    pub async fn leave_family(self: Arc<Self>) -> Result<()> {
        self.run(|this| this.ctx().leave_family()).await
    }

    /// Organiser: deletes the family and its Family vault for everyone.
    pub async fn delete_family(self: Arc<Self>) -> Result<()> {
        self.run(|this| this.ctx().delete_family()).await
    }

    // ---------- Share links ----------

    /// Encrypts a snapshot of the item for a one-time link. With a passphrase this runs
    /// Argon2id.
    pub async fn create_share_link(
        self: Arc<Self>,
        item_id: String,
        options: ShareLinkOptions,
    ) -> Result<CreatedShareLink> {
        self.run(move |this| this.ctx().create_share_link(&item_id, &options))
            .await
    }

    pub async fn list_share_links(self: Arc<Self>) -> Result<Vec<ShareLinkInfo>> {
        self.run(|this| this.ctx().list_share_links()).await
    }

    pub async fn revoke_share_link(self: Arc<Self>, id: String) -> Result<()> {
        self.run(move |this| this.ctx().revoke_share_link(&id))
            .await
    }

    /// Works signed out. Counts a view; fails with `notFound` once a link is used up, expired or
    /// revoked.
    pub async fn fetch_share_link(
        self: Arc<Self>,
        server_url: String,
        id: String,
    ) -> Result<ShareLinkEnvelope> {
        self.run(move |this| crate::links::fetch_share_link(&this.api, &server_url, &id))
            .await
    }

    /// Decrypts on this phone. Fails with `wrongPassphrase` or `invalidShareLink`.
    pub async fn open_share_link(
        self: Arc<Self>,
        ciphertext: String,
        key: String,
        passphrase: Option<String>,
    ) -> Result<SharedItem> {
        let passphrase = passphrase.map(Zeroizing::new);
        self.run(move |_| {
            crate::links::open_share_link(
                &ciphertext,
                &key,
                passphrase.as_deref().map(String::as_str),
            )
        })
        .await
    }

    // ---------- Emergency access ----------

    pub async fn list_emergency_contacts(self: Arc<Self>) -> Result<EmergencyContacts> {
        self.run(|this| this.ctx().list_emergency_contacts()).await
    }

    pub async fn add_emergency_contact(
        self: Arc<Self>,
        account: AccountLookup,
        wait_days: u32,
        access_level: EmergencyAccessLevel,
        scope: EmergencyScope,
    ) -> Result<EmergencyContact> {
        self.run(move |this| {
            this.ctx()
                .add_emergency_contact(&account, wait_days, access_level, &scope)
        })
        .await
    }

    /// Either side: removes a contact, or steps down as one.
    pub async fn remove_emergency_contact(self: Arc<Self>, id: String) -> Result<()> {
        self.run(move |this| this.ctx().remove_emergency_contact(&id))
            .await
    }

    pub async fn request_emergency_access(self: Arc<Self>, id: String) -> Result<()> {
        self.run(move |this| this.ctx().emergency_action(&id, "request"))
            .await
    }

    pub async fn deny_emergency_access(self: Arc<Self>, id: String) -> Result<()> {
        self.run(move |this| this.ctx().emergency_action(&id, "deny"))
            .await
    }

    pub async fn approve_emergency_access(self: Arc<Self>, id: String) -> Result<()> {
        self.run(move |this| this.ctx().emergency_action(&id, "approve"))
            .await
    }

    /// As the grantor, after a rotation: seals the vault's current key to the contact again.
    /// Pass a lookup whose fingerprint the user compared: this never happens by itself.
    pub async fn renew_emergency_key(
        self: Arc<Self>,
        id: String,
        account: AccountLookup,
    ) -> Result<()> {
        self.run(move |this| this.ctx().renew_emergency_key(&id, &account))
            .await
    }

    /// As the contact of a released takeover record (plan 06): a new master password, Secret Key
    /// and recovery code for the grantor, who is signed out everywhere. `contact_password` is
    /// this account's own. Show the kit before anything else: it's the only copy.
    pub async fn take_over_account(
        self: Arc<Self>,
        id: String,
        contact_password: String,
        new_password: String,
    ) -> Result<NewRecoveryKit> {
        let (contact_password, new_password) = (
            Zeroizing::new(contact_password),
            Zeroizing::new(new_password),
        );
        self.run(move |this| {
            let kit = this
                .vault
                .take_over_account(&id, contact_password, new_password)
                .map_err(|error| not_allowed(error.into()))?;
            this.ctx().sharing_changed();
            Ok(NewRecoveryKit {
                email: kit.email,
                server_url: kit.server_url,
                secret_key: kit.secret_key,
                recovery_code: Some(kit.recovery_code),
                created_at: kit.created_at,
            })
        })
        .await
    }

    /// As a family member: lets the organiser help recover this account (plan 06). Off unless the
    /// member turns it on. `removeEmergencyContact` turns it off.
    pub async fn enable_organiser_recovery(
        self: Arc<Self>,
        account: AccountLookup,
        wait_days: u32,
    ) -> Result<EmergencyContact> {
        self.run(move |this| this.ctx().enable_organiser_recovery(&account, wait_days))
            .await
    }

    /// A new key for a vault this account owns or manages, on demand.
    pub async fn rotate_vault_key(self: Arc<Self>, vault_id: String) -> Result<()> {
        self.run(move |this| this.ctx().rotate_vault_key(&vault_id))
            .await
    }

    /// As the contact, once released: the grantor's vaults in scope, read-only.
    pub async fn open_emergency_access(self: Arc<Self>, id: String) -> Result<EmergencyVaultView> {
        self.run(move |this| this.ctx().open_emergency_access(&id))
            .await
    }

    /// As the contact, once released: one of the grantor's files, decrypted to a path as
    /// `openAttachment` does.
    pub async fn open_emergency_attachment(
        self: Arc<Self>,
        id: String,
        item_id: String,
        attachment_id: String,
    ) -> Result<String> {
        self.run(move |this| {
            Ok(path_text(&this.ctx().open_emergency_attachment(
                &id,
                &item_id,
                &attachment_id,
            )?))
        })
        .await
    }

    // ---------- Devices and the security log ----------

    pub async fn list_devices(self: Arc<Self>) -> Result<Vec<Device>> {
        self.run(|this| {
            let devices: Vec<DeviceRecord> = this.server_call(Method::Get, "v1/devices", None)?;
            Ok(devices
                .into_iter()
                .map(|device| Device {
                    id: device.id,
                    name: device.name,
                    platform: device.platform,
                    created_at: device.created_at,
                    last_seen_at: device.last_seen_at,
                    current: device.current,
                })
                .collect())
        })
        .await
    }

    /// Renames this phone in the device list: 1 to 64 characters.
    pub async fn rename_device(self: Arc<Self>, name: String) -> Result<()> {
        self.run(move |this| {
            let name = name.trim();
            if name.is_empty() || name.chars().count() > 64 {
                return Err(VaultError::new(
                    ErrorCode::InvalidInput,
                    "a device name is 1 to 64 characters",
                ));
            }
            this.server_call::<()>(
                Method::Patch,
                "v1/devices/current",
                Some(&serde_json::json!({ "name": name })),
            )
        })
        .await
    }

    /// Signs another device out. Signing out this phone is `signOut`.
    pub async fn sign_out_device(self: Arc<Self>, device_id: String) -> Result<()> {
        self.run(move |this| {
            this.server_call::<()>(
                Method::Delete,
                &format!("v1/devices/{}", segment(&device_id)),
                None,
            )
        })
        .await
    }

    pub async fn security_log(self: Arc<Self>) -> Result<Vec<SecurityEvent>> {
        self.run(|this| {
            let log: SecurityLogResponse =
                this.server_call(Method::Get, "v1/security-log", None)?;
            Ok(log
                .events
                .into_iter()
                .map(|event| SecurityEvent {
                    event_type: event.event_type.as_str().into(),
                    created_at: event.created_at,
                    other_account_email: event.other_account_email,
                    emergency_contact_id: event.emergency_contact_id,
                    device_name: event.device_name,
                    device_platform: event.device_platform,
                    export_format: event.export_format.map(Into::into),
                    export_attachments: event.export_attachments,
                })
                .collect())
        })
        .await
    }

    // ---------- Import and export ----------

    /// Writes an export to the app's private storage and returns its path, for the share sheet.
    /// Delete it with `closeAttachment` once shared; locking deletes it anyway. With
    /// `master_password` the password is checked first (plan 07); `password` encrypts the
    /// `encrypted` format.
    pub async fn export_vault(
        self: Arc<Self>,
        format: ExportFormat,
        password: Option<String>,
        master_password: Option<String>,
    ) -> Result<String> {
        let (password, master) = (
            password.map(Zeroizing::new),
            master_password.map(Zeroizing::new),
        );
        self.run(move |this| {
            if let Some(master) = master {
                this.vault.confirm_user(Some(master))?;
            }
            let vaults = this.vaults()?;
            let mut items = this.visible_items()?;
            // Importing the dashboard's settings would turn email breach alerts on for another
            // account.
            items.retain(|item| {
                item.deleted_at.is_none()
                    && !octapass_mobile_vault::health::is_health_settings(item)
            });
            items.sort_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| a.id.cmp(&b.id))
            });
            let exported_at = now_text();
            let document = transfer::document(&vaults, &items, &exported_at);
            let bytes = match format {
                ExportFormat::Json => Zeroizing::new(document.to_json().into_bytes()),
                ExportFormat::Csv => Zeroizing::new(transfer::csv(&vaults, &items).into_bytes()),
                ExportFormat::Cxf => {
                    let access = this.vault.access()?;
                    Zeroizing::new(transfer::cxf(
                        &document,
                        access.email(),
                        &access.server_url(),
                    ))
                }
                ExportFormat::Encrypted => transfer::encrypted(
                    &document,
                    &items,
                    password.as_deref().map(String::as_str).unwrap_or_default(),
                    octapass_core::export::EXPORT_KDF,
                    |item_id, attachment_id| {
                        Ok(Zeroizing::new(
                            this.vault.get_attachment(item_id, attachment_id)?,
                        ))
                    },
                )?,
            };
            let name = transfer::export_file_name(format, &exported_at[..10]);
            let path = this.vault.new_opened_path(&name)?;
            std::fs::write(&path, &*bytes)
                .map_err(|error| VaultError::unexpected(format!("files: {error}")))?;
            // "Vault exported" in the security log, with only the format. Exporting works
            // offline too; the entry is then missing.
            let _ = this.vault.record_export(format.into());
            Ok(path_text(&path))
        })
        .await
    }

    /// Imports the file at `path` (where the app's picker copied it) into the personal vault:
    /// items, one-time codes for logins already there, and an encrypted export's files. Works
    /// offline. `key_file_path` is a KeePass key file.
    /// Keeps the CXF another app handed over (the app gets it from the system), unsaved, and
    /// says what it holds. `importReceived` saves it, `discardReceived` forgets it; locking
    /// forgets it too.
    pub async fn preview_received(
        self: Arc<Self>,
        json: String,
        from: String,
    ) -> Result<ReceivedPreview> {
        let json = Zeroizing::new(json);
        self.run(move |this| {
            let preview = this.vault.preview_received(ReceivedCredentials {
                json: json.clone(),
                from: from.clone(),
            })?;
            Ok(preview.into())
        })
        .await
    }

    /// Saves what `previewReceived` kept into the Personal vault. Fails with `notFound` when
    /// there's nothing.
    pub async fn import_received(self: Arc<Self>) -> Result<ImportSummary> {
        self.run(|this| {
            let summary = this.vault.import_received()?;
            this.refresh_pending();
            Ok(summary.into())
        })
        .await
    }

    pub fn discard_received(&self) {
        self.vault.discard_received();
    }

    /// Reads a file for the import review (authenticator imports), where the user links each
    /// one-time code to a login. Nothing is saved until `finishImport`; the file's contents stay
    /// in the vault until then, `cancelImport`, or the vault locks. Imports into the personal
    /// vault.
    pub async fn review_import(
        self: Arc<Self>,
        source: ImportSource,
        path: String,
        password: Option<String>,
        key_file_path: Option<String>,
    ) -> Result<ImportReview> {
        let password = password.map(Zeroizing::new);
        self.run(move |this| {
            let read = |path: &str| {
                std::fs::read(path)
                    .map(Zeroizing::new)
                    .map_err(|error| VaultError::unexpected(format!("files: {error}")))
            };
            let file = read(&path)?;
            let key_file = key_file_path.as_deref().map(read).transpose()?;
            let options = transfer::import_options(
                password.as_deref().cloned(),
                key_file.map(|key| key.to_vec()),
            );
            let personal = this.personal_vault_id()?;
            Ok(this
                .vault
                .review_import(source.core(), &file, options, &personal)?
                .into())
        })
        .await
    }

    /// The import review for one-time codes scanned from QR codes (`otpauth://` links and
    /// Google Authenticator exports, as `summarizeQrScans` found them).
    pub async fn review_scanned_codes(self: Arc<Self>, links: Vec<String>) -> Result<ImportReview> {
        let text = Zeroizing::new(links.join("\n"));
        self.run(move |this| {
            let personal = this.personal_vault_id()?;
            Ok(this
                .vault
                .review_import(
                    ImportSource::Otpauth.core(),
                    text.as_bytes(),
                    transfer::import_options(None, None),
                    &personal,
                )?
                .into())
        })
        .await
    }

    /// Saves a reviewed import with the user's choices; codes without a choice stay as the
    /// review showed them. `importReviewExpired` when it was finished, cancelled or forgotten.
    pub async fn finish_import(
        self: Arc<Self>,
        review_id: String,
        links: Vec<CodeLink>,
    ) -> Result<ImportSummary> {
        self.run(move |this| {
            let links: Vec<octapass_core::import::CodeLink> =
                links.into_iter().map(Into::into).collect();
            let summary = this.vault.finish_import(&review_id, &links)?;
            this.refresh_pending();
            Ok(summary.into())
        })
        .await
    }

    /// Drops a review without saving anything.
    pub fn cancel_import(&self, review_id: String) {
        self.vault.cancel_import(&review_id);
    }

    pub async fn import_file(
        self: Arc<Self>,
        source: ImportSource,
        path: String,
        password: Option<String>,
        key_file_path: Option<String>,
    ) -> Result<ImportSummary> {
        let password = password.map(Zeroizing::new);
        self.run(move |this| {
            let read = |path: &str| {
                std::fs::read(path)
                    .map(Zeroizing::new)
                    .map_err(|error| VaultError::unexpected(format!("files: {error}")))
            };
            let file = read(&path)?;
            let key_file = key_file_path.as_deref().map(read).transpose()?;
            let options = transfer::import_options(
                password.as_deref().cloned(),
                key_file.map(|key| key.to_vec()),
            );
            let personal = this.personal_vault_id()?;
            let summary = this
                .vault
                .import_file(source.core(), &file, options, &personal)?;
            this.refresh_pending();
            Ok(summary.into())
        })
        .await
    }

    // ---------- Settings and the app's lifecycle ----------

    pub fn settings(&self) -> Settings {
        self.settings_guard().clone()
    }

    /// Saved on this phone. `autoLockMinutes` is one of 1, 5, 15, 30, 60, 240 or 0. Turning
    /// website icons off forgets the ones kept on this phone.
    pub fn update_settings(&self, settings: Settings) -> Result<()> {
        if !AUTO_LOCK_CHOICES.contains(&settings.auto_lock_minutes) {
            return Err(VaultError::new(
                ErrorCode::InvalidInput,
                "unsupported auto-lock time",
            ));
        }
        local::save_settings(Path::new(&self.config.data_dir), &settings)?;
        let stay_unlocked = settings.stay_unlocked;
        let stay_unlocked_changed = self.settings_guard().stay_unlocked != stay_unlocked;
        if !settings.show_site_icons {
            self.icons.clear();
        }
        *self.settings_guard() = settings;
        if stay_unlocked_changed {
            self.stay_unlocked_changed(stay_unlocked)?;
        }
        Ok(())
    }

    /// What to hand a paired watch, as an opaque string: a bundle of one-time codes while the
    /// vault is unlocked and `showCodesOnWatch` is on, otherwise a clear. The app passes it on
    /// unread after any change of session, items or that setting, and whenever the watch asks.
    /// Nothing here fails: anything going wrong is a clear.
    pub async fn watch_payload(self: Arc<Self>, at_ms: Option<u64>) -> String {
        let now_ms = at_ms.unwrap_or_else(now_ms);
        self.run(move |this| this.watch_json(now_ms))
            .await
            .unwrap_or_else(|_| watch::clear_json(now_ms))
    }

    /// The remembered sort and grouping for a list (`view`: `all`, `favorites`, `passkeys`,
    /// `codes`, `vault`, or a type's name), or its default, limited to the groupings
    /// `listGroupings` offers.
    pub fn list_arrangement(&self, view: String, vault_count: u32) -> ListArrangement {
        let settings = self.settings_guard();
        resolve_arrangement(settings.list_arrangements.get(&view), &view, vault_count)
    }

    /// Remembers a list's sort and grouping on this phone.
    pub fn set_list_arrangement(&self, view: String, arrangement: ListArrangement) -> Result<()> {
        let mut settings = self.settings();
        settings.list_arrangements.insert(view, arrangement);
        self.update_settings(settings)
    }

    /// The website icon for `domain` (an `iconDomain`) from the signed-in server, as a PNG of
    /// at most 128 px, or none: the site has none, the server doesn't fetch icons, icons are
    /// off, or try again later. Kept on this phone for a week (misses a day).
    pub async fn site_icon(self: Arc<Self>, domain: String) -> Result<Option<Vec<u8>>> {
        self.run(move |this| {
            if !this.settings_guard().show_site_icons {
                return Ok(None);
            }
            let Some(server) = this.snapshot().server_url else {
                return Ok(None);
            };
            // A local vault has no server: the default one answers, while icons stay on (plan 03).
            let server = match server.starts_with(octapass_ffi::LOCAL_SERVER_PREFIX) {
                true => this.config.default_server_url.clone(),
                false => server,
            };
            Ok(this.icons.load(&server, &domain))
        })
        .await
    }

    /// The user did something: the auto-lock time starts again. Cheap; call it on touches.
    pub fn record_activity(&self) {
        self.touch();
    }

    /// The app went to the background: locks at once when the settings say so.
    pub fn app_did_enter_background(&self) {
        if self.settings_guard().lock_on_background && !self.stays_unlocked() {
            self.vault.lock();
        } else {
            self.vault.auto_backup();
        }
    }

    /// The app is back: locks if it was away longer than the auto-lock time, else syncs (to
    /// upload what an autofill extension saved meanwhile).
    pub fn app_will_enter_foreground(self: Arc<Self>) {
        self.check_auto_lock();
        if self.is_unlocked() {
            self.sync_soon();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_time_comes_from_the_uuidv7() {
        assert_eq!(
            created_at("0190a6c4-7d00-7000-8000-000000000001").as_deref(),
            Some("2024-07-12T11:46:53.312Z")
        );
        assert_eq!(created_at("0190a6c4-7d00-4000-8000-000000000001"), None);
    }

    #[test]
    fn the_kit_qr_code_names_the_account_but_not_the_recovery_code() {
        let uri = recovery_kit_setup_uri(RecoveryKit {
            email: "ada+1@example.com".into(),
            server_url: "https://vault.example.com".into(),
            secret_key: "OP1-AAAAAA".into(),
            recovery_code: "never".into(),
            created_at: String::new(),
        });
        assert_eq!(
            uri,
            "octapass://setup?email=ada%2B1%40example.com&server=https%3A%2F%2Fvault.example.com&secretKey=OP1-AAAAAA"
        );
    }
}
