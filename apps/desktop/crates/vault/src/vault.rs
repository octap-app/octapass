//! The vault behind the desktop app's commands. It mirrors `VaultService` from
//! `packages/vault-client`, but the keys never leave this process: the UI receives decrypted
//! fields to render, and nothing else.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use octapass_api::problem::types;
use octapass_api::{
    DeleteAccountRequest, DeviceInfo, ItemRecord, LoginFinishRequest, LoginFinishResponse,
    LoginStartRequest, NewPersonalVault, PutItemRequest, ReauthFinishRequest, ReauthPurpose,
    ReauthStartRequest, RegisterFinishRequest, RegisterStartRequest, SecondFactorChallenge,
    SecondFactorRequest, ServerInfo, SsoChallenge, SsoLoginRequest, TotpConfirmRequest,
    TotpConfirmResponse, VaultRecord, VaultRole, VaultType,
};
use octapass_core::account::{AccountBundle, NewAccount, new_id};
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::kdf::{AccountKeys, KdfParams, normalize_email};
use octapass_core::opaque::{LoginClient, ReauthClient, RegistrationClient};
use octapass_core::secret_key::SecretKey;
use octapass_core::session::{EncryptedItem, Session};
use octapass_core::sharing::Role;
use octapass_core::sharing::vault::{GrantSignature, SyncedVault};
use octapass_device_unlock::DeviceUnlock;
use rand_core::OsRng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::api::{Api, ApiError, ApiResult, Method, Precondition};
use crate::cache::VaultCache;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{
    AccountSummary, DevicePlatform, Item, ItemDraft, ItemSummary, RecoveryKit, RememberedAccount,
    SessionState, SessionStatus, SignInResult, SignupStarted, TotpSetup, TwoStepMethod,
    TwoStepProof, TwoStepStatus, UnlockMethods, Vault as VaultView, now, parse_rfc3339, require,
    rfc3339, unix_ms, vault_names,
};
use crate::store::{AccountKey, DeviceState, Store, StoredAccount, WrappedAsk};

mod attachments;
mod emergency;
mod gates;
mod health_data;
mod key_log;
mod local;
mod master_password;
mod organisations;
mod places;
pub mod safes;
pub(crate) mod service_accounts;
mod share_links;
mod sharing;
mod stay_unlocked;
mod transfer;
mod versions;

pub use emergency::EmergencyVaultView;
pub use key_log::{KeyCheck, KeyLogAlertView, KeyLogView};
pub use service_accounts::{CreatedServiceAccount, ServiceAccount};
pub use share_links::{CreatedShareLink, ShareLinkInfo, ShareLinkOptions, SharedItem};
pub use sharing::{AccountLookup, Family, FamilyMember, FamilyState, Fingerprint, VaultMember};
pub use transfer::{FileExport, ImportReview, ImportSummary, ReviewCode, document};

pub use attachments::StorageUsage;
pub use local::{LocalCapabilities, LocalVaultInfo, RestoreSecret};
pub use organisations::{
    ConfirmedGrant, OrgAccessGrant, OrgAccessReview, OrgMember, OrgMembers, OrgVault,
};
pub use health_data::HealthDataLists;
pub use stay_unlocked::StayUnlockedStatus;
pub use versions::{EquivalentDomains, EquivalentDomainsInput, ItemVersion};

/// Device unlock asks for the master password again after this long (plan 03).
pub const PASSWORD_RECHECK: Duration = Duration::from_secs(14 * 86_400);
const SIGNUP_TTL: Duration = Duration::from_secs(15 * 60);
const CONFLICT_SUFFIX: &str = " (conflicting copy)";

pub struct Config {
    pub data_dir: std::path::PathBuf,
    /// How this device appears in the account's device list.
    pub device: DeviceInfo,
    pub pwned_passwords_url: String,
}

/// What the UI hears about without asking.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Event {
    Session(SessionSnapshot),
    ItemsChanged,
    /// Members, families, invitations, share links or emergency contacts changed, here or (as a
    /// sync found) elsewhere.
    SharingChanged,
    /// A background sync failed; the vault keeps working from its local copy.
    SyncFailed {
        message: String,
    },
    /// An automatic backup couldn't be written; the vault is safe here either way.
    BackupFailed {
        message: String,
    },
}

/// The session plus the accounts this device remembers, which the UI reads synchronously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSnapshot {
    pub session: SessionState,
    pub remembered_accounts: Vec<RememberedAccount>,
}

pub type Listener = Box<dyn Fn(Event) + Send + Sync>;

/// Guards against a server that never stops saying `hasMore`.
const MAX_SYNC_PAGES: usize = 1000;

pub struct Vault {
    pub(crate) config: Config,
    pub(crate) http: reqwest::Client,
    store: Store,
    pub(crate) device_unlock: Arc<dyn DeviceUnlock>,
    listener: Listener,
    state: Mutex<State>,
    /// Serialises everything that talks to the server with a token, so a rotating refresh token
    /// is never presented twice (the server would revoke the session).
    io: tokio::sync::Mutex<()>,
}

struct State {
    device: DeviceState,
    unlocked: Option<Unlocked>,
    /// Bumped on every lock, unlock and sign-out, so work started for one session can't land in
    /// the next one.
    generation: u64,
    signups: HashMap<String, PendingSignup>,
    access_tokens: HashMap<AccountKey, String>,
    /// A sign-in waiting for its second step.
    two_step: Option<PendingTwoStep>,
    /// A sign-in waiting for the identity provider.
    sso: Option<PendingTwoStep>,
    /// An authenticator being added, waiting for its first code: the account and the setup id.
    totp_setup: Option<(AccountKey, String)>,
    /// Master password resets in progress, by reset id. They don't survive a restart.
    resets: HashMap<String, master_password::PendingReset>,
    /// Local vaults turning on sync, by signup id.
    upgrades: HashMap<String, local::PendingUpgrade>,
    /// When the device lock last opened the vault.
    device_unlocked_at: Option<Instant>,
    /// "Lock now": stay unlocked (plan 18) doesn't open the vault by itself until the user
    /// unlocks it. In memory only, so a restarted app opens unlocked.
    held: bool,
}

pub(crate) struct Unlocked {
    pub(crate) key: AccountKey,
    pub(crate) session: Session,
    pub(crate) cache: VaultCache,
    /// Decrypted list rows, by item id, with the revision they were made from.
    summaries: HashMap<String, (u64, ItemSummary)>,
    /// Imports waiting for their review, by review id. Locking forgets them.
    pub(crate) imports: HashMap<String, transfer::PendingImport>,
    /// Vault id → the wrapped key and role its open key came from. A rotation or a new role
    /// changes them, and the vault opens again.
    opened: HashMap<String, (String, VaultRole)>,
    /// Shared and family vaults whose grant didn't verify: their keys aren't used.
    untrusted: HashSet<String>,
    /// A vault on this computer only: `cache` mirrors it, and changes land here.
    pub(crate) local: Option<local::OpenLocal>,
    /// `SessionState::confirmed`: the user's own unlock, or a device-lock answer since.
    pub(crate) confirmed: bool,
}

impl Unlocked {
    fn new(key: AccountKey, session: Session, cache: VaultCache) -> Self {
        let mut unlocked = Self {
            key,
            session,
            cache,
            summaries: HashMap::new(),
            imports: HashMap::new(),
            opened: HashMap::new(),
            untrusted: HashSet::new(),
            local: None,
            confirmed: true,
        };
        unlocked.open_vaults();
        unlocked
    }

    /// Opens the cache's vaults that are new or changed (the core checks shared vaults' grants),
    /// and closes the ones the account lost.
    fn open_vaults(&mut self) {
        let cache = &self.cache;
        let gone: Vec<String> = self
            .opened
            .keys()
            .filter(|id| cache.vault(id).is_none())
            .cloned()
            .collect();
        for id in gone {
            self.session.close_vault(&id);
            self.opened.remove(&id);
        }
        self.untrusted.retain(|id| cache.vault(id).is_some());
        for vault in &cache.vaults {
            let current = (vault.wrapped_vault_key.clone(), vault.role);
            if self.opened.get(&vault.id) == Some(&current) {
                continue;
            }
            let opened = self.session.open_synced_vault(&synced_vault(vault));
            if opened.is_ok() || vault.vault_type == VaultType::Personal {
                self.untrusted.remove(&vault.id);
            } else {
                self.untrusted.insert(vault.id.clone());
            }
            self.opened.insert(vault.id.clone(), current);
            // Rows from the old key may no longer be readable.
            self.summaries
                .retain(|_, (_, row)| row.vault_id != vault.id);
        }
    }

    /// Tries again the vaults that didn't open, now that the session holds more keys.
    fn retry_untrusted(&mut self) {
        for id in &self.untrusted {
            self.opened.remove(id);
        }
        self.open_vaults();
    }

    /// A vault this account can write to: not read-only, and not one whose grant didn't verify.
    pub(crate) fn writable(&self, vault_id: &str) -> Result<&VaultRecord> {
        let vault = self.cache.vault(vault_id).ok_or(ErrorCode::NotFound)?;
        require(
            !self.untrusted.contains(vault_id),
            ErrorCode::UntrustedVault,
        )?;
        require(vault.role != VaultRole::Read, ErrorCode::ReadOnlyVault)?;
        Ok(vault)
    }
}

/// What finishing a sign-in after its second step needs: the keys stay in this process until then.
struct PendingTwoStep {
    key: AccountKey,
    secret_key: SecretKey,
    keys: AccountKeys,
    challenge_id: String,
    expires_at: Instant,
}

/// How an OPAQUE login ended, when the password was right.
#[allow(
    clippy::large_enum_variant,
    reason = "lives for one call; the account bundle grew with its key record"
)]
enum Login {
    Finished(LoginFinishResponse),
    /// The account asks this device for a second step.
    SecondStep(SecondFactorChallenge),
    /// The account's organisation requires single sign-on, before any second step.
    Sso(SsoChallenge),
}

struct PendingSignup {
    server_url: String,
    account: NewAccount,
    registration_upload: String,
    expires_at: Instant,
}

impl Vault {
    pub fn new(
        config: Config,
        device_unlock: Arc<dyn DeviceUnlock>,
        listener: Listener,
    ) -> Result<Arc<Self>> {
        let store = Store::new(&config.data_dir);
        let device = store.load_state()?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("OctaPass-Desktop/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| VaultError::unexpected(error.to_string()))?;
        Ok(Arc::new(Self {
            config,
            http,
            store,
            device_unlock,
            listener,
            state: Mutex::new(State {
                device,
                unlocked: None,
                generation: 0,
                signups: HashMap::new(),
                access_tokens: HashMap::new(),
                two_step: None,
                sso: None,
                totp_setup: None,
                resets: HashMap::new(),
                upgrades: HashMap::new(),
                device_unlocked_at: None,
                held: false,
            }),
            io: tokio::sync::Mutex::new(()),
        }))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn api(&self, server_url: &str) -> Api {
        Api::new(self.http.clone(), server_url)
    }

    // ---------- Session ----------

    pub fn snapshot(&self) -> SessionSnapshot {
        let state = self.state();
        let named = |status, key: &AccountKey| {
            let mut session = session_state(status, key);
            // A local vault has a name where an account has its email.
            if let Some(local) = state.device.local(key) {
                session.email = Some(local.name.clone());
            }
            session
        };
        let session = match (&state.unlocked, &state.device.current) {
            (Some(unlocked), _) => SessionState {
                confirmed: unlocked.confirmed,
                ..named(SessionStatus::Unlocked, &unlocked.key)
            },
            (None, Some(current)) => named(SessionStatus::Locked, current),
            (None, None) => SessionState {
                status: SessionStatus::SignedOut,
                email: None,
                server_url: None,
                confirmed: false,
            },
        };
        SessionSnapshot {
            session,
            remembered_accounts: state
                .device
                .accounts
                .iter()
                .map(|account| RememberedAccount {
                    email: account.key.email.clone(),
                    server_url: account.key.server_url.clone(),
                })
                .collect(),
        }
    }

    fn emit_session(&self) {
        (self.listener)(Event::Session(self.snapshot()));
    }

    fn emit(&self, event: Event) {
        (self.listener)(event);
    }

    pub(crate) fn with_unlocked<T>(
        &self,
        run: impl FnOnce(&mut Unlocked) -> Result<T>,
    ) -> Result<T> {
        let mut state = self.state();
        let unlocked = state.unlocked.as_mut().ok_or(ErrorCode::Locked)?;
        run(unlocked)
    }

    /// Bumped by signing in, locking and signing out.
    pub(crate) fn state_generation(&self) -> u64 {
        self.state().generation
    }

    pub(crate) fn current_account(&self) -> Result<StoredAccount> {
        let state = self.state();
        let current = state.device.current.as_ref().ok_or(ErrorCode::Locked)?;
        state
            .device
            .account(current)
            .cloned()
            .ok_or_else(|| ErrorCode::Locked.into())
    }

    fn save_device(&self, state: &State) -> Result<()> {
        self.store.save_state(&state.device)
    }

    /// Opens the session: loads the local copy of the vaults and makes it current.
    pub(crate) fn install(&self, key: AccountKey, session: Session) -> Result<()> {
        self.install_as(key, session, true)
    }

    /// `confirmed`: the user opened it (false only for stay unlocked).
    pub(crate) fn install_as(
        &self,
        key: AccountKey,
        session: Session,
        confirmed: bool,
    ) -> Result<()> {
        let cache = self.store.load_cache(&key)?;
        let mut unlocked = Unlocked::new(key.clone(), session, cache);
        unlocked.confirmed = confirmed;
        let mut state = self.state();
        state.held = false;
        state.generation += 1;
        state.device.current = Some(key);
        state.unlocked = Some(unlocked);
        self.save_device(&state)?;
        drop(state);
        // Before the session event, so whoever hears it sees the key (plan 18).
        self.enroll_stay_unlocked();
        self.emit_session();
        self.emit(Event::ItemsChanged);
        Ok(())
    }

    // ---------- Server + account ----------

    pub async fn server_info(&self, server_url: &str) -> Result<ServerInfo> {
        let server_url = normalize_server_url(server_url)?;
        Ok(self.api(&server_url).server_info().await?)
    }

    pub async fn start_signup(
        &self,
        server_url: &str,
        email: &str,
        password: Zeroizing<String>,
    ) -> Result<SignupStarted> {
        let server_url = normalize_server_url(server_url)?;
        let email = valid_email(email)?;
        let account = blocking(move || {
            NewAccount::create(
                &email,
                &password,
                KdfParams::DEFAULT,
                unix_ms(now()),
                &mut OsRng,
            )
            .map_err(VaultError::from)
        })
        .await?;
        let (registration, registration_request) =
            RegistrationClient::start(&account.keys.auth_secret, &mut OsRng)?;
        let api = self.api(&server_url);
        let started = api
            .register_start(&RegisterStartRequest {
                email: account.bundle.email.clone(),
                registration_request,
            })
            .await?;
        let registration_upload = registration.finish(
            &account.keys.auth_secret,
            &started.registration_response,
            &mut OsRng,
        )?;
        let signup_id = new_id(unix_ms(now()), &mut OsRng);
        let mut state = self.state();
        state
            .signups
            .retain(|_, pending| pending.expires_at > Instant::now());
        state.signups.insert(
            signup_id.clone(),
            PendingSignup {
                server_url,
                account,
                registration_upload,
                expires_at: Instant::now() + SIGNUP_TTL,
            },
        );
        Ok(SignupStarted {
            signup_id,
            dev_verification_code: started.dev_verification_code,
        })
    }

    pub async fn finish_signup(
        self: &Arc<Self>,
        signup_id: &str,
        verification_code: &str,
    ) -> Result<RecoveryKit> {
        let pending = self
            .state()
            .signups
            .remove(signup_id)
            .filter(|pending| pending.expires_at > Instant::now())
            .ok_or(ErrorCode::SignupExpired)?;
        let api = self.api(&pending.server_url);
        let account = &pending.account;
        let request = RegisterFinishRequest {
            email: account.bundle.email.clone(),
            verification_code: verification_code.split_whitespace().collect(),
            registration_upload: pending.registration_upload.clone(),
            account: convert(&account.bundle)?,
            personal_vault: NewPersonalVault {
                id: account.personal_vault.id.clone(),
                wrapped_vault_key: account.personal_vault.wrapped_vault_key.clone(),
            },
        };
        if let Err(error) = api.register_finish(&request).await {
            if error.is(octapass_api::problem::types::INVALID_VERIFICATION_CODE) {
                // Let the user try the code again.
                self.state().signups.insert(signup_id.to_owned(), pending);
            }
            return Err(error.into());
        }

        let _io = self.io.lock().await;
        // A new account has no second step yet.
        let Login::Finished(login) = self
            .login(&api, &account.bundle.email, &account.keys, None)
            .await?
        else {
            return Err(VaultError::unexpected(
                "a new account asked for a second step",
            ));
        };
        let bundle: AccountBundle = convert(&login.account)?;
        let session = Session::unlock(bundle.clone(), &account.keys.auk)?;
        let key = AccountKey {
            server_url: pending.server_url.clone(),
            email: bundle.email.clone(),
        };
        let created_at = rfc3339(now());
        self.remember(
            StoredAccount {
                key: key.clone(),
                secret_key: account.secret_key.to_text().to_string(),
                bundle,
                refresh_token: Some(login.refresh_token),
                trusted_device_token: login.trusted_device_token,
                last_password_unlock_at: created_at.clone(),
                device_unlock: None,
            },
            login.access_token,
        )?;
        self.install(key.clone(), session)?;
        self.report(self.sync_locked().await);
        Ok(RecoveryKit {
            email: key.email,
            server_url: key.server_url,
            secret_key: account.secret_key.to_text().to_string(),
            recovery_code: account.recovery_code.to_text().to_string(),
            created_at,
        })
    }

    /// Signs in. When the account asks this device for a second step, the sign-in waits for
    /// `finish_two_step` instead.
    pub async fn sign_in(
        self: &Arc<Self>,
        server_url: &str,
        email: &str,
        password: Zeroizing<String>,
        secret_key: Option<Zeroizing<String>>,
    ) -> Result<SignInResult> {
        let key = AccountKey {
            server_url: normalize_server_url(server_url)?,
            email: normalize_email(email),
        };
        let remembered = {
            let mut state = self.state();
            state.two_step = None;
            state.sso = None;
            state.device.account(&key).cloned()
        };
        let secret_key = match (
            &remembered,
            secret_key.filter(|text| !text.trim().is_empty()),
        ) {
            // One the user typed wins: this device's copy is out of date after a rotation.
            (_, Some(text)) => SecretKey::parse(&text)?,
            (Some(account), None) => SecretKey::parse(&account.secret_key)?,
            (None, None) => return Err(ErrorCode::SecretKeyRequired.into()),
        };
        let api = self.api(&key.server_url);
        let prelogin = api.prelogin(&key.email).await?;
        let kdf: KdfParams = convert(&prelogin.kdf)?;
        let salt = b64_decode(&prelogin.account_salt)?;
        let keys = derive(password, secret_key.clone(), key.email.clone(), salt, kdf).await?;

        let _io = self.io.lock().await;
        let trusted = remembered.and_then(|account| account.trusted_device_token);
        match self.login(&api, &key.email, &keys, trusted).await? {
            Login::Finished(login) => {
                self.finish_sign_in(key, &secret_key, &keys, login).await?;
                Ok(SignInResult::SignedIn)
            }
            Login::SecondStep(challenge) => {
                Ok(self.wait_for_second_step(key, secret_key, keys, challenge))
            }
            Login::Sso(challenge) => {
                self.state().sso = Some(PendingTwoStep {
                    key,
                    secret_key,
                    keys,
                    challenge_id: challenge.challenge_id,
                    expires_at: Instant::now() + Duration::from_secs(challenge.expires_in),
                });
                Ok(SignInResult::SsoRequired {
                    url: challenge.url,
                    org_name: challenge.org_name,
                })
            }
        }
    }

    fn wait_for_second_step(
        &self,
        key: AccountKey,
        secret_key: SecretKey,
        keys: AccountKeys,
        challenge: SecondFactorChallenge,
    ) -> SignInResult {
        self.state().two_step = Some(PendingTwoStep {
            key,
            secret_key,
            keys,
            challenge_id: challenge.challenge_id,
            expires_at: Instant::now() + Duration::from_secs(challenge.expires_in),
        });
        SignInResult::TwoStepRequired {
            methods: TwoStepMethod::offered(&challenge.methods),
        }
    }

    /// Finishes the SSO step with the code the browser showed. A wrong code can be tried again,
    /// `ssoPending` means the browser hasn't finished yet, and `twoStepExpired` means starting
    /// over with `sign_in`. Two-step sign-in, if the account has it, comes after.
    pub async fn finish_sso(self: &Arc<Self>, code: &str) -> Result<SignInResult> {
        let pending = self
            .state()
            .sso
            .take()
            .filter(|pending| pending.expires_at > Instant::now())
            .ok_or(ErrorCode::TwoStepExpired)?;
        let request = SsoLoginRequest {
            challenge_id: pending.challenge_id.clone(),
            code: code.split_whitespace().collect(),
        };
        let _io = self.io.lock().await;
        match self.api(&pending.key.server_url).login_sso(&request).await {
            Ok(login) => {
                self.finish_sign_in(
                    pending.key.clone(),
                    &pending.secret_key,
                    &pending.keys,
                    login,
                )
                .await?;
                Ok(SignInResult::SignedIn)
            }
            Err(error) => {
                if let Some(challenge) = error.second_factor() {
                    let challenge = challenge.clone();
                    let PendingTwoStep {
                        key,
                        secret_key,
                        keys,
                        ..
                    } = pending;
                    return Ok(self.wait_for_second_step(key, secret_key, keys, challenge));
                }
                // The server keeps the sign-in after a wrong code (a few times), while the
                // browser hasn't finished, and after a request that never reached it.
                if error.is(types::INVALID_SECOND_FACTOR)
                    || error.is(types::SSO_PENDING)
                    || matches!(error, ApiError::Network(_))
                {
                    self.state().sso.get_or_insert(pending);
                }
                Err(if error.is(types::LOGIN_FAILED) {
                    VaultError::new(ErrorCode::TwoStepExpired, error.to_string())
                } else {
                    error.into()
                })
            }
        }
    }

    /// Finishes a sign-in that asked for a second step. A wrong code can be tried again;
    /// `twoStepExpired` means starting over with `sign_in`.
    pub async fn finish_two_step(self: &Arc<Self>, proof: TwoStepProof) -> Result<()> {
        let (totp_code, recovery_code) = match proof {
            TwoStepProof::Totp { code } => (Some(code.trim().to_owned()), None),
            TwoStepProof::RecoveryCode { code } => (None, Some(code.trim().to_owned())),
            TwoStepProof::SecurityKey => return Err(ErrorCode::SecurityKeyUnsupported.into()),
        };
        let pending = self
            .state()
            .two_step
            .take()
            .filter(|pending| pending.expires_at > Instant::now())
            .ok_or(ErrorCode::TwoStepExpired)?;
        let request = SecondFactorRequest {
            challenge_id: pending.challenge_id.clone(),
            totp_code,
            recovery_code,
            webauthn: None,
        };
        let _io = self.io.lock().await;
        let login = match self
            .api(&pending.key.server_url)
            .login_second_factor(&request)
            .await
        {
            Ok(login) => login,
            Err(error) => {
                // The server keeps the challenge after a wrong code (a few times), and after
                // a request that never reached it.
                if error.is(types::INVALID_SECOND_FACTOR) || matches!(error, ApiError::Network(_)) {
                    self.state().two_step.get_or_insert(pending);
                }
                return Err(if error.is(types::LOGIN_FAILED) {
                    VaultError::new(ErrorCode::TwoStepExpired, error.to_string())
                } else {
                    error.into()
                });
            }
        };
        self.finish_sign_in(
            pending.key.clone(),
            &pending.secret_key,
            &pending.keys,
            login,
        )
        .await
    }

    /// Keeps the new session and its tokens, opens the vault and syncs. The caller holds `io`.
    async fn finish_sign_in(
        &self,
        key: AccountKey,
        secret_key: &SecretKey,
        keys: &AccountKeys,
        login: LoginFinishResponse,
    ) -> Result<()> {
        let bundle: AccountBundle = convert(&login.account)?;
        let session = Session::unlock(bundle.clone(), &keys.auk)?;
        let remembered = self.state().device.account(&key).cloned();
        self.lock();
        self.remember(
            StoredAccount {
                key: key.clone(),
                secret_key: secret_key.to_text().to_string(),
                bundle,
                refresh_token: Some(login.refresh_token),
                trusted_device_token: login.trusted_device_token.or_else(|| {
                    remembered
                        .as_ref()
                        .and_then(|account| account.trusted_device_token.clone())
                }),
                last_password_unlock_at: rfc3339(now()),
                device_unlock: remembered.and_then(|account| account.device_unlock),
            },
            login.access_token,
        )?;
        self.install(key, session)?;
        self.report(self.sync_locked().await);
        Ok(())
    }

    fn remember(&self, account: StoredAccount, access_token: String) -> Result<()> {
        let mut state = self.state();
        state
            .access_tokens
            .insert(account.key.clone(), access_token);
        state.device.upsert(account);
        self.save_device(&state)
    }

    /// An OPAQUE login. A wrong password or Secret Key fails here with `invalidCredentials`,
    /// whichever side noticed. A valid `trusted_device_token` skips the second step.
    async fn login(
        &self,
        api: &Api,
        email: &str,
        keys: &AccountKeys,
        trusted_device_token: Option<String>,
    ) -> Result<Login> {
        let (client, credential_request) = LoginClient::start(&keys.auth_secret, &mut OsRng)?;
        let started = api
            .login_start(&LoginStartRequest {
                email: email.into(),
                credential_request,
            })
            .await?;
        let credential_finalization =
            client.finish(&keys.auth_secret, &started.credential_response, &mut OsRng)?;
        let finished = api
            .login_finish(&LoginFinishRequest {
                login_id: started.login_id,
                credential_finalization,
                device: self.config.device.clone(),
                trusted_device_token,
            })
            .await;
        match finished {
            Ok(login) => Ok(Login::Finished(login)),
            Err(error) => match (error.second_factor(), error.sso()) {
                (Some(challenge), _) => Ok(Login::SecondStep(challenge.clone())),
                (_, Some(challenge)) => Ok(Login::Sso(challenge.clone())),
                _ => Err(error.into()),
            },
        }
    }

    pub fn lock(&self) {
        self.auto_backup(true);
        let mut state = self.state();
        state.held = true;
        if state.unlocked.take().is_none() {
            return;
        }
        state.generation += 1;
        drop(state);
        self.emit_session();
    }

    /// Unlocks with the master password, offline: the account bundle is on this device. A sync
    /// follows in the background (signing in again with the same keys if the server session
    /// ended).
    pub async fn unlock(self: &Arc<Self>, password: Zeroizing<String>) -> Result<()> {
        if let Some(local) = self.current_local() {
            return self.unlock_local(local, password).await;
        }
        let account = self.current_account()?;
        require(self.state().unlocked.is_none(), ErrorCode::Locked)?;
        let keys = derive(
            password,
            SecretKey::parse(&account.secret_key)?,
            account.key.email.clone(),
            account.bundle.account_salt_bytes()?,
            account.bundle.kdf,
        )
        .await?;
        let session = Session::unlock(account.bundle.clone(), &keys.auk)?;
        {
            let mut state = self.state();
            if state.unlocked.is_some() {
                return Ok(());
            }
            if let Some(stored) = state.device.account_mut(&account.key) {
                stored.last_password_unlock_at = rfc3339(now());
            }
            self.save_device(&state)?;
        }
        self.install(account.key.clone(), session)?;
        let vault = Arc::clone(self);
        tokio::spawn(async move {
            let result = vault.resume_server_session(&account.key, Some(&keys)).await;
            vault.report(result);
        });
        Ok(())
    }

    /// Makes sure there's a server session (refreshing, or logging in again when `keys` are at
    /// hand), then syncs.
    pub(crate) async fn resume_server_session(
        &self,
        key: &AccountKey,
        keys: Option<&AccountKeys>,
    ) -> Result<()> {
        let _io = self.io.lock().await;
        if let (Err(_), Some(keys)) = (self.access_token(key, false).await, keys) {
            let trusted = self
                .state()
                .device
                .account(key)
                .and_then(|account| account.trusted_device_token.clone());
            let api = self.api(&key.server_url);
            let login = match self.login(&api, &key.email, keys, trusted).await? {
                Login::Finished(login) => login,
                // This device isn't trusted (any more): only a sign-in with the second step
                // gets a new session, so it's one that can't be resumed.
                Login::SecondStep(_) | Login::Sso(_) => {
                    return Err(VaultError::new(
                        ErrorCode::SessionExpired,
                        "signing in again needs the second step",
                    ));
                }
            };
            let mut state = self.state();
            state.access_tokens.insert(key.clone(), login.access_token);
            if let Some(account) = state.device.account_mut(key) {
                account.refresh_token = Some(login.refresh_token);
                if login.trusted_device_token.is_some() {
                    account.trusted_device_token = login.trusted_device_token;
                }
            }
            self.save_device(&state)?;
        }
        self.sync_locked().await
    }

    pub(crate) fn report(&self, result: Result<()>) {
        if let Err(error) = result {
            self.emit(Event::SyncFailed {
                message: error.message,
            });
        }
    }

    /// Signs out and forgets this device's Secret Key and device unlock for the account.
    pub async fn sign_out(&self) -> Result<()> {
        // There's no account to sign out of, and nothing here should delete the only copy.
        require(self.current_local().is_none(), ErrorCode::NeedsSync)?;
        let Ok(account) = self.current_account() else {
            return Ok(());
        };
        let token = self.state().access_tokens.get(&account.key).cloned();
        if let Some(token) = token {
            // Best effort: the local data goes either way.
            let _ = self.api(&account.key.server_url).logout(&token).await;
        }
        self.forget(&account.key)
    }

    /// Removes everything this device keeps for an account.
    fn forget(&self, key: &AccountKey) -> Result<()> {
        let _ = self.device_unlock.remove(&key.id());
        let _ = self.forget_stay_unlocked(key);
        self.store.delete_cache(key)?;
        let mut state = self.state();
        if state
            .unlocked
            .as_ref()
            .is_some_and(|unlocked| &unlocked.key == key)
        {
            state.unlocked = None;
        }
        state.generation += 1;
        state.access_tokens.remove(key);
        state.device.remove(key);
        self.save_device(&state)?;
        drop(state);
        self.emit_session();
        Ok(())
    }

    pub fn secret_key(&self) -> Result<String> {
        let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
        require(!key.is_local(), ErrorCode::NeedsSync)?;
        let state = self.state();
        Ok(state
            .device
            .account(&key)
            .ok_or(ErrorCode::Locked)?
            .secret_key
            .clone())
    }

    /// What deleting the account would remove: the devices signed in, and the shared vaults
    /// this account alone owns (deleting it deletes them for every member).
    pub async fn account_summary(&self) -> Result<AccountSummary> {
        if self.current_local().is_some() {
            return self.local_account_summary();
        }
        let (key, email, item_count, vault_count) = self.with_unlocked(|unlocked| {
            Ok((
                unlocked.key.clone(),
                unlocked.key.email.clone(),
                unlocked
                    .cache
                    .items
                    .iter()
                    .filter(|item| item.deleted_at.is_none())
                    .count(),
                unlocked.cache.vaults.len(),
            ))
        })?;
        let devices = self.list_devices().await?;
        let shared_vaults_owned = self.shared_vaults_owned(&key).await?;
        Ok(AccountSummary {
            email,
            item_count,
            vault_count,
            device_count: devices.len(),
            shared_vaults_owned,
        })
    }

    /// Re-authenticates with the master password (a fresh OPAQUE login for a single-use reauth
    /// token), deletes the account on the server, then everything on this device.
    pub async fn delete_account(
        &self,
        confirm_email: &str,
        password: Zeroizing<String>,
    ) -> Result<()> {
        require(self.current_local().is_none(), ErrorCode::NeedsSync)?;
        let account = self.current_account()?;
        self.with_unlocked(|_| Ok(()))?;
        require(
            normalize_email(confirm_email) == account.key.email,
            ErrorCode::EmailMismatch,
        )?;
        let _io = self.io.lock().await;
        let reauth_token = self
            .reauth(&account, password, ReauthPurpose::DeleteAccount)
            .await?;
        let request = DeleteAccountRequest {
            confirm_email: account.key.email.clone(),
        };
        self.authed(&account.key, |api, token| {
            let (request, reauth_token) = (request.clone(), reauth_token.clone());
            async move { api.delete_account(&token, &reauth_token, &request).await }
        })
        .await??;
        self.forget(&account.key)
    }

    /// A single-use reauth token for `purpose`, from a fresh OPAQUE login with the master
    /// password. A wrong password fails before anything is sent. The caller holds `io`.
    async fn reauth(
        &self,
        account: &StoredAccount,
        password: Zeroizing<String>,
        purpose: ReauthPurpose,
    ) -> Result<String> {
        Ok(self.reauth_session(account, password, purpose).await?.0)
    }

    /// `reauth`, plus the session the master password opened (for a password change, which
    /// wraps the same account key again). The caller holds `io`.
    async fn reauth_session(
        &self,
        account: &StoredAccount,
        password: Zeroizing<String>,
        purpose: ReauthPurpose,
    ) -> Result<(String, Session)> {
        let keys = derive(
            password,
            SecretKey::parse(&account.secret_key)?,
            account.key.email.clone(),
            account.bundle.account_salt_bytes()?,
            account.bundle.kdf,
        )
        .await?;
        let session = Session::unlock(account.bundle.clone(), &keys.auk)?;

        let (client, credential_request) = ReauthClient::start(&keys.auth_secret, &mut OsRng)?;
        let started = self
            .authed(&account.key, |api, token| {
                let request = ReauthStartRequest {
                    credential_request: credential_request.clone(),
                };
                async move { api.reauth_start(&token, &request).await }
            })
            .await??;
        let credential_finalization =
            client.finish(&keys.auth_secret, &started.credential_response, &mut OsRng)?;
        let request = ReauthFinishRequest {
            reauth_id: started.reauth_id,
            credential_finalization,
            purpose,
        };
        let reauth = self
            .authed(&account.key, |api, token| {
                let request = request.clone();
                async move { api.reauth_finish(&token, &request).await }
            })
            .await??;
        Ok((reauth.reauth_token, session))
    }

    // ---------- Two-step sign-in settings ----------

    /// The unlocked account, for the two-step settings.
    fn unlocked_account(&self) -> Result<StoredAccount> {
        let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
        require(!key.is_local(), ErrorCode::NeedsSync)?;
        self.state()
            .device
            .account(&key)
            .cloned()
            .ok_or_else(|| ErrorCode::Locked.into())
    }

    pub async fn two_step_status(&self) -> Result<TwoStepStatus> {
        let account = self.unlocked_account()?;
        let _io = self.io.lock().await;
        let status = self
            .authed(&account.key, |api, token| async move {
                api.two_step_status(&token).await
            })
            .await??;
        Ok(TwoStepStatus {
            enabled: status.enabled,
            security_keys: status.security_keys,
            recovery_codes_left: status.recovery_codes_left,
            security_keys_supported: false,
        })
    }

    /// Starts adding (or replacing) the authenticator app. Nothing changes until
    /// `confirm_totp_setup` gets a code from it.
    pub async fn start_totp_setup(&self, password: Zeroizing<String>) -> Result<TotpSetup> {
        let account = self.unlocked_account()?;
        let _io = self.io.lock().await;
        let reauth_token = self
            .reauth(&account, password, ReauthPurpose::TwoStep)
            .await?;
        let setup = self
            .authed(&account.key, |api, token| {
                let reauth_token = reauth_token.clone();
                async move { api.start_totp(&token, &reauth_token).await }
            })
            .await??;
        self.state().totp_setup = Some((account.key, setup.setup_id));
        Ok(TotpSetup {
            secret: setup.secret,
            otpauth_uri: setup.otpauth_uri,
        })
    }

    /// Turns two-step sign-in on (recovery codes come back, to show once) or swaps the
    /// authenticator. A wrong code can be tried again.
    pub async fn confirm_totp_setup(&self, code: &str) -> Result<TotpConfirmResponse> {
        let account = self.unlocked_account()?;
        let setup_id = match &self.state().totp_setup {
            Some((key, setup_id)) if *key == account.key => setup_id.clone(),
            _ => return Err(ErrorCode::TwoStepExpired.into()),
        };
        let request = TotpConfirmRequest {
            setup_id,
            code: code.trim().to_owned(),
        };
        let _io = self.io.lock().await;
        let confirmed = self
            .authed(&account.key, |api, token| {
                let request = request.clone();
                async move { api.confirm_totp(&token, &request).await }
            })
            .await?;
        match confirmed {
            Ok(confirmed) => {
                self.state().totp_setup = None;
                Ok(confirmed)
            }
            // The setup expired: start over.
            Err(error) if error.is(types::INVALID_REQUEST) => {
                self.state().totp_setup = None;
                Err(VaultError::new(
                    ErrorCode::TwoStepExpired,
                    error.to_string(),
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Replaces every recovery code; the new ones are shown once.
    pub async fn renew_recovery_codes(&self, password: Zeroizing<String>) -> Result<Vec<String>> {
        let account = self.unlocked_account()?;
        let _io = self.io.lock().await;
        let reauth_token = self
            .reauth(&account, password, ReauthPurpose::TwoStep)
            .await?;
        let renewed = self
            .authed(&account.key, |api, token| {
                let reauth_token = reauth_token.clone();
                async move { api.renew_recovery_codes(&token, &reauth_token).await }
            })
            .await??;
        Ok(renewed.recovery_codes)
    }

    /// Turns two-step sign-in off: the authenticator, security keys and recovery codes go.
    pub async fn disable_two_step(&self, password: Zeroizing<String>) -> Result<()> {
        let account = self.unlocked_account()?;
        let _io = self.io.lock().await;
        let reauth_token = self
            .reauth(&account, password, ReauthPurpose::TwoStep)
            .await?;
        self.authed(&account.key, |api, token| {
            let reauth_token = reauth_token.clone();
            async move { api.disable_two_step(&token, &reauth_token).await }
        })
        .await??;
        Ok(())
    }

    /// Security keys can't be added here, but the ones added in a browser can be removed.
    pub async fn remove_security_key(&self, id: &str, password: Zeroizing<String>) -> Result<()> {
        require(
            !id.is_empty()
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            ErrorCode::NotFound,
        )?;
        let account = self.unlocked_account()?;
        let _io = self.io.lock().await;
        let reauth_token = self
            .reauth(&account, password, ReauthPurpose::TwoStep)
            .await?;
        self.authed(&account.key, |api, token| {
            let (reauth_token, id) = (reauth_token.clone(), id.to_owned());
            async move { api.remove_security_key(&token, &reauth_token, &id).await }
        })
        .await??;
        Ok(())
    }

    // ---------- Device unlock ----------

    pub async fn unlock_methods(&self) -> UnlockMethods {
        let device_unlock = Arc::clone(&self.device_unlock);
        let capabilities = blocking(move || Ok(device_unlock.capabilities().ok()))
            .await
            .ok()
            .flatten();
        let method = capabilities.and_then(|capabilities| capabilities.method);
        if let Some(local) = self.current_local() {
            let enabled = local.device_unlock.is_some();
            return UnlockMethods {
                device_unlock_supported: method.is_some(),
                device_unlock_enabled: enabled,
                label: method.map_or("your device", |method| method.label()).into(),
                platform: DevicePlatform::current(),
                password_required: enabled && password_due(&local.last_password_unlock_at),
            };
        }
        let account = self.current_account().ok();
        let enabled = account
            .as_ref()
            .is_some_and(|account| account.device_unlock.is_some());
        UnlockMethods {
            device_unlock_supported: method.is_some(),
            device_unlock_enabled: enabled,
            label: method.map_or("your device", |method| method.label()).into(),
            platform: DevicePlatform::current(),
            password_required: enabled && account.as_ref().is_some_and(password_recheck_due),
        }
    }

    /// Turns on device unlock: the user confirms with the device lock once, then the account key
    /// is wrapped by a fresh device secret kept behind that lock.
    pub async fn enable_device_unlock(&self) -> Result<()> {
        let (key, generation) = {
            let state = self.state();
            let unlocked = state.unlocked.as_ref().ok_or(ErrorCode::Locked)?;
            (unlocked.key.clone(), state.generation)
        };
        let device_unlock = Arc::clone(&self.device_unlock);
        let account_id = key.id();
        let secret = blocking(move || {
            device_unlock.verify_user("turn on unlocking Octa Pass this way")?;
            Ok(device_unlock.enroll(&account_id)?)
        })
        .await?;
        let mut state = self.state();
        let unlocked = state
            .unlocked
            .as_ref()
            .filter(|_| state.generation == generation)
            .ok_or(ErrorCode::Locked)?;
        let wrapped = unlocked
            .session
            .enable_device_unlock(secret.as_ref(), &mut OsRng)?;
        let record = WrappedAsk {
            device_salt: b64_encode(&wrapped.device_salt),
            wrapped_ask: wrapped.wrapped_ask,
            enabled_at: rfc3339(now()),
        };
        if key.is_local() {
            drop(state);
            return self.set_local_device_unlock(&key, record);
        }
        state
            .device
            .account_mut(&key)
            .ok_or(ErrorCode::Locked)?
            .device_unlock = Some(record);
        self.save_device(&state)
    }

    pub fn disable_device_unlock(&self) -> Result<()> {
        let Some(key) = self.state().device.current.clone() else {
            return Ok(());
        };
        self.remove_device_unlock(&key)
    }

    fn remove_device_unlock(&self, key: &AccountKey) -> Result<()> {
        self.device_unlock.remove(&key.id())?;
        let mut state = self.state();
        if let Some(account) = state.device.account_mut(key) {
            account.device_unlock = None;
        }
        if let Some(local) = state.device.local_mut(key) {
            local.device_unlock = None;
        }
        self.save_device(&state)
    }

    /// Unlocks with Touch ID / the Mac password, Windows Hello or polkit.
    pub async fn unlock_with_device(self: &Arc<Self>) -> Result<()> {
        if let Some(local) = self.current_local() {
            return self.unlock_local_with_device(local).await;
        }
        let account = self.current_account()?;
        if self.state().unlocked.is_some() {
            return Ok(());
        }
        let record = account
            .device_unlock
            .clone()
            .ok_or(ErrorCode::DeviceUnlockFailed)?;
        require(!password_recheck_due(&account), ErrorCode::PasswordRequired)?;

        let device_unlock = Arc::clone(&self.device_unlock);
        let account_id = account.key.id();
        let secret =
            match blocking(move || Ok(device_unlock.unlock(&account_id, "unlock your vault")?))
                .await
            {
                Err(error) if error.code == ErrorCode::DeviceUnlockFailed => {
                    // The OS no longer has the secret (or refuses it for good): start over.
                    self.remove_device_unlock(&account.key)?;
                    return Err(error);
                }
                other => other?,
            };
        let session = match Session::unlock_with_device_key(
            account.bundle.clone(),
            secret.as_ref(),
            &b64_decode(&record.device_salt)?,
            &record.wrapped_ask,
        ) {
            Ok(session) => session,
            Err(error) => {
                self.remove_device_unlock(&account.key)?;
                return Err(error.into());
            }
        };
        // The master password may have unlocked the vault while the prompt was open.
        if self.state().unlocked.is_some() {
            return Ok(());
        }
        self.install(account.key.clone(), session)?;
        self.note_device_unlock();
        let vault = Arc::clone(self);
        tokio::spawn(async move {
            let result = vault.resume_server_session(&account.key, None).await;
            vault.report(result);
        });
        Ok(())
    }

    /// Confirms the master password again without changing the session: reveal, copy or export.
    pub async fn confirm_master_password(&self, password: Zeroizing<String>) -> Result<()> {
        if let Some(local) = self.current_local() {
            self.confirm_local_password(local, password).await?;
            self.mark_confirmed();
            return Ok(());
        }
        let account = self.unlocked_account()?;
        let keys = derive(
            password,
            SecretKey::parse(&account.secret_key)?,
            account.key.email.clone(),
            account.bundle.account_salt_bytes()?,
            account.bundle.kdf,
        )
        .await?;
        Session::unlock(account.bundle.clone(), &keys.auk)?;
        self.mark_confirmed();
        Ok(())
    }

    /// Confirms the device unlock secret again without changing the session: reveal, copy or export.
    pub async fn confirm_with_device(&self) -> Result<()> {
        if let Some(local) = self.current_local() {
            self.with_unlocked(|_| Ok(()))?;
            let record = local
                .device_unlock
                .clone()
                .ok_or(ErrorCode::DeviceUnlockFailed)?;
            let device_unlock = Arc::clone(&self.device_unlock);
            let account_id = local.key.id();
            let secret =
                blocking(move || Ok(device_unlock.unlock(&account_id, "confirm it's you")?))
                    .await?;
            let blob = self.store.read_local(&local.tag)?;
            octapass_core::local::LocalVault::unlock_with_device_key(
                &blob,
                secret.as_ref(),
                &b64_decode(&record.device_salt)?,
                &record.wrapped_ask,
            )?;
            self.mark_confirmed();
            return Ok(());
        }
        let account = self.unlocked_account()?;
        let record = account
            .device_unlock
            .clone()
            .ok_or(ErrorCode::DeviceUnlockFailed)?;
        let device_unlock = Arc::clone(&self.device_unlock);
        let account_id = account.key.id();
        let secret =
            blocking(move || Ok(device_unlock.unlock(&account_id, "confirm it's you")?)).await?;
        Session::unlock_with_device_key(
            account.bundle.clone(),
            secret.as_ref(),
            &b64_decode(&record.device_salt)?,
            &record.wrapped_ask,
        )?;
        self.mark_confirmed();
        Ok(())
    }

    // ---------- Vault ----------

    /// Shared vaults are named by a record inside them. One whose grant didn't verify is
    /// `untrusted`: it has no items here.
    pub fn list_vaults(&self) -> Result<Vec<VaultView>> {
        self.with_unlocked(|unlocked| {
            let items: Vec<Item> = unlocked
                .cache
                .items
                .iter()
                .filter_map(|record| decrypt(&unlocked.session, record).ok())
                .filter(Item::is_vault_info)
                .collect();
            let names = vault_names(&items);
            Ok(unlocked
                .cache
                .vaults
                .iter()
                .map(|vault| VaultView::new(vault, &names, unlocked.untrusted.contains(&vault.id)))
                .collect())
        })
    }

    /// Every item's row, trash included; the UI filters and sorts.
    pub fn list_items(&self) -> Result<Vec<ItemSummary>> {
        self.with_unlocked(|unlocked| {
            let Unlocked {
                session,
                cache,
                summaries,
                untrusted,
                ..
            } = unlocked;
            let mut rows = Vec::with_capacity(cache.items.len());
            for record in &cache.items {
                if untrusted.contains(&record.vault_id) {
                    continue;
                }
                match summaries.get(&record.id) {
                    Some((revision, row)) if *revision == record.revision => rows.push(row.clone()),
                    _ => {
                        // Items in vaults this session can't open are left out, and so are shared
                        // vaults' name records.
                        if let Ok(item) = decrypt(session, record)
                            && !item.is_vault_info()
                        {
                            let row = ItemSummary::from(&item);
                            summaries.insert(record.id.clone(), (record.revision, row.clone()));
                            rows.push(row);
                        }
                    }
                }
            }
            Ok(rows)
        })
    }

    pub fn get_item(&self, id: &str) -> Result<Item> {
        self.with_unlocked(|unlocked| {
            decrypt(
                &unlocked.session,
                unlocked.cache.item(id).ok_or(ErrorCode::NotFound)?,
            )
        })
    }

    /// Every item not in the trash, decrypted.
    pub fn live_items(&self) -> Result<Vec<Item>> {
        self.with_unlocked(|unlocked| {
            Ok(unlocked
                .cache
                .items
                .iter()
                .filter(|record| record.deleted_at.is_none())
                .filter_map(|record| decrypt(&unlocked.session, record).ok())
                .filter(|item| !item.is_vault_info())
                .collect())
        })
    }

    /// Creates or updates an item. An edit based on an old revision, or one the server rejects
    /// because someone else changed the item first, is saved as a conflicting copy instead.
    pub async fn save_item(&self, draft: ItemDraft) -> Result<Item> {
        let _io = self.io.lock().await;
        self.save_locked(draft).await
    }

    /// `save_item` for a caller that holds `io`.
    async fn save_locked(&self, draft: ItemDraft) -> Result<Item> {
        draft.to_core()?;
        let (key, existing) = self.with_unlocked(|unlocked| {
            unlocked.writable(&draft.vault_id)?;
            let existing = match &draft.id {
                Some(id) => {
                    let record = unlocked.cache.item(id).ok_or(ErrorCode::NotFound)?;
                    Some((
                        decrypt(&unlocked.session, record)?,
                        record.encrypted_item_key.clone(),
                    ))
                }
                None => None,
            };
            Ok((unlocked.key.clone(), existing))
        })?;
        let now = rfc3339(now());
        let saved = match existing {
            Some((previous, _))
                if draft
                    .revision
                    .is_some_and(|revision| revision != previous.revision) =>
            {
                let copy = draft.with_title_suffix(CONFLICT_SUFFIX);
                self.create(&key, copy.with_attachments_of(None)).await?
            }
            Some((previous, _)) if previous.vault_id != draft.vault_id => {
                let draft = draft.with_attachments_of(None);
                let moved = self
                    .create(&key, draft.with_password_history(&previous, &now))
                    .await?;
                self.trash(&key, &previous.vault_id, &previous.id, previous.revision)
                    .await?;
                moved
            }
            Some((previous, item_key)) => {
                let draft = draft
                    .with_password_history(&previous, &now)
                    .with_attachments_of(Some(&previous));
                let mut put = self
                    .put(
                        &key,
                        &draft,
                        &previous.id,
                        Some(&item_key),
                        Precondition::Revision(previous.revision),
                    )
                    .await?;
                if stale_vault_key(&put) {
                    // A rotation re-wrapped every item key and bumped every revision without
                    // touching item bodies, so the edit still applies on top of the rotated record.
                    self.sync_locked().await?;
                    let (item_key, revision) = self.with_unlocked(|unlocked| {
                        let record = unlocked
                            .cache
                            .item(&previous.id)
                            .ok_or(ErrorCode::NotFound)?;
                        Ok((record.encrypted_item_key.clone(), record.revision))
                    })?;
                    put = self
                        .put(
                            &key,
                            &draft,
                            &previous.id,
                            Some(&item_key),
                            Precondition::Revision(revision),
                        )
                        .await?;
                }
                match put {
                    Ok(()) => previous.id,
                    Err(ApiError::Problem { problem, .. }) if problem.current.is_some() => {
                        self.with_unlocked(|unlocked| {
                            unlocked
                                .cache
                                .upsert(problem.current.expect("checked above"));
                            Ok(())
                        })?;
                        let copy = draft.with_title_suffix(CONFLICT_SUFFIX);
                        self.create(&key, copy.with_attachments_of(None)).await?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            None => self.create(&key, draft.with_attachments_of(None)).await?,
        };
        self.sync_locked().await?;
        self.get_item(&saved)
    }

    /// Creates new items (an import). Returns how many were saved.
    pub async fn import_items(&self, drafts: Vec<ItemDraft>) -> Result<usize> {
        let _io = self.io.lock().await;
        let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
        let mut imported = 0;
        for draft in drafts {
            draft.to_core()?;
            self.create(&key, draft).await?;
            imported += 1;
        }
        self.sync_locked().await?;
        Ok(imported)
    }

    async fn create(&self, key: &AccountKey, draft: ItemDraft) -> Result<String> {
        let id = new_id(unix_ms(now()), &mut OsRng);
        self.put_new(key, &draft, &id)
            .await?
            .map_err(VaultError::from)?;
        Ok(id)
    }

    /// Creates an item. Another device or member rotating the vault key meanwhile means syncing
    /// to open the new key and encrypting again.
    pub(crate) async fn put_new(
        &self,
        key: &AccountKey,
        draft: &ItemDraft,
        id: &str,
    ) -> Result<ApiResult<()>> {
        let put = self.put(key, draft, id, None, Precondition::Create).await?;
        if !stale_vault_key(&put) {
            return Ok(put);
        }
        self.sync_locked().await?;
        self.put(key, draft, id, None, Precondition::Create).await
    }

    /// Encrypts and uploads one item. The outer error is local (locked, a token problem); the
    /// inner one is the server's answer, so callers can handle a `409`.
    async fn put(
        &self,
        key: &AccountKey,
        draft: &ItemDraft,
        item_id: &str,
        item_key: Option<&str>,
        precondition: Precondition,
    ) -> Result<ApiResult<()>> {
        self.put_with(key, draft, item_id, item_key, precondition, false)
            .await
    }

    /// `put`; `skip_history` when the write is bookkeeping, not an edit.
    async fn put_with(
        &self,
        key: &AccountKey,
        draft: &ItemDraft,
        item_id: &str,
        item_key: Option<&str>,
        precondition: Precondition,
        skip_history: bool,
    ) -> Result<ApiResult<()>> {
        if key.is_local() {
            self.put_local(draft, item_id, item_key)?;
            return Ok(Ok(()));
        }
        let encrypted = self.with_unlocked(|unlocked| {
            Ok(unlocked.session.encrypt_item(
                &draft.vault_id,
                item_id,
                &draft.to_core()?,
                item_key,
                &mut OsRng,
            )?)
        })?;
        let body = PutItemRequest {
            encrypted_item_key: encrypted.encrypted_item_key,
            overview: encrypted.overview,
            details: encrypted.details,
            skip_history,
        };
        let (vault_id, item_id) = (draft.vault_id.clone(), item_id.to_owned());
        Ok(self
            .authed(key, |api, token| {
                let (body, vault_id, item_id) = (body.clone(), vault_id.clone(), item_id.clone());
                async move {
                    api.put_item(&token, &vault_id, &item_id, precondition, &body)
                        .await
                }
            })
            .await?
            .map(drop))
    }

    pub async fn delete_item(&self, id: &str) -> Result<()> {
        let _io = self.io.lock().await;
        let (key, record) = self.writable_record(id)?;
        self.trash(&key, &record.vault_id, &record.id, record.revision)
            .await?;
        self.sync_locked().await
    }

    async fn trash(
        &self,
        key: &AccountKey,
        vault_id: &str,
        item_id: &str,
        revision: u64,
    ) -> Result<()> {
        if key.is_local() {
            return self.trash_local(item_id, true);
        }
        let (vault_id, item_id) = (vault_id.to_owned(), item_id.to_owned());
        self.authed(key, |api, token| {
            let (vault_id, item_id) = (vault_id.clone(), item_id.clone());
            async move { api.delete_item(&token, &vault_id, &item_id, revision).await }
        })
        .await??;
        Ok(())
    }

    pub async fn restore_item(&self, id: &str) -> Result<()> {
        let _io = self.io.lock().await;
        let (key, record) = self.writable_record(id)?;
        if key.is_local() {
            return self.trash_local(&record.id, false);
        }
        self.authed(&key, |api, token| {
            let (vault_id, item_id) = (record.vault_id.clone(), record.id.clone());
            async move { api.restore_item(&token, &vault_id, &item_id).await }
        })
        .await??;
        self.sync_locked().await
    }

    fn writable_record(&self, id: &str) -> Result<(AccountKey, ItemRecord)> {
        self.with_unlocked(|unlocked| {
            let record = unlocked.cache.item(id).ok_or(ErrorCode::NotFound)?.clone();
            unlocked.writable(&record.vault_id)?;
            Ok((unlocked.key.clone(), record))
        })
    }

    // ---------- Sync ----------

    pub async fn sync(&self) -> Result<()> {
        let _io = self.io.lock().await;
        self.sync_locked().await
    }

    /// Pulls what changed since the last sync, following `hasMore` pages. The caller holds `io`.
    async fn sync_locked(&self) -> Result<()> {
        // Sharing still works without these, so neither stands between the user and the vault,
        // and what monitoring finds shows as an alert.
        let key = self.account_key().ok();
        if let Some(key) = &key {
            let _ = self.ensure_key_record(key).await;
        }
        for _ in 0..MAX_SYNC_PAGES {
            if !self.sync_page().await? {
                break;
            }
        }
        if let Some(key) = &key {
            let _ = self.monitor_key_log(key, false).await;
        }
        Ok(())
    }

    /// Pulls and applies one page of changes. Returns whether the server has more.
    async fn sync_page(&self) -> Result<bool> {
        let (key, since, generation) = {
            let state = self.state();
            let Some(unlocked) = &state.unlocked else {
                return Ok(false);
            };
            // Nothing to pull: a local vault is the only copy.
            if unlocked.key.is_local() {
                return Ok(false);
            }
            (
                unlocked.key.clone(),
                unlocked.cache.since(),
                state.generation,
            )
        };
        let response = self
            .authed(&key, |api, token| {
                let since = since.clone();
                async move { api.sync(&token, &since).await }
            })
            .await??;
        let changed_and_more = {
            let mut state = self.state();
            if state.generation != generation {
                return Ok(false);
            }
            let Some(unlocked) = state.unlocked.as_mut() else {
                return Ok(false);
            };
            let has_more = response.has_more;
            let memberships = |cache: &VaultCache| {
                let mut vaults: Vec<(String, VaultRole)> = cache
                    .vaults
                    .iter()
                    .map(|vault| (vault.id.clone(), vault.role))
                    .collect();
                vaults.sort();
                vaults
            };
            let before = memberships(&unlocked.cache);
            let changed = unlocked.cache.apply(response);
            unlocked.open_vaults();
            if changed {
                self.store.save_cache(&key, &unlocked.cache)?;
            }
            (changed, has_more, before != memberships(&unlocked.cache))
        };
        let (changed, has_more, memberships_changed) = changed_and_more;
        if changed {
            self.emit(Event::ItemsChanged);
        }
        if memberships_changed {
            self.emit(Event::SharingChanged);
        }
        Ok(has_more)
    }

    // ---------- Server session ----------

    /// The unlocked account.
    fn account_key(&self) -> Result<AccountKey> {
        self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))
    }

    /// An authenticated JSON call to `path` (`/v1/…`). The caller holds `io`.
    async fn server<T: DeserializeOwned>(
        &self,
        key: &AccountKey,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<ApiResult<T>> {
        self.authed(key, |api, token| {
            let (method, body) = (method.clone(), body.clone());
            async move { api.call(method, path, &token, body.as_ref()).await }
        })
        .await
    }

    /// Runs an authenticated call, refreshing the access token once if it expired. The outer
    /// result fails when there's no usable server session; the inner one is the call's own.
    /// The caller holds `io`.
    async fn authed<T, F, Fut>(&self, key: &AccountKey, call: F) -> Result<ApiResult<T>>
    where
        F: Fn(Api, String) -> Fut,
        Fut: Future<Output = ApiResult<T>>,
    {
        require(!key.is_local(), ErrorCode::NeedsSync)?;
        let api = self.api(&key.server_url);
        let token = self.access_token(key, false).await?;
        let result = match call(api.clone(), token).await {
            Err(error) if error.is_unauthorized() => {
                let token = self.access_token(key, true).await?;
                call(api, token).await
            }
            other => other,
        };
        if let Err(error) = &result
            && error.is_account_deleted()
        {
            self.forget(key)?;
        }
        Ok(result)
    }

    /// The access token in memory, or a new one from the stored refresh token.
    async fn access_token(&self, key: &AccountKey, renew: bool) -> Result<String> {
        let refresh_token = {
            let state = self.state();
            if !renew && let Some(token) = state.access_tokens.get(key) {
                return Ok(token.clone());
            }
            state
                .device
                .account(key)
                .and_then(|account| account.refresh_token.clone())
                .ok_or(ErrorCode::SessionExpired)?
        };
        match self.api(&key.server_url).refresh(&refresh_token).await {
            Ok(refreshed) => {
                let mut state = self.state();
                state
                    .access_tokens
                    .insert(key.clone(), refreshed.access_token.clone());
                if let Some(account) = state.device.account_mut(key) {
                    account.refresh_token = Some(refreshed.refresh_token);
                    // Only for a device that signed in before the server issued these.
                    if refreshed.trusted_device_token.is_some() {
                        account.trusted_device_token = refreshed.trusted_device_token;
                    }
                }
                self.save_device(&state)?;
                Ok(refreshed.access_token)
            }
            Err(error) if error.is_account_deleted() => {
                self.forget(key)?;
                Err(error.into())
            }
            Err(error @ ApiError::Problem { .. }) => {
                // The refresh token is dead; only a password unlock can sign in again.
                let mut state = self.state();
                state.access_tokens.remove(key);
                if let Some(account) = state.device.account_mut(key) {
                    account.refresh_token = None;
                }
                self.save_device(&state)?;
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// For tests that act as another client of the account (the web vault sharing a vault): the
/// unlocked keys and a current access token. Never built into the app.
#[cfg(feature = "testing")]
impl Vault {
    pub fn with_keys<T>(&self, run: impl FnOnce(&mut Session, &VaultCache) -> T) -> Result<T> {
        self.with_unlocked(|unlocked| Ok(run(&mut unlocked.session, &unlocked.cache)))
    }

    pub async fn current_access_token(&self) -> Result<String> {
        let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
        self.access_token(&key, false).await
    }
}

fn session_state(status: SessionStatus, key: &AccountKey) -> SessionState {
    SessionState {
        status,
        email: Some(key.email.clone()),
        server_url: Some(key.server_url.clone()),
        confirmed: false,
    }
}

fn password_recheck_due(account: &StoredAccount) -> bool {
    password_due(&account.last_password_unlock_at)
}

/// The 14-day master password rule, from when the password last unlocked.
fn password_due(last_unlock: &str) -> bool {
    parse_rfc3339(last_unlock).is_none_or(|at| now() - at > PASSWORD_RECHECK)
}

/// What the core needs from a `VaultRecord` to open its key.
/// The server refused an item key wrapped under a vault key that's no longer current.
pub(crate) fn stale_vault_key<T>(answer: &ApiResult<T>) -> bool {
    matches!(answer, Err(error) if error.is(types::VAULT_KEY_CHANGED))
}

fn synced_vault(vault: &VaultRecord) -> SyncedVault<'_> {
    SyncedVault {
        id: &vault.id,
        personal: vault.vault_type == VaultType::Personal,
        role: match vault.role {
            VaultRole::Read => Role::Read,
            VaultRole::Write => Role::Write,
            VaultRole::Manage => Role::Manage,
            VaultRole::Owner => Role::Owner,
        },
        wrapped_vault_key: &vault.wrapped_vault_key,
        grant: vault.grant.as_ref().map(|grant| GrantSignature {
            granted_by: &grant.granted_by,
            granter_public_sign_key: &grant.granter_public_sign_key,
            granted_at: grant.granted_at,
            signature: &grant.signature,
        }),
    }
}

pub(crate) fn decrypt(session: &Session, record: &ItemRecord) -> Result<Item> {
    let encrypted = EncryptedItem {
        encrypted_item_key: record.encrypted_item_key.clone(),
        overview: record.overview.clone(),
        details: record.details.clone(),
    };
    let plaintext = session.decrypt_item(&record.vault_id, &record.id, &encrypted)?;
    Ok(Item::new(record, &plaintext))
}

/// The API and core types are the same JSON; this converts between them.
fn convert<T: DeserializeOwned>(value: &impl Serialize) -> Result<T> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(|error| VaultError::unexpected(error.to_string()))
}

/// Argon2id, on a blocking thread.
async fn derive(
    password: Zeroizing<String>,
    secret_key: SecretKey,
    email: String,
    account_salt: Vec<u8>,
    kdf: KdfParams,
) -> Result<AccountKeys> {
    blocking(move || {
        Ok(AccountKeys::derive(
            &password,
            &secret_key,
            &email,
            &account_salt,
            &kdf,
        )?)
    })
    .await
}

pub(crate) async fn blocking<T: Send + 'static>(
    run: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(run)
        .await
        .map_err(|error| VaultError::unexpected(error.to_string()))?
}

/// The server's origin. Plain `http` is only accepted for this computer (development servers).
pub fn normalize_server_url(raw: &str) -> Result<String> {
    let url = reqwest::Url::parse(raw.trim()).map_err(|_| ErrorCode::InsecureServerUrl)?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match url.scheme() {
        "https" => {}
        "http" if local => {}
        _ => return Err(ErrorCode::InsecureServerUrl.into()),
    }
    Ok(url.origin().ascii_serialization())
}

fn valid_email(email: &str) -> Result<String> {
    let email = normalize_email(email);
    let valid = email.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !email.chars().any(char::is_whitespace)
            && !domain.contains('@')
    });
    require(valid, ErrorCode::InvalidEmail)?;
    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls_must_be_https_except_on_this_computer() {
        assert_eq!(
            normalize_server_url(" https://vault.example.com/some/path ").unwrap(),
            "https://vault.example.com"
        );
        assert_eq!(
            normalize_server_url("http://localhost:8080/").unwrap(),
            "http://localhost:8080"
        );
        assert_eq!(
            normalize_server_url("http://127.0.0.1:8080").unwrap(),
            "http://127.0.0.1:8080"
        );
        for bad in [
            "http://vault.example.com",
            "ftp://localhost",
            "not a url",
            "",
        ] {
            assert_eq!(
                normalize_server_url(bad).unwrap_err().code,
                ErrorCode::InsecureServerUrl,
                "{bad}"
            );
        }
    }

    #[test]
    fn emails_are_normalised_and_checked() {
        assert_eq!(valid_email("  A@Example.COM ").unwrap(), "a@example.com");
        for bad in ["a", "a@b", "@b.c", "a@.c", "a b@c.d", "a@b@c.d"] {
            assert_eq!(
                valid_email(bad).unwrap_err().code,
                ErrorCode::InvalidEmail,
                "{bad}"
            );
        }
    }
}
