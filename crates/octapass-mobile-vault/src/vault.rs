//! The vault behind the mobile app's commands. It mirrors `VaultService` from
//! `packages/vault-client` on top of `octapass-ffi`: the encrypted store is the `LocalStore` file
//! the AutoFill extension reads too, and the keys never leave this process. Every method blocks
//! (Argon2id, the network): call them off the main thread.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use octapass_ffi::{
    DeviceInfo, HttpMethod, LocalStore, LogInResult, OctaPassError, OctaPassServer, ReauthPurpose,
    SecondFactorLogin, Session, SignedIn, Signup, SsoLogin, normalize_secret_key,
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::accounts::{Account, Accounts, store_path};
use crate::error::{ErrorCode, Result, VaultError};
use crate::http::Http;
use crate::model::{
    AccountSummary, Item, ItemDraft, ItemSummary, RecoveryKit, RememberedAccount, ServerInfo,
    SessionState, SessionStatus, SignInResult, SignupStarted, StayUnlockedStatus, TotpConfirmed,
    TotpSetup, TwoStepMethod, TwoStepProof, TwoStepStatus, UnlockMethods, Vault as VaultView, now,
    require, vault_names,
};
use crate::native::Native;

pub use versions::{EquivalentDomains, EquivalentDomainsInput, ItemVersion};

mod access;
mod attachments;
#[cfg(all(feature = "desktop", any(target_os = "macos", target_os = "linux")))]
mod desktop;
mod local;
mod password;
mod qr;
pub mod safes;
mod transfer;
mod versions;

pub use access::{Access, OutboxStatus, TwoStepPending};
pub use local::{LocalCapabilities, LocalVaultInfo, RestoreSecret};
pub use qr::{read_qr_codes, summarize_qr_scans};
pub use transfer::{FileExport, ImportReview, ImportSummary, ReceivedPreview, ReviewCode};

const SIGNUP_TTL: Duration = Duration::from_secs(15 * 60);
const CONFLICT_SUFFIX: &str = " (conflicting copy)";
/// What Face ID or the passcode sheet says the unlock is for.
const UNLOCK_REASON: &str = "Unlock Octa Pass";
const CONFIRM_REASON: &str = "Show a secret as a QR code";

pub struct Config {
    /// The App Group container (iOS) or app storage (Android), shared with the autofill
    /// extensions.
    pub data_dir: PathBuf,
    /// The app's own private storage for plaintext files on their way from a picker or to the
    /// viewer, never shared with the extensions. Emptied on lock and when the app starts.
    pub temp_dir: PathBuf,
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
    /// A sync failed; the vault keeps working from the local store.
    SyncFailed {
        message: String,
    },
}

/// The session plus the accounts this phone remembers, which the UI reads synchronously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSnapshot {
    pub session: SessionState,
    pub remembered_accounts: Vec<RememberedAccount>,
}

pub type Listener = Box<dyn Fn(Event) + Send + Sync>;

pub struct Vault {
    config: Config,
    pub(crate) http: Arc<Http>,
    native: Arc<dyn Native>,
    listener: Listener,
    state: Mutex<State>,
    /// Serialises everything that uses the refresh token, so a rotated one is never presented
    /// twice (the server would sign the device out).
    io: Mutex<()>,
}

struct State {
    accounts: Accounts,
    unlocked: Option<Unlocked>,
    signups: HashMap<String, PendingSignup>,
    /// The current account's access token, by account tag.
    access_token: Option<(String, String)>,
    /// A sign-in waiting for its second step.
    two_step: Option<PendingTwoStep>,
    /// A sign-in waiting for the identity provider.
    sso: Option<PendingSso>,
    /// An authenticator being added, waiting for its first code: the account tag and setup id.
    totp_setup: Option<(String, String)>,
    /// Files the system picker copied here, by the id the UI knows them by.
    picked: HashMap<String, attachments::Picked>,
    /// Master password resets in progress, by reset id. They don't survive a restart.
    resets: HashMap<String, password::PendingReset>,
    /// Imports waiting for their review, by review id. Only while unlocked.
    imports: HashMap<String, transfer::PendingImport>,
    /// Items another app handed over, waiting for the user to import them.
    received: Option<transfer::Received>,
}

#[derive(Clone)]
pub(crate) struct Unlocked {
    pub(crate) account: Account,
    pub(crate) store: Arc<LocalStore>,
    pub(crate) session: Arc<Session>,
    server: Arc<OctaPassServer>,
}

struct PendingTwoStep {
    server: Arc<OctaPassServer>,
    email: String,
    secret_key: Zeroizing<String>,
    login: Arc<SecondFactorLogin>,
    expires_at: Instant,
}

struct PendingSso {
    server: Arc<OctaPassServer>,
    email: String,
    secret_key: Zeroizing<String>,
    login: Arc<SsoLogin>,
    expires_at: Instant,
}

struct PendingSignup {
    server: Arc<OctaPassServer>,
    signup: Arc<Signup>,
    expires_at: Instant,
    /// Turning on sync for this local vault, by tag: its items move into the new account.
    upgrades: Option<String>,
}

impl Vault {
    pub fn new(config: Config, native: Arc<dyn Native>, listener: Listener) -> Result<Arc<Self>> {
        let accounts = Accounts::load(&config.data_dir)?;
        let user_agent = format!(
            "OctaPass-{}/{}",
            config.device.platform,
            env!("CARGO_PKG_VERSION")
        );
        let vault = Arc::new(Self {
            config,
            http: Arc::new(Http::new(&user_agent)),
            native,
            listener,
            state: Mutex::new(State {
                accounts,
                unlocked: None,
                signups: HashMap::new(),
                access_token: None,
                two_step: None,
                sso: None,
                totp_setup: None,
                picked: HashMap::new(),
                resets: HashMap::new(),
                imports: HashMap::new(),
                received: None,
            }),
            io: Mutex::new(()),
        });
        // Whatever the last run left, if it ended without locking.
        vault.clear_plaintext();
        Ok(vault)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn server(&self, server_url: &str) -> Result<Arc<OctaPassServer>> {
        Ok(OctaPassServer::new(
            server_url.to_owned(),
            self.http.clone(),
        )?)
    }

    // ---------- Session ----------

    pub fn snapshot(&self) -> SessionSnapshot {
        let state = self.state();
        let account = match &state.unlocked {
            Some(unlocked) => Some((SessionStatus::Unlocked, &unlocked.account)),
            None => state
                .accounts
                .current()
                .map(|account| (SessionStatus::Locked, account)),
        };
        let session = match account {
            Some((status, account)) => SessionState {
                status,
                email: Some(account.email.clone()),
                server_url: Some(account.server_url.clone()),
            },
            None => SessionState {
                status: SessionStatus::SignedOut,
                email: None,
                server_url: None,
            },
        };
        SessionSnapshot {
            session,
            remembered_accounts: state
                .accounts
                .accounts
                .iter()
                // Local vaults have their own list: nobody signs in to them.
                .filter(|account| !account.is_local())
                .map(|account| RememberedAccount {
                    email: account.email.clone(),
                    server_url: account.server_url.clone(),
                })
                .collect(),
        }
    }

    fn emit_session(&self) {
        (self.listener)(Event::Session(self.snapshot()));
    }

    pub(crate) fn unlocked(&self) -> Result<Unlocked> {
        self.state()
            .unlocked
            .clone()
            .ok_or_else(|| ErrorCode::Locked.into())
    }

    fn current_account(&self) -> Result<Account> {
        self.state()
            .accounts
            .current()
            .cloned()
            .ok_or_else(|| ErrorCode::Locked.into())
    }

    fn open_store(&self, account: &Account) -> Result<Arc<LocalStore>> {
        let path = store_path(&self.config.data_dir, account);
        Ok(LocalStore::open(path.to_string_lossy().into_owned())?)
    }

    // ---------- Server and account ----------

    pub fn server_info(&self, server_url: &str) -> Result<ServerInfo> {
        let mut info: ServerInfo = self.server(server_url)?.server_info()?.into();
        info.email_breach_checks = self.http.email_breach_checks(server_url);
        Ok(info)
    }

    pub fn start_signup(
        &self,
        server_url: &str,
        email: &str,
        password: Zeroizing<String>,
    ) -> Result<SignupStarted> {
        let server = self.server(server_url)?;
        let signup = server.start_signup(email.to_owned(), password.to_string())?;
        let signup_id = new_signup_id();
        let started = SignupStarted {
            signup_id: signup_id.clone(),
            dev_verification_code: signup.dev_verification_code(),
        };
        let mut state = self.state();
        state
            .signups
            .retain(|_, pending| pending.expires_at > Instant::now());
        state.signups.insert(
            signup_id,
            PendingSignup {
                server,
                signup,
                expires_at: Instant::now() + SIGNUP_TTL,
                upgrades: None,
            },
        );
        Ok(started)
    }

    /// Finishes sign-up and signs in. A wrong code can be retried.
    pub fn finish_signup(&self, signup_id: &str, verification_code: &str) -> Result<RecoveryKit> {
        let (server, signup) = {
            let state = self.state();
            let pending = state
                .signups
                .get(signup_id)
                .filter(|pending| pending.expires_at > Instant::now())
                .ok_or(ErrorCode::SignupExpired)?;
            (pending.server.clone(), pending.signup.clone())
        };
        let signed_in = signup.finish(verification_code.to_owned(), self.config.device.clone())?;
        self.state().signups.remove(signup_id);
        let secret_key = Zeroizing::new(signup.secret_key());
        let account = self.adopt(&server, &signup.email(), &secret_key, signed_in)?;
        Ok(RecoveryKit {
            email: account.email,
            server_url: account.server_url,
            secret_key: secret_key.to_string(),
            recovery_code: signup.recovery_code(),
            created_at: now(),
        })
    }

    /// `secret_key` is needed for an account this phone doesn't remember. When the account asks
    /// this phone for a second step, the sign-in waits for `finish_two_step` instead.
    pub fn sign_in(
        &self,
        server_url: &str,
        email: &str,
        password: Zeroizing<String>,
        secret_key: Option<Zeroizing<String>>,
    ) -> Result<SignInResult> {
        let server = self.server(server_url)?;
        let email = octapass_core::kdf::normalize_email(email);
        let remembered = {
            let mut state = self.state();
            state.two_step = None;
            state.sso = None;
            state.accounts.find(&server.base_url(), &email).cloned()
        };
        let secret_key = match (secret_key, &remembered) {
            (Some(text), _) => Zeroizing::new(normalize_secret_key(text.to_string())?),
            (None, Some(account)) => self
                .native
                .secret(&account.secret_key_name())?
                .ok_or(ErrorCode::SecretKeyRequired)?,
            (None, None) => return Err(ErrorCode::SecretKeyRequired.into()),
        };
        let trusted = match &remembered {
            Some(account) => self.native.secret(&account.trusted_device_name())?,
            None => None,
        };
        let result = server.log_in_trusted(
            email.clone(),
            password.to_string(),
            secret_key.to_string(),
            self.config.device.clone(),
            trusted.map(|token| token.to_string()),
        )?;
        self.login_result(server, email, secret_key, result)
    }

    /// Goes on from how a login step ended.
    fn login_result(
        &self,
        server: Arc<OctaPassServer>,
        email: String,
        secret_key: Zeroizing<String>,
        result: LogInResult,
    ) -> Result<SignInResult> {
        match result {
            LogInResult::SignedIn { signed_in } => {
                self.adopt(&server, &email, &secret_key, signed_in)?;
                Ok(SignInResult::SignedIn)
            }
            LogInResult::SecondFactorRequired { second_factor } => {
                let methods = TwoStepMethod::offered(&second_factor.methods());
                self.state().two_step = Some(PendingTwoStep {
                    server,
                    email,
                    secret_key,
                    expires_at: Instant::now() + Duration::from_secs(second_factor.expires_in()),
                    login: second_factor,
                });
                Ok(SignInResult::TwoStepRequired { methods })
            }
            LogInResult::SsoRequired { sso } => {
                let (url, org_name) = (sso.url(), sso.org_name());
                self.state().sso = Some(PendingSso {
                    server,
                    email,
                    secret_key,
                    expires_at: Instant::now() + Duration::from_secs(sso.expires_in()),
                    login: sso,
                });
                Ok(SignInResult::SsoRequired { url, org_name })
            }
        }
    }

    /// Finishes the SSO step with the code the browser showed. A wrong code can be tried again,
    /// `ssoPending` means the browser hasn't finished yet, and `twoStepExpired` means starting
    /// over with `sign_in`. Two-step sign-in, if the account has it, comes after.
    pub fn finish_sso(&self, code: &str) -> Result<SignInResult> {
        let pending = self
            .state()
            .sso
            .take()
            .filter(|pending| pending.expires_at > Instant::now())
            .ok_or(ErrorCode::TwoStepExpired)?;
        match pending.login.finish(code.to_owned()) {
            Ok(result) => self.login_result(
                pending.server.clone(),
                pending.email.clone(),
                pending.secret_key.clone(),
                result,
            ),
            Err(error @ OctaPassError::LoginFailed) => Err(VaultError::new(
                ErrorCode::TwoStepExpired,
                error.to_string(),
            )),
            Err(error) => {
                let error = VaultError::from(error);
                // The server keeps the sign-in after a wrong code (a few times), while the
                // browser hasn't finished, and after a request that never reached it.
                if matches!(
                    error.code,
                    ErrorCode::InvalidTwoStepCode
                        | ErrorCode::SsoPending
                        | ErrorCode::ServerUnreachable
                ) {
                    self.state().sso.get_or_insert(pending);
                }
                Err(error)
            }
        }
    }

    /// Finishes a sign-in that asked for a second step. A wrong code can be tried again;
    /// `twoStepExpired` means starting over with `sign_in`.
    pub fn finish_two_step(&self, proof: TwoStepProof) -> Result<()> {
        if let TwoStepProof::SecurityKey = proof {
            return Err(ErrorCode::SecurityKeyUnsupported.into());
        }
        let pending = self
            .state()
            .two_step
            .take()
            .filter(|pending| pending.expires_at > Instant::now())
            .ok_or(ErrorCode::TwoStepExpired)?;
        let finished = match proof {
            TwoStepProof::Totp { code } => pending.login.finish_with_totp(code),
            TwoStepProof::RecoveryCode { code } => pending.login.finish_with_recovery_code(code),
            TwoStepProof::SecurityKey => unreachable!("refused above"),
        };
        let signed_in = match finished {
            Ok(signed_in) => signed_in,
            // The challenge expired or had too many wrong tries.
            Err(error @ OctaPassError::LoginFailed) => {
                return Err(VaultError::new(
                    ErrorCode::TwoStepExpired,
                    error.to_string(),
                ));
            }
            Err(error) => {
                let error = VaultError::from(error);
                // The server keeps the challenge after a wrong code (a few times), and after a
                // request that never reached it.
                if matches!(
                    error.code,
                    ErrorCode::InvalidTwoStepCode | ErrorCode::ServerUnreachable
                ) {
                    self.state().two_step.get_or_insert(pending);
                }
                return Err(error);
            }
        };
        self.adopt(
            &pending.server,
            &pending.email,
            &pending.secret_key,
            signed_in,
        )?;
        Ok(())
    }

    /// Makes a freshly signed-in account the current one: a new store, filled by a first sync,
    /// and its secrets in the Keychain.
    fn adopt(
        &self,
        server: &Arc<OctaPassServer>,
        email: &str,
        secret_key: &str,
        signed_in: SignedIn,
    ) -> Result<Account> {
        self.adopt_with(server, email, secret_key, signed_in, None)
    }

    /// `adopt`, starting from a local vault's items: they wait in the new store to upload.
    fn adopt_with(
        &self,
        server: &Arc<OctaPassServer>,
        email: &str,
        secret_key: &str,
        signed_in: SignedIn,
        items: Option<&LocalStore>,
    ) -> Result<Account> {
        let account = Account::new(&server.base_url(), email);
        // A new store has device unlock off; an old secret for this account would be stale.
        self.delete_device_keys(&account)?;
        let path = store_path(&self.config.data_dir, &account);
        std::fs::create_dir_all(&self.config.data_dir)
            .map_err(|error| VaultError::unexpected(format!("storage: {error}")))?;
        let store = LocalStore::create(
            path.to_string_lossy().into_owned(),
            server.base_url(),
            signed_in.session.clone(),
        )?;
        if let Some(items) = items {
            store.adopt_local_items(items)?;
        }
        server.sync(signed_in.tokens.access_token.clone(), store.clone())?;
        self.native
            .set_secret(&account.secret_key_name(), secret_key)?;
        self.native.set_secret(
            &account.refresh_token_name(),
            &signed_in.tokens.refresh_token,
        )?;
        if let Some(token) = &signed_in.tokens.trusted_device_token {
            self.native
                .set_secret(&account.trusted_device_name(), token)?;
        }
        // Pins the save inbox's key (plan 03), so the Autofill service can save while locked.
        if cfg!(not(target_os = "ios")) {
            let _ = store.clone().merge_inbox(signed_in.session.clone());
        }
        {
            let mut state = self.state();
            if let Some(previous) = state.unlocked.take() {
                previous.session.lock();
            }
            state.accounts.upsert_current(account.clone());
            state.accounts.save(&self.config.data_dir)?;
            state.access_token = Some((account.tag.clone(), signed_in.tokens.access_token));
            state.unlocked = Some(Unlocked {
                account: account.clone(),
                store,
                session: signed_in.session,
                server: server.clone(),
            });
        }
        self.emit_session();
        self.publish_identities();
        Ok(account)
    }

    pub fn lock(&self) {
        self.auto_backup();
        let unlocked = {
            let mut state = self.state();
            state.access_token = None;
            state.imports.clear();
            state.unlocked.take()
        };
        self.clear_plaintext();
        if let Some(unlocked) = unlocked {
            unlocked.session.lock();
            self.emit_session();
        }
    }

    pub fn unlock(&self, password: Zeroizing<String>) -> Result<()> {
        let account = self.current_account()?;
        if account.is_local() {
            return self.unlock_local(account, password);
        }
        let secret_key = self
            .native
            .secret(&account.secret_key_name())?
            .ok_or(ErrorCode::SecretKeyRequired)?;
        let store = self.open_store(&account)?;
        let opened = store
            .unlock_with_password(password.to_string(), secret_key.to_string())
            .map_err(VaultError::from);
        // A new master password set on another device signs this one out, and the copy kept here
        // still opens with the old one. The server says which is current: a device it still
        // knows has the current password, and one it signed out signs in again with the
        // password typed. Offline, the copy here decides.
        let server = self.server(server_of(&account))?;
        let signed_out = match &opened {
            Ok(_) => self.signed_out_here(&account, &server),
            Err(error) if error.code == ErrorCode::InvalidCredentials => {
                self.signed_out_here(&account, &server)
            }
            Err(_) => false,
        };
        if !signed_out {
            return match opened {
                Ok(session) => self.set_unlocked(account, store, session),
                Err(error) => {
                    self.state().access_token = None;
                    Err(error)
                }
            };
        }
        let again = self.sign_in_again(&account, &store, &server, &password, &secret_key);
        match (again, opened) {
            (Ok(session), Ok(old)) => {
                old.lock();
                self.set_unlocked(account, store, session)
            }
            (Ok(session), Err(_)) => self.set_unlocked(account, store, session),
            // The old password: the server no longer takes it.
            (Err(error), Ok(old)) if error.code == ErrorCode::InvalidCredentials => {
                old.lock();
                Err(error)
            }
            // The server couldn't say (offline since, or a second step this screen can't show):
            // the copy here opens as before, and sync says to sign in again.
            (Err(_), Ok(old)) => self.set_unlocked(account, store, old),
            (Err(error), Err(_)) => Err(error),
        }
    }

    /// Whether the server has signed this device out (a new master password or Secret Key set
    /// elsewhere, or the device removed). False offline or when it can't tell. Keeps the access
    /// token it gets, for the sync after unlocking.
    fn signed_out_here(&self, account: &Account, server: &Arc<OctaPassServer>) -> bool {
        let _io = self.io();
        let name = account.refresh_token_name();
        let Ok(token) = self.native.secret(&name) else {
            return false;
        };
        let Some(token) = token else {
            return true;
        };
        match server.refresh(token.to_string()) {
            Ok(tokens) => {
                let _ = self.native.set_secret(&name, &tokens.refresh_token);
                if let Some(trusted) = &tokens.trusted_device_token {
                    let _ = self
                        .native
                        .set_secret(&account.trusted_device_name(), trusted);
                }
                self.state().access_token = Some((account.tag.clone(), tokens.access_token));
                false
            }
            Err(OctaPassError::Unauthorized) => true,
            Err(_) => false,
        }
    }

    /// Signs this device in again with `password` after the server signed it out, keeping the
    /// store and what waits in it to upload. The store takes the account's current bundle, so
    /// the next unlock offline takes the new password too, and device unlock starts again.
    fn sign_in_again(
        &self,
        account: &Account,
        store: &Arc<LocalStore>,
        server: &Arc<OctaPassServer>,
        password: &str,
        secret_key: &str,
    ) -> Result<Arc<Session>> {
        let _io = self.io();
        let trusted = self.native.secret(&account.trusted_device_name())?;
        let result = server.log_in_trusted(
            account.email.clone(),
            password.to_owned(),
            secret_key.to_owned(),
            self.config.device.clone(),
            trusted.map(|token| token.to_string()),
        )?;
        let LogInResult::SignedIn { signed_in } = result else {
            return Err(ErrorCode::SessionExpired.into());
        };
        store.update_account(signed_in.session.clone())?;
        self.delete_device_keys(account)?;
        self.native.set_secret(
            &account.refresh_token_name(),
            &signed_in.tokens.refresh_token,
        )?;
        if let Some(token) = &signed_in.tokens.trusted_device_token {
            self.native
                .set_secret(&account.trusted_device_name(), token)?;
        }
        self.state().access_token = Some((account.tag.clone(), signed_in.tokens.access_token));
        Ok(signed_in.session)
    }

    fn set_unlocked(
        &self,
        account: Account,
        store: Arc<LocalStore>,
        session: Arc<Session>,
    ) -> Result<()> {
        // Saving while locked (plan 03): pins this account's own public keys for the store's save
        // inbox and merges what the Autofill service sealed into it. iOS has no save requests, so no
        // inbox. A failure leaves the entries for the next unlock and never blocks this one.
        if cfg!(not(target_os = "ios")) {
            let _ = store.clone().merge_inbox(session.clone());
        }
        let server = self.server(server_of(&account))?;
        let mut state = self.state();
        // Another account's reviews never carry over.
        if state.unlocked.as_ref().map(|now| &now.account.tag) != Some(&account.tag) {
            state.imports.clear();
        }
        state.unlocked = Some(Unlocked {
            account,
            store,
            session,
            server,
        });
        drop(state);
        self.emit_session();
        Ok(())
    }

    /// Signs out here: the server forgets this device, and the store, the Keychain items and
    /// the AutoFill suggestions are deleted.
    pub fn sign_out(&self) -> Result<()> {
        let account = self.current_account()?;
        // There's no account to sign out of, and this would wipe the only copy of the vault.
        require(!account.is_local(), ErrorCode::NeedsSync)?;
        let _io = self.io();
        if let Ok(unlocked) = self.unlocked() {
            // Best effort: offline, the server's session simply expires.
            let _ = self.with_token(&unlocked, |token| unlocked.server.log_out(token.into()));
        }
        self.forget(&account)
    }

    /// Wipes everything this phone keeps for `account`, files waiting to upload included.
    fn forget(&self, account: &Account) -> Result<()> {
        {
            let mut state = self.state();
            if let Some(unlocked) = state.unlocked.take() {
                unlocked.session.lock();
            }
            state.access_token = None;
            state.imports.clear();
            state.accounts.remove(&account.tag);
            state.accounts.save(&self.config.data_dir)?;
        }
        self.clear_plaintext();
        crate::outbox::Outbox::new(&self.config.data_dir, account).delete()?;
        let path = store_path(&self.config.data_dir, account);
        for file in [
            path.clone(),
            path.with_extension("opstore.lock"),
            path.with_extension("opstore.inbox"),
        ] {
            match std::fs::remove_file(file) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(VaultError::unexpected(format!("storage: {error}")));
                }
                _ => {}
            }
        }
        self.native.delete_secret(&account.secret_key_name())?;
        self.native.delete_secret(&account.refresh_token_name())?;
        self.native.delete_secret(&account.trusted_device_name())?;
        self.delete_device_keys(account)?;
        self.native.set_credential_identities(&[])?;
        self.emit_session();
        Ok(())
    }

    pub fn secret_key(&self) -> Result<String> {
        let unlocked = self.unlocked()?;
        require(!unlocked.account.is_local(), ErrorCode::NeedsSync)?;
        let key = self
            .native
            .secret(&unlocked.account.secret_key_name())?
            .ok_or(ErrorCode::SecretKeyRequired)?;
        Ok(key.to_string())
    }

    pub fn account_summary(&self) -> Result<AccountSummary> {
        let unlocked = self.unlocked()?;
        let items = unlocked.session.decrypt_items(&unlocked.store)?;
        let base = unlocked.server.base_url();
        let _io = self.io();
        let device_count = if unlocked.account.is_local() {
            1
        } else {
            self.with_token(&unlocked, |token| {
                self.http
                    .json::<Vec<octapass_api::DeviceRecord>>(
                        HttpMethod::Get,
                        format!("{base}v1/devices"),
                        token,
                        &[],
                    )
                    .map(|devices| devices.len())
            })
            // Offline, this phone is the one device we know of.
            .unwrap_or(1)
        };
        Ok(AccountSummary {
            email: unlocked.account.email.clone(),
            item_count: items
                .iter()
                .filter(|item| item.record.deleted_at.is_none())
                .count(),
            vault_count: unlocked.store.vaults().len(),
            device_count,
            shared_vaults_owned: Vec::new(),
        })
    }

    pub fn delete_account(&self, confirm_email: &str, password: Zeroizing<String>) -> Result<()> {
        let unlocked = self.unlocked()?;
        require(
            octapass_core::kdf::normalize_email(confirm_email) == unlocked.account.email,
            ErrorCode::EmailMismatch,
        )?;
        let secret_key = self.secret_key()?;
        let _io = self.io();
        self.with_token(&unlocked, |token| {
            let reauth = unlocked.server.reauth(
                token.into(),
                unlocked.session.clone(),
                password.to_string(),
                secret_key.clone(),
                ReauthPurpose::DeleteAccount,
            )?;
            unlocked
                .server
                .delete_account(token.into(), reauth, unlocked.account.email.clone())
        })?;
        self.forget(&unlocked.account)
    }

    // ---------- Two-step sign-in settings ----------

    pub fn two_step_status(&self) -> Result<TwoStepStatus> {
        let unlocked = self.unlocked()?;
        let _io = self.io();
        let status = self.with_token(&unlocked, |token| {
            unlocked.server.two_step_status(token.into())
        })?;
        Ok(status.into())
    }

    /// Re-authenticates with the master password, then runs `call` with the access token and
    /// the reauth token. The caller holds `io`.
    fn with_reauth<T>(
        &self,
        unlocked: &Unlocked,
        password: &str,
        call: impl Fn(&str, String) -> std::result::Result<T, OctaPassError>,
    ) -> Result<T> {
        let secret_key = self.secret_key()?;
        self.with_token(unlocked, |token| {
            let reauth = unlocked.server.reauth(
                token.into(),
                unlocked.session.clone(),
                password.to_owned(),
                secret_key.clone(),
                ReauthPurpose::TwoStep,
            )?;
            call(token, reauth)
        })
    }

    /// Starts adding (or replacing) the authenticator app. Nothing changes until
    /// `confirm_totp_setup` gets a code from it.
    pub fn start_totp_setup(&self, password: Zeroizing<String>) -> Result<TotpSetup> {
        let unlocked = self.unlocked()?;
        let _io = self.io();
        let setup = self.with_reauth(&unlocked, &password, |token, reauth| {
            unlocked.server.start_totp_setup(token.into(), reauth)
        })?;
        self.state().totp_setup = Some((unlocked.account.tag.clone(), setup.setup_id));
        Ok(TotpSetup {
            secret: setup.secret,
            otpauth_uri: setup.otpauth_uri,
        })
    }

    /// Turns two-step sign-in on (recovery codes come back, to show once) or swaps the
    /// authenticator. A wrong code can be tried again.
    pub fn confirm_totp_setup(&self, code: &str) -> Result<TotpConfirmed> {
        let unlocked = self.unlocked()?;
        let setup_id = match &self.state().totp_setup {
            Some((tag, setup_id)) if *tag == unlocked.account.tag => setup_id.clone(),
            _ => return Err(ErrorCode::TwoStepExpired.into()),
        };
        let _io = self.io();
        // `None`: the setup expired.
        let confirmed = self.with_token(&unlocked, |token| {
            let confirmed = unlocked.server.confirm_totp_setup(
                token.into(),
                setup_id.clone(),
                code.trim().to_owned(),
            );
            match confirmed {
                Err(OctaPassError::Server { problem_type, .. })
                    if problem_type == "invalid-request" =>
                {
                    Ok(None)
                }
                other => other.map(Some),
            }
        })?;
        self.state().totp_setup = None;
        match confirmed {
            Some(recovery_codes) => Ok(TotpConfirmed { recovery_codes }),
            None => Err(ErrorCode::TwoStepExpired.into()),
        }
    }

    /// Replaces every recovery code; the new ones are shown once.
    pub fn renew_recovery_codes(&self, password: Zeroizing<String>) -> Result<Vec<String>> {
        let unlocked = self.unlocked()?;
        let _io = self.io();
        self.with_reauth(&unlocked, &password, |token, reauth| {
            unlocked.server.renew_recovery_codes(token.into(), reauth)
        })
    }

    /// Turns two-step sign-in off: the authenticator, security keys and recovery codes go.
    pub fn disable_two_step(&self, password: Zeroizing<String>) -> Result<()> {
        let unlocked = self.unlocked()?;
        let _io = self.io();
        self.with_reauth(&unlocked, &password, |token, reauth| {
            unlocked.server.disable_two_step(token.into(), reauth)
        })
    }

    /// Security keys can't be added here, but the ones added in a browser can be removed.
    pub fn remove_security_key(&self, id: &str, password: Zeroizing<String>) -> Result<()> {
        let unlocked = self.unlocked()?;
        let _io = self.io();
        self.with_reauth(&unlocked, &password, |token, reauth| {
            unlocked
                .server
                .remove_security_key(token.into(), reauth, id.to_owned())
        })
    }

    // ---------- Device unlock (Face ID, Touch ID or the passcode) ----------

    pub fn unlock_methods(&self) -> UnlockMethods {
        let lock = self.native.device_lock();
        let status = self
            .current_account()
            .and_then(|account| self.open_store(&account))
            .map(|store| store.device_unlock_status())
            .ok();
        UnlockMethods {
            device_unlock_supported: lock.available,
            device_unlock_enabled: status.is_some_and(|status| status.enabled),
            label: lock.label,
            platform: platform_name(&self.config.device.platform),
            password_required: status.is_some_and(|status| status.password_required),
        }
    }

    pub fn enable_device_unlock(&self) -> Result<()> {
        let unlocked = self.unlocked()?;
        require(
            self.native.device_lock().available,
            ErrorCode::DeviceUnlockUnsupported,
        )?;
        let mut secret = Zeroizing::new([0u8; 32]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, secret.as_mut());
        self.native
            .store_device_secret(&unlocked.account.device_secret_name(), secret.as_ref())?;
        unlocked
            .store
            .enable_device_unlock(unlocked.session.clone(), secret.to_vec())?;
        Ok(())
    }

    pub fn disable_device_unlock(&self) -> Result<()> {
        let account = self.current_account()?;
        self.open_store(&account)?.disable_device_unlock()?;
        self.native
            .delete_device_secret(&account.device_secret_name())
    }

    /// Every event that ends device unlock (plan 03: a master password change or reset, a key
    /// rotation, a new store for the account, forgetting it) also ends the stay-unlocked key
    /// (plan 18).
    pub(crate) fn delete_device_keys(&self, account: &Account) -> Result<()> {
        self.native
            .delete_device_secret(&account.device_secret_name())?;
        self.native
            .delete_stay_unlocked_key(&account.stay_unlocked_name())
    }

    // ---------- Stay unlocked while logged in to this phone (plan 18) ----------

    /// What Settings shows for stay unlocked, and whether the app may open without a prompt.
    pub fn stay_unlocked_status(&self) -> StayUnlockedStatus {
        let available = self.native.device_lock().available;
        let account = self.current_account().ok();
        let enrolled = account.as_ref().is_some_and(|account| {
            self.native
                .stay_unlocked_key(&account.stay_unlocked_name())
                .is_ok_and(|key| key.is_some())
        });
        let password_required = account
            .and_then(|account| self.open_store(&account).ok())
            .is_some_and(|store| store.password_required());
        StayUnlockedStatus {
            available,
            enrolled,
            password_required,
        }
    }

    /// Keeps a stay-unlocked key for the open account behind the phone's own lock. Fails with
    /// `deviceUnlockUnsupported` on a phone with no passcode (it falls back to locking as before).
    pub fn enable_stay_unlocked(&self) -> Result<()> {
        let unlocked = self.unlocked()?;
        require(
            self.native.device_lock().available,
            ErrorCode::DeviceUnlockUnsupported,
        )?;
        let key = Zeroizing::new(unlocked.store.stay_unlocked_key(unlocked.session.clone())?);
        self.native
            .store_stay_unlocked_key(&unlocked.account.stay_unlocked_name(), &key)
    }

    /// Forgets the key: the next start asks as before.
    pub fn disable_stay_unlocked(&self) -> Result<()> {
        let account = self.current_account()?;
        self.native
            .delete_stay_unlocked_key(&account.stay_unlocked_name())
    }

    /// Opens the current account with its stay-unlocked key, without a prompt. `Ok(false)` when
    /// there's no key (never set up, turned off, or the phone dropped it when its passcode was
    /// removed). Fails with `passwordRequired` while the 14-day check is due; a key that no
    /// longer opens the account is deleted.
    pub fn unlock_stay_unlocked(&self) -> Result<bool> {
        let account = self.current_account()?;
        if self.state().unlocked.is_some() {
            return Ok(true);
        }
        let name = account.stay_unlocked_name();
        let Some(key) = self.native.stay_unlocked_key(&name)? else {
            return Ok(false);
        };
        if !self.native.device_lock().available {
            // No passcode any more: nothing guards the key, so it goes.
            self.native.delete_stay_unlocked_key(&name)?;
            return Ok(false);
        }
        let store = self.open_store(&account)?;
        let session = match store.unlock_stay_unlocked(key.to_vec()) {
            Ok(session) => session,
            Err(OctaPassError::DeviceUnlockFailed) => {
                self.native.delete_stay_unlocked_key(&name)?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        self.set_unlocked(account, store, session)?;
        Ok(true)
    }

    pub fn unlock_with_device(&self) -> Result<()> {
        let account = self.current_account()?;
        let store = self.open_store(&account)?;
        let status = store.device_unlock_status();
        require(
            status.enabled && !status.password_required,
            ErrorCode::PasswordRequired,
        )?;
        let secret = self
            .native
            .device_secret(&account.device_secret_name(), UNLOCK_REASON)?;
        let session = store.unlock_with_device(secret.to_vec())?;
        self.set_unlocked(account, store, session)
    }

    /// Checks it's still the owner before a secret is shown as a QR code (plan 01): the master
    /// password if given, otherwise Face ID / Touch ID or the passcode. Unlocked only.
    pub fn confirm_user(&self, password: Option<Zeroizing<String>>) -> Result<()> {
        let unlocked = self.unlocked()?;
        let store = &unlocked.store;
        let session = match password {
            Some(password) if unlocked.account.is_local() => {
                store.unlock_local(password.to_string(), self.chip_secret(&unlocked.account)?)?
            }
            Some(password) => {
                let secret_key = self.secret_key()?;
                store.unlock_with_password(password.to_string(), secret_key)?
            }
            None => {
                let status = store.device_unlock_status();
                require(
                    status.enabled && !status.password_required,
                    ErrorCode::PasswordRequired,
                )?;
                let secret = self
                    .native
                    .device_secret(&unlocked.account.device_secret_name(), CONFIRM_REASON)?;
                store.unlock_with_device(secret.to_vec())?
            }
        };
        session.lock();
        Ok(())
    }

    // ---------- Vault ----------

    /// Shared vaults are named by a record inside them. One whose grant didn't verify is
    /// `untrusted`: it has no items here.
    pub fn list_vaults(&self) -> Result<Vec<VaultView>> {
        let unlocked = self.unlocked()?;
        let untrusted = unlocked.session.untrusted_vaults(&unlocked.store)?;
        let names = vault_names(&self.items()?);
        Ok(unlocked
            .store
            .vaults()
            .iter()
            .map(|record| VaultView::new(record, &names, untrusted.contains(&record.id)))
            .collect())
    }

    /// Every item, the trash included; the UI filters. Shared vaults' name records aren't items.
    pub fn list_items(&self) -> Result<Vec<ItemSummary>> {
        Ok(self
            .items()?
            .iter()
            .filter(|item| !item.is_vault_info())
            .map(ItemSummary::from)
            .collect())
    }

    pub(crate) fn items(&self) -> Result<Vec<Item>> {
        let unlocked = self.unlocked()?;
        Ok(unlocked
            .session
            .decrypt_items(&unlocked.store)?
            .iter()
            .map(Item::from)
            .collect())
    }

    /// Plaintext items outside the trash, for an export the user asked for.
    pub fn live_items(&self) -> Result<Vec<Item>> {
        let mut items = self.items()?;
        items.retain(|item| item.deleted_at.is_none() && !item.is_vault_info());
        Ok(items)
    }

    /// The item for the UI: files still waiting to upload are marked `pending`.
    pub fn get_item(&self, id: &str) -> Result<Item> {
        let unlocked = self.unlocked()?;
        let item = self.stored_item(&unlocked, id)?;
        Ok(self.with_pending_marks(&unlocked, item))
    }

    /// The item exactly as stored.
    fn stored_item(&self, unlocked: &Unlocked, id: &str) -> Result<Item> {
        Ok(Item::from(
            &unlocked.session.decrypt_item(&unlocked.store, id)?,
        ))
    }

    /// Saves to the store at once, then uploads. An edit based on an older revision than the
    /// stored one is saved as a conflict copy instead of overwriting the newer version.
    pub fn save_item(&self, draft: ItemDraft) -> Result<Item> {
        let unlocked = self.unlocked()?;
        if let Some(id) = &draft.id {
            unlocked.store.set_bookkeeping(id, false);
        }
        let id = self.save_draft(&unlocked, draft)?;
        self.upload_quietly(&unlocked);
        (self.listener)(Event::ItemsChanged);
        self.get_item(&id)
    }

    /// `save_item` for a write that isn't an edit: the version it replaces stays out of the
    /// item's history. Unless an edit is already waiting to upload: that one counts as an edit.
    fn save_item_as_bookkeeping(&self, draft: ItemDraft) -> Result<Item> {
        let unlocked = self.unlocked()?;
        let id = draft.id.clone().ok_or(ErrorCode::NotFound)?;
        if !unlocked.store.has_waiting_upload(&id) {
            unlocked.store.set_bookkeeping(&id, true);
        }
        let saved = self.save_draft(&unlocked, draft)?;
        self.upload_quietly(&unlocked);
        (self.listener)(Event::ItemsChanged);
        self.get_item(&saved)
    }

    fn save_draft(&self, unlocked: &Unlocked, draft: ItemDraft) -> Result<String> {
        let (existing, draft) = match &draft.id {
            Some(id) => {
                let previous = self.stored_item(unlocked, id)?;
                if draft
                    .revision
                    .is_some_and(|revision| revision != previous.revision)
                {
                    let copy = ItemDraft {
                        id: None,
                        revision: None,
                        vault_id: previous.vault_id.clone(),
                        ..draft
                    }
                    .with_title_suffix(CONFLICT_SUFFIX)
                    .with_attachments_of(None);
                    (None, copy)
                } else {
                    let draft = draft
                        .with_password_history(&previous, &now())
                        .with_attachments_of(Some(&previous));
                    (Some(previous.id), draft)
                }
            }
            None => (None, draft.with_attachments_of(None)),
        };
        let item = draft.to_core()?;
        Ok(unlocked.session.save_item(
            &unlocked.store,
            &draft.vault_id,
            existing.as_deref(),
            &item,
        )?)
    }

    /// Several new items at once (an import), uploaded together.
    pub fn import_items(&self, drafts: Vec<ItemDraft>) -> Result<usize> {
        let unlocked = self.unlocked()?;
        let count = drafts.len();
        for draft in drafts {
            self.save_draft(&unlocked, ItemDraft { id: None, ..draft })?;
        }
        self.upload_quietly(&unlocked);
        (self.listener)(Event::ItemsChanged);
        Ok(count)
    }

    /// Moves an item to the trash. The trash lives on the server, so this needs the network.
    pub fn delete_item(&self, id: &str) -> Result<()> {
        if self.is_local_unlocked() {
            return self.trash_local(id, true);
        }
        self.trash_call(
            id,
            |item| item.deleted_at.is_some(),
            |base, item| {
                (
                    HttpMethod::Delete,
                    format!("{base}v1/vaults/{}/items/{}", item.vault_id, item.id),
                    vec![("if-match", format!("\"{}\"", item.revision))],
                )
            },
        )
    }

    pub fn restore_item(&self, id: &str) -> Result<()> {
        if self.is_local_unlocked() {
            return self.trash_local(id, false);
        }
        self.trash_call(
            id,
            |item| item.deleted_at.is_none(),
            |base, item| {
                (
                    HttpMethod::Post,
                    format!(
                        "{base}v1/vaults/{}/items/{}/restore",
                        item.vault_id, item.id
                    ),
                    Vec::new(),
                )
            },
        )
    }

    /// `done` says whether an item is already where the call puts it: another device may have
    /// moved it first, and then the server refuses this device's older revision. A sync settles it.
    fn trash_call(
        &self,
        id: &str,
        done: impl Fn(&Item) -> bool,
        request: impl Fn(&str, &Item) -> (HttpMethod, String, Vec<(&'static str, String)>),
    ) -> Result<()> {
        let unlocked = self.unlocked()?;
        require(!unlocked.account.is_local(), ErrorCode::NeedsSync)?;
        let _io = self.io();
        // An item saved here but not uploaded yet must exist on the server first, with its files.
        self.push_changes(&unlocked)?;
        let item = self.stored_item(&unlocked, id)?;
        let vault = unlocked
            .store
            .vaults()
            .into_iter()
            .find(|vault| vault.id == item.vault_id)
            .ok_or(ErrorCode::NotFound)?;
        require(
            vault.role != octapass_api::VaultRole::Read,
            ErrorCode::ReadOnlyVault,
        )?;
        let (method, url, headers) = request(&unlocked.server.base_url(), &item);
        let sent = self.with_token(&unlocked, |token| {
            self.http
                .json::<octapass_api::RevisionResponse>(method, url.clone(), token, &headers)
        });
        if let Err(error) = sent {
            if matches!(
                error.code,
                ErrorCode::ServerUnreachable | ErrorCode::SessionExpired
            ) {
                return Err(error);
            }
            self.pull(&unlocked)?;
            return match self.stored_item(&unlocked, id) {
                Ok(item) if done(&item) => Ok(()),
                Ok(_) => Err(error),
                // Gone altogether (the trash emptied elsewhere): nothing left to move.
                Err(_) => Ok(()),
            };
        }
        self.pull(&unlocked)
    }

    // ---------- Sync ----------

    /// Uploads what was saved here (by the app or the AutoFill extension) and the files
    /// waiting to go up, then pulls what changed elsewhere, and refreshes the AutoFill
    /// suggestions.
    pub fn sync(&self) -> Result<()> {
        let unlocked = self.unlocked()?;
        let _io = self.io();
        unlocked.store.reload()?;
        if unlocked.account.is_local() {
            // No server: only what the AutoFill extension saved to see.
            (self.listener)(Event::ItemsChanged);
            self.publish_identities();
            return Ok(());
        }
        self.push_changes(&unlocked)?;
        self.pull(&unlocked)
    }

    /// The caller holds `io`.
    fn pull(&self, unlocked: &Unlocked) -> Result<()> {
        // Sharing still works without this, so it never stands between the user and the vault.
        // It comes first because this sync may bring grants sealed to the account's ML-KEM key.
        let _ = self.with_token(unlocked, |token| {
            unlocked
                .server
                .ensure_key_record(token, &unlocked.session, &unlocked.store)
        });
        let result = self.with_token(unlocked, |token| {
            unlocked.server.sync(token.into(), unlocked.store.clone())
        });
        if let Err(error) = &result
            && error.code == ErrorCode::AccountDeleted
        {
            self.forget(&unlocked.account)?;
        }
        result?;
        // What it finds shows as an alert.
        let _ = self.with_token(unlocked, |token| {
            unlocked.server.monitor_key_log(token, &unlocked.store)
        });
        (self.listener)(Event::ItemsChanged);
        self.publish_identities();
        Ok(())
    }

    /// Uploads after a save; offline, the change waits in the store for the next sync.
    fn upload_quietly(&self, unlocked: &Unlocked) {
        if unlocked.account.is_local() {
            self.publish_identities();
            return;
        }
        let _io = self.io();
        self.push_quietly(unlocked);
    }

    /// Hands the current logins and passkeys to the system's AutoFill suggestions.
    fn publish_identities(&self) {
        let Ok(unlocked) = self.unlocked() else {
            return;
        };
        let published = unlocked
            .session
            .credential_identities(unlocked.store.clone())
            .map_err(VaultError::from)
            .and_then(|identities| self.native.set_credential_identities(&identities));
        if let Err(error) = published {
            (self.listener)(Event::SyncFailed {
                message: format!("AutoFill suggestions: {}", error.message),
            });
        }
    }

    pub(crate) fn io(&self) -> MutexGuard<'_, ()> {
        self.io
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Runs `call` with an access token, refreshing it once if it expired. The caller holds
    /// `io`.
    pub(crate) fn with_token<T>(
        &self,
        unlocked: &Unlocked,
        call: impl Fn(&str) -> std::result::Result<T, OctaPassError>,
    ) -> Result<T> {
        require(!unlocked.account.is_local(), ErrorCode::NeedsSync)?;
        let cached = match &self.state().access_token {
            Some((tag, token)) if *tag == unlocked.account.tag => Some(token.clone()),
            _ => None,
        };
        let token = match cached {
            Some(token) => token,
            None => self.refresh(unlocked)?,
        };
        match call(&token) {
            Err(OctaPassError::Unauthorized) => Ok(call(&self.refresh(unlocked)?)?),
            result => Ok(result?),
        }
    }

    fn refresh(&self, unlocked: &Unlocked) -> Result<String> {
        let name = unlocked.account.refresh_token_name();
        let refresh_token = self
            .native
            .secret(&name)?
            .ok_or(ErrorCode::SessionExpired)?;
        let tokens = unlocked.server.refresh(refresh_token.to_string())?;
        self.native.set_secret(&name, &tokens.refresh_token)?;
        // Only for a phone that signed in before the server issued these.
        if let Some(token) = &tokens.trusted_device_token {
            self.native
                .set_secret(&unlocked.account.trusted_device_name(), token)?;
        }
        self.state().access_token =
            Some((unlocked.account.tag.clone(), tokens.access_token.clone()));
        Ok(tokens.access_token)
    }

    // ---------- Tools ----------

    /// The code for an item's `totp` field at `at` (Unix milliseconds), or now.
    pub fn totp(&self, totp: &str, at: Option<u64>) -> Result<octapass_ffi::TotpCode> {
        let at = at.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis() as u64)
        });
        octapass_ffi::totp_code(totp.to_owned(), at / 1000)
            .map_err(|_| VaultError::unexpected("invalid one-time code secret"))
    }

    /// How often the password appears in Pwned Passwords. Only the first five hex characters of
    /// its SHA-1 leave the device.
    pub fn check_breached(&self, password: &str) -> Result<u64> {
        use octapass_core::tools::breach::{count_in_range, sha1_range};
        let range = sha1_range(password);
        let body = self
            .http
            .pwned_range(&self.config.pwned_passwords_url, &range.prefix)?;
        Ok(count_in_range(&range.suffix, &body))
    }

    /// Asks the server about one address (email breach alerts, opt-in).
    pub fn lookup_email_breaches(&self, address: &str) -> Result<Vec<octapass_api::EmailBreach>> {
        let unlocked = self.unlocked()?;
        let _io = self.io();
        let url = format!("{}v1/health/breach-email", unlocked.server.base_url());
        let body = octapass_api::BreachEmailRequest {
            email: address.to_owned(),
        };
        let answer: octapass_api::BreachEmailResponse = self.with_token(&unlocked, |token| {
            self.http.post_for_json(url.clone(), token, &body)
        })?;
        Ok(answer.breaches)
    }

    pub(crate) fn pwned_passwords_url(&self) -> &str {
        &self.config.pwned_passwords_url
    }
}

/// The server behind an account. A local vault has none: nothing may reach this address, and
/// `with_token` refuses before anything could.
fn server_of(account: &Account) -> &str {
    if account.is_local() {
        "https://local.invalid"
    } else {
        &account.server_url
    }
}

fn platform_name(platform: &str) -> &'static str {
    match platform {
        "ios" => "ios",
        "android" => "android",
        "macos" => "macos",
        _ => "other",
    }
}

/// Sign-ups in progress are keyed by a random id, never by the email.
fn new_signup_id() -> String {
    let mut bytes = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
