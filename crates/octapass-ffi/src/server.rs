//! The account flows and sync against an Octa Pass server, through the app's `HttpClient`.
//!
//! Every call blocks on the network and some run Argon2id (about a second): call them off the
//! main thread. Tokens stay with the app (Keychain / Keystore-backed storage); each call takes
//! the access token it needs. On `Unauthorized`, refresh and retry; on `AccountDeleted`, wipe the
//! account's local data.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use octapass_api as api;
use octapass_core::account::{NewAccount, new_id};
use octapass_core::item::{merge_hotp_counter, with_newest_hotp};
use octapass_core::kdf::{AccountKeys, KdfParams, normalize_email};
use octapass_core::opaque::{LoginClient, ReauthClient, RegistrationClient};
use octapass_core::secret_key::SecretKey;
use octapass_core::session::Session as CoreSession;
use rand_core::OsRng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::app::{Resolution, Resolve};
use crate::error::{OctaPassError, Result};
use crate::http::{Api, HttpClient, HttpMethod, Reply, problem_name};
use crate::session::{Session, decrypt, encrypt};
use crate::store::{LocalStore, StoredItem, SyncState};
use crate::{now_ms, timestamp};

const CONFLICT_SUFFIX: &str = " (conflicting copy)";

#[derive(uniffi::Object)]
pub struct OctaPassServer {
    pub(crate) api: Api,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SignupMode {
    Open,
    Invite,
    Closed,
}

/// `GET /v1/server-info`
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    pub api_version: u32,
    pub signups: SignupMode,
    pub push_relay: bool,
}

/// Shown in the account's device list.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceInfo {
    /// At most 64 characters, e.g. "Alice's iPhone".
    pub name: String,
    /// `ios` or `android`.
    pub platform: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AuthTokens {
    /// `Authorization: Bearer` token for the other calls.
    pub access_token: String,
    /// For `refresh`. Rotated on every use; presenting an old one signs the device out.
    pub refresh_token: String,
    /// Access token lifetime in seconds.
    pub expires_in: u64,
    /// Keep it (Keychain / Keystore) with the account and pass it to `log_in_trusted` on the
    /// next sign-in from this device, so that sign-in skips the second step. Replaces the one
    /// kept before. A `refresh` returns one only to a device that has none yet. Delete it on
    /// sign-out.
    #[uniffi(default = None)]
    pub trusted_device_token: Option<String>,
}

/// A signed-in, unlocked account. Next: `LocalStore.create`, then `sync`.
#[derive(uniffi::Record)]
pub struct SignedIn {
    pub session: Arc<Session>,
    pub tokens: AuthTokens,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ReauthPurpose {
    DeleteAccount,
    /// Turning two-step sign-in on or off, a new authenticator, new recovery codes, removing a
    /// security key.
    TwoStep,
    /// A new master password (`changeMasterPassword` asks for it itself).
    ChangePassword,
}

/// How `log_in_trusted` ended.
#[derive(uniffi::Enum)]
pub enum LogInResult {
    SignedIn {
        signed_in: SignedIn,
    },
    /// The password and Secret Key were right, and the account asks new devices for a second
    /// step: finish with `second_factor`.
    SecondFactorRequired {
        second_factor: Arc<SecondFactorLogin>,
    },
    /// The password and Secret Key were right, and the account's organisation requires single
    /// sign-on: finish with `sso`.
    SsoRequired {
        sso: Arc<SsoLogin>,
    },
}

/// A way to finish two-step sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SecondFactorMethod {
    /// A 6-digit code from an authenticator app.
    Totp,
    /// A security key or passkey. It only works where WebAuthn runs for the server's relying
    /// party id (the web vault's host), so the apps don't offer it.
    SecurityKey,
    /// One of the single-use recovery codes (`ABCDE-12345`).
    RecoveryCode,
}

/// A security key registered for two-step sign-in (in a browser).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SecurityKeyInfo {
    pub id: String,
    pub name: String,
    /// RFC 3339.
    pub created_at: String,
    /// RFC 3339, the last sign-in with it.
    pub last_used_at: Option<String>,
}

/// `GET /v1/account/two-step`
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TwoStepStatus {
    pub enabled: bool,
    /// Empty when two-step sign-in is off.
    pub methods: Vec<SecondFactorMethod>,
    pub security_keys: Vec<SecurityKeyInfo>,
    pub recovery_codes_left: u32,
    /// The WebAuthn relying party id security keys belong to.
    pub rp_id: String,
}

/// A new authenticator secret, not active until `confirm_totp_setup`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TotpSetup {
    pub setup_id: String,
    /// Base32, for typing into an authenticator app.
    pub secret: String,
    /// `otpauth://totp/…`, for a QR code or a link to the authenticator app.
    pub otpauth_uri: String,
    /// Seconds until the setup expires.
    pub expires_in: u64,
}

#[uniffi::export]
impl OctaPassServer {
    /// `base_url` must be `https` (`http` only for `localhost` and loopback addresses).
    #[uniffi::constructor]
    pub fn new(base_url: String, http: Arc<dyn HttpClient>) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            api: Api::new(&base_url, http)?,
        }))
    }

    /// The normalised base URL, to store with the account.
    pub fn base_url(&self) -> String {
        self.api.base_url().to_owned()
    }

    /// Fails with `InvalidResponse` for servers that don't speak API v1.
    pub fn server_info(&self) -> Result<ServerInfo> {
        let info: api::ServerInfo = self.api.get("v1/server-info", None)?;
        if info.api_version != api::API_VERSION {
            return Err(OctaPassError::InvalidResponse);
        }
        Ok(ServerInfo {
            name: info.name,
            version: info.version,
            api_version: info.api_version,
            signups: match info.signups {
                api::SignupMode::Open => SignupMode::Open,
                api::SignupMode::Invite => SignupMode::Invite,
                api::SignupMode::Closed => SignupMode::Closed,
            },
            push_relay: info.push_relay,
        })
    }

    /// Creates every key of a new account (Argon2id) and registers it; the server emails a
    /// verification code. Show the Secret Key and recovery code from the result in the Recovery
    /// Kit, then call `finish` with the code.
    pub fn start_signup(&self, email: String, password: String) -> Result<Arc<Signup>> {
        let password = Zeroizing::new(password);
        let account =
            NewAccount::create(&email, &password, KdfParams::DEFAULT, now_ms(), &mut OsRng)?;
        self.start_signup_for(account)
    }

    /// Signs in with email, master password and Secret Key (needed on every new device), and
    /// unlocks. Wrong credentials fail with `LoginFailed`, whichever was wrong.
    pub fn log_in(
        &self,
        email: String,
        password: String,
        secret_key: String,
        device: DeviceInfo,
    ) -> Result<SignedIn> {
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let email = normalize_email(&email);
        let keys = self.derive_keys(&email, &password, &secret_key)?;
        match log_in_with_keys(&self.api, &email, keys, device, None)? {
            LogInResult::SignedIn { signed_in } => Ok(signed_in),
            LogInResult::SecondFactorRequired { .. } => Err(OctaPassError::Server {
                status: 401,
                problem_type: "second-factor-required".into(),
                detail: None,
            }),
            LogInResult::SsoRequired { .. } => Err(OctaPassError::Server {
                status: 401,
                problem_type: "sso-required".into(),
                detail: None,
            }),
        }
    }

    /// `log_in` for accounts that may have two-step sign-in: sends this device's trusted-device
    /// token (from `AuthTokens`), which skips the second step while it's valid, and returns the
    /// second step instead of failing when the account asks for one.
    pub fn log_in_trusted(
        &self,
        email: String,
        password: String,
        secret_key: String,
        device: DeviceInfo,
        trusted_device_token: Option<String>,
    ) -> Result<LogInResult> {
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let email = normalize_email(&email);
        let keys = self.derive_keys(&email, &password, &secret_key)?;
        log_in_with_keys(&self.api, &email, keys, device, trusted_device_token)
    }

    pub fn refresh(&self, refresh_token: String) -> Result<AuthTokens> {
        let tokens: api::RefreshResponse = self.api.post(
            "v1/auth/refresh",
            None,
            &api::RefreshRequest { refresh_token },
        )?;
        Ok(AuthTokens {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
            trusted_device_token: tokens.trusted_device_token,
        })
    }

    /// Revokes this device's tokens. Delete the local store and device secret too.
    pub fn log_out(&self, access_token: String) -> Result<()> {
        self.api
            .call::<()>(
                HttpMethod::Post,
                "v1/auth/logout",
                Some(&access_token),
                &[],
                None::<&()>,
            )?
            .into_result()
    }

    /// Re-authenticates with the master password before a dangerous action and returns the
    /// single-use reauth token (valid 5 minutes). Fails with `LoginFailed` before sending
    /// anything if the password or Secret Key don't unlock this account. The session isn't
    /// changed.
    pub fn reauth(
        &self,
        access_token: String,
        session: Arc<Session>,
        password: String,
        secret_key: String,
        purpose: ReauthPurpose,
    ) -> Result<String> {
        let purpose = match purpose {
            ReauthPurpose::DeleteAccount => api::ReauthPurpose::DeleteAccount,
            ReauthPurpose::TwoStep => api::ReauthPurpose::TwoStep,
            ReauthPurpose::ChangePassword => api::ReauthPurpose::ChangePassword,
        };
        self.reauth_as(access_token, session, password, secret_key, purpose)
    }

    /// Deletes the account and everything in it, for good (plan 11). Needs a `DeleteAccount`
    /// reauth token and the account email typed by the user. Then wipe all local data.
    pub fn delete_account(
        &self,
        access_token: String,
        reauth_token: String,
        confirm_email: String,
    ) -> Result<()> {
        self.api
            .call::<()>(
                HttpMethod::Delete,
                "v1/account",
                Some(&access_token),
                &[(api::REAUTH_TOKEN_HEADER, reauth_token)],
                Some(&api::DeleteAccountRequest { confirm_email }),
            )?
            .into_result()
    }

    /// Two-step sign-in: whether it's on, and with what.
    pub fn two_step_status(&self, access_token: String) -> Result<TwoStepStatus> {
        let status: api::TwoStepStatus =
            self.api.get("v1/account/two-step", Some(&access_token))?;
        Ok(TwoStepStatus {
            enabled: status.enabled,
            methods: status
                .methods
                .iter()
                .map(|method| (*method).into())
                .collect(),
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
            rp_id: status.rp_id,
        })
    }

    /// Starts adding (or replacing) the authenticator app. Needs a `TwoStep` reauth token.
    /// Nothing changes until `confirm_totp_setup`.
    pub fn start_totp_setup(
        &self,
        access_token: String,
        reauth_token: String,
    ) -> Result<TotpSetup> {
        let setup: api::TotpSetupResponse = self
            .api
            .call(
                HttpMethod::Post,
                "v1/account/two-step/totp",
                Some(&access_token),
                &[(api::REAUTH_TOKEN_HEADER, reauth_token)],
                None::<&()>,
            )?
            .into_result()?;
        Ok(TotpSetup {
            setup_id: setup.setup_id,
            secret: setup.secret,
            otpauth_uri: setup.otpauth_uri,
            expires_in: setup.expires_in,
        })
    }

    /// Checks the first code from the new authenticator and turns two-step sign-in on, or swaps
    /// the authenticator. Returns the recovery codes when this turned it on (show them once),
    /// otherwise `None`. A wrong code fails with `Server { problem_type: "invalid-second-factor" }`
    /// and can be tried again; an expired setup with `Server { problem_type: "invalid-request" }`.
    pub fn confirm_totp_setup(
        &self,
        access_token: String,
        setup_id: String,
        code: String,
    ) -> Result<Option<Vec<String>>> {
        let confirmed: api::TotpConfirmResponse = self.api.post(
            "v1/account/two-step/totp/confirm",
            Some(&access_token),
            &api::TotpConfirmRequest { setup_id, code },
        )?;
        Ok(confirmed.recovery_codes)
    }

    /// Replaces every recovery code. Needs a `TwoStep` reauth token. Show the new ones once.
    pub fn renew_recovery_codes(
        &self,
        access_token: String,
        reauth_token: String,
    ) -> Result<Vec<String>> {
        let renewed: api::RecoveryCodesResponse = self
            .api
            .call(
                HttpMethod::Post,
                "v1/account/two-step/recovery-codes",
                Some(&access_token),
                &[(api::REAUTH_TOKEN_HEADER, reauth_token)],
                None::<&()>,
            )?
            .into_result()?;
        Ok(renewed.recovery_codes)
    }

    /// Turns two-step sign-in off: the authenticator, security keys and recovery codes are
    /// removed. Needs a `TwoStep` reauth token.
    pub fn disable_two_step(&self, access_token: String, reauth_token: String) -> Result<()> {
        self.api
            .call::<()>(
                HttpMethod::Delete,
                "v1/account/two-step",
                Some(&access_token),
                &[(api::REAUTH_TOKEN_HEADER, reauth_token)],
                None::<&()>,
            )?
            .into_result()
    }

    /// Removes a security key (they're added in a browser). Needs a `TwoStep` reauth token.
    pub fn remove_security_key(
        &self,
        access_token: String,
        reauth_token: String,
        id: String,
    ) -> Result<()> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(OctaPassError::Server {
                status: 404,
                problem_type: "not-found".into(),
                detail: None,
            });
        }
        self.api
            .call::<()>(
                HttpMethod::Delete,
                &format!("v1/account/two-step/security-keys/{id}"),
                Some(&access_token),
                &[(api::REAUTH_TOKEN_HEADER, reauth_token)],
                None::<&()>,
            )?
            .into_result()
    }

    /// Fetches what changed since the last sync into the store, page by page.
    pub fn sync(&self, access_token: String, store: Arc<LocalStore>) -> Result<()> {
        loop {
            let since = store.data().sync_cursor();
            let path = match since.as_str() {
                "" => "v1/sync".to_owned(),
                since => format!("v1/sync?since={since}"),
            };
            let response: api::SyncResponse = self.api.get(&path, Some(&access_token))?;
            let has_more = response.has_more;
            // Each page's vault revisions are where the next one starts.
            let cursor = store.mutate(|data| {
                data.apply_sync(response);
                Ok(data.sync_cursor())
            })?;
            // A vault waiting for its new key stays where it was, and would answer the same again.
            if !has_more || cursor == since {
                return Ok(());
            }
        }
    }

    /// Uploads the items saved or changed on this device (new logins, passkeys). An item that
    /// changed on the server meanwhile is kept as the server has it, and this device's version
    /// is saved next to it as "<title> (conflicting copy)", so nothing is lost. The copy leaves
    /// out the item's attachments: their keys are bound to the original item.
    pub fn upload_pending(
        &self,
        access_token: String,
        session: Arc<Session>,
        store: Arc<LocalStore>,
    ) -> Result<()> {
        self.upload_pending_resolving(access_token, session, store, &|_, local, _| {
            Resolution::copy(local)
        })
    }
}

impl OctaPassServer {
    /// `start_signup` for keys that already exist: a local vault turning on sync keeps its own
    /// (Rust-only).
    pub fn start_signup_for(&self, account: NewAccount) -> Result<Arc<Signup>> {
        let (registration, registration_request) =
            RegistrationClient::start(&account.keys.auth_secret, &mut OsRng)?;
        let started: api::RegisterStartResponse = self.api.post(
            "v1/auth/register/start",
            None,
            &api::RegisterStartRequest {
                email: account.bundle.email.clone(),
                registration_request,
            },
        )?;
        let registration_upload = registration.finish(
            &account.keys.auth_secret,
            &started.registration_response,
            &mut OsRng,
        )?;
        Ok(Arc::new(Signup {
            api: self.api.clone(),
            account,
            registration_upload,
            dev_verification_code: started.dev_verification_code,
            state: Mutex::new(SignupState::Started),
        }))
    }

    /// `upload_pending`, with `resolve` deciding what happens to an item that changed both here
    /// and on the server (Rust-only, for the app's attachment changes; see `app.rs`).
    pub fn upload_pending_resolving(
        &self,
        access_token: String,
        session: Arc<Session>,
        store: Arc<LocalStore>,
        resolve: Resolve<'_>,
    ) -> Result<()> {
        store.check_account(&session)?;
        let mut queue: VecDeque<String> = store
            .data()
            .items
            .iter()
            .filter(|(_, item)| item.sync != SyncState::Synced)
            .map(|(id, _)| id.clone())
            .collect();
        let mut recreated = HashSet::new();
        let mut merged = HashSet::new();
        let mut rekeyed = HashSet::new();
        while let Some(item_id) = queue.pop_front() {
            let Some(sent) = store.data().items.get(&item_id).cloned() else {
                continue;
            };
            let precondition = match sent.sync {
                SyncState::Synced => continue,
                SyncState::Changed => ("if-match", format!("\"{}\"", sent.record.revision)),
                SyncState::New => ("if-none-match", "*".to_owned()),
            };
            let record = &sent.record;
            let reply = self.api.call::<api::RevisionResponse>(
                HttpMethod::Put,
                &format!("v1/vaults/{}/items/{}", record.vault_id, record.id),
                Some(&access_token),
                &[precondition],
                Some(&api::PutItemRequest {
                    encrypted_item_key: record.encrypted_item_key.clone(),
                    overview: record.overview.clone(),
                    details: record.details.clone(),
                    skip_history: store.is_bookkeeping(&item_id),
                }),
            )?;
            match reply {
                Reply::Ok(saved) => store
                    .mutate(|data| {
                        if let Some(current) = data.items.get_mut(&item_id) {
                            // Changed again while uploading: the upload is the new base.
                            current.sync = if current.record == sent.record {
                                SyncState::Synced
                            } else {
                                SyncState::Changed
                            };
                            current.record.revision = saved.revision;
                        }
                        Ok(())
                    })
                    .map(|()| store.set_bookkeeping(&item_id, false))?,
                // The item is gone from the server: create it again, once.
                Reply::Problem(404, _)
                    if sent.sync == SyncState::Changed && recreated.insert(item_id.clone()) =>
                {
                    store.mutate(|data| {
                        if let Some(current) = data.items.get_mut(&item_id) {
                            current.sync = SyncState::New;
                        }
                        Ok(())
                    })?;
                    queue.push_back(item_id);
                }
                // The vault's key was rotated elsewhere: move what's waiting here onto the new
                // key. Every revision moved on, so a change to an existing item then goes through
                // the conflict path, and nothing is lost.
                Reply::Problem(409, problem)
                    if problem_name(&problem) == "vault-key-changed"
                        && rekeyed.insert(sent.record.vault_id.clone()) =>
                {
                    self.rekey_vault(&access_token, &session, &store, &sent.record.vault_id)?;
                    queue.push_front(item_id);
                }
                Reply::Problem(409, problem) if problem_name(&problem) == "conflict" => {
                    let settled =
                        self.settle_conflict(&session, &store, &sent, problem.current, resolve)?;
                    // A merge goes up on top of the server's version, once per upload: if that
                    // conflicts too, it waits for the next sync.
                    if settled.merged && merged.insert(item_id.clone()) {
                        queue.push_back(item_id);
                    }
                    queue.extend(settled.copy_id);
                }
                problem => problem.into_result().map(|_| ())?,
            }
        }
        Ok(())
    }

    /// Fetches a vault's rotated record, moves what's waiting in `store` onto its key, and syncs.
    fn rekey_vault(
        &self,
        access_token: &str,
        session: &Session,
        store: &Arc<LocalStore>,
        vault_id: &str,
    ) -> Result<()> {
        let since = store.data().sync_cursor();
        let response: api::SyncResponse = self
            .api
            .get(&format!("v1/sync?since={since}"), Some(access_token))?;
        // Gone means this account lost the vault: the sync below drops its items.
        if let Some(vault) = response.vaults.iter().find(|vault| vault.id == vault_id) {
            session.rekey_vault(store, vault)?;
        }
        self.sync(access_token.to_owned(), Arc::clone(store))
    }

    /// `reauth`, for any purpose: some aren't named in the bindings (Rust only).
    pub(crate) fn reauth_as(
        &self,
        access_token: String,
        session: Arc<Session>,
        password: String,
        secret_key: String,
        purpose: api::ReauthPurpose,
    ) -> Result<String> {
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let bundle = session.with(|core| Ok(core.bundle().clone()))?;
        let keys = AccountKeys::derive(
            &password,
            &secret_key,
            &bundle.email,
            &bundle.account_salt_bytes()?,
            &bundle.kdf,
        )?;
        CoreSession::unlock(bundle, &keys.auk)?;
        let (client, credential_request) = ReauthClient::start(&keys.auth_secret, &mut OsRng)?;
        let started: api::ReauthStartResponse = self.api.post(
            "v1/auth/reauth/start",
            Some(&access_token),
            &api::ReauthStartRequest { credential_request },
        )?;
        let credential_finalization =
            client.finish(&keys.auth_secret, &started.credential_response, &mut OsRng)?;
        let finished: api::ReauthFinishResponse = self.api.post(
            "v1/auth/reauth/finish",
            Some(&access_token),
            &api::ReauthFinishRequest {
                reauth_id: started.reauth_id,
                credential_finalization,
                purpose,
            },
        )?;
        Ok(finished.reauth_token)
    }

    /// Argon2id over the server's parameters for `email`.
    fn derive_keys(
        &self,
        email: &str,
        password: &str,
        secret_key: &SecretKey,
    ) -> Result<AccountKeys> {
        let prelogin: api::PreloginResponse = self.api.post(
            "v1/auth/prelogin",
            None,
            &api::PreloginRequest {
                email: email.to_owned(),
            },
        )?;
        let kdf: KdfParams = convert(&prelogin.kdf)?;
        let account_salt = octapass_core::encoding::b64_decode(&prelogin.account_salt)
            .map_err(|_| OctaPassError::InvalidResponse)?;
        Ok(AccountKeys::derive(
            password,
            secret_key,
            email,
            &account_salt,
            &kdf,
        )?)
    }

    /// Keeps the server's version of a conflicting item, with what `resolve` merged into it
    /// saved on top, and saves the copy `resolve` asked for as a new item.
    fn settle_conflict(
        &self,
        session: &Session,
        store: &LocalStore,
        sent: &StoredItem,
        current: Option<api::ItemRecord>,
        resolve: Resolve<'_>,
    ) -> Result<Settled> {
        let vault_id = sent.record.vault_id.clone();
        let copy_id = new_id(now_ms(), &mut OsRng);
        let current = current.map(|record| StoredItem {
            record,
            sync: SyncState::Synced,
        });
        let (merged, copy) = session.with_store(store, |core, data| {
            let local = decrypt(core, data, &sent.record)?;
            let server = match &current {
                Some(current) => Some(decrypt(core, data, &current.record)?),
                None => None,
            };
            // A waiting bookkeeping write changed nothing but the counter, whatever the server
            // changed meanwhile. Without that mark, only an upload that differs in the counter alone
            // merges.
            let moved_counter = store.is_bookkeeping(&sent.record.id);
            let counter_only = server.as_ref().and_then(|server| {
                if moved_counter {
                    with_newest_hotp(&local, server)
                } else {
                    merge_hotp_counter(&local, server)
                }
            });
            let resolution = match counter_only {
                Some(merged) => Resolution {
                    merged: Some(merged),
                    copy: None,
                },
                None => resolve(&sent.record.id, &local, server.as_ref()),
            };
            let merged = match (resolution.merged, &current) {
                (Some(item), Some(current)) => Some(encrypt(
                    core,
                    data,
                    &current.record.vault_id,
                    &current.record.id,
                    &item,
                    Some(current),
                )?),
                _ => None,
            };
            let copy = match resolution.copy {
                Some(mut item) => {
                    item.overview.title.push_str(CONFLICT_SUFFIX);
                    Some(encrypt(core, data, &vault_id, &copy_id, &item, None)?)
                }
                None => None,
            };
            Ok((merged, copy))
        })?;
        store.mutate(|data| {
            let now = timestamp(now_ms());
            let mut merged_saved = false;
            if data.items.get(&sent.record.id) == Some(sent) {
                match current {
                    Some(current) => {
                        let id = current.record.id.clone();
                        let vault_id = current.record.vault_id.clone();
                        data.items.insert(id.clone(), current.clone());
                        if let Some(merged) = merged {
                            data.put_local(&vault_id, &id, merged, Some(&current), &now);
                            merged_saved = true;
                        }
                    }
                    // The next sync brings whatever the server holds under this id.
                    None => {
                        data.items.remove(&sent.record.id);
                    }
                }
            }
            let copy_id = copy.map(|copy| {
                data.put_local(&vault_id, &copy_id, copy, None, &now);
                copy_id
            });
            Ok(Settled {
                merged: merged_saved,
                copy_id,
            })
        })
    }
}

/// What `settle_conflict` saved: the merge over the server's version, and the copy's id.
struct Settled {
    merged: bool,
    copy_id: Option<String>,
}

enum SignupState {
    Started,
    /// `register/finish` succeeded; only the login is left.
    Registered,
    Finished,
}

/// Sign-up between `register/start` and the verification code. Holds the new account's keys
/// until it's dropped.
#[derive(uniffi::Object)]
pub struct Signup {
    api: Api,
    account: NewAccount,
    registration_upload: String,
    dev_verification_code: Option<String>,
    state: Mutex<SignupState>,
}

#[uniffi::export]
impl Signup {
    /// The normalised email.
    pub fn email(&self) -> String {
        self.account.bundle.email.clone()
    }

    /// `OP1-…`: for the Recovery Kit, and to keep on this device (Keychain / Keystore).
    pub fn secret_key(&self) -> String {
        self.account.secret_key.to_text().to_string()
    }

    /// For the Recovery Kit only. Never store it.
    pub fn recovery_code(&self) -> String {
        self.account.recovery_code.to_text().to_string()
    }

    /// The code itself, when the server runs in development mode.
    pub fn dev_verification_code(&self) -> Option<String> {
        self.dev_verification_code.clone()
    }

    /// Finishes sign-up with the emailed code and signs in. After `InvalidVerificationCode` or
    /// a network error, call it again.
    pub fn finish(&self, verification_code: String, device: DeviceInfo) -> Result<SignedIn> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let SignupState::Finished = *state {
            return Err(OctaPassError::FlowFinished);
        }
        if let SignupState::Started = *state {
            let _: api::RegisterFinishResponse = self.api.post(
                "v1/auth/register/finish",
                None,
                &api::RegisterFinishRequest {
                    email: self.account.bundle.email.clone(),
                    verification_code,
                    registration_upload: self.registration_upload.clone(),
                    account: convert(&self.account.bundle)?,
                    personal_vault: convert(&self.account.personal_vault)?,
                },
            )?;
            *state = SignupState::Registered;
        }
        // A new account has no second step yet.
        let LogInResult::SignedIn { signed_in } = log_in_with_keys(
            &self.api,
            &self.account.bundle.email,
            self.account.keys.clone(),
            device,
            None,
        )?
        else {
            return Err(OctaPassError::InvalidResponse);
        };
        *state = SignupState::Finished;
        Ok(signed_in)
    }
}

/// A sign-in waiting for the identity provider. Holds the account's keys until it's dropped: SSO
/// decides only whether the sign-in may go on, and those keys still come from the password.
#[derive(uniffi::Object)]
pub struct SsoLogin {
    api: Api,
    email: String,
    keys: AccountKeys,
    challenge_id: String,
    url: String,
    org_name: String,
    expires_in: u64,
    finished: Mutex<bool>,
}

#[uniffi::export]
impl SsoLogin {
    /// Open this in a browser. It ends on a page with a 6-digit code.
    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn org_name(&self) -> String {
        self.org_name.clone()
    }

    /// Seconds the server waits.
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }

    /// Finishes with the code the browser showed. It can end in `SecondFactorRequired`. A wrong
    /// code fails with `Server { problem_type: "invalid-second-factor" }`, a browser that hasn't
    /// finished with `"sso-pending"`, and both can be tried again; `LoginFailed` means sign in
    /// again.
    pub fn finish(&self, code: String) -> Result<LogInResult> {
        let mut finished = self
            .finished
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *finished {
            return Err(OctaPassError::FlowFinished);
        }
        let reply = self.api.call::<api::LoginFinishResponse>(
            HttpMethod::Post,
            "v1/auth/login/sso",
            None,
            &[],
            Some(&api::SsoLoginRequest {
                challenge_id: self.challenge_id.clone(),
                code: code.split_whitespace().collect(),
            }),
        )?;
        let result = login_result(&self.api, &self.email, self.keys.clone(), reply)?;
        *finished = true;
        Ok(result)
    }
}

/// A sign-in waiting for its second step. Holds the account's keys until it's dropped.
#[derive(uniffi::Object)]
pub struct SecondFactorLogin {
    api: Api,
    email: String,
    keys: AccountKeys,
    challenge_id: String,
    methods: Vec<SecondFactorMethod>,
    expires_in: u64,
    finished: Mutex<bool>,
}

#[uniffi::export]
impl SecondFactorLogin {
    /// What the server accepts. Offer only what the app can do (not `SecurityKey`).
    pub fn methods(&self) -> Vec<SecondFactorMethod> {
        self.methods.clone()
    }

    /// Seconds the server waits for the second step.
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }

    /// Finishes with a code from the authenticator app. A wrong code fails with
    /// `Server { problem_type: "invalid-second-factor" }` and can be tried again (a few times);
    /// `LoginFailed` means the challenge expired or had too many wrong tries: sign in again.
    pub fn finish_with_totp(&self, code: String) -> Result<SignedIn> {
        self.finish(api::SecondFactorRequest {
            challenge_id: self.challenge_id.clone(),
            totp_code: Some(code.trim().to_owned()),
            recovery_code: None,
            webauthn: None,
        })
    }

    /// Finishes with a recovery code, which then stops working. Errors as `finish_with_totp`.
    pub fn finish_with_recovery_code(&self, code: String) -> Result<SignedIn> {
        self.finish(api::SecondFactorRequest {
            challenge_id: self.challenge_id.clone(),
            totp_code: None,
            recovery_code: Some(code.trim().to_owned()),
            webauthn: None,
        })
    }
}

impl SecondFactorLogin {
    fn finish(&self, request: api::SecondFactorRequest) -> Result<SignedIn> {
        let mut finished = self
            .finished
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *finished {
            return Err(OctaPassError::FlowFinished);
        }
        let response: api::LoginFinishResponse =
            self.api
                .post("v1/auth/login/second-factor", None, &request)?;
        let signed_in = signed_in(&self.email, &self.keys, response)?;
        *finished = true;
        Ok(signed_in)
    }
}

impl From<api::SecondFactorMethod> for SecondFactorMethod {
    fn from(method: api::SecondFactorMethod) -> Self {
        match method {
            api::SecondFactorMethod::Totp => Self::Totp,
            api::SecondFactorMethod::Webauthn => Self::SecurityKey,
            api::SecondFactorMethod::RecoveryCode => Self::RecoveryCode,
        }
    }
}

/// OPAQUE login with keys already derived, then unlock with the bundle the server returns, or
/// the second step the account asks for.
fn log_in_with_keys(
    api_client: &Api,
    email: &str,
    keys: AccountKeys,
    device: DeviceInfo,
    trusted_device_token: Option<String>,
) -> Result<LogInResult> {
    let (client, credential_request) = LoginClient::start(&keys.auth_secret, &mut OsRng)?;
    let started: api::LoginStartResponse = api_client.post(
        "v1/auth/login/start",
        None,
        &api::LoginStartRequest {
            email: email.to_owned(),
            credential_request,
        },
    )?;
    let credential_finalization =
        client.finish(&keys.auth_secret, &started.credential_response, &mut OsRng)?;
    let reply = api_client.call::<api::LoginFinishResponse>(
        HttpMethod::Post,
        "v1/auth/login/finish",
        None,
        &[],
        Some(&api::LoginFinishRequest {
            login_id: started.login_id,
            credential_finalization,
            device: api::DeviceInfo {
                name: device.name,
                platform: device.platform,
            },
            trusted_device_token,
        }),
    )?;
    login_result(api_client, email, keys, reply)
}

/// What a server's answer to a login step means: signed in, or which step comes next.
fn login_result(
    api_client: &Api,
    email: &str,
    keys: AccountKeys,
    reply: Reply<api::LoginFinishResponse>,
) -> Result<LogInResult> {
    let finished = match reply {
        Reply::Problem(_, problem)
            if problem_name(&problem) == "sso-required" && problem.sso.is_some() =>
        {
            let challenge = problem.sso.expect("checked above");
            return Ok(LogInResult::SsoRequired {
                sso: Arc::new(SsoLogin {
                    api: api_client.clone(),
                    email: email.to_owned(),
                    keys,
                    challenge_id: challenge.challenge_id,
                    url: challenge.url,
                    org_name: challenge.org_name,
                    expires_in: challenge.expires_in,
                    finished: Mutex::new(false),
                }),
            });
        }
        Reply::Problem(_, problem)
            if problem_name(&problem) == "second-factor-required"
                && problem.second_factor.is_some() =>
        {
            let challenge = problem.second_factor.expect("checked above");
            return Ok(LogInResult::SecondFactorRequired {
                second_factor: Arc::new(SecondFactorLogin {
                    api: api_client.clone(),
                    email: email.to_owned(),
                    keys,
                    challenge_id: challenge.challenge_id,
                    methods: challenge.methods.into_iter().map(Into::into).collect(),
                    expires_in: challenge.expires_in,
                    finished: Mutex::new(false),
                }),
            });
        }
        reply => reply.into_result()?,
    };
    Ok(LogInResult::SignedIn {
        signed_in: signed_in(email, &keys, finished)?,
    })
}

/// Unlocks with the bundle a finished login returned.
fn signed_in(
    email: &str,
    keys: &AccountKeys,
    finished: api::LoginFinishResponse,
) -> Result<SignedIn> {
    let bundle: octapass_core::account::AccountBundle = convert(&finished.account)?;
    if normalize_email(&bundle.email) != email {
        return Err(OctaPassError::InvalidResponse);
    }
    let session = CoreSession::unlock(bundle, &keys.auk)?;
    Ok(SignedIn {
        session: Session::new(session),
        tokens: AuthTokens {
            access_token: finished.access_token,
            refresh_token: finished.refresh_token,
            expires_in: finished.expires_in,
            trusted_device_token: finished.trusted_device_token,
        },
    })
}

/// Between the core's and the API crate's mirror types, which share one JSON form.
fn convert<T: Serialize, U: DeserializeOwned>(value: &T) -> Result<U> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(|_| OctaPassError::InvalidResponse)
}
