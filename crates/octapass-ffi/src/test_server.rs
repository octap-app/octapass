//! An in-process fake of the sync API (plan 11) for the Swift, Kotlin and Rust tests, built only
//! with the `test-server` feature. It runs the real OPAQUE server from `octapass-core` and keeps
//! everything in memory. The tests' native `HttpClient` hands each request to `handle`, so the
//! bindings are exercised exactly as in the apps, minus the network.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use octapass_api::{self as api, ItemRecord, Problem, VaultRecord, VaultRole, VaultType};
use octapass_core::account::new_id;
use octapass_core::encoding::b64_encode;
use octapass_core::kdf::{KdfParams, normalize_email};
use octapass_core::opaque::server::{OpaqueServer, ServerLoginState};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::http::{HttpMethod, HttpRequest, HttpResponse};
use crate::{now_ms, timestamp};

const VERIFICATION_CODE: &str = "123456";
/// The authenticator code that finishes two-step sign-in, whatever the time.
const TWO_STEP_CODE: &str = "654321";
/// The one recovery code; it works once.
const RECOVERY_CODE: &str = "ABCDE-12345";
/// Wrong second steps before a challenge stops working, as on the real server.
const SECOND_FACTOR_TRIES: u32 = 5;

#[derive(uniffi::Object)]
pub struct TestServer {
    opaque: OpaqueServer,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Emails that started registration.
    registering: Vec<String>,
    accounts: HashMap<String, Account>,
    vaults: HashMap<String, Vault>,
    /// Logins and reauths between start and finish, by id: (email, OPAQUE state).
    logins: HashMap<String, (String, ServerLoginState)>,
    access_tokens: HashMap<String, String>,
    refresh_tokens: HashMap<String, String>,
    reauth_tokens: HashMap<String, String>,
    deleted_tokens: Vec<String>,
    /// Accounts with two-step sign-in on, and whether their recovery code is still unused.
    two_step: HashMap<String, bool>,
    /// Sign-ins waiting for their second step, by challenge id: (email, wrong tries).
    challenges: HashMap<String, (String, u32)>,
    /// Trusted-device tokens and their accounts.
    trusted: HashMap<String, String>,
}

struct Account {
    password_file: String,
    bundle: api::AccountBundle,
    vault_id: String,
}

struct Vault {
    record: VaultRecord,
    items: BTreeMap<String, ItemRecord>,
}

type Reply = Result<HttpResponse, HttpResponse>;

#[uniffi::export]
impl TestServer {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            opaque: OpaqueServer::generate(&mut OsRng),
            state: Mutex::default(),
        }
    }

    /// Answers one request as the sync server would. The base URL can be anything.
    pub fn handle(&self, request: HttpRequest) -> HttpResponse {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.route(&mut state, &request)
            .unwrap_or_else(|problem| problem)
    }

    /// Turns two-step sign-in on for an account: the second step then takes the code `654321`
    /// or, once, the recovery code `ABCDE-12345`. Devices signed in before keep their trust.
    pub fn enable_two_step(&self, email: String) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.two_step.insert(normalize_email(&email), true);
    }

    /// How many items the server stores for an account: the tests check that local changes
    /// arrived, still encrypted.
    pub fn item_count(&self, email: String) -> u64 {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state
            .accounts
            .get(&normalize_email(&email))
            .and_then(|account| state.vaults.get(&account.vault_id))
            .map_or(0, |vault| vault.items.len() as u64)
    }
}

impl Default for TestServer {
    fn default() -> Self {
        Self::new()
    }
}

impl TestServer {
    fn route(&self, state: &mut State, request: &HttpRequest) -> Reply {
        let url = request.url.as_str();
        let path = url.find("/v1/").map_or(url, |start| &url[start + 1..]);
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let segments: Vec<&str> = path.split('/').collect();
        match (request.method, segments.as_slice()) {
            (HttpMethod::Get, ["v1", "server-info"]) => ok(&api::ServerInfo {
                name: "Octa Pass test server".into(),
                version: "0.0.0".into(),
                api_version: api::API_VERSION,
                signups: api::SignupMode::Open,
                push_relay: false,
                masked_email_relay: false,
                email_breach_checks: false,
            }),
            (HttpMethod::Post, ["v1", "auth", "prelogin"]) => self.prelogin(state, body(request)?),
            (HttpMethod::Post, ["v1", "auth", "register", "start"]) => {
                self.register_start(state, body(request)?)
            }
            (HttpMethod::Post, ["v1", "auth", "register", "finish"]) => {
                register_finish(state, body(request)?)
            }
            (HttpMethod::Post, ["v1", "auth", "login", "start"]) => {
                let start: api::LoginStartRequest = body(request)?;
                let (login_id, credential_response) =
                    self.login_start(state, &start.email, &start.credential_request)?;
                ok(&api::LoginStartResponse {
                    login_id,
                    credential_response,
                })
            }
            (HttpMethod::Post, ["v1", "auth", "login", "finish"]) => {
                login_finish(state, body(request)?)
            }
            (HttpMethod::Post, ["v1", "auth", "login", "second-factor"]) => {
                second_factor(state, body(request)?)
            }
            (HttpMethod::Post, ["v1", "auth", "refresh"]) => refresh(state, body(request)?),
            (HttpMethod::Post, ["v1", "auth", "logout"]) => {
                // This fake keeps one session per account: logging out ends all of them.
                let email = authenticate(state, request)?;
                state.access_tokens.retain(|_, owner| *owner != email);
                state.refresh_tokens.retain(|_, owner| *owner != email);
                state.trusted.retain(|_, owner| *owner != email);
                no_content()
            }
            (HttpMethod::Post, ["v1", "auth", "reauth", "start"]) => {
                let email = authenticate(state, request)?;
                let start: api::ReauthStartRequest = body(request)?;
                let (reauth_id, credential_response) =
                    self.login_start(state, &email, &start.credential_request)?;
                ok(&api::ReauthStartResponse {
                    reauth_id,
                    credential_response,
                })
            }
            (HttpMethod::Post, ["v1", "auth", "reauth", "finish"]) => {
                let email = authenticate(state, request)?;
                let finish: api::ReauthFinishRequest = body(request)?;
                finish_opaque(
                    state,
                    &finish.reauth_id,
                    &email,
                    &finish.credential_finalization,
                )?;
                let reauth_token = token();
                state.reauth_tokens.insert(reauth_token.clone(), email);
                ok(&api::ReauthFinishResponse {
                    reauth_token,
                    expires_in: 300,
                })
            }
            (HttpMethod::Delete, ["v1", "account"]) => delete_account(state, request),
            (HttpMethod::Get, ["v1", "sync"]) => {
                let email = authenticate(state, request)?;
                sync(state, &email, query)
            }
            (HttpMethod::Put, ["v1", "vaults", vault_id, "items", item_id]) => {
                let email = authenticate(state, request)?;
                put_item(state, &email, vault_id, item_id, request)
            }
            _ => Err(problem(404, "not-found", None)),
        }
    }

    fn prelogin(&self, state: &State, request: api::PreloginRequest) -> Reply {
        let email = normalize_email(&request.email);
        match state.accounts.get(&email) {
            Some(account) => ok(&api::PreloginResponse {
                kdf: account.bundle.kdf,
                account_salt: account.bundle.account_salt.clone(),
            }),
            // Unknown emails get a stable fake salt, as on the real server.
            None => ok(&api::PreloginResponse {
                kdf: convert(&KdfParams::DEFAULT)?,
                account_salt: b64_encode(&Sha256::digest(email.as_bytes())[..16]),
            }),
        }
    }

    fn register_start(&self, state: &mut State, request: api::RegisterStartRequest) -> Reply {
        let email = normalize_email(&request.email);
        let registration_response = self
            .opaque
            .registration_start(&email, &request.registration_request)
            .map_err(|_| invalid())?;
        state.registering.push(email);
        ok(&api::RegisterStartResponse {
            registration_response,
            verification_required: true,
            dev_verification_code: Some(VERIFICATION_CODE.into()),
        })
    }

    fn login_start(
        &self,
        state: &mut State,
        email: &str,
        credential_request: &str,
    ) -> Result<(String, String), HttpResponse> {
        let email = normalize_email(email);
        let password_file = state
            .accounts
            .get(&email)
            .map(|account| account.password_file.as_str());
        let (login, credential_response) = self
            .opaque
            .login_start(&email, password_file, credential_request, &mut OsRng)
            .map_err(|_| invalid())?;
        let login_id = token();
        state.logins.insert(login_id.clone(), (email, login));
        Ok((login_id, credential_response))
    }
}

fn register_finish(state: &mut State, request: api::RegisterFinishRequest) -> Reply {
    let email = normalize_email(&request.email);
    if !state.registering.contains(&email) || request.verification_code != VERIFICATION_CODE {
        return Err(problem(400, "invalid-verification-code", None));
    }
    if state.accounts.contains_key(&email) {
        return Err(problem(409, "account-exists", None));
    }
    let password_file =
        OpaqueServer::registration_finish(&request.registration_upload).map_err(|_| invalid())?;
    let account_id = new_id(now_ms(), &mut OsRng);
    let vault_id = request.personal_vault.id.clone();
    state.vaults.insert(
        vault_id.clone(),
        Vault {
            record: VaultRecord {
                id: vault_id.clone(),
                vault_type: VaultType::Personal,
                revision: 0,
                wrapped_vault_key: request.personal_vault.wrapped_vault_key,
                role: VaultRole::Owner,
                key_id: None,
                grant: None,
                org_id: None,
            },
            items: BTreeMap::new(),
        },
    );
    let mut bundle = request.account;
    bundle.account_id = Some(account_id.clone());
    bundle.email = email.clone();
    state.accounts.insert(
        email,
        Account {
            password_file,
            bundle,
            vault_id,
        },
    );
    ok(&api::RegisterFinishResponse { account_id })
}

fn login_finish(state: &mut State, request: api::LoginFinishRequest) -> Reply {
    let email = state
        .logins
        .get(&request.login_id)
        .map(|(email, _)| email.clone())
        .ok_or_else(|| problem(401, "login-failed", None))?;
    finish_opaque(
        state,
        &request.login_id,
        &email,
        &request.credential_finalization,
    )?;
    let trusted = request
        .trusted_device_token
        .filter(|token| state.trusted.get(token) == Some(&email));
    if trusted.is_none() && state.two_step.contains_key(&email) {
        let challenge_id = token();
        state
            .challenges
            .insert(challenge_id.clone(), (email.clone(), 0));
        return Err(second_factor_required(challenge_id));
    }
    if let Some(token) = trusted {
        state.trusted.remove(&token);
    }
    complete_login(state, email)
}

/// A new session for `email`, and a trusted-device token for the device.
fn complete_login(state: &mut State, email: String) -> Reply {
    let account = state
        .accounts
        .get(&email)
        .ok_or_else(|| problem(401, "login-failed", None))?;
    let bundle = account.bundle.clone();
    let (access_token, refresh_token, trusted_device_token) = (token(), token(), token());
    state
        .access_tokens
        .insert(access_token.clone(), email.clone());
    state
        .refresh_tokens
        .insert(refresh_token.clone(), email.clone());
    state.trusted.insert(trusted_device_token.clone(), email);
    ok(&api::LoginFinishResponse {
        access_token,
        refresh_token,
        expires_in: 900,
        account: bundle,
        trusted_device_token: Some(trusted_device_token),
    })
}

fn second_factor(state: &mut State, request: api::SecondFactorRequest) -> Reply {
    let (email, tries) = state
        .challenges
        .remove(&request.challenge_id)
        .ok_or_else(|| problem(401, "login-failed", None))?;
    let passed = match (&request.totp_code, &request.recovery_code) {
        (Some(code), None) => code == TWO_STEP_CODE,
        (None, Some(code)) if code.eq_ignore_ascii_case(RECOVERY_CODE) => {
            state.two_step.get_mut(&email).is_some_and(std::mem::take)
        }
        (None, Some(_)) => false,
        _ => {
            state
                .challenges
                .insert(request.challenge_id, (email, tries));
            return Err(invalid());
        }
    };
    if passed {
        return complete_login(state, email);
    }
    if tries + 1 < SECOND_FACTOR_TRIES {
        state
            .challenges
            .insert(request.challenge_id, (email, tries + 1));
    }
    Err(problem(401, "invalid-second-factor", None))
}

/// Finishes a login or reauth for `email`; any failure is the one generic `login-failed`.
fn finish_opaque(
    state: &mut State,
    id: &str,
    email: &str,
    credential_finalization: &str,
) -> Result<(), HttpResponse> {
    let failed = || problem(401, "login-failed", None);
    let (owner, login) = state.logins.remove(id).ok_or_else(failed)?;
    if owner != email || !state.accounts.contains_key(email) {
        return Err(failed());
    }
    login.finish(credential_finalization).map_err(|_| failed())
}

fn refresh(state: &mut State, request: api::RefreshRequest) -> Reply {
    let email = state
        .refresh_tokens
        .remove(&request.refresh_token)
        .ok_or_else(|| problem(401, "unauthorized", None))?;
    let (access_token, refresh_token) = (token(), token());
    state
        .access_tokens
        .insert(access_token.clone(), email.clone());
    state.refresh_tokens.insert(refresh_token.clone(), email);
    ok(&api::RefreshResponse {
        access_token,
        refresh_token,
        expires_in: 900,
        trusted_device_token: None,
    })
}

fn delete_account(state: &mut State, request: &HttpRequest) -> Reply {
    let email = authenticate(state, request)?;
    let reauth = header(request, api::REAUTH_TOKEN_HEADER)
        .and_then(|token| state.reauth_tokens.remove(token))
        .filter(|owner| *owner == email)
        .ok_or_else(|| problem(403, "reauth-required", None))?;
    let confirm: api::DeleteAccountRequest = body(request)?;
    if normalize_email(&confirm.confirm_email) != reauth {
        return Err(problem(400, "invalid-request", None));
    }
    if let Some(account) = state.accounts.remove(&email) {
        state.vaults.remove(&account.vault_id);
    }
    let tokens: Vec<String> = state
        .access_tokens
        .iter()
        .filter(|(_, owner)| **owner == email)
        .map(|(token, _)| token.clone())
        .collect();
    state.access_tokens.retain(|_, owner| *owner != email);
    state.refresh_tokens.retain(|_, owner| *owner != email);
    state.deleted_tokens.extend(tokens);
    no_content()
}

fn sync(state: &State, email: &str, query: &str) -> Reply {
    let since: HashMap<&str, u64> = query
        .strip_prefix("since=")
        .unwrap_or_default()
        .split(',')
        .filter_map(|pair| {
            let (vault, revision) = pair.split_once(':')?;
            Some((vault, revision.parse().ok()?))
        })
        .collect();
    let vault = state
        .accounts
        .get(email)
        .and_then(|account| state.vaults.get(&account.vault_id))
        .ok_or_else(|| problem(401, "unauthorized", None))?;
    let after = since.get(vault.record.id.as_str()).copied().unwrap_or(0);
    ok(&api::SyncResponse {
        vaults: vec![vault.record.clone()],
        items: vault
            .items
            .values()
            .filter(|item| item.revision > after)
            .cloned()
            .collect(),
        deleted: Vec::new(),
        has_more: false,
    })
}

fn put_item(
    state: &mut State,
    email: &str,
    vault_id: &str,
    item_id: &str,
    request: &HttpRequest,
) -> Reply {
    let item: api::PutItemRequest = body(request)?;
    let owned = state
        .accounts
        .get(email)
        .is_some_and(|account| account.vault_id == vault_id);
    let vault = state
        .vaults
        .get_mut(vault_id)
        .filter(|_| owned)
        .ok_or_else(|| problem(404, "not-found", None))?;
    let current = vault.items.get(item_id);
    let conflict = || problem(409, "conflict", current.cloned());
    match (
        header(request, "if-match"),
        header(request, "if-none-match"),
    ) {
        (Some(revision), None) => {
            let current = current.ok_or_else(|| problem(404, "not-found", None))?;
            if revision.trim_matches('"') != current.revision.to_string() {
                return Err(conflict());
            }
        }
        (None, Some("*")) if current.is_some() => return Err(conflict()),
        (None, Some("*")) => {}
        _ => return Err(problem(428, "precondition-required", None)),
    }
    vault.record.revision += 1;
    let revision = vault.record.revision;
    vault.items.insert(
        item_id.to_owned(),
        ItemRecord {
            id: item_id.to_owned(),
            vault_id: vault_id.to_owned(),
            revision,
            encrypted_item_key: item.encrypted_item_key,
            overview: item.overview,
            details: item.details,
            updated_at: timestamp(now_ms()),
            deleted_at: None,
        },
    );
    ok(&api::RevisionResponse { revision })
}

fn authenticate(state: &State, request: &HttpRequest) -> Result<String, HttpResponse> {
    let token = header(request, "authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if state.deleted_tokens.iter().any(|deleted| deleted == token) {
        return Err(problem(401, "account-deleted", None));
    }
    state
        .access_tokens
        .get(token)
        .cloned()
        .ok_or_else(|| problem(401, "unauthorized", None))
}

fn header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn body<T: DeserializeOwned>(request: &HttpRequest) -> Result<T, HttpResponse> {
    serde_json::from_slice(request.body.as_deref().unwrap_or_default()).map_err(|_| invalid())
}

fn convert<T: Serialize, U: DeserializeOwned>(value: &T) -> Result<U, HttpResponse> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(|_| invalid())
}

fn token() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    b64_encode(&bytes)
}

fn ok(body: &impl Serialize) -> Reply {
    Ok(HttpResponse {
        status: 200,
        body: serde_json::to_vec(body).expect("API types serialize"),
    })
}

fn no_content() -> Reply {
    Ok(HttpResponse {
        status: 204,
        body: Vec::new(),
    })
}

fn invalid() -> HttpResponse {
    problem(400, "invalid-request", None)
}

fn second_factor_required(challenge_id: String) -> HttpResponse {
    let name = "second-factor-required";
    HttpResponse {
        status: 401,
        body: serde_json::to_vec(&Problem {
            problem_type: format!("https://octap.app/problems/{name}"),
            title: name.into(),
            status: 401,
            detail: None,
            current: None,
            second_factor: Some(api::SecondFactorChallenge {
                challenge_id,
                methods: vec![
                    api::SecondFactorMethod::Totp,
                    api::SecondFactorMethod::RecoveryCode,
                ],
                webauthn: None,
                expires_in: 300,
            }),
            sso: None,
            vault_ids: Vec::new(),
        })
        .expect("problems serialize"),
    }
}

fn problem(status: u16, name: &str, current: Option<ItemRecord>) -> HttpResponse {
    HttpResponse {
        status,
        body: serde_json::to_vec(&Problem {
            problem_type: format!("https://octap.app/problems/{name}"),
            title: name.into(),
            status,
            detail: None,
            current,
            second_factor: None,
            sso: None,
            vault_ids: Vec::new(),
        })
        .expect("problems serialize"),
    }
}
