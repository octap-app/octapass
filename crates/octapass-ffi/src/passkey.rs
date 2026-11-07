//! Passkeys for the system credential providers: iOS `ASCredentialProviderViewController`
//! (`ASPasskeyCredentialRequest`) and Android `CredentialProviderService`, plus web views.
//!
//! The private key never crosses the FFI: the core creates passkeys inside encrypted logins and
//! signs with them, and the new or changed login is saved to the store before the credential is
//! returned, so a passkey the relying party accepted can't be lost.
//!
//! Who built `clientDataJSON` decides the mode ([`ClientData`]). For a web page the core checks
//! the `rpId` against the origin and writes it. On iOS, and on Android for apps and for browsers
//! that pass `clientDataHash`, the platform or the provider already checked the caller (associated
//! domains, Digital Asset Links, the privileged-browser allowlist), so only the hash is signed.
//! Every mode is the core's authenticator (`octapass_core::passkey::ClientData`); this module only
//! finds the login and keeps the store.

use std::sync::Arc;

use octapass_core::account::new_id;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::passkey::{
    self, Caller, Candidate, CreationOptions, CredentialDescriptor, CredentialParameters,
    ExtensionInputs, PasskeyRecord, PrfInputs, PrfOutputs, PrfValues, RelyingPartyEntity,
    RequestOptions, Target, UserEntity,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use crate::error::{OctaPassError, Result};
use crate::items::{login_details, passkey_records};
use crate::matching::match_overviews;
use crate::session::{Session, encrypted, live_items, open_vault};
use crate::store::{LocalStore, StoredItem};
use crate::{now_ms, timestamp};
use octapass_core::matching::{MatchMode, MatchOptions};

const PUBLIC_KEY: &str = "public-key";

/// Who built `clientDataJSON`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ClientData {
    /// A web page: the core checks the `rpId` against `origin` and writes `clientDataJSON`.
    /// `top_origin` is the top-level page when the request comes from an iframe; a cross-origin
    /// frame is refused unless `frame_allowed`.
    Web {
        origin: String,
        top_origin: Option<String>,
        frame_allowed: bool,
    },
    /// `clientDataJSON` the provider built after checking the caller (Android apps, origin
    /// `android:apk-key-hash:…`). It goes into `responseJson` as is.
    Json { client_data_json: String },
    /// The SHA-256 of `clientDataJSON` the platform built (iOS; Android browsers that pass
    /// `clientDataHash`). `responseJson` then has an empty `clientDataJSON` for the platform to
    /// fill in.
    Hash { client_data_hash: Vec<u8> },
}

/// `navigator.credentials.create()`, as iOS's `ASPasskeyCredentialRequest` or the WebAuthn
/// options JSON carries it (see `passkeyCreationRequestFromJson`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyCreationRequest {
    /// Required unless the client data is `Web` (then it defaults to the origin's host).
    pub rp_id: Option<String>,
    /// The new login's title when there's no login to add the passkey to.
    pub rp_name: String,
    /// 1–64 bytes, chosen by the relying party.
    pub user_handle: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    /// COSE algorithms in the relying party's order of preference; empty means ES256.
    pub algorithms: Vec<i64>,
    pub excluded_credentials: Vec<Vec<u8>>,
    /// Only used to write `clientDataJSON` for `Web` client data.
    pub challenge: Vec<u8>,
    /// The relying party asked for the `credProps` extension.
    pub cred_props: bool,
    /// The PRF extension (plan 05). `eval` only: there's no credential yet.
    #[uniffi(default = None)]
    pub prf: Option<PasskeyPrfRequest>,
}

/// The PRF extension's inputs: the page's own values (Apple's `saltInput1` and `saltInput2`),
/// which the core hashes with "WebAuthn PRF" as the spec says.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyPrfInput {
    pub first: Vec<u8>,
    #[uniffi(default = None)]
    pub second: Option<Vec<u8>>,
}

/// `eval` for any passkey, `by_credential` for particular ones (sign-in only).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyPrfRequest {
    #[uniffi(default = None)]
    pub eval: Option<PasskeyPrfInput>,
    #[uniffi(default = [])]
    pub by_credential: Vec<PasskeyPrfCredentialInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyPrfCredentialInput {
    pub credential_id: Vec<u8>,
    pub input: PasskeyPrfInput,
}

/// The PRF extension's outputs: `enabled` on creation, the 32-byte results when inputs came.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyPrfOutput {
    pub enabled: bool,
    pub first: Option<Vec<u8>>,
    pub second: Option<Vec<u8>>,
}

/// `navigator.credentials.get()`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyAssertionRequest {
    /// Required unless the client data is `Web` (then it defaults to the origin's host).
    pub rp_id: Option<String>,
    /// Empty: any passkey for the relying party (discoverable credentials).
    pub allowed_credentials: Vec<Vec<u8>>,
    /// Only used to write `clientDataJSON` for `Web` client data.
    pub challenge: Vec<u8>,
    #[uniffi(default = None)]
    pub prf: Option<PasskeyPrfRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyRegistration {
    /// The login the passkey was saved in (already in the store, waiting for upload).
    pub item_id: String,
    pub credential_id: Vec<u8>,
    /// CBOR, attestation `none`.
    pub attestation_object: Vec<u8>,
    /// `RegistrationResponseJSON`, for Android's `CreatePublicKeyCredentialResponse` and web
    /// views.
    pub response_json: String,
    /// When the relying party asked for PRF.
    pub prf: Option<PasskeyPrfOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyAssertion {
    pub item_id: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// `AuthenticationResponseJSON`, for Android's `PublicKeyCredential` and web views.
    pub response_json: String,
    /// When the relying party asked for PRF and the passkey has a PRF secret.
    pub prf: Option<PasskeyPrfOutput>,
}

/// A passkey the user can pick, without its private key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeyMatch {
    pub item_id: String,
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: Option<String>,
    pub created_at: String,
}

/// Reads `PublicKeyCredentialCreationOptionsJSON` (Android's `CreatePublicKeyCredentialRequest`
/// `requestJson`).
#[uniffi::export]
pub fn passkey_creation_request_from_json(options_json: String) -> Result<PasskeyCreationRequest> {
    let options: CreationOptions =
        serde_json::from_str(&options_json).map_err(|_| OctaPassError::PasskeyInvalidRequest)?;
    Ok(PasskeyCreationRequest {
        rp_id: options.rp.id,
        rp_name: options.rp.name,
        user_handle: decode(&options.user.id)?,
        user_name: options.user.name,
        user_display_name: options.user.display_name,
        algorithms: options
            .pub_key_cred_params
            .iter()
            .filter(|param| param.kind == PUBLIC_KEY)
            .map(|param| param.alg)
            .collect(),
        excluded_credentials: credential_ids(&options.exclude_credentials),
        challenge: decode(&options.challenge)?,
        cred_props: options.extensions.cred_props,
        prf: options
            .extensions
            .prf
            .as_ref()
            .map(prf_request)
            .transpose()?,
    })
}

/// Reads `PublicKeyCredentialRequestOptionsJSON` (Android's `GetPublicKeyCredentialOption`
/// `requestJson`).
#[uniffi::export]
pub fn passkey_assertion_request_from_json(
    options_json: String,
) -> Result<PasskeyAssertionRequest> {
    let options: RequestOptions =
        serde_json::from_str(&options_json).map_err(|_| OctaPassError::PasskeyInvalidRequest)?;
    Ok(PasskeyAssertionRequest {
        rp_id: options.rp_id,
        allowed_credentials: credential_ids(&options.allow_credentials),
        challenge: decode(&options.challenge)?,
        prf: options
            .extensions
            .prf
            .as_ref()
            .map(prf_request)
            .transpose()?,
    })
}

#[uniffi::export]
impl Session {
    /// Creates a passkey. It goes into the login that already has a passkey for this user on
    /// this site, else into a login for the site with the same user name, else into a new login
    /// in the personal vault. Fails with `PasskeyExcluded` if one of `excludedCredentials` is
    /// saved.
    pub fn create_passkey(
        &self,
        store: Arc<LocalStore>,
        request: PasskeyCreationRequest,
        client: ClientData,
    ) -> Result<PasskeyRegistration> {
        let core_client = client.core()?;
        let rp_id = effective_rp_id(request.rp_id.as_deref(), &client);
        let options = creation_options(&request);
        let (mut credential, item_id, vault_id, base, item) =
            self.with_store(&store, |core, data| {
                let logins: Vec<(&StoredItem, Vec<PasskeyRecord>, bool)> = live_items(core, data)
                    .into_iter()
                    .filter_map(|(stored, item)| {
                        let login = login_details(&item)?;
                        let same_user = login
                            .username
                            .as_deref()
                            .is_some_and(|name| name.eq_ignore_ascii_case(&request.user_name));
                        // Which login a new passkey joins keeps the rule it had before
                        // 2026-11-05 (any part of the domain): passkeys follow WebAuthn.
                        let for_site = match_overviews(
                            &format!("https://{rp_id}"),
                            [(stored.record.id.as_str(), &item.overview)],
                            &MatchOptions {
                                default_mode: MatchMode::BaseDomain,
                                ..MatchOptions::default()
                            },
                        )
                        .is_ok_and(|found| !found.is_empty());
                        Some((stored, passkey_records(&item), same_user && for_site))
                    })
                    .collect();
                let user_handle = b64_encode(&request.user_handle);
                let writable =
                    |stored: &StoredItem| data.writable_vault(&stored.record.vault_id).is_ok();
                let target = logins
                    .iter()
                    .find(|(stored, passkeys, _)| {
                        writable(stored)
                            && passkeys
                                .iter()
                                .any(|p| p.rp_id == rp_id && p.user_handle == user_handle)
                    })
                    .or_else(|| {
                        logins
                            .iter()
                            .find(|(stored, _, same)| *same && writable(stored))
                    })
                    .map(|(stored, _, _)| (*stored).clone());
                let others: Vec<Candidate> = logins
                    .iter()
                    .filter(|(stored, passkeys, _)| {
                        target
                            .as_ref()
                            .is_none_or(|t| t.record.id != stored.record.id)
                            && passkeys.iter().any(|p| p.rp_id == rp_id)
                    })
                    .map(|(stored, _, _)| candidate(stored))
                    .collect();
                let (vault_id, item_id) = match &target {
                    Some(target) => (target.record.vault_id.clone(), target.record.id.clone()),
                    None => (
                        data.personal_vault()?.id.clone(),
                        new_id(now_ms(), &mut OsRng),
                    ),
                };
                data.writable_vault(&vault_id)?;
                open_vault(core, data, &vault_id)?;
                let (credential, item) = core.create_passkey(
                    &options,
                    &core_client,
                    &Target {
                        vault_id: vault_id.clone(),
                        item_id: item_id.clone(),
                        item: target.as_ref().map(|target| encrypted(&target.record)),
                    },
                    &others,
                    now_ms(),
                    &mut OsRng,
                )?;
                Ok((credential, item_id, vault_id, target, item))
            })?;
        store.mutate(|data| {
            data.put_local(
                &vault_id,
                &item_id,
                item,
                base.as_ref(),
                &timestamp(now_ms()),
            );
            Ok(())
        })?;
        if let Some(client_data_json) = client.provider_json() {
            credential.response.client_data_json = client_data_json;
        }
        Ok(PasskeyRegistration {
            item_id,
            credential_id: decode(&credential.raw_id)?,
            attestation_object: decode(&credential.response.attestation_object)?,
            prf: prf_output(credential.client_extension_results.prf.as_ref())?,
            response_json: to_json(&credential),
        })
    }

    /// The saved passkeys that can answer this request, for the user to pick from.
    pub fn find_passkeys(
        &self,
        store: Arc<LocalStore>,
        request: PasskeyAssertionRequest,
        client: ClientData,
    ) -> Result<Vec<PasskeyMatch>> {
        let core_client = client.core()?;
        let options = request_options(&request);
        self.with_store(&store, |core, data| {
            let candidates: Vec<Candidate> = live_items(core, data)
                .iter()
                .filter(|(_, item)| !passkey_records(item).is_empty())
                .map(|(stored, _)| candidate(stored))
                .collect();
            core.find_passkeys(&options, &core_client, &candidates)?
                .into_iter()
                .map(|found| {
                    Ok(PasskeyMatch {
                        credential_id: decode(&found.credential_id)?,
                        item_id: found.item_id,
                        rp_id: found.rp_id,
                        user_name: found.user_name,
                        user_display_name: found.user_display_name,
                        created_at: found.created_at,
                    })
                })
                .collect()
        })
    }

    /// Signs in with the passkey `credential_id` (from `findPasskeys` or the system's credential
    /// identity).
    pub fn get_passkey_assertion(
        &self,
        store: Arc<LocalStore>,
        request: PasskeyAssertionRequest,
        client: ClientData,
        credential_id: Vec<u8>,
    ) -> Result<PasskeyAssertion> {
        let core_client = client.core()?;
        let options = request_options(&request);
        let wanted = b64_encode(&credential_id);
        self.with_store(&store, |core, data| {
            let stored = live_items(core, data)
                .into_iter()
                .find(|(_, item)| {
                    passkey_records(item)
                        .iter()
                        .any(|record| record.credential_id == wanted)
                })
                .map(|(stored, _)| stored)
                .ok_or(OctaPassError::PasskeyNotFound)?;
            let mut response =
                core.get_assertion(&options, &core_client, &candidate(stored), &wanted)?;
            if let Some(client_data_json) = client.provider_json() {
                response.response.client_data_json = client_data_json;
            }
            Ok(PasskeyAssertion {
                item_id: stored.record.id.clone(),
                credential_id: decode(&response.raw_id)?,
                user_handle: decode(&response.response.user_handle)?,
                authenticator_data: decode(&response.response.authenticator_data)?,
                signature: decode(&response.response.signature)?,
                prf: prf_output(response.client_extension_results.prf.as_ref())?,
                response_json: to_json(&response),
            })
        })
    }
}

impl ClientData {
    /// The core's mode: a page to check, or the hash of client data the platform or the provider
    /// wrote. The platform vouched for the caller then; the core still requires the `rpId` and
    /// refuses public suffixes.
    fn core(&self) -> Result<passkey::ClientData> {
        Ok(match self {
            ClientData::Web {
                origin,
                top_origin,
                frame_allowed,
            } => passkey::ClientData::Web(Caller {
                origin: origin.clone(),
                top_origin: top_origin.clone(),
                frame_allowed: *frame_allowed,
            }),
            ClientData::Json { client_data_json } => {
                passkey::ClientData::Hash(Sha256::digest(client_data_json.as_bytes()).into())
            }
            ClientData::Hash { client_data_hash } => passkey::ClientData::Hash(
                client_data_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| OctaPassError::PasskeyInvalidRequest)?,
            ),
        })
    }

    /// The provider's `clientDataJSON` for the response JSON. For `Hash` the core leaves it empty
    /// for the platform to fill in.
    fn provider_json(&self) -> Option<String> {
        match self {
            ClientData::Json { client_data_json } => Some(b64_encode(client_data_json.as_bytes())),
            ClientData::Web { .. } | ClientData::Hash { .. } => None,
        }
    }
}

fn effective_rp_id(rp_id: Option<&str>, client: &ClientData) -> String {
    match (rp_id, client) {
        (Some(rp_id), _) => rp_id.to_ascii_lowercase(),
        (None, ClientData::Web { origin, .. }) => url::Url::parse(origin)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .unwrap_or_default(),
        (None, _) => String::new(),
    }
}

fn creation_options(request: &PasskeyCreationRequest) -> CreationOptions {
    CreationOptions {
        rp: RelyingPartyEntity {
            id: request.rp_id.clone(),
            name: request.rp_name.clone(),
        },
        user: UserEntity {
            id: b64_encode(&request.user_handle),
            name: request.user_name.clone(),
            display_name: request.user_display_name.clone(),
        },
        challenge: b64_encode(&request.challenge),
        pub_key_cred_params: request
            .algorithms
            .iter()
            .map(|&alg| CredentialParameters {
                kind: PUBLIC_KEY.into(),
                alg,
            })
            .collect(),
        exclude_credentials: descriptors(&request.excluded_credentials),
        extensions: ExtensionInputs {
            cred_props: request.cred_props,
            prf: request.prf.as_ref().map(prf_inputs),
        },
    }
}

fn request_options(request: &PasskeyAssertionRequest) -> RequestOptions {
    RequestOptions {
        challenge: b64_encode(&request.challenge),
        rp_id: request.rp_id.clone(),
        allow_credentials: descriptors(&request.allowed_credentials),
        extensions: ExtensionInputs {
            cred_props: false,
            prf: request.prf.as_ref().map(prf_inputs),
        },
    }
}

/// The FFI's PRF request as the core's JSON form (base64url).
fn prf_inputs(request: &PasskeyPrfRequest) -> PrfInputs {
    let values = |input: &PasskeyPrfInput| PrfValues {
        first: b64_encode(&input.first),
        second: input.second.as_deref().map(b64_encode),
    };
    PrfInputs {
        eval: request.eval.as_ref().map(values),
        eval_by_credential: request
            .by_credential
            .iter()
            .map(|entry| (b64_encode(&entry.credential_id), values(&entry.input)))
            .collect(),
    }
}

/// The JSON form's PRF inputs, decoded (`passkey…RequestFromJson`).
fn prf_request(inputs: &PrfInputs) -> Result<PasskeyPrfRequest> {
    let input = |values: &PrfValues| -> Result<PasskeyPrfInput> {
        Ok(PasskeyPrfInput {
            first: decode(&values.first)?,
            second: values.second.as_deref().map(decode).transpose()?,
        })
    };
    Ok(PasskeyPrfRequest {
        eval: inputs.eval.as_ref().map(input).transpose()?,
        by_credential: inputs
            .eval_by_credential
            .iter()
            .map(|(id, values)| {
                Ok(PasskeyPrfCredentialInput {
                    credential_id: decode(id)?,
                    input: input(values)?,
                })
            })
            .collect::<Result<_>>()?,
    })
}

/// The core's PRF outputs, decoded.
fn prf_output(prf: Option<&PrfOutputs>) -> Result<Option<PasskeyPrfOutput>> {
    let Some(prf) = prf else { return Ok(None) };
    let results = prf.results.as_ref();
    Ok(Some(PasskeyPrfOutput {
        enabled: prf.enabled.unwrap_or(false),
        first: results.map(|values| decode(&values.first)).transpose()?,
        second: results
            .and_then(|values| values.second.as_deref())
            .map(decode)
            .transpose()?,
    }))
}

fn descriptors(ids: &[Vec<u8>]) -> Vec<CredentialDescriptor> {
    ids.iter()
        .map(|id| CredentialDescriptor {
            kind: PUBLIC_KEY.into(),
            id: b64_encode(id),
        })
        .collect()
}

/// The ids of `public-key` descriptors; others (and undecodable ids) can't name our passkeys.
fn credential_ids(descriptors: &[CredentialDescriptor]) -> Vec<Vec<u8>> {
    descriptors
        .iter()
        .filter(|descriptor| descriptor.kind == PUBLIC_KEY)
        .filter_map(|descriptor| b64_decode(&descriptor.id).ok())
        .collect()
}

fn candidate(stored: &StoredItem) -> Candidate {
    Candidate {
        vault_id: stored.record.vault_id.clone(),
        item_id: stored.record.id.clone(),
        item: encrypted(&stored.record),
    }
}

fn decode(text: &str) -> Result<Vec<u8>> {
    b64_decode(text).map_err(|_| OctaPassError::PasskeyInvalidRequest)
}

fn to_json(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value).expect("WebAuthn responses serialize infallibly")
}
