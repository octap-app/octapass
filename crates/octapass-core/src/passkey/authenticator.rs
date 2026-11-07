//! The two authenticator operations: make a credential and get an assertion (WebAuthn §6.3).

use rand_core::CryptoRngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::cbor;
use super::json::{
    AssertionResponse, AttestationResponse, AuthenticationResponse, CreationOptions,
    CredentialProperties, ExtensionOutputs, PUBLIC_KEY, PrfOutputs, PrfValues,
    RegistrationResponse, RequestOptions,
};
use super::key::PrivateKey;
use super::origin::{ClientData, Relying};
use super::record::{PasskeyRecord, iso_timestamp};
use crate::encoding::{b64_decode, b64_encode};
use crate::error::{Error, Result};

/// The Octa Pass AAGUID, `c9a07734-1d0b-4c72-8ff5-45e0daa2064f`. Relying parties use it to show
/// "Octa Pass" next to passkeys created here.
pub const AAGUID: [u8; 16] = [
    0xc9, 0xa0, 0x77, 0x34, 0x1d, 0x0b, 0x4c, 0x72, 0x8f, 0xf5, 0x45, 0xe0, 0xda, 0xa2, 0x06, 0x4f,
];
pub const CREDENTIAL_ID_LEN: usize = 16;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
/// User present and verified (the host only asks after the user chose Octa Pass in an unlocked
/// vault), backup eligible and backed up (passkeys sync like every item).
const FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;

/// The authenticator for the browser extension: `transports` and `authenticatorAttachment` say
/// it's built into this device, as platform authenticators and other passkey managers do.
const TRANSPORTS: [&str; 1] = ["internal"];
const ATTACHMENT: &str = "platform";

/// A new passkey: the response for the relying party and the record to store in the item.
#[derive(Debug)]
pub struct NewPasskey {
    pub credential: RegistrationResponse,
    pub record: PasskeyRecord,
}

/// `navigator.credentials.create()`: a new key pair for `options.rp`, attestation `none`. With
/// attestation `none` nothing signs the client data, so for [`ClientData::Hash`] the hash isn't
/// used and the challenge isn't read.
pub fn create(
    options: &CreationOptions,
    client: &ClientData,
    now_ms: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<NewPasskey> {
    let relying = client.relying(options.rp.id.as_deref())?;
    let algorithm = options.algorithm()?;
    let (client_data, _) = client_data(client, "webauthn.create", &options.challenge, &relying)?;
    let user_handle = b64_decode(&options.user.id).map_err(|_| Error::InvalidPasskeyRequest)?;
    if !(1..=64).contains(&user_handle.len()) {
        return Err(Error::InvalidPasskeyRequest);
    }

    let key = PrivateKey::generate(algorithm, rng);
    let mut credential_id = [0u8; CREDENTIAL_ID_LEN];
    rng.fill_bytes(&mut credential_id);
    // Every new passkey can answer PRF, asked for now or later.
    let mut prf_secret = zeroize::Zeroizing::new([0u8; 32]);
    rng.fill_bytes(prf_secret.as_mut());
    let cose_key = key.cose_public_key();

    let mut attested = Vec::with_capacity(18 + CREDENTIAL_ID_LEN + cose_key.len());
    attested.extend_from_slice(&AAGUID);
    attested.extend_from_slice(&(CREDENTIAL_ID_LEN as u16).to_be_bytes());
    attested.extend_from_slice(&credential_id);
    attested.extend_from_slice(&cose_key);
    let authenticator_data = authenticator_data(&relying.rp_id, FLAGS | FLAG_AT, &attested);

    let id = b64_encode(&credential_id);
    let display_name = &options.user.display_name;
    let record = PasskeyRecord {
        rp_id: relying.rp_id.clone(),
        user_name: options.user.name.clone(),
        created_at: iso_timestamp(now_ms),
        credential_id: id.clone(),
        user_handle: b64_encode(&user_handle),
        user_display_name: (!display_name.is_empty()).then(|| display_name.clone()),
        private_key: b64_encode(&key.to_pkcs8()),
        sign_count: 0,
        prf_secret: Some(b64_encode(prf_secret.as_ref())),
        extra: Default::default(),
    };
    let prf = match &options.extensions.prf {
        Some(inputs) => Some(PrfOutputs {
            enabled: Some(true),
            results: inputs
                .eval
                .as_ref()
                .map(|values| prf_results(&record, values))
                .transpose()?,
        }),
        None => None,
    };
    let credential = RegistrationResponse {
        raw_id: id.clone(),
        id,
        response: AttestationResponse {
            client_data_json: b64_encode(&client_data),
            attestation_object: b64_encode(&attestation_object(&authenticator_data)),
            authenticator_data: b64_encode(&authenticator_data),
            transports: TRANSPORTS.to_vec(),
            public_key: b64_encode(&key.spki_public_key()),
            public_key_algorithm: algorithm.cose(),
        },
        authenticator_attachment: ATTACHMENT,
        client_extension_results: ExtensionOutputs {
            cred_props: options
                .extensions
                .cred_props
                .then_some(CredentialProperties { rk: true }),
            prf,
        },
        kind: PUBLIC_KEY,
    };
    Ok(NewPasskey { credential, record })
}

/// `navigator.credentials.get()` with a passkey the host picked: signs
/// `authenticatorData ‖ clientDataHash`, the same way whoever wrote the client data. Refuses with
/// [`Error::PasskeyNotFound`] if the passkey is for another site or not in `allowCredentials`.
pub fn get(
    options: &RequestOptions,
    client: &ClientData,
    passkey: &PasskeyRecord,
) -> Result<AuthenticationResponse> {
    let relying = client.relying(options.rp_id.as_deref())?;
    if !matches(options, &relying.rp_id, passkey) {
        return Err(Error::PasskeyNotFound);
    }
    let (client_data, client_data_hash) =
        client_data(client, "webauthn.get", &options.challenge, &relying)?;
    let key = passkey.private_key()?;

    let prf = match &options.extensions.prf {
        Some(inputs) if passkey.prf_secret.is_some() => {
            let values = inputs.for_credential(&passkey.credential_id_bytes()?);
            values
                .map(|values| prf_results(passkey, values))
                .transpose()?
                .map(|results| PrfOutputs {
                    enabled: None,
                    results: Some(results),
                })
        }
        _ => None,
    };

    let authenticator_data = authenticator_data(&relying.rp_id, FLAGS, &[]);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&client_data_hash);

    Ok(AuthenticationResponse {
        id: passkey.credential_id.clone(),
        raw_id: passkey.credential_id.clone(),
        response: AssertionResponse {
            client_data_json: b64_encode(&client_data),
            authenticator_data: b64_encode(&authenticator_data),
            signature: b64_encode(&key.sign(&signed)),
            user_handle: passkey.user_handle.clone(),
        },
        authenticator_attachment: ATTACHMENT,
        client_extension_results: ExtensionOutputs {
            cred_props: None,
            prf,
        },
        kind: PUBLIC_KEY,
    })
}

/// The PRF outputs for the page's inputs (base64url), for a passkey with a PRF secret.
fn prf_results(passkey: &PasskeyRecord, values: &PrfValues) -> Result<PrfValues> {
    let output = |input: &str| -> Result<String> {
        let input = b64_decode(input).map_err(|_| Error::InvalidPasskeyRequest)?;
        let output = passkey.prf(&input)?.ok_or(Error::InvalidPasskeyRequest)?;
        Ok(b64_encode(output.as_ref()))
    };
    Ok(PrfValues {
        first: output(&values.first)?,
        second: values.second.as_deref().map(output).transpose()?,
    })
}

/// Whether `passkey` can answer a request for `rp_id` (already checked against the caller).
pub(crate) fn matches(options: &RequestOptions, rp_id: &str, passkey: &PasskeyRecord) -> bool {
    passkey.rp_id == rp_id
        && passkey
            .credential_id_bytes()
            .is_ok_and(|id| options.allows(&id))
}

/// The response's `clientDataJSON` and its SHA-256: written here for a page, or empty next to the
/// platform's hash.
fn client_data(
    client: &ClientData,
    kind: &str,
    challenge: &str,
    relying: &Relying,
) -> Result<(Vec<u8>, [u8; 32])> {
    match client {
        ClientData::Web(_) => {
            let challenge = b64_decode(challenge).map_err(|_| Error::InvalidPasskeyRequest)?;
            let json = client_data_json(kind, &challenge, relying);
            let hash = Sha256::digest(&json).into();
            Ok((json, hash))
        }
        ClientData::Hash(hash) => Ok((Vec::new(), *hash)),
    }
}

/// `rpIdHash ‖ flags ‖ signCount (0) ‖ attestedCredentialData`.
fn authenticator_data(rp_id: &str, flags: u8, attested: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(37 + attested.len());
    out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
    out.push(flags);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(attested);
    out
}

/// `{ "fmt": "none", "attStmt": {}, "authData": … }` in CTAP2 canonical key order.
fn attestation_object(authenticator_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(authenticator_data.len() + 32);
    cbor::map(&mut out, 3);
    cbor::text(&mut out, "fmt");
    cbor::text(&mut out, "none");
    cbor::text(&mut out, "attStmt");
    cbor::map(&mut out, 0);
    cbor::text(&mut out, "authData");
    cbor::bytes(&mut out, authenticator_data);
    out
}

/// The JSON-compatible serialization of client data (WebAuthn §5.8.1.1): members in this exact
/// order, so relying parties using the limited verification algorithm accept it.
fn client_data_json(kind: &str, challenge: &[u8], relying: &Relying) -> Vec<u8> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ClientData<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
        challenge: String,
        origin: &'a str,
        cross_origin: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        top_origin: Option<&'a str>,
    }
    serde_json::to_vec(&ClientData {
        kind,
        challenge: b64_encode(challenge),
        origin: &relying.origin,
        cross_origin: relying.top_origin.is_some(),
        top_origin: relying.top_origin.as_deref(),
    })
    .expect("client data serializes infallibly")
}
