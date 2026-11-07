//! Passkeys: the core as the WebAuthn authenticator, on encrypted items, so the private key never
//! reaches JavaScript. Options and responses use the WebAuthn Level 3 JSON forms.

use octapass_core::Error;
use octapass_core::passkey::{Candidate, ClientData, CreationOptions, RequestOptions, Target};
use rand_core::OsRng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;

use crate::account::Session;
use crate::{from_js, js_error, now_ms, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** Where a WebAuthn call comes from. `topOrigin` is the top-level page's origin when the call
 * comes from an iframe; a cross-origin frame is refused unless `frameAllowed` is true. */
export type PasskeyCaller = { origin: string; topOrigin?: string; frameAllowed?: boolean };
/** An encrypted item that may hold passkeys for the site. */
export type PasskeyCandidate = { vaultId: string; itemId: string; item: EncryptedItem };
/** Where a new passkey goes: into the existing login `item`, or a new login with this id. */
export type PasskeyTarget = { vaultId: string; itemId: string; item?: EncryptedItem };
export type PublicKeyCredentialDescriptorJSON = { type: "public-key" | (string & {}); id: string; transports?: string[] };
export type PublicKeyCredentialCreationOptionsJSON = {
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: "public-key" | (string & {}); alg: number }[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: { authenticatorAttachment?: string; residentKey?: string; requireResidentKey?: boolean; userVerification?: string };
  hints?: string[];
  attestation?: string;
  extensions?: { credProps?: boolean; [extension: string]: unknown };
};
export type PublicKeyCredentialRequestOptionsJSON = {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  userVerification?: string;
  hints?: string[];
  extensions?: { [extension: string]: unknown };
};
export type RegistrationResponseJSON = {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    transports: string[];
    publicKey: string;
    publicKeyAlgorithm: number;
    attestationObject: string;
  };
  authenticatorAttachment: "platform";
  clientExtensionResults: { credProps?: { rk: boolean } };
  type: "public-key";
};
export type AuthenticationResponseJSON = {
  id: string;
  rawId: string;
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle: string };
  authenticatorAttachment: "platform";
  clientExtensionResults: Record<string, never>;
  type: "public-key";
};
export type PasskeyCreated = { credential: RegistrationResponseJSON; item: EncryptedItem };
/** A passkey the user can pick. It never contains the private key. */
export type PasskeyMatch = {
  vaultId: string;
  itemId: string;
  credentialId: string;
  rpId: string;
  userName: string;
  userDisplayName?: string;
  createdAt: string;
};
"#;

#[wasm_bindgen]
impl Session {
    /// `navigator.credentials.create()`: makes a passkey and stores it in `target` (an existing
    /// login, or a new one). Save the returned `item` with `PUT
    /// /v1/vaults/{vaultId}/items/{itemId}`, then answer the page with `credential`. Pass the
    /// user's other items for this site as `others` (or `[]`), so `excludeCredentials` is
    /// honoured.
    #[wasm_bindgen(js_name = createPasskey, unchecked_return_type = "PasskeyCreated")]
    pub fn create_passkey(
        &self,
        #[wasm_bindgen(unchecked_param_type = "PublicKeyCredentialCreationOptionsJSON")]
        options: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PasskeyCaller")] caller: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PasskeyTarget")] target: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PasskeyCandidate[]")] others: Vec<JsValue>,
    ) -> Result<JsValue, JsValue> {
        let options: CreationOptions = options_from_js(options)?;
        let caller = ClientData::Web(from_js(caller, "passkey caller")?);
        let target: Target = from_js(target, "passkey target")?;
        let others = candidates_from_js(others)?;
        let (credential, item) = self
            .inner
            .create_passkey(&options, &caller, &target, &others, now_ms(), &mut OsRng)
            .map_err(js_error)?;
        #[derive(Serialize)]
        struct Created<T, U> {
            credential: T,
            item: U,
        }
        to_js(&Created { credential, item })
    }

    /// The passkeys in `candidates` that can answer this `navigator.credentials.get()` request,
    /// for the user to pick from. Throws `passkey_rp_mismatch` if the page may not use the
    /// requested `rpId`.
    #[wasm_bindgen(js_name = findPasskeys, unchecked_return_type = "PasskeyMatch[]")]
    pub fn find_passkeys(
        &self,
        #[wasm_bindgen(unchecked_param_type = "PublicKeyCredentialRequestOptionsJSON")]
        options: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PasskeyCaller")] caller: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PasskeyCandidate[]")] candidates: Vec<JsValue>,
    ) -> Result<JsValue, JsValue> {
        let options: RequestOptions = options_from_js(options)?;
        let caller = ClientData::Web(from_js(caller, "passkey caller")?);
        let candidates = candidates_from_js(candidates)?;
        to_js(
            &self
                .inner
                .find_passkeys(&options, &caller, &candidates)
                .map_err(js_error)?,
        )
    }

    /// `navigator.credentials.get()` with the passkey `credentialId` (from `findPasskeys`) stored
    /// in `candidate`.
    #[wasm_bindgen(js_name = getAssertion, unchecked_return_type = "AuthenticationResponseJSON")]
    pub fn get_assertion(
        &self,
        #[wasm_bindgen(unchecked_param_type = "PublicKeyCredentialRequestOptionsJSON")]
        options: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PasskeyCaller")] caller: JsValue,
        #[wasm_bindgen(unchecked_param_type = "PasskeyCandidate")] candidate: JsValue,
        #[wasm_bindgen(js_name = credentialId)] credential_id: String,
    ) -> Result<JsValue, JsValue> {
        let options: RequestOptions = options_from_js(options)?;
        let caller = ClientData::Web(from_js(caller, "passkey caller")?);
        let candidate: Candidate = from_js(candidate, "passkey candidate")?;
        to_js(
            &self
                .inner
                .get_assertion(&options, &caller, &candidate, &credential_id)
                .map_err(js_error)?,
        )
    }
}

/// Malformed WebAuthn options are the page's mistake (a `TypeError` for it), not the host's.
fn options_from_js<T: DeserializeOwned>(options: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(options).map_err(|_| js_error(Error::InvalidPasskeyRequest))
}

fn candidates_from_js(values: Vec<JsValue>) -> Result<Vec<Candidate>, JsValue> {
    values
        .into_iter()
        .map(|value| from_js(value, "passkey candidate"))
        .collect()
}
