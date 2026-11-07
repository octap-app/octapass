//! WebAssembly bindings of `octapass-core`, designed to run inside a Web Worker.
//!
//! Secrets stay in WASM memory behind handle classes (`Signup`, `DerivedKeys`, `LoginFlow`,
//! `ReauthFlow`, `Session`). JavaScript only receives what it must send to the server, display
//! strings it must show once (Secret Key, recovery code), and decrypted items when it asks for
//! them. Calling `free()` on a handle zeroes the keys it holds. See `README.md` for the flows.

use octapass_core::Error;
use serde::Serialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;

mod account;
mod attachment;
mod export;
mod import;
mod inbox;
#[cfg(feature = "strength")]
mod local;
mod matching;
mod passkey;
mod rules;
mod sharing;
#[cfg(feature = "test-server")]
mod test_server;
mod tools;
mod transparency;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export type KdfParams = { algorithm: "argon2id"; memoryKib: number; iterations: number; parallelism: number };
/** The `POST /v1/auth/prelogin` response. */
export type Prelogin = { kdf: KdfParams; accountSalt: string };
export type AccountBundle = {
  accountId?: string;
  email: string;
  kdf: KdfParams;
  accountSalt: string;
  wrappedAsk: string;
  publicEncKey: string;
  publicSignKey: string;
  wrappedPrivateKeys: string;
  recoveryWrappedAsk: string;
  /** The ML-KEM-768 seed sealed by the ASK, once the account has one. */
  wrappedPqPrivateKey?: string;
  /** The account's signed key record, once it has published one. */
  keyRecord?: KeyRecord;
};
/** What a device stores for device unlock (never sent to the server). */
export type DeviceUnlock = { deviceSalt: string; wrappedAsk: string };
export type NewVault = { id: string; wrappedVaultKey: string };
/** `POST /v1/auth/register/finish` body, minus `email` and `verificationCode`. */
export type RegisterFinish = { registrationUpload: string; account: AccountBundle; personalVault: NewVault };
/** The password-dependent part of the account bundle, as a master password change or reset replaces it. */
export type CredentialsUpdate = { kdf: KdfParams; accountSalt: string; wrappedAsk: string; recoveryWrappedAsk?: string };
/** `PUT /v1/account/password` body; with `recoveryId` and `signature`, `POST /v1/auth/recover/finish`. */
export type CredentialsFinish = { registrationUpload: string; account: CredentialsUpdate };
/** The `{ encryptedItemKey, overview, details }` part of an `ItemRecord`. */
export type EncryptedItem = { encryptedItemKey: string; overview: string; details: string };
export type ItemType = "login" | "secureNote" | "card" | "identity" | "password" | "document" | "wifi" | "sshKey" | "maskedEmailProvider" | "environment" | "certificate" | "key" | "bankAccount" | "apiCredential" | "softwareLicense" | "idDocument" | "cryptoWallet" | "database" | "custom" | "customTemplate";
export type ItemOverview = {
  schemaVersion?: number;
  title: string;
  type: ItemType | (string & {});
  urls?: string[];
  subtitle?: string;
  tags?: string[];
  favorite?: boolean;
  [field: string]: unknown;
};
/** A plaintext item. `details` is typed by `overview.type` (see the item model). */
export type ItemPlaintext = { overview: ItemOverview; details: { schemaVersion?: number; [field: string]: unknown } };
export type GeneratorOptions =
  | { type: "random"; length?: number; lowercase?: boolean; uppercase?: boolean; digits?: boolean; symbols?: boolean; avoidAmbiguous?: boolean }
  | { type: "passphrase"; words?: number; separator?: string; capitalize?: boolean; includeNumber?: boolean };
export type Strength = { score: 0 | 1 | 2 | 3 | 4; guessesLog10: number; feedback?: string };
export type TotpCode = { code: string; period: number; remaining: number };
/** Errors thrown by this module are `Error`s with `name === "OctaPassError"` and a stable `code`. */
export type OctaPassErrorCode =
  | "invalid_base64" | "invalid_secret_key" | "invalid_recovery_code" | "unsupported_kdf" | "kdf_failed"
  | "invalid_passkey_request" | "passkey_rp_mismatch" | "passkey_frame_not_allowed" | "passkey_unsupported_algorithm" | "passkey_excluded" | "passkey_not_found"
  | "malformed_ciphertext" | "unsupported_version" | "wrong_key" | "decryption_failed" | "encryption_failed"
  | "invalid_key" | "key_mismatch" | "invalid_opaque_message" | "opaque_protocol" | "login_failed"
  | "device_unlock_failed" | "vault_not_open" | "invalid_id" | "invalid_item" | "invalid_account_bundle" | "invalid_totp"
  | "invalid_generator_options" | "invalid_import_file" | "import_password_required" | "wrong_import_password"
  | "unsupported_import" | "pgp_unavailable" | "invalid_url" | "invalid_password_rules" | "invalid_local_vault" | "invalid_backup"
  | "hardware_secret_required" | "weak_master_password" | "item_not_found" | "invalid_argument" | "flow_finished"
  | "invalid_signature" | "invalid_grant" | "invalid_share_link" | "wrong_passphrase" | "invalid_export"
  | "invalid_image" | "invalid_ssh_key" | "unsupported_ssh_key" | "ssh_passphrase_required" | "ssh_public_key_only"
  | "unknown_tool" | "invalid_tool_input" | "invalid_encoding" | "unsupported_algorithm" | "invalid_hash_parameters"
  | "invalid_key_file" | "private_key_required" | "key_algorithm_mismatch" | "invalid_token" | "no_matching_key"
  | "invalid_certificate" | "certificate_key_mismatch" | "invalid_pkcs12" | "name_not_permitted" | "invalid_acme"
  | "inbox_full";
"#;

/// Converts a core error into a JS `Error` with `name = "OctaPassError"` and a stable `code`.
pub(crate) fn js_error(error: Error) -> JsValue {
    make_error(error.code(), &error.to_string())
}

pub(crate) fn make_error(code: &str, message: &str) -> JsValue {
    let error = js_sys::Error::new(message);
    error.set_name("OctaPassError");
    // Setting a property on a fresh Error object can't fail.
    let _ = js_sys::Reflect::set(&error, &"code".into(), &code.into());
    error.into()
}

/// A JS argument that didn't have the documented shape.
pub(crate) fn invalid_argument(what: &str) -> JsValue {
    make_error("invalid_argument", &format!("invalid argument: {what}"))
}

/// A handle method called after the flow it belongs to already finished.
pub(crate) fn flow_finished() -> JsValue {
    make_error("flow_finished", "this flow has already finished")
}

pub(crate) fn from_js<T: DeserializeOwned>(value: JsValue, what: &str) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value).map_err(|_| invalid_argument(what))
}

/// Like [`from_js`], but `undefined` and `null` mean the defaults (optional option bags).
pub(crate) fn options_from_js<T: DeserializeOwned + Default>(
    value: JsValue,
    what: &str,
) -> Result<T, JsValue> {
    if value.is_undefined() || value.is_null() {
        Ok(T::default())
    } else {
        from_js(value, what)
    }
}

pub(crate) fn to_js(value: &impl Serialize) -> Result<JsValue, JsValue> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|_| invalid_argument("unserializable value"))
}

pub(crate) fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

/// A new UUIDv7 for a vault or item.
#[wasm_bindgen(js_name = newId)]
pub fn new_id() -> String {
    octapass_core::account::new_id(now_ms(), &mut rand_core::OsRng)
}
