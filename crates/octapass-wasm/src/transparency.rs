//! The key log: what a device pins and checks (plan 03). Fetching and storing are the caller's;
//! `KeyLog::save` gives the state to keep, and it must be kept after a failed check too, because
//! that's what records an alert.

use octapass_core::encoding::b64_encode;
use octapass_core::transparency::client::{HeadUpdate, KeyStatus, LabelProof, LogPage, LogState};
use octapass_core::transparency::label::{self, EvaluatedLabel};
use octapass_core::transparency::publish::PublishKeys;
use octapass_core::transparency::record::{KeyRecord, OfferedKeys};
use rand_core::OsRng;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::account::Session;
use crate::{from_js, invalid_argument, js_error, now_ms, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** An account's signed statement of its public keys. */
export type KeyRecord = {
  logId: string;
  accountId: string;
  label: string;
  publicEncKey: string;
  publicSignKey: string;
  publicPqKey: string;
  createdAt: number;
  signature: string;
};
export type KeyLogIdentity = { signKey: string; oprfKey: string };
export type KeyLogHead = { treeSize: number; rootHash: string; timestamp: number; signature: string };
/** `GET /v1/transparency/head`. */
export type KeyLogHeadUpdate = { log: KeyLogIdentity; head: KeyLogHead; consistency: string[] };
/** `GET /v1/transparency/proof`. */
export type KeyLogProof = KeyLogHeadUpdate & {
  entry?: { leafIndex: number; record: KeyRecord; inclusion: string[] };
};
/** `GET /v1/transparency/entries`. */
export type KeyLogPage = { start: number; frontier: string[]; leaves: string };
export type KeyLogAlert = {
  kind: "logChanged" | "logInconsistent" | "foreignRecord" | "ownRecordMissing";
  leafIndex?: number;
  at: number;
};
export type KeyLogAccount = {
  accountId: string;
  publicEncKey: string;
  publicSignKey: string;
  keyRecord?: KeyRecord;
};
/** `POST /v1/transparency/publish`. */
export type PublishKeys = { record: KeyRecord; wrappedPqPrivateKey: string };
export type BlindedLabel = { state: string; blinded: string };
"#;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsAccount {
    account_id: String,
    public_enc_key: String,
    public_sign_key: String,
    key_record: Option<KeyRecord>,
}

/// A device's pins for one account.
#[wasm_bindgen]
pub struct KeyLog {
    state: LogState,
}

#[wasm_bindgen]
impl KeyLog {
    /// Opens what `save` returned, or starts empty.
    #[wasm_bindgen(constructor)]
    pub fn new(saved: Option<String>) -> Result<KeyLog, JsValue> {
        let state = match saved {
            Some(saved) => {
                serde_json::from_str(&saved).map_err(|_| invalid_argument("key log state"))?
            }
            None => LogState::default(),
        };
        Ok(Self { state })
    }

    pub fn save(&self) -> String {
        serde_json::to_string(&self.state).expect("the state serializes")
    }

    /// The size to ask for a consistency proof from.
    #[wasm_bindgen(getter, js_name = pinnedSize)]
    pub fn pinned_size(&self) -> f64 {
        self.state.pinned_size() as f64
    }

    #[wasm_bindgen(getter, js_name = checkedAt)]
    pub fn checked_at(&self) -> f64 {
        self.state.checked_at as f64
    }

    /// The first alert since the user last dismissed one.
    #[wasm_bindgen(getter, unchecked_return_type = "KeyLogAlert | undefined")]
    pub fn alert(&self) -> Result<JsValue, JsValue> {
        match &self.state.alert {
            Some(alert) => to_js(alert),
            None => Ok(JsValue::UNDEFINED),
        }
    }

    /// Forgets every pin: after the user heard the alert and accepts the log as it is now.
    pub fn reset(&mut self) {
        self.state.reset();
    }

    /// The pinned log's VOPRF public key, if a head has been accepted.
    #[wasm_bindgen(getter, js_name = oprfKey)]
    pub fn oprf_key(&self) -> Option<String> {
        self.state.log.as_ref().map(|log| log.oprf_key.clone())
    }

    /// The pinned log's id, if a head has been accepted.
    #[wasm_bindgen(getter, js_name = logId)]
    pub fn log_id(&self) -> Option<String> {
        self.state
            .log
            .as_ref()
            .and_then(|log| log.log_id_b64().ok())
    }

    #[wasm_bindgen(js_name = knownLabel)]
    pub fn known_label(&self, email: String) -> Option<String> {
        self.state.labels.get(&email).cloned()
    }

    #[wasm_bindgen(js_name = rememberLabel)]
    pub fn remember_label(&mut self, email: String, label: String) {
        self.state.labels.insert(email, label);
    }

    #[wasm_bindgen(js_name = acceptHead)]
    pub fn accept_head(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "KeyLogHeadUpdate")] update: JsValue,
    ) -> Result<(), JsValue> {
        let update: HeadUpdate = from_js(update, "key log head")?;
        self.state.accept_head(&update, now_ms()).map_err(js_error)
    }

    /// Checks keys a server offered against the log. Throws `key_log_mismatch` when they must not
    /// be sealed to; returns `false` when the log has nothing on the account, `true` when it
    /// backs them up.
    #[wasm_bindgen(js_name = verifyAccount)]
    pub fn verify_account(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "KeyLogAccount")] account: JsValue,
        label: String,
        #[wasm_bindgen(unchecked_param_type = "KeyLogProof")] proof: JsValue,
    ) -> Result<bool, JsValue> {
        let account: JsAccount = from_js(account, "account")?;
        let proof: LabelProof = from_js(proof, "key log proof")?;
        let offered = OfferedKeys {
            account_id: &account.account_id,
            public_enc_key: &account.public_enc_key,
            public_sign_key: &account.public_sign_key,
        };
        let status = self
            .state
            .verify_account(
                &offered,
                account.key_record.as_ref(),
                &label,
                &proof,
                now_ms(),
            )
            .map_err(js_error)?;
        Ok(status == KeyStatus::Verified)
    }

    /// Checks this account's own record and starts monitoring. Throws on anything wrong, with
    /// the alert in `alert`.
    #[wasm_bindgen(js_name = checkOwn)]
    pub fn check_own(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "KeyRecord")] record: JsValue,
        #[wasm_bindgen(unchecked_param_type = "KeyLogProof")] proof: JsValue,
    ) -> Result<(), JsValue> {
        let record: KeyRecord = from_js(record, "key record")?;
        let proof: LabelProof = from_js(proof, "key log proof")?;
        self.state
            .check_own(&record, &proof, now_ms())
            .map_err(js_error)
    }

    /// `[start, end]` of the leaves to read next, if any.
    #[wasm_bindgen(js_name = scanRange)]
    pub fn scan_range(&self) -> Option<Vec<f64>> {
        self.state
            .scan_range()
            .map(|(start, end)| vec![start as f64, end as f64])
    }

    /// Reads a page of leaves. Returns whether the scan reached the pinned head.
    #[wasm_bindgen(js_name = applyPage)]
    pub fn apply_page(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "KeyLogPage")] page: JsValue,
    ) -> Result<bool, JsValue> {
        let page: LogPage = from_js(page, "key log page")?;
        self.state.apply_page(&page, now_ms()).map_err(js_error)
    }
}

/// Blinds an email for `POST /v1/transparency/label`.
#[wasm_bindgen(js_name = keyLogBlind, unchecked_return_type = "BlindedLabel")]
pub fn key_log_blind(email: String) -> Result<JsValue, JsValue> {
    to_js(&label::blind(&email, &mut OsRng).map_err(js_error)?)
}

/// Checks the server's answer against the pinned `oprfKey` and returns the email's label.
#[wasm_bindgen(js_name = keyLogFinishLabel)]
pub fn key_log_finish_label(
    email: String,
    state: String,
    evaluated: String,
    proof: String,
    #[wasm_bindgen(js_name = oprfKey)] oprf_key: String,
) -> Result<String, JsValue> {
    let answer = EvaluatedLabel { evaluated, proof };
    let label = label::finish(&email, &state, &answer, &oprf_key).map_err(js_error)?;
    Ok(b64_encode(&label))
}

#[wasm_bindgen]
impl Session {
    /// A signed record for `POST /v1/transparency/publish`, generating the account's ML-KEM key
    /// the first time. Changes nothing until `adoptKeyRecord`.
    #[wasm_bindgen(js_name = prepareKeyRecord, unchecked_return_type = "PublishKeys")]
    pub fn prepare_key_record(
        &self,
        #[wasm_bindgen(js_name = logId)] log_id: String,
        label: String,
    ) -> Result<JsValue, JsValue> {
        let label = octapass_core::encoding::b64_decode_array(&label).map_err(js_error)?;
        let keys = self
            .inner
            .prepare_key_record(&log_id, &label, now_ms(), &mut OsRng)
            .map_err(js_error)?;
        to_js(&keys)
    }

    /// Takes a record the server accepted, or another device's from `GET /v1/account`.
    #[wasm_bindgen(js_name = adoptKeyRecord)]
    pub fn adopt_key_record(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "PublishKeys")] keys: JsValue,
    ) -> Result<(), JsValue> {
        let keys: PublishKeys = from_js(keys, "published keys")?;
        self.inner.adopt_key_record(keys).map_err(js_error)
    }
}
