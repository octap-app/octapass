//! The key log (plan 03) for the phone apps: publishing this account's keys, checking other
//! people's before sealing to them, and watching the log. The checks are the core's; this file
//! fetches them over the app's HTTP client and keeps the pins in the store. Rust-only: the phone
//! apps call it from their vault crate, so the generated bindings don't change.

use octapass_api as api;
use octapass_core::encoding::b64_encode;
use octapass_core::kdf::normalize_email;
use octapass_core::transparency::client::{KeyStatus, LabelProof, LogPage, LogState};
use octapass_core::transparency::label::{self, BlindedLabel, EvaluatedLabel};
use octapass_core::transparency::publish::PublishKeys;
use octapass_core::transparency::record::{KeyRecord, OfferedKeys};
use rand_core::OsRng;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{OctaPassError, Result};
use crate::now_ms;
use crate::server::OctaPassServer;
use crate::session::Session;
use crate::store::LocalStore;

/// A device reads the log at most this often.
const MONITOR_EVERY_MS: u64 = 60 * 60 * 1000;

/// What the key log says about keys the server offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCheck {
    /// In the log and matching.
    Verified,
    /// Nothing to check against, which isn't a pass.
    NotLogged,
    /// Don't seal to them.
    Failed,
    /// The check couldn't run: offline, rate limited, or an older server.
    Unavailable,
}

/// The keys to check, as a lookup or a member list gives them.
#[derive(Debug, Clone, Copy)]
pub struct Account<'a> {
    pub account_id: &'a str,
    pub email: &'a str,
    pub public_enc_key: &'a str,
    pub public_sign_key: &'a str,
    pub record: Option<&'a KeyRecord>,
}

/// The core and the API crate each have their own copy of these wire shapes.
fn convert<T: DeserializeOwned>(value: &impl Serialize) -> Result<T> {
    let json = serde_json::to_value(value).map_err(|_| OctaPassError::InvalidResponse)?;
    serde_json::from_value(json).map_err(|_| OctaPassError::InvalidResponse)
}

/// A key record as the API crate holds it, for the core.
pub fn core_record(record: Option<&api::KeyRecord>) -> Option<KeyRecord> {
    convert(&record?).ok()
}

fn is_mismatch(error: &OctaPassError) -> bool {
    matches!(error, OctaPassError::Core { code, .. } if code == "key_log_mismatch")
}

impl LocalStore {
    pub(crate) fn key_log(&self) -> LogState {
        serde_json::from_str(&self.data().key_log).unwrap_or_default()
    }

    fn save_key_log(&self, state: &LogState) -> Result<()> {
        let json = serde_json::to_string(state).map_err(|_| OctaPassError::InvalidStore)?;
        self.mutate(|data| {
            data.key_log = json;
            Ok(())
        })
    }
}

impl OctaPassServer {
    fn pin_head(&self, token: &str, state: &mut LogState) -> Result<()> {
        if state.log.is_some() {
            return Ok(());
        }
        let update: api::KeyLogHeadResponse =
            self.api.get("v1/transparency/head?since=0", Some(token))?;
        Ok(state.accept_head(&convert(&update)?, now_ms())?)
    }

    fn label(&self, token: &str, state: &mut LogState, email: &str) -> Result<String> {
        let email = normalize_email(email);
        if let Some(known) = state.labels.get(&email) {
            return Ok(known.clone());
        }
        self.pin_head(token, state)?;
        let oprf_key = state
            .log
            .as_ref()
            .ok_or(OctaPassError::InvalidResponse)?
            .oprf_key
            .clone();
        let BlindedLabel {
            state: blind,
            blinded,
        } = label::blind(&email, &mut OsRng)?;
        let answer: api::KeyLogLabelResponse = self.api.post(
            "v1/transparency/label",
            Some(token),
            &api::KeyLogLabelRequest { blinded },
        )?;
        let evaluated = EvaluatedLabel {
            evaluated: answer.evaluated,
            proof: answer.proof,
        };
        let found = b64_encode(&label::finish(&email, &blind, &evaluated, &oprf_key)?);
        state.labels.insert(email, found.clone());
        Ok(found)
    }

    fn proof(&self, token: &str, label: &str, since: u64) -> Result<LabelProof> {
        let answer: api::KeyLogProofResponse = self.api.get(
            &format!("v1/transparency/proof?label={label}&since={since}"),
            Some(token),
        )?;
        convert(&answer)
    }

    /// Gives the session the account's ML-KEM key and puts the account in the log, or takes both
    /// from another device of this account that got there first. Run it before a sync: the sync
    /// may bring hybrid grants.
    pub fn ensure_key_record(
        &self,
        token: &str,
        session: &Session,
        store: &LocalStore,
    ) -> Result<()> {
        if store.data().account.key_record.is_some() {
            return Ok(());
        }
        let fresh: api::AccountBundle = self.api.get("v1/account", Some(token))?;
        let keys = match (fresh.key_record, fresh.wrapped_pq_private_key) {
            (Some(record), Some(wrapped_pq_private_key)) => PublishKeys {
                record: convert(&record)?,
                wrapped_pq_private_key,
            },
            _ => self.publish(token, session, store)?,
        };
        let bundle = session.adopt_key_record(keys)?;
        store.mutate(|data| {
            data.account = bundle;
            Ok(())
        })
    }

    fn publish(&self, token: &str, session: &Session, store: &LocalStore) -> Result<PublishKeys> {
        let mut state = store.key_log();
        self.pin_head(token, &mut state)?;
        let email = store.data().account.email.clone();
        let label = self.label(token, &mut state, &email)?;
        store.save_key_log(&state)?;
        let log_id = state
            .log
            .as_ref()
            .ok_or(OctaPassError::InvalidResponse)?
            .log_id_b64()?;
        let label = octapass_core::encoding::b64_decode_array(&label)?;
        let keys = session.with_keys(|core| {
            Ok(core.prepare_key_record(&log_id, &label, now_ms(), &mut OsRng)?)
        })?;
        let body = api::PublishKeysRequest {
            record: convert(&keys.record)?,
            wrapped_pq_private_key: keys.wrapped_pq_private_key.clone(),
        };
        let _: api::PublishKeysResponse =
            self.api
                .post("v1/transparency/publish", Some(token), &body)?;
        Ok(keys)
    }

    /// Checks this account's record and reads what's new in the log, at most hourly. What it
    /// finds goes in the pins as an alert.
    pub fn monitor_key_log(&self, token: &str, store: &LocalStore) -> Result<()> {
        let Some(record) = store.data().account.key_record.clone() else {
            return Ok(());
        };
        let mut state = store.key_log();
        if now_ms().saturating_sub(state.checked_at) < MONITOR_EVERY_MS {
            return Ok(());
        }
        let result = self.read_log(token, &record, &mut state);
        store.save_key_log(&state)?;
        match result {
            Err(error) if is_mismatch(&error) => Ok(()),
            other => other,
        }
    }

    fn read_log(&self, token: &str, record: &KeyRecord, state: &mut LogState) -> Result<()> {
        let proof = self.proof(token, &record.label, state.pinned_size())?;
        state.check_own(record, &proof, now_ms())?;
        while let Some((start, end)) = state.scan_range() {
            let page: api::KeyLogEntriesResponse = self.api.get(
                &format!("v1/transparency/entries?start={start}&end={end}"),
                Some(token),
            )?;
            let page: LogPage = convert(&page)?;
            state.apply_page(&page, now_ms())?;
        }
        Ok(())
    }

    /// Checks keys the server offered, on this device.
    pub fn check_account(&self, token: &str, store: &LocalStore, account: Account<'_>) -> KeyCheck {
        let mut state = store.key_log();
        let check = (|| {
            let label = self.label(token, &mut state, account.email)?;
            let proof = self.proof(token, &label, state.pinned_size())?;
            let offered = OfferedKeys {
                account_id: account.account_id,
                public_enc_key: account.public_enc_key,
                public_sign_key: account.public_sign_key,
            };
            state
                .verify_account(&offered, account.record, &label, &proof, now_ms())
                .map_err(OctaPassError::from)
        })();
        let saved = store.save_key_log(&state);
        match (check, saved) {
            (Ok(KeyStatus::Verified), _) => KeyCheck::Verified,
            (Ok(KeyStatus::NotLogged), _) => KeyCheck::NotLogged,
            (Err(error), _) if is_mismatch(&error) => KeyCheck::Failed,
            _ => KeyCheck::Unavailable,
        }
    }
}
