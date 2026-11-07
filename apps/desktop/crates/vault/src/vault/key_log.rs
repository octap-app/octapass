//! The key log (plan 03), as the web vault does it in `packages/vault-client/src/remote/keyLog.ts`:
//! publishing this account's keys, checking other people's before sealing to them, and watching
//! the log. The checks are the core's; the pins live in the account's sharing notes.

use octapass_api::{
    AccountBundle, KeyLogEntriesResponse, KeyLogHeadResponse, KeyLogLabelResponse,
    KeyLogProofResponse, PublishKeysResponse,
};
use octapass_core::Error as CoreError;
use octapass_core::encoding::{b64_decode_array, b64_encode};
use octapass_core::kdf::normalize_email;
use octapass_core::transparency::client::{HeadUpdate, KeyStatus, LabelProof, LogPage, LogState};
use octapass_core::transparency::head::LogIdentity;
use octapass_core::transparency::label::{self, EvaluatedLabel};
use octapass_core::transparency::publish::PublishKeys;
use octapass_core::transparency::record::{KeyRecord, OfferedKeys};
use rand_core::OsRng;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::Vault;
use super::sharing::AccountLookup;
use crate::error::{ErrorCode, Result, VaultError};
use crate::store::AccountKey;

/// A device reads the log at most this often.
const MONITOR_EVERY_MS: u64 = 60 * 60 * 1000;

/// What the key log says about keys the server offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

/// This device's view of the key log, for the settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyLogView {
    pub published: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<KeyLogAlertView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyLogAlertView {
    pub kind: octapass_core::transparency::client::AlertKind,
    pub at: String,
}

/// The keys to check, as a lookup or a member list gives them.
#[derive(Debug, Clone, Copy)]
pub(super) struct Offered<'a> {
    pub account_id: &'a str,
    pub email: &'a str,
    pub public_enc_key: &'a str,
    pub public_sign_key: &'a str,
    pub record: Option<&'a KeyRecord>,
}

impl<'a> From<&'a AccountLookup> for Offered<'a> {
    fn from(account: &'a AccountLookup) -> Self {
        Self {
            account_id: &account.account_id,
            email: &account.email,
            public_enc_key: &account.public_enc_key,
            public_sign_key: &account.public_sign_key,
            record: account.key_record.as_ref(),
        }
    }
}

/// The core and the API crate each have their own copy of these wire shapes.
fn convert<T: DeserializeOwned>(value: &impl Serialize) -> Result<T> {
    let unexpected = |error: serde_json::Error| VaultError::unexpected(error.to_string());
    serde_json::from_value(serde_json::to_value(value).map_err(unexpected)?).map_err(unexpected)
}

pub(super) fn core_record(record: Option<&octapass_api::KeyRecord>) -> Option<KeyRecord> {
    convert(&record?).ok()
}

fn iso(ms: u64) -> String {
    let at = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    crate::model::rfc3339(at)
}

fn now_ms() -> u64 {
    super::sharing::timestamp_ms()
}

impl Vault {
    fn key_log(&self, key: &AccountKey) -> Result<LogState> {
        Ok(self.store.load_notes(key)?.key_log)
    }

    fn save_key_log(&self, key: &AccountKey, state: LogState) -> Result<()> {
        self.store.update_notes(key, |notes| notes.key_log = state)
    }

    async fn pin_head(&self, key: &AccountKey, state: &mut LogState) -> Result<()> {
        if state.log.is_some() {
            return Ok(());
        }
        let head: KeyLogHeadResponse = self
            .server(key, Method::GET, "/v1/transparency/head?since=0", None)
            .await??;
        let update: HeadUpdate = convert(&head)?;
        Ok(state.accept_head(&update, now_ms())?)
    }

    async fn label(&self, key: &AccountKey, state: &mut LogState, email: &str) -> Result<String> {
        let email = normalize_email(email);
        if let Some(known) = state.labels.get(&email) {
            return Ok(known.clone());
        }
        self.pin_head(key, state).await?;
        let oprf_key = state
            .log
            .as_ref()
            .ok_or_else(|| VaultError::unexpected("no key log"))?
            .oprf_key
            .clone();
        let blinded = label::blind(&email, &mut OsRng)?;
        let body = json!({ "blinded": blinded.blinded });
        let answer: KeyLogLabelResponse = self
            .server(key, Method::POST, "/v1/transparency/label", Some(body))
            .await??;
        let evaluated = EvaluatedLabel {
            evaluated: answer.evaluated,
            proof: answer.proof,
        };
        let found = b64_encode(&label::finish(
            &email,
            &blinded.state,
            &evaluated,
            &oprf_key,
        )?);
        state.labels.insert(email, found.clone());
        Ok(found)
    }

    async fn proof(&self, key: &AccountKey, label: &str, since: u64) -> Result<LabelProof> {
        let path = format!("/v1/transparency/proof?label={label}&since={since}");
        let answer: KeyLogProofResponse = self.server(key, Method::GET, &path, None).await??;
        convert(&answer)
    }

    /// Gives the session the account's ML-KEM key and puts the account in the log, or takes both
    /// from another device of this account that got there first. Runs before a sync, which may
    /// bring hybrid grants. The caller holds `io`.
    pub(super) async fn ensure_key_record(&self, key: &AccountKey) -> Result<()> {
        let published =
            self.with_unlocked(|unlocked| Ok(unlocked.session.bundle().key_record.is_some()))?;
        if published {
            return Ok(());
        }
        let fresh: AccountBundle = self.server(key, Method::GET, "/v1/account", None).await??;
        let keys = match (fresh.key_record, fresh.wrapped_pq_private_key) {
            (Some(record), Some(wrapped_pq_private_key)) => PublishKeys {
                record: convert(&record)?,
                wrapped_pq_private_key,
            },
            _ => self.publish(key).await?,
        };
        self.adopt(key, keys)
    }

    fn adopt(&self, key: &AccountKey, keys: PublishKeys) -> Result<()> {
        let bundle = self.with_unlocked(|unlocked| {
            unlocked.session.adopt_key_record(keys)?;
            unlocked.retry_untrusted();
            Ok(unlocked.session.bundle().clone())
        })?;
        let mut state = self.state();
        if let Some(account) = state.device.account_mut(key) {
            account.bundle = bundle;
        }
        self.save_device(&state)
    }

    async fn publish(&self, key: &AccountKey) -> Result<PublishKeys> {
        let mut state = self.key_log(key)?;
        self.pin_head(key, &mut state).await?;
        let email = self.with_unlocked(|unlocked| Ok(unlocked.session.bundle().email.clone()))?;
        let label = self.label(key, &mut state, &email).await?;
        let log_id = state
            .log
            .as_ref()
            .ok_or_else(|| VaultError::unexpected("no key log"))?
            .log_id_b64()?;
        self.save_key_log(key, state)?;
        let label: [u8; 32] = b64_decode_array(&label)?;
        let keys = self.with_unlocked(|unlocked| {
            Ok(unlocked
                .session
                .prepare_key_record(&log_id, &label, now_ms(), &mut OsRng)?)
        })?;
        let body = serde_json::to_value(&keys).expect("records serialize");
        let _: PublishKeysResponse = self
            .server(key, Method::POST, "/v1/transparency/publish", Some(body))
            .await??;
        Ok(keys)
    }

    /// Checks this account's record and reads what's new in the log, at most hourly. What it
    /// finds goes in the pins as an alert. The caller holds `io`.
    pub(super) async fn monitor_key_log(&self, key: &AccountKey, force: bool) -> Result<()> {
        let record =
            self.with_unlocked(|unlocked| Ok(unlocked.session.bundle().key_record.clone()))?;
        let Some(record) = record else {
            return Ok(());
        };
        let mut state = self.key_log(key)?;
        if !force && now_ms().saturating_sub(state.checked_at) < MONITOR_EVERY_MS {
            return Ok(());
        }
        let had_alert = state.alert.is_some();
        let result = self.read_log(key, &record, &mut state).await;
        let has_alert = state.alert.is_some();
        self.save_key_log(key, state)?;
        if has_alert != had_alert {
            self.sharing_changed();
        }
        match result {
            Err(error) if error.code == ErrorCode::KeyLogMismatch => Ok(()),
            other => other,
        }
    }

    async fn read_log(
        &self,
        key: &AccountKey,
        record: &KeyRecord,
        state: &mut LogState,
    ) -> Result<()> {
        let proof = self.proof(key, &record.label, state.pinned_size()).await?;
        state.check_own(record, &proof, now_ms())?;
        while let Some((start, end)) = state.scan_range() {
            let path = format!("/v1/transparency/entries?start={start}&end={end}");
            let page: KeyLogEntriesResponse = self.server(key, Method::GET, &path, None).await??;
            let page: LogPage = convert(&page)?;
            state.apply_page(&page, now_ms())?;
        }
        Ok(())
    }

    /// Checks keys the server offered, on this device. The caller holds `io`.
    pub(super) async fn check_account(
        &self,
        key: &AccountKey,
        account: Offered<'_>,
    ) -> Result<KeyCheck> {
        let mut state = self.key_log(key)?;
        let check = self.verify_account(key, account, &mut state).await;
        self.save_key_log(key, state)?;
        Ok(match check {
            Ok(KeyStatus::Verified) => KeyCheck::Verified,
            Ok(KeyStatus::NotLogged) => KeyCheck::NotLogged,
            Err(error) if error.code == ErrorCode::KeyLogMismatch => KeyCheck::Failed,
            Err(error) if error.code == ErrorCode::Locked => return Err(error),
            Err(_) => KeyCheck::Unavailable,
        })
    }

    async fn verify_account(
        &self,
        key: &AccountKey,
        account: Offered<'_>,
        state: &mut LogState,
    ) -> Result<KeyStatus> {
        let label = self.label(key, state, account.email).await?;
        let proof = self.proof(key, &label, state.pinned_size()).await?;
        let offered = OfferedKeys {
            account_id: account.account_id,
            public_enc_key: account.public_enc_key,
            public_sign_key: account.public_sign_key,
        };
        Ok(state.verify_account(&offered, account.record, &label, &proof, now_ms())?)
    }

    /// As `check_account`, for when a key is about to be sealed. The caller holds `io`.
    pub(super) async fn require_account(
        &self,
        key: &AccountKey,
        account: Offered<'_>,
    ) -> Result<()> {
        if self.check_account(key, account).await? == KeyCheck::Failed {
            return Err(CoreError::KeyLogMismatch.into());
        }
        Ok(())
    }

    pub fn key_log_state(&self) -> Result<KeyLogView> {
        let key = self.account_key()?;
        let state = self.key_log(&key)?;
        let published =
            self.with_unlocked(|unlocked| Ok(unlocked.session.bundle().key_record.is_some()))?;
        Ok(KeyLogView {
            published,
            checked_at: (state.checked_at != 0).then(|| iso(state.checked_at)),
            alert: state.alert.map(|alert| KeyLogAlertView {
                kind: alert.kind,
                at: iso(alert.at),
            }),
        })
    }

    /// Clears the alert and the pins behind it, trusting the log as it is now.
    pub async fn dismiss_key_log_alert(&self) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let mut state = LogState::default();
        self.pin_head(&key, &mut state).await?;
        let log_id = state
            .log
            .as_ref()
            .map(LogIdentity::log_id_b64)
            .transpose()?;
        self.save_key_log(&key, state)?;
        // A log that started again has no record of this account. The ML-KEM key stays.
        let record =
            self.with_unlocked(|unlocked| Ok(unlocked.session.bundle().key_record.clone()))?;
        if record.is_some_and(|record| Some(record.log_id) != log_id) {
            let keys = self.publish(&key).await?;
            self.adopt(&key, keys)?;
        }
        self.sharing_changed();
        self.monitor_key_log(&key, true).await
    }
}
