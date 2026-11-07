//! Stay unlocked while logged in to this computer (plan 18). Per computer, never synced, on by
//! default (`DeviceState::stay_unlocked`; the app's migration decides for existing installs).
//!
//! The key is the device-unlock wrapping of the account key (`octapass_core::device`) under a
//! random 32-byte secret kept in the system key store with no presence check
//! (`DeviceUnlock::store_unprotected`: the Keychain with no access-control flags, DPAPI, the
//! Secret Service), the way the CLI's `octapass unlock` session keeps its key. While it's on:
//!
//! - the app opens without a prompt ([`Vault::unlock_stay_unlocked`]);
//! - filling doesn't ask (`confirm_fill`), and the browser extension gets the account key through
//!   native messaging without a prompt (`wrap_session_key`);
//! - a session it opened isn't `confirmed`: the first reveal or copy asks, and the answer covers
//!   the rest until the vault locks, the screen locks or the computer sleeps ([`Vault::device_locked`]);
//! - "Lock now" holds until the user unlocks;
//! - the 14-day master password check stops it, and a master password change or reset, a Secret
//!   Key rotation or forgetting the account deletes the key, as for device unlock.
//!
//! Without a usable key store (Linux with no keyring running) it falls back to locking as before.

use std::sync::Arc;

use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::local::LocalVault;
use octapass_core::session::Session;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use zeroize::Zeroizing;

use super::{Vault, blocking, password_due};
use crate::error::Result;
use crate::model::{now, rfc3339};
use crate::store::{AccountKey, WrappedAsk};

/// Asked of the key store to see whether it works at all; never written.
const PROBE: &str = "octapass/stay-unlocked/probe";

/// What Settings shows under the switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StayUnlockedStatus {
    /// `None` until this computer has decided (the app's migration).
    pub on: Option<bool>,
    /// The system key store works here.
    pub available: bool,
    /// Why not, when not: `noKeyring`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<&'static str>,
    /// The current account has its key on this computer.
    pub enrolled: bool,
    /// The 14-day master password check is due: the master password opens the vault once first.
    pub password_required: bool,
}

impl Vault {
    pub async fn stay_unlocked_status(self: &Arc<Self>) -> StayUnlockedStatus {
        let device_unlock = Arc::clone(&self.device_unlock);
        let available = blocking(move || Ok(device_unlock.load_unprotected(PROBE).is_ok()))
            .await
            .unwrap_or(false);
        let state = self.state();
        let current = state.device.current.clone();
        let enrolled = current
            .as_ref()
            .is_some_and(|key| state.device.stay_unlocked_keys.contains_key(&key.id()));
        let password_required = current.as_ref().is_some_and(|key| {
            state
                .device
                .local(key)
                .map(|local| &local.last_password_unlock_at)
                .or_else(|| {
                    state
                        .device
                        .account(key)
                        .map(|account| &account.last_password_unlock_at)
                })
                .is_some_and(|at| password_due(at))
        });
        StayUnlockedStatus {
            on: state.device.stay_unlocked,
            available,
            unavailable: (!available).then_some("noKeyring"),
            enrolled,
            password_required,
        }
    }

    /// The switch. On, the open account gets its key now; off, every account's key on this
    /// computer goes.
    pub async fn set_stay_unlocked(self: &Arc<Self>, on: bool) -> Result<StayUnlockedStatus> {
        let forget: Vec<String> = {
            let mut state = self.state();
            state.device.stay_unlocked = Some(on);
            let forget = if on {
                Vec::new()
            } else {
                std::mem::take(&mut state.device.stay_unlocked_keys)
                    .into_keys()
                    .collect()
            };
            self.save_device(&state)?;
            forget
        };
        let device_unlock = Arc::clone(&self.device_unlock);
        blocking(move || {
            for id in forget {
                let _ = device_unlock.remove_unprotected(&id);
            }
            Ok(())
        })
        .await?;
        if on {
            self.enroll_stay_unlocked();
        }
        Ok(self.stay_unlocked_status().await)
    }

    /// The switch is on and the current account has its key: no prompt to open, fill or hand the
    /// key to the browser extension.
    pub fn stays_unlocked(&self) -> bool {
        let state = self.state();
        state.device.stay_unlocked == Some(true)
            && state
                .device
                .current
                .as_ref()
                .is_some_and(|key| state.device.stay_unlocked_keys.contains_key(&key.id()))
    }

    /// After every unlock: with the switch on, the open account gets a key if it has none (after
    /// sign-in, a password change, a new computer). Best effort: without a key store the
    /// computer simply locks as before.
    pub(super) fn enroll_stay_unlocked(&self) {
        let (id, generation, wrapped, secret) = {
            let state = self.state();
            if state.device.stay_unlocked != Some(true) {
                return;
            }
            let Some(unlocked) = state.unlocked.as_ref() else {
                return;
            };
            let id = unlocked.key.id();
            if state.device.stay_unlocked_keys.contains_key(&id) {
                return;
            }
            let mut secret = Zeroizing::new([0u8; octapass_device_unlock::SECRET_LEN]);
            OsRng.fill_bytes(secret.as_mut());
            let Ok(wrapped) = unlocked
                .session
                .enable_device_unlock(secret.as_ref(), &mut OsRng)
            else {
                return;
            };
            (id, state.generation, wrapped, secret)
        };
        // Not under the state lock: a keyring may take its time (or ask to be unlocked).
        if self.device_unlock.store_unprotected(&id, &secret).is_err() {
            return;
        }
        let mut state = self.state();
        let still_open = state.generation == generation
            && state
                .unlocked
                .as_ref()
                .is_some_and(|unlocked| unlocked.key.id() == id);
        if !still_open || state.device.stay_unlocked != Some(true) {
            drop(state);
            let _ = self.device_unlock.remove_unprotected(&id);
            return;
        }
        state.device.stay_unlocked_keys.insert(
            id,
            WrappedAsk {
                device_salt: b64_encode(&wrapped.device_salt),
                wrapped_ask: wrapped.wrapped_ask,
                enabled_at: rfc3339(now()),
            },
        );
        let _ = self.save_device(&state);
    }

    /// Deletes an account's key: the events that end device unlock end it too (plan 03, plan 18).
    pub(crate) fn forget_stay_unlocked(&self, key: &AccountKey) -> Result<()> {
        let id = key.id();
        let _ = self.device_unlock.remove_unprotected(&id);
        let mut state = self.state();
        if state.device.stay_unlocked_keys.remove(&id).is_some() {
            self.save_device(&state)?;
        }
        Ok(())
    }

    /// Opens the current account or local vault with its key, without a prompt. False when it
    /// can't: the switch is off, "Lock now" is holding, there's no key, or the 14-day check is
    /// due. A key the key store lost, or that no longer opens the vault, is deleted.
    pub async fn unlock_stay_unlocked(self: &Arc<Self>) -> Result<bool> {
        let (key, record, local, account) = {
            let state = self.state();
            if state.unlocked.is_some() {
                return Ok(true);
            }
            if state.device.stay_unlocked != Some(true) || state.held {
                return Ok(false);
            }
            let Some(key) = state.device.current.clone() else {
                return Ok(false);
            };
            let Some(record) = state.device.stay_unlocked_keys.get(&key.id()).cloned() else {
                return Ok(false);
            };
            let local = state.device.local(&key).cloned();
            let account = state.device.account(&key).cloned();
            (key, record, local, account)
        };
        let last_password = match (&local, &account) {
            (Some(local), _) => &local.last_password_unlock_at,
            (None, Some(account)) => &account.last_password_unlock_at,
            (None, None) => return Ok(false),
        };
        if password_due(last_password) {
            return Ok(false);
        }
        let device_unlock = Arc::clone(&self.device_unlock);
        let id = key.id();
        let secret = match blocking(move || Ok(device_unlock.load_unprotected(&id)?)).await {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                self.forget_stay_unlocked(&key)?;
                return Ok(false);
            }
            // The key store isn't reachable right now: ask as before, keep the key.
            Err(_) => return Ok(false),
        };
        let salt = b64_decode(&record.device_salt)?;
        if let Some(local) = local {
            let blob = self.store.read_local(&local.tag)?;
            let Ok(vault) = LocalVault::unlock_with_device_key(
                &blob,
                secret.as_ref(),
                &salt,
                &record.wrapped_ask,
            ) else {
                self.forget_stay_unlocked(&key)?;
                return Ok(false);
            };
            if self.state().unlocked.is_some() {
                return Ok(true);
            }
            self.install_local_as(local, vault, false)?;
            return Ok(true);
        }
        let account = account.expect("matched above");
        let Ok(session) = Session::unlock_with_device_key(
            account.bundle.clone(),
            secret.as_ref(),
            &salt,
            &record.wrapped_ask,
        ) else {
            self.forget_stay_unlocked(&key)?;
            return Ok(false);
        };
        // The user may have unlocked meanwhile.
        if self.state().unlocked.is_some() {
            return Ok(true);
        }
        self.install_as(key.clone(), session, false)?;
        let vault = Arc::clone(self);
        tokio::spawn(async move {
            let result = vault.resume_server_session(&key, None).await;
            vault.report(result);
        });
        Ok(true)
    }

    /// The screen locked or the computer slept. While staying unlocked, revealing and copying ask
    /// again (plan 18). Otherwise nothing changes (plan 03's once-per-unlock rule).
    pub fn device_locked(&self) {
        if !self.stays_unlocked() {
            return;
        }
        let changed = {
            let mut state = self.state();
            match state.unlocked.as_mut() {
                Some(unlocked) if unlocked.confirmed => {
                    unlocked.confirmed = false;
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.emit_session();
        }
    }

    /// The user answered the device lock or the master password: revealing and copying are
    /// covered until the vault locks (or, while staying unlocked, the screen locks).
    pub(crate) fn mark_confirmed(&self) {
        let changed = {
            let mut state = self.state();
            match state.unlocked.as_mut() {
                Some(unlocked) if !unlocked.confirmed => {
                    unlocked.confirmed = true;
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.emit_session();
        }
    }
}
