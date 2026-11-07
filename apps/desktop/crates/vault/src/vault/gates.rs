//! The autofill gate on the desktop app (plan 03, *Two device-auth gates*): auto-type and the
//! macOS AutoFill provider ask for the device lock on every fill while the gate is on. With it
//! off, filling works directly while the vault is unlocked. A locked vault always asks.
//!
//! **Lockless computers** follow Google Password Manager: with nothing to verify with, an
//! unlocked vault fills without a prompt. After a restart or a lock, the master password opens
//! the vault, as everywhere.
//!
//! **Stay unlocked** (plan 18, `stay_unlocked.rs`) turns the gate off while it's on: filling
//! doesn't ask. Its key is the one long-lived copy kept behind the OS user account only
//! (`DeviceUnlock::store_unprotected`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{Vault, blocking};
use crate::error::{ErrorCode, Result};
use crate::model::require;

/// Unlocking with the device lock for a fill counts for that fill: nobody needs two Touch ID
/// prompts in a row.
const AFTER_UNLOCK: Duration = Duration::from_secs(10);

impl Vault {
    /// Whether every fill asks for the device lock. On unless turned off on this computer.
    pub fn fill_gate(&self) -> bool {
        self.state().device.ask_on_fill.unwrap_or(true)
    }

    pub fn set_fill_gate(&self, on: bool) -> Result<()> {
        let mut state = self.state();
        state.device.ask_on_fill = Some(on);
        self.save_device(&state)
    }

    /// Called after the device lock opened the vault.
    pub(super) fn note_device_unlock(&self) {
        self.state().device_unlocked_at = Some(Instant::now());
    }

    /// The gate, before a fill: blocks while the prompt is up. Fails with `locked` on a locked
    /// vault and `deviceUnlockCancelled` when the user says no.
    pub fn confirm_fill(&self, reason: &str) -> Result<()> {
        {
            let state = self.state();
            require(state.unlocked.is_some(), ErrorCode::Locked)?;
            let just_unlocked = state
                .device_unlocked_at
                .is_some_and(|at| at.elapsed() < AFTER_UNLOCK);
            if just_unlocked || !state.device.ask_on_fill.unwrap_or(true) {
                return Ok(());
            }
        }
        // Stay unlocked (plan 18): filling doesn't ask; the gate applies only with it off.
        if self.stays_unlocked() {
            return Ok(());
        }
        if self.lockless() {
            return Ok(());
        }
        Ok(self.device_unlock.verify_user(reason)?)
    }

    pub async fn confirm_fill_async(self: &Arc<Self>, reason: &'static str) -> Result<()> {
        let vault = Arc::clone(self);
        blocking(move || vault.confirm_fill(reason)).await
    }

    /// Nothing to ask: no device lock Octa Pass can use here, or device unlock isn't set up.
    fn lockless(&self) -> bool {
        let enrolled = match self.current_local() {
            Some(local) => local.device_unlock.is_some(),
            None => self
                .current_account()
                .is_ok_and(|account| account.device_unlock.is_some()),
        };
        !enrolled
            || self
                .device_unlock
                .capabilities()
                .map_or(true, |capabilities| capabilities.method.is_none())
    }
}
