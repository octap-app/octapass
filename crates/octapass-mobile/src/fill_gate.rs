//! The autofill gate on the phones (plan 03, *Two device-auth gates*): `Settings::
//! device_auth_on_autofill`, per phone, never synced, on by default. On, the AutoFill extension
//! (iOS) and the Autofill and Credential Manager services (Android) ask for the device lock on
//! every fill, as before. Off, they fill directly **while the app's vault is unlocked**; a locked
//! vault always asks.
//!
//! The extension and the services run apart from the app's vault (another process on iOS, their
//! own store on Android), so "unlocked" reaches them as a **fill key**: the account key wrapped
//! like stay unlocked's (`LocalStore.fillKey`), with the moment the app's lock timer runs out in
//! front, in the same kind of platform item (`NativePlatform.storeStayUnlockedKey`, name
//! `unlockedFill.<account tag>`), which the phone's own lock guards. The app keeps it only while
//! its vault is unlocked and deletes it whenever it locks; the deadline stops it even when the app
//! is suspended and can't. With the timer at "only when the app is closed", the longest timer
//! (4 hours) stands in, since the app can't tell the extension it was closed.
//!
//! **Lockless** (device unlock not set up here) follows the same path whatever the switch says,
//! as the desktop app does: with nothing to verify with, an unlocked vault fills without a prompt
//! (plan 03). A phone with no passcode can't keep the key at all, so it keeps asking for the
//! master password: no unguarded key copy (plan 03, plan 18).
//!
//! **Stay unlocked** (plan 18) replaces both: its own key fills, so no fill key is kept while it's
//! on.

use std::sync::Arc;
use std::time::Duration;

use crate::vault::{OctaPassVault, now_ms};

/// The fill key's life when the auto-lock is "only when the app is closed": the longest timer.
const CLOSED_APP_MINUTES: u32 = 240;
/// The key is written again once the app's lock time has moved on by this much.
const REWRITE_MS: u64 = 60_000;

/// Rust-only.
impl OctaPassVault {
    /// Filling may skip its prompt now: the vault is unlocked here, stay unlocked isn't on (its
    /// own key fills then), and the gate is off or there's nothing to ask with.
    pub(crate) fn fill_key_wanted(&self) -> bool {
        if !self.is_unlocked() || self.stays_unlocked() {
            return false;
        }
        !self.settings().device_auth_on_autofill
            || !self.vault.unlock_methods().device_unlock_enabled
    }

    /// When the app's vault locks by its timer, in ms since 1970.
    pub(crate) fn lock_deadline_ms(&self) -> u64 {
        let minutes = match self.settings().auto_lock_minutes {
            0 => CLOSED_APP_MINUTES,
            minutes => minutes,
        };
        let timeout = Duration::from_secs(u64::from(minutes) * 60);
        let left = timeout.saturating_sub(self.idle());
        now_ms().saturating_add(u64::try_from(left.as_millis()).unwrap_or(u64::MAX))
    }

    /// Writes, moves on or deletes the fill key to match the vault and the settings. `force`
    /// writes it again even when the deadline barely moved (after an unlock, a settings change).
    /// Never fails: a key that can't be written means the next fill asks, which is the safe side.
    pub(crate) fn refresh_fill_key(&self, force: bool) {
        let mut until = self.fill_key_until();
        if !self.fill_key_wanted() {
            if until.take().is_some() || force {
                self.vault.delete_fill_key();
            }
            return;
        }
        let deadline = self.lock_deadline_ms();
        if !force && until.is_some_and(|until| deadline.abs_diff(until) < REWRITE_MS) {
            return;
        }
        *until = self.vault.store_fill_key(deadline).ok().map(|()| deadline);
        // Locked meanwhile, after its own delete: this key mustn't outlive it.
        if until.is_some() && !self.is_unlocked() {
            self.vault.delete_fill_key();
            *until = None;
        }
    }

    /// The auto-lock tick: moves the key on while the user keeps using the app. Cheap when there's
    /// no key.
    pub(crate) fn tick_fill_key(&self) {
        let Some(until) = *self.fill_key_until() else {
            return;
        };
        if !self.is_unlocked() || self.lock_deadline_ms().abs_diff(until) >= REWRITE_MS {
            self.refresh_fill_key(false);
        }
    }

    /// After any unlock, on its own thread: the session event that calls it may come from inside
    /// the vault.
    pub(crate) fn fill_key_after_unlock(self: &Arc<Self>) {
        let this = Arc::clone(self);
        std::thread::spawn(move || this.refresh_fill_key(true));
    }
}

#[uniffi::export]
impl OctaPassVault {
    /// Whether the AutoFill extension or the Autofill services can fill without a prompt right
    /// now because of the autofill gate (not stay unlocked): the fill key is on this phone.
    pub fn fills_without_prompt(&self) -> bool {
        self.fill_key_until().is_some() && self.vault.has_fill_key()
    }
}
