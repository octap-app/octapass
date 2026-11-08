//! Stay unlocked while logged in to this phone (plan 18). On by default, per phone, never synced
//! (`Settings::stay_unlocked`). While it's on and the phone has a passcode:
//!
//! - the app opens without a prompt (`unlockStayUnlocked`, called by the app when it starts or
//!   comes back while locked), and the autofill extension or services fill without one, from the
//!   same key (`LocalStore.unlockStayUnlocked`);
//! - there's no lock timer and no lock in the background;
//! - "Lock now" holds until the user unlocks once;
//! - the 14-day master password check still stops it (`passwordRequired`).
//!
//! Revealing and copying ask once (the app's `confirmedUnlock`), and the high-risk actions ask
//! every time: those are the app's, not this crate's. Without a passcode the phone falls back to
//! the lock timer and the two device-auth gates.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::error::Result;
use crate::vault::OctaPassVault;

/// What Settings shows under the switch, and what the app checks before opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct StayUnlockedStatus {
    /// The switch (`Settings::stay_unlocked`).
    pub on: bool,
    /// The phone has a passcode (or a secure lock screen). Without one, Settings says "Set a
    /// passcode on this device to stay unlocked." and the phone locks as before.
    pub available: bool,
    /// This account's key is on the phone, so the app can open without a prompt.
    pub enrolled: bool,
    /// The 14-day master password check is due: the master password opens the vault once first.
    pub password_required: bool,
}

/// Rust-only.
impl OctaPassVault {
    /// The switch is on and the phone can honour it: no lock timer, no lock in the background.
    pub(crate) fn stays_unlocked(&self) -> bool {
        self.settings().stay_unlocked && self.vault.stay_unlocked_status().available
    }

    /// After every unlock, however it happened: the hold ends, and with the switch on the
    /// account gets its key if it has none (after sign-in, a password change, a new phone).
    /// Runs on its own thread: the session event that calls it may come from inside the vault.
    pub(crate) fn after_any_unlock(self: &Arc<Self>) {
        self.held.store(false, Ordering::SeqCst);
        // The autofill gate off fills while the vault is unlocked (plan 03, `fill_gate`).
        self.fill_key_after_unlock();
        if !self.settings().stay_unlocked {
            return;
        }
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            let status = this.vault.stay_unlocked_status();
            if status.available && !status.enrolled {
                let _ = this.vault.enable_stay_unlocked();
            }
        });
    }

    /// `updateSettings` turned the switch on or off.
    pub(crate) fn stay_unlocked_changed(&self, on: bool) -> Result<()> {
        if on {
            if self.vault.snapshot().session.status
                == octapass_mobile_vault::model::SessionStatus::Unlocked
                && self.vault.stay_unlocked_status().available
            {
                self.vault.enable_stay_unlocked()?;
            }
            Ok(())
        } else {
            match self.vault.disable_stay_unlocked() {
                // Signed out: there's no account key to forget.
                Err(error) if error.code == octapass_mobile_vault::ErrorCode::Locked => Ok(()),
                other => Ok(other?),
            }
        }
    }
}

#[uniffi::export]
impl OctaPassVault {
    pub fn stay_unlocked_status(&self) -> StayUnlockedStatus {
        let status = self.vault.stay_unlocked_status();
        StayUnlockedStatus {
            on: self.settings().stay_unlocked,
            available: status.available,
            enrolled: status.enrolled,
            password_required: status.password_required,
        }
    }

    /// Opens the vault without a prompt when stay unlocked is on, the phone has a passcode, the
    /// user didn't lock it with "Lock now", and the 14-day check isn't due. True when the vault
    /// is unlocked afterwards; false means show the unlock screen as before (`passwordRequired`
    /// is in `stayUnlockedStatus`). Call it when the app starts or comes back while locked.
    pub async fn unlock_stay_unlocked(self: Arc<Self>) -> Result<bool> {
        self.run(|this| {
            if !this.settings().stay_unlocked || this.held.load(Ordering::SeqCst) {
                return Ok(false);
            }
            match this.vault.unlock_stay_unlocked() {
                Ok(true) => {
                    this.after_unlock();
                    Ok(true)
                }
                Ok(false) => Ok(false),
                Err(error) if error.code == octapass_mobile_vault::ErrorCode::PasswordRequired => {
                    Ok(false)
                }
                Err(error) if error.code == octapass_mobile_vault::ErrorCode::Locked => Ok(false),
                Err(error) => Err(error.into()),
            }
        })
        .await
    }
}
