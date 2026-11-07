//! The master password: changing it while signed in, and resetting a forgotten one with the
//! recovery code (plan 03, Recovery), through `octapass-ffi`. The account key stays the same.

use std::sync::Arc;
use std::time::{Duration, Instant};

use octapass_ffi::{OctaPassServer, PasswordReset};
use zeroize::Zeroizing;

use super::Vault;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{NewRecoveryKit, PasswordResetResult, RecoveryKit, ResetStarted, now};

/// How long a reset waits between steps; the server drops its own after 15 minutes.
const RESET_TTL: Duration = Duration::from_secs(15 * 60);

/// A master password reset between its steps.
pub(super) struct PendingReset {
    server: Arc<OctaPassServer>,
    email: String,
    expires_at: Instant,
    /// After `verify_password_reset`.
    verified: Option<Arc<PasswordReset>>,
}

impl Vault {
    /// A new master password, after checking the current one (`invalidCredentials` when it's
    /// wrong). The Secret Key and recovery code stay; every other device is signed out, and
    /// device unlock has to be turned on again.
    pub fn change_master_password(
        &self,
        current_password: Zeroizing<String>,
        new_password: Zeroizing<String>,
    ) -> Result<()> {
        let unlocked = self.unlocked()?;
        if unlocked.account.is_local() {
            return self.change_local_password(&unlocked, &current_password, new_password);
        }
        let secret_key = self.secret_key()?;
        let _io = self.io();
        self.with_token(&unlocked, |token| {
            unlocked.server.change_master_password(
                token.into(),
                unlocked.session.clone(),
                current_password.to_string(),
                new_password.to_string(),
                secret_key.clone(),
            )
        })?;
        unlocked.store.update_account(unlocked.session.clone())?;
        self.delete_device_keys(&unlocked.account)
    }

    /// A new Secret Key with the same master password (`invalidCredentials` when it's wrong). The
    /// recovery code stays unless `new_recovery_code` is set; every other device is signed out,
    /// and device unlock has to be turned on again. The kit is the only copy of the new key off
    /// this device.
    pub fn rotate_secret_key(
        &self,
        password: Zeroizing<String>,
        new_recovery_code: bool,
    ) -> Result<NewRecoveryKit> {
        let unlocked = self.unlocked()?;
        let secret_key = self.secret_key()?;
        let _io = self.io();
        let rotated = self.with_token(&unlocked, |token| {
            unlocked.server.rotate_secret_key(
                token.into(),
                unlocked.session.clone(),
                password.to_string(),
                secret_key.clone(),
                new_recovery_code,
            )
        })?;
        self.native
            .set_secret(&unlocked.account.secret_key_name(), &rotated.secret_key)?;
        unlocked.store.update_account(unlocked.session.clone())?;
        self.delete_device_keys(&unlocked.account)?;
        Ok(NewRecoveryKit {
            email: unlocked.account.email.clone(),
            server_url: unlocked.store.server_url(),
            secret_key: rotated.secret_key,
            recovery_code: rotated.recovery_code,
            created_at: now(),
        })
    }

    /// As the contact of a released takeover record: a new master password, Secret Key and
    /// recovery code for the grantor, who is signed out everywhere (plan 06). `password` is this
    /// account's own. The kit returned is the only copy.
    pub fn take_over_account(
        &self,
        record_id: &str,
        password: Zeroizing<String>,
        new_password: Zeroizing<String>,
    ) -> Result<RecoveryKit> {
        let unlocked = self.unlocked()?;
        let secret_key = self.secret_key()?;
        let _io = self.io();
        let taken = self.with_token(&unlocked, |token| {
            unlocked.server.take_over_account(
                token.into(),
                unlocked.session.clone(),
                record_id,
                password.to_string(),
                secret_key.clone(),
                new_password.to_string(),
            )
        })?;
        Ok(RecoveryKit {
            email: taken.email,
            server_url: unlocked.store.server_url(),
            secret_key: taken.secret_key,
            recovery_code: taken.recovery_code,
            created_at: now(),
        })
    }

    /// Starts a reset with the recovery code: emails a code. The answer is the same for an
    /// email without an account.
    pub fn start_password_reset(&self, server_url: &str, email: &str) -> Result<ResetStarted> {
        let server = self.server(server_url)?;
        let email = octapass_core::kdf::normalize_email(email);
        let started = server.start_password_reset(email.clone())?;
        let mut state = self.state();
        let now = Instant::now();
        state.resets.retain(|_, reset| reset.expires_at > now);
        state.resets.insert(
            started.reset_id.clone(),
            PendingReset {
                server,
                email,
                expires_at: now + RESET_TTL,
                verified: None,
            },
        );
        Ok(ResetStarted {
            reset_id: started.reset_id,
            dev_verification_code: started.dev_verification_code,
        })
    }

    /// Checks the emailed code: `invalidVerificationCode` to try again, `resetExpired` to start
    /// over.
    pub fn verify_password_reset(&self, reset_id: &str, verification_code: &str) -> Result<()> {
        let (server, _) = self.pending_reset(reset_id)?;
        let verified = self.reset_call(reset_id, || {
            server.verify_password_reset(reset_id.into(), verification_code.into())
        })?;
        if let Some(reset) = self.state().resets.get_mut(reset_id) {
            reset.verified = Some(verified);
        }
        Ok(())
    }

    /// Opens the account key with the recovery code (`invalidRecoveryCode` when it doesn't),
    /// sets the new master password and signs in. Show the new Recovery Kit: the recovery code
    /// is always new, and so is the Secret Key unless this phone remembers the account.
    pub fn finish_password_reset(
        &self,
        reset_id: &str,
        recovery_code: &str,
        password: Zeroizing<String>,
    ) -> Result<PasswordResetResult> {
        let (server, email) = self.pending_reset(reset_id)?;
        let reset = self
            .state()
            .resets
            .get(reset_id)
            .and_then(|reset| reset.verified.clone())
            .ok_or(ErrorCode::ResetExpired)?;
        let remembered = self
            .state()
            .accounts
            .find(&server.base_url(), &email)
            .cloned();
        let secret_key = match &remembered {
            Some(account) => self
                .native
                .secret(&account.secret_key_name())?
                .map(|key| key.to_string()),
            None => None,
        };
        let kit = {
            let _io = self.io();
            self.reset_call(reset_id, || {
                reset.finish(
                    recovery_code.into(),
                    password.to_string(),
                    secret_key.clone(),
                )
            })?
        };
        self.state().resets.remove(reset_id);
        let recovery_kit = RecoveryKit {
            email: email.clone(),
            server_url: server.base_url(),
            secret_key: kit.secret_key.clone(),
            recovery_code: kit.recovery_code,
            created_at: now(),
        };
        // Every device was signed out, this one too. A new master password starts device unlock
        // from scratch.
        if let Some(account) = &remembered {
            if let Ok(store) = self.open_store(account) {
                store.disable_device_unlock()?;
            }
            self.delete_device_keys(account)?;
        }
        // The new kit matters more than signing in, which can be done again by hand.
        let sign_in = self
            .sign_in(
                &server.base_url(),
                &email,
                password,
                Some(Zeroizing::new(kit.secret_key)),
            )
            .ok();
        Ok(PasswordResetResult {
            recovery_kit,
            sign_in,
        })
    }

    /// Drops a reset in progress: "Start over".
    pub fn cancel_password_reset(&self, reset_id: &str) {
        self.state().resets.remove(reset_id);
    }

    /// A live reset's server and email.
    fn pending_reset(&self, reset_id: &str) -> Result<(Arc<OctaPassServer>, String)> {
        let state = self.state();
        let reset = state
            .resets
            .get(reset_id)
            .filter(|reset| reset.expires_at > Instant::now())
            .ok_or(ErrorCode::ResetExpired)?;
        Ok((reset.server.clone(), reset.email.clone()))
    }

    /// A reset's server call. When the server says the reset is over, it's dropped here too.
    fn reset_call<T>(
        &self,
        reset_id: &str,
        call: impl FnOnce() -> std::result::Result<T, octapass_ffi::OctaPassError>,
    ) -> Result<T> {
        call().map_err(|error| {
            let error = VaultError::from(error);
            if error.code == ErrorCode::ResetExpired {
                self.state().resets.remove(reset_id);
            }
            error
        })
    }
}
