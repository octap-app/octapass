//! The master password: changing it while signed in, and resetting a forgotten one with the
//! recovery code (plan 03, Recovery). The account key stays the same, so nothing is re-encrypted.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use octapass_api::problem::types;
use octapass_api::{
    AccountBundle as ApiBundle, ChangePasswordRequest, ReauthPurpose, RecoverFinishRequest,
    RecoverVerifyRequest,
};
use octapass_core::account::AccountBundle;
use octapass_core::kdf::KdfParams;
use octapass_core::opaque::RegistrationClient;
use octapass_core::recovery::RecoveryCode;
use octapass_core::secret_key::SecretKey;
use octapass_core::session::Session;
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::{Login, PendingTwoStep, Vault, blocking, convert, normalize_server_url, valid_email};
use crate::api::Method;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{
    NewRecoveryKit, PasswordResetResult, RecoveryKit, ResetStarted, SignInResult, TwoStepMethod,
    now, rfc3339,
};
use crate::store::AccountKey;

/// A master password reset with the recovery code, between its steps.
pub(super) struct PendingReset {
    pub(super) server_url: String,
    pub(super) email: String,
    pub(super) expires_at: Instant,
    /// After `verify_password_reset`: the account bundle and the server's challenge to sign.
    pub(super) verified: Option<(AccountBundle, String)>,
}

/// How long a reset waits between steps; the server drops its own after 15 minutes.
pub(super) const RESET_TTL: Duration = Duration::from_secs(15 * 60);

impl Vault {
    /// A new master password, after checking the current one (`invalidCredentials` when it's
    /// wrong). The Secret Key and recovery code stay; every other device is signed out, and
    /// device unlock has to be turned on again.
    pub async fn change_master_password(
        &self,
        current_password: Zeroizing<String>,
        new_password: Zeroizing<String>,
    ) -> Result<()> {
        if let Some(local) = self.current_local() {
            return self
                .change_local_password(local, current_password, new_password)
                .await;
        }
        let account = self.unlocked_account()?;
        let _io = self.io.lock().await;
        let (reauth_token, session) = self
            .reauth_session(&account, current_password, ReauthPurpose::ChangePassword)
            .await?;
        let secret_key = SecretKey::parse(&account.secret_key)?;
        let new = blocking(move || {
            Ok(session.new_credentials(
                &new_password,
                Some(secret_key),
                false,
                KdfParams::DEFAULT,
                &mut OsRng,
            )?)
        })
        .await?;
        let (registration, registration_request) =
            RegistrationClient::start(&new.keys.auth_secret, &mut OsRng)?;
        let registered = self
            .authed(&account.key, |api, token| {
                let request = registration_request.clone();
                async move { api.password_registration(&token, &request).await }
            })
            .await??;
        let request = ChangePasswordRequest {
            registration_upload: registration.finish(
                &new.keys.auth_secret,
                &registered.registration_response,
                &mut OsRng,
            )?,
            account: convert(&new.update)?,
        };
        self.authed(&account.key, |api, token| {
            let (request, reauth_token) = (request.clone(), reauth_token.clone());
            async move { api.change_password(&token, &reauth_token, &request).await }
        })
        .await??;

        // The server now has the new bundle: keep it, so later unlocks and reauths use the new
        // password. Device unlock wrapped the account key for the old one's sake; start over.
        {
            let mut state = self.state();
            if let Some(unlocked) = state
                .unlocked
                .as_mut()
                .filter(|unlocked| unlocked.key == account.key)
            {
                unlocked.session.accept_credentials(&new);
            }
            if let Some(stored) = state.device.account_mut(&account.key) {
                stored.bundle = new.apply(&account.bundle);
                stored.last_password_unlock_at = rfc3339(now());
            }
            self.save_device(&state)?;
        }
        self.remove_device_unlock(&account.key)?;
        // Plan 18: the stay-unlocked key goes with it; the next unlock makes a new one.
        self.forget_stay_unlocked(&account.key)
    }

    /// A new Secret Key with the same master password (`invalidCredentials` when it's wrong). The
    /// account key stays, so nothing is re-encrypted; the recovery code stays unless
    /// `new_recovery_code` is set. Every other device is signed out, and device unlock has to be
    /// turned on again. The kit is the only copy of the new key off this device.
    pub async fn rotate_secret_key(
        &self,
        password: Zeroizing<String>,
        new_recovery_code: bool,
    ) -> Result<NewRecoveryKit> {
        let account = self.unlocked_account()?;
        let _io = self.io.lock().await;
        let (reauth_token, session) = self
            .reauth_session(&account, password.clone(), ReauthPurpose::RotateSecretKey)
            .await?;
        let new = blocking(move || {
            Ok(session.new_credentials(
                &password,
                None,
                new_recovery_code,
                KdfParams::DEFAULT,
                &mut OsRng,
            )?)
        })
        .await?;
        let (registration, registration_request) =
            RegistrationClient::start(&new.keys.auth_secret, &mut OsRng)?;
        let registered = self
            .authed(&account.key, |api, token| {
                let request = registration_request.clone();
                async move { api.password_registration(&token, &request).await }
            })
            .await??;
        let request = ChangePasswordRequest {
            registration_upload: registration.finish(
                &new.keys.auth_secret,
                &registered.registration_response,
                &mut OsRng,
            )?,
            account: convert(&new.update)?,
        };
        let sent = self
            .authed(&account.key, |api, token| {
                let (request, reauth_token) = (request.clone(), reauth_token.clone());
                async move { api.rotate_secret_key(&token, &reauth_token, &request).await }
            })
            .await?;
        if let Err(error) = sent {
            // A lost answer must not lose the only copy of the new key: ask whether it landed.
            let stored = self
                .server::<ApiBundle>(&account.key, Method::GET, "/v1/account", None)
                .await
                .ok()
                .and_then(Result::ok);
            if stored.is_none_or(|stored| stored.account_salt != new.update.account_salt) {
                return Err(error.into());
            }
        }

        let secret_key = new.secret_key.to_text().to_string();
        {
            let mut state = self.state();
            if let Some(unlocked) = state
                .unlocked
                .as_mut()
                .filter(|unlocked| unlocked.key == account.key)
            {
                unlocked.session.accept_credentials(&new);
            }
            if let Some(stored) = state.device.account_mut(&account.key) {
                stored.bundle = new.apply(&account.bundle);
                stored.secret_key = secret_key.clone();
                stored.last_password_unlock_at = rfc3339(now());
            }
            self.save_device(&state)?;
        }
        self.remove_device_unlock(&account.key)?;
        self.forget_stay_unlocked(&account.key)?;
        Ok(NewRecoveryKit {
            email: account.key.email.clone(),
            server_url: account.key.server_url.clone(),
            secret_key,
            recovery_code: new
                .recovery_code
                .as_ref()
                .map(|code| code.to_text().to_string()),
            created_at: rfc3339(now()),
        })
    }

    /// Starts a master password reset with the recovery code: emails a code. The answer is the
    /// same for an email without an account.
    pub async fn start_password_reset(
        &self,
        server_url: &str,
        email: &str,
    ) -> Result<ResetStarted> {
        let server_url = normalize_server_url(server_url)?;
        let email = valid_email(email)?;
        let started = self.api(&server_url).recover_start(&email).await?;
        let mut state = self.state();
        let now = Instant::now();
        state.resets.retain(|_, reset| reset.expires_at > now);
        state.resets.insert(
            started.recovery_id.clone(),
            PendingReset {
                server_url,
                email,
                expires_at: now + RESET_TTL,
                verified: None,
            },
        );
        Ok(ResetStarted {
            reset_id: started.recovery_id,
            dev_verification_code: started.dev_verification_code,
        })
    }

    /// Checks the emailed code: `invalidVerificationCode` to try again, `resetExpired` to start
    /// over.
    pub async fn verify_password_reset(
        &self,
        reset_id: &str,
        verification_code: &str,
    ) -> Result<()> {
        let server_url = self.pending_reset(reset_id)?.0;
        let request = RecoverVerifyRequest {
            recovery_id: reset_id.into(),
            verification_code: verification_code.split_whitespace().collect(),
        };
        let verified = self
            .reset_call(reset_id, self.api(&server_url).recover_verify(&request))
            .await?;
        let bundle: AccountBundle = convert(&verified.account)?;
        if let Some(reset) = self.state().resets.get_mut(reset_id) {
            reset.verified = Some((bundle, verified.challenge));
        }
        Ok(())
    }

    /// Opens the account key with the recovery code (`invalidRecoveryCode` when it doesn't),
    /// sets the new master password and signs in. Show the new Recovery Kit: the recovery code
    /// is always new, and so is the Secret Key unless this device remembers the account. Every
    /// device was signed out.
    pub async fn finish_password_reset(
        self: &Arc<Self>,
        reset_id: &str,
        recovery_code: &str,
        password: Zeroizing<String>,
    ) -> Result<PasswordResetResult> {
        let (server_url, email, verified) = self.pending_reset(reset_id)?;
        let (bundle, challenge) = verified.ok_or(ErrorCode::ResetExpired)?;
        let code =
            RecoveryCode::parse(recovery_code).map_err(|_| ErrorCode::InvalidRecoveryCode)?;
        let session =
            Session::recover(bundle, &code).map_err(|_| ErrorCode::InvalidRecoveryCode)?;
        let key = AccountKey {
            server_url: server_url.clone(),
            email: email.clone(),
        };
        let remembered = self.state().device.account(&key).cloned();
        let secret_key = remembered
            .as_ref()
            .map(|account| SecretKey::parse(&account.secret_key))
            .transpose()?;
        let (session, new) = blocking(move || {
            let new = session.new_credentials(
                &password,
                secret_key,
                true,
                KdfParams::DEFAULT,
                &mut OsRng,
            )?;
            Ok((session, new))
        })
        .await?;

        let _io = self.io.lock().await;
        let api = self.api(&server_url);
        let (registration, registration_request) =
            RegistrationClient::start(&new.keys.auth_secret, &mut OsRng)?;
        let registered = self
            .reset_call(
                reset_id,
                api.recover_registration(reset_id, &registration_request),
            )
            .await?;
        let registration_upload = registration.finish(
            &new.keys.auth_secret,
            &registered.registration_response,
            &mut OsRng,
        )?;
        let signature = session.sign_recovery(&challenge, &registration_upload, &new.update)?;
        let request = RecoverFinishRequest {
            recovery_id: reset_id.into(),
            registration_upload,
            account: convert(&new.update)?,
            signature,
        };
        self.reset_call(reset_id, api.recover_finish(&request))
            .await?;
        self.state().resets.remove(reset_id);

        let recovery_kit = RecoveryKit {
            email: email.clone(),
            server_url: server_url.clone(),
            secret_key: new.secret_key.to_text().to_string(),
            recovery_code: new
                .recovery_code
                .as_ref()
                .map(|code| code.to_text().to_string())
                .ok_or_else(|| {
                    VaultError::unexpected("a reset always makes a new recovery code")
                })?,
            created_at: rfc3339(now()),
        };
        // Every device was signed out, this one too. A new master password starts device unlock
        // from scratch.
        if remembered.is_some() {
            self.remove_device_unlock(&key)?;
            self.forget_stay_unlocked(&key)?;
        }
        // The new kit matters more than signing in, which can be done again by hand.
        let trusted = remembered.and_then(|account| account.trusted_device_token);
        let sign_in = match self.login(&api, &email, &new.keys, trusted).await {
            Ok(Login::Finished(login)) => self
                .finish_sign_in(key, &new.secret_key, &new.keys, login)
                .await
                .ok()
                .map(|()| SignInResult::SignedIn),
            Ok(Login::SecondStep(challenge)) => {
                let methods = TwoStepMethod::offered(&challenge.methods);
                self.state().two_step = Some(PendingTwoStep {
                    key,
                    secret_key: new.secret_key.clone(),
                    keys: new.keys.clone(),
                    challenge_id: challenge.challenge_id,
                    expires_at: Instant::now() + Duration::from_secs(challenge.expires_in),
                });
                Some(SignInResult::TwoStepRequired { methods })
            }
            Ok(Login::Sso(challenge)) => {
                self.state().sso = Some(PendingTwoStep {
                    key,
                    secret_key: new.secret_key.clone(),
                    keys: new.keys.clone(),
                    challenge_id: challenge.challenge_id,
                    expires_at: Instant::now() + Duration::from_secs(challenge.expires_in),
                });
                Some(SignInResult::SsoRequired {
                    url: challenge.url,
                    org_name: challenge.org_name,
                })
            }
            Err(_) => None,
        };
        Ok(PasswordResetResult {
            recovery_kit,
            sign_in,
        })
    }

    /// Drops a reset in progress: "Start over".
    pub fn cancel_password_reset(&self, reset_id: &str) {
        self.state().resets.remove(reset_id);
    }

    /// A live reset: its server, email and (once verified) bundle and challenge.
    #[allow(clippy::type_complexity)]
    fn pending_reset(
        &self,
        reset_id: &str,
    ) -> Result<(String, String, Option<(AccountBundle, String)>)> {
        let state = self.state();
        let reset = state
            .resets
            .get(reset_id)
            .filter(|reset| reset.expires_at > Instant::now())
            .ok_or(ErrorCode::ResetExpired)?;
        Ok((
            reset.server_url.clone(),
            reset.email.clone(),
            reset.verified.clone(),
        ))
    }

    /// A reset's server call. When the server says the reset is over, it's dropped here too.
    async fn reset_call<T>(
        &self,
        reset_id: &str,
        call: impl Future<Output = crate::api::ApiResult<T>>,
    ) -> Result<T> {
        match call.await {
            Ok(value) => Ok(value),
            Err(error) => {
                if error.is(types::RECOVERY_EXPIRED) {
                    self.state().resets.remove(reset_id);
                }
                Err(error.into())
            }
        }
    }
}
