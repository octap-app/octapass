//! The master password: changing it while signed in, and resetting a forgotten one with the
//! recovery code (plan 03, Recovery). The account key stays the same, so nothing is re-encrypted.
//!
//! ```text
//! change   server.changeMasterPassword(token, session, current, new, secretKey)
//!          store.updateAccount(session)                       (device unlock is turned off)
//! rotate   server.rotate_secret_key(token, session, password, secretKey, newRecoveryCode)
//!          store the new Secret Key; store.updateAccount(session)   (Rust only)
//! reset    server.startPasswordReset(email)  → emailed code
//!          server.verifyPasswordReset(id, code) → reset
//!          reset.finish(recoveryCode, password, secretKey?) → new Recovery Kit secrets
//!          then sign in with logInTrusted and the new password and Secret Key
//! ```

use std::sync::Arc;

use octapass_api as api;
use octapass_core::account::AccountBundle;
use octapass_core::kdf::KdfParams;
use octapass_core::opaque::RegistrationClient;
use octapass_core::recovery::RecoveryCode;
use octapass_core::secret_key::SecretKey;
use octapass_core::session::Session as CoreSession;
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::error::{OctaPassError, Result};
use crate::http::{Api, HttpMethod};
use crate::now_ms;
use crate::server::{OctaPassServer, ReauthPurpose};
use crate::session::Session;
use crate::store::LocalStore;

/// What rotating the Secret Key made. Show them once, on a new Recovery Kit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatedSecretKey {
    pub secret_key: String,
    /// Only when it was replaced too.
    pub recovery_code: Option<String>,
}

/// What an emergency takeover made: the only copy of the grantor's new Recovery Kit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakenOver {
    pub email: String,
    pub secret_key: String,
    pub recovery_code: String,
}

/// A reset that emailed its code.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordResetStart {
    pub reset_id: String,
    /// Only from a server in dev mode.
    pub dev_verification_code: Option<String>,
}

/// The secrets of the new Recovery Kit after a reset. Show them once.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasswordResetKit {
    pub secret_key: String,
    pub recovery_code: String,
}

/// A reset whose emailed code was right: the account bundle and the server's challenge.
#[derive(uniffi::Object)]
pub struct PasswordReset {
    api: Api,
    reset_id: String,
    bundle: AccountBundle,
    challenge: String,
}

#[uniffi::export]
impl OctaPassServer {
    /// A new master password, after checking the current one (`LoginFailed` when it's wrong).
    /// The Secret Key and recovery code stay; every other device is signed out. `session` keeps
    /// the new bundle: then call `LocalStore.updateAccount(session)`, and delete the device unlock
    /// secret. Runs Argon2id twice; call it off the main thread.
    pub fn change_master_password(
        &self,
        access_token: String,
        session: Arc<Session>,
        current_password: String,
        new_password: String,
        secret_key: String,
    ) -> Result<()> {
        let new_password = Zeroizing::new(new_password);
        let reauth_token = self.reauth(
            access_token.clone(),
            Arc::clone(&session),
            current_password,
            secret_key.clone(),
            ReauthPurpose::ChangePassword,
        )?;
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key))?;
        let new = session.with(|core| {
            Ok(core.new_credentials(
                &new_password,
                Some(secret_key),
                false,
                KdfParams::DEFAULT,
                &mut OsRng,
            )?)
        })?;
        let (registration, registration_request) =
            RegistrationClient::start(&new.keys.auth_secret, &mut OsRng)?;
        let registered: api::PasswordRegistrationResponse = self.api.post(
            "v1/account/password/registration",
            Some(&access_token),
            &api::PasswordRegistrationRequest {
                recovery_id: None,
                registration_request,
            },
        )?;
        let request = api::ChangePasswordRequest {
            registration_upload: registration.finish(
                &new.keys.auth_secret,
                &registered.registration_response,
                &mut OsRng,
            )?,
            account: convert(&new.update)?,
        };
        self.api
            .call::<()>(
                HttpMethod::Put,
                "v1/account/password",
                Some(&access_token),
                &[(api::REAUTH_TOKEN_HEADER, reauth_token)],
                Some(&request),
            )?
            .into_result()?;
        session.with(|core| {
            core.accept_credentials(&new);
            Ok(())
        })
    }

    /// Starts a reset with the recovery code: emails a code. The answer is the same for an email
    /// without an account.
    pub fn start_password_reset(&self, email: String) -> Result<PasswordResetStart> {
        let started: api::RecoverStartResponse = self.api.post(
            "v1/auth/recover/start",
            None,
            &api::RecoverStartRequest {
                email: octapass_core::kdf::normalize_email(&email),
            },
        )?;
        Ok(PasswordResetStart {
            reset_id: started.recovery_id,
            dev_verification_code: started.dev_verification_code,
        })
    }

    /// Checks the emailed code. A wrong one fails with `Server { problemType:
    /// "invalid-verification-code" }`: try again; `"recovery-expired"`: start over.
    pub fn verify_password_reset(
        &self,
        reset_id: String,
        verification_code: String,
    ) -> Result<Arc<PasswordReset>> {
        let verified: api::RecoverVerifyResponse = self.api.post(
            "v1/auth/recover/verify",
            None,
            &api::RecoverVerifyRequest {
                recovery_id: reset_id.clone(),
                verification_code: verification_code.split_whitespace().collect(),
            },
        )?;
        Ok(Arc::new(PasswordReset {
            api: self.api.clone(),
            reset_id,
            bundle: convert(&verified.account)?,
            challenge: verified.challenge,
        }))
    }
}

#[uniffi::export]
impl PasswordReset {
    /// Opens the account key with the recovery code (`InvalidRecoveryCode` when it doesn't), sets
    /// the new master password and returns the new Recovery Kit's secrets: the recovery code is
    /// always new, and so is the Secret Key when `secret_key` is `None` (a device that doesn't
    /// know the account). Every device is signed out; sign in with the new password. Runs
    /// Argon2id; call it off the main thread.
    pub fn finish(
        &self,
        recovery_code: String,
        new_password: String,
        secret_key: Option<String>,
    ) -> Result<PasswordResetKit> {
        let new_password = Zeroizing::new(new_password);
        let code = RecoveryCode::parse(&Zeroizing::new(recovery_code))
            .map_err(|_| OctaPassError::InvalidRecoveryCode)?;
        let session = CoreSession::recover(self.bundle.clone(), &code)
            .map_err(|_| OctaPassError::InvalidRecoveryCode)?;
        let secret_key = secret_key
            .map(|text| SecretKey::parse(&Zeroizing::new(text)))
            .transpose()?;
        let new = session.new_credentials(
            &new_password,
            secret_key,
            true,
            KdfParams::DEFAULT,
            &mut OsRng,
        )?;
        let (registration, registration_request) =
            RegistrationClient::start(&new.keys.auth_secret, &mut OsRng)?;
        let registered: api::PasswordRegistrationResponse = self.api.post(
            "v1/auth/recover/registration",
            None,
            &api::PasswordRegistrationRequest {
                recovery_id: Some(self.reset_id.clone()),
                registration_request,
            },
        )?;
        let registration_upload = registration.finish(
            &new.keys.auth_secret,
            &registered.registration_response,
            &mut OsRng,
        )?;
        let signature =
            session.sign_recovery(&self.challenge, &registration_upload, &new.update)?;
        self.api.post::<()>(
            "v1/auth/recover/finish",
            None,
            &api::RecoverFinishRequest {
                recovery_id: self.reset_id.clone(),
                registration_upload,
                account: convert(&new.update)?,
                signature,
            },
        )?;
        let recovery_code = new
            .recovery_code
            .as_ref()
            .ok_or(OctaPassError::InvalidRecoveryCode)?
            .to_text()
            .to_string();
        Ok(PasswordResetKit {
            secret_key: new.secret_key.to_text().to_string(),
            recovery_code,
        })
    }
}

#[uniffi::export]
impl LocalStore {
    /// After `OctaPassServer.changeMasterPassword`: keeps the session's new account bundle, so
    /// the next unlock takes the new password, and turns device unlock off (a new master password
    /// starts it from scratch).
    pub fn update_account(&self, session: Arc<Session>) -> Result<()> {
        let account = session.with(|core| Ok(core.bundle().clone()))?;
        self.mutate(|data| {
            data.account = account;
            data.device_unlock = None;
            data.password_unlocked_at = now_ms();
            Ok(())
        })
    }
}

impl OctaPassServer {
    /// A new Secret Key with the same master password (`LoginFailed` when it's wrong). The recovery
    /// code stays unless `new_recovery_code` is set; every other device is signed out. `session`
    /// keeps the new bundle: keep the new key, call `LocalStore.update_account(session)` and
    /// delete the device unlock secret. Runs Argon2id twice; call it off the main thread.
    pub fn rotate_secret_key(
        &self,
        access_token: String,
        session: Arc<Session>,
        password: String,
        secret_key: String,
        new_recovery_code: bool,
    ) -> Result<RotatedSecretKey> {
        let password = Zeroizing::new(password);
        let reauth_token = self.reauth_as(
            access_token.clone(),
            Arc::clone(&session),
            password.to_string(),
            secret_key,
            api::ReauthPurpose::RotateSecretKey,
        )?;
        let new = session.with(|core| {
            Ok(core.new_credentials(
                &password,
                None,
                new_recovery_code,
                KdfParams::DEFAULT,
                &mut OsRng,
            )?)
        })?;
        let (registration, registration_request) =
            RegistrationClient::start(&new.keys.auth_secret, &mut OsRng)?;
        let registered: api::PasswordRegistrationResponse = self.api.post(
            "v1/account/password/registration",
            Some(&access_token),
            &api::PasswordRegistrationRequest {
                recovery_id: None,
                registration_request,
            },
        )?;
        let request = api::ChangePasswordRequest {
            registration_upload: registration.finish(
                &new.keys.auth_secret,
                &registered.registration_response,
                &mut OsRng,
            )?,
            account: convert(&new.update)?,
        };
        let sent = self.api.call::<()>(
            HttpMethod::Put,
            "v1/account/secret-key",
            Some(&access_token),
            &[(api::REAUTH_TOKEN_HEADER, reauth_token)],
            Some(&request),
        );
        if let Err(error) = sent.and_then(|reply| reply.into_result()) {
            // A lost answer must not lose the only copy of the new key: ask whether it landed.
            let stored = self
                .api
                .get::<api::AccountBundle>("v1/account", Some(&access_token));
            if stored.map_or(true, |stored| {
                stored.account_salt != new.update.account_salt
            }) {
                return Err(error);
            }
        }
        session.with(|core| {
            core.accept_credentials(&new);
            Ok(())
        })?;
        Ok(RotatedSecretKey {
            secret_key: new.secret_key.to_text().to_string(),
            recovery_code: new
                .recovery_code
                .as_ref()
                .map(|code| code.to_text().to_string()),
        })
    }

    /// As the contact of a released takeover record (plan 06, "Takeover design"): a new master
    /// password, Secret Key and recovery code for the grantor, who is signed out everywhere.
    /// `session`, `password` and `secret_key` are this account's own. Runs Argon2id twice.
    pub fn take_over_account(
        &self,
        access_token: String,
        session: Arc<Session>,
        record_id: &str,
        password: String,
        secret_key: String,
        new_password: String,
    ) -> Result<TakenOver> {
        let new_password = Zeroizing::new(new_password);
        let reauth_token = self.reauth_as(
            access_token.clone(),
            Arc::clone(&session),
            password,
            secret_key,
            api::ReauthPurpose::EmergencyTakeover,
        )?;
        let path = format!("v1/emergency-contacts/{record_id}");
        let release: api::EmergencyReleaseResponse = self
            .api
            .get(&format!("{path}/release"), Some(&access_token))?;
        let bundle: AccountBundle = convert(
            release
                .grantor
                .as_ref()
                .ok_or(OctaPassError::InvalidResponse)?,
        )?;
        let email = bundle.email.clone();
        let grantor =
            session.with(|core| Ok(core.open_emergency_account(bundle, &release.sealed_key)?))?;
        let new =
            grantor.new_credentials(&new_password, None, true, KdfParams::DEFAULT, &mut OsRng)?;
        let (registration, registration_request) =
            RegistrationClient::start(&new.keys.auth_secret, &mut OsRng)?;
        let registered: api::PasswordRegistrationResponse = self.api.post(
            &format!("{path}/takeover/registration"),
            Some(&access_token),
            &api::TakeoverRegistrationRequest {
                registration_request,
            },
        )?;
        let registration_upload = registration.finish(
            &new.keys.auth_secret,
            &registered.registration_response,
            &mut OsRng,
        )?;
        let signature = grantor.sign_takeover(
            record_id,
            &release.contact.contact_id,
            &registration_upload,
            &new.update,
        )?;
        let request = api::EmergencyTakeoverRequest {
            registration_upload,
            account: convert(&new.update)?,
            signature,
        };
        let sent = self.api.call::<()>(
            HttpMethod::Post,
            &format!("{path}/takeover"),
            Some(&access_token),
            &[(api::REAUTH_TOKEN_HEADER, reauth_token)],
            Some(&request),
        );
        if let Err(error) = sent.and_then(|reply| reply.into_result()) {
            // A lost answer must not lose the only copy of the new kit: the record is gone once
            // it landed.
            let contacts = self.api.get::<api::EmergencyContactsResponse>(
                "v1/emergency-contacts",
                Some(&access_token),
            );
            let gone = contacts.is_ok_and(|contacts| {
                contacts
                    .received
                    .iter()
                    .all(|record| record.id != record_id)
            });
            if !gone {
                return Err(error);
            }
        }
        let recovery_code = new
            .recovery_code
            .as_ref()
            .map(|code| code.to_text().to_string())
            .ok_or(OctaPassError::InvalidResponse)?;
        Ok(TakenOver {
            email,
            secret_key: new.secret_key.to_text().to_string(),
            recovery_code,
        })
    }
}

/// Between the API's types and the core's, which serialize the same way.
fn convert<T: serde::de::DeserializeOwned>(value: &impl serde::Serialize) -> Result<T> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(|_| OctaPassError::InvalidResponse)
}
