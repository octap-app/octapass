//! New credentials for an existing account: a master password change while signed in, or a reset
//! with the recovery code (plan 03, Recovery).
//!
//! The ASK stays the same, so no vault or item is re-encrypted: only the wrappings that depend on
//! the master password, the Secret Key or the recovery code are replaced. Every change also gets a
//! fresh account salt, so the new AUK and OPAQUE secret share nothing with the old ones.
//!
//! A reset happens without a session, so the device proves to the server that it opened the ASK by
//! signing the new credentials with the account's Ed25519 key (which only the ASK unwraps):
//!
//! ```text
//! message = "octapass/v1/account-recovery" ‖ 0x00 ‖ for each field: len (u32 BE) ‖ UTF-8 bytes
//! fields  = accountId, challenge, registrationUpload, accountSalt, wrappedAsk, recoveryWrappedAsk
//! ```
//!
//! An emergency takeover (plan 06) proves the same thing, from the contact's device, over the
//! record it uses and the salt the account has now, which makes each signature good only once:
//!
//! ```text
//! message = "octapass/v1/emergency-takeover" ‖ 0x00 ‖ for each field: len (u32 BE) ‖ UTF-8 bytes
//! fields  = recordId, grantorId, contactId, currentAccountSalt,
//!           registrationUpload, accountSalt, wrappedAsk, recoveryWrappedAsk
//! ```

use ed25519_dalek::Signer;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::account::{AccountBundle, parse_id};
use crate::encoding::b64_encode;
use crate::envelope::{Context, wrap_key};
use crate::error::{Error, Result};
use crate::kdf::{AccountKeys, KdfParams, generate_account_salt};
use crate::recovery::RecoveryCode;
use crate::secret_key::SecretKey;
use crate::session::Session;

const RECOVERY_LABEL: &[u8] = b"octapass/v1/account-recovery\0";
const TAKEOVER_LABEL: &[u8] = b"octapass/v1/emergency-takeover\0";

/// What replaces the password-dependent parts of the [`AccountBundle`] on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsUpdate {
    pub kdf: KdfParams,
    pub account_salt: String,
    /// The ASK sealed by the new AUK (context `ask`).
    pub wrapped_ask: String,
    /// The ASK sealed by a new recovery code (context `recovery`), when the code was replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_wrapped_ask: Option<String>,
}

/// New credentials for an account. The secrets in it are shown once (a new Secret Key or recovery
/// code goes on a new Recovery Kit) or kept only in memory.
pub struct NewCredentials {
    pub secret_key: SecretKey,
    /// Only when the recovery code was replaced.
    pub recovery_code: Option<RecoveryCode>,
    pub keys: AccountKeys,
    pub update: CredentialsUpdate,
}

impl NewCredentials {
    /// The bundle as the server stores it once the update is accepted.
    pub fn apply(&self, bundle: &AccountBundle) -> AccountBundle {
        let mut updated = bundle.clone();
        updated.kdf = self.update.kdf;
        updated.account_salt = self.update.account_salt.clone();
        updated.wrapped_ask = self.update.wrapped_ask.clone();
        if let Some(recovery_wrapped_ask) = &self.update.recovery_wrapped_ask {
            updated.recovery_wrapped_ask = recovery_wrapped_ask.clone();
        }
        updated
    }
}

impl Session {
    /// Wraps this session's ASK for a new master password. Runs Argon2id, so it takes about a
    /// second.
    ///
    /// `secret_key`: the account's Secret Key to keep, or `None` for a new one. With
    /// `new_recovery_code`, the recovery code is replaced too and the old one stops working.
    pub fn new_credentials(
        &self,
        password: &str,
        secret_key: Option<SecretKey>,
        new_recovery_code: bool,
        kdf: KdfParams,
        rng: &mut impl CryptoRngCore,
    ) -> Result<NewCredentials> {
        let secret_key = secret_key.unwrap_or_else(|| SecretKey::generate(rng));
        let account_salt = generate_account_salt(rng);
        let keys = AccountKeys::derive(
            password,
            &secret_key,
            &self.bundle().email,
            &account_salt,
            &kdf,
        )?;
        let recovery_code = new_recovery_code.then(|| RecoveryCode::generate(rng));
        let recovery_wrapped_ask = recovery_code
            .as_ref()
            .map(|code| wrap_key(&code.wrapping_key(), &Context::Recovery, self.ask(), rng))
            .transpose()?;
        let update = CredentialsUpdate {
            kdf,
            account_salt: b64_encode(&account_salt),
            wrapped_ask: wrap_key(&keys.auk, &Context::Ask, self.ask(), rng)?,
            recovery_wrapped_ask,
        };
        Ok(NewCredentials {
            secret_key,
            recovery_code,
            keys,
            update,
        })
    }

    /// Keeps the bundle the server now stores, once it accepted `new`, so later reauths derive
    /// from the new salt and KDF parameters.
    pub fn accept_credentials(&mut self, new: &NewCredentials) {
        let bundle = new.apply(self.bundle());
        self.set_bundle(bundle);
    }

    /// Signs a reset's new credentials with the account's Ed25519 key, for
    /// `POST /v1/auth/recover/finish`. `challenge` is the server's, from `recover/verify`. A reset
    /// always replaces the recovery code, so `update` must carry one.
    pub fn sign_recovery(
        &self,
        challenge: &str,
        registration_upload: &str,
        update: &CredentialsUpdate,
    ) -> Result<String> {
        let message =
            recovery_message(&self.account_id()?, challenge, registration_upload, update)?;
        let signature = self.key_pairs().signing_key().sign(&message);
        Ok(b64_encode(&signature.to_bytes()))
    }

    /// Signs a takeover's new credentials with the grantor's Ed25519 key, for
    /// `POST /v1/emergency-contacts/{id}/takeover`. `self` is the grantor's session, opened with
    /// [`Session::open_emergency_account`]; its bundle holds the salt being replaced. A takeover
    /// always replaces the recovery code, so `update` must carry one.
    pub fn sign_takeover(
        &self,
        record_id: &str,
        contact_account_id: &str,
        registration_upload: &str,
        update: &CredentialsUpdate,
    ) -> Result<String> {
        let message = takeover_message(
            record_id,
            &self.account_id()?,
            contact_account_id,
            &self.bundle().account_salt,
            registration_upload,
            update,
        )?;
        let signature = self.key_pairs().signing_key().sign(&message);
        Ok(b64_encode(&signature.to_bytes()))
    }
}

/// The bytes a reset signs (see the module docs). Servers build the same message to check it.
pub fn recovery_message(
    account_id: &str,
    challenge: &str,
    registration_upload: &str,
    update: &CredentialsUpdate,
) -> Result<Vec<u8>> {
    let account_id = parse_id(account_id)?;
    let recovery_wrapped_ask = update
        .recovery_wrapped_ask
        .as_deref()
        .ok_or(Error::InvalidRecoveryCode)?;
    let fields = [
        account_id.as_str(),
        challenge,
        registration_upload,
        &update.account_salt,
        &update.wrapped_ask,
        recovery_wrapped_ask,
    ];
    let mut message = RECOVERY_LABEL.to_vec();
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| Error::InvalidAccountBundle)?;
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    Ok(message)
}

/// The bytes a takeover signs (see the module docs). Servers build the same message to check it.
pub fn takeover_message(
    record_id: &str,
    grantor_account_id: &str,
    contact_account_id: &str,
    current_account_salt: &str,
    registration_upload: &str,
    update: &CredentialsUpdate,
) -> Result<Vec<u8>> {
    let (record_id, grantor, contact) = (
        parse_id(record_id)?,
        parse_id(grantor_account_id)?,
        parse_id(contact_account_id)?,
    );
    let recovery_wrapped_ask = update
        .recovery_wrapped_ask
        .as_deref()
        .ok_or(Error::InvalidRecoveryCode)?;
    let fields = [
        record_id.as_str(),
        grantor.as_str(),
        contact.as_str(),
        current_account_salt,
        registration_upload,
        &update.account_salt,
        &update.wrapped_ask,
        recovery_wrapped_ask,
    ];
    let mut message = TAKEOVER_LABEL.to_vec();
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| Error::InvalidAccountBundle)?;
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, VerifyingKey};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::account::NewAccount;
    use crate::encoding::b64_decode_array;

    const ACCOUNT_ID: &str = "0192b7a9-0000-7000-8000-000000000001";

    const KDF: KdfParams = KdfParams::DEFAULT;

    fn account(rng: &mut ChaCha20Rng) -> (NewAccount, Session) {
        let account = NewAccount::create("a@example.com", "old password", KDF, 0, rng).unwrap();
        let mut bundle = account.bundle.clone();
        bundle.account_id = Some(ACCOUNT_ID.into());
        let session = Session::unlock(bundle, &account.keys.auk).unwrap();
        (account, session)
    }

    #[test]
    fn a_new_password_keeps_the_ask_and_the_secret_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (account, session) = account(&mut rng);
        let secret_key = Some(account.secret_key.clone());
        let new = session
            .new_credentials("new password", secret_key, false, KDF, &mut rng)
            .unwrap();
        assert_eq!(new.secret_key, account.secret_key);
        assert!(new.recovery_code.is_none());
        assert!(new.update.recovery_wrapped_ask.is_none());
        assert_ne!(new.update.account_salt, account.bundle.account_salt);

        let bundle = new.apply(session.bundle());
        let again = AccountKeys::derive(
            "new password",
            &new.secret_key,
            &bundle.email,
            &bundle.account_salt_bytes().unwrap(),
            &bundle.kdf,
        )
        .unwrap();
        let reopened = Session::unlock(bundle.clone(), &again.auk).unwrap();
        assert_eq!(reopened.ask(), session.ask());
        // The old password no longer opens it, and the recovery code still does.
        assert_eq!(
            Session::unlock(bundle.clone(), &account.keys.auk).err(),
            Some(Error::LoginFailed)
        );
        assert!(Session::recover(bundle, &account.recovery_code).is_ok());
    }

    #[test]
    fn a_reset_replaces_the_recovery_code_and_signs_the_update() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (account, _) = account(&mut rng);
        let mut bundle = account.bundle.clone();
        bundle.account_id = Some(ACCOUNT_ID.into());
        let session = Session::recover(bundle, &account.recovery_code).unwrap();
        let new = session
            .new_credentials("new password", None, true, KDF, &mut rng)
            .unwrap();
        assert_ne!(new.secret_key, account.secret_key);
        let code = new.recovery_code.as_ref().unwrap();

        let bundle = new.apply(session.bundle());
        assert!(Session::recover(bundle.clone(), code).is_ok());
        assert_eq!(
            Session::recover(bundle, &account.recovery_code).err(),
            Some(Error::InvalidRecoveryCode)
        );

        let signature = session
            .sign_recovery("challenge", "upload", &new.update)
            .unwrap();
        let message = recovery_message(ACCOUNT_ID, "challenge", "upload", &new.update).unwrap();
        let key = VerifyingKey::from_bytes(&session.key_pairs().public_sign_key()).unwrap();
        let signature = Signature::from_bytes(&b64_decode_array(&signature).unwrap());
        assert!(key.verify_strict(&message, &signature).is_ok());
        let other = recovery_message(ACCOUNT_ID, "another", "upload", &new.update).unwrap();
        assert!(key.verify_strict(&other, &signature).is_err());
    }

    #[test]
    fn message_layout() {
        let update = CredentialsUpdate {
            kdf: KdfParams::DEFAULT,
            account_salt: "salt".into(),
            wrapped_ask: "ask".into(),
            recovery_wrapped_ask: Some("rec".into()),
        };
        let message = recovery_message(ACCOUNT_ID, "c", "u", &update).unwrap();
        assert!(message.starts_with(b"octapass/v1/account-recovery\0\0\0\0\x24"));
        assert!(message.ends_with(b"\0\0\0\x03ask\0\0\0\x03rec"));
        let without = CredentialsUpdate {
            recovery_wrapped_ask: None,
            ..update
        };
        assert!(recovery_message(ACCOUNT_ID, "c", "u", &without).is_err());
    }

    #[test]
    fn a_secret_key_rotation_keeps_the_password_and_the_ask() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let (account, session) = account(&mut rng);
        let new = session
            .new_credentials("old password", None, false, KDF, &mut rng)
            .unwrap();
        assert_ne!(new.secret_key, account.secret_key);
        assert_ne!(new.update.account_salt, account.bundle.account_salt);
        assert!(new.update.recovery_wrapped_ask.is_none());

        let bundle = new.apply(session.bundle());
        // The same password with the old Secret Key no longer derives the key that opens it.
        let stale = AccountKeys::derive(
            "old password",
            &account.secret_key,
            &bundle.email,
            &bundle.account_salt_bytes().unwrap(),
            &bundle.kdf,
        )
        .unwrap();
        assert_eq!(
            Session::unlock(bundle.clone(), &stale.auk).err(),
            Some(Error::LoginFailed)
        );
        let fresh = AccountKeys::derive(
            "old password",
            &new.secret_key,
            &bundle.email,
            &bundle.account_salt_bytes().unwrap(),
            &bundle.kdf,
        )
        .unwrap();
        assert_ne!(fresh.auth_secret, stale.auth_secret);
        let reopened = Session::unlock(bundle.clone(), &fresh.auk).unwrap();
        assert_eq!(reopened.ask(), session.ask());
        // The recovery code on the old Kit keeps working unless it's replaced too.
        assert!(Session::recover(bundle, &account.recovery_code).is_ok());

        let with_code = session
            .new_credentials("old password", None, true, KDF, &mut rng)
            .unwrap();
        let bundle = with_code.apply(session.bundle());
        assert_eq!(
            Session::recover(bundle, &account.recovery_code).err(),
            Some(Error::InvalidRecoveryCode)
        );
    }

    #[test]
    fn a_takeover_signature_covers_the_record_and_the_current_salt() {
        const RECORD: &str = "0192b7a9-0000-7000-8000-000000000002";
        const CONTACT: &str = "0192b7a9-0000-7000-8000-000000000003";
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let (_, session) = account(&mut rng);
        let new = session
            .new_credentials("new password", None, true, KDF, &mut rng)
            .unwrap();
        let salt = session.bundle().account_salt.clone();
        let signature = session
            .sign_takeover(RECORD, CONTACT, "upload", &new.update)
            .unwrap();
        let key = VerifyingKey::from_bytes(&session.key_pairs().public_sign_key()).unwrap();
        let signature = Signature::from_bytes(&b64_decode_array(&signature).unwrap());
        let message = |record, contact, current: &str, upload| {
            takeover_message(record, ACCOUNT_ID, contact, current, upload, &new.update).unwrap()
        };
        assert!(
            key.verify_strict(&message(RECORD, CONTACT, &salt, "upload"), &signature)
                .is_ok()
        );
        for other in [
            message(CONTACT, CONTACT, &salt, "upload"),
            message(RECORD, RECORD, &salt, "upload"),
            message(RECORD, CONTACT, "changed", "upload"),
            message(RECORD, CONTACT, &salt, "another"),
        ] {
            assert!(key.verify_strict(&other, &signature).is_err());
        }
    }

    #[test]
    fn a_takeover_must_replace_the_recovery_code() {
        const RECORD: &str = "0192b7a9-0000-7000-8000-000000000002";
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let (_, session) = account(&mut rng);
        let new = session
            .new_credentials("new password", None, false, KDF, &mut rng)
            .unwrap();
        assert_eq!(
            session
                .sign_takeover(RECORD, ACCOUNT_ID, "upload", &new.update)
                .err(),
            Some(Error::InvalidRecoveryCode)
        );
    }

    #[test]
    fn takeover_message_layout() {
        const RECORD: &str = "0192b7a9-0000-7000-8000-000000000002";
        let update = CredentialsUpdate {
            kdf: KdfParams::DEFAULT,
            account_salt: "salt".into(),
            wrapped_ask: "ask".into(),
            recovery_wrapped_ask: Some("rec".into()),
        };
        let message =
            takeover_message(RECORD, ACCOUNT_ID, ACCOUNT_ID, "was", "u", &update).unwrap();
        assert!(message.starts_with(b"octapass/v1/emergency-takeover\0\0\0\0\x24"));
        assert!(
            message.ends_with(b"\0\0\0\x03was\0\0\0\x01u\0\0\0\x04salt\0\0\0\x03ask\0\0\0\x03rec")
        );
    }
}
