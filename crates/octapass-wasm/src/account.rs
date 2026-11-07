//! Account flows: sign-up, key derivation, login, reauth, new master passwords and the unlocked
//! session.

use octapass_core::Error;
use octapass_core::account::{AccountBundle, NewAccount};
use octapass_core::credentials::{CredentialsUpdate, NewCredentials};
use octapass_core::device::DeviceUnlock;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::item::Item;
use octapass_core::kdf::{AccountKeys, KdfParams, normalize_email};
use octapass_core::keys::SymmetricKey;
use octapass_core::opaque::{LoginClient, ReauthClient, RegistrationClient};
use octapass_core::recovery::RecoveryCode;
use octapass_core::secret_key::SecretKey;
use octapass_core::session::{self, EncryptedItem};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{flow_finished, from_js, js_error, now_ms, to_js};

/// Sign-up, between `register/start` and `register/finish`.
///
/// Holds the new account's keys. Show `secretKey` and `recoveryCode` to the user once (Recovery
/// Kit), then `free()` it after logging in.
#[wasm_bindgen]
pub struct Signup {
    account: NewAccount,
    registration: Option<RegistrationClient>,
    registration_request: String,
}

#[wasm_bindgen]
impl Signup {
    /// Generates every key for a new account and starts OPAQUE registration. Runs Argon2id, so it
    /// takes about a second: call it from a worker.
    pub fn create(email: String, password: String) -> Result<Signup, JsValue> {
        let password = Zeroizing::new(password);
        let account =
            NewAccount::create(&email, &password, KdfParams::DEFAULT, now_ms(), &mut OsRng)
                .map_err(js_error)?;
        let (registration, registration_request) =
            RegistrationClient::start(&account.keys.auth_secret, &mut OsRng).map_err(js_error)?;
        Ok(Signup {
            account,
            registration: Some(registration),
            registration_request,
        })
    }

    /// Starts OPAQUE registration for an account whose keys already exist: turning on sync for a
    /// local vault keeps its ASK, key pairs and personal vault.
    #[cfg(feature = "strength")] // only local mode's upgrade-to-account builds a Signup this way
    pub(crate) fn from_account(account: NewAccount) -> Result<Signup, JsValue> {
        let (registration, registration_request) =
            RegistrationClient::start(&account.keys.auth_secret, &mut OsRng).map_err(js_error)?;
        Ok(Signup {
            account,
            registration: Some(registration),
            registration_request,
        })
    }

    /// The normalised email to send with `register/start` and `register/finish`.
    #[wasm_bindgen(getter)]
    pub fn email(&self) -> String {
        self.account.bundle.email.clone()
    }

    /// `registrationRequest` for `POST /v1/auth/register/start`.
    #[wasm_bindgen(getter, js_name = registrationRequest)]
    pub fn registration_request(&self) -> String {
        self.registration_request.clone()
    }

    /// The Secret Key (`OP1-…`), for the Recovery Kit and the device's local storage.
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> String {
        self.account.secret_key.to_text().to_string()
    }

    /// The recovery code (11 groups of 5), for the Recovery Kit only.
    #[wasm_bindgen(getter, js_name = recoveryCode)]
    pub fn recovery_code(&self) -> String {
        self.account.recovery_code.to_text().to_string()
    }

    /// Takes `registrationResponse` from `register/start` and returns the body for
    /// `register/finish` (add `email` and `verificationCode`). Can only be called once.
    #[wasm_bindgen(unchecked_return_type = "RegisterFinish")]
    pub fn finish(
        &mut self,
        #[wasm_bindgen(js_name = registrationResponse)] registration_response: String,
    ) -> Result<JsValue, JsValue> {
        let registration = self.registration.take().ok_or_else(flow_finished)?;
        let registration_upload = registration
            .finish(
                &self.account.keys.auth_secret,
                &registration_response,
                &mut OsRng,
            )
            .map_err(js_error)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct RegisterFinish<'a> {
            registration_upload: String,
            account: &'a AccountBundle,
            personal_vault: &'a octapass_core::account::NewVault,
        }
        to_js(&RegisterFinish {
            registration_upload,
            account: &self.account.bundle,
            personal_vault: &self.account.personal_vault,
        })
    }

    /// The derived keys, to log in right after sign-up without running Argon2id again.
    #[wasm_bindgen(js_name = derivedKeys)]
    pub fn derived_keys(&self) -> DerivedKeys {
        DerivedKeys {
            keys: self.account.keys.clone(),
            email: self.account.bundle.email.clone(),
        }
    }
}

/// A new master password for an account, between the OPAQUE registration and the server
/// accepting it: a change (`PUT /v1/account/password`) or a reset with the recovery code
/// (`POST /v1/auth/recover/finish`). The account key stays the same.
///
/// Show a new `secretKey` or `recoveryCode` once (a new Recovery Kit), then `free()` it.
#[wasm_bindgen]
pub struct CredentialsChange {
    new: NewCredentials,
    email: String,
    registration: Option<RegistrationClient>,
    registration_request: String,
}

#[wasm_bindgen]
impl CredentialsChange {
    /// `registrationRequest` for `/v1/account/password/registration` or
    /// `/v1/auth/recover/registration`.
    #[wasm_bindgen(getter, js_name = registrationRequest)]
    pub fn registration_request(&self) -> String {
        self.registration_request.clone()
    }

    /// The Secret Key the account has from now on: the one kept, or a new one.
    #[wasm_bindgen(getter, js_name = secretKey)]
    pub fn secret_key(&self) -> String {
        self.new.secret_key.to_text().to_string()
    }

    /// The new recovery code, when it was replaced.
    #[wasm_bindgen(getter, js_name = recoveryCode)]
    pub fn recovery_code(&self) -> Option<String> {
        self.new
            .recovery_code
            .as_ref()
            .map(|code| code.to_text().to_string())
    }

    /// Takes `registrationResponse` and returns the body for `PUT /v1/account/password` (and,
    /// with `recoveryId` and `signature` added, for `recover/finish`). Can only be called once.
    #[wasm_bindgen(unchecked_return_type = "CredentialsFinish")]
    pub fn finish(
        &mut self,
        #[wasm_bindgen(js_name = registrationResponse)] registration_response: String,
    ) -> Result<JsValue, JsValue> {
        let registration = self.registration.take().ok_or_else(flow_finished)?;
        let registration_upload = registration
            .finish(
                &self.new.keys.auth_secret,
                &registration_response,
                &mut OsRng,
            )
            .map_err(js_error)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Finish<'a> {
            registration_upload: String,
            account: &'a CredentialsUpdate,
        }
        to_js(&Finish {
            registration_upload,
            account: &self.new.update,
        })
    }

    /// The new derived keys, to sign in right after a reset without running Argon2id again.
    #[wasm_bindgen(js_name = derivedKeys)]
    pub fn derived_keys(&self) -> DerivedKeys {
        DerivedKeys {
            keys: self.new.keys.clone(),
            email: self.email.clone(),
        }
    }
}

/// The AUK and OPAQUE secret derived from email + master password + Secret Key.
#[wasm_bindgen]
pub struct DerivedKeys {
    keys: AccountKeys,
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Prelogin {
    kdf: KdfParams,
    account_salt: String,
}

#[wasm_bindgen]
impl DerivedKeys {
    /// Runs Argon2id with the parameters from `prelogin` (about a second: call it from a
    /// worker). Rejects KDF parameters weaker than the defaults, so a malicious server can't
    /// make offline guessing cheaper.
    pub fn derive(
        email: String,
        password: String,
        #[wasm_bindgen(js_name = secretKey)] secret_key: String,
        #[wasm_bindgen(unchecked_param_type = "Prelogin")] prelogin: JsValue,
    ) -> Result<DerivedKeys, JsValue> {
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key)).map_err(js_error)?;
        let prelogin: Prelogin = from_js(prelogin, "prelogin")?;
        let account_salt = b64_decode(&prelogin.account_salt).map_err(js_error)?;
        let keys =
            AccountKeys::derive(&password, &secret_key, &email, &account_salt, &prelogin.kdf)
                .map_err(js_error)?;
        Ok(DerivedKeys {
            keys,
            email: normalize_email(&email),
        })
    }

    /// Starts `POST /v1/auth/login/start`.
    #[wasm_bindgen(js_name = startLogin)]
    pub fn start_login(&self) -> Result<LoginFlow, JsValue> {
        let (client, credential_request) =
            LoginClient::start(&self.keys.auth_secret, &mut OsRng).map_err(js_error)?;
        Ok(LoginFlow {
            client: Some(client),
            auth_secret: self.keys.auth_secret.clone(),
            credential_request,
        })
    }

    /// Unwraps the account key from the bundle `login/finish` (or `GET /v1/account`) returned.
    /// Also unlocks a locked vault locally, without the server.
    pub fn unlock(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AccountBundle")] account: JsValue,
    ) -> Result<Session, JsValue> {
        let bundle: AccountBundle = from_js(account, "account")?;
        if normalize_email(&bundle.email) != self.email {
            return Err(js_error(Error::InvalidAccountBundle));
        }
        let inner = session::Session::unlock(bundle, &self.keys.auk).map_err(js_error)?;
        Ok(Session { inner })
    }
}

/// OPAQUE login, between `login/start` and `login/finish`.
#[wasm_bindgen]
pub struct LoginFlow {
    client: Option<LoginClient>,
    auth_secret: SymmetricKey,
    credential_request: String,
}

#[wasm_bindgen]
impl LoginFlow {
    /// `credentialRequest` for `POST /v1/auth/login/start`.
    #[wasm_bindgen(getter, js_name = credentialRequest)]
    pub fn credential_request(&self) -> String {
        self.credential_request.clone()
    }

    /// Takes `credentialResponse` and returns `credentialFinalization` for `login/finish`.
    /// Throws `login_failed` for a wrong password or Secret Key. Can only be called once.
    pub fn finish(
        &mut self,
        #[wasm_bindgen(js_name = credentialResponse)] credential_response: String,
    ) -> Result<String, JsValue> {
        let client = self.client.take().ok_or_else(flow_finished)?;
        client
            .finish(&self.auth_secret, &credential_response, &mut OsRng)
            .map_err(js_error)
    }
}

/// Re-authentication before a dangerous action, between `reauth/start` and `reauth/finish`.
/// The session it came from keeps working; the server answers with a single-use reauth token.
#[wasm_bindgen]
pub struct ReauthFlow {
    client: Option<ReauthClient>,
    auth_secret: SymmetricKey,
    credential_request: String,
}

#[wasm_bindgen]
impl ReauthFlow {
    /// `credentialRequest` for `POST /v1/auth/reauth/start`.
    #[wasm_bindgen(getter, js_name = credentialRequest)]
    pub fn credential_request(&self) -> String {
        self.credential_request.clone()
    }

    /// Takes `credentialResponse` and returns `credentialFinalization` for `reauth/finish`.
    /// Can only be called once.
    pub fn finish(
        &mut self,
        #[wasm_bindgen(js_name = credentialResponse)] credential_response: String,
    ) -> Result<String, JsValue> {
        let client = self.client.take().ok_or_else(flow_finished)?;
        client
            .finish(&self.auth_secret, &credential_response, &mut OsRng)
            .map_err(js_error)
    }
}

/// An unlocked account. `free()` it to lock: that zeroes the account key and every vault key.
#[wasm_bindgen]
pub struct Session {
    pub(crate) inner: session::Session,
}

#[wasm_bindgen]
impl Session {
    /// Unlocks with the recovery code instead of password + Secret Key.
    pub fn recover(
        #[wasm_bindgen(js_name = recoveryCode)] recovery_code: String,
        #[wasm_bindgen(unchecked_param_type = "AccountBundle")] account: JsValue,
    ) -> Result<Session, JsValue> {
        let code = RecoveryCode::parse(&Zeroizing::new(recovery_code)).map_err(js_error)?;
        let bundle: AccountBundle = from_js(account, "account")?;
        let inner = session::Session::recover(bundle, &code).map_err(js_error)?;
        Ok(Session { inner })
    }

    /// Unlocks with this device's key: the 32-byte WebAuthn PRF output of the platform passkey,
    /// plus the `deviceSalt` and `wrappedAsk` that `enableDeviceUnlock` returned. Throws
    /// `device_unlock_failed` if they don't open this account.
    #[wasm_bindgen(js_name = unlockWithDeviceKey)]
    pub fn unlock_with_device_key(
        #[wasm_bindgen(js_name = prfOutput)] prf_output: Vec<u8>,
        #[wasm_bindgen(js_name = deviceSalt)] device_salt: String,
        #[wasm_bindgen(js_name = wrappedAsk)] wrapped_ask: String,
        #[wasm_bindgen(unchecked_param_type = "AccountBundle")] account: JsValue,
    ) -> Result<Session, JsValue> {
        let prf_output = Zeroizing::new(prf_output);
        let device_salt = b64_decode(&device_salt).map_err(js_error)?;
        let bundle: AccountBundle = from_js(account, "account")?;
        let inner = session::Session::unlock_with_device_key(
            bundle,
            &prf_output,
            &device_salt,
            &wrapped_ask,
        )
        .map_err(js_error)?;
        Ok(Session { inner })
    }

    /// Wraps the account key for device unlock with the 32-byte WebAuthn PRF output. Store the
    /// result on this device only (IndexedDB); nothing goes to the server.
    #[wasm_bindgen(js_name = enableDeviceUnlock, unchecked_return_type = "DeviceUnlock")]
    pub fn enable_device_unlock(
        &self,
        #[wasm_bindgen(js_name = prfOutput)] prf_output: Vec<u8>,
    ) -> Result<JsValue, JsValue> {
        let prf_output = Zeroizing::new(prf_output);
        let DeviceUnlock {
            device_salt,
            wrapped_ask,
        } = self
            .inner
            .enable_device_unlock(&prf_output, &mut OsRng)
            .map_err(js_error)?;
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Stored {
            device_salt: String,
            wrapped_ask: String,
        }
        to_js(&Stored {
            device_salt: b64_encode(&device_salt),
            wrapped_ask,
        })
    }

    /// The account bundle this session was unlocked from.
    #[wasm_bindgen(getter, unchecked_return_type = "AccountBundle")]
    pub fn account(&self) -> Result<JsValue, JsValue> {
        to_js(self.inner.bundle())
    }

    /// Unwraps a vault key from a `VaultRecord` and keeps it in this session.
    #[wasm_bindgen(js_name = openVault)]
    pub fn open_vault(
        &mut self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(js_name = wrappedVaultKey)] wrapped_vault_key: String,
    ) -> Result<(), JsValue> {
        self.inner
            .open_vault(&vault_id, &wrapped_vault_key)
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = isVaultOpen)]
    pub fn is_vault_open(&self, #[wasm_bindgen(js_name = vaultId)] vault_id: String) -> bool {
        self.inner.is_vault_open(&vault_id)
    }

    /// Encrypts an item for `PUT /v1/vaults/{vaultId}/items/{itemId}`. When updating, pass the
    /// record's current `encryptedItemKey` so the item keeps its key.
    #[wasm_bindgen(js_name = encryptItem, unchecked_return_type = "EncryptedItem")]
    pub fn encrypt_item(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(js_name = itemId)] item_id: String,
        #[wasm_bindgen(unchecked_param_type = "ItemPlaintext")] item: JsValue,
        #[wasm_bindgen(js_name = existingEncryptedItemKey)] existing_encrypted_item_key: Option<
            String,
        >,
    ) -> Result<JsValue, JsValue> {
        let item = item_from_js(item)?;
        let encrypted = self
            .inner
            .encrypt_item(
                &vault_id,
                &item_id,
                &item,
                existing_encrypted_item_key.as_deref(),
                &mut OsRng,
            )
            .map_err(js_error)?;
        to_js(&encrypted)
    }

    /// Decrypts a whole item (overview and details).
    #[wasm_bindgen(js_name = decryptItem, unchecked_return_type = "ItemPlaintext")]
    pub fn decrypt_item(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(js_name = itemId)] item_id: String,
        #[wasm_bindgen(unchecked_param_type = "EncryptedItem")] encrypted: JsValue,
    ) -> Result<JsValue, JsValue> {
        let encrypted: EncryptedItem = from_js(encrypted, "encrypted item")?;
        to_js(
            &self
                .inner
                .decrypt_item(&vault_id, &item_id, &encrypted)
                .map_err(js_error)?,
        )
    }

    /// Decrypts only the overview, for lists and search.
    #[wasm_bindgen(js_name = decryptOverview, unchecked_return_type = "ItemOverview")]
    pub fn decrypt_overview(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(js_name = itemId)] item_id: String,
        #[wasm_bindgen(unchecked_param_type = "EncryptedItem")] encrypted: JsValue,
    ) -> Result<JsValue, JsValue> {
        let encrypted: EncryptedItem = from_js(encrypted, "encrypted item")?;
        to_js(
            &self
                .inner
                .decrypt_overview(&vault_id, &item_id, &encrypted)
                .map_err(js_error)?,
        )
    }

    /// Wraps this account's key for a new master password, or the same one with a new Secret Key,
    /// and starts its OPAQUE registration. Runs Argon2id. `secretKey`: the Secret Key to keep, or
    /// `undefined` for a new one; with `newRecoveryCode`, the recovery code is replaced too (a
    /// reset always replaces it).
    #[wasm_bindgen(js_name = newCredentials)]
    pub fn new_credentials(
        &self,
        password: String,
        #[wasm_bindgen(js_name = secretKey)] secret_key: Option<String>,
        #[wasm_bindgen(js_name = newRecoveryCode)] new_recovery_code: bool,
    ) -> Result<CredentialsChange, JsValue> {
        let password = Zeroizing::new(password);
        let secret_key = secret_key
            .map(|text| SecretKey::parse(&Zeroizing::new(text)))
            .transpose()
            .map_err(js_error)?;
        let new = self
            .inner
            .new_credentials(
                &password,
                secret_key,
                new_recovery_code,
                KdfParams::DEFAULT,
                &mut OsRng,
            )
            .map_err(js_error)?;
        let (registration, registration_request) =
            RegistrationClient::start(&new.keys.auth_secret, &mut OsRng).map_err(js_error)?;
        Ok(CredentialsChange {
            new,
            email: normalize_email(&self.inner.bundle().email),
            registration: Some(registration),
            registration_request,
        })
    }

    /// The `signature` for `POST /v1/auth/recover/finish`: the account's own key signs the
    /// server's `challenge` (from `recover/verify`) and the new credentials.
    #[wasm_bindgen(js_name = signRecovery)]
    pub fn sign_recovery(
        &self,
        challenge: String,
        #[wasm_bindgen(js_name = registrationUpload)] registration_upload: String,
        #[wasm_bindgen(unchecked_param_type = "CredentialsUpdate")] account: JsValue,
    ) -> Result<String, JsValue> {
        let update: CredentialsUpdate = from_js(account, "account")?;
        self.inner
            .sign_recovery(&challenge, &registration_upload, &update)
            .map_err(js_error)
    }

    /// The `signature` for `POST /v1/emergency-contacts/{id}/takeover`. Call it on the grantor's
    /// session (`openEmergencyAccount`): the grantor's key signs the record, the account salt being
    /// replaced and the new credentials.
    #[wasm_bindgen(js_name = signTakeover)]
    pub fn sign_takeover(
        &self,
        #[wasm_bindgen(js_name = recordId)] record_id: String,
        #[wasm_bindgen(js_name = contactAccountId)] contact_account_id: String,
        #[wasm_bindgen(js_name = registrationUpload)] registration_upload: String,
        #[wasm_bindgen(unchecked_param_type = "CredentialsUpdate")] account: JsValue,
    ) -> Result<String, JsValue> {
        let update: CredentialsUpdate = from_js(account, "account")?;
        self.inner
            .sign_takeover(
                &record_id,
                &contact_account_id,
                &registration_upload,
                &update,
            )
            .map_err(js_error)
    }

    /// Once the server accepted `change`, this session keeps the new bundle (see `account`), so
    /// later reauths use the new master password.
    #[wasm_bindgen(js_name = acceptCredentials)]
    pub fn accept_credentials(&mut self, change: &CredentialsChange) {
        self.inner.accept_credentials(&change.new);
    }

    /// Starts re-authentication (`POST /v1/auth/reauth/start`) with the master password and the
    /// device's Secret Key. Runs Argon2id. Throws `login_failed` right away if they don't unlock
    /// this account, before anything is sent. This session is not changed.
    #[wasm_bindgen(js_name = startReauth)]
    pub fn start_reauth(
        &self,
        password: String,
        #[wasm_bindgen(js_name = secretKey)] secret_key: String,
    ) -> Result<ReauthFlow, JsValue> {
        let password = Zeroizing::new(password);
        let secret_key = SecretKey::parse(&Zeroizing::new(secret_key)).map_err(js_error)?;
        let bundle = self.inner.bundle();
        let account_salt = bundle.account_salt_bytes().map_err(js_error)?;
        let keys = AccountKeys::derive(
            &password,
            &secret_key,
            &bundle.email,
            &account_salt,
            &bundle.kdf,
        )
        .map_err(js_error)?;
        // Fail fast, before anything is sent, if these don't unlock this account.
        session::Session::unlock(bundle.clone(), &keys.auk).map_err(js_error)?;
        let (client, credential_request) =
            ReauthClient::start(&keys.auth_secret, &mut OsRng).map_err(js_error)?;
        Ok(ReauthFlow {
            client: Some(client),
            auth_secret: keys.auth_secret.clone(),
            credential_request,
        })
    }
}

pub(crate) fn item_from_js(item: JsValue) -> Result<Item, JsValue> {
    #[derive(Deserialize)]
    struct Raw {
        overview: serde_json::Value,
        details: serde_json::Value,
    }
    let raw: Raw = from_js(item, "item")?;
    let overview =
        serde_json::from_value(raw.overview).map_err(|_| js_error(Error::InvalidItem))?;
    Item::from_parts(overview, raw.details).map_err(js_error)
}
