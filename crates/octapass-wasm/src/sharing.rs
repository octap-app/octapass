//! Sharing: shared vaults and their grants, key rotation, fingerprints, one-time share links
//! and emergency access. Vault keys and account keys stay inside the `Session`.

use octapass_core::account::AccountBundle;
use octapass_core::encoding::b64_decode_array;
use octapass_core::sharing::emergency::EmergencyScope;
use octapass_core::sharing::grant::{Recipient, SignedGrant};
use octapass_core::sharing::pq::PqPublicKey;
use octapass_core::sharing::vault::ItemKey;
use octapass_core::sharing::{Role, fingerprint, share_link};
use octapass_core::transparency::record::{KeyRecord, OfferedKeys};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::account::{Session, item_from_js};
use crate::{from_js, invalid_argument, js_error, now_ms, to_js};

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export type VaultRole = "read" | "write" | "manage" | "owner";
/** A member's sealed, signed copy of a shared vault's key. `grantedAt` is Unix milliseconds. */
export type SignedGrant = {
  vaultId: string;
  recipientAccountId: string;
  role: VaultRole;
  wrappedVaultKey: string;
  grantedBy: string;
  grantedAt: number;
  signature: string;
};
/** Who gets a grant: from `GET /v1/accounts/lookup` or a vault's member list. */
export type GrantRecipient = {
  accountId: string;
  publicEncKey: string;
  role: VaultRole;
  /** With `keyRecord`, the grant is hybrid: the record is checked against these keys. */
  publicSignKey?: string;
  keyRecord?: KeyRecord;
};
/** `POST /v1/vaults`. */
export type NewSharedVault = { id: string; keyId: string; grant: SignedGrant };
export type ItemKey = { itemId: string; encryptedItemKey: string };
/** `POST /v1/vaults/{vaultId}/rotate`, minus `revision`. */
export type VaultRotation = { keyId: string; grants: SignedGrant[]; items: ItemKey[]; wrappedVaultKey?: string };
export type Fingerprint = { digits: string; emoji: { emoji: string; name: string }[] };
/** `ciphertext` goes to `POST /v1/share-links`; `key` is the link's `#` fragment. */
export type ShareLink = { ciphertext: string; key: string; passphraseRequired: boolean };
export type EmergencyScope = { type: "account" } | { type: "vault"; vaultId: string };
/** `POST /v1/vaults/{vaultId}/service-accounts`, plus `token`, which never goes to the server. */
export type NewServiceAccount = {
  id: string;
  publicEncKey: string;
  publicSignKey: string;
  encryptedName: string;
  grant: SignedGrant;
  keyId: string;
  token: string;
};
"#;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRecipient {
    account_id: String,
    public_enc_key: String,
    role: Role,
    public_sign_key: Option<String>,
    key_record: Option<KeyRecord>,
}

impl JsRecipient {
    fn into_recipient(self) -> Result<Recipient, JsValue> {
        let public_pq_key = pq_key_of(
            &self.account_id,
            &self.public_enc_key,
            self.public_sign_key.as_deref(),
            self.key_record.as_ref(),
        )?;
        Ok(Recipient {
            public_enc_key: b64_decode_array(&self.public_enc_key).map_err(js_error)?,
            public_pq_key,
            account_id: self.account_id,
            role: self.role,
        })
    }
}

/// The ML-KEM key to seal to, from a record that's checked against the offered keys.
fn pq_key_of(
    account_id: &str,
    public_enc_key: &str,
    public_sign_key: Option<&str>,
    record: Option<&KeyRecord>,
) -> Result<Option<PqPublicKey>, JsValue> {
    let Some(public_sign_key) = public_sign_key else {
        return Ok(None);
    };
    let offered = OfferedKeys {
        account_id,
        public_enc_key,
        public_sign_key,
    };
    KeyRecord::pq_key_of(record, &offered).map_err(js_error)
}

fn recipients_from_js(values: Vec<JsValue>) -> Result<Vec<Recipient>, JsValue> {
    values
        .into_iter()
        .map(|value| from_js::<JsRecipient>(value, "grant recipient")?.into_recipient())
        .collect()
}

fn public_key(text: &str) -> Result<[u8; 32], JsValue> {
    b64_decode_array(text).map_err(js_error)
}

#[wasm_bindgen]
impl Session {
    /// Creates a shared vault owned by this account and opens it. Send the result as the body
    /// of `POST /v1/vaults`.
    #[wasm_bindgen(js_name = createSharedVault, unchecked_return_type = "NewSharedVault")]
    pub fn create_shared_vault(&mut self) -> Result<JsValue, JsValue> {
        let vault = self
            .inner
            .create_shared_vault(now_ms(), &mut OsRng)
            .map_err(js_error)?;
        to_js(&vault)
    }

    /// Grants an open vault to another account (for `POST /v1/vaults/{vaultId}/members`).
    #[wasm_bindgen(js_name = grantVault, unchecked_return_type = "SignedGrant")]
    pub fn grant_vault(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(unchecked_param_type = "GrantRecipient")] recipient: JsValue,
    ) -> Result<JsValue, JsValue> {
        let recipient = from_js::<JsRecipient>(recipient, "grant recipient")?.into_recipient()?;
        let grant = self
            .inner
            .grant_vault(&vault_id, &recipient, now_ms(), &mut OsRng)
            .map_err(js_error)?;
        to_js(&grant)
    }

    /// Verifies a shared vault's grant (from its `VaultRecord`) against the granter's public
    /// signing key and opens the vault. Throws `invalid_signature` if the grant was tampered
    /// with or signed by someone else.
    #[wasm_bindgen(js_name = openSharedVault)]
    pub fn open_shared_vault(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "SignedGrant")] grant: JsValue,
        #[wasm_bindgen(js_name = granterPublicSignKey)] granter_public_sign_key: String,
    ) -> Result<(), JsValue> {
        let grant: SignedGrant = from_js(grant, "grant")?;
        self.inner
            .open_shared_vault(&grant, &public_key(&granter_public_sign_key)?)
            .map_err(js_error)
    }

    /// The key id of an open vault's key: compare it with a vault's `keyId` to know whether the
    /// key changed.
    #[wasm_bindgen(js_name = vaultKeyId)]
    pub fn vault_key_id(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
    ) -> Result<String, JsValue> {
        self.inner.vault_key_id(&vault_id).map_err(js_error)
    }

    /// After removing a member: a new key for the vault, a grant for each remaining member
    /// (this account included) and every item key re-wrapped. Pass every item in the vault,
    /// trash included. The session keeps the old key until you open the new grant.
    #[wasm_bindgen(js_name = rotateVaultKey, unchecked_return_type = "VaultRotation")]
    pub fn rotate_vault_key(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(unchecked_param_type = "GrantRecipient[]")] members: Vec<JsValue>,
        #[wasm_bindgen(unchecked_param_type = "ItemKey[]")] items: Vec<JsValue>,
    ) -> Result<JsValue, JsValue> {
        let members = recipients_from_js(members)?;
        let items: Vec<ItemKey> = items
            .into_iter()
            .map(|item| from_js(item, "item key"))
            .collect::<Result<_, _>>()?;
        let rotation = self
            .inner
            .rotate_vault_key(&vault_id, &members, &items, now_ms(), &mut OsRng)
            .map_err(js_error)?;
        to_js(&rotation)
    }

    /// On demand: a new key for a personal vault, wrapped by the account key, and every item key
    /// re-wrapped. Pass every item in the vault, trash included. The session keeps the old key
    /// until the vault is opened again with the new `wrappedVaultKey`.
    #[wasm_bindgen(js_name = rotatePersonalVaultKey, unchecked_return_type = "VaultRotation")]
    pub fn rotate_personal_vault_key(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(unchecked_param_type = "ItemKey[]")] items: Vec<JsValue>,
    ) -> Result<JsValue, JsValue> {
        let items: Vec<ItemKey> = items
            .into_iter()
            .map(|item| from_js(item, "item key"))
            .collect::<Result<_, _>>()?;
        let rotation = self
            .inner
            .rotate_personal_vault_key(&vault_id, &items, &mut OsRng)
            .map_err(js_error)?;
        to_js(&rotation)
    }

    /// Makes a service account for an open vault. The token is in the result and must be shown
    /// once and never sent anywhere: strip it from the request body.
    #[wasm_bindgen(js_name = createServiceAccount, unchecked_return_type = "NewServiceAccount")]
    pub fn create_service_account(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        #[wasm_bindgen(unchecked_param_type = "VaultRole")] role: JsValue,
        name: String,
        #[wasm_bindgen(js_name = serverUrl)] server_url: String,
    ) -> Result<JsValue, JsValue> {
        let role: Role = from_js(role, "role")?;
        let new = self
            .inner
            .create_service_account(&vault_id, role, &name, &server_url, now_ms(), &mut OsRng)
            .map_err(js_error)?;
        let token = new.token.encode();
        let mut value =
            serde_json::to_value(&new).map_err(|_| invalid_argument("service account"))?;
        value["token"] = serde_json::Value::String(token.to_string());
        to_js(&value)
    }

    /// The name of a service account this account made; `undefined` for anyone else's.
    #[wasm_bindgen(js_name = openServiceAccountName)]
    pub fn open_service_account_name(
        &self,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        id: String,
        #[wasm_bindgen(js_name = encryptedName)] encrypted_name: String,
    ) -> Option<String> {
        self.inner
            .open_service_account_name(&vault_id, &id, &encrypted_name)
            .ok()
    }

    /// The JSON text of a sealed security log entry; `undefined` if it isn't this account's.
    #[wasm_bindgen(js_name = openAuditDetail)]
    pub fn open_audit_detail(&self, sealed: String) -> Option<String> {
        let bytes = self.inner.open_audit_detail(&sealed).ok()?;
        String::from_utf8(bytes.to_vec()).ok()
    }

    /// Seals this account's key, or one open vault's key, to an emergency contact (for
    /// `POST /v1/emergency-contacts`).
    #[wasm_bindgen(js_name = sealForEmergencyContact)]
    pub fn seal_for_emergency_contact(
        &self,
        #[wasm_bindgen(js_name = contactAccountId)] contact_account_id: String,
        #[wasm_bindgen(js_name = contactPublicEncKey)] contact_public_enc_key: String,
        #[wasm_bindgen(unchecked_param_type = "EmergencyScope")] scope: JsValue,
        #[wasm_bindgen(js_name = contactPublicSignKey)] contact_public_sign_key: Option<String>,
        #[wasm_bindgen(js_name = contactKeyRecord, unchecked_param_type = "KeyRecord | undefined")]
        contact_key_record: JsValue,
    ) -> Result<String, JsValue> {
        let scope: EmergencyScope = from_js(scope, "emergency scope")?;
        let record: Option<KeyRecord> = if contact_key_record.is_undefined() {
            None
        } else {
            Some(from_js(contact_key_record, "key record")?)
        };
        let pq_key = pq_key_of(
            &contact_account_id,
            &contact_public_enc_key,
            contact_public_sign_key.as_deref(),
            record.as_ref(),
        )?;
        self.inner
            .seal_for_emergency_contact(
                &contact_account_id,
                &public_key(&contact_public_enc_key)?,
                pq_key.as_ref(),
                &scope,
                &mut OsRng,
            )
            .map_err(js_error)
    }

    /// As an emergency contact: opens the grantor's released account key and returns a session
    /// for the grantor's account. `grantor` is the grantor's `AccountBundle`.
    #[wasm_bindgen(js_name = openEmergencyAccount)]
    pub fn open_emergency_account(
        &self,
        #[wasm_bindgen(unchecked_param_type = "AccountBundle")] grantor: JsValue,
        sealed: String,
    ) -> Result<Session, JsValue> {
        let grantor: AccountBundle = from_js(grantor, "grantor account")?;
        let inner = self
            .inner
            .open_emergency_account(grantor, &sealed)
            .map_err(js_error)?;
        Ok(Session { inner })
    }

    /// As an emergency contact: opens one of the grantor's vaults from its released key.
    #[wasm_bindgen(js_name = openEmergencyVault)]
    pub fn open_emergency_vault(
        &mut self,
        #[wasm_bindgen(js_name = grantorAccountId)] grantor_account_id: String,
        #[wasm_bindgen(js_name = vaultId)] vault_id: String,
        sealed: String,
    ) -> Result<(), JsValue> {
        self.inner
            .open_emergency_vault(&grantor_account_id, &vault_id, &sealed)
            .map_err(js_error)
    }
}

/// The fingerprint of an account's public keys, for comparing out of band.
#[wasm_bindgen(js_name = keyFingerprint, unchecked_return_type = "Fingerprint")]
pub fn key_fingerprint(
    #[wasm_bindgen(js_name = publicEncKey)] public_enc_key: String,
    #[wasm_bindgen(js_name = publicSignKey)] public_sign_key: String,
) -> Result<JsValue, JsValue> {
    to_js(&fingerprint::fingerprint(
        &public_key(&public_enc_key)?,
        &public_key(&public_sign_key)?,
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsShareLink {
    ciphertext: String,
    key: String,
    passphrase_required: bool,
}

/// Encrypts an item snapshot for a one-time share link. With a passphrase this runs Argon2id.
#[wasm_bindgen(js_name = createShareLink, unchecked_return_type = "ShareLink")]
pub fn create_share_link(
    #[wasm_bindgen(unchecked_param_type = "ItemPlaintext")] item: JsValue,
    passphrase: Option<String>,
) -> Result<JsValue, JsValue> {
    let item = item_from_js(item)?;
    let passphrase = passphrase.map(zeroize::Zeroizing::new);
    let link = share_link::create(&item, passphrase.as_deref().map(String::as_str), &mut OsRng)
        .map_err(js_error)?;
    to_js(&JsShareLink {
        ciphertext: link.ciphertext,
        key: link.key,
        passphrase_required: link.passphrase_required,
    })
}

/// Whether a share link's ciphertext needs a passphrase as well as the link key.
#[wasm_bindgen(js_name = shareLinkNeedsPassphrase)]
pub fn share_link_needs_passphrase(ciphertext: String) -> Result<bool, JsValue> {
    share_link::needs_passphrase(&ciphertext).map_err(js_error)
}

/// Decrypts a share link with its `#` fragment. Throws `wrong_passphrase` or
/// `invalid_share_link`.
#[wasm_bindgen(js_name = openShareLink, unchecked_return_type = "ItemPlaintext")]
pub fn open_share_link(
    ciphertext: String,
    key: String,
    passphrase: Option<String>,
) -> Result<JsValue, JsValue> {
    if key.is_empty() {
        return Err(invalid_argument("share link key"));
    }
    let passphrase = passphrase.map(zeroize::Zeroizing::new);
    let item = share_link::open(&ciphertext, &key, passphrase.as_deref().map(String::as_str))
        .map_err(js_error)?;
    to_js(&item)
}
