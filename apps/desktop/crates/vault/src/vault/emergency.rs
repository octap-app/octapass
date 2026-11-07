//! Emergency access (plan 06), as `packages/vault-client/src/remote/emergency.ts` does it. The
//! grantor seals their account key, or one vault's key, to a trusted contact. The server hands it
//! over only after a waiting period the grantor didn't cut short with a denial; then the contact
//! opens the grantor's vaults read-only, in this process.

use octapass_api::problem::types;
use octapass_api::{
    EmergencyAccessLevel, EmergencyContactRecord, EmergencyContactsResponse,
    EmergencyReleaseResponse, EmergencyScope as ApiScope, EmergencyTakeoverRequest,
    PasswordRegistrationResponse, ReauthPurpose, SyncResponse, VaultRole,
};
use octapass_core::account::AccountBundle;
use octapass_core::attachment::Decryptor;
use octapass_core::encoding::b64_decode_array;
use octapass_core::kdf::KdfParams;
use octapass_core::opaque::RegistrationClient;
use octapass_core::session::Session;
use octapass_core::sharing::emergency::EmergencyScope;
use octapass_core::sharing::pq::PqPublicKey;
use octapass_core::transparency::record::{KeyRecord, OfferedKeys};
use rand_core::OsRng;
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::key_log::KeyCheck;
use super::sharing::{AccountLookup, check_fingerprint, segment};
use super::{Event, Vault, blocking, convert, decrypt, synced_vault};
use crate::api::{ApiError, Method};
use crate::error::{ErrorCode, Result, VaultError, not_allowed};
use crate::model::{Item, NewRecoveryKit, Vault as VaultView, now, require, rfc3339, vault_names};
use crate::store::AccountKey;

/// Before sealing anything to `account`: the fingerprint the user compared must match, the key
/// log must not contradict its keys, and its ML-KEM key comes only from a record that checks out
/// (plan 03). Returns the X25519 key and the ML-KEM key, if any.
fn contact_keys(account: &AccountLookup) -> Result<([u8; 32], Option<PqPublicKey>)> {
    check_fingerprint(account)?;
    if account.key_log == Some(KeyCheck::Failed) {
        return Err(ErrorCode::KeyLogMismatch.into());
    }
    let offered = OfferedKeys {
        account_id: &account.account_id,
        public_enc_key: &account.public_enc_key,
        public_sign_key: &account.public_sign_key,
    };
    let pq_key = KeyRecord::pq_key_of(account.key_record.as_ref(), &offered)?;
    Ok((b64_decode_array(&account.public_enc_key)?, pq_key))
}

const WAIT_DAYS: std::ops::RangeInclusive<u32> = 1..=30;
const MAX_PAGES: usize = 1000;
/// A renewal races key rotations by other members; after this many `vault-key-changed`, give up.
const KEY_ATTEMPTS: usize = 2;

/// A grantor's vaults, opened read-only by their contact after release.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyVaultView {
    pub contact: EmergencyContactRecord,
    pub vaults: Vec<VaultView>,
    pub items: Vec<Item>,
}

/// What the contact can do with a released key.
enum Released {
    /// The grantor's own session, opened with their account key: every vault they can open.
    Account(Box<Session>),
    /// One vault's key, kept in this account's session.
    Vault(String),
}

impl Vault {
    pub async fn list_emergency_contacts(&self) -> Result<EmergencyContactsResponse> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        Ok(self
            .server(&key, Method::GET, "/v1/emergency-contacts", None)
            .await??)
    }

    /// Seals this account's key, or one vault's, to `account` (from `lookup_account`, after the
    /// user compared its fingerprint).
    pub async fn add_emergency_contact(
        &self,
        account: &AccountLookup,
        wait_days: u32,
        access_level: EmergencyAccessLevel,
        scope: EmergencyScope,
    ) -> Result<EmergencyContactRecord> {
        if !WAIT_DAYS.contains(&wait_days) {
            return Err(VaultError::new(
                ErrorCode::ServerError,
                "The waiting period is 1 to 30 days.",
            ));
        }
        let (public_enc_key, pq_key) = contact_keys(account)?;
        let sealed_key = self.with_unlocked(|unlocked| {
            if let EmergencyScope::Vault { vault_id } = &scope {
                unlocked.cache.vault(vault_id).ok_or(ErrorCode::NotFound)?;
                require(
                    !unlocked.untrusted.contains(vault_id),
                    ErrorCode::UntrustedVault,
                )?;
            }
            Ok(unlocked.session.seal_for_emergency_contact(
                &account.account_id,
                &public_enc_key,
                pq_key.as_ref(),
                &scope,
                &mut OsRng,
            )?)
        })?;
        let body = json!({
            "contactAccountId": account.account_id,
            "sealedKey": sealed_key,
            "scope": scope,
            "accessLevel": access_level,
            "waitDays": wait_days,
        });
        let key = self.account_key()?;
        let contact = {
            let _io = self.io.lock().await;
            self.server(&key, Method::POST, "/v1/emergency-contacts", Some(body))
                .await??
        };
        self.emit(Event::SharingChanged);
        Ok(contact)
    }

    /// Either side: removes a contact, or steps down as one.
    pub async fn remove_emergency_contact(&self, id: &str) -> Result<()> {
        let key = self.account_key()?;
        {
            let _io = self.io.lock().await;
            let path = format!("/v1/emergency-contacts/{}", segment(id));
            self.server::<Value>(&key, Method::DELETE, &path, None)
                .await??;
        }
        self.emit(Event::SharingChanged);
        Ok(())
    }

    /// `request` (the contact), `deny` or `approve` (the grantor).
    /// As the grantor, after a rotation: seals the vault's current key to the contact again.
    /// `account` is a lookup whose fingerprint the user compared: sealing to whichever key a
    /// server names, by itself, would let a server collect the vault key.
    pub async fn renew_emergency_key(&self, id: &str, account: &AccountLookup) -> Result<()> {
        let (public_enc_key, pq_key) = contact_keys(account)?;
        let key = self.account_key()?;
        {
            let _io = self.io.lock().await;
            let contacts: EmergencyContactsResponse = self
                .server(&key, Method::GET, "/v1/emergency-contacts", None)
                .await??;
            let contact = contacts
                .granted
                .iter()
                .find(|contact| contact.id == id)
                .ok_or(ErrorCode::NotFound)?;
            let ApiScope::Vault { vault_id } = &contact.scope else {
                return Err(ErrorCode::NotAllowed.into());
            };
            require(
                contact.contact_id == account.account_id,
                ErrorCode::NotAllowed,
            )?;
            let scope = EmergencyScope::Vault {
                vault_id: vault_id.clone(),
            };
            for attempt in 1..=KEY_ATTEMPTS {
                self.sync_locked().await?;
                let (sealed_key, key_id) = self.with_unlocked(|unlocked| {
                    Ok((
                        unlocked.session.seal_for_emergency_contact(
                            &account.account_id,
                            &public_enc_key,
                            pq_key.as_ref(),
                            &scope,
                            &mut OsRng,
                        )?,
                        unlocked.session.vault_key_id(vault_id)?,
                    ))
                })?;
                let path = format!("/v1/emergency-contacts/{}/key", segment(id));
                let body = json!({ "sealedKey": sealed_key, "keyId": key_id });
                match self
                    .server::<Value>(&key, Method::PUT, &path, Some(body))
                    .await?
                {
                    Ok(_) => break,
                    Err(error) if error.is(types::VAULT_KEY_CHANGED) && attempt < KEY_ATTEMPTS => {}
                    Err(error) => return Err(not_allowed(error.into())),
                }
            }
        }
        self.emit(Event::SharingChanged);
        Ok(())
    }

    /// As a family member: lets the organiser help recover this account (plan 06). `account` is
    /// the organiser, from a lookup whose fingerprint the user compared.
    pub async fn enable_organiser_recovery(
        &self,
        account: &AccountLookup,
        wait_days: u32,
    ) -> Result<EmergencyContactRecord> {
        if !WAIT_DAYS.contains(&wait_days) {
            return Err(VaultError::new(
                ErrorCode::ServerError,
                "The waiting period is 1 to 30 days.",
            ));
        }
        let (public_enc_key, pq_key) = contact_keys(account)?;
        let key = self.account_key()?;
        let record: EmergencyContactRecord = {
            let _io = self.io.lock().await;
            let family = self.require_family(&key).await?;
            require(
                family.organiser_id == account.account_id,
                ErrorCode::NotAllowed,
            )?;
            let sealed_key = self.with_unlocked(|unlocked| {
                Ok(unlocked.session.seal_for_emergency_contact(
                    &account.account_id,
                    &public_enc_key,
                    pq_key.as_ref(),
                    &EmergencyScope::Account,
                    &mut OsRng,
                )?)
            })?;
            let path = format!("/v1/families/{}/organiser-recovery", segment(&family.id));
            let body = json!({ "sealedKey": sealed_key, "waitDays": wait_days });
            self.server(&key, Method::POST, &path, Some(body))
                .await?
                .map_err(|error| not_allowed(error.into()))?
        };
        self.emit(Event::SharingChanged);
        Ok(record)
    }

    /// As the contact of a released takeover record (plan 06, "Takeover design"): sets a new
    /// master password, Secret Key and recovery code for the grantor, who is signed out
    /// everywhere. `contact_password` is this account's own. The kit returned is the only copy.
    pub async fn take_over_account(
        &self,
        id: &str,
        contact_password: Zeroizing<String>,
        new_password: Zeroizing<String>,
    ) -> Result<NewRecoveryKit> {
        let account = self.unlocked_account()?;
        let key = account.key.clone();
        let kit = {
            let _io = self.io.lock().await;
            let (reauth_token, own_session) = self
                .reauth_session(&account, contact_password, ReauthPurpose::EmergencyTakeover)
                .await?;
            let path = format!("/v1/emergency-contacts/{}/release", segment(id));
            let release: EmergencyReleaseResponse = self
                .server(&key, Method::GET, &path, None)
                .await?
                .map_err(|error| not_allowed(error.into()))?;
            let bundle: AccountBundle =
                convert(release.grantor.as_ref().ok_or(ErrorCode::NotAllowed)?)?;
            let email = bundle.email.clone();
            let grantor = own_session.open_emergency_account(bundle, &release.sealed_key)?;
            let (grantor, new) = blocking(move || {
                let new = grantor.new_credentials(
                    &new_password,
                    None,
                    true,
                    KdfParams::DEFAULT,
                    &mut OsRng,
                )?;
                Ok((grantor, new))
            })
            .await?;
            let (registration, registration_request) =
                RegistrationClient::start(&new.keys.auth_secret, &mut OsRng)?;
            let path = format!(
                "/v1/emergency-contacts/{}/takeover/registration",
                segment(id)
            );
            let body = json!({ "registrationRequest": registration_request });
            let registered: PasswordRegistrationResponse = self
                .server(&key, Method::POST, &path, Some(body))
                .await?
                .map_err(|error| not_allowed(error.into()))?;
            let registration_upload = registration.finish(
                &new.keys.auth_secret,
                &registered.registration_response,
                &mut OsRng,
            )?;
            let signature = grantor.sign_takeover(
                id,
                &release.contact.contact_id,
                &registration_upload,
                &new.update,
            )?;
            let request = EmergencyTakeoverRequest {
                registration_upload,
                account: convert(&new.update)?,
                signature,
            };
            let sent = self
                .authed(&key, |api, token| {
                    let (request, reauth_token) = (request.clone(), reauth_token.clone());
                    let id = segment(id);
                    async move {
                        api.emergency_takeover(&token, &id, &reauth_token, &request)
                            .await
                    }
                })
                .await?;
            if let Err(error) = sent {
                // A lost answer must not lose the only copy of the new kit: the record is gone
                // once it landed.
                let contacts = self
                    .server::<EmergencyContactsResponse>(
                        &key,
                        Method::GET,
                        "/v1/emergency-contacts",
                        None,
                    )
                    .await
                    .ok()
                    .and_then(Result::ok);
                let gone =
                    contacts.is_some_and(|contacts| contacts.received.iter().all(|c| c.id != id));
                if !gone {
                    return Err(not_allowed(error.into()));
                }
            }
            NewRecoveryKit {
                email,
                server_url: key.server_url.clone(),
                secret_key: new.secret_key.to_text().to_string(),
                recovery_code: new
                    .recovery_code
                    .as_ref()
                    .map(|code| code.to_text().to_string()),
                created_at: rfc3339(now()),
            }
        };
        self.emit(Event::SharingChanged);
        Ok(kit)
    }

    pub async fn emergency_action(&self, id: &str, action: &str) -> Result<()> {
        require(
            matches!(action, "request" | "deny" | "approve"),
            ErrorCode::NotFound,
        )?;
        let key = self.account_key()?;
        {
            let _io = self.io.lock().await;
            let path = format!("/v1/emergency-contacts/{}/{action}", segment(id));
            self.server::<Value>(&key, Method::POST, &path, None)
                .await?
                .map_err(|error| not_allowed(error.into()))?;
        }
        self.emit(Event::SharingChanged);
        Ok(())
    }

    /// As the contact, once released: the grantor's vaults in scope, read-only.
    pub async fn open_emergency_access(&self, id: &str) -> Result<EmergencyVaultView> {
        let key = self.account_key()?;
        let (release, sync) = {
            let _io = self.io.lock().await;
            self.released(&key, id).await?
        };
        let contact = release.contact.clone();
        self.with_released(&release, &sync, |session, vault_scope| {
            let decrypted: Vec<Item> = sync
                .items
                .iter()
                .filter(|record| record.deleted_at.is_none())
                .filter(|record| vault_scope.is_none_or(|vault_id| record.vault_id == vault_id))
                .filter_map(|record| decrypt(session, record).ok())
                .collect();
            let names = vault_names(&decrypted);
            let vaults = sync
                .vaults
                .iter()
                .filter(|vault| vault_scope.is_none_or(|vault_id| vault.id == vault_id))
                .map(|vault| {
                    let mut view = VaultView::new(vault, &names, !session.is_vault_open(&vault.id));
                    view.role = VaultRole::Read;
                    view
                })
                .collect();
            let items = decrypted
                .into_iter()
                .filter(|item| !item.is_vault_info())
                .collect();
            Ok(EmergencyVaultView {
                contact,
                vaults,
                items,
            })
        })
    }

    /// As the contact, once released: downloads and decrypts one of the grantor's files. Checks
    /// the release again, so a denial or removal stops it.
    pub async fn emergency_attachment(
        &self,
        id: &str,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Vec<u8>> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let (release, sync) = self.released(&key, id).await?;
        let record = sync
            .items
            .iter()
            .find(|record| record.id == item_id && record.deleted_at.is_none())
            .ok_or(ErrorCode::NotFound)?;
        let mut decryptor: Decryptor =
            self.with_released(&release, &sync, |session, vault_scope| {
                require(
                    vault_scope.is_none_or(|vault_id| record.vault_id == vault_id),
                    ErrorCode::NotFound,
                )?;
                let item = decrypt(session, record)?;
                let wrapped_key = item
                    .details
                    .get("attachments")
                    .and_then(Value::as_array)
                    .and_then(|files| {
                        files.iter().find(|file| {
                            file.get("id").and_then(Value::as_str) == Some(attachment_id)
                        })
                    })
                    .and_then(|file| file.get("key").and_then(Value::as_str))
                    .ok_or(ErrorCode::NotFound)?;
                Ok(session.open_attachment(
                    &record.vault_id,
                    &record.id,
                    &record.encrypted_item_key,
                    attachment_id,
                    wrapped_key,
                )?)
            })?;
        let path = format!(
            "/v1/emergency-contacts/{}/vaults/{}/items/{}/attachments/{}",
            segment(id),
            segment(&record.vault_id),
            segment(&record.id),
            segment(attachment_id)
        );
        let mut response = self
            .authed(&key, |api, token| {
                let path = path.clone();
                async move { api.download(&token, &path).await }
            })
            .await??;
        let network = |error: reqwest::Error| {
            VaultError::from(ApiError::Network(error.without_url().to_string()))
        };
        let damaged =
            |_| VaultError::new(ErrorCode::ServerError, "the file could not be decrypted");
        let mut file = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(network)? {
            file.extend_from_slice(&decryptor.push(&chunk).map_err(damaged)?);
        }
        file.extend_from_slice(&decryptor.finish().map_err(damaged)?);
        Ok(file)
    }

    /// The released key and everything in scope. The caller holds `io`.
    async fn released(
        &self,
        key: &AccountKey,
        id: &str,
    ) -> Result<(EmergencyReleaseResponse, SyncResponse)> {
        let path = format!("/v1/emergency-contacts/{}/release", segment(id));
        let release: EmergencyReleaseResponse = self
            .server(key, Method::GET, &path, None)
            .await?
            .map_err(|error| not_allowed(error.into()))?;
        let mut merged = SyncResponse {
            vaults: Vec::new(),
            items: Vec::new(),
            deleted: Vec::new(),
            has_more: false,
        };
        let mut since = String::new();
        for _ in 0..MAX_PAGES {
            let path = format!("/v1/emergency-contacts/{}/sync{since}", segment(id));
            let page: SyncResponse = self
                .server(key, Method::GET, &path, None)
                .await?
                .map_err(|error| not_allowed(error.into()))?;
            merged.vaults = page.vaults;
            merged.items.extend(page.items);
            if !page.has_more {
                return Ok((release, merged));
            }
            let cursor: Vec<String> = merged
                .vaults
                .iter()
                .map(|vault| format!("{}:{}", vault.id, vault.revision))
                .collect();
            since = format!("?since={}", cursor.join(","));
        }
        Err(VaultError::new(
            ErrorCode::ServerError,
            "too many sync pages",
        ))
    }

    /// Runs `read` with a session that opens what the release covers, and the vault it's
    /// limited to (a vault scope).
    fn with_released<T>(
        &self,
        release: &EmergencyReleaseResponse,
        sync: &SyncResponse,
        read: impl FnOnce(&Session, Option<&str>) -> Result<T>,
    ) -> Result<T> {
        let contact = &release.contact;
        let released = self.with_unlocked(|unlocked| match &contact.scope {
            ApiScope::Account => {
                let grantor = release
                    .grantor
                    .as_ref()
                    .ok_or_else(|| VaultError::new(ErrorCode::ServerError, "no grantor account"))?;
                let bundle: AccountBundle = convert(grantor)?;
                Ok(Released::Account(Box::new(
                    unlocked
                        .session
                        .open_emergency_account(bundle, &release.sealed_key)?,
                )))
            }
            ApiScope::Vault { vault_id } => {
                // A member of the vault already holds its current key; the released one may be
                // older, and would replace it.
                let member = unlocked.cache.vault(vault_id).is_some()
                    && unlocked.session.is_vault_open(vault_id);
                if !member {
                    unlocked.session.open_emergency_vault(
                        &contact.grantor_id,
                        vault_id,
                        &release.sealed_key,
                    )?;
                }
                Ok(Released::Vault(vault_id.clone()))
            }
        })?;
        match released {
            Released::Account(mut grantor) => {
                // As the grantor's own apps would: personal vaults with the account key, shared
                // ones once their grant verifies.
                for vault in &sync.vaults {
                    let _ = grantor.open_synced_vault(&synced_vault(vault));
                }
                read(&grantor, None)
            }
            Released::Vault(vault_id) => {
                self.with_unlocked(|unlocked| read(&unlocked.session, Some(&vault_id)))
            }
        }
    }
}
