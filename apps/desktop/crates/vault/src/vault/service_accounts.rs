//! Managing service accounts, and the sealed security log entries of Octa Pass Connect (plan 03,
//! "Non-human access"). Tokens are made here, on a person's device, and shown once.

use octapass_api::{
    ConnectEventsRequest, SecurityEvent, ServiceAccountRecord, ServiceAccountsResponse, VaultRole,
    VaultType,
};
use octapass_core::encoding::b64_decode_array;
use octapass_core::service_account::{NewServiceAccount, ServiceAccountToken};
use octapass_core::sharing::Role;
use octapass_core::sharing::grant::Recipient;
use rand_core::OsRng;
use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

use super::Vault;
use super::sharing::segment;
use crate::api::Method;
use crate::error::{ErrorCode, Result, VaultError, not_allowed};
use crate::model::{now, parse_rfc3339, require, rfc3339, unix_ms};
use crate::store::AccountKey;

/// A service account as the apps show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccount {
    pub id: String,
    pub vault_id: String,
    /// Only its creator can open the name; others see `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub role: VaultRole,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// Someone other than its creator rotated the vault's key, so the token can't verify its
    /// grant and has to be replaced.
    pub needs_new_token: bool,
}

/// A new service account, with the token that's shown only now.
pub struct CreatedServiceAccount {
    pub account: ServiceAccount,
    pub token: Zeroizing<String>,
}

impl Vault {
    /// Makes a service account for a shared vault this account manages. `role` is read or write.
    pub async fn create_service_account(
        &self,
        vault_id: &str,
        name: &str,
        role: VaultRole,
        expires_at: Option<&str>,
    ) -> Result<CreatedServiceAccount> {
        let key = self.account_key()?;
        let core_role = match role {
            VaultRole::Read => Role::Read,
            VaultRole::Write => Role::Write,
            _ => return Err(ErrorCode::NotAllowed.into()),
        };
        let expires_at = expires_at
            .map(|at| {
                let parsed = parse_rfc3339(at).ok_or_else(|| {
                    VaultError::unexpected("the expiry isn't an RFC 3339 timestamp")
                })?;
                Ok::<_, VaultError>(rfc3339(parsed))
            })
            .transpose()?;
        let _io = self.io.lock().await;
        self.sync_locked().await?;
        let new: NewServiceAccount = self.with_unlocked(|unlocked| {
            let vault = unlocked.cache.vault(vault_id).ok_or(ErrorCode::NotFound)?;
            require(vault.vault_type == VaultType::Shared, ErrorCode::NotAllowed)?;
            require(
                matches!(vault.role, VaultRole::Owner | VaultRole::Manage),
                ErrorCode::NotAllowed,
            )?;
            require(
                !unlocked.untrusted.contains(vault_id),
                ErrorCode::UntrustedVault,
            )?;
            Ok(unlocked.session.create_service_account(
                vault_id,
                core_role,
                name,
                &key.server_url,
                unix_ms(now()),
                &mut OsRng,
            )?)
        })?;
        let mut body = serde_json::to_value(&new)
            .map_err(|error| VaultError::unexpected(error.to_string()))?;
        if let Some(at) = expires_at {
            body["expiresAt"] = Value::String(at);
        }
        let path = format!("/v1/vaults/{}/service-accounts", segment(vault_id));
        let record: ServiceAccountRecord = self
            .server(&key, Method::POST, &path, Some(body))
            .await?
            .map_err(|error| not_allowed(error.into()))?;
        Ok(CreatedServiceAccount {
            account: self.view(record)?,
            token: new.token.encode(),
        })
    }

    pub async fn list_service_accounts(&self, vault_id: &str) -> Result<Vec<ServiceAccount>> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let records = self.service_account_records(&key, vault_id).await?;
        records
            .into_iter()
            .map(|record| self.view(record))
            .collect()
    }

    /// The caller holds `io`.
    pub(super) async fn service_account_records(
        &self,
        key: &AccountKey,
        vault_id: &str,
    ) -> Result<Vec<ServiceAccountRecord>> {
        let path = format!("/v1/vaults/{}/service-accounts", segment(vault_id));
        let response: ServiceAccountsResponse = self
            .server(key, Method::GET, &path, None)
            .await?
            .map_err(|error| not_allowed(error.into()))?;
        Ok(response.service_accounts)
    }

    /// Ends a service account now, then rotates the vault's key, as removing a member does. If the
    /// rotation fails the account is still revoked, and the error says what's left to do.
    pub async fn revoke_service_account(&self, vault_id: &str, id: &str) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let path = format!(
            "/v1/vaults/{}/service-accounts/{}",
            segment(vault_id),
            segment(id)
        );
        self.server::<Value>(&key, Method::DELETE, &path, None)
            .await?
            .map_err(|error| not_allowed(error.into()))?;
        self.rotate(&key, vault_id, Vec::new()).await
    }

    /// The name, when this account made it; `None` otherwise.
    fn view(&self, record: ServiceAccountRecord) -> Result<ServiceAccount> {
        let name = self.with_unlocked(|unlocked| {
            Ok(unlocked
                .session
                .open_service_account_name(&record.vault_id, &record.id, &record.encrypted_name)
                .ok())
        })?;
        Ok(ServiceAccount {
            needs_new_token: record.granted_by != record.created_by,
            id: record.id,
            vault_id: record.vault_id,
            name,
            role: record.role,
            created_at: record.created_at,
            expires_at: record.expires_at,
            last_used_at: record.last_used_at,
            revoked_at: record.revoked_at,
        })
    }

    /// The recipients a rotation must also seal the new key to, in the order they're listed.
    pub(super) fn service_recipients(records: &[ServiceAccountRecord]) -> Result<Vec<Recipient>> {
        records
            .iter()
            .filter(|record| record.revoked_at.is_none())
            .map(|record| {
                Ok(Recipient {
                    account_id: record.id.clone(),
                    public_enc_key: b64_decode_array(&record.public_enc_key)?,
                    public_pq_key: None,
                    role: if record.role == VaultRole::Write {
                        Role::Write
                    } else {
                        Role::Read
                    },
                })
            })
            .collect()
    }

    // ---------- Sealed security log entries ----------

    /// Seals one entry so that only this account can read it.
    pub fn seal_audit_detail(&self, detail: &[u8]) -> Result<String> {
        self.with_unlocked(|unlocked| Ok(unlocked.session.seal_audit_detail(detail, &mut OsRng)?))
    }

    /// Sends sealed entries to the security log. They're ciphertext to the server.
    pub async fn record_connect_events(&self, sealed_details: Vec<String>) -> Result<()> {
        let key = self.account_key()?;
        let _io = self.io.lock().await;
        let body = ConnectEventsRequest { sealed_details };
        let body = serde_json::to_value(&body)
            .map_err(|error| VaultError::unexpected(error.to_string()))?;
        self.server::<Value>(&key, Method::POST, "/v1/security-log/connect", Some(body))
            .await??;
        Ok(())
    }

    /// The security log with Connect's entries opened where this account can open them: each
    /// event's `sealedDetail` becomes the entry's JSON text.
    pub async fn security_log_opened(&self) -> Result<Vec<SecurityEvent>> {
        let mut events = self.security_log().await?;
        self.with_unlocked(|unlocked| {
            for event in &mut events {
                event.sealed_detail = event.sealed_detail.as_deref().and_then(|sealed| {
                    let bytes = unlocked.session.open_audit_detail(sealed).ok()?;
                    String::from_utf8(bytes.to_vec()).ok()
                });
            }
            Ok(())
        })?;
        Ok(events)
    }
}

/// Parses a token without using it: a runner's first check, and the CLI's `status`.
pub fn parse_token(text: &str) -> Result<ServiceAccountToken> {
    ServiceAccountToken::parse(text).map_err(|_| {
        VaultError::new(
            ErrorCode::InvalidServiceAccountToken,
            "This isn't a whole service account token.",
        )
    })
}
