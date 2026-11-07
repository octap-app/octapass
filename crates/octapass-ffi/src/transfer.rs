//! Moving the vault to another password manager on the phone: Android's credential transfer
//! (`androidx.credentials.providerevents`) asks Octa Pass for its items in the FIDO Credential
//! Exchange Format, which [`octapass_core::export::cxf`] writes.

use std::sync::Arc;

use octapass_api::VaultType;
use octapass_core::export::cxf::{self, CxfAccount};
use octapass_core::export::{ExportDocument, ExportItem, ExportVault};
use serde_json::Map;

use crate::error::Result;
use crate::session::{Session, live_items};
use crate::store::LocalStore;
use crate::{now_ms, timestamp};

/// CXF for another app, and how many items are in it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CredentialExport {
    /// A CXF `Header` with one account. Plaintext: hand it straight to the app that asked.
    pub json: String,
    pub exported: u32,
}

#[uniffi::export]
impl Session {
    /// Every item outside the trash as CXF, holding only the `credential_types` the importing
    /// app asked for (`basic-auth`, `passkey`, …). `exporter_rp_id` is the server's host. Call it
    /// only after the user confirmed the export with the master password (plan 07).
    pub fn export_for_app(
        &self,
        store: Arc<LocalStore>,
        credential_types: Vec<String>,
        exporter_rp_id: String,
    ) -> Result<CredentialExport> {
        self.with_store(&store, |core, data| {
            let email = core.bundle().email.clone();
            let id = core
                .bundle()
                .account_id
                .clone()
                .unwrap_or_else(|| email.clone());
            let vaults = data
                .vaults
                .values()
                .map(|vault| ExportVault {
                    id: vault.id.clone(),
                    // Vault names aren't in `VaultRecord` yet (plan 11 History).
                    name: match vault.vault_type {
                        VaultType::Personal => "Personal",
                        VaultType::Shared => "Shared",
                        VaultType::Family => "Family",
                    }
                    .into(),
                    vault_type: serde_json::to_value(vault.vault_type)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_default(),
                    extra: Map::new(),
                })
                .collect();
            let mut items: Vec<ExportItem> = live_items(core, data)
                .into_iter()
                .map(|(stored, item)| {
                    let value = serde_json::to_value(&item).expect("items serialize");
                    ExportItem {
                        id: stored.record.id.clone(),
                        vault_id: stored.record.vault_id.clone(),
                        created_at: created_at(&stored.record.id)
                            .unwrap_or_else(|| stored.record.updated_at.clone()),
                        updated_at: stored.record.updated_at.clone(),
                        overview: value["overview"].clone(),
                        details: value["details"].clone(),
                    }
                })
                .collect();
            items.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
            let now = now_ms();
            let document = ExportDocument::new(timestamp(now), vaults, items);
            let export = cxf::export_for_app(
                &document,
                &CxfAccount {
                    id,
                    username: String::new(),
                    email,
                },
                &exporter_rp_id,
                now / 1000,
                &credential_types,
            );
            Ok(CredentialExport {
                json: export.json,
                exported: u32::try_from(export.exported).unwrap_or(u32::MAX),
            })
        })
    }
}

/// Items get UUIDv7 ids when they're created, so the id carries the creation time.
fn created_at(id: &str) -> Option<String> {
    let hex: String = id.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || hex.as_bytes()[12] != b'7' {
        return None;
    }
    u64::from_str_radix(&hex[..12], 16).ok().map(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_times_come_from_the_id() {
        assert_eq!(
            created_at("0190a6c4-7d00-7000-8000-000000000001").as_deref(),
            Some("2024-07-12T11:46:53.312Z")
        );
        assert_eq!(created_at("not-an-id"), None);
    }
}
