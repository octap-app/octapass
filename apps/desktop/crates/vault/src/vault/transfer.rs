//! Exports and imports that need the core (`octapass_core::export` and `import`): the encrypted
//! export with every attachment, CXF, and every importer. The Octa Pass JSON and CSV exports are
//! made from [`Vault::live_items`] by the caller (the web view, or the CLI).

use octapass_api::{EmailBreach, ExportFormat, SecurityEvent, VaultExportedRequest, VaultRole};
use octapass_core::account::new_id;
use octapass_core::encoding::b64_encode;
use octapass_core::export::{
    self, ArchiveFiles, ArchiveWriter, ExportDocument, ExportItem, ExportVault,
};
use octapass_core::import::{
    self, CodeLink, ImportOptions, ImportResult, ImportSource, ImportedFile,
};
use octapass_core::kdf::KdfParams;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::Vault;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{Item, ItemDraft, Vault as VaultView, now, rfc3339, unix_ms};

/// The exports made here; JSON and CSV come from the items directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileExport {
    Cxf,
    Encrypted,
}

/// `ImportResult` in `packages/vault-client`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    pub imported: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
    /// Attached files restored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<usize>,
    /// Items already in the vault that the file changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<usize>,
    /// Items already in the vault exactly as the file has them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unchanged: Option<usize>,
}

/// `ImportReview` in `packages/vault-client`: an authenticator import waiting for the user to
/// link its one-time codes to logins. It never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReview {
    pub id: String,
    pub codes: Vec<ReviewCode>,
    /// New items that aren't one-time codes (counter-based codes kept as fields, notes).
    pub other_items: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
}

/// `ReviewCode` in `packages/vault-client`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewCode {
    /// For [`CodeLink::code`].
    pub index: usize,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The login the importer matched it to; without one it becomes a login of its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_id: Option<String>,
}

impl ImportReview {
    fn new(id: String, result: &ImportResult) -> Self {
        let code_items = result
            .codes
            .iter()
            .filter(|code| code.item.is_some())
            .count();
        Self {
            id,
            codes: result
                .codes
                .iter()
                .enumerate()
                .map(|(index, code)| ReviewCode {
                    index,
                    title: code.title.clone(),
                    issuer: code.issuer.clone(),
                    account: code.account.clone(),
                    login_id: code
                        .update
                        .and_then(|update| result.totp_updates.get(update))
                        .map(|update| update.item_id.clone()),
                })
                .collect(),
            other_items: result.items.len().saturating_sub(code_items),
            skipped: result.skipped,
            warnings: result.warnings.clone(),
        }
    }
}

/// A parsed import kept in memory until its review is finished or cancelled.
pub(crate) struct PendingImport {
    result: ImportResult,
    files: ArchiveFiles,
    vault_id: String,
}

/// The Octa Pass JSON document of `items`, as the web vault writes it.
pub fn document(vaults: &[VaultView], items: &[Item], exported_at: &str) -> ExportDocument {
    ExportDocument::new(
        exported_at.to_owned(),
        vaults
            .iter()
            .map(|vault| ExportVault {
                id: vault.id.clone(),
                name: vault.name.clone(),
                vault_type: serde_json::to_value(vault.vault_type)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                extra: Map::new(),
            })
            .collect(),
        items
            .iter()
            .map(|item| ExportItem {
                id: item.id.clone(),
                vault_id: item.vault_id.clone(),
                created_at: item.created_at.clone(),
                updated_at: item.updated_at.clone(),
                overview: item.overview.clone(),
                details: item.details.clone(),
            })
            .collect(),
    )
}

fn import_error(error: import::ImportError) -> VaultError {
    let code = match error.code {
        octapass_core::Error::ImportPasswordRequired => ErrorCode::ImportPasswordRequired,
        octapass_core::Error::WrongImportPassword => ErrorCode::WrongImportPassword,
        _ => ErrorCode::InvalidImportFile,
    };
    VaultError::new(code, error.detail)
}

impl Vault {
    /// Every live item, oldest first, the order exports list them in.
    fn export_items(&self) -> Result<Vec<Item>> {
        let mut items = self.live_items()?;
        // Importing the dashboard's settings would turn email breach alerts on for another account.
        items.retain(|item| !crate::health::is_health_settings(item));
        items.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(items)
    }

    /// The CXF export, or the encrypted export with every attachment (downloaded and decrypted
    /// one at a time). `kdf` is the encrypted export's Argon2id settings
    /// ([`export::EXPORT_KDF`] outside tests).
    pub async fn export_file(
        &self,
        format: FileExport,
        password: Option<&str>,
        kdf: KdfParams,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let vaults = self.list_vaults()?;
        let items = self.export_items()?;
        let (email, server_url) = self.with_unlocked(|unlocked| {
            Ok((unlocked.key.email.clone(), unlocked.key.server_url.clone()))
        })?;
        let at = now();
        let document = document(&vaults, &items, &rfc3339(at));
        match format {
            FileExport::Cxf => {
                let host = reqwest::Url::parse(&server_url)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .unwrap_or_default();
                let account = export::cxf::CxfAccount {
                    id: email.clone(),
                    username: String::new(),
                    email,
                };
                let cxf = export::cxf::export(&document, &account, &host, unix_ms(at) / 1000);
                Ok(Zeroizing::new(cxf.json.into_bytes()))
            }
            FileExport::Encrypted => {
                let password = password.filter(|p| !p.is_empty()).ok_or_else(|| {
                    VaultError::new(
                        ErrorCode::PasswordRequired,
                        "an encrypted export needs a password",
                    )
                })?;
                let mut writer = ArchiveWriter::new(password, kdf, &mut OsRng)?;
                let mut out = Zeroizing::new(writer.add_items(document.to_json().as_bytes())?);
                for item in &items {
                    for id in attachment_ids(&item.details) {
                        let file = Zeroizing::new(self.get_attachment(&item.id, &id).await?);
                        out.extend(writer.add_file(&id, &file)?);
                    }
                }
                out.extend(writer.finish()?);
                Ok(out)
            }
        }
    }

    /// Adds "vault exported" to the account's security log once the user has the file: the format,
    /// and whether the attachments went with it (only the encrypted export holds them). Nothing
    /// from the vault. Callers carry on when this fails, as an export works offline too.
    pub async fn record_export(&self, format: ExportFormat) -> Result<()> {
        let _io = self.io.lock().await;
        let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
        // A local vault has no security log.
        if key.is_local() {
            return Ok(());
        }
        let body = &VaultExportedRequest {
            format,
            attachments: format == ExportFormat::Encrypted,
        };
        self.authed(&key, |api, token| async move {
            api.record_export(&token, body).await
        })
        .await??;
        Ok(())
    }

    /// Asks the server about one address (email breach alerts, opt-in).
    pub async fn lookup_email_breaches(&self, address: &str) -> Result<Vec<EmailBreach>> {
        let _io = self.io.lock().await;
        let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
        let address = address.to_owned();
        let answer = self
            .authed(&key, |api, token| {
                let address = address.clone();
                async move { api.email_breaches(&token, &address).await }
            })
            .await??;
        Ok(answer.breaches)
    }

    /// The account's security log, newest first.
    pub async fn security_log(&self) -> Result<Vec<SecurityEvent>> {
        let _io = self.io.lock().await;
        let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
        let log = self
            .authed(
                &key,
                |api, token| async move { api.security_log(&token).await },
            )
            .await??;
        Ok(log.events)
    }

    /// Imports a file into `vault_id`: items, one-time codes for logins already there, and an
    /// Octa Pass encrypted export's attachments.
    pub async fn import_file(
        &self,
        source: ImportSource,
        bytes: &[u8],
        options: ImportOptions,
        vault_id: &str,
    ) -> Result<ImportSummary> {
        self.import_target(vault_id)?;
        let (result, files) = self.parse_import(source, bytes, options, vault_id)?;
        self.save_import(result, &files, vault_id).await
    }

    /// Parses a file for the import review (authenticator imports), where the user links each
    /// one-time code to a login. Nothing is saved until [`Vault::finish_import`]; the parsed file
    /// stays in memory until then, [`Vault::cancel_import`], or the vault locks.
    pub fn review_import(
        &self,
        source: ImportSource,
        bytes: &[u8],
        options: ImportOptions,
        vault_id: &str,
    ) -> Result<ImportReview> {
        self.import_target(vault_id)?;
        let (result, files) = self.parse_import(source, bytes, options, vault_id)?;
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let review = ImportReview::new(b64_encode(&id), &result);
        self.with_unlocked(|unlocked| {
            unlocked.imports.insert(
                review.id.clone(),
                PendingImport {
                    result,
                    files,
                    vault_id: vault_id.to_owned(),
                },
            );
            Ok(())
        })?;
        Ok(review)
    }

    /// Saves a reviewed import with the user's choices. Codes without a link stay as the review
    /// showed them.
    pub async fn finish_import(
        &self,
        review_id: &str,
        links: &[CodeLink],
    ) -> Result<ImportSummary> {
        let pending = self.with_unlocked(|unlocked| {
            unlocked
                .imports
                .remove(review_id)
                .ok_or_else(|| ErrorCode::ImportReviewExpired.into())
        })?;
        self.import_target(&pending.vault_id)?;
        let result = import::link_codes(pending.result, links);
        self.save_import(result, &pending.files, &pending.vault_id)
            .await
    }

    /// Drops a review without saving anything. A review that's already gone is fine.
    pub fn cancel_import(&self, review_id: &str) {
        let _ = self.with_unlocked(|unlocked| {
            unlocked.imports.remove(review_id);
            Ok(())
        });
    }

    /// Imports go into a vault the user can write to.
    fn import_target(&self, vault_id: &str) -> Result<()> {
        let target = self
            .list_vaults()?
            .into_iter()
            .find(|vault| vault.id == vault_id)
            .ok_or(ErrorCode::NotFound)?;
        if target.untrusted {
            return Err(ErrorCode::UntrustedVault.into());
        }
        if target.role == VaultRole::Read {
            return Err(ErrorCode::ReadOnlyVault.into());
        }
        Ok(())
    }

    /// Runs the importer, with the logins already in the vault for one-time codes to join, and the
    /// items already in `vault_id` that the file may update.
    fn parse_import(
        &self,
        source: ImportSource,
        bytes: &[u8],
        mut options: ImportOptions,
        vault_id: &str,
    ) -> Result<(ImportResult, ArchiveFiles)> {
        options.existing_logins = self.existing_logins()?;
        options.existing_items = self.vault_items()?;
        options.vault_id = Some(vault_id.to_owned());
        options.now = Some(rfc3339(now()));
        if source == ImportSource::OctaPass {
            import::import_octapass(bytes, &options).map_err(import_error)
        } else {
            Ok((
                import::import_file(source, bytes, &options).map_err(import_error)?,
                Vec::new(),
            ))
        }
    }

    /// Saves what an importer produced into `vault_id`: new items, one-time codes for logins
    /// already there, then the files that belong to the new items.
    async fn save_import(
        &self,
        mut result: ImportResult,
        files: &ArchiveFiles,
        vault_id: &str,
    ) -> Result<ImportSummary> {
        let ids: Vec<String> = result
            .items
            .iter()
            .map(|_| new_id(unix_ms(now()), &mut OsRng))
            .collect();
        // Recovery info pointing at a brought-back item, in new items and in the ones updated.
        import::relink_all(&mut result, &ids);

        let mut summary = ImportSummary {
            skipped: result.skipped,
            warnings: result.warnings.clone(),
            ..ImportSummary::default()
        };
        let mut saved = vec![false; ids.len()];
        {
            let _io = self.io.lock().await;
            let key = self.with_unlocked(|unlocked| Ok(unlocked.key.clone()))?;
            for (index, item) in result.items.iter().enumerate() {
                let value = serde_json::to_value(item).expect("items serialize");
                let draft = ItemDraft {
                    id: None,
                    vault_id: vault_id.to_owned(),
                    revision: None,
                    overview: value["overview"].clone(),
                    details: value["details"].clone(),
                };
                match self.put_new(&key, &draft, &ids[index]).await? {
                    Ok(()) => saved[index] = true,
                    Err(error) => {
                        summary.skipped += 1;
                        summary.warnings.push(format!(
                            "\"{}\" couldn't be saved: {}",
                            item.overview.title,
                            VaultError::from(error).message
                        ));
                    }
                }
            }
            summary.imported = saved.iter().filter(|s| **s).count();
            self.sync_locked().await?;
        }
        for update in &result.updates {
            let item = self.get_item(&update.item_id)?;
            let value = serde_json::to_value(&update.item).expect("items serialize");
            let saved = self
                .save_item(ItemDraft {
                    id: Some(item.id.clone()),
                    vault_id: item.vault_id.clone(),
                    revision: Some(item.revision),
                    overview: value["overview"].clone(),
                    details: value["details"].clone(),
                })
                .await;
            match saved {
                Ok(_) => *summary.updated.get_or_insert(0) += 1,
                Err(error) => {
                    summary.skipped += 1;
                    summary.warnings.push(format!(
                        "\"{}\" couldn't be updated: {}",
                        update.item.overview.title, error.message
                    ));
                }
            }
        }
        summary.unchanged = (result.unchanged > 0).then_some(result.unchanged);
        for update in &result.totp_updates {
            let item = self.get_item(&update.item_id)?;
            let mut details = item.details.clone();
            details["totp"] = json!(update.totp);
            self.save_item(ItemDraft {
                id: Some(item.id.clone()),
                vault_id: item.vault_id.clone(),
                revision: Some(item.revision),
                overview: item.overview.clone(),
                details,
            })
            .await?;
            summary.imported += 1;
        }
        let mut restored = 0;
        for ImportedFile {
            item,
            file_id,
            name,
            media_type,
            ..
        } in &result.files
        {
            if !saved[*item] {
                continue;
            }
            let Some((_, data)) = files.iter().find(|(id, _)| id == file_id) else {
                continue;
            };
            self.add_attachment(&ids[*item], name, media_type, data.to_vec())
                .await?;
            restored += 1;
        }
        // Files the vault's own copy of an item lacks (an Octa Pass export imported again).
        for file in &result.existing_files {
            let Some((_, data)) = files.iter().find(|(id, _)| *id == file.file_id) else {
                continue;
            };
            self.add_attachment(&file.item_id, &file.name, &file.media_type, data.to_vec())
                .await?;
            restored += 1;
        }
        summary.files = (restored > 0).then_some(restored);
        Ok(summary)
    }

    /// Every vault's live items, so importing a file again updates them instead of adding copies.
    /// The importer compares only the target vault's ([`ImportOptions::vault_id`]), except that an
    /// Octa Pass export finds its own items by id wherever they are.
    fn vault_items(&self) -> Result<Vec<import::ExistingItem>> {
        Ok(self
            .live_items()?
            .into_iter()
            .filter_map(|item| {
                Some(import::ExistingItem {
                    overview: serde_json::from_value(item.overview).ok()?,
                    details: item.details,
                    id: item.id,
                    vault_id: Some(item.vault_id),
                    updated_at: Some(item.updated_at),
                })
            })
            .collect())
    }

    fn existing_logins(&self) -> Result<Vec<import::ExistingLogin>> {
        Ok(self
            .live_items()?
            .iter()
            .filter(|item| item.is_login_like())
            .map(|item| import::ExistingLogin {
                id: item.id.clone(),
                title: item.title().to_owned(),
                urls: serde_json::from_value(
                    item.overview.get("urls").cloned().unwrap_or_default(),
                )
                .unwrap_or_default(),
                username: item.detail("username").map(str::to_owned),
                subtitle: item
                    .overview
                    .get("subtitle")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                has_totp: item.detail("totp").is_some(),
                totp: item.detail("totp").map(str::to_owned),
            })
            .collect())
    }
}

fn attachment_ids(details: &Value) -> Vec<String> {
    details
        .get("attachments")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|file| file.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}
