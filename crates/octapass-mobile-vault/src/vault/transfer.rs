//! Exports and imports that need the core (`octapass_core::export` and `import`): the encrypted
//! export with every attachment, CXF, every importer, and items another password manager on the
//! phone hands over (Android's credential transfer). The web view makes the Octa Pass JSON and
//! CSV exports from [`Vault::live_items`] itself.
//!
//! Items saved here go into the offline outbox and get their ids from it, so links between
//! imported items (recovery info pointing at an Identity) are fixed once they're saved.

use std::collections::BTreeMap;

use octapass_api::{ExportFormat, VaultExportedRequest, VaultRole, VaultType};
use octapass_core::export::{
    self, ArchiveFiles, ArchiveWriter, ExportDocument, ExportItem, ExportVault,
};
use octapass_core::import::{
    self, CodeLink, ImportOptions, ImportResult, ImportSource, ImportedFile,
};
use octapass_core::kdf::KdfParams;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::attachments::random_name;
use super::{Event, Vault};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::{Item, ItemDraft, now};
use crate::native::ReceivedCredentials;

/// The exports made here; JSON and CSV come from the items directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileExport {
    Cxf,
    Encrypted,
}

/// Items another app handed over, kept until the user imports them or backs out. Locking drops
/// them.
pub(crate) struct Received {
    json: Zeroizing<String>,
}

/// What another app handed over, for the user to look at before anything is saved. No secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedPreview {
    /// The app's name.
    pub from: String,
    /// New items by type (`login`, `card`, …).
    pub items: BTreeMap<String, usize>,
    /// Passkeys among the new items.
    pub passkeys: usize,
    /// One-time codes that join logins already in the vault.
    pub codes: usize,
    /// Items already in the vault that the transfer changes, or that it has exactly as they are.
    pub updated: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
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

/// A parsed import kept in memory until its review is finished or cancelled, or the vault locks.
pub(crate) struct PendingImport {
    result: ImportResult,
    files: ArchiveFiles,
    vault_id: String,
}

fn core_error(error: octapass_core::Error) -> VaultError {
    VaultError::new(ErrorCode::Unexpected, error.code())
}

fn import_error(error: import::ImportError) -> VaultError {
    let code = match error.code {
        octapass_core::Error::ImportPasswordRequired => ErrorCode::ImportPasswordRequired,
        octapass_core::Error::WrongImportPassword => ErrorCode::WrongImportPassword,
        _ => ErrorCode::InvalidImportFile,
    };
    VaultError::new(code, error.detail)
}

/// Unix seconds of an RFC 3339 time, for the CXF header.
fn unix_seconds(time: &str) -> u64 {
    export::cxf::unix_seconds(time).unwrap_or(0)
}

impl Vault {
    fn document(&self, items: &[Item], exported_at: &str) -> Result<ExportDocument> {
        let vaults = self
            .list_vaults()?
            .into_iter()
            .map(|vault| ExportVault {
                vault_type: serde_json::to_value(vault.vault_type)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                id: vault.id,
                name: vault.name,
                extra: Map::new(),
            })
            .collect();
        let items = items
            .iter()
            .map(|item| ExportItem {
                id: item.id.clone(),
                vault_id: item.vault_id.clone(),
                created_at: item.created_at.clone(),
                updated_at: item.updated_at.clone(),
                overview: item.overview.clone(),
                details: item.details.clone(),
            })
            .collect();
        Ok(ExportDocument::new(exported_at.to_owned(), vaults, items))
    }

    /// Adds "vault exported" to the account's security log once the user has the file: the format,
    /// and whether the attachments went with it (only the encrypted export holds them). Nothing
    /// from the vault. Callers carry on when this fails, as an export works offline too.
    pub fn record_export(&self, format: ExportFormat) -> Result<()> {
        let access = self.access()?;
        let url = format!("{}v1/security-log/exports", access.server_url());
        let body = VaultExportedRequest {
            format,
            attachments: format == ExportFormat::Encrypted,
        };
        access.authorized(|token| self.http.post_json(url.clone(), token, &body))
    }

    /// The CXF export, or the encrypted export with every attachment (decrypted one at a time;
    /// files still waiting to upload are read from this phone). `kdf` is the encrypted export's
    /// Argon2id settings ([`export::EXPORT_KDF`] outside tests).
    pub fn export_file(
        &self,
        format: FileExport,
        password: Option<&str>,
        kdf: KdfParams,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut items = self.live_items()?;
        // Importing the dashboard's settings would turn email breach alerts on for another account.
        items.retain(|item| !crate::health::is_health_settings(item));
        items.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let exported_at = now();
        let document = self.document(&items, &exported_at)?;
        match format {
            FileExport::Cxf => {
                let account = self.unlocked()?.account;
                let host = account
                    .server_url
                    .split("://")
                    .nth(1)
                    .and_then(|rest| rest.split(['/', ':']).next())
                    .unwrap_or_default()
                    .to_owned();
                let cxf = export::cxf::export(
                    &document,
                    &export::cxf::CxfAccount {
                        id: account.email.clone(),
                        username: String::new(),
                        email: account.email.clone(),
                    },
                    &host,
                    unix_seconds(&exported_at),
                );
                Ok(Zeroizing::new(cxf.json.into_bytes()))
            }
            FileExport::Encrypted => {
                let password = password.filter(|p| !p.is_empty()).ok_or_else(|| {
                    VaultError::new(
                        ErrorCode::PasswordRequired,
                        "an encrypted export needs a password",
                    )
                })?;
                let mut writer =
                    ArchiveWriter::new(password, kdf, &mut OsRng).map_err(core_error)?;
                let mut out = Zeroizing::new(
                    writer
                        .add_items(document.to_json().as_bytes())
                        .map_err(core_error)?,
                );
                for item in &items {
                    for id in attachment_ids(&item.details) {
                        let file = Zeroizing::new(self.get_attachment(&item.id, &id)?);
                        out.extend(writer.add_file(&id, &file).map_err(core_error)?);
                    }
                }
                out.extend(writer.finish().map_err(core_error)?);
                Ok(out)
            }
        }
    }

    /// Imports a file into `vault_id`: items, one-time codes for logins already there, and an
    /// Octa Pass encrypted export's attachments. Works offline: everything goes through the outbox.
    pub fn import_file(
        &self,
        source: ImportSource,
        bytes: &[u8],
        options: ImportOptions,
        vault_id: &str,
    ) -> Result<ImportSummary> {
        self.import_target(vault_id)?;
        let (result, files) = self.parse_import(source, bytes, options, vault_id)?;
        self.save_import(result, &files, vault_id)
    }

    /// Parses a file for the import review (authenticator imports, scanned QR codes), where the
    /// user links each one-time code to a login. Nothing is saved until [`Vault::finish_import`];
    /// the parsed file stays in memory until then, [`Vault::cancel_import`], or the vault locks.
    pub fn review_import(
        &self,
        source: ImportSource,
        bytes: &[u8],
        options: ImportOptions,
        vault_id: &str,
    ) -> Result<ImportReview> {
        self.import_target(vault_id)?;
        let (result, files) = self.parse_import(source, bytes, options, vault_id)?;
        let review = ImportReview::new(random_name(), &result);
        let mut state = self.state();
        // Locked meanwhile: nothing to keep it for.
        if state.unlocked.is_none() {
            return Err(ErrorCode::Locked.into());
        }
        state.imports.insert(
            review.id.clone(),
            PendingImport {
                result,
                files,
                vault_id: vault_id.to_owned(),
            },
        );
        Ok(review)
    }

    /// Saves a reviewed import with the user's choices. Codes without a link stay as the review
    /// showed them. `importReviewExpired` when the review was finished, cancelled or forgotten.
    pub fn finish_import(&self, review_id: &str, links: &[CodeLink]) -> Result<ImportSummary> {
        self.unlocked()?;
        let pending = self
            .state()
            .imports
            .remove(review_id)
            .ok_or(ErrorCode::ImportReviewExpired)?;
        self.import_target(&pending.vault_id)?;
        let result = import::link_codes(pending.result, links);
        self.save_import(result, &pending.files, &pending.vault_id)
    }

    /// Drops a review without saving anything. A review that's already gone is fine.
    pub fn cancel_import(&self, review_id: &str) {
        self.state().imports.remove(review_id);
    }

    /// Imports go into a vault the user can write to.
    fn import_target(&self, vault_id: &str) -> Result<()> {
        let target = self
            .list_vaults()?
            .into_iter()
            .find(|vault| vault.id == vault_id)
            .ok_or(ErrorCode::NotFound)?;
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
        options.now = Some(now());
        if source == ImportSource::OctaPass {
            import::import_octapass(bytes, &options).map_err(import_error)
        } else {
            Ok((
                import::import_file(source, bytes, &options).map_err(import_error)?,
                Vec::new(),
            ))
        }
    }

    /// Saves what an importer found: new items (relinked to each other once they have ids), one-time
    /// codes for logins already here, and the encrypted export's files.
    fn save_import(
        &self,
        result: ImportResult,
        files: &ArchiveFiles,
        vault_id: &str,
    ) -> Result<ImportSummary> {
        let unlocked = self.unlocked()?;
        let draft = |item: &octapass_core::item::Item, id: Option<String>| {
            let value = serde_json::to_value(item).expect("items serialize");
            ItemDraft {
                id,
                vault_id: vault_id.to_owned(),
                revision: None,
                overview: value["overview"].clone(),
                details: value["details"].clone(),
            }
        };
        let mut ids = Vec::with_capacity(result.items.len());
        for item in &result.items {
            ids.push(self.save_draft(&unlocked, draft(item, None))?);
        }
        // Recovery info linked to an imported Identity points at its new id.
        let mut linked = result.items.clone();
        import::relink(&mut linked, &result.source_ids, &ids);
        for ((before, after), id) in result.items.iter().zip(&linked).zip(&ids) {
            if before != after {
                self.save_draft(&unlocked, draft(after, Some(id.clone())))?;
            }
        }
        let mut summary = ImportSummary {
            imported: ids.len(),
            skipped: result.skipped,
            warnings: result.warnings.clone(),
            unchanged: (result.unchanged > 0).then_some(result.unchanged),
            ..ImportSummary::default()
        };
        for update in &result.updates {
            let item = self.stored_item(&unlocked, &update.item_id)?;
            // An Octa Pass export imported again can point it at an item it brought back.
            let mut new_version = update.item.clone();
            import::relink(
                std::slice::from_mut(&mut new_version),
                &result.source_ids,
                &ids,
            );
            self.save_draft(
                &unlocked,
                ItemDraft {
                    revision: Some(item.revision),
                    vault_id: item.vault_id.clone(),
                    ..draft(&new_version, Some(item.id.clone()))
                },
            )?;
            *summary.updated.get_or_insert(0) += 1;
        }
        for update in &result.totp_updates {
            let item = self.stored_item(&unlocked, &update.item_id)?;
            let mut details = item.details.clone();
            details["totp"] = json!(update.totp);
            self.save_draft(
                &unlocked,
                ItemDraft {
                    id: Some(item.id.clone()),
                    vault_id: item.vault_id.clone(),
                    revision: Some(item.revision),
                    overview: item.overview.clone(),
                    details,
                },
            )?;
            summary.imported += 1;
        }
        self.upload_quietly(&unlocked);
        let mut restored = 0;
        for ImportedFile {
            item,
            file_id,
            name,
            media_type,
            ..
        } in &result.files
        {
            let Some((_, data)) = files.iter().find(|(id, _)| id == file_id) else {
                continue;
            };
            self.add_attachment(&ids[*item], name, media_type, data)?;
            restored += 1;
        }
        // Files the vault's own copy of an item lacks (an Octa Pass export imported again).
        for file in &result.existing_files {
            let Some((_, data)) = files.iter().find(|(id, _)| *id == file.file_id) else {
                continue;
            };
            self.add_attachment(&file.item_id, &file.name, &file.media_type, data)?;
            restored += 1;
        }
        summary.files = (restored > 0).then_some(restored);
        (self.listener)(Event::ItemsChanged);
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

    /// Asks another password manager on the phone for its items (Android's credential transfer,
    /// through [`crate::Native::receive_credentials`]) and keeps them, unsaved, for
    /// [`Self::import_received`]. `None` when the user backed out.
    pub fn receive_from_app(&self) -> Result<Option<ReceivedPreview>> {
        self.unlocked()?;
        let Some(received) = self.native.receive_credentials()? else {
            return Ok(None);
        };
        self.preview_received(received).map(Some)
    }

    /// Keeps CXF another app handed over, unsaved, for [`Self::import_received`], and says what
    /// it holds. The native apps get it from the system themselves (Android's credential
    /// transfer, iOS's Credential Exchange) and pass it here.
    pub fn preview_received(&self, received: ReceivedCredentials) -> Result<ReceivedPreview> {
        self.unlocked()?;
        // As `import_received` will save them: items already in the Personal vault are updates.
        let personal = self
            .list_vaults()?
            .into_iter()
            .find(|vault| vault.vault_type == VaultType::Personal);
        let (existing_items, vault_id) = match personal {
            Some(vault) => (self.vault_items()?, Some(vault.id)),
            None => (Vec::new(), None),
        };
        let options = ImportOptions {
            existing_logins: self.existing_logins()?,
            existing_items,
            vault_id,
            now: Some(now()),
            ..ImportOptions::default()
        };
        let result = import::import_file(ImportSource::Cxf, received.json.as_bytes(), &options)
            .map_err(import_error)?;
        let mut preview = ReceivedPreview {
            from: received.from,
            codes: result.totp_updates.len(),
            updated: result.updates.len(),
            unchanged: result.unchanged,
            skipped: result.skipped,
            warnings: result.warnings.clone(),
            ..ReceivedPreview::default()
        };
        for item in &result.items {
            let value = serde_json::to_value(item).expect("items serialize");
            let kind = value["overview"]["type"].as_str().unwrap_or("login");
            *preview.items.entry(kind.to_owned()).or_default() += 1;
            preview.passkeys += value["details"]["passkeys"].as_array().map_or(0, Vec::len);
        }
        self.state().received = Some(Received {
            json: received.json,
        });
        Ok(preview)
    }

    /// Saves what [`Self::receive_from_app`] got into the Personal vault, and forgets it.
    pub fn import_received(&self) -> Result<ImportSummary> {
        let received = self
            .state()
            .received
            .take()
            .ok_or_else(|| VaultError::new(ErrorCode::NotFound, "nothing was received"))?;
        let personal = self
            .list_vaults()?
            .into_iter()
            .find(|vault| vault.vault_type == VaultType::Personal)
            .ok_or_else(|| VaultError::new(ErrorCode::NotFound, "no personal vault"))?;
        self.import_file(
            ImportSource::Cxf,
            received.json.as_bytes(),
            ImportOptions::default(),
            &personal.id,
        )
    }

    /// Forgets what [`Self::receive_from_app`] got, without saving it.
    pub fn discard_received(&self) {
        self.state().received = None;
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
