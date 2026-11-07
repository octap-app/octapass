//! Importing other apps' exports into the item model (plan 07). Parsing runs on the device; the
//! caller previews the result, then encrypts and uploads the items.
//!
//! Every importer returns `{ items, totpUpdates, warnings, skipped }`. Each field an app exports
//! goes where it means the same in the item model: dates, the app's own id, folders as tags,
//! password history. Fields with no such place are kept as custom fields (logins) or as
//! `Label: value` lines in the notes (other types), never dropped. A file that isn't in the
//! chosen format at all is an [`ImportError`].
//!
//! With [`ImportOptions::existing_items`], items already in the vault are updated instead of
//! copied (see `reimport`). Authenticator backups also skip codes the vault already has
//! ([`ExistingLogin::totp`]).

mod aegis;
mod andotp;
mod authenticator;
mod avira;
mod bitwarden;
mod bitwarden_crypto;
mod bitwarden_csv;
mod build;
mod chromium;
mod csv_table;
mod cxf;
mod dashlane;
mod enpass;
mod ente;
mod firefox;
mod generic;
mod kaspersky;
mod keepass;
mod keeper;
mod lastpass;
mod mcafee;
mod nordpass;
mod norton;
mod octapass;
mod onepassword_csv;
mod onepux;
mod otp;
mod protonpass;
mod raivo;
mod reimport;
mod roboform;
mod safari;
mod twofas;
mod zoho;

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use generic::{ColumnMapping, CsvPreview, preview_csv};
pub use octapass::{archive_error, import_octapass, octapass_items, octapass_items_for};
pub use otp::ExistingLogin;
pub use reimport::{ExistingItem, ItemUpdate};

use crate::error::Error;
use crate::item::{Item, ItemDetails};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportSource {
    /// Chrome, Edge, Brave, Opera, Vivaldi and Arc (one Chromium format).
    #[serde(rename = "chrome")]
    Chrome,
    #[serde(rename = "firefox")]
    Firefox,
    /// Safari and the Apple Passwords app.
    #[serde(rename = "safari")]
    Safari,
    /// Unencrypted or password-protected (`.json (Encrypted)`) JSON, also from Vaultwarden.
    #[serde(rename = "bitwarden-json")]
    BitwardenJson,
    #[serde(rename = "onepassword-1pux")]
    OnePassword1Pux,
    #[serde(rename = "onepassword-csv")]
    OnePasswordCsv,
    #[serde(rename = "lastpass-csv")]
    LastPassCsv,
    /// Any CSV with a header row, with an optional column mapping.
    #[serde(rename = "generic-csv")]
    GenericCsv,
    /// `otpauth://` and Google Authenticator `otpauth-migration://` links, one per line.
    #[serde(rename = "otpauth")]
    OtpAuth,
    /// Octa Pass's own export: plaintext JSON, or the encrypted file (with attachments).
    #[serde(rename = "octapass")]
    OctaPass,
    /// The FIDO Credential Exchange Format (JSON), from any app that exports it.
    #[serde(rename = "cxf")]
    Cxf,
    /// Proton Pass: the ZIP or JSON export, plain or PGP-encrypted with a passphrase, or CSV.
    #[serde(rename = "protonpass")]
    ProtonPass,
    /// Dashlane: the ZIP of CSVs, or JSON.
    #[serde(rename = "dashlane")]
    Dashlane,
    /// Keeper: CSV or JSON.
    #[serde(rename = "keeper")]
    Keeper,
    #[serde(rename = "nordpass")]
    NordPass,
    /// KeePass and KeePassXC: KDBX 3.1 or 4 (password and/or key file), XML or CSV.
    #[serde(rename = "keepass")]
    KeePass,
    #[serde(rename = "enpass")]
    Enpass,
    #[serde(rename = "roboform")]
    RoboForm,
    /// Aegis Authenticator JSON, plain or encrypted.
    #[serde(rename = "aegis")]
    Aegis,
    /// 2FAS Authenticator `.2fas` backups, plain or encrypted.
    #[serde(rename = "2fas")]
    TwoFas,
    /// andOTP JSON backups, plain or encrypted.
    #[serde(rename = "andotp")]
    AndOtp,
    /// Ente Auth's plaintext `otpauth://` list or password-encrypted JSON backup.
    #[serde(rename = "ente-auth")]
    EnteAuth,
    /// Bitwarden's CSV export (logins and secure notes only), also from organisations.
    #[serde(rename = "bitwarden-csv")]
    BitwardenCsv,
    /// Raivo OTP: the password-protected ZIP export, or the JSON inside it.
    #[serde(rename = "raivo")]
    Raivo,
    /// Zoho Vault: General CSV or Zoho Vault CSV.
    #[serde(rename = "zoho-vault")]
    ZohoVault,
    /// Avira Password Manager CSV.
    #[serde(rename = "avira")]
    Avira,
    /// Norton Password Manager CSV.
    #[serde(rename = "norton")]
    Norton,
    /// McAfee True Key CSV.
    #[serde(rename = "mcafee")]
    McAfee,
    /// Kaspersky Password Manager: the text export, or CSV.
    #[serde(rename = "kaspersky")]
    Kaspersky,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ImportOptions {
    /// The password of a password-protected export (Bitwarden, KeePass, Proton Pass, the Open
    /// Pass encrypted export, authenticator backups).
    pub password: Option<Zeroizing<String>>,
    /// A KeePass key file, as unpadded base64url in JSON.
    #[serde(deserialize_with = "base64_bytes")]
    pub key_file: Option<Zeroizing<Vec<u8>>>,
    /// Generic CSV: which column holds what. Without it, columns are recognised by name.
    pub columns: Option<ColumnMapping>,
    /// Authenticator imports: logins already in the vault that a one-time code can join.
    pub existing_logins: Vec<ExistingLogin>,
    /// The items already in the vault the import goes into. Imported items that match one (by
    /// the other app's id, or as a duplicate) become [`ImportResult::updates`] instead of new
    /// items. Authenticator backups match codes by the app's id only. Octa Pass exports match by
    /// their own item ids first, in every vault (see [`vault_id`](Self::vault_id)), and an item
    /// that changed in the vault after the export is kept.
    pub existing_items: Vec<ExistingItem>,
    /// The vault the import goes into, when `existing_items` holds the items of every vault (each
    /// with its [`ExistingItem::vault_id`]). Without it, every item counts as in that vault.
    pub vault_id: Option<String>,
    /// The time now (RFC 3339), for the history entry of a password that changed when the file
    /// doesn't say when.
    pub now: Option<String>,
}

/// Deserializes too, so a client can hand a result back to [`link_codes`] after the review.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ImportResult {
    pub items: Vec<Item>,
    /// One-time codes for logins already in the vault (from [`ImportOptions::existing_logins`]).
    pub totp_updates: Vec<TotpUpdate>,
    /// Short English sentences for the preview. They never contain secrets.
    pub warnings: Vec<String>,
    pub skipped: usize,
    /// Files that belong to `items` (the Octa Pass encrypted export). The caller reads them from
    /// the file with [`crate::export::ArchiveReader`] and attaches them after saving the items.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<ImportedFile>,
    /// Octa Pass exports: each item's id in the export, for [`relink`] once the items have new ids.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_ids: Vec<String>,
    /// Items already in the vault that the file changes (see [`ImportOptions::existing_items`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub updates: Vec<ItemUpdate>,
    /// Items already in the vault exactly as the file has them, or (Octa Pass exports) changed in
    /// the vault after the export was made, and so kept as they are.
    #[serde(skip_serializing_if = "is_zero")]
    pub unchanged: usize,
    /// Octa Pass encrypted exports: files of items already in the vault that the vault's item
    /// doesn't have. The caller attaches them to `item_id` as it does [`files`](Self::files).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub existing_files: Vec<ExistingFile>,
    /// Authenticator imports: every one-time code, as a new login in `items` or as a code for a
    /// login already in the vault in `totp_updates`. The import review lets the user choose
    /// another login for each, or none; [`link_codes`] applies the choices.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub codes: Vec<ImportedCode>,
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// A one-time code from an authenticator import, for the import review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedCode {
    /// Index into [`ImportResult::items`]: the code became a login of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<usize>,
    /// Index into [`ImportResult::totp_updates`]: the code joins a login already in the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<usize>,
    /// The name the authenticator app showed.
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

/// The user's choice for one [`ImportedCode`] (by its index): add it to the login `login_id`, or
/// keep it as a login of its own when `None`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeLink {
    pub code: usize,
    #[serde(default)]
    pub login_id: Option<String>,
}

/// Applies the import review's choices: a code moves from its own new login to an existing one,
/// or the other way round. Codes without a choice stay as the importer placed them. A login gets
/// one code at most; a second choice of the same login keeps that code as its own login, with a
/// warning. A new login's note is kept as a secure note when its code joins another login.
/// [`ImportResult::codes`] is empty afterwards.
pub fn link_codes(mut result: ImportResult, links: &[CodeLink]) -> ImportResult {
    let codes = std::mem::take(&mut result.codes);
    let mut drop_item = vec![false; result.items.len()];
    let mut drop_update = vec![false; result.totp_updates.len()];
    let mut new_updates = Vec::new();
    let mut new_items = Vec::new();
    let mut handled = Vec::new();
    // Logins taken by codes that stay where the importer put them.
    let choice = |index: usize| links.iter().find(|link| link.code == index);
    let mut taken: Vec<String> = codes
        .iter()
        .enumerate()
        .filter_map(|(index, code)| {
            let update = result.totp_updates.get(code.update?)?;
            match choice(index) {
                Some(link) if link.login_id.as_deref() != Some(update.item_id.as_str()) => None,
                _ => Some(update.item_id.clone()),
            }
        })
        .collect();
    for link in links {
        let Some(code) = codes.get(link.code) else {
            continue;
        };
        if handled.contains(&link.code) {
            continue;
        }
        handled.push(link.code);
        let update = code.update.and_then(|u| result.totp_updates.get(u));
        let item = code.item.and_then(|i| result.items.get(i));
        let totp = match (update, item.map(|item| &item.details)) {
            (Some(update), _) => update.totp.clone(),
            (None, Some(ItemDetails::Login(login))) => match &login.totp {
                Some(totp) => totp.clone(),
                None => continue,
            },
            _ => continue,
        };
        let current = update.map(|u| u.item_id.as_str());
        match &link.login_id {
            Some(login_id) if current == Some(login_id.as_str()) => {}
            None if current.is_none() => {}
            Some(login_id) if taken.contains(login_id) => {
                result.warnings.push(format!(
                    "\"{}\": another code from this import already goes to that login, so this one was kept as its own login.",
                    code.title
                ));
                if let Some(u) = code.update {
                    drop_update[u] = true;
                    new_items.extend(code_login(code, &totp, &mut result.warnings));
                }
            }
            Some(login_id) => {
                taken.push(login_id.clone());
                new_updates.push(TotpUpdate {
                    item_id: login_id.clone(),
                    totp,
                });
                if let Some(u) = code.update {
                    drop_update[u] = true;
                }
                if let Some(i) = code.item {
                    drop_item[i] = true;
                    if let Some(note) = item.and_then(note_of) {
                        new_items.push(note);
                    }
                }
            }
            None => {
                if let Some(u) = code.update {
                    drop_update[u] = true;
                }
                new_items.extend(code_login(code, &totp, &mut result.warnings));
            }
        }
    }

    // Item indices change: move the files that belong to items along with them.
    let mut new_index = Vec::with_capacity(drop_item.len());
    let mut next = 0;
    for &dropped in &drop_item {
        new_index.push((!dropped).then_some(next));
        next += usize::from(!dropped);
    }
    result
        .files
        .retain_mut(|file| match new_index.get(file.item).copied().flatten() {
            Some(index) => {
                file.item = index;
                true
            }
            None => false,
        });
    if !result.source_ids.is_empty() {
        let mut keep = drop_item.iter();
        result
            .source_ids
            .retain(|_| !keep.next().copied().unwrap_or(false));
    }
    let mut keep = drop_item.iter();
    result
        .items
        .retain(|_| !keep.next().copied().unwrap_or(false));
    result.items.extend(new_items);
    let mut keep = drop_update.iter();
    result
        .totp_updates
        .retain(|_| !keep.next().copied().unwrap_or(false));
    result.totp_updates.extend(new_updates);
    result
}

/// A login of its own for a code that was going to join an existing login.
fn code_login(code: &ImportedCode, totp: &str, warnings: &mut Vec<String>) -> Option<Item> {
    let mut out = build::Collector::default();
    let item = build::LoginFields {
        title: Some(code.title.clone()),
        username: code.account.clone(),
        totp: Some(totp.to_string()),
        ..build::LoginFields::default()
    }
    .build(&mut out);
    warnings.extend(out.finish().warnings);
    item
}

/// The note of a new login whose code joins another login, as a secure note of its own.
fn note_of(item: &Item) -> Option<Item> {
    let ItemDetails::Login(login) = &item.details else {
        return None;
    };
    let notes = build::clean(login.notes.as_deref())?;
    Some(build::note(
        Some(format!("{} (note)", item.overview.title)),
        item.overview.tags.clone().unwrap_or_default(),
        false,
        Some(notes),
    ))
}

/// Points recovery info linked to another imported item (an Identity) at that item's new id.
/// `source_ids` are [`ImportResult::source_ids`]; `new_ids` are the ids the items were saved with,
/// in the same order. Links to items that weren't imported are left as they are.
pub fn relink(items: &mut [Item], source_ids: &[String], new_ids: &[String]) {
    let new_id = |old: &str| {
        source_ids
            .iter()
            .position(|id| id == old)
            .and_then(|at| new_ids.get(at))
    };
    for item in items {
        let ItemDetails::Login(details) = &mut item.details else {
            continue;
        };
        let Some(recovery) = &mut details.recovery else {
            continue;
        };
        for source in [&mut recovery.email_source, &mut recovery.phone_source]
            .into_iter()
            .flatten()
        {
            if let Some(id) = source.item_id.as_deref().and_then(new_id) {
                source.item_id = Some(id.clone());
            }
        }
    }
}

/// [`relink`] for everything an import saves: its new items, and the vault items it updates (an
/// Octa Pass export imported again can point those at items it brings back). `new_ids` are the new
/// items' ids, in the order of [`ImportResult::items`].
pub fn relink_all(result: &mut ImportResult, new_ids: &[String]) {
    relink(&mut result.items, &result.source_ids, new_ids);
    for update in &mut result.updates {
        relink(
            std::slice::from_mut(&mut update.item),
            &result.source_ids,
            new_ids,
        );
    }
}

/// A file to attach to an imported item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedFile {
    /// Index into [`ImportResult::items`].
    pub item: usize,
    /// The file's name inside the export (its old attachment id).
    pub file_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub media_type: String,
    pub size: u64,
}

/// A file to attach to an item already in the vault (an Octa Pass export imported again).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExistingFile {
    pub item_id: String,
    /// The file's name inside the export (its old attachment id).
    pub file_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub media_type: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpUpdate {
    pub item_id: String,
    /// The `otpauth://` URI for the item's `totp` field.
    pub totp: String,
}

/// Why a file can't be imported: a stable [`Error`] code plus a fixed sentence for the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportError {
    pub code: Error,
    pub detail: &'static str,
}

impl ImportError {
    pub(crate) fn new(code: Error, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail)
    }
}

impl std::error::Error for ImportError {}

/// Parses an export file.
pub fn import_file(
    source: ImportSource,
    bytes: &[u8],
    options: &ImportOptions,
) -> Result<ImportResult, ImportError> {
    let mut result = parse(source, bytes, options)?;
    let name = source.name();
    stamp_source(&mut result, name);
    // One entry can list a site more than once (`https://a.example` and `https://a.example/`).
    for item in &mut result.items {
        crate::matching::websites::dedupe_overview(&mut item.overview);
    }
    let now = options.now.as_deref().unwrap_or("1970-01-01T00:00:00Z");
    if source.is_authenticator() {
        let known: Vec<&str> = options
            .existing_logins
            .iter()
            .filter_map(|login| login.totp.as_deref())
            .collect();
        reimport::reconcile_codes(&mut result, reimport::in_target(options), &known, name, now);
    } else if source != ImportSource::OctaPass && !options.existing_items.is_empty() {
        // Octa Pass exports were matched while they were read (`octapass::octapass_items_for`).
        reimport::reconcile(&mut result, reimport::in_target(options), name, now);
    }
    Ok(result)
}

/// Names the app in `importedFrom` of items that have an id from it but no app yet.
fn stamp_source(result: &mut ImportResult, name: &str) {
    for item in &mut result.items {
        if let Some(from) = &mut item.overview.imported_from
            && from.source.is_empty()
        {
            from.source = name.to_owned();
        }
    }
}

impl ImportSource {
    /// Authenticator apps, whose one-time codes go through the import review ([`link_codes`]).
    pub fn is_authenticator(self) -> bool {
        matches!(
            self,
            ImportSource::OtpAuth
                | ImportSource::Aegis
                | ImportSource::TwoFas
                | ImportSource::AndOtp
                | ImportSource::EnteAuth
                | ImportSource::Raivo
        )
    }

    /// The name in JSON (`firefox`, `bitwarden-json`, …), also kept in `importedFrom.source`.
    pub fn name(self) -> &'static str {
        match self {
            ImportSource::Chrome => "chrome",
            ImportSource::Firefox => "firefox",
            ImportSource::Safari => "safari",
            ImportSource::BitwardenJson => "bitwarden-json",
            ImportSource::BitwardenCsv => "bitwarden-csv",
            ImportSource::OnePassword1Pux => "onepassword-1pux",
            ImportSource::OnePasswordCsv => "onepassword-csv",
            ImportSource::LastPassCsv => "lastpass-csv",
            ImportSource::GenericCsv => "generic-csv",
            ImportSource::OtpAuth => "otpauth",
            ImportSource::OctaPass => "octapass",
            ImportSource::Cxf => "cxf",
            ImportSource::ProtonPass => "protonpass",
            ImportSource::Dashlane => "dashlane",
            ImportSource::Keeper => "keeper",
            ImportSource::NordPass => "nordpass",
            ImportSource::KeePass => "keepass",
            ImportSource::Enpass => "enpass",
            ImportSource::RoboForm => "roboform",
            ImportSource::Aegis => "aegis",
            ImportSource::TwoFas => "2fas",
            ImportSource::AndOtp => "andotp",
            ImportSource::EnteAuth => "ente-auth",
            ImportSource::Raivo => "raivo",
            ImportSource::ZohoVault => "zoho-vault",
            ImportSource::Avira => "avira",
            ImportSource::Norton => "norton",
            ImportSource::McAfee => "mcafee",
            ImportSource::Kaspersky => "kaspersky",
        }
    }
}

fn parse(
    source: ImportSource,
    bytes: &[u8],
    options: &ImportOptions,
) -> Result<ImportResult, ImportError> {
    let text = || decode_text(bytes);
    match source {
        ImportSource::Chrome => chromium::parse(&text()?),
        ImportSource::Firefox => firefox::parse(&text()?),
        ImportSource::Safari => safari::parse(&text()?),
        ImportSource::BitwardenJson => {
            bitwarden::parse(&text()?, options.password.as_ref().map(|p| p.as_str()))
        }
        ImportSource::BitwardenCsv => bitwarden_csv::parse(&text()?),
        ImportSource::OnePassword1Pux => onepux::parse(bytes),
        ImportSource::OnePasswordCsv => onepassword_csv::parse(&text()?),
        ImportSource::LastPassCsv => lastpass::parse(&text()?),
        ImportSource::GenericCsv => generic::parse(&text()?, options.columns.as_ref()),
        ImportSource::OtpAuth => Ok(otp::parse(&text()?, &options.existing_logins)),
        ImportSource::OctaPass => octapass::parse(bytes, options),
        ImportSource::Cxf => cxf::parse(&text()?),
        ImportSource::ProtonPass => protonpass::parse(bytes, options),
        ImportSource::Dashlane => dashlane::parse(bytes, options),
        ImportSource::Keeper => keeper::parse(bytes, options),
        ImportSource::NordPass => nordpass::parse(bytes, options),
        ImportSource::KeePass => keepass::parse(bytes, options),
        ImportSource::Enpass => enpass::parse(bytes, options),
        ImportSource::RoboForm => roboform::parse(bytes, options),
        ImportSource::Aegis => aegis::parse(bytes, options),
        ImportSource::TwoFas => twofas::parse(bytes, options),
        ImportSource::AndOtp => andotp::parse(bytes, options),
        ImportSource::EnteAuth => ente::parse(bytes, options),
        ImportSource::Raivo => raivo::parse(bytes, options),
        ImportSource::ZohoVault => zoho::parse(bytes, options),
        ImportSource::Avira => avira::parse(bytes, options),
        ImportSource::Norton => norton::parse(bytes, options),
        ImportSource::McAfee => mcafee::parse(bytes, options),
        ImportSource::Kaspersky => kaspersky::parse(bytes, options),
    }
}

fn base64_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Zeroizing<Vec<u8>>>, D::Error> {
    let text: Option<Zeroizing<String>> = Option::deserialize(deserializer)?;
    text.map(|text| {
        crate::encoding::b64_decode(&text)
            .map(Zeroizing::new)
            .map_err(serde::de::Error::custom)
    })
    .transpose()
}

/// UTF-8, with or without a byte order mark, or UTF-16 with one (spreadsheet apps on Windows).
/// Other encodings are refused rather than guessed, so passwords are never silently changed.
pub(super) fn decode_text(bytes: &[u8]) -> Result<Zeroizing<String>, ImportError> {
    let utf16 = |bytes: &[u8], read: fn([u8; 2]) -> u16| {
        let (pairs, rest) = bytes.as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().map(|&pair| read(pair)).collect();
        rest.is_empty()
            .then(|| String::from_utf16(&units).ok())
            .flatten()
    };
    let text = if let Some(rest) = bytes.strip_prefix(b"\xef\xbb\xbf") {
        String::from_utf8(rest.to_vec()).ok()
    } else if let Some(rest) = bytes.strip_prefix(b"\xff\xfe") {
        utf16(rest, u16::from_le_bytes)
    } else if let Some(rest) = bytes.strip_prefix(b"\xfe\xff") {
        utf16(rest, u16::from_be_bytes)
    } else {
        String::from_utf8(bytes.to_vec()).ok()
    };
    text.map(Zeroizing::new).ok_or(ImportError::new(
        Error::InvalidImportFile,
        "The file isn't UTF-8 text. Export it again, or save it as UTF-8.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_encodings() {
        assert_eq!(decode_text(b"\xef\xbb\xbfname").unwrap().as_str(), "name");
        assert_eq!(
            decode_text(b"\xff\xfen\x00\xe9\x00").unwrap().as_str(),
            "né"
        );
        assert_eq!(
            decode_text(b"\xfe\xff\x00n\x00\xe9").unwrap().as_str(),
            "né"
        );
        assert_eq!(
            decode_text(b"caf\xe9").unwrap_err().code,
            Error::InvalidImportFile
        );
        assert!(decode_text(b"\xff\xfen").is_err());
    }

    #[test]
    fn sources_have_stable_names() {
        let names: Vec<String> = [
            ImportSource::Chrome,
            ImportSource::Firefox,
            ImportSource::Safari,
            ImportSource::BitwardenJson,
            ImportSource::OnePassword1Pux,
            ImportSource::OnePasswordCsv,
            ImportSource::LastPassCsv,
            ImportSource::GenericCsv,
            ImportSource::OtpAuth,
            ImportSource::OctaPass,
            ImportSource::Cxf,
            ImportSource::ProtonPass,
            ImportSource::Dashlane,
            ImportSource::Keeper,
            ImportSource::NordPass,
            ImportSource::KeePass,
            ImportSource::Enpass,
            ImportSource::RoboForm,
            ImportSource::Aegis,
            ImportSource::TwoFas,
            ImportSource::AndOtp,
            ImportSource::EnteAuth,
            ImportSource::BitwardenCsv,
            ImportSource::Raivo,
            ImportSource::ZohoVault,
            ImportSource::Avira,
            ImportSource::Norton,
            ImportSource::McAfee,
            ImportSource::Kaspersky,
        ]
        .iter()
        .map(|s| {
            let name = serde_json::to_value(s)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(name, s.name());
            name
        })
        .collect();
        assert_eq!(
            names,
            [
                "chrome",
                "firefox",
                "safari",
                "bitwarden-json",
                "onepassword-1pux",
                "onepassword-csv",
                "lastpass-csv",
                "generic-csv",
                "otpauth",
                "octapass",
                "cxf",
                "protonpass",
                "dashlane",
                "keeper",
                "nordpass",
                "keepass",
                "enpass",
                "roboform",
                "aegis",
                "2fas",
                "andotp",
                "ente-auth",
                "bitwarden-csv",
                "raivo",
                "zoho-vault",
                "avira",
                "norton",
                "mcafee",
                "kaspersky"
            ]
        );
    }
}
