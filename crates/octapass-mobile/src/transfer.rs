//! Exports and imports (plan 07). The four exports are the web vault's: the Octa Pass JSON and
//! the CSV (`packages/vault-client/src/tools/export.ts`), CXF, and the encrypted export with
//! every attachment. Files are written to the app's private storage for the share sheet, and
//! read from where the app's picker copied them.

use octapass_core::export::{self, ArchiveWriter, ExportDocument, ExportItem, ExportVault};
use octapass_core::import::{ImportOptions, ImportSource as CoreSource};
use octapass_core::kdf::KdfParams;
use octapass_mobile_vault::model::Item as StoredItem;
use rand_core::OsRng;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result, VaultError};
use crate::sharing::{Vault, VaultType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ExportFormat {
    /// Octa Pass JSON: every field, attachments listed but not included. Plaintext.
    Json,
    /// One row per item, for spreadsheets. Plaintext.
    Csv,
    /// The FIDO Credential Exchange Format. Plaintext.
    Cxf,
    /// Everything, attachments included, under a password chosen for the export.
    Encrypted,
}

impl From<ExportFormat> for octapass_api::ExportFormat {
    fn from(format: ExportFormat) -> Self {
        match format {
            ExportFormat::Json => Self::Json,
            ExportFormat::Csv => Self::Csv,
            ExportFormat::Cxf => Self::Cxf,
            ExportFormat::Encrypted => Self::Encrypted,
        }
    }
}

impl From<octapass_api::ExportFormat> for ExportFormat {
    fn from(format: octapass_api::ExportFormat) -> Self {
        match format {
            octapass_api::ExportFormat::Json => Self::Json,
            octapass_api::ExportFormat::Csv => Self::Csv,
            octapass_api::ExportFormat::Cxf => Self::Cxf,
            octapass_api::ExportFormat::Encrypted => Self::Encrypted,
        }
    }
}

/// Every source the core imports from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ImportSource {
    Chrome,
    Firefox,
    Safari,
    BitwardenJson,
    OnePassword1Pux,
    OnePasswordCsv,
    LastPassCsv,
    GenericCsv,
    Otpauth,
    OctaPass,
    Cxf,
    ProtonPass,
    Dashlane,
    Keeper,
    NordPass,
    KeePass,
    Enpass,
    RoboForm,
    Aegis,
    TwoFas,
    AndOtp,
    EnteAuth,
    BitwardenCsv,
    Raivo,
    ZohoVault,
    Avira,
    Norton,
    McAfee,
    Kaspersky,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportSummary {
    pub imported: u32,
    pub skipped: u32,
    pub warnings: Vec<String>,
    /// Attached files restored (Octa Pass encrypted exports).
    pub files: u32,
    /// Items already in the vault that the file changed (importing a file again updates them).
    pub updated: u32,
    /// Items already in the vault exactly as the file has them.
    pub unchanged: u32,
}

impl ImportSource {
    /// The web vault's name for it (`bitwarden-json`).
    fn name(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::BitwardenJson => "bitwarden-json",
            Self::BitwardenCsv => "bitwarden-csv",
            Self::OnePassword1Pux => "onepassword-1pux",
            Self::OnePasswordCsv => "onepassword-csv",
            Self::LastPassCsv => "lastpass-csv",
            Self::GenericCsv => "generic-csv",
            Self::Otpauth => "otpauth",
            Self::OctaPass => "octapass",
            Self::Cxf => "cxf",
            Self::ProtonPass => "protonpass",
            Self::Dashlane => "dashlane",
            Self::Keeper => "keeper",
            Self::NordPass => "nordpass",
            Self::KeePass => "keepass",
            Self::Enpass => "enpass",
            Self::RoboForm => "roboform",
            Self::Aegis => "aegis",
            Self::TwoFas => "2fas",
            Self::AndOtp => "andotp",
            Self::EnteAuth => "ente-auth",
            Self::Raivo => "raivo",
            Self::ZohoVault => "zoho-vault",
            Self::Avira => "avira",
            Self::Norton => "norton",
            Self::McAfee => "mcafee",
            Self::Kaspersky => "kaspersky",
        }
    }

    pub(crate) fn core(self) -> CoreSource {
        serde_json::from_value(Value::String(self.name().into()))
            .expect("every source is the core's")
    }
}

pub(crate) fn import_options(password: Option<String>, key_file: Option<Vec<u8>>) -> ImportOptions {
    ImportOptions {
        password: password.filter(|p| !p.is_empty()).map(Zeroizing::new),
        key_file: key_file.map(Zeroizing::new),
        ..ImportOptions::default()
    }
}

/// New items of one type in what another app handed over.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReceivedCount {
    /// `login`, `card`, …
    pub item_type: String,
    pub count: u32,
}

/// What another password manager handed over (Android's credential transfer, iOS's Credential
/// Exchange), for the user to look at before anything is saved. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReceivedPreview {
    /// The app's name.
    pub from: String,
    /// New items by type, in type name order.
    pub items: Vec<ReceivedCount>,
    /// Passkeys among the new items.
    pub passkeys: u32,
    /// One-time codes that join logins already in the vault.
    pub codes: u32,
    /// Items already in the Personal vault that this changes.
    pub updated: u32,
    /// Items already there exactly as sent.
    pub unchanged: u32,
    pub skipped: u32,
    pub warnings: Vec<String>,
}

impl From<octapass_mobile_vault::vault::ReceivedPreview> for ReceivedPreview {
    fn from(preview: octapass_mobile_vault::vault::ReceivedPreview) -> Self {
        Self {
            from: preview.from,
            items: preview
                .items
                .into_iter()
                .map(|(item_type, count)| ReceivedCount {
                    item_type,
                    count: count as u32,
                })
                .collect(),
            passkeys: preview.passkeys as u32,
            codes: preview.codes as u32,
            updated: preview.updated as u32,
            unchanged: preview.unchanged as u32,
            skipped: preview.skipped as u32,
            warnings: preview.warnings,
        }
    }
}

impl From<octapass_mobile_vault::vault::ImportSummary> for ImportSummary {
    fn from(summary: octapass_mobile_vault::vault::ImportSummary) -> Self {
        Self {
            imported: summary.imported as u32,
            skipped: summary.skipped as u32,
            warnings: summary.warnings,
            files: summary.files.unwrap_or(0) as u32,
            updated: summary.updated.unwrap_or(0) as u32,
            unchanged: summary.unchanged.unwrap_or(0) as u32,
        }
    }
}

/// `octapass-export-2026-10-24.json`, as the web vault names it.
pub(crate) fn export_file_name(format: ExportFormat, today: &str) -> String {
    let extension = match format {
        ExportFormat::Json => "json",
        ExportFormat::Csv => "csv",
        ExportFormat::Cxf => "cxf.json",
        ExportFormat::Encrypted => "octapass",
    };
    format!("octapass-export-{today}.{extension}")
}

fn type_name(vault_type: VaultType) -> &'static str {
    match vault_type {
        VaultType::Personal => "personal",
        VaultType::Shared => "shared",
        VaultType::Family => "family",
    }
}

/// The document every format starts from. `items` are live, listable items, oldest first.
pub(crate) fn document(
    vaults: &[Vault],
    items: &[StoredItem],
    exported_at: &str,
) -> ExportDocument {
    ExportDocument::new(
        exported_at.to_owned(),
        vaults
            .iter()
            .map(|vault| ExportVault {
                id: vault.id.clone(),
                name: vault.name.clone(),
                vault_type: type_name(vault.vault_type).into(),
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

/// The server's host, which CXF names as the exporter.
fn host(server_url: &str) -> String {
    url::Url::parse(server_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default()
}

pub(crate) fn cxf(document: &ExportDocument, email: &str, server_url: &str) -> Vec<u8> {
    let exported = export::cxf::export(
        document,
        &export::cxf::CxfAccount {
            id: email.into(),
            username: String::new(),
            email: email.into(),
        },
        &host(server_url),
        export::cxf::unix_seconds(&document.exported_at).unwrap_or(0),
    );
    exported.json.into_bytes()
}

/// The encrypted export: the document, then each item's files, read by `file`.
pub(crate) fn encrypted(
    document: &ExportDocument,
    items: &[StoredItem],
    password: &str,
    kdf: KdfParams,
    file: impl Fn(&str, &str) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<Zeroizing<Vec<u8>>> {
    if password.is_empty() {
        return Err(VaultError::new(
            ErrorCode::PasswordRequired,
            "an encrypted export needs a password",
        ));
    }
    let mut writer = ArchiveWriter::new(password, kdf, &mut OsRng)?;
    let mut out = Zeroizing::new(writer.add_items(document.to_json().as_bytes())?);
    for item in items {
        for attachment in crate::items::attachments(&item.details) {
            let bytes = file(&item.id, &attachment.id)?;
            out.extend(writer.add_file(&attachment.id, &bytes)?);
        }
    }
    out.extend(writer.finish()?);
    Ok(out)
}

// ---------- CSV ----------

const CSV_HEADER: [&str; 10] = [
    "vault", "type", "title", "url", "username", "password", "totp", "notes", "tags", "favorite",
];

fn field<'a>(details: &'a Value, key: &str) -> Option<&'a str> {
    details
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}

fn lines(fields: &[(&str, Option<String>)]) -> Vec<String> {
    fields
        .iter()
        .filter_map(|(label, value)| {
            value
                .as_deref()
                .filter(|v| !v.is_empty())
                .map(|v| format!("{label}: {v}"))
        })
        .collect()
}

fn address_text(address: Option<&Value>) -> Option<String> {
    let address = address?;
    let part = |key: &str| field(address, key).map(str::to_owned);
    let city_line = [part("postalCode"), part("city"), part("region")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    let text = [
        part("line1"),
        part("line2"),
        Some(city_line),
        part("country"),
    ]
    .into_iter()
    .flatten()
    .filter(|p| !p.is_empty())
    .collect::<Vec<_>>()
    .join(", ");
    (!text.is_empty()).then_some(text)
}

/// Fields without a column go into the notes as "Label: value" lines, ahead of the notes.
fn notes_of(item_type: &str, details: &Value) -> String {
    let get = |key: &str| field(details, key).map(str::to_owned);
    let join = |summary: Vec<String>, notes: Option<String>| {
        summary
            .into_iter()
            .chain(notes)
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    };
    match item_type {
        "card" => join(
            lines(&[
                ("Cardholder", get("cardholder")),
                ("Number", get("number")),
                ("Expiry", get("expiry")),
                ("CVV", get("cvv")),
                ("PIN", get("pin")),
                ("Brand", get("brand")),
            ]),
            get("notes"),
        ),
        "identity" => {
            let name = [get("firstName"), get("lastName")]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            join(
                lines(&[
                    ("Name", Some(name)),
                    ("Email", get("email")),
                    ("Phone", get("phone")),
                    ("Address", address_text(details.get("address"))),
                    ("Birth date", get("birthDate")),
                ]),
                get("notes"),
            )
        }
        "secureNote" => details
            .get("notes")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        "document" => {
            let files: Vec<(&str, Option<String>)> = crate::items::attachments(details)
                .into_iter()
                .map(|file| ("File", Some(file.name)))
                .collect();
            join(lines(&files), get("notes"))
        }
        "login" | "password" => {
            let custom: Vec<(String, Option<String>)> = details
                .get("customFields")
                .and_then(Value::as_array)
                .map(|fields| {
                    fields
                        .iter()
                        .map(|f| {
                            (
                                f.get("label")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                                f.get("value").and_then(Value::as_str).map(str::to_owned),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let borrowed: Vec<(&str, Option<String>)> = custom
                .iter()
                .map(|(l, v)| (l.as_str(), v.clone()))
                .collect();
            join(lines(&borrowed), get("notes"))
        }
        _ => String::new(),
    }
}

fn quote(cell: &str) -> String {
    if cell.contains(['"', ',', '\r', '\n']) || cell != cell.trim() {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell.to_owned()
    }
}

/// A lossy, spreadsheet-friendly export: one row per item; JSON is the full one. Masked email
/// provider tokens are settings, not items another app could import, so only JSON has them.
/// Cells starting with `= + - @` stay as they are: a leading `'` would change passwords that
/// are imported again.
pub(crate) fn csv(vaults: &[Vault], items: &[StoredItem]) -> String {
    let mut rows = vec![CSV_HEADER.map(str::to_owned).to_vec()];
    for item in items {
        let overview = &item.overview;
        let item_type = overview
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if item_type == "maskedEmailProvider"
            || item_type == octapass_mobile_vault::health::HEALTH_SETTINGS_TYPE
        {
            continue;
        }
        let login = matches!(item_type, "login" | "password");
        let detail = |key: &str| {
            login
                .then(|| item.details.get(key).and_then(Value::as_str))
                .flatten()
                .unwrap_or_default()
                .to_owned()
        };
        let list = |key: &str, separator: &str| {
            overview
                .get(key)
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(separator)
                })
                .unwrap_or_default()
        };
        rows.push(vec![
            vaults
                .iter()
                .find(|vault| vault.id == item.vault_id)
                .map(|vault| vault.name.clone())
                .unwrap_or_default(),
            item_type.to_owned(),
            item.title().to_owned(),
            list("urls", " "),
            detail("username"),
            detail("password"),
            detail("totp"),
            notes_of(item_type, &item.details),
            list("tags", ","),
            if overview.get("favorite") == Some(&Value::Bool(true)) {
                "true"
            } else {
                "false"
            }
            .into(),
        ]);
    }
    rows.iter()
        .map(|row| {
            row.iter()
                .map(|cell| quote(cell))
                .collect::<Vec<_>>()
                .join(",")
                + "\r\n"
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::sharing::VaultRole;

    fn item(overview: Value, details: Value) -> StoredItem {
        StoredItem {
            id: "0190a6c4-7d00-7000-8000-000000000001".into(),
            vault_id: "v".into(),
            revision: 1,
            created_at: "2024-07-12T11:46:53.312Z".into(),
            updated_at: "2024-07-12T11:46:53.312Z".into(),
            deleted_at: None,
            overview,
            details,
        }
    }

    fn vaults() -> Vec<Vault> {
        vec![Vault {
            id: "v".into(),
            name: "Personal".into(),
            vault_type: VaultType::Personal,
            role: VaultRole::Owner,
            untrusted: false,
        }]
    }

    #[test]
    fn csv_matches_the_web_vault() {
        let items = [
            item(
                json!({ "type": "login", "title": "GitHub", "urls": ["https://github.com", "https://gist.github.com"], "tags": ["a", "b"], "favorite": true }),
                json!({ "username": "ada", "password": " =pw,\"x\"", "customFields": [{ "label": "PIN", "value": "1", "hidden": true }], "notes": "n" }),
            ),
            item(
                json!({ "type": "card", "title": "Visa" }),
                json!({ "number": "4111", "expiry": "01/30" }),
            ),
            item(
                json!({ "type": "maskedEmailProvider", "title": "addy" }),
                json!({ "provider": "addy", "token": "secret" }),
            ),
        ];
        let csv = csv(&vaults(), &items);
        assert_eq!(
            csv,
            "vault,type,title,url,username,password,totp,notes,tags,favorite\r\n\
             Personal,login,GitHub,https://github.com https://gist.github.com,ada,\" =pw,\"\"x\"\"\",,\"PIN: 1\nn\",\"a,b\",true\r\n\
             Personal,card,Visa,,,,,\"Number: 4111\nExpiry: 01/30\",,false\r\n"
        );
    }

    #[test]
    fn imports_name_the_cores_sources() {
        assert_eq!(ImportSource::TwoFas.core(), CoreSource::TwoFas);
        assert_eq!(ImportSource::EnteAuth.core(), CoreSource::EnteAuth);
        assert_eq!(ImportSource::Raivo.core(), CoreSource::Raivo);
        assert_eq!(
            ImportSource::BitwardenJson.core(),
            CoreSource::BitwardenJson
        );
        assert_eq!(
            export_file_name(ExportFormat::Cxf, "2026-10-24"),
            "octapass-export-2026-10-24.cxf.json"
        );
    }

    #[test]
    fn json_drops_attachment_keys_and_encrypted_needs_a_password() {
        let items = [item(
            json!({ "type": "document", "title": "Lease" }),
            json!({ "attachments": [{ "id": "0190a6c4-7d00-7000-8000-0000000000aa", "name": "l.pdf", "type": "application/pdf", "size": 3, "key": "k" }] }),
        )];
        let doc = document(&vaults(), &items, "2026-10-24T00:00:00Z");
        assert!(!doc.to_json().contains("\"key\""));
        let none = |_: &str, _: &str| -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(b"pdf".to_vec()))
        };
        assert_eq!(
            encrypted(&doc, &items, "", export::EXPORT_KDF, none)
                .unwrap_err()
                .code(),
            ErrorCode::PasswordRequired
        );
        assert!(!cxf(&doc, "ada@example.com", "https://vault.octap.app/").is_empty());
    }
}

/// An authenticator import (or scanned one-time codes) waiting for the user to link each code to
/// a login. Never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ImportReview {
    pub id: String,
    pub codes: Vec<ReviewCode>,
    /// New items that aren't one-time codes (counter-based codes kept as fields, notes).
    pub other_items: u32,
    pub skipped: u32,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ReviewCode {
    /// For `CodeLink.code`.
    pub index: u32,
    pub title: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
    /// The login the importer matched it to; without one it becomes a login of its own.
    pub login_id: Option<String>,
}

/// The user's choice for one code: a login to join, or none for a login of its own.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CodeLink {
    pub code: u32,
    pub login_id: Option<String>,
}

impl From<octapass_mobile_vault::vault::ImportReview> for ImportReview {
    fn from(review: octapass_mobile_vault::vault::ImportReview) -> Self {
        Self {
            id: review.id,
            codes: review
                .codes
                .into_iter()
                .map(|code| ReviewCode {
                    index: code.index as u32,
                    title: code.title,
                    issuer: code.issuer,
                    account: code.account,
                    login_id: code.login_id,
                })
                .collect(),
            other_items: review.other_items as u32,
            skipped: review.skipped as u32,
            warnings: review.warnings,
        }
    }
}

impl From<CodeLink> for octapass_core::import::CodeLink {
    fn from(link: CodeLink) -> Self {
        Self {
            code: link.code as usize,
            login_id: link.login_id,
        }
    }
}
