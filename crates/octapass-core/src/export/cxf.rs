//! The FIDO Alliance Credential Exchange Format (CXF) v1.0, as JSON: exporting items to it. The
//! importer is [`crate::import`]'s `cxf` source, and uses the types here.
//!
//! Spec: <https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html>. One `Account`
//! holds every item; vaults become collections when there are several.
//!
//! | Octa Pass | CXF credentials |
//! |---|---|
//! | Login, Password | `basic-auth`, `totp`, one `passkey` each, `note`, `custom-fields`; URLs in `scope` |
//! | Secure note | `note` |
//! | Card | `credit-card`, `note` |
//! | Identity | `person-name`, `address` (with the phone as `tel`), `custom-fields` (email, birth date), `note` |
//! | Document | `note` (the file isn't in a CXF file) |
//! | Wi-Fi | `wifi`, `custom-fields` (Enterprise settings), `note` |
//! | SSH key | `ssh-key` (the private key as PKCS#8), `custom-fields` (passphrase), `note` |
//! | ID document | `passport`, `drivers-license` or `identity-document`, `custom-fields`, `note` |
//! | API credential | `api-key`, `custom-fields` (the secret, the type), `note` |
//! | Bank account, Software licence, Crypto wallet, Database, Custom item | `custom-fields`, `note` |
//!
//! CXF has no credential for the last row, so those go out as a `custom-fields` credential other apps
//! can read, labelled with the type. Its [`ITEM_TYPE_EXTENSION`] extension names the Octa Pass type and
//! each field's `id` is the base64url of its path in the details (`iban`, `addresses.0.address`,
//! `fields.1.hidden`), so importing the file here brings the same item back. Custom templates hold no
//! credentials, so like masked email connections they're left out.
//!
//! DSA and security key (`sk-`) SSH keys have no PKCS#8 form, so they aren't exported; the export
//! says how many.
//!
//! CXF has no place for password history, recovery info or attachments; the export says how many
//! items had them. The Octa Pass export keeps everything.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::document::ExportDocument;
use crate::encoding::{b64_encode, base32_encode};
use crate::item::{
    ApiCredentialDetails, CardDetails, CryptoWalletDetails, CustomDetails, CustomField,
    DatabaseDetails, IdDocumentDetails, IdentityDetails, Item, ItemDetails, ItemType, LoginDetails,
    SshKeyDetails, WifiDetails,
};
use crate::item_fields::{FieldKind, english_label, fields_of};
use crate::passkey::PasskeyRecord;
use crate::tools::otpauth::{OtpAlgorithm, OtpKind, OtpParams};

pub const MAJOR: u8 = 1;
pub const MINOR: u8 = 0;
/// Items' `androidApps` are kept in item URLs as `androidapp://<package>`.
pub const ANDROID_APP: &str = "androidapp://";
/// The extension on a `custom-fields` credential that holds an Octa Pass item type.
pub const ITEM_TYPE_EXTENSION: &str = "octapass.app/item-type";

/// CXF dates are whole Unix seconds. Apple's Credential Exchange hands over its data as Swift values,
/// and `JSONEncoder` with `.secondsSince1970` writes a `Date` as a `Double`, with a fraction for any
/// real time (the Passwords app's exports). Reading drops the fraction rather than refusing the file.
mod unix_time {
    use serde::{Deserialize, Deserializer, de::Error};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Seconds {
        Whole(u64),
        Fraction(f64),
    }

    impl Seconds {
        fn get(self) -> Option<u64> {
            match self {
                Seconds::Whole(seconds) => Some(seconds),
                Seconds::Fraction(seconds) if seconds.is_finite() && seconds >= 0.0 => {
                    Some(seconds.floor() as u64)
                }
                Seconds::Fraction(_) => None,
            }
        }
    }

    pub fn whole<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        Seconds::deserialize(deserializer)?
            .get()
            .ok_or_else(|| D::Error::custom("a Unix time before 1970"))
    }

    /// A date before 1970 is left out, like a missing one.
    pub fn optional<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
        Ok(Option::<Seconds>::deserialize(deserializer)?.and_then(Seconds::get))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Header {
    pub version: Version,
    pub exporter_rp_id: String,
    pub exporter_display_name: String,
    #[serde(deserialize_with = "unix_time::whole")]
    pub timestamp: u64,
    pub accounts: Vec<Account>,
}

/// Deserializing is lenient (missing fields default) because real exporters differ in what they
/// leave out; serializing follows the spec, required arrays included.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(default)]
    pub collections: Vec<Collection>,
    #[serde(default)]
    pub items: Vec<CxfItem>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    #[serde(default)]
    pub id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "unix_time::optional"
    )]
    pub creation_at: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "unix_time::optional"
    )]
    pub modified_at: Option<u64>,
    #[serde(default)]
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(default)]
    pub items: Vec<LinkedItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_collections: Vec<Collection>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkedItem {
    pub item: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfItem {
    #[serde(default)]
    pub id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "unix_time::optional"
    )]
    pub creation_at: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "unix_time::optional"
    )]
    pub modified_at: Option<u64>,
    #[serde(default)]
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// Typed by their `type`; unknown types are skipped on import, as the spec asks.
    #[serde(default)]
    pub credentials: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub android_apps: Vec<AndroidApp>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidApp {
    pub bundle_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// An `EditableField`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub field_type: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

pub fn field(field_type: &str, value: &str) -> Value {
    json!({ "fieldType": field_type, "value": value })
}

fn labelled(field_type: &str, value: &str, label: &str) -> Value {
    json!({ "fieldType": field_type, "value": value, "label": label })
}

/// Who the export belongs to: the CXF `Account`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CxfAccount {
    /// Any stable id (the account id); it's base64url-encoded.
    pub id: String,
    pub username: String,
    pub email: String,
}

/// What [`export`] made: the JSON and a summary for the user.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CxfExport {
    pub json: String,
    pub exported: usize,
    pub skipped: usize,
    /// Short English sentences; never secrets.
    pub warnings: Vec<String>,
}

#[derive(Default)]
struct Losses {
    history: usize,
    recovery: usize,
    files: usize,
    passkeys: usize,
    unsupported: usize,
    ssh_keys: usize,
}

/// Exports a document's items as one CXF account. `exporter_rp_id` names this app's domain (the
/// server's host); `timestamp` is now, in Unix seconds. Masked email connections are settings,
/// not credentials, and are left out.
pub fn export(
    document: &ExportDocument,
    account: &CxfAccount,
    exporter_rp_id: &str,
    timestamp: u64,
) -> CxfExport {
    export_types(document, account, exporter_rp_id, timestamp, None)
}

/// [`export`] for another app that asked for some credential types only (the Credential Exchange
/// Protocol's `credentialTypes`, such as `basic-auth` and `passkey`): every other credential is
/// left out, and so is an item left with none. They aren't counted as skipped: the app didn't
/// ask for them.
pub fn export_for_app(
    document: &ExportDocument,
    account: &CxfAccount,
    exporter_rp_id: &str,
    timestamp: u64,
    credential_types: &[String],
) -> CxfExport {
    export_types(
        document,
        account,
        exporter_rp_id,
        timestamp,
        Some(credential_types),
    )
}

fn export_types(
    document: &ExportDocument,
    account: &CxfAccount,
    exporter_rp_id: &str,
    timestamp: u64,
    credential_types: Option<&[String]>,
) -> CxfExport {
    let mut losses = Losses::default();
    let mut items = Vec::new();
    let mut skipped = 0;
    for exported in &document.items {
        // Exported attachments have no keys, which the item model wants: they're counted, not used.
        let mut details = exported.details.clone();
        if let Some(details) = details.as_object_mut() {
            details.remove("attachments");
        }
        let Ok(item) = Item::from_json(
            &json!({ "overview": exported.overview, "details": details }).to_string(),
        ) else {
            skipped += 1;
            continue;
        };
        if matches!(
            item.overview.item_type,
            ItemType::MaskedEmailProvider | ItemType::EquivalentDomains | ItemType::CustomTemplate
        ) {
            continue;
        }
        if exported
            .details
            .get("attachments")
            .and_then(Value::as_array)
            .is_some_and(|files| !files.is_empty())
        {
            losses.files += 1;
        }
        let Some(mut credentials) = credentials(&item, &mut losses) else {
            losses.unsupported += 1;
            skipped += 1;
            continue;
        };
        // An SSH key CXF can't hold (counted in `credentials`).
        if credentials.is_empty() && matches!(item.details, ItemDetails::SshKey(_)) {
            skipped += 1;
            continue;
        }
        if let Some(types) = credential_types {
            credentials.retain(|credential| {
                credential
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| types.iter().any(|asked| asked == kind))
            });
            if credentials.is_empty() {
                continue;
            }
        }
        let overview = &item.overview;
        let (urls, android_apps): (Vec<&String>, Vec<&String>) = overview
            .urls
            .iter()
            .flatten()
            .partition(|url| !url.starts_with(ANDROID_APP));
        let scope = (!urls.is_empty() || !android_apps.is_empty()).then(|| Scope {
            urls: urls.into_iter().cloned().collect(),
            android_apps: android_apps
                .into_iter()
                .map(|url| AndroidApp {
                    bundle_id: url[ANDROID_APP.len()..].trim_end_matches('/').to_owned(),
                    certificate: None,
                    name: None,
                })
                .collect(),
        });
        items.push((
            exported.vault_id.as_str(),
            CxfItem {
                id: b64_encode(exported.id.as_bytes()),
                // The dates from the app an item was imported from, when it has them.
                creation_at: unix_seconds(
                    overview
                        .created_at
                        .as_deref()
                        .unwrap_or(&exported.created_at),
                ),
                modified_at: unix_seconds(
                    overview
                        .updated_at
                        .as_deref()
                        .unwrap_or(&exported.updated_at),
                ),
                title: overview.title.clone(),
                subtitle: overview.subtitle.clone(),
                favorite: overview.favorite.filter(|f| *f),
                scope,
                credentials,
                tags: overview.tags.clone().unwrap_or_default(),
            },
        ));
    }
    // One vault needs no collections; several become one each, so they can be told apart.
    let collections = if document.vaults.len() > 1 {
        document
            .vaults
            .iter()
            .map(|vault| Collection {
                id: b64_encode(vault.id.as_bytes()),
                creation_at: None,
                modified_at: None,
                title: vault.name.clone(),
                subtitle: None,
                items: items
                    .iter()
                    .filter(|(vault_id, _)| *vault_id == vault.id)
                    .map(|(_, item)| LinkedItem {
                        item: item.id.clone(),
                        account: None,
                    })
                    .collect(),
                sub_collections: Vec::new(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let exported = items.len();
    let header = Header {
        version: Version {
            major: MAJOR,
            minor: MINOR,
        },
        exporter_rp_id: exporter_rp_id.to_owned(),
        exporter_display_name: "Octa Pass".into(),
        timestamp,
        accounts: vec![Account {
            id: b64_encode(account.id.as_bytes()),
            username: account.username.clone(),
            email: account.email.clone(),
            full_name: None,
            collections,
            items: items.into_iter().map(|(_, item)| item).collect(),
        }],
    };
    CxfExport {
        json: serde_json::to_string_pretty(&header).expect("CXF serializes"),
        exported,
        skipped,
        warnings: losses.warnings(),
    }
}

impl Losses {
    fn warnings(&self) -> Vec<String> {
        let count = |n: usize| {
            if n == 1 {
                "1 item".to_owned()
            } else {
                format!("{n} items")
            }
        };
        let mut warnings = Vec::new();
        if self.history > 0 {
            warnings.push(format!(
                "{} had password history, which CXF can't hold.",
                count(self.history)
            ));
        }
        if self.recovery > 0 {
            warnings.push(format!(
                "{} had recovery info, which CXF can't hold.",
                count(self.recovery)
            ));
        }
        if self.files > 0 {
            warnings.push(format!(
                "{} had attached files, which aren't in a CXF file.",
                count(self.files)
            ));
        }
        if self.passkeys > 0 {
            warnings.push(format!(
                "{} passkey{} without a private key (saved by an older app) couldn't be exported.",
                self.passkeys,
                if self.passkeys == 1 { "" } else { "s" }
            ));
        }
        if self.ssh_keys > 0 {
            warnings.push(format!(
                "{} SSH key{} of a kind CXF can't hold (DSA, security key) weren't exported.",
                self.ssh_keys,
                if self.ssh_keys == 1 { "" } else { "s" }
            ));
        }
        if self.unsupported > 0 {
            warnings.push(format!(
                "{} of a type CXF doesn't have weren't exported.",
                count(self.unsupported)
            ));
        }
        if !warnings.is_empty() {
            warnings.push("The Octa Pass export keeps all of it.".into());
        }
        warnings
    }
}

fn credentials(item: &Item, losses: &mut Losses) -> Option<Vec<Value>> {
    let mut out = Vec::new();
    let note = |out: &mut Vec<Value>, notes: Option<&String>| {
        if let Some(notes) = notes.filter(|n| !n.is_empty()) {
            out.push(json!({ "type": "note", "content": field("string", notes) }));
        }
    };
    match &item.details {
        ItemDetails::Login(details) => login(details, &mut out, losses),
        ItemDetails::SecureNote(details) => note(&mut out, Some(&details.notes)),
        ItemDetails::Card(details) => {
            out.push(card(details));
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::Identity(details) => {
            identity(details, &mut out);
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::Document(details) => note(&mut out, details.notes.as_ref()),
        ItemDetails::Wifi(details) => wifi(details, &mut out, losses),
        // CXF has no environment credential: the variables go out as custom fields.
        ItemDetails::Environment(details) => {
            let fields: Vec<Value> = details
                .variables
                .iter()
                .map(|var| {
                    let kind = if var.concealed {
                        "concealed-string"
                    } else {
                        "string"
                    };
                    labelled(kind, &var.value, &var.key)
                })
                .collect();
            if !fields.is_empty() {
                out.push(json!({ "type": "custom-fields", "fields": fields }));
            }
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::SshKey(details) => {
            let Some(key) = ssh_key(details) else {
                losses.ssh_keys += 1;
                return Some(Vec::new());
            };
            out.push(key);
            let mut custom: Vec<Value> = Vec::new();
            if let Some(passphrase) = details.passphrase.as_ref().filter(|p| !p.is_empty()) {
                custom.push(labelled("concealed-string", passphrase, "Passphrase"));
            }
            for field in details.custom_fields.iter().flatten() {
                let kind = if field.hidden {
                    "concealed-string"
                } else {
                    "string"
                };
                custom.push(labelled(kind, &field.value, &field.label));
            }
            if !custom.is_empty() {
                out.push(json!({ "type": "custom-fields", "fields": custom }));
            }
            note(&mut out, details.notes.as_ref());
        }
        // CXF has no certificate or key credential: they go out as custom fields, the secret
        // parts concealed.
        ItemDetails::Certificate(details) => {
            let parts = [
                ("string", "Certificate", &details.certificate),
                ("string", "Chain", &details.chain),
                ("concealed-string", "Private key", &details.private_key),
            ];
            custom_parts(&parts, details.custom_fields.as_deref(), &mut out);
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::Key(details) => {
            let parts = [
                ("string", "Kind", &details.kind),
                ("string", "Algorithm", &details.algorithm),
                ("string", "Key ID", &details.key_id),
                ("string", "Fingerprint", &details.fingerprint),
                ("string", "User ID", &details.user_id),
                ("string", "Public key", &details.public_key),
                ("string", "JWKS", &details.jwks),
                ("concealed-string", "Private key", &details.private_key),
                ("concealed-string", "Secret", &details.secret),
                ("concealed-string", "JWK", &details.jwk),
                ("concealed-string", "Passphrase", &details.passphrase),
            ];
            custom_parts(&parts, details.custom_fields.as_deref(), &mut out);
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::BankAccount(details) => {
            typed_item(item, &[], &mut out);
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::SoftwareLicense(details) => {
            typed_item(item, &[], &mut out);
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::CryptoWallet(details) => {
            wallet(item, details, &mut out);
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::Database(details) => {
            database(item, details, &mut out, losses);
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::IdDocument(details) => {
            out.push(document(details));
            typed_item(item, DOCUMENT_FIELDS, &mut out);
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::ApiCredential(details) => {
            out.push(api_key(details));
            typed_item(item, API_KEY_FIELDS, &mut out);
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::Custom(details) => {
            out.push(custom_item(item, details));
            note(&mut out, details.notes.as_ref());
        }
        ItemDetails::MaskedEmailProvider(_)
        | ItemDetails::EquivalentDomains(_)
        | ItemDetails::CustomTemplate(_)
        | ItemDetails::Other(_) => return None,
    }
    Some(out)
}

/// The filled-in `parts` and the item's own custom fields, as one `custom-fields` credential.
fn custom_parts(
    parts: &[(&str, &str, &Option<String>)],
    custom_fields: Option<&[crate::item::CustomField]>,
    out: &mut Vec<Value>,
) {
    let mut fields: Vec<Value> = parts
        .iter()
        .filter_map(|(kind, label, value)| {
            let value = value.as_ref().filter(|value| !value.is_empty())?;
            Some(labelled(kind, value, label))
        })
        .collect();
    for field in custom_fields.into_iter().flatten() {
        let kind = if field.hidden {
            "concealed-string"
        } else {
            "string"
        };
        fields.push(labelled(kind, &field.value, &field.label));
    }
    if !fields.is_empty() {
        out.push(json!({ "type": "custom-fields", "fields": fields }));
    }
}

/// Fields the native `passport`, `drivers-license` and `identity-document` credentials hold.
const DOCUMENT_FIELDS: &[&str] = &[
    "number",
    "fullName",
    "birthDate",
    "issuer",
    "country",
    "issueDate",
    "expiryDate",
];
/// Fields the native `api-key` credential holds.
const API_KEY_FIELDS: &[&str] = &["key", "username", "host", "credentialType", "expiryDate"];

fn typed_field(path: &str, field_type: &str, value: &str, label: &str) -> Value {
    json!({ "id": b64_encode(path.as_bytes()), "fieldType": field_type, "value": value, "label": label })
}

fn field_type_of(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Secret | FieldKind::SecretLong => "concealed-string",
        FieldKind::Date => "date",
        FieldKind::Email => "email",
        _ => "string",
    }
}

fn custom_field_rows(fields: Option<&Vec<CustomField>>, out: &mut Vec<Value>) {
    for (i, custom) in fields.into_iter().flatten().enumerate() {
        let kind = if custom.hidden {
            "concealed-string"
        } else {
            "string"
        };
        out.push(typed_field(
            &format!("customFields.{i}"),
            kind,
            &custom.value,
            &custom.label,
        ));
    }
}

/// The item's table fields, except `skip`, as a `custom-fields` credential marked with its type.
fn typed_fields(item: &Item, skip: &[&str]) -> Vec<Value> {
    let name = String::from(item.overview.item_type.clone());
    let details = serde_json::to_value(&item.details).expect("items serialize");
    fields_of(&name)
        .iter()
        .filter(|spec| !skip.contains(&spec.key))
        .filter_map(|spec| {
            let value = details.get(spec.key)?.as_str().filter(|v| !v.is_empty())?;
            Some(typed_field(
                spec.key,
                field_type_of(spec.kind),
                value,
                &english_label(spec.key),
            ))
        })
        .collect()
}

fn typed_credential(item: &Item, fields: Vec<Value>) -> Value {
    let name = String::from(item.overview.item_type.clone());
    json!({
        "type": "custom-fields",
        "label": english_label(&name),
        "fields": fields,
        "extensions": [{ "name": ITEM_TYPE_EXTENSION, "itemType": name }],
    })
}

fn typed_item(item: &Item, skip: &[&str], out: &mut Vec<Value>) {
    let mut fields = typed_fields(item, skip);
    let custom = match &item.details {
        ItemDetails::BankAccount(details) => details.custom_fields.as_ref(),
        ItemDetails::SoftwareLicense(details) => details.custom_fields.as_ref(),
        ItemDetails::IdDocument(details) => details.custom_fields.as_ref(),
        ItemDetails::ApiCredential(details) => details.custom_fields.as_ref(),
        _ => None,
    };
    custom_field_rows(custom, &mut fields);
    // Always written, so even an ID document with nothing extra keeps its Octa Pass type.
    out.push(typed_credential(item, fields));
}

fn wallet(item: &Item, details: &CryptoWalletDetails, out: &mut Vec<Value>) {
    let mut fields = typed_fields(item, &[]);
    for (i, entry) in details.addresses.iter().flatten().enumerate() {
        let label = entry.label.as_deref().unwrap_or(&entry.network);
        let path = format!("addresses.{i}");
        fields.push(typed_field(
            &format!("{path}.address"),
            "string",
            &entry.address,
            label,
        ));
        fields.push(typed_field(
            &format!("{path}.network"),
            "string",
            &entry.network,
            "Network",
        ));
        if let Some(name) = &entry.label {
            fields.push(typed_field(
                &format!("{path}.label"),
                "string",
                name,
                "Label",
            ));
        }
    }
    custom_field_rows(details.custom_fields.as_ref(), &mut fields);
    out.push(typed_credential(item, fields));
}

fn database(item: &Item, details: &DatabaseDetails, out: &mut Vec<Value>, losses: &mut Losses) {
    let mut fields = typed_fields(item, &[]);
    custom_field_rows(details.custom_fields.as_ref(), &mut fields);
    out.push(typed_credential(item, fields));
    if details
        .password_history
        .as_ref()
        .is_some_and(|h| !h.is_empty())
    {
        losses.history += 1;
    }
}

fn custom_item(item: &Item, details: &CustomDetails) -> Value {
    let fields: Vec<Value> = details
        .fields
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let kind = if crate::item_fields::custom_kind_is_plain(&entry.kind) {
                "string"
            } else {
                "concealed-string"
            };
            typed_field(
                &format!("fields.{i}.{}", entry.kind),
                kind,
                &entry.value,
                &entry.label,
            )
        })
        .collect();
    let mut credential = typed_credential(item, fields);
    if let Some(name) = details.template_name.as_ref().filter(|n| !n.is_empty()) {
        credential["label"] = name.as_str().into();
    }
    credential
}

fn set(credential: &mut Map<String, Value>, key: &str, kind: &str, value: Option<&String>) {
    if let Some(value) = value.filter(|v| !v.is_empty()) {
        credential.insert(key.into(), field(kind, value));
    }
}

/// The credential for a passport, a driver's licence or any other ID.
fn document(details: &IdDocumentDetails) -> Value {
    let mut credential = Map::new();
    let (kind, number) = match details.document_type.as_deref() {
        Some("passport") => ("passport", "passportNumber"),
        Some("driverLicense") => ("drivers-license", "licenseNumber"),
        _ => ("identity-document", "documentNumber"),
    };
    credential.insert("type".into(), kind.into());
    set(
        &mut credential,
        number,
        "concealed-string",
        details.number.as_ref(),
    );
    set(
        &mut credential,
        "fullName",
        "string",
        details.full_name.as_ref(),
    );
    set(
        &mut credential,
        "birthDate",
        "date",
        details.birth_date.as_ref(),
    );
    set(
        &mut credential,
        "issueDate",
        "date",
        details.issue_date.as_ref(),
    );
    set(
        &mut credential,
        "expiryDate",
        "date",
        details.expiry_date.as_ref(),
    );
    set(
        &mut credential,
        "issuingAuthority",
        "string",
        details.issuer.as_ref(),
    );
    set(
        &mut credential,
        "issuingCountry",
        "string",
        details.country.as_ref(),
    );
    Value::Object(credential)
}

fn api_key(details: &ApiCredentialDetails) -> Value {
    let mut credential = Map::new();
    credential.insert("type".into(), "api-key".into());
    set(
        &mut credential,
        "key",
        "concealed-string",
        details.key.as_ref(),
    );
    set(
        &mut credential,
        "username",
        "string",
        details.username.as_ref(),
    );
    set(
        &mut credential,
        "keyType",
        "string",
        details.credential_type.as_ref(),
    );
    set(&mut credential, "url", "string", details.host.as_ref());
    set(
        &mut credential,
        "expiryDate",
        "date",
        details.expiry_date.as_ref(),
    );
    Value::Object(credential)
}

fn login(details: &LoginDetails, out: &mut Vec<Value>, losses: &mut Losses) {
    let mut basic = Map::new();
    basic.insert("type".into(), "basic-auth".into());
    if let Some(username) = &details.username {
        basic.insert("username".into(), field("string", username));
    }
    if let Some(password) = &details.password {
        basic.insert("password".into(), field("concealed-string", password));
    }
    if basic.len() > 1 {
        out.push(Value::Object(basic));
    }
    let mut custom: Vec<Value> = Vec::new();
    if let Some(totp) = &details.totp {
        match OtpParams::parse(totp) {
            Ok(params) if matches!(params.kind, OtpKind::Totp { .. }) => {
                out.push(totp_credential(&params))
            }
            // HOTP and broken setups have no CXF credential: kept as a hidden field.
            _ => custom.push(labelled("concealed-string", totp, "One-time code")),
        }
    }
    for passkey in details.passkeys.iter().flatten() {
        match PasskeyRecord::from_item(passkey) {
            Some(record) => {
                out.push(serde_json::to_value(record.to_cxf()).expect("passkeys serialize"))
            }
            None => losses.passkeys += 1,
        }
    }
    if let Some(notes) = details.notes.as_ref().filter(|n| !n.is_empty()) {
        out.push(json!({ "type": "note", "content": field("string", notes) }));
    }
    for field in details.custom_fields.iter().flatten() {
        let kind = if field.hidden {
            "concealed-string"
        } else {
            "string"
        };
        custom.push(labelled(kind, &field.value, &field.label));
    }
    if !custom.is_empty() {
        out.push(json!({ "type": "custom-fields", "fields": custom }));
    }
    if details
        .password_history
        .as_ref()
        .is_some_and(|h| !h.is_empty())
    {
        losses.history += 1;
    }
    if details.recovery.is_some() {
        losses.recovery += 1;
    }
}

/// The CXF `wifi` credential. Its security types are Personal ones; WPA/WPA2 and WPA2/WPA3
/// transition modes export as the older standard, and Enterprise settings as custom fields.
fn wifi(details: &WifiDetails, out: &mut Vec<Value>, losses: &mut Losses) {
    let mut wifi = Map::new();
    wifi.insert("type".into(), "wifi".into());
    wifi.insert("ssid".into(), field("string", &details.ssid));
    let security = match details.security.as_str() {
        "open" => Some("unsecured"),
        "wep" => Some("wep"),
        "wpa" | "wpaWpa2" => Some("wpa-personal"),
        "wpa2" | "wpa2Wpa3" => Some("wpa2-personal"),
        "wpa3" => Some("wpa3-personal"),
        _ => None,
    };
    if let Some(security) = security {
        wifi.insert(
            "networkSecurityType".into(),
            field("wifi-network-security-type", security),
        );
    }
    if let Some(password) = details.password.as_ref().filter(|p| !p.is_empty()) {
        wifi.insert("passphrase".into(), field("concealed-string", password));
    }
    let hidden = if details.hidden == Some(true) {
        "true"
    } else {
        "false"
    };
    wifi.insert("hidden".into(), field("boolean", hidden));
    out.push(Value::Object(wifi));

    let mut custom: Vec<Value> = Vec::new();
    if security.is_none() {
        custom.push(labelled("string", &details.security, "Security"));
    }
    for (label, value) in [
        ("EAP method", &details.eap_method),
        ("Phase 2", &details.phase2),
        ("Username", &details.username),
        ("Identity", &details.identity),
        ("Server domain", &details.server_domain),
        ("CA certificate", &details.ca_certificate),
    ] {
        if let Some(value) = value.as_ref().filter(|v| !v.is_empty()) {
            custom.push(labelled("string", value, label));
        }
    }
    for field in details.custom_fields.iter().flatten() {
        let kind = if field.hidden {
            "concealed-string"
        } else {
            "string"
        };
        custom.push(labelled(kind, &field.value, &field.label));
    }
    if !custom.is_empty() {
        out.push(json!({ "type": "custom-fields", "fields": custom }));
    }
    if let Some(notes) = details.notes.as_ref().filter(|n| !n.is_empty()) {
        out.push(json!({ "type": "note", "content": field("string", notes) }));
    }
    if details
        .password_history
        .as_ref()
        .is_some_and(|h| !h.is_empty())
    {
        losses.history += 1;
    }
}

/// An `ssh-key` credential: the private key as base64url PKCS#8 DER, as CXF requires. `None` for
/// keys that have no PKCS#8 form (DSA, `sk-`) or no private key.
fn ssh_key(details: &SshKeyDetails) -> Option<Value> {
    let der = crate::tools::ssh::to_pkcs8_der(details.private_key.as_deref()?).ok()?;
    let key = crate::tools::ssh::read_private_key(details.private_key.as_deref()?, None).ok()?;
    let mut credential = Map::new();
    credential.insert("type".into(), "ssh-key".into());
    credential.insert("keyType".into(), key.info.key_type.into());
    credential.insert("privateKey".into(), b64_encode(&der).into());
    if let Some(comment) = details.comment.as_ref().filter(|c| !c.trim().is_empty()) {
        credential.insert("keyComment".into(), comment.trim().into());
    }
    Some(Value::Object(credential))
}

fn totp_credential(params: &OtpParams) -> Value {
    let OtpKind::Totp { period } = params.kind else {
        unreachable!("only TOTP")
    };
    let mut totp = json!({
        "type": "totp",
        "secret": base32_encode(&params.secret),
        "period": period,
        "digits": params.digits,
        "algorithm": match params.algorithm {
            OtpAlgorithm::Sha1 => "sha1",
            OtpAlgorithm::Sha256 => "sha256",
            OtpAlgorithm::Sha512 => "sha512",
        },
    });
    if let Some(account) = params.account.as_ref().filter(|a| !a.is_empty()) {
        totp["username"] = account.as_str().into();
    }
    if let Some(issuer) = &params.issuer {
        totp["issuer"] = issuer.as_str().into();
    }
    totp
}

fn card(details: &CardDetails) -> Value {
    let mut card = Map::new();
    card.insert("type".into(), "credit-card".into());
    let mut put = |key: &str, kind: &str, value: Option<&String>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            card.insert(key.into(), field(kind, value));
        }
    };
    put("number", "concealed-string", details.number.as_ref());
    put("fullName", "string", details.cardholder.as_ref());
    put("cardType", "string", details.brand.as_ref());
    put(
        "verificationNumber",
        "concealed-string",
        details.cvv.as_ref(),
    );
    put("pin", "concealed-string", details.pin.as_ref());
    // `MM/YY` becomes the spec's `YYYY-MM`; anything else is kept as text.
    if let Some(expiry) = &details.expiry {
        match year_month(expiry) {
            Some(value) => put("expiryDate", "year-month", Some(&value)),
            None => put("expiryDate", "string", Some(expiry)),
        }
    }
    Value::Object(card)
}

/// `MM/YY` or `MM/YYYY` as `YYYY-MM`.
pub fn year_month(expiry: &str) -> Option<String> {
    let (month, year) = expiry.trim().split_once('/')?;
    let month: u32 = month.trim().parse().ok().filter(|m| (1..=12).contains(m))?;
    let year = year.trim();
    let year: u32 = match year.len() {
        2 => 2000 + year.parse::<u32>().ok()?,
        4 => year.parse().ok()?,
        _ => return None,
    };
    Some(format!("{year:04}-{month:02}"))
}

fn identity(details: &IdentityDetails, out: &mut Vec<Value>) {
    let mut name = Map::new();
    name.insert("type".into(), "person-name".into());
    if let Some(first) = &details.first_name {
        name.insert("given".into(), field("string", first));
    }
    if let Some(last) = &details.last_name {
        name.insert("surname".into(), field("string", last));
    }
    if name.len() > 1 {
        out.push(Value::Object(name));
    }
    let mut address = Map::new();
    address.insert("type".into(), "address".into());
    if let Some(lines) = &details.address {
        let street: Vec<&str> = [&lines.line1, &lines.line2]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect();
        if !street.is_empty() {
            address.insert("streetAddress".into(), field("string", &street.join("\n")));
        }
        if let Some(code) = &lines.postal_code {
            address.insert("postalCode".into(), field("string", code));
        }
        if let Some(city) = &lines.city {
            address.insert("city".into(), field("string", city));
        }
        if let Some(region) = &lines.region {
            // Only ISO 3166-2 codes (`US-CA`) are a subdivision code; a name stays text.
            let kind = if is_subdivision(region) {
                "subdivision-code"
            } else {
                "string"
            };
            address.insert("territory".into(), field(kind, region));
        }
        if let Some(country) = &lines.country {
            let kind = if is_country(country) {
                "country-code"
            } else {
                "string"
            };
            address.insert("country".into(), field(kind, country));
        }
    }
    if let Some(phone) = &details.phone {
        address.insert("tel".into(), field("string", phone));
    }
    if address.len() > 1 {
        out.push(Value::Object(address));
    }
    let mut custom = Vec::new();
    if let Some(email) = &details.email {
        custom.push(labelled("email", email, "Email"));
    }
    if let Some(birth) = &details.birth_date {
        custom.push(labelled("date", birth, "Birth date"));
    }
    if !custom.is_empty() {
        out.push(json!({ "type": "custom-fields", "fields": custom }));
    }
}

pub fn is_country(text: &str) -> bool {
    text.len() == 2 && text.bytes().all(|b| b.is_ascii_uppercase())
}

pub fn is_subdivision(text: &str) -> bool {
    text.split_once('-').is_some_and(|(country, sub)| {
        is_country(country)
            && (1..=3).contains(&sub.len())
            && sub
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    })
}

/// Unix seconds of an RFC 3339 UTC time (`2026-10-24T09:30:00.000Z`), as items store them.
pub fn unix_seconds(time: &str) -> Option<u64> {
    let time = time.trim();
    let number = |range: core::ops::Range<usize>| time.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let separators = time.get(4..5) == Some("-")
        && time.get(7..8) == Some("-")
        && matches!(time.get(10..11), Some("T" | "t" | " "));
    if !separators || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Howard Hinnant's days-from-civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_codes() {
        assert_eq!(unix_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            unix_seconds("2024-01-14T10:40:00.000Z"),
            Some(1_705_228_800)
        );
        assert_eq!(unix_seconds("2000-02-29T12:00:00Z"), Some(951_825_600));
        assert_eq!(unix_seconds("yesterday"), None);
        assert_eq!(year_month("04/29").as_deref(), Some("2029-04"));
        assert_eq!(year_month("4/2031").as_deref(), Some("2031-04"));
        assert_eq!(year_month("13/29"), None);
        assert!(is_country("JO") && !is_country("Jordan"));
        assert!(is_subdivision("US-CA") && !is_subdivision("California"));
    }

    #[test]
    fn wifi_networks_become_wifi_credentials() {
        let item = |details: Value| {
            Item::from_json(
                &json!({ "overview": { "title": "Home", "type": "wifi" }, "details": details })
                    .to_string(),
            )
            .unwrap()
        };
        let mut losses = Losses::default();
        let home = credentials(
            &item(json!({ "ssid": "Rahman-5G", "security": "wpa2Wpa3", "password": "pw", "hidden": true, "notes": "hall" })),
            &mut losses,
        )
        .unwrap();
        assert_eq!(
            home,
            [
                json!({ "type": "wifi", "ssid": field("string", "Rahman-5G"), "networkSecurityType": field("wifi-network-security-type", "wpa2-personal"), "passphrase": field("concealed-string", "pw"), "hidden": field("boolean", "true") }),
                json!({ "type": "note", "content": field("string", "hall") }),
            ]
        );
        let cafe = credentials(
            &item(json!({ "ssid": "Cafe", "security": "open" })),
            &mut losses,
        )
        .unwrap();
        assert_eq!(cafe[0]["networkSecurityType"]["value"], "unsecured");
        assert!(cafe[0].get("passphrase").is_none());
        // Enterprise has no CXF security type: its settings go along as fields.
        let work = credentials(
            &item(json!({ "ssid": "Corp", "security": "wpa3Enterprise", "eapMethod": "peap", "username": "u", "password": "p" })),
            &mut losses,
        )
        .unwrap();
        assert!(work[0].get("networkSecurityType").is_none());
        assert_eq!(
            work[1]["fields"],
            json!([
                labelled("string", "wpa3Enterprise", "Security"),
                labelled("string", "peap", "EAP method"),
                labelled("string", "u", "Username")
            ])
        );
    }
}
