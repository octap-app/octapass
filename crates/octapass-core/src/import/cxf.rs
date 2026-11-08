//! The FIDO Credential Exchange Format (CXF) v1.0: a `Header` with accounts, or a single `Account`
//! (what apps hand over through the Credential Exchange Protocol, and what Dashlane and 1Password
//! write). See [`crate::export::cxf`] for the types and the spec.
//!
//! Each CXF item becomes one item, typed by its main credential: `basic-auth`, `passkey` or `totp`
//! make a login; `credit-card` a card; `passport`, `drivers-license` and `identity-document` an ID
//! document; `api-key` an API credential; `person-name` and `address` an identity; `ssh-key` an SSH
//! key (when its PKCS#8 key reads; a `Passphrase` custom field becomes its passphrase);
//! `generated-password` a password; anything else a secure note. An ID document or API key kept with a
//! login or card is that item's fields instead. Credentials the type has no field for go into
//! custom fields or `Label: value` lines in the notes. Extra logins, cards, documents and API keys
//! in one item become items of their own. Collections become tags. Files and unknown credential
//! types can't come across and are reported.
//!
//! A `custom-fields` credential with the [`ITEM_TYPE_EXTENSION`] extension is an Octa Pass item of a
//! type CXF doesn't have: each field's `id` is the base64url of its path in the details, as the
//! export writes it. Other extensions are ignored, as the spec asks.
//!
//! An item's `id` is kept so importing the file again updates it, and `creationAt` and
//! `modifiedAt` (Unix seconds) become its dates.

use serde_json::Value;

use super::build::{
    self, Collector, ItemMeta, LoginFields, TypedItem, card_details, clean, custom_field,
    identity_details, notes_with, rfc3339, unix_time,
};
use super::{ImportError, ImportResult};
use crate::encoding::b64_decode;
use crate::error::Error;
use crate::export::cxf::{
    ANDROID_APP, Account, CxfItem, Field, Header, ITEM_TYPE_EXTENSION, LinkedItem, MAJOR,
};
use crate::item::{CustomField, ItemDetails, ItemType, SCHEMA_VERSION, SshKeyDetails, WifiDetails};
use crate::item_fields::{english_label, fields_of};
use crate::passkey::{CxfPasskey, PasskeyRecord};
use crate::tools::otpauth::{OtpAlgorithm, OtpKind, OtpParams};

fn invalid() -> ImportError {
    ImportError::new(
        Error::InvalidImportFile,
        "This isn't a Credential Exchange (CXF) file.",
    )
}

pub(super) fn parse(text: &str) -> Result<ImportResult, ImportError> {
    let value: Value = serde_json::from_str(text).map_err(|_| invalid())?;
    let (accounts, timestamp) = if value.get("accounts").is_some() {
        let major = value
            .pointer("/version/major")
            .and_then(Value::as_u64)
            .ok_or_else(invalid)?;
        if major != u64::from(MAJOR) {
            return Err(ImportError::new(
                Error::UnsupportedImport,
                "This CXF file uses a newer version of the format than Octa Pass reads.",
            ));
        }
        let header: Header = serde_json::from_value(value).map_err(|_| invalid())?;
        (header.accounts, Some(header.timestamp))
    } else if value.get("items").is_some_and(Value::is_array) {
        let account: Account = serde_json::from_value(value).map_err(|_| invalid())?;
        (vec![account], None)
    } else {
        return Err(invalid());
    };
    let mut out = Collector::default();
    let mut stats = Stats::default();
    for account in &accounts {
        let collections = collection_tags(account);
        for item in &account.items {
            let mut tags = item.tags.clone();
            tags.extend(
                collections
                    .iter()
                    .filter(|(id, _)| *id == item.id)
                    .map(|(_, tag)| tag.clone()),
            );
            add_item(item, tags, timestamp, &mut out, &mut stats);
        }
    }
    stats.report(&mut out);
    Ok(out.finish())
}

#[derive(Default)]
struct Stats {
    files: usize,
    unknown: Vec<String>,
    passkeys: usize,
}

impl Stats {
    fn report(self, out: &mut Collector) {
        if self.files > 0 {
            out.warn(format!(
                "{} attached file{} couldn't be imported: CXF files don't include them.",
                self.files,
                if self.files == 1 { "" } else { "s" }
            ));
        }
        if self.passkeys > 0 {
            out.warn(format!(
                "{} passkey{} used a key type Octa Pass can't sign with, so {} skipped.",
                self.passkeys,
                if self.passkeys == 1 { "" } else { "s" },
                if self.passkeys == 1 {
                    "it was"
                } else {
                    "they were"
                }
            ));
        }
        if !self.unknown.is_empty() {
            out.warn(format!(
                "Skipped credential types Octa Pass doesn't know: {}.",
                self.unknown.join(", ")
            ));
        }
    }
}

/// `(item id, tag)` for every collection an item is in; nested collections read `Parent/Child`.
fn collection_tags(account: &Account) -> Vec<(String, String)> {
    fn walk(
        collections: &[crate::export::cxf::Collection],
        account: &str,
        parent: &str,
        out: &mut Vec<(String, String)>,
    ) {
        for collection in collections {
            let title = collection.title.trim();
            let path = match (parent.is_empty(), title.is_empty()) {
                (_, true) => parent.to_owned(),
                (true, false) => title.to_owned(),
                (false, false) => format!("{parent}/{title}"),
            };
            if !path.is_empty() {
                // Items of other accounts (shared with this one) aren't in this exchange.
                let own =
                    |linked: &&LinkedItem| linked.account.as_deref().is_none_or(|a| a == account);
                for linked in collection.items.iter().filter(own) {
                    out.push((linked.item.clone(), path.clone()));
                }
            }
            walk(&collection.sub_collections, account, &path, out);
        }
    }
    let mut out = Vec::new();
    walk(&account.collections, &account.id, "", &mut out);
    out
}

/// An `EditableField` member's value, ignoring empty ones (1Password writes many).
fn text(credential: &Value, key: &str) -> Option<String> {
    let field: Field = serde_json::from_value(credential.get(key)?.clone()).ok()?;
    clean(Some(&field.value))
}

fn kind(credential: &Value) -> &str {
    credential
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// What an item holds, sorted by what it will become.
#[derive(Default)]
struct Parts<'a> {
    logins: Vec<&'a Value>,
    passkeys: Vec<&'a Value>,
    totps: Vec<&'a Value>,
    cards: Vec<&'a Value>,
    names: Vec<&'a Value>,
    addresses: Vec<&'a Value>,
    documents: Vec<&'a Value>,
    notes: Vec<String>,
    custom: Vec<&'a Value>,
    api_keys: Vec<&'a Value>,
    generated: Vec<&'a Value>,
    other: Vec<&'a Value>,
}

fn add_item(
    item: &CxfItem,
    tags: Vec<String>,
    timestamp: Option<u64>,
    out: &mut Collector,
    stats: &mut Stats,
) {
    let meta = ItemMeta {
        created_at: item
            .creation_at
            .and_then(|t| i64::try_from(t).ok())
            .and_then(unix_time),
        updated_at: item
            .modified_at
            .and_then(|t| i64::try_from(t).ok())
            .and_then(unix_time),
        last_used_at: None,
        source_id: clean(Some(&item.id)),
    };
    let before = out.count();
    add_parts(item, tags, timestamp, out, stats);
    out.meta_since(before, &meta);
}

fn add_parts(
    item: &CxfItem,
    tags: Vec<String>,
    timestamp: Option<u64>,
    out: &mut Collector,
    stats: &mut Stats,
) {
    let mut parts = Parts::default();
    for credential in &item.credentials {
        match kind(credential) {
            "basic-auth" => parts.logins.push(credential),
            "passkey" => parts.passkeys.push(credential),
            "totp" => parts.totps.push(credential),
            "credit-card" => parts.cards.push(credential),
            "person-name" => parts.names.push(credential),
            "address" => parts.addresses.push(credential),
            "identity-document" | "drivers-license" | "passport" => {
                parts.documents.push(credential)
            }
            "note" => parts.notes.extend(text(credential, "content")),
            "custom-fields" => parts.custom.push(credential),
            "api-key" => parts.api_keys.push(credential),
            "generated-password" => parts.generated.push(credential),
            "wifi" | "ssh-key" => parts.other.push(credential),
            "file" => stats.files += 1,
            "item-reference" => {}
            unknown => {
                let unknown = unknown.chars().take(40).collect::<String>();
                if !unknown.is_empty() && !stats.unknown.contains(&unknown) {
                    stats.unknown.push(unknown);
                }
            }
        }
    }
    let title = clean(Some(&item.title)).or_else(|| clean(item.subtitle.as_deref()));
    let favorite = item.favorite.unwrap_or(false);
    let created = rfc3339(
        item.creation_at
            .or(timestamp)
            .and_then(|t| i64::try_from(t).ok())
            .unwrap_or(0),
    );
    let mut urls: Vec<String> = Vec::new();
    if let Some(scope) = &item.scope {
        urls.extend(scope.urls.iter().filter_map(|url| website(url)));
        urls.extend(
            scope
                .android_apps
                .iter()
                .filter_map(|app| clean(Some(&app.bundle_id)))
                .map(|id| format!("{ANDROID_APP}{id}")),
        );
    }
    let notes = clean(Some(&parts.notes.join("\n\n")));
    let is_credential =
        !parts.logins.is_empty() || !parts.passkeys.is_empty() || !parts.totps.is_empty();
    // An API key with a card keeps to the card, as it did: only the card's item can hold both.
    let is_login = is_credential || (!parts.api_keys.is_empty() && !parts.cards.is_empty());
    if !is_credential
        && parts.cards.is_empty()
        && (parts
            .custom
            .iter()
            .any(|group| octa_pass_type(group).is_some())
            || !parts.documents.is_empty()
            || !parts.api_keys.is_empty())
    {
        add_typed(&parts, title, urls, notes, &tags, favorite, out);
    } else if is_login {
        add_login(
            &parts,
            title.clone(),
            urls,
            notes,
            &tags,
            favorite,
            &created,
            out,
            stats,
        );
        // A card kept with a login is an item of its own.
        for card in &parts.cards {
            add_card(card, None, title.clone(), &tags, favorite, out);
        }
    } else if let Some((first, rest)) = parts.cards.split_first() {
        let lines = other_lines(&parts, &[]);
        add_card(
            first,
            notes_with(&lines, notes),
            title.clone(),
            &tags,
            favorite,
            out,
        );
        for card in rest {
            add_card(card, None, title.clone(), &tags, favorite, out);
        }
    } else if !parts.names.is_empty() || !parts.addresses.is_empty() || !parts.documents.is_empty()
    {
        add_identity(&parts, title, notes, tags, favorite, out);
    } else if add_ssh_key(&parts, title.clone(), notes.clone(), &tags, favorite, out)
        || add_wifi(&parts, title.clone(), notes.clone(), &tags, favorite, out)
    {
        // Done.
    } else if let Some(generated) = parts.generated.first() {
        let mut details = build::login_details();
        details.password = generated
            .get("password")
            .and_then(Value::as_str)
            .and_then(|p| build::clean_password(Some(p)));
        details.notes = notes_with(&other_lines(&parts, &[]), notes);
        out.add(crate::item::Item {
            overview: build::overview(ItemType::Password, title, urls, None, tags, favorite),
            details: ItemDetails::Login(details),
        });
    } else {
        let lines = other_lines(&parts, &[]);
        match notes_with(&lines, notes) {
            Some(notes) => out.add(build::note(title, tags, favorite, Some(notes))),
            None if urls.is_empty() => out.skip(Some(format!(
                "\"{}\" skipped: nothing Octa Pass can import.",
                title.as_deref().unwrap_or("Untitled")
            ))),
            None => {
                let fields = LoginFields {
                    title,
                    urls,
                    tags,
                    favorite,
                    ..LoginFields::default()
                };
                out.add_login(fields, String::new);
            }
        }
    }
}

/// The Octa Pass type a `custom-fields` credential holds, from its extension.
fn octa_pass_type(group: &Value) -> Option<ItemType> {
    let extension = group
        .get("extensions")?
        .as_array()?
        .iter()
        .find(|extension| {
            extension.get("name").and_then(Value::as_str) == Some(ITEM_TYPE_EXTENSION)
        })?;
    let name = extension.get("itemType")?.as_str()?;
    (name == "custom" || !fields_of(name).is_empty()).then(|| ItemType::from(name.to_owned()))
}

/// An item made from a `custom-fields` credential Octa Pass wrote: a field's `id` says where it goes.
fn read_typed_fields(group: &Value, item: &mut TypedItem) {
    let mut addresses: Vec<(usize, [Option<String>; 3])> = Vec::new();
    for field in group
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|field| serde_json::from_value::<Field>(field.clone()).ok())
    {
        let hidden = field.field_type == "concealed-string";
        let label = field.label.as_deref().unwrap_or("Field");
        let path = field
            .id
            .as_deref()
            .and_then(|id| b64_decode(id).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default();
        let parts: Vec<&str> = path.split('.').collect();
        match parts.as_slice() {
            ["addresses", index, part] => {
                let Ok(index) = index.parse() else {
                    item.custom(label, &field.value, hidden);
                    continue;
                };
                let at = addresses
                    .iter()
                    .position(|(i, _)| *i == index)
                    .unwrap_or_else(|| {
                        addresses.push((index, Default::default()));
                        addresses.len() - 1
                    });
                let slot = match *part {
                    "address" => 0,
                    "network" => 1,
                    _ => 2,
                };
                addresses[at].1[slot] = Some(field.value);
            }
            ["fields", _, kind] => item.field(label, &field.value, kind),
            [key] if !key.is_empty() && *key != "customFields" => {
                item.set(key, Some(field.value));
            }
            _ => item.custom(label, &field.value, hidden),
        }
    }
    for (_, [address, network, label]) in addresses {
        item.address(
            network.as_deref().unwrap_or_default(),
            address.as_deref().unwrap_or_default(),
            label,
        );
    }
}

/// A CXF ID document's fields, on an ID document.
fn read_document(document: &Value, item: &mut TypedItem) {
    let number = match kind(document) {
        "passport" => "passportNumber",
        "drivers-license" => "licenseNumber",
        _ => "documentNumber",
    };
    for (key, member) in [
        ("number", number),
        ("fullName", "fullName"),
        ("birthDate", "birthDate"),
        ("issueDate", "issueDate"),
        ("expiryDate", "expiryDate"),
        ("issuer", "issuingAuthority"),
        ("country", "issuingCountry"),
    ] {
        let value = if key == "number" {
            raw(document, member)
        } else {
            text(document, member)
        };
        item.set(key, value);
    }
    let claimed = [
        "type",
        "id",
        "extensions",
        number,
        "fullName",
        "birthDate",
        "issueDate",
        "expiryDate",
        "issuingAuthority",
        "issuingCountry",
    ];
    for member in document
        .as_object()
        .into_iter()
        .flatten()
        .map(|(key, _)| key)
    {
        if claimed.contains(&member.as_str()) {
            continue;
        }
        // A member a newer version of the format adds counts as a secret.
        let (label, hidden) = match member.as_str() {
            "identificationNumber" | "nationalIdentificationNumber" => ("ID number".into(), true),
            "passportType" => ("Passport type".into(), false),
            "licenseClass" => ("Class".into(), false),
            "country" => ("Country".into(), false),
            "territory" => ("Region".into(), false),
            "nationality" => ("Nationality".into(), false),
            "birthPlace" => ("Birth place".into(), false),
            "sex" => ("Sex".into(), false),
            other => (english_label(other), true),
        };
        if let Some(value) = text(document, member) {
            item.custom(&label, &value, hidden);
        }
    }
}

fn read_api_key(key: &Value, item: &mut TypedItem) {
    item.set("key", raw(key, "key"));
    item.set("username", text(key, "username"));
    item.set("credentialType", text(key, "keyType"));
    item.set("host", text(key, "url"));
    item.set("expiryDate", text(key, "expiryDate"));
    if let Some(value) = text(key, "validFrom") {
        item.custom("Valid from", &value, false);
    }
}

fn document_type(document: &Value) -> &'static str {
    match kind(document) {
        "passport" => "passport",
        "drivers-license" => "driverLicense",
        _ => "nationalId",
    }
}

/// An item with no login or card that is an ID document, an API credential or an Octa Pass type
/// CXF has no credential for. A person's name or address kept with it is an identity of its own, and
/// further documents and API keys are items of their own.
fn add_typed(
    parts: &Parts,
    title: Option<String>,
    urls: Vec<String>,
    notes: Option<String>,
    tags: &[String],
    favorite: bool,
    out: &mut Collector,
) {
    let group = parts
        .custom
        .iter()
        .find(|group| octa_pass_type(group).is_some());
    let item_type =
        group
            .and_then(|group| octa_pass_type(group))
            .unwrap_or(if parts.documents.is_empty() {
                ItemType::ApiCredential
            } else {
                ItemType::IdDocument
            });
    let mut item = TypedItem::new(item_type.clone());
    if let Some(group) = group {
        let label = group.get("label").and_then(Value::as_str);
        if item_type == ItemType::Custom {
            let name = label.filter(|label| *label != english_label("custom"));
            item = TypedItem::custom_item(name.map(str::to_owned));
        }
        read_typed_fields(group, &mut item);
    }
    let mut documents = parts.documents.iter();
    let mut api_keys = parts.api_keys.iter();
    if item_type == ItemType::IdDocument
        && let Some(document) = documents.next()
    {
        if !item.has("documentType") {
            item.set("documentType", Some(document_type(document).to_owned()));
        }
        read_document(document, &mut item);
    }
    if item_type == ItemType::ApiCredential
        && let Some(key) = api_keys.next()
    {
        read_api_key(key, &mut item);
    }
    for extra in parts
        .custom
        .iter()
        .filter(|other| group.is_none_or(|group| !std::ptr::eq(**other, *group)))
        .flat_map(|group| group_fields(group))
    {
        item.custom(&extra.label, &extra.value, extra.hidden);
    }
    let rest = Parts {
        other: parts.other.clone(),
        generated: parts.generated.clone(),
        ..Parts::default()
    };
    for (label, value) in other_lines(&rest, &["custom-fields"]) {
        item.custom(&label, &value, build::looks_secret(&label));
    }
    for url in urls {
        item.url(Some(url));
    }
    out.add(item.build(title.clone(), tags.to_vec(), favorite, notes));
    for document in documents {
        let mut item = TypedItem::id_document(document_type(document));
        read_document(document, &mut item);
        out.add(item.build(title.clone(), tags.to_vec(), favorite, None));
    }
    for key in api_keys {
        let mut item = TypedItem::api_credential();
        read_api_key(key, &mut item);
        out.add(item.build(title.clone(), tags.to_vec(), favorite, None));
    }
    if !parts.names.is_empty() || !parts.addresses.is_empty() {
        let person = Parts {
            names: parts.names.clone(),
            addresses: parts.addresses.clone(),
            ..Parts::default()
        };
        add_identity(&person, title, None, tags.to_vec(), favorite, out);
    }
}

/// An item whose main credential is an `ssh-key`, as an SSH key. False when it has none, or its key
/// doesn't read (the item then becomes a note with the key in it).
fn add_ssh_key(
    parts: &Parts,
    title: Option<String>,
    notes: Option<String>,
    tags: &[String],
    favorite: bool,
    out: &mut Collector,
) -> bool {
    let Some(credential) = parts.other.iter().find(|c| kind(c) == "ssh-key") else {
        return false;
    };
    let member = |key: &str| {
        credential
            .get(key)
            .and_then(Value::as_str)
            .and_then(|v| clean(Some(v)))
    };
    let comment = member("keyComment").unwrap_or_default();
    let Some(der) = member("privateKey").and_then(|k| b64_decode(&k).ok()) else {
        return false;
    };
    let Ok(key) = crate::tools::ssh::from_pkcs8_der(&zeroize::Zeroizing::new(der), &comment) else {
        return false;
    };
    let mut custom: Vec<CustomField> = parts.custom.iter().flat_map(|g| group_fields(g)).collect();
    let passphrase = custom
        .iter()
        .position(|f| f.label.eq_ignore_ascii_case("passphrase"))
        .map(|i| custom.remove(i).value);
    let mut lines = other_lines(parts, &["ssh-key", "custom-fields"]);
    for (member, label) in [
        ("creationDate", "Created"),
        ("expiryDate", "Expires"),
        ("keyGenerationSource", "Generated at"),
    ] {
        if let Some(value) = text(credential, member) {
            lines.push((label.into(), value));
        }
    }
    let details = SshKeyDetails {
        schema_version: SCHEMA_VERSION,
        private_key: Some(key.private_key.to_string()),
        public_key: Some(key.info.public_key),
        key_type: Some(key.info.key_type),
        fingerprint: Some(key.info.fingerprint.clone()),
        comment: clean(Some(&comment)),
        passphrase,
        notes: notes_with(&lines, notes),
        custom_fields: (!custom.is_empty()).then_some(custom),
        extra: Default::default(),
    };
    out.add(crate::item::Item {
        overview: build::overview(
            ItemType::SshKey,
            title,
            Vec::new(),
            Some(key.info.fingerprint),
            tags.to_vec(),
            favorite,
        ),
        details: ItemDetails::SshKey(details),
    });
    true
}

/// A `wifi` credential as a Wi-Fi network. Settings CXF has no member for (Enterprise ones, and
/// security types other than Personal ones) come in custom fields, as Octa Pass exports them.
fn add_wifi(
    parts: &Parts,
    title: Option<String>,
    notes: Option<String>,
    tags: &[String],
    favorite: bool,
    out: &mut Collector,
) -> bool {
    let Some(credential) = parts.other.iter().find(|c| kind(c) == "wifi") else {
        return false;
    };
    let Some(ssid) = credential
        .get("ssid")
        .and_then(|field| serde_json::from_value::<Field>(field.clone()).ok())
        .map(|field| field.value)
        .filter(|ssid| !ssid.is_empty())
    else {
        return false;
    };
    let password = credential
        .get("passphrase")
        .and_then(|field| serde_json::from_value::<Field>(field.clone()).ok())
        .and_then(|field| build::clean_password(Some(&field.value)));
    let mut custom: Vec<CustomField> = parts.custom.iter().flat_map(|g| group_fields(g)).collect();
    let mut take = |label: &str| {
        custom
            .iter()
            .position(|f| f.label.eq_ignore_ascii_case(label))
            .and_then(|i| clean(Some(&custom.remove(i).value)))
    };
    let security = take("Security")
        .or_else(|| {
            let kind = text(credential, "networkSecurityType")?;
            Some(
                match kind.as_str() {
                    "unsecured" => "open",
                    "wep" => "wep",
                    "wpa-personal" => "wpa",
                    "wpa2-personal" => "wpa2",
                    "wpa3-personal" => "wpa3",
                    other => other,
                }
                .to_owned(),
            )
        })
        .unwrap_or_else(|| if password.is_some() { "wpa2" } else { "open" }.to_owned());
    let details = WifiDetails {
        schema_version: SCHEMA_VERSION,
        ssid: ssid.clone(),
        security,
        password,
        hidden: text(credential, "hidden")
            .is_some_and(|hidden| hidden.eq_ignore_ascii_case("true"))
            .then_some(true),
        eap_method: take("EAP method"),
        phase2: take("Phase 2"),
        username: take("Username"),
        identity: take("Identity"),
        server_domain: take("Server domain"),
        ca_certificate: take("CA certificate"),
        captive_portal: None,
        managed: None,
        hotspot: None,
        notes: notes_with(&other_lines(parts, &["wifi", "custom-fields"]), notes),
        custom_fields: (!custom.is_empty()).then_some(custom),
        password_history: None,
        extra: Default::default(),
    };
    out.add(crate::item::Item {
        overview: build::overview(
            ItemType::Wifi,
            title,
            Vec::new(),
            Some(ssid),
            tags.to_vec(),
            favorite,
        ),
        details: ItemDetails::Wifi(details),
    });
    true
}

/// A scope URL as a website address: Dashlane writes bare domains.
fn website(url: &str) -> Option<String> {
    let url = clean(Some(url))?;
    if url.contains("://") {
        Some(url)
    } else {
        Some(format!("https://{url}"))
    }
}

#[allow(clippy::too_many_arguments)]
fn add_login(
    parts: &Parts,
    title: Option<String>,
    urls: Vec<String>,
    notes: Option<String>,
    tags: &[String],
    favorite: bool,
    created: &str,
    out: &mut Collector,
    stats: &mut Stats,
) {
    let mut custom_fields = Vec::new();
    let mut totp = parts.totps.iter().filter_map(|t| totp_uri(t));
    let mut first_totp = totp.next();
    for extra in totp {
        custom_fields.push(custom_field("One-time code", &extra, true));
    }
    for group in &parts.custom {
        for field in group_fields(group) {
            // 1Password keeps one-time codes as custom fields.
            if first_totp.is_none() && field.value.to_ascii_lowercase().starts_with("otpauth://") {
                first_totp = Some(field.value);
            } else {
                custom_fields.push(field);
            }
        }
    }
    // The first API key fills the login; any others are kept as fields.
    let api_key = parts.api_keys.first();
    for (index, key) in parts.api_keys.iter().enumerate() {
        let members: &[(&str, &str, bool)] = if index == 0 {
            &[
                ("keyType", "Key type", false),
                ("validFrom", "Valid from", false),
                ("expiryDate", "Expires", false),
            ]
        } else {
            &[
                ("key", "API key", true),
                ("username", "Username", false),
                ("url", "URL", false),
                ("keyType", "Key type", false),
                ("validFrom", "Valid from", false),
                ("expiryDate", "Expires", false),
            ]
        };
        for (member, label, hidden) in members {
            if let Some(value) = text(key, member) {
                custom_fields.push(custom_field(label, &value, *hidden));
            }
        }
    }
    for (label, value) in other_lines(parts, &["api-key", "custom-fields"]) {
        custom_fields.push(custom_field(&label, &value, build::looks_secret(&label)));
    }
    let mut passkeys = Vec::new();
    for credential in &parts.passkeys {
        let record = serde_json::from_value::<CxfPasskey>((*credential).clone())
            .ok()
            .and_then(|passkey| PasskeyRecord::from_cxf(&passkey, created.to_owned()).ok());
        match record {
            Some(record) => passkeys.push(record.to_item()),
            None => stats.passkeys += 1,
        }
    }
    let mut urls = urls;
    let login = parts.logins.first();
    let username = login
        .and_then(|l| text(l, "username"))
        .or_else(|| api_key.and_then(|k| text(k, "username")))
        .or_else(|| passkeys.first().map(|p| p.user_name.clone()));
    let password = login
        .and_then(|l| raw(l, "password"))
        .or_else(|| api_key.and_then(|k| raw(k, "key")));
    if let Some(url) = api_key
        .and_then(|k| text(k, "url"))
        .and_then(|u| website(&u))
    {
        urls.push(url);
    }
    let fields = LoginFields {
        title: title.clone(),
        urls: urls.clone(),
        username,
        password,
        totp: first_totp,
        notes,
        tags: tags.to_vec(),
        favorite,
        custom_fields,
        passkeys,
        ..LoginFields::default()
    };
    out.add_login(fields, || "An empty login was skipped.".into());
    // Further username/password pairs in the same item.
    for extra in parts.logins.iter().skip(1) {
        let fields = LoginFields {
            title: title.clone(),
            urls: urls.clone(),
            username: text(extra, "username"),
            password: raw(extra, "password"),
            tags: tags.to_vec(),
            ..LoginFields::default()
        };
        out.add_login(fields, || "An empty login was skipped.".into());
    }
}

/// A field's value with its spaces, for passwords and keys.
fn raw(credential: &Value, key: &str) -> Option<String> {
    let field: Field = serde_json::from_value(credential.get(key)?.clone()).ok()?;
    build::clean_password(Some(&field.value))
}

/// The `otpauth://` URI of a `totp` credential, or `None` for an algorithm the spec says to skip.
fn totp_uri(totp: &Value) -> Option<String> {
    let secret = totp.get("secret")?.as_str()?;
    let mut params = OtpParams::parse(secret).ok()?;
    params.algorithm = match totp
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or("sha1")
    {
        "sha1" => OtpAlgorithm::Sha1,
        "sha256" => OtpAlgorithm::Sha256,
        "sha512" => OtpAlgorithm::Sha512,
        _ => return None,
    };
    let number = |key: &str, default: u64| totp.get(key).and_then(Value::as_u64).unwrap_or(default);
    params.digits = u32::try_from(number("digits", 6)).ok()?;
    params.kind = OtpKind::Totp {
        period: number("period", 30),
    };
    params.issuer = totp
        .get("issuer")
        .and_then(Value::as_str)
        .and_then(|i| clean(Some(i)));
    params.account = totp
        .get("username")
        .and_then(Value::as_str)
        .and_then(|a| clean(Some(a)));
    // Out-of-range digits or periods are refused by parsing the URI back.
    let uri = params.to_uri();
    OtpParams::parse(&uri).ok()?;
    Some(uri.to_string())
}

/// A `custom-fields` credential's non-empty fields. The group's label prefixes unlabelled ones.
fn group_fields(group: &Value) -> Vec<CustomField> {
    let label = group
        .get("label")
        .and_then(Value::as_str)
        .and_then(|l| clean(Some(l)));
    group
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|field| serde_json::from_value::<Field>(field.clone()).ok())
        .filter(|field| !field.value.trim().is_empty())
        .map(|field| {
            let name = clean(field.label.as_deref())
                .or_else(|| label.clone())
                .unwrap_or_else(|| "Field".into());
            let value = match field.field_type.as_str() {
                "concealed-string" => field.value,
                _ => field.value.trim().to_owned(),
            };
            custom_field(&name, &value, field.field_type == "concealed-string")
        })
        .collect()
}

/// `Label: value` lines for the credentials an item's type doesn't use (`skip` kinds aside).
fn other_lines(parts: &Parts, skip: &[&str]) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    for credential in &parts.other {
        match kind(credential) {
            "wifi" if !skip.contains(&"wifi") => {
                for (member, label) in [
                    ("ssid", "Network"),
                    ("passphrase", "Password"),
                    ("networkSecurityType", "Security"),
                    ("hidden", "Hidden network"),
                ] {
                    if let Some(value) = text(credential, member) {
                        lines.push((label.to_owned(), value));
                    }
                }
            }
            "ssh-key" if !skip.contains(&"ssh-key") => {
                let field = |key: &str| {
                    credential
                        .get(key)
                        .and_then(Value::as_str)
                        .and_then(|v| clean(Some(v)))
                };
                if let Some(kind) = field("keyType") {
                    lines.push(("Key type".into(), kind));
                }
                if let Some(comment) = field("keyComment") {
                    lines.push(("Comment".into(), comment));
                }
                if let Some(pem) = field("privateKey").and_then(|k| pem(&k)) {
                    lines.push(("Private key".into(), pem));
                }
                for (member, label) in [
                    ("creationDate", "Created"),
                    ("expiryDate", "Expires"),
                    ("keyGenerationSource", "Generated at"),
                ] {
                    if let Some(value) = text(credential, member) {
                        lines.push((label.into(), value));
                    }
                }
            }
            _ => {}
        }
    }
    if !skip.contains(&"api-key") {
        for key in &parts.api_keys {
            for (member, label) in [
                ("key", "API key"),
                ("username", "Username"),
                ("keyType", "Key type"),
                ("url", "URL"),
                ("validFrom", "Valid from"),
                ("expiryDate", "Expires"),
            ] {
                if let Some(value) = text(key, member) {
                    lines.push((label.into(), value));
                }
            }
        }
    }
    for generated in &parts.generated {
        if let Some(password) = generated.get("password").and_then(Value::as_str) {
            lines.push(("Generated password".into(), password.to_owned()));
        }
    }
    for document in &parts.documents {
        lines.extend(document_lines(document));
    }
    if !skip.contains(&"custom-fields") {
        for group in &parts.custom {
            lines.extend(group_fields(group).into_iter().map(|f| (f.label, f.value)));
        }
    }
    lines
}

/// A PKCS#8 key (base64url DER) as PEM.
fn pem(key: &str) -> Option<String> {
    use base64::Engine;
    let der = zeroize::Zeroizing::new(b64_decode(key).ok()?);
    let body = zeroize::Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*der));
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect();
    Some(format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        lines.join("\n")
    ))
}

fn document_lines(document: &Value) -> Vec<(String, String)> {
    let heading = match kind(document) {
        "passport" => "Passport",
        "drivers-license" => "Driver's license",
        _ => "ID document",
    };
    let mut lines = vec![("Type".to_owned(), heading.to_owned())];
    for (member, label) in [
        ("fullName", "Name"),
        ("documentNumber", "Number"),
        ("passportNumber", "Number"),
        ("licenseNumber", "Number"),
        ("identificationNumber", "ID number"),
        ("nationalIdentificationNumber", "ID number"),
        ("passportType", "Passport type"),
        ("licenseClass", "Class"),
        ("issuingCountry", "Issuing country"),
        ("country", "Country"),
        ("territory", "Region"),
        ("nationality", "Nationality"),
        ("birthDate", "Birth date"),
        ("birthPlace", "Birth place"),
        ("sex", "Sex"),
        ("issueDate", "Issued"),
        ("expiryDate", "Expires"),
        ("issuingAuthority", "Issued by"),
    ] {
        if let Some(value) = text(document, member) {
            lines.push((label.to_owned(), value));
        }
    }
    if lines.len() == 1 { Vec::new() } else { lines }
}

fn add_card(
    card: &Value,
    notes: Option<String>,
    title: Option<String>,
    tags: &[String],
    favorite: bool,
    out: &mut Collector,
) {
    let mut details = card_details();
    details.number = text(card, "number").map(|n| n.replace(' ', ""));
    details.cardholder = text(card, "fullName");
    details.brand = text(card, "cardType");
    details.cvv = text(card, "verificationNumber");
    details.pin = text(card, "pin");
    details.expiry = text(card, "expiryDate").map(|date| {
        // `YYYY-MM` → `MM/YY`; anything else as written.
        date.split_once('-')
            .and_then(|(year, month)| build::expiry(month.parse().ok()?, year.parse().ok()?))
            .unwrap_or(date)
    });
    let valid_from = text(card, "validFrom").map(|v| ("Valid from".to_owned(), v));
    details.notes = notes_with(&valid_from.into_iter().collect::<Vec<_>>(), notes);
    let title = title
        .or_else(|| details.brand.clone())
        .or_else(|| details.cardholder.clone());
    out.add(build::card(title, tags.to_vec(), favorite, details));
}

fn add_identity(
    parts: &Parts,
    title: Option<String>,
    notes: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    out: &mut Collector,
) {
    let mut details = identity_details();
    let mut lines = Vec::new();
    if let Some(name) = parts.names.first() {
        details.first_name = text(name, "given");
        let surname: Vec<String> = ["surnamePrefix", "surname", "surname2"]
            .iter()
            .filter_map(|key| text(name, key))
            .collect();
        details.last_name = clean(Some(&surname.join(" ")));
        for (member, label) in [
            ("title", "Title"),
            ("givenInformal", "Nickname"),
            ("given2", "Middle name"),
            ("credentials", "Credentials"),
            ("generation", "Generation"),
        ] {
            if let Some(value) = text(name, member) {
                lines.push((label.to_owned(), value));
            }
        }
    }
    if let Some(address) = parts.addresses.first() {
        let street = text(address, "streetAddress").unwrap_or_default();
        let mut street = street.splitn(2, '\n');
        details.address = build::address(
            clean(street.next()),
            clean(street.next()),
            text(address, "city"),
            text(address, "territory"),
            text(address, "postalCode"),
            text(address, "country"),
        );
        details.phone = text(address, "tel");
    }
    for document in &parts.documents {
        if details.birth_date.is_none() {
            details.birth_date = text(document, "birthDate");
        }
    }
    // Email and birth date come in custom fields (that's how Octa Pass exports them).
    let mut custom = Vec::new();
    for group in &parts.custom {
        let fields: Vec<(String, Field)> = group
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|f| serde_json::from_value::<Field>(f.clone()).ok())
            .filter(|f| !f.value.trim().is_empty())
            .map(|f| (f.label.clone().unwrap_or_default(), f))
            .collect();
        for (label, field) in fields {
            let lower = label.to_lowercase();
            if field.field_type == "email" && details.email.is_none() {
                details.email = clean(Some(&field.value));
            } else if field.field_type == "date"
                && lower.contains("birth")
                && details.birth_date.is_none()
            {
                details.birth_date = clean(Some(&field.value));
            } else {
                let label = if label.trim().is_empty() {
                    "Field".into()
                } else {
                    label
                };
                custom.push((label, field.value));
            }
        }
    }
    let other = Parts {
        other: parts.other.clone(),
        api_keys: parts.api_keys.clone(),
        generated: parts.generated.clone(),
        documents: parts.documents.clone(),
        ..Parts::default()
    };
    lines.extend(other_lines(&other, &[]));
    for extra in parts.addresses.iter().skip(1) {
        for (member, label) in [
            ("streetAddress", "Address"),
            ("city", "City"),
            ("postalCode", "Postal code"),
            ("country", "Country"),
            ("tel", "Phone"),
        ] {
            if let Some(value) = text(extra, member) {
                lines.push((label.to_owned(), value));
            }
        }
    }
    lines.extend(custom);
    details.notes = notes_with(&lines, notes);
    let title = title.or_else(|| {
        clean(Some(
            &[details.first_name.clone(), details.last_name.clone()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" "),
        ))
    });
    out.add(build::identity(title, tags, favorite, details));
}
