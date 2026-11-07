//! Building items from imported fields, and collecting results and warnings.

use serde_json::{Map, Value};

use super::{ImportResult, ImportedCode, TotpUpdate};
use crate::item::{
    Address, CardDetails, CustomField, IdentityDetails, ImportedFrom, Item, ItemDetails,
    ItemOverview, ItemType, LoginDetails, Passkey, PasswordHistoryEntry, RecoveryInfo,
    SCHEMA_VERSION, SecureNoteDetails, SecurityQuestion, TypedField, WalletAddress,
};
use crate::item_fields::{FieldKind, english_label, fields_of, subtitle_key};
use crate::matching::Site;
use crate::tools::otpauth::OtpParams;

const MAX_WARNINGS: usize = 20;

/// Collects items, skips and warnings. Warnings are capped so a broken file can't flood the UI.
#[derive(Default)]
pub(super) struct Collector {
    result: ImportResult,
}

impl Collector {
    pub fn add(&mut self, item: Item) {
        self.result.items.push(item);
    }

    /// How many items were added so far, for [`Collector::meta_since`].
    pub fn count(&self) -> usize {
        self.result.items.len()
    }

    /// Gives the items added since `count` the app's dates and id: for an entry that the
    /// importer turns into an item in several ways.
    pub fn meta_since(&mut self, count: usize, meta: &ItemMeta) {
        for item in self.result.items.iter_mut().skip(count) {
            meta.clone().apply(&mut item.overview);
        }
    }

    pub fn attach_totp(&mut self, update: TotpUpdate) {
        self.result.totp_updates.push(update);
    }

    /// A one-time code that joins a login already in the vault, listed for the import review.
    pub fn attach_code(&mut self, update: TotpUpdate, params: &OtpParams, title: String) {
        self.result.codes.push(ImportedCode {
            item: None,
            update: Some(self.result.totp_updates.len()),
            title,
            issuer: params.issuer.clone(),
            account: params.account.clone(),
        });
        self.attach_totp(update);
    }

    /// A new login made for a one-time code, listed for the import review. `false` when there
    /// was nothing to add.
    pub fn add_code(&mut self, fields: LoginFields, params: &OtpParams) -> bool {
        let title = fields.title.clone().unwrap_or_default();
        let Some(item) = fields.build(self) else {
            return false;
        };
        let has_code = matches!(&item.details, ItemDetails::Login(login) if login.totp.is_some());
        if has_code {
            self.result.codes.push(ImportedCode {
                item: Some(self.result.items.len()),
                update: None,
                title,
                issuer: params.issuer.clone(),
                account: params.account.clone(),
            });
        }
        self.add(item);
        true
    }

    /// Without a warning when the caller reports a batch of skips in one line instead.
    pub fn skip(&mut self, warning: Option<String>) {
        self.result.skipped += 1;
        if let Some(warning) = warning {
            self.warn(warning);
        }
    }

    pub fn warn(&mut self, warning: impl Into<String>) {
        self.result.warnings.push(warning.into());
    }

    /// Adds a login (or note), or skips the row with `skipped` as the reason.
    pub fn add_login(&mut self, fields: LoginFields, skipped: impl FnOnce() -> String) {
        match fields.build(self) {
            Some(item) => self.add(item),
            None => self.skip(Some(skipped())),
        }
    }

    pub fn finish(mut self) -> ImportResult {
        let warnings = &mut self.result.warnings;
        if warnings.len() > MAX_WARNINGS {
            let more = warnings.len() - MAX_WARNINGS;
            warnings.truncate(MAX_WARNINGS);
            warnings.push(format!("…and {more} more."));
        }
        self.result
    }
}

/// Trimmed text, or `None` when empty, so no empty strings get written.
pub(super) fn clean(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Passwords keep their spaces: leading or trailing ones can be part of the password.
pub(super) fn clean_password(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.is_empty()).map(str::to_string)
}

pub(super) fn is_true(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("true" | "yes" | "y" | "1")
    )
}

pub(super) fn split_tags(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split([';', ','])
        .filter_map(|tag| clean(Some(tag)))
        .collect()
}

/// Field labels that hold secrets, so their custom fields start hidden.
pub(super) fn looks_secret(label: &str) -> bool {
    let label = label.to_lowercase();
    [
        "password",
        "secret",
        "pin",
        "cvv",
        "cvc",
        "code",
        "key",
        "token",
        "passphrase",
    ]
    .iter()
    .any(|word| label.contains(word))
}

pub(super) fn custom_field(label: &str, value: &str, hidden: bool) -> CustomField {
    CustomField {
        label: label.trim().to_string(),
        value: value.to_string(),
        hidden,
        extra: Map::new(),
    }
}

/// Unclaimed CSV columns as custom fields, hidden when the header suggests a secret.
pub(super) fn extra_fields(extras: Vec<(String, String)>) -> Vec<CustomField> {
    extras
        .into_iter()
        .map(|(label, value)| custom_field(&label, &value, looks_secret(&label)))
        .collect()
}

pub(super) fn skipped_row(line: u64) -> String {
    format!("Row {line} skipped: no URL, username, password or notes.")
}

/// `"Label: value"` lines for fields an item type has no place for, ahead of the notes.
pub(super) fn notes_with(lines: &[(String, String)], notes: Option<String>) -> Option<String> {
    let mut parts: Vec<String> = lines
        .iter()
        .filter(|(_, value)| !value.trim().is_empty())
        .map(|(label, value)| {
            let value = value.trim();
            // Multi-line values (keys, addresses) start on their own line.
            if value.contains('\n') {
                format!("{label}:\n{value}")
            } else {
                format!("{label}: {value}")
            }
        })
        .collect();
    parts.extend(notes);
    clean(Some(&parts.join("\n")))
}

pub(super) fn overview(
    item_type: ItemType,
    title: Option<String>,
    urls: Vec<String>,
    subtitle: Option<String>,
    tags: Vec<String>,
    favorite: bool,
) -> ItemOverview {
    let mut tags: Vec<String> = tags.into_iter().filter_map(|t| clean(Some(&t))).collect();
    tags.dedup();
    ItemOverview {
        schema_version: SCHEMA_VERSION,
        title: clean(title.as_deref())
            .or_else(|| urls.first().and_then(|url| title_from_url(url)))
            .unwrap_or_else(|| "Untitled".into()),
        item_type,
        urls: (!urls.is_empty()).then_some(urls),
        subtitle,
        tags: (!tags.is_empty()).then_some(tags),
        favorite: favorite.then_some(true),
        created_at: None,
        updated_at: None,
        last_used_at: None,
        imported_from: None,
        extra: Map::new(),
    }
}

/// What an app records about any item besides its fields: its dates and its own id.
#[derive(Debug, Default, Clone, PartialEq)]
pub(super) struct ItemMeta {
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub last_used_at: Option<String>,
    /// The item's id in that app, kept as `importedFrom` so importing the file again updates the
    /// item instead of adding a copy. [`super::import_file`] fills in the source.
    pub source_id: Option<String>,
}

impl ItemMeta {
    pub fn apply(self, overview: &mut ItemOverview) {
        overview.created_at = self.created_at;
        overview.updated_at = self.updated_at;
        overview.last_used_at = self.last_used_at;
        overview.imported_from = clean(self.source_id.as_deref()).map(|id| ImportedFrom {
            source: String::new(),
            id,
            extra: Map::new(),
        });
    }
}

/// `item` with `meta`'s dates and id.
pub(super) fn with_meta(mut item: Item, meta: ItemMeta) -> Item {
    meta.apply(&mut item.overview);
    item
}

/// `github.com` for `https://www.github.com/login`; the app id for `android://…@com.example/`.
fn title_from_url(url: &str) -> Option<String> {
    if let Ok(site) = Site::parse(url) {
        return Some(site.display_host());
    }
    let parsed = url::Url::parse(url).ok()?;
    clean(parsed.host_str())
}

/// The fields of a login. Builds a secure note when there are only notes, and nothing when
/// there is nothing worth keeping.
#[derive(Default)]
pub(super) struct LoginFields {
    pub title: Option<String>,
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub custom_fields: Vec<CustomField>,
    pub password_history: Vec<PasswordHistoryEntry>,
    pub passkeys: Vec<Passkey>,
    /// Dates and the app's id for the item.
    pub meta: ItemMeta,
    pub password_changed_at: Option<String>,
    /// HTTP authentication realm (Firefox).
    pub http_realm: Option<String>,
    pub security_questions: Vec<SecurityQuestion>,
    /// Overview fields beyond the model's own, such as `urlMatch`.
    pub overview_extra: Map<String, serde_json::Value>,
    /// Login details beyond the model's own, such as `autoType`.
    pub details_extra: Map<String, serde_json::Value>,
}

impl LoginFields {
    pub fn build(self, out: &mut Collector) -> Option<Item> {
        let urls: Vec<String> = self.urls.iter().filter_map(|u| clean(Some(u))).collect();
        let username = clean(self.username.as_deref());
        let password = clean_password(self.password.as_deref());
        let mut custom_fields = self.custom_fields;
        let mut security_questions = self.security_questions;
        pair_security_questions(&mut custom_fields, &mut security_questions);
        let totp = clean(self.totp.as_deref()).and_then(|totp| {
            if OtpParams::parse(&totp).is_ok() {
                Some(totp)
            } else {
                // Steam codes and typos: kept, but not as a code the app would fail to compute.
                out.warn(format!(
                    "\"{}\": the one-time code setup isn't a TOTP secret, so it was kept as a hidden field.",
                    self.title.as_deref().unwrap_or("Untitled")
                ));
                custom_fields.push(custom_field("One-time code", &totp, true));
                None
            }
        });
        let notes = clean(self.notes.as_deref());
        let empty = urls.is_empty()
            && username.is_none()
            && password.is_none()
            && totp.is_none()
            && custom_fields.is_empty()
            && security_questions.is_empty()
            && self.passkeys.is_empty();
        if empty {
            let notes = notes?;
            let mut overview = overview(
                ItemType::SecureNote,
                self.title,
                vec![],
                None,
                self.tags,
                self.favorite,
            );
            self.meta.apply(&mut overview);
            return Some(Item {
                overview,
                details: ItemDetails::SecureNote(secure_note(notes)),
            });
        }
        let mut overview = overview(
            ItemType::Login,
            self.title,
            urls,
            username.clone(),
            self.tags,
            self.favorite,
        );
        overview.extra = self.overview_extra;
        self.meta.apply(&mut overview);
        Some(Item {
            overview,
            details: ItemDetails::Login(LoginDetails {
                username,
                password,
                totp,
                notes,
                custom_fields: (!custom_fields.is_empty()).then_some(custom_fields),
                password_history: (!self.password_history.is_empty())
                    .then_some(self.password_history),
                passkeys: (!self.passkeys.is_empty()).then_some(self.passkeys),
                recovery: (!security_questions.is_empty()).then(|| RecoveryInfo {
                    security_questions: Some(security_questions),
                    ..RecoveryInfo::default()
                }),
                password_changed_at: self.password_changed_at,
                http_realm: clean(self.http_realm.as_deref()),
                extra: self.details_extra,
                ..login_details()
            }),
        })
    }
}

/// One security question, as apps' exports give it.
pub(super) fn security_question(question: &str, answer: &str) -> SecurityQuestion {
    SecurityQuestion {
        question: question.trim().to_string(),
        answer: answer.to_string(),
        extra: Map::new(),
    }
}

/// Moves a "Security question" field followed by its "Security answer" into the login's recovery
/// info. A question or answer without its other half stays a custom field.
fn pair_security_questions(fields: &mut Vec<CustomField>, questions: &mut Vec<SecurityQuestion>) {
    let named = |field: &CustomField, name: &str| field.label.trim().eq_ignore_ascii_case(name);
    let mut at = 0;
    while at + 1 < fields.len() {
        if named(&fields[at], "Security question") && named(&fields[at + 1], "Security answer") {
            questions.push(security_question(&fields[at].value, &fields[at + 1].value));
            fields.drain(at..at + 2);
        } else {
            at += 1;
        }
    }
}

pub(super) fn login_details() -> LoginDetails {
    LoginDetails {
        schema_version: SCHEMA_VERSION,
        username: None,
        password: None,
        totp: None,
        notes: None,
        passkeys: None,
        recovery: None,
        custom_fields: None,
        password_history: None,
        password_changed_at: None,
        http_realm: None,
        extra: Map::new(),
    }
}

/// An item of a type from the field table (`crate::item_fields`), or a custom item. Each app's field
/// goes to its place with [`TypedItem::set`]; nothing is ever dropped: a value with no place, a second
/// value for a place that's taken, and a date that can't be read all become custom fields.
pub(super) struct TypedItem {
    item_type: ItemType,
    details: Map<String, Value>,
    custom_fields: Vec<CustomField>,
    addresses: Vec<WalletAddress>,
    fields: Vec<TypedField>,
    password_history: Vec<PasswordHistoryEntry>,
    urls: Vec<String>,
}

impl TypedItem {
    pub fn new(item_type: ItemType) -> Self {
        Self {
            item_type,
            details: Map::new(),
            custom_fields: Vec::new(),
            addresses: Vec::new(),
            fields: Vec::new(),
            password_history: Vec::new(),
            urls: Vec::new(),
        }
    }

    pub fn bank_account() -> Self {
        Self::new(ItemType::BankAccount)
    }

    pub fn api_credential() -> Self {
        Self::new(ItemType::ApiCredential)
    }

    pub fn software_license() -> Self {
        Self::new(ItemType::SoftwareLicense)
    }

    /// `document_type` is `passport`, `driverLicense`, `nationalId` or `other`.
    pub fn id_document(document_type: &str) -> Self {
        let mut item = Self::new(ItemType::IdDocument);
        item.set("documentType", Some(document_type.to_owned()));
        item
    }

    pub fn crypto_wallet() -> Self {
        Self::new(ItemType::CryptoWallet)
    }

    /// `database_type` is one of the table's choices, or the words the app used.
    pub fn database(database_type: Option<String>) -> Self {
        let mut item = Self::new(ItemType::Database);
        item.set("databaseType", database_type);
        item
    }

    pub fn custom_item(template_name: Option<String>) -> Self {
        let mut item = Self::new(ItemType::Custom);
        if let Some(name) = clean(template_name.as_deref()) {
            item.details.insert("templateName".into(), name.into());
        }
        item
    }

    pub fn kind(&self) -> &ItemType {
        &self.item_type
    }

    pub fn has(&self, key: &str) -> bool {
        self.details.contains_key(key)
    }

    /// A value for a field of the table. Secrets keep their spaces; other values are trimmed; dates
    /// are normalised. Whatever doesn't fit is kept as a custom field.
    pub fn set(&mut self, key: &str, value: Option<String>) {
        let name = String::from(self.item_type.clone());
        let Some(spec) = fields_of(&name).iter().find(|spec| spec.key == key) else {
            if let Some(value) = clean(value.as_deref()) {
                self.custom(&english_label(key), &value, true);
            }
            return;
        };
        let secret = spec.kind.is_secret();
        let value = if secret {
            clean_password(value.as_deref())
        } else {
            clean(value.as_deref())
        };
        let Some(value) = value else {
            return;
        };
        let value = match spec.kind {
            FieldKind::Date => date_only(&value).ok_or(value),
            FieldKind::Choice => Ok(known_choice(spec.choices, value)),
            _ => Ok(value),
        };
        match value {
            Ok(value) if !self.details.contains_key(key) => {
                self.details.insert(key.to_owned(), value.into());
            }
            Ok(value) | Err(value) => self.custom(&english_label(key), &value, secret),
        }
    }

    /// A field with no place in the table. On a custom item it's one of its fields.
    pub fn custom(&mut self, label: &str, value: &str, hidden: bool) {
        if value.trim().is_empty() {
            return;
        }
        if self.item_type == ItemType::Custom {
            self.field(label, value, if hidden { "hidden" } else { "text" });
        } else {
            self.custom_fields.push(custom_field(label, value, hidden));
        }
    }

    /// A field of a custom item, as it was, however empty.
    pub fn field(&mut self, label: &str, value: &str, kind: &str) {
        self.fields.push(TypedField {
            label: label.trim().to_owned(),
            value: value.to_owned(),
            kind: kind.to_owned(),
            extra: Map::new(),
        });
    }

    /// A wallet's receiving address.
    pub fn address(&mut self, network: &str, address: &str, label: Option<String>) {
        if let Some(address) = clean(Some(address)) {
            self.addresses.push(WalletAddress {
                network: network.trim().to_owned(),
                address,
                label: clean(label.as_deref()),
                extra: Map::new(),
            });
        }
    }

    pub fn url(&mut self, url: Option<String>) {
        if let Some(url) = clean(url.as_deref())
            && !self.urls.contains(&url)
        {
            self.urls.push(url);
        }
    }

    pub fn password_history(&mut self, history: Vec<PasswordHistoryEntry>) {
        self.password_history = history;
    }

    /// Nothing was put in it besides its kind.
    pub fn is_empty(&self) -> bool {
        const KINDS: [&str; 3] = ["documentType", "databaseType", "templateName"];
        self.details.keys().all(|key| KINDS.contains(&key.as_str()))
            && self.custom_fields.is_empty()
            && self.addresses.is_empty()
            && self.fields.is_empty()
            && self.urls.is_empty()
    }

    pub fn build(
        self,
        title: Option<String>,
        tags: Vec<String>,
        favorite: bool,
        notes: Option<String>,
    ) -> Item {
        let name = String::from(self.item_type.clone());
        let mut details = self.details;
        details.insert("schemaVersion".into(), SCHEMA_VERSION.into());
        let subtitle = subtitle_key(&name)
            .and_then(|key| details.get(key)?.as_str())
            .map(str::to_owned);
        if let Some(notes) = clean(notes.as_deref()) {
            details.insert("notes".into(), notes.into());
        }
        let to_json = |value| serde_json::to_value(value).expect("fields serialize");
        if !self.custom_fields.is_empty() {
            details.insert("customFields".into(), to_json(&self.custom_fields));
        }
        if !self.addresses.is_empty() {
            let addresses = serde_json::to_value(&self.addresses).expect("addresses serialize");
            details.insert("addresses".into(), addresses);
        }
        if !self.password_history.is_empty() {
            let history = serde_json::to_value(&self.password_history).expect("history serializes");
            details.insert("passwordHistory".into(), history);
        }
        if self.item_type == ItemType::Custom {
            let fields = serde_json::to_value(&self.fields).expect("fields serialize");
            details.insert("fields".into(), fields);
        }
        let overview = overview(self.item_type, title, self.urls, subtitle, tags, favorite);
        Item::from_parts(overview, Value::Object(details)).expect("text in text fields is valid")
    }
}

/// The table's choice for what an app wrote (`Checking`, `SQL Server`), or its own words.
fn known_choice(choices: &[&str], value: String) -> String {
    let plain = |text: &str| text.replace([' ', '-', '_'], "").to_lowercase();
    choices
        .iter()
        .find(|choice| plain(choice) == plain(&value))
        .map_or(value, |choice| (*choice).to_owned())
}

/// A date as `YYYY-MM-DD`: a date or a date and time in ISO 8601 (`2024-1-5` too), or a Unix time.
/// `None` for anything else, so a strange value is never turned into a wrong date.
pub(super) fn date_only(text: &str) -> Option<String> {
    let text = text.trim();
    let day_part = text.split(['T', 't', ' ']).next().unwrap_or_default();
    let mut parts = day_part.splitn(3, '-');
    let date = (|| {
        let year = parts.next()?;
        if year.len() != 4 {
            return None;
        }
        let year = year.parse().ok()?;
        let month = parts.next()?.parse().ok()?;
        let day = parts.next()?.parse().ok()?;
        iso_date(year, month, day)
    })();
    date.or_else(|| timestamp(Some(text)).map(|time| time[..10].to_owned()))
}

pub(super) fn secure_note(notes: String) -> SecureNoteDetails {
    SecureNoteDetails {
        schema_version: SCHEMA_VERSION,
        notes,
        extra: Map::new(),
    }
}

pub(super) fn card_details() -> CardDetails {
    CardDetails {
        schema_version: SCHEMA_VERSION,
        cardholder: None,
        number: None,
        expiry: None,
        cvv: None,
        pin: None,
        brand: None,
        notes: None,
        extra: Map::new(),
    }
}

pub(super) fn identity_details() -> IdentityDetails {
    IdentityDetails {
        schema_version: SCHEMA_VERSION,
        first_name: None,
        last_name: None,
        email: None,
        phone: None,
        address: None,
        birth_date: None,
        notes: None,
        extra: Map::new(),
    }
}

/// An address, or `None` when every line is empty.
pub(super) fn address(
    line1: Option<String>,
    line2: Option<String>,
    city: Option<String>,
    region: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
) -> Option<Address> {
    let address = Address {
        line1,
        line2,
        city,
        region,
        postal_code,
        country,
        extra: Map::new(),
    };
    let empty = [
        &address.line1,
        &address.line2,
        &address.city,
        &address.region,
        &address.postal_code,
        &address.country,
    ]
    .iter()
    .all(|line| line.is_none());
    (!empty).then_some(address)
}

/// A card item, with the last four digits as its subtitle.
pub(super) fn card(
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    details: CardDetails,
) -> Item {
    Item {
        overview: overview(
            ItemType::Card,
            title,
            vec![],
            last_four(details.number.as_deref()),
            tags,
            favorite,
        ),
        details: ItemDetails::Card(details),
    }
}

pub(super) fn identity(
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    details: IdentityDetails,
) -> Item {
    Item {
        overview: overview(
            ItemType::Identity,
            title,
            vec![],
            details.email.clone(),
            tags,
            favorite,
        ),
        details: ItemDetails::Identity(details),
    }
}

pub(super) fn note(
    title: Option<String>,
    tags: Vec<String>,
    favorite: bool,
    notes: Option<String>,
) -> Item {
    Item {
        overview: overview(ItemType::SecureNote, title, vec![], None, tags, favorite),
        details: ItemDetails::SecureNote(secure_note(notes.unwrap_or_default())),
    }
}

fn last_four(number: Option<&str>) -> Option<String> {
    let digits: String = number?.chars().filter(char::is_ascii_digit).collect();
    (digits.len() >= 4).then(|| format!("•••• {}", &digits[digits.len() - 4..]))
}

/// `MM/YY` from a month (1–12) and a two- or four-digit year.
pub(super) fn expiry(month: u32, year: u32) -> Option<String> {
    ((1..=12).contains(&month) && year < 10_000).then(|| format!("{month:02}/{:02}", year % 100))
}

/// English month names as LastPass writes them, or numbers.
pub(super) fn month_number(text: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ];
    let text = text.trim().to_lowercase();
    MONTHS
        .iter()
        .position(|m| *m == text || (text.len() >= 3 && m.starts_with(&text)))
        .map(|i| i as u32 + 1)
        .or_else(|| text.parse().ok().filter(|m| (1..=12).contains(m)))
}

/// `YYYY-MM-DD` when the parts form a real calendar date.
pub(super) fn iso_date(year: i64, month: u32, day: u32) -> Option<String> {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let valid = (1..=9999).contains(&year)
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days[month as usize - 1];
    valid.then(|| format!("{year:04}-{month:02}-{day:02}"))
}

/// `(year, month, day)` of a Unix timestamp in seconds (UTC).
pub(super) fn civil_date(unix_seconds: i64) -> (i64, u32, u32) {
    // Howard Hinnant's days-from-civil, inverted.
    let days = unix_seconds.div_euclid(86_400) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// RFC 3339 (`2026-10-23T08:00:00Z`) for a Unix timestamp in seconds.
pub(super) fn rfc3339(unix_seconds: i64) -> String {
    let (year, month, day) = civil_date(unix_seconds);
    let seconds = unix_seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

/// Unix seconds of a UTC calendar date and time.
fn unix_from_civil(year: i64, month: u32, day: u32, seconds_of_day: i64) -> i64 {
    // Howard Hinnant's days-from-civil.
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) * 86_400 + seconds_of_day
}

/// RFC 3339 for a Unix time in seconds or milliseconds (told apart by size). Exports write zero
/// or small numbers for "not recorded", so times before 1990 give `None`, as do times past 9999.
pub(super) fn unix_time(value: i64) -> Option<String> {
    // Seconds reach 10^11 only in the year 5138; milliseconds pass it in 1973.
    let seconds = if value.abs() >= 100_000_000_000 {
        value.div_euclid(1000)
    } else {
        value
    };
    (631_152_000..253_402_300_800)
        .contains(&seconds)
        .then(|| rfc3339(seconds))
}

/// A date and time from an export as RFC 3339 in UTC: Unix seconds or milliseconds, ISO 8601 /
/// RFC 3339 (`2024-05-01T10:00:00.123+02:00`), `2024-05-01 10:00:00` (read as UTC) or a bare
/// date. Anything else gives `None`, so a strange value is never turned into a wrong date.
pub(super) fn timestamp(value: Option<&str>) -> Option<String> {
    let text = value?.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(number) = text.parse::<i64>() {
        return unix_time(number);
    }
    if let Ok(number) = text.parse::<f64>()
        && number.is_finite()
        && number.abs() < 1e15
    {
        return unix_time(number as i64);
    }
    let bytes = text.as_bytes();
    let digits = |from: usize, len: usize| -> Option<i64> {
        let part = text.get(from..from + len)?;
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let year = digits(0, 4)?;
    let month = u32::try_from(digits(5, 2)?).ok()?;
    let day = u32::try_from(digits(8, 2)?).ok()?;
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return None;
    }
    iso_date(year, month, day)?;
    let mut seconds_of_day = 0;
    let mut rest = &text[10..];
    if rest.starts_with(['T', 't', ' ']) {
        let hour = digits(11, 2)?;
        let minute = digits(14, 2)?;
        if text.as_bytes().get(13) != Some(&b':') || hour > 23 || minute > 59 {
            return None;
        }
        let mut at = 16;
        let mut second = 0;
        if bytes.get(16) == Some(&b':') {
            second = digits(17, 2)?;
            if second > 60 {
                return None;
            }
            at = 19;
            if bytes.get(19) == Some(&b'.') || bytes.get(19) == Some(&b',') {
                at = 20;
                while bytes.get(at).is_some_and(u8::is_ascii_digit) {
                    at += 1;
                }
            }
        }
        seconds_of_day = hour * 3600 + minute * 60 + second.min(59);
        rest = text.get(at..)?;
    }
    let offset = match rest.trim() {
        "" | "Z" | "z" => 0,
        zone => {
            let sign = match zone.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let zone = zone[1..].replace(':', "");
            let hours: i64 = zone.get(0..2)?.parse().ok()?;
            let minutes: i64 = zone.get(2..4).map_or(Some(0), |m| m.parse().ok())?;
            if zone.len() > 4 || hours > 23 || minutes > 59 {
                return None;
            }
            sign * (hours * 3600 + minutes * 60)
        }
    };
    unix_time(unix_from_civil(year, month, day, seconds_of_day) - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(
            timestamp(Some("1718000000000")).as_deref(),
            Some("2024-06-10T06:13:20Z")
        );
        assert_eq!(
            timestamp(Some("1718000000")).as_deref(),
            Some("2024-06-10T06:13:20Z")
        );
        assert_eq!(
            timestamp(Some("1718000000.5")).as_deref(),
            Some("2024-06-10T06:13:20Z")
        );
        assert_eq!(
            timestamp(Some("2024-06-10T06:13:20.123Z")).as_deref(),
            Some("2024-06-10T06:13:20Z")
        );
        assert_eq!(
            timestamp(Some("2024-06-10T08:13:20+02:00")).as_deref(),
            Some("2024-06-10T06:13:20Z")
        );
        assert_eq!(
            timestamp(Some("2024-06-10 06:13")).as_deref(),
            Some("2024-06-10T06:13:00Z")
        );
        assert_eq!(
            timestamp(Some("2024-02-29")).as_deref(),
            Some("2024-02-29T00:00:00Z")
        );
        assert_eq!(timestamp(Some("1969-12-31T00:00:00Z")), None);
        for bad in [
            "",
            "0",
            "-5",
            "yesterday",
            "2023-02-29",
            "2024-06-10T25:00:00Z",
            "2024-06-10Tx",
            "2024-06-10T06:13:20+2",
        ] {
            assert_eq!(timestamp(Some(bad)), None, "{bad}");
        }
        assert_eq!(unix_from_civil(2000, 2, 29, 43_200), 951_825_600);
        assert_eq!(unix_from_civil(1970, 1, 1, 0), 0);
    }

    #[test]
    fn dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_761_177_600), "2025-10-23T00:00:00Z");
        assert_eq!(rfc3339(951_825_600), "2000-02-29T12:00:00Z");
        assert_eq!(rfc3339(-86_400), "1969-12-31T00:00:00Z");
        assert_eq!(iso_date(2024, 2, 29).as_deref(), Some("2024-02-29"));
        assert_eq!(iso_date(2023, 2, 29), None);
        assert_eq!(expiry(1, 2030).as_deref(), Some("01/30"));
        assert_eq!(expiry(13, 2030), None);
        assert_eq!(month_number("January"), Some(1));
        assert_eq!(month_number("sep"), Some(9));
        assert_eq!(month_number("12"), Some(12));
        assert_eq!(month_number("Smarch"), None);
    }

    #[test]
    fn dates_become_days() {
        for (text, day) in [
            ("2024-02-29", "2024-02-29"),
            ("2024-1-5", "2024-01-05"),
            ("1975-06-30T10:00:00Z", "1975-06-30"),
            ("2024-06-10 06:13", "2024-06-10"),
            ("1718000000", "2024-06-10"),
        ] {
            assert_eq!(date_only(text).as_deref(), Some(day), "{text}");
        }
        for bad in ["", "2023-02-29", "01/02/1990", "next year", "24-01-05"] {
            assert_eq!(date_only(bad), None, "{bad}");
        }
    }

    #[test]
    fn typed_items_keep_everything() {
        let mut item = TypedItem::id_document("passport");
        assert!(item.is_empty());
        item.set("number", Some(" X1 ".into()));
        item.set("number", Some("X2".into()));
        item.set("expiryDate", Some("2030-1-4".into()));
        item.set("issueDate", Some("soon".into()));
        item.set("fullName", Some(" Ada ".into()));
        item.set("favouriteColour", Some("blue".into()));
        item.set("issuer", Some("  ".into()));
        item.custom("Class", "B", false);
        item.custom("Empty", " ", false);
        let item = item.build(Some("ID".into()), vec![], false, Some("n".into()));
        let mut bank = TypedItem::bank_account();
        bank.set("accountType", Some("Savings".into()));
        let mut database = TypedItem::database(Some("SQL Server".into()));
        database.set("port", Some("not a port".into()));
        let (bank, database) = (
            bank.build(None, vec![], false, None),
            database.build(None, vec![], false, None),
        );
        let ItemDetails::BankAccount(bank) = &bank.details else {
            panic!()
        };
        assert_eq!(bank.account_type.as_deref(), Some("savings"));
        let ItemDetails::Database(database) = &database.details else {
            panic!()
        };
        assert_eq!(database.database_type.as_deref(), Some("sqlServer"));
        assert_eq!(database.port.as_deref(), Some("not a port"));
        assert_eq!(item.overview.subtitle.as_deref(), Some("Ada"));
        let value = serde_json::to_value(&item.details).unwrap();
        assert_eq!(value["documentType"], "passport");
        assert_eq!(value["number"], " X1 ");
        assert_eq!(value["expiryDate"], "2030-01-04");
        assert_eq!(value["fullName"], "Ada");
        assert_eq!(value["notes"], "n");
        assert!(value.get("issuer").is_none());
        let labels: Vec<(&str, &str, bool)> = value["customFields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["label"].as_str().unwrap(),
                    f["value"].as_str().unwrap(),
                    f["hidden"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            labels,
            [
                ("Number", "X2", true),
                ("Issue date", "soon", false),
                ("Favourite colour", "blue", true),
                ("Class", "B", false)
            ]
        );
    }

    #[test]
    fn typed_wallets_and_custom_items() {
        let mut wallet = TypedItem::crypto_wallet();
        wallet.set("seedPhrase", Some("legal winner".into()));
        wallet.address("bitcoin", " bc1q ", Some("Savings".into()));
        wallet.address("ethereum", " ", None);
        let wallet = wallet.build(None, vec![], false, None);
        assert_eq!(wallet.overview.item_type, ItemType::CryptoWallet);
        let ItemDetails::CryptoWallet(details) = &wallet.details else {
            panic!()
        };
        assert_eq!(details.addresses.as_ref().unwrap().len(), 1);
        assert_eq!(wallet.overview.subtitle, None, "never the seed");

        let mut custom = TypedItem::custom_item(Some("Locker".into()));
        assert!(custom.is_empty());
        custom.custom("Code", "4321", true);
        custom.field("Empty", "", "text");
        let custom = custom.build(Some("Gym".into()), vec![], false, None);
        let ItemDetails::Custom(details) = &custom.details else {
            panic!()
        };
        assert_eq!(details.fields[0].kind, "hidden");
        assert_eq!(details.fields[1].label, "Empty");
        assert_eq!(custom.overview.subtitle.as_deref(), Some("Locker"));
    }

    #[test]
    fn logins_notes_and_nothing() {
        let mut out = Collector::default();
        let login = LoginFields {
            urls: vec!["https://www.example.com/login".into()],
            username: Some(" alice ".into()),
            password: Some(" spaced ".into()),
            ..LoginFields::default()
        }
        .build(&mut out)
        .unwrap();
        assert_eq!(login.overview.title, "example.com");
        assert_eq!(login.overview.subtitle.as_deref(), Some("alice"));
        let ItemDetails::Login(details) = &login.details else {
            panic!()
        };
        assert_eq!(details.password.as_deref(), Some(" spaced "));

        let note = LoginFields {
            title: Some("Note".into()),
            notes: Some("hello".into()),
            ..LoginFields::default()
        }
        .build(&mut out)
        .unwrap();
        assert_eq!(note.overview.item_type, ItemType::SecureNote);
        assert!(LoginFields::default().build(&mut out).is_none());
    }

    #[test]
    fn unusable_totp_setups_become_hidden_fields() {
        let mut out = Collector::default();
        let item = LoginFields {
            title: Some("Steam".into()),
            totp: Some("steam://ABCDEF".into()),
            ..LoginFields::default()
        }
        .build(&mut out)
        .unwrap();
        let ItemDetails::Login(details) = &item.details else {
            panic!()
        };
        assert_eq!(details.totp, None);
        assert_eq!(
            details.custom_fields.as_ref().unwrap()[0].value,
            "steam://ABCDEF"
        );
        assert_eq!(out.finish().warnings.len(), 1);
    }

    #[test]
    fn warnings_are_capped() {
        let mut out = Collector::default();
        for i in 0..30 {
            out.skip(Some(format!("w{i}")));
        }
        let result = out.finish();
        assert_eq!(result.skipped, 30);
        assert_eq!(result.warnings.len(), MAX_WARNINGS + 1);
        assert_eq!(result.warnings.last().unwrap(), "…and 10 more.");
    }

    #[test]
    fn titles_fall_back_to_the_host() {
        assert_eq!(
            title_from_url("android://hash@com.example.app/").as_deref(),
            Some("com.example.app")
        );
        assert_eq!(
            overview(ItemType::Login, None, vec![], None, vec![], false).title,
            "Untitled"
        );
    }
}
