//! Items as the apps and autofill extensions see them: typed fields for filling, built from the
//! core item model. Saving goes back through the core model, so fields these records don't
//! carry (and fields from newer clients) survive untouched.

use octapass_core::item::{
    CardDetails, IdentityDetails, Item as CoreItem, ItemDetails, ItemOverview, ItemType,
    LoginDetails, PasswordHistoryEntry, SCHEMA_VERSION,
};
use octapass_core::passkey::PasskeyRecord;

use crate::error::{OctaPassError, Result};
use octapass_core::matching::Site;

/// What a list row shows. Never contains a password, card number or other secret.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ItemSummary {
    pub item_id: String,
    pub vault_id: String,
    /// `login`, `secureNote`, `card`, `identity`, `password`, or a type from a newer client.
    pub item_type: String,
    pub title: String,
    pub subtitle: Option<String>,
    pub urls: Vec<String>,
    pub favorite: bool,
    pub username: Option<String>,
    pub has_totp: bool,
    pub has_passkey: bool,
    /// A non-empty password: a login made by saving a passkey has none, so it can't fill a password.
    pub has_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct Item {
    pub item_id: String,
    pub vault_id: String,
    pub item_type: String,
    pub title: String,
    pub subtitle: Option<String>,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    /// For `login` and `password` items.
    pub login: Option<LoginFields>,
    pub card: Option<CardFields>,
    pub identity: Option<IdentityFields>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LoginFields {
    pub username: Option<String>,
    pub password: Option<String>,
    /// An `otpauth://` URI or a base32 secret; `Session.totpCode` turns it into a code.
    pub totp: Option<String>,
    pub passkeys: Vec<PasskeySummary>,
}

/// A passkey saved in a login, without its private key.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PasskeySummary {
    pub rp_id: String,
    pub user_name: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CardFields {
    pub cardholder: Option<String>,
    pub number: Option<String>,
    /// `MM/YY`
    pub expiry: Option<String>,
    pub cvv: Option<String>,
    pub brand: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IdentityFields {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address_line1: Option<String>,
    pub address_line2: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub birth_date: Option<String>,
}

/// A login to create, or the changes to make to one (`item_id` set). On update, `None` leaves a
/// field as it is, a new password moves the old one to the password history, and a new URL is
/// added to the item's URLs.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LoginDraft {
    pub item_id: Option<String>,
    /// A new login without a title is named after the URL's site.
    pub title: Option<String>,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// An `otpauth://` URI or base32 secret, e.g. from a scanned QR code.
    pub totp: Option<String>,
}

pub(crate) fn summary(item_id: &str, vault_id: &str, item: &CoreItem) -> ItemSummary {
    let login = login_details(item);
    ItemSummary {
        item_id: item_id.to_owned(),
        vault_id: vault_id.to_owned(),
        item_type: item.overview.item_type.clone().into(),
        title: item.overview.title.clone(),
        subtitle: item.overview.subtitle.clone(),
        urls: item.overview.urls.clone().unwrap_or_default(),
        favorite: item.overview.favorite.unwrap_or(false),
        username: login.and_then(|login| login.username.clone()),
        has_totp: login.is_some_and(|login| login.totp.as_deref().is_some_and(|t| !t.is_empty())),
        has_passkey: !passkey_records(item).is_empty(),
        has_password: login
            .is_some_and(|login| login.password.as_deref().is_some_and(|p| !p.is_empty())),
    }
}

pub(crate) fn full(item_id: &str, vault_id: &str, item: &CoreItem) -> Item {
    let overview = &item.overview;
    let (login, card, identity, notes) = match &item.details {
        ItemDetails::Login(login) => (Some(login_fields(login)), None, None, login.notes.clone()),
        ItemDetails::Card(card) => (None, Some(card_fields(card)), None, card.notes.clone()),
        ItemDetails::Identity(identity) => (
            None,
            None,
            Some(identity_fields(identity)),
            identity.notes.clone(),
        ),
        ItemDetails::SecureNote(note) => (None, None, None, Some(note.notes.clone())),
        ItemDetails::Document(document) => (None, None, None, document.notes.clone()),
        ItemDetails::Wifi(wifi) => (None, None, None, wifi.notes.clone()),
        ItemDetails::SshKey(key) => (None, None, None, key.notes.clone()),
        ItemDetails::Environment(environment) => (None, None, None, environment.notes.clone()),
        ItemDetails::Certificate(certificate) => (None, None, None, certificate.notes.clone()),
        ItemDetails::Key(key) => (None, None, None, key.notes.clone()),
        ItemDetails::BankAccount(details) => (None, None, None, details.notes.clone()),
        ItemDetails::ApiCredential(details) => (None, None, None, details.notes.clone()),
        ItemDetails::SoftwareLicense(details) => (None, None, None, details.notes.clone()),
        ItemDetails::IdDocument(details) => (None, None, None, details.notes.clone()),
        ItemDetails::CryptoWallet(details) => (None, None, None, details.notes.clone()),
        ItemDetails::Database(details) => (None, None, None, details.notes.clone()),
        ItemDetails::Custom(details) => (None, None, None, details.notes.clone()),
        ItemDetails::MaskedEmailProvider(_)
        | ItemDetails::EquivalentDomains(_)
        | ItemDetails::CustomTemplate(_)
        | ItemDetails::Other(_) => (None, None, None, None),
    };
    Item {
        item_id: item_id.to_owned(),
        vault_id: vault_id.to_owned(),
        item_type: overview.item_type.clone().into(),
        title: overview.title.clone(),
        subtitle: overview.subtitle.clone(),
        urls: overview.urls.clone().unwrap_or_default(),
        tags: overview.tags.clone().unwrap_or_default(),
        favorite: overview.favorite.unwrap_or(false),
        login,
        card,
        identity,
        notes,
    }
}

pub(crate) fn login_details(item: &CoreItem) -> Option<&LoginDetails> {
    match &item.details {
        ItemDetails::Login(login) => Some(login),
        _ => None,
    }
}

/// The passkeys of a login that can sign (display-only entries are skipped).
pub(crate) fn passkey_records(item: &CoreItem) -> Vec<PasskeyRecord> {
    login_details(item)
        .and_then(|login| login.passkeys.as_deref())
        .unwrap_or_default()
        .iter()
        .filter_map(PasskeyRecord::from_item)
        .collect()
}

/// A new login from a draft.
pub(crate) fn new_login(draft: &LoginDraft) -> Result<CoreItem> {
    let title = match (draft.title.as_deref().map(str::trim), &draft.url) {
        (Some(title), _) if !title.is_empty() => title.to_owned(),
        (_, Some(url)) => Site::parse(url)?.display_host(),
        _ => return Err(OctaPassError::InvalidItem),
    };
    Ok(CoreItem {
        overview: ItemOverview {
            schema_version: SCHEMA_VERSION,
            title,
            item_type: ItemType::Login,
            urls: draft.url.clone().map(|url| vec![url]),
            subtitle: None,
            tags: None,
            favorite: None,
            created_at: None,
            updated_at: None,
            last_used_at: None,
            imported_from: None,
            extra: Default::default(),
        },
        details: ItemDetails::Login(LoginDetails {
            schema_version: SCHEMA_VERSION,
            username: draft.username.clone(),
            password: draft.password.clone(),
            totp: draft.totp.clone(),
            notes: None,
            passkeys: None,
            recovery: None,
            custom_fields: None,
            password_history: None,
            password_changed_at: None,
            http_realm: None,
            extra: Default::default(),
        }),
    })
}

/// Applies a draft to an existing login, keeping every field the draft doesn't name. The
/// imported app's last-changed date goes: the login now changed here.
pub(crate) fn update_login(item: &mut CoreItem, draft: &LoginDraft, now: &str) -> Result<()> {
    let ItemDetails::Login(login) = &mut item.details else {
        return Err(OctaPassError::InvalidItem);
    };
    item.overview.updated_at = None;
    if let Some(title) = draft
        .title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        item.overview.title = title.to_owned();
    }
    if let Some(url) = &draft.url {
        // Not again when the login has the site already, written another way (`/login`, `www.`).
        let modes =
            octapass_core::matching::websites::modes_of(item.overview.extra.get("urlMatch"));
        let urls = item.overview.urls.get_or_insert_with(Vec::new);
        if !octapass_core::matching::has_website(urls, &modes, url) {
            urls.push(url.clone());
        }
    }
    if let Some(username) = &draft.username {
        login.username = Some(username.clone());
    }
    if let Some(totp) = &draft.totp {
        login.totp = Some(totp.clone());
    }
    if let Some(password) = &draft.password
        && login.password.as_ref() != Some(password)
    {
        let old = login.password.replace(password.clone());
        if let Some(old) = old {
            login.password_history.get_or_insert_with(Vec::new).insert(
                0,
                PasswordHistoryEntry {
                    password: old,
                    changed_at: now.to_owned(),
                    extra: Default::default(),
                },
            );
        }
    }
    Ok(())
}

fn login_fields(login: &LoginDetails) -> LoginFields {
    LoginFields {
        username: login.username.clone(),
        password: login.password.clone(),
        totp: login.totp.clone(),
        passkeys: login
            .passkeys
            .iter()
            .flatten()
            .map(|passkey| PasskeySummary {
                rp_id: passkey.rp_id.clone(),
                user_name: passkey.user_name.clone(),
                created_at: passkey.created_at.clone(),
            })
            .collect(),
    }
}

fn card_fields(card: &CardDetails) -> CardFields {
    CardFields {
        cardholder: card.cardholder.clone(),
        number: card.number.clone(),
        expiry: card.expiry.clone(),
        cvv: card.cvv.clone(),
        brand: card.brand.clone(),
    }
}

fn identity_fields(identity: &IdentityDetails) -> IdentityFields {
    let address = identity.address.as_ref();
    let line = |field: fn(&octapass_core::item::Address) -> &Option<String>| {
        address.and_then(|address| field(address).clone())
    };
    IdentityFields {
        first_name: identity.first_name.clone(),
        last_name: identity.last_name.clone(),
        email: identity.email.clone(),
        phone: identity.phone.clone(),
        address_line1: line(|a| &a.line1),
        address_line2: line(|a| &a.line2),
        city: line(|a| &a.city),
        region: line(|a| &a.region),
        postal_code: line(|a| &a.postal_code),
        country: line(|a| &a.country),
        birth_date: identity.birth_date.clone(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn item(value: Value) -> CoreItem {
        CoreItem::from_json(&value.to_string()).unwrap()
    }

    #[test]
    fn summaries_show_no_secrets() {
        let login = item(json!({
            "overview": { "title": "GitHub", "type": "login", "urls": ["https://github.com"] },
            "details": { "username": "octo", "password": "pw", "totp": "JBSWY3DPEHPK3PXP" }
        }));
        let summary = summary("i", "v", &login);
        assert_eq!(summary.username.as_deref(), Some("octo"));
        assert!(summary.has_totp && !summary.has_passkey);
        assert!(!format!("{summary:?}").contains("pw"));
    }

    #[test]
    fn every_type_maps_to_its_fields() {
        let card = full(
            "i",
            "v",
            &item(json!({
                "overview": { "title": "Visa", "type": "card" },
                "details": { "number": "4111", "cvv": "123", "notes": "n" }
            })),
        );
        assert_eq!(card.card.unwrap().cvv.as_deref(), Some("123"));
        assert_eq!(card.notes.as_deref(), Some("n"));

        let identity = full(
            "i",
            "v",
            &item(json!({
                "overview": { "title": "Me", "type": "identity" },
                "details": { "firstName": "A", "address": { "city": "Amman" } }
            })),
        );
        let fields = identity.identity.unwrap();
        assert_eq!(fields.city.as_deref(), Some("Amman"));
        assert_eq!(fields.address_line1, None);

        let note = full(
            "i",
            "v",
            &item(
                json!({ "overview": { "title": "N", "type": "secureNote" }, "details": { "notes": "hi" } }),
            ),
        );
        assert_eq!(note.notes.as_deref(), Some("hi"));
    }

    #[test]
    fn updates_keep_unknown_fields_and_password_history() {
        let mut login = item(json!({
            "overview": { "title": "Site", "type": "login", "urls": ["https://a.example"], "iconHint": "x" },
            "details": { "username": "u", "password": "old", "future": { "keep": true } }
        }));
        let draft = LoginDraft {
            item_id: Some("i".into()),
            title: None,
            url: Some("https://b.example".into()),
            username: None,
            password: Some("new".into()),
            totp: None,
        };
        update_login(&mut login, &draft, "2026-10-24T00:00:00Z").unwrap();
        let out: Value = serde_json::from_str(&login.to_json()).unwrap();
        assert_eq!(out["overview"]["iconHint"], "x");
        assert_eq!(
            out["overview"]["urls"],
            json!(["https://a.example", "https://b.example"])
        );
        assert_eq!(out["details"]["future"], json!({ "keep": true }));
        assert_eq!(out["details"]["username"], "u");
        assert_eq!(out["details"]["password"], "new");
        assert_eq!(
            out["details"]["passwordHistory"],
            json!([{ "password": "old", "changedAt": "2026-10-24T00:00:00Z" }])
        );

        update_login(&mut login, &draft, "later").unwrap();
        let out: Value = serde_json::from_str(&login.to_json()).unwrap();
        assert_eq!(
            out["details"]["passwordHistory"].as_array().unwrap().len(),
            1,
            "saving the same password again changes nothing"
        );
    }

    #[test]
    fn a_site_the_login_has_is_not_added_again() {
        let mut login = item(json!({
            "overview": { "title": "Site", "type": "login", "urls": ["https://a.example"] },
            "details": { "username": "u", "password": "pw" }
        }));
        for url in [
            "https://a.example/",
            "https://www.a.example/login",
            "http://A.example",
        ] {
            let draft = LoginDraft {
                item_id: Some("i".into()),
                title: None,
                url: Some(url.into()),
                username: None,
                password: Some("pw".into()),
                totp: None,
            };
            update_login(&mut login, &draft, "now").unwrap();
        }
        let out: Value = serde_json::from_str(&login.to_json()).unwrap();
        assert_eq!(out["overview"]["urls"], json!(["https://a.example"]));
    }

    #[test]
    fn new_logins_are_named_after_the_site() {
        let login = new_login(&LoginDraft {
            item_id: None,
            title: None,
            url: Some("https://www.github.com/login".into()),
            username: Some("octo".into()),
            password: Some("pw".into()),
            totp: None,
        })
        .unwrap();
        assert_eq!(login.overview.title, "github.com");
        let untitled = LoginDraft {
            item_id: None,
            title: Some(" ".into()),
            url: None,
            username: None,
            password: None,
            totp: None,
        };
        assert_eq!(
            new_login(&untitled).unwrap_err(),
            OctaPassError::InvalidItem
        );
    }
}
