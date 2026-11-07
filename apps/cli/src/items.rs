//! Finding items and fields by name, and `octapass://` references.

use octapass_desktop_vault::health::HEALTH_SETTINGS_TYPE;
use octapass_desktop_vault::model::{Item, ItemSummary, Vault};

use crate::error::{CliError, Exit, Result};

/// The vault named `query` (case-insensitive) or with that id.
pub fn find_vault<'a>(vaults: &'a [Vault], query: &str) -> Result<&'a Vault> {
    let mut matches = vaults
        .iter()
        .filter(|vault| vault.id == query || vault.name.eq_ignore_ascii_case(query));
    match (matches.next(), matches.next()) {
        (Some(vault), None) => Ok(vault),
        (Some(_), Some(_)) => Err(CliError::new(
            Exit::Ambiguous,
            format!("More than one vault is called \"{query}\". Use its id instead."),
        )),
        (None, _) => Err(CliError::not_found(format!("No vault called \"{query}\"."))),
    }
}

pub fn vault_name<'a>(vaults: &'a [Vault], id: &str) -> &'a str {
    vaults
        .iter()
        .find(|vault| vault.id == id)
        .map_or("", |vault| vault.name.as_str())
}

/// Items not in the trash, by title. The dashboard's hidden settings item isn't one.
pub fn live(mut rows: Vec<ItemSummary>) -> Vec<ItemSummary> {
    rows.retain(|row| row.deleted_at.is_none() && row.item_type != HEALTH_SETTINGS_TYPE);
    rows.sort_by(|a, b| {
        a.title
            .to_lowercase()
            .cmp(&b.title.to_lowercase())
            .then_with(|| a.id.cmp(&b.id))
    });
    rows
}

/// Case-insensitive search over titles, subtitles, URLs and tags.
pub fn matches_search(row: &ItemSummary, query: &str) -> bool {
    let query = query.to_lowercase();
    let hit = |text: &str| text.to_lowercase().contains(&query);
    hit(&row.title)
        || row.subtitle.as_deref().is_some_and(hit)
        || row.urls.iter().flatten().any(|url| hit(url))
        || row.tags.iter().flatten().any(|tag| hit(tag))
}

/// The one item whose id is `query`, or whose title is `query` (case-insensitive).
pub fn find_item<'a>(rows: &'a [ItemSummary], query: &str) -> Result<&'a ItemSummary> {
    if let Some(row) = rows.iter().find(|row| row.id == query) {
        return Ok(row);
    }
    let titled: Vec<&ItemSummary> = rows
        .iter()
        .filter(|row| row.title.eq_ignore_ascii_case(query.trim()))
        .collect();
    match titled.as_slice() {
        [row] => Ok(row),
        [] => Err(CliError::not_found(format!("No item called \"{query}\"."))),
        many => {
            let ids: Vec<&str> = many.iter().map(|row| row.id.as_str()).collect();
            Err(CliError::new(
                Exit::Ambiguous,
                format!(
                    "{} items are called \"{query}\". Use an id instead: {}",
                    many.len(),
                    ids.join(", ")
                ),
            ))
        }
    }
}

pub use octapass_connect::reference::{Field, Reference, SCHEME, is_environment};

/// The fields `--field` knows by name. `totp` is the current code (the caller computes it).
pub fn field(item: &Item, name: &str) -> Result<Field> {
    octapass_connect::reference::field(item, name).ok_or_else(|| {
        CliError::not_found(format!(
            "\"{}\" has no field called \"{}\".",
            item.title(),
            name.trim()
        ))
    })
}

/// A reference, or a message saying how to write one.
pub fn parse_reference(text: &str) -> Result<Reference> {
    Reference::parse(text).ok_or_else(|| {
        CliError::usage(format!(
            "\"{text}\" isn't a reference. Write octapass://<vault>/<item>/<field>."
        ))
    })
}

#[cfg(test)]
mod tests {
    use octapass_api::{VaultRole, VaultType};
    use serde_json::{Value, json};

    use super::*;

    fn row(id: &str, title: &str) -> ItemSummary {
        ItemSummary {
            id: id.into(),
            vault_id: "v".into(),
            item_type: "login".into(),
            title: title.into(),
            subtitle: Some("octocat".into()),
            urls: Some(vec!["https://github.com".into()]),
            tags: Some(vec!["Work".into()]),
            favorite: false,
            pinned: false,
            has_totp: false,
            has_passkey: false,
            created_at: "t".into(),
            updated_at: "t".into(),
            deleted_at: None,
        }
    }

    fn item(overview: Value, details: Value) -> Item {
        Item {
            id: "i".into(),
            vault_id: "v".into(),
            revision: 1,
            created_at: "t".into(),
            updated_at: "t".into(),
            deleted_at: None,
            overview,
            details,
        }
    }

    #[test]
    fn items_are_found_by_id_or_exact_title() {
        let rows = vec![row("1", "GitHub"), row("2", "Bank"), row("3", "bank")];
        assert_eq!(find_item(&rows, "github").unwrap().id, "1");
        assert_eq!(find_item(&rows, "2").unwrap().id, "2");
        assert_eq!(find_item(&rows, "Git").unwrap_err().exit, Exit::NotFound);
        let ambiguous = find_item(&rows, "BANK").unwrap_err();
        assert_eq!(ambiguous.exit, Exit::Ambiguous);
        assert!(ambiguous.message.contains("2, 3"));
    }

    #[test]
    fn search_looks_at_titles_usernames_urls_and_tags() {
        let row = row("1", "GitHub");
        for query in ["hub", "OCTO", "github.com", "work"] {
            assert!(matches_search(&row, query), "{query}");
        }
        assert!(!matches_search(&row, "bank"));
    }

    #[test]
    fn vaults_by_name_or_id() {
        let vaults = vec![
            Vault {
                id: "p".into(),
                name: "Personal".into(),
                vault_type: VaultType::Personal,
                role: VaultRole::Owner,
                untrusted: false,
            },
            Vault {
                id: "s1".into(),
                name: "Shared".into(),
                vault_type: VaultType::Shared,
                role: VaultRole::Write,
                untrusted: false,
            },
            Vault {
                id: "s2".into(),
                name: "Shared".into(),
                vault_type: VaultType::Shared,
                role: VaultRole::Read,
                untrusted: false,
            },
        ];
        assert_eq!(find_vault(&vaults, "personal").unwrap().id, "p");
        assert_eq!(find_vault(&vaults, "s2").unwrap().id, "s2");
        assert_eq!(
            find_vault(&vaults, "shared").unwrap_err().exit,
            Exit::Ambiguous
        );
        assert_eq!(
            find_vault(&vaults, "Work").unwrap_err().exit,
            Exit::NotFound
        );
    }

    #[test]
    fn fields_by_name_with_secrets_marked() {
        let login = item(
            json!({ "type": "login", "title": "GitHub", "urls": ["https://github.com"] }),
            json!({
                "username": "octocat", "password": "hunter2", "notes": "main",
                "customFields": [
                    { "label": "API key", "value": "k-123", "hidden": true },
                    { "label": "Region", "value": "eu", "hidden": false },
                    { "label": "Empty", "value": "" }
                ]
            }),
        );
        let get = |name| field(&login, name).map(|f| (f.value, f.secret));
        assert_eq!(get("password").unwrap(), ("hunter2".into(), true));
        assert_eq!(get("Username").unwrap(), ("octocat".into(), false));
        assert_eq!(get("url").unwrap(), ("https://github.com".into(), false));
        assert_eq!(get("notes").unwrap(), ("main".into(), false));
        assert_eq!(get("api key").unwrap(), ("k-123".into(), true));
        assert_eq!(get("region").unwrap(), ("eu".into(), false));
        assert_eq!(get("empty").unwrap_err().exit, Exit::NotFound);
        assert_eq!(get("cvv").unwrap_err().exit, Exit::NotFound);

        let note = item(
            json!({ "type": "secureNote", "title": "Wi-Fi" }),
            json!({ "notes": "SSID home" }),
        );
        assert!(field(&note, "notes").unwrap().secret);

        let card = item(
            json!({ "type": "card", "title": "Visa" }),
            json!({ "cardholder": "Ada", "number": "4111", "cvv": "123" }),
        );
        assert!(field(&card, "cvv").unwrap().secret);
        assert!(!field(&card, "cardholder").unwrap().secret);
    }

    #[test]
    fn new_types_mark_their_secrets() {
        let wallet = item(
            json!({ "type": "cryptoWallet", "title": "Cold" }),
            json!({
                "walletName": "Hardware",
                "seedPhrase": "abandon ability",
                "passphrase": "p",
                "addresses": [
                    { "network": "bitcoin", "address": "bc1first" },
                    { "network": "ethereum", "address": "0xsecond", "label": "Savings" }
                ],
                "somethingNew": "from a newer client"
            }),
        );
        let get = |name| field(&wallet, name).map(|f| (f.value, f.secret));
        assert_eq!(get("seedPhrase").unwrap(), ("abandon ability".into(), true));
        assert!(get("passphrase").unwrap().1);
        assert!(get("somethingNew").unwrap().1);
        assert_eq!(get("walletName").unwrap(), ("Hardware".into(), false));
        assert_eq!(get("address").unwrap(), ("bc1first".into(), false));
        assert_eq!(get("ethereum").unwrap(), ("0xsecond".into(), false));
        assert_eq!(get("savings").unwrap(), ("0xsecond".into(), false));

        let bank = item(
            json!({ "type": "bankAccount", "title": "Main" }),
            json!({ "iban": "DE89", "pin": "1234" }),
        );
        assert!(!field(&bank, "iban").unwrap().secret);
        assert!(field(&bank, "pin").unwrap().secret);

        let database = item(
            json!({ "type": "database", "title": "Shop" }),
            json!({ "host": "db", "connectionString": "postgres://x" }),
        );
        assert!(!field(&database, "host").unwrap().secret);
        assert!(field(&database, "connectionString").unwrap().secret);

        let custom = item(
            json!({ "type": "custom", "title": "Library" }),
            json!({ "fields": [
                { "label": "Member", "value": "42", "kind": "text" },
                { "label": "PIN", "value": "1", "kind": "hidden" },
                { "label": "Later", "value": "x", "kind": "quantumKey" }
            ] }),
        );
        assert!(!field(&custom, "member").unwrap().secret);
        assert!(field(&custom, "pin").unwrap().secret);
        assert!(field(&custom, "later").unwrap().secret);
    }

    #[test]
    fn environment_variables_by_name() {
        let env = item(
            json!({ "type": "environment", "title": "Shop API (production)" }),
            json!({
                "project": "shop-api", "stage": "production",
                "variables": [
                    { "key": "DATABASE_URL", "value": "postgres://db", "concealed": true },
                    { "key": "PORT", "value": "8080", "concealed": false },
                    { "key": "notes", "value": "a variable" },
                    { "key": "EMPTY", "value": "" }
                ],
                "notes": "the item's notes"
            }),
        );
        let get = |name| field(&env, name).map(|f| (f.value, f.secret));
        assert_eq!(get("DATABASE_URL").unwrap(), ("postgres://db".into(), true));
        assert_eq!(get("database_url").unwrap(), ("postgres://db".into(), true));
        assert_eq!(get("PORT").unwrap(), ("8080".into(), false));
        assert_eq!(get("notes").unwrap(), ("a variable".into(), true));
        assert_eq!(get("Notes").unwrap(), ("the item's notes".into(), false));
        assert_eq!(get("EMPTY").unwrap(), (String::new(), true));
        assert_eq!(get("stage").unwrap(), ("production".into(), false));
        assert_eq!(get("MISSING").unwrap_err().exit, Exit::NotFound);
        // Other items have no variables.
        let login = item(
            json!({ "type": "login", "title": "x" }),
            json!({ "variables": [{ "key": "A", "value": "1" }] }),
        );
        assert_eq!(field(&login, "A").unwrap_err().exit, Exit::NotFound);
    }

    #[test]
    fn references() {
        assert_eq!(
            parse_reference("octapass://Work/Stripe/api key").unwrap(),
            Reference {
                vault: "Work".into(),
                item: "Stripe".into(),
                field: "api key".into()
            }
        );
        assert_eq!(
            parse_reference("octapass://Personal/A%2FB%20C/password")
                .unwrap()
                .item,
            "A/B C"
        );
        for bad in [
            "octapass://Personal/GitHub",
            "octapass://Personal/GitHub/password/x",
            "octapass:///GitHub/password",
            "op://Personal/GitHub/password",
            "octapass://Personal/Git%ZZ/password",
        ] {
            assert_eq!(parse_reference(bad).unwrap_err().exit, Exit::Usage, "{bad}");
        }
        assert!(Reference::is_reference(" octapass://a/b/c"));
        assert!(!Reference::is_reference("postgres://octapass://"));
    }
}
