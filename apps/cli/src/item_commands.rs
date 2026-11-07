//! `octapass create`, `edit`, `delete` and `restore`. Items are JSON end to end, so fields this
//! version doesn't know about stay as they are. Subtitles follow the web vault's editor
//! (`apps/web/src/screens/vault/editorModel.ts`), so a row reads the same in every client.

use octapass_api::VaultRole;
use octapass_core::tools::generator::{
    GeneratorOptions, PassphraseOptions, RandomOptions, generate,
};
use octapass_desktop_vault::model::{Item, ItemDraft};
use rand_core::OsRng;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::cli::{CreateArgs, EditArgs, FieldArgs};
use crate::error::{CliError, Exit, Result};
use crate::session::DEFAULT_IDLE;
use crate::{App, Opened, input_error, items};

/// Canonical field names per type. `None` for a type this version has no table for: any name goes.
fn fields_of(item_type: &str) -> Option<&'static [&'static str]> {
    Some(match item_type {
        "login" | "password" => &["username", "password", "totp", "notes", "httpRealm"],
        "secureNote" | "document" => &["notes"],
        "card" => &[
            "cardholder",
            "number",
            "expiry",
            "cvv",
            "pin",
            "brand",
            "notes",
        ],
        "identity" => &[
            "firstName",
            "lastName",
            "email",
            "phone",
            "birthDate",
            "notes",
            "address.line1",
            "address.line2",
            "address.city",
            "address.region",
            "address.postalCode",
            "address.country",
        ],
        "wifi" => &[
            "ssid",
            "security",
            "password",
            "username",
            "identity",
            "serverDomain",
            "notes",
        ],
        _ => return None,
    })
}

/// Values worth a warning when they arrive on the command line.
fn is_secret_field(name: &str) -> bool {
    matches!(name, "password" | "totp" | "number" | "cvv" | "pin")
}

/// Types made by their own commands, whose details need more than typed values.
fn own_command(item_type: &str) -> Option<&'static str> {
    match item_type {
        "sshKey" => Some("octapass ssh generate or octapass ssh import"),
        "gpgKey" => Some("octapass gpg import"),
        "environment" => Some("octapass env create"),
        _ => None,
    }
}

fn normalize_type(item_type: &str) -> String {
    match item_type.to_lowercase().as_str() {
        "note" | "securenote" | "secure-note" => "secureNote".into(),
        "sshkey" | "ssh-key" => "sshKey".into(),
        "gpgkey" | "gpg-key" => "gpgKey".into(),
        "login" | "password" | "card" | "identity" | "wifi" | "document" | "environment" => {
            item_type.to_lowercase()
        }
        _ => item_type.to_owned(),
    }
}

/// `field=value`, or `field` alone for a value typed without showing.
#[derive(Debug, PartialEq, Eq)]
pub enum Assignment {
    Set(String, String),
    Ask(String),
}

pub fn parse_assignment(text: &str) -> Result<Assignment> {
    match text.split_once('=') {
        Some((key, _)) if key.trim().is_empty() => Err(CliError::usage(format!(
            "`{text}` needs a field name before the =."
        ))),
        Some((key, value)) => Ok(Assignment::Set(key.trim().to_owned(), value.to_owned())),
        None if text.trim().is_empty() => Err(CliError::usage("A field name is empty.")),
        None => Ok(Assignment::Ask(text.trim().to_owned())),
    }
}

/// Where a typed name goes: a details field, or a custom field with this label.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    Detail(String),
    Custom(String),
}

fn target(item_type: &str, name: &str) -> Result<Target> {
    let Some(fields) = fields_of(item_type) else {
        return Ok(Target::Detail(name.to_owned()));
    };
    if let Some(field) = fields.iter().find(|field| field.eq_ignore_ascii_case(name)) {
        return Ok(Target::Detail((*field).to_owned()));
    }
    if matches!(item_type, "login" | "password" | "wifi") {
        return Ok(Target::Custom(name.to_owned()));
    }
    Err(CliError::usage(format!(
        "A {item_type} has no field called \"{name}\". It has: {}.",
        fields.join(", ")
    )))
}

fn object(value: &mut Value) -> &mut Map<String, Value> {
    if !value.is_object() {
        *value = json!({});
    }
    value.as_object_mut().expect("just made an object")
}

fn set_detail(details: &mut Value, field: &str, value: &str) {
    match field.strip_prefix("address.") {
        Some(part) => {
            let address = object(details)
                .entry("address")
                .or_insert_with(|| json!({}));
            object(address).insert(part.to_owned(), json!(value));
        }
        None => {
            object(details).insert(field.to_owned(), json!(value));
        }
    }
}

fn unset_detail(details: &mut Value, field: &str) {
    match field.strip_prefix("address.") {
        Some(part) => {
            let details = object(details);
            if let Some(address) = details.get_mut("address") {
                object(address).remove(part);
                if address.as_object().is_some_and(Map::is_empty) {
                    details.remove("address");
                }
            }
        }
        None => {
            object(details).remove(field);
        }
    }
}

/// Adds a custom field, or changes the one with this label. `hidden` applies to new fields; an
/// existing field keeps what it was unless `--plain` says otherwise.
fn set_custom(details: &mut Value, label: &str, value: &str, plain: bool) {
    let list = object(details)
        .entry("customFields")
        .or_insert_with(|| json!([]));
    if !list.is_array() {
        *list = json!([]);
    }
    let list = list.as_array_mut().expect("just made a list");
    let same = |field: &&mut Value| {
        field
            .get("label")
            .and_then(Value::as_str)
            .is_some_and(|existing| existing.eq_ignore_ascii_case(label))
    };
    match list.iter_mut().find(|field| same(field)) {
        Some(field) => {
            field["value"] = json!(value);
            if plain {
                field["hidden"] = json!(false);
            }
        }
        None => list.push(json!({ "label": label, "value": value, "hidden": !plain })),
    }
}

fn unset_custom(details: &mut Value, label: &str) -> bool {
    let details = object(details);
    let Some(list) = details
        .get_mut("customFields")
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let before = list.len();
    list.retain(|field| {
        field
            .get("label")
            .and_then(Value::as_str)
            .is_none_or(|existing| !existing.eq_ignore_ascii_case(label))
    });
    let removed = list.len() != before;
    if list.is_empty() {
        details.remove("customFields");
    }
    removed
}

fn strings(overview: &Value, key: &str) -> Vec<String> {
    overview
        .get(key)
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn set_list(overview: &mut Value, key: &str, list: Vec<String>) {
    if list.is_empty() {
        object(overview).remove(key);
    } else {
        overview[key] = json!(list);
    }
}

/// The list row's second line, as the web vault's editor writes it. `before` is the item as it
/// was, so a custom subtitle stays.
fn subtitle(overview: &mut Value, details: &Value, before: Option<&Value>) {
    let text = |value: &Value, key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .filter(|text| !text.is_empty())
    };
    let current = text(overview, "subtitle");
    let next = match overview.get("type").and_then(Value::as_str) {
        Some("login") => {
            let old = before.and_then(|details| text(details, "username"));
            if current.is_none() || current == old {
                text(details, "username")
            } else {
                current
            }
        }
        Some("card") => {
            let digits: String = text(details, "number")
                .unwrap_or_default()
                .chars()
                .filter(char::is_ascii_digit)
                .collect();
            let custom = current
                .as_deref()
                .is_some_and(|subtitle| !ends_with_last_four(subtitle));
            if custom || digits.len() < 4 {
                current
            } else {
                let brand = text(details, "brand").unwrap_or_else(|| "Card".into());
                Some(format!("{brand} ending {}", &digits[digits.len() - 4..]))
            }
        }
        Some("identity") => current.or_else(|| {
            let name: Vec<String> = ["firstName", "lastName"]
                .iter()
                .filter_map(|key| text(details, key))
                .collect();
            (!name.is_empty()).then(|| name.join(" "))
        }),
        Some("wifi") => text(details, "ssid"),
        _ => current,
    };
    match next {
        Some(next) => overview["subtitle"] = json!(next),
        None => {
            object(overview).remove("subtitle");
        }
    }
}

fn ends_with_last_four(subtitle: &str) -> bool {
    subtitle
        .rsplit_once(" ending ")
        .is_some_and(|(_, last)| last.len() == 4 && last.bytes().all(|byte| byte.is_ascii_digit()))
}

impl App {
    /// Values for `--generate` and the typed fields, in order, with the stdin value last.
    fn field_values(
        &mut self,
        item_type: &str,
        args: &FieldArgs,
    ) -> Result<Vec<(Target, Zeroizing<String>)>> {
        let mut values = Vec::new();
        for text in &args.fields {
            let (name, value) = match parse_assignment(text)? {
                Assignment::Set(name, value) => {
                    let secret = matches!(target(item_type, &name)?, Target::Custom(_))
                        && !args.plain
                        || is_secret_field(&name.to_lowercase());
                    if secret && self.context.terminal.interactive() {
                        self.note(&format!(
                            "Warning: other programs can see command-line arguments. Write just `{name}` to type the value instead."
                        ));
                    }
                    (name, Zeroizing::new(value))
                }
                Assignment::Ask(name) => {
                    target(item_type, &name)?;
                    if !self.context.terminal.interactive() {
                        return Err(CliError::usage(format!(
                            "`{name}` needs a value: write {name}=value, use --stdin {name}, or run this in a terminal."
                        )));
                    }
                    let value = self
                        .context
                        .terminal
                        .ask_hidden(&format!("{name}: "))
                        .map_err(input_error)?;
                    (name, value)
                }
            };
            values.push((target(item_type, &name)?, value));
        }
        if args.generate {
            if !fields_of(item_type).is_some_and(|fields| fields.contains(&"password")) {
                return Err(CliError::usage(format!(
                    "--generate makes a password, and a {item_type} has none."
                )));
            }
            let options = match args.words {
                Some(words) => GeneratorOptions::Passphrase(PassphraseOptions {
                    words,
                    ..PassphraseOptions::default()
                }),
                None => GeneratorOptions::Random(RandomOptions {
                    length: args.length.unwrap_or(RandomOptions::default().length),
                    ..RandomOptions::default()
                }),
            };
            let password = generate(&options, &mut OsRng)
                .map_err(|_| CliError::usage("Use 4 to 128 characters, or 3 to 20 words."))?;
            values.push((
                Target::Detail("password".into()),
                Zeroizing::new(password.to_string()),
            ));
        }
        if let Some(name) = &args.stdin {
            let mut text = Zeroizing::new(String::new());
            std::io::Read::read_to_string(&mut self.context.stdin, &mut text)
                .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
            let value = text.strip_suffix('\n').unwrap_or(&text);
            values.push((
                target(item_type, name)?,
                Zeroizing::new(value.trim_end_matches('\r').to_owned()),
            ));
        }
        Ok(values)
    }

    fn check_totp(&self, opened: &Opened, values: &[(Target, Zeroizing<String>)]) -> Result<()> {
        for (target, value) in values {
            if *target == Target::Detail("totp".into())
                && !value.is_empty()
                && opened.vault.totp(value, None).is_err()
            {
                return Err(CliError::usage(
                    "The totp value is neither an otpauth:// link nor a base32 secret.",
                ));
            }
        }
        Ok(())
    }

    fn report_item(&mut self, verb: &str, item: &Item) -> Result<()> {
        if self.global.json {
            self.out_json(&json!({
                "id": item.id,
                "title": item.title(),
                "type": item.overview.get("type"),
                "vaultId": item.vault_id,
                "revision": item.revision,
            }))
        } else {
            self.note(&format!("{verb} “{}”.", item.title()));
            self.out(&item.id)
        }
    }

    pub(crate) async fn create_item(&mut self, args: CreateArgs) -> Result<Option<i32>> {
        let item_type = normalize_type(&args.item_type);
        if let Some(command) = own_command(&item_type) {
            return Err(CliError::usage(format!("Use {command} for this type.")));
        }
        if fields_of(&item_type).is_none() {
            return Err(CliError::usage(format!(
                "Octa Pass can't make a {item_type} from the command line. Choose login, password, note, card, identity or wifi."
            )));
        }
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let vault_id = self.writable_vault(&opened, args.vault.as_deref())?;
        let values = self.field_values(&item_type, &args.values)?;
        self.check_totp(&opened, &values)?;

        let mut details = json!({ "schemaVersion": 1 });
        match item_type.as_str() {
            "secureNote" => details["notes"] = json!(""),
            "wifi" => {
                details["ssid"] = json!("");
                details["security"] = json!("wpa2");
            }
            _ => {}
        }
        let mut overview = json!({ "schemaVersion": 1, "type": item_type, "title": "" });
        for (target, value) in &values {
            match target {
                Target::Detail(field) => set_detail(&mut details, field, value),
                Target::Custom(label) => {
                    set_custom(&mut details, label, value, args.values.plain);
                }
            }
        }
        let title = args
            .title
            .or_else(|| {
                (item_type == "wifi")
                    .then(|| details["ssid"].as_str().map(str::to_owned))
                    .flatten()
            })
            .map(|title| title.trim().to_owned())
            .filter(|title| !title.is_empty())
            .ok_or_else(|| CliError::usage("Give the item a --title."))?;
        overview["title"] = json!(title);
        set_list(&mut overview, "urls", args.urls);
        set_list(&mut overview, "tags", args.tags);
        if args.favorite {
            overview["favorite"] = json!(true);
        }
        subtitle(&mut overview, &details, None);
        let item = opened
            .vault
            .save_item(ItemDraft {
                id: None,
                vault_id,
                revision: None,
                overview,
                details,
            })
            .await?;
        self.report_item("Saved", &item)?;
        Ok(None)
    }

    /// The vault to add to: `query`, or Personal.
    pub(crate) fn writable_vault(&self, opened: &Opened, query: Option<&str>) -> Result<String> {
        let vaults = opened.vault.list_vaults()?;
        let target = match query {
            Some(query) => items::find_vault(&vaults, query)?,
            None => vaults
                .iter()
                .find(|vault| vault.vault_type == octapass_api::VaultType::Personal)
                .ok_or_else(|| CliError::not_found("No Personal vault. Pass --vault."))?,
        };
        if target.role == VaultRole::Read {
            return Err(CliError::other(format!(
                "You can only read the {} vault, not add to it.",
                target.name
            )));
        }
        Ok(target.id.clone())
    }

    pub(crate) async fn edit_item(&mut self, args: EditArgs) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let item = self.find_item(&opened, &args.item, args.vault.as_deref())?;
        let item_type = item
            .overview
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if (!args.values.fields.is_empty() || args.values.stdin.is_some() || args.values.generate)
            && let Some(command) = own_command(&item_type)
        {
            return Err(CliError::usage(format!(
                "This item's fields change through {command}. Here you can change its title, URLs, tags and favorite."
            )));
        }
        let values = self.field_values(&item_type, &args.values)?;
        self.check_totp(&opened, &values)?;

        let before = item.details.clone();
        let mut overview = item.overview.clone();
        let mut details = item.details.clone();
        for (target, value) in &values {
            match target {
                Target::Detail(field) => set_detail(&mut details, field, value),
                Target::Custom(label) => {
                    set_custom(&mut details, label, value, args.values.plain);
                }
            }
        }
        for name in &args.unset {
            match target(&item_type, name)? {
                Target::Detail(field) if field == "ssid" || field == "security" => {
                    return Err(CliError::usage(format!("A wifi item needs its {field}.")));
                }
                Target::Detail(field) => {
                    if item_type == "secureNote" {
                        details["notes"] = json!("");
                    } else {
                        unset_detail(&mut details, &field);
                    }
                }
                Target::Custom(label) => {
                    if !unset_custom(&mut details, &label) {
                        return Err(CliError::not_found(format!(
                            "“{}” has no field called \"{label}\".",
                            item.title()
                        )));
                    }
                }
            }
        }
        if let Some(title) = args.title {
            let title = title.trim().to_owned();
            if title.is_empty() {
                return Err(CliError::usage("The title is empty."));
            }
            overview["title"] = json!(title);
        }
        let mut urls = strings(&overview, "urls");
        urls.extend(args.add_urls);
        urls.retain(|url| !args.remove_urls.contains(url));
        set_list(&mut overview, "urls", urls);
        let mut tags = strings(&overview, "tags");
        for tag in args.add_tags {
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        tags.retain(|tag| !args.remove_tags.contains(tag));
        set_list(&mut overview, "tags", tags);
        if args.favorite {
            overview["favorite"] = json!(true);
        }
        if args.no_favorite {
            object(&mut overview).remove("favorite");
        }
        // Set by importers, and only true until the item is edited here.
        object(&mut overview).remove("updatedAt");
        subtitle(&mut overview, &details, Some(&before));

        if overview == item.overview && details == item.details {
            self.note("Nothing to change.");
            return Ok(None);
        }
        let saved = opened
            .vault
            .save_item(ItemDraft {
                id: Some(item.id.clone()),
                vault_id: item.vault_id.clone(),
                revision: Some(item.revision),
                overview,
                details,
            })
            .await?;
        if saved.id != item.id {
            // The server had a newer version: the vault kept both, as in every other client.
            self.note(&format!(
                "“{}” changed on another device, so this was saved as a copy.",
                item.title()
            ));
        }
        self.report_item("Saved", &saved)?;
        Ok(None)
    }

    pub(crate) async fn delete_item(
        &mut self,
        query: String,
        vault: Option<String>,
    ) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let item = self.find_item(&opened, &query, vault.as_deref())?;
        opened.vault.delete_item(&item.id).await?;
        self.report_item("Moved to the trash:", &item)?;
        Ok(None)
    }

    pub(crate) async fn restore_item(&mut self, query: String) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let mut rows = opened.vault.list_items()?;
        rows.retain(|row| row.deleted_at.is_some());
        let row = items::find_item(&rows, &query).map_err(|error| match error.exit {
            Exit::NotFound => {
                CliError::not_found(format!("Nothing in the trash is called \"{query}\"."))
            }
            _ => error,
        })?;
        let id = row.id.clone();
        opened.vault.restore_item(&id).await?;
        let item = opened.vault.get_item(&id)?;
        self.report_item("Restored", &item)?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments() {
        assert_eq!(
            parse_assignment("username=ada=lovelace").unwrap(),
            Assignment::Set("username".into(), "ada=lovelace".into())
        );
        assert_eq!(
            parse_assignment("notes=").unwrap(),
            Assignment::Set("notes".into(), String::new())
        );
        assert_eq!(
            parse_assignment("password").unwrap(),
            Assignment::Ask("password".into())
        );
        assert_eq!(parse_assignment("=x").unwrap_err().exit, Exit::Usage);
    }

    #[test]
    fn names_find_their_field() {
        assert_eq!(
            target("identity", "FirstName").unwrap(),
            Target::Detail("firstName".into())
        );
        assert_eq!(
            target("login", "API key").unwrap(),
            Target::Custom("API key".into())
        );
        assert_eq!(target("card", "colour").unwrap_err().exit, Exit::Usage);
    }

    #[test]
    fn custom_fields_are_kept_by_label() {
        let mut details = json!({});
        set_custom(&mut details, "API key", "one", false);
        set_custom(&mut details, "api KEY", "two", false);
        set_custom(&mut details, "Region", "eu", true);
        assert_eq!(
            details["customFields"],
            json!([
                { "label": "API key", "value": "two", "hidden": true },
                { "label": "Region", "value": "eu", "hidden": false }
            ])
        );
        assert!(unset_custom(&mut details, "region"));
        assert!(!unset_custom(&mut details, "region"));
        assert!(unset_custom(&mut details, "api key"));
        assert_eq!(details, json!({}));
    }

    #[test]
    fn address_parts_nest() {
        let mut details = json!({});
        set_detail(&mut details, "address.city", "Cairo");
        assert_eq!(details, json!({ "address": { "city": "Cairo" } }));
        unset_detail(&mut details, "address.city");
        assert_eq!(details, json!({}));
    }

    #[test]
    fn subtitles_read_like_the_web_vaults() {
        let mut login = json!({ "type": "login" });
        subtitle(&mut login, &json!({ "username": "ada" }), None);
        assert_eq!(login["subtitle"], "ada");
        // Follows the username, but a custom one stays.
        subtitle(
            &mut login,
            &json!({ "username": "grace" }),
            Some(&json!({ "username": "ada" })),
        );
        assert_eq!(login["subtitle"], "grace");
        let mut custom = json!({ "type": "login", "subtitle": "Work account" });
        subtitle(
            &mut custom,
            &json!({ "username": "ada" }),
            Some(&json!({ "username": "x" })),
        );
        assert_eq!(custom["subtitle"], "Work account");

        let mut card = json!({ "type": "card" });
        subtitle(
            &mut card,
            &json!({ "number": "4111 1111 1111 1234", "brand": "Visa" }),
            None,
        );
        assert_eq!(card["subtitle"], "Visa ending 1234");
        subtitle(&mut card, &json!({ "number": "4111111111119999" }), None);
        assert_eq!(card["subtitle"], "Card ending 9999");

        let mut person = json!({ "type": "identity" });
        subtitle(
            &mut person,
            &json!({ "firstName": "Ada", "lastName": "L" }),
            None,
        );
        assert_eq!(person["subtitle"], "Ada L");
    }

    #[test]
    fn types_have_friendly_names() {
        assert_eq!(normalize_type("note"), "secureNote");
        assert_eq!(normalize_type("Login"), "login");
    }
}
