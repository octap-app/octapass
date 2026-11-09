//! `octapass create`, `edit`, `delete` and `restore`. Items are JSON end to end, so fields this
//! version doesn't know about stay as they are. Subtitles follow the web vault's editor
//! (`apps/web/src/screens/vault/editorModel.ts`), so a row reads the same in every client.

use octapass_api::VaultRole;
use octapass_core::item_fields::{self, CUSTOM_FIELD_KINDS, FieldKind, TABLE_TYPES};
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
/// The newer types' fields come from the core's table (`octapass_core::item_fields`), the one the
/// apps build their editors from. A wallet's addresses are `address.<network>`; a custom item's
/// fields and a template's are named by their labels.
fn fields_of(item_type: &str) -> Option<Vec<&'static str>> {
    if TABLE_TYPES.contains(&item_type) {
        let mut fields: Vec<&'static str> = item_fields::fields_of(item_type)
            .iter()
            .map(|field| field.key)
            .collect();
        fields.push("notes");
        return Some(fields);
    }
    Some(match item_type {
        "custom" => vec!["notes"],
        "customTemplate" => vec![],
        _ => return fields_of_older(item_type).map(<[&str]>::to_vec),
    })
}

fn fields_of_older(item_type: &str) -> Option<&'static [&'static str]> {
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

/// Every type `create` makes, as the error and `--help` name them.
const CREATABLE: &str = "login, password, note, card, identity, wifi, bank-account, api-credential, licence, id-document, wallet, database, custom or template";

/// Values worth a warning when they arrive on the command line.
fn is_secret_field(item_type: &str, name: &str) -> bool {
    let table = item_fields::fields_of(item_type);
    if let Some(field) = table.iter().find(|field| same_name(field.key, name)) {
        return field.kind.is_secret();
    }
    matches!(
        name.to_lowercase().as_str(),
        "password" | "totp" | "number" | "cvv" | "pin"
    )
}

/// `licenseKey`, `license-key`, `license_key` and `LICENSEKEY` are one name.
fn same_name(field: &str, name: &str) -> bool {
    let fold = |text: &str| {
        text.chars()
            .filter(|c| !matches!(c, '-' | '_' | ' '))
            .collect::<String>()
            .to_lowercase()
    };
    fold(field) == fold(name)
}

/// Types made by their own commands, whose details need more than typed values.
fn own_command(item_type: &str) -> Option<&'static str> {
    match item_type {
        "sshKey" => Some("octapass ssh generate or octapass ssh import"),
        "gpgKey" => Some("octapass gpg import"),
        "environment" => Some("octapass env create"),
        "certificate" => {
            Some("octapass cert self-signed, cert ca-create or cert issue with --save")
        }
        "key" => Some("octapass key generate, key age or key gpg with --save"),
        _ => None,
    }
}

fn normalize_type(item_type: &str) -> String {
    match item_type.to_lowercase().as_str() {
        "note" | "securenote" | "secure-note" => "secureNote".into(),
        "sshkey" | "ssh-key" => "sshKey".into(),
        "gpgkey" | "gpg-key" => "gpgKey".into(),
        "login" | "password" | "card" | "identity" | "wifi" | "document" | "environment"
        | "database" | "custom" | "certificate" | "key" => item_type.to_lowercase(),
        "bank" | "bankaccount" | "bank-account" => "bankAccount".into(),
        "api" | "apikey" | "api-key" | "apicredential" | "api-credential" => "apiCredential".into(),
        "licence" | "license" | "softwarelicense" | "software-license" | "software-licence" => {
            "softwareLicense".into()
        }
        "id" | "iddocument" | "id-document" => "idDocument".into(),
        "wallet" | "cryptowallet" | "crypto-wallet" => "cryptoWallet".into(),
        "db" => "database".into(),
        "template" | "customtemplate" | "custom-template" => "customTemplate".into(),
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

/// Where a typed name goes: a details field, a custom field with this label (a custom item's or a
/// template's own fields too), or a wallet's address on this network.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    Detail(String),
    Custom(String),
    Address(String),
}

fn target(item_type: &str, name: &str) -> Result<Target> {
    let Some(fields) = fields_of(item_type) else {
        return Ok(Target::Detail(name.to_owned()));
    };
    if let Some(field) = fields.iter().find(|field| same_name(field, name)) {
        return Ok(Target::Detail((*field).to_owned()));
    }
    if item_type == "cryptoWallet"
        && let Some((_, network)) = name.split_once('.').filter(|(head, _)| {
            head.eq_ignore_ascii_case("address") || head.eq_ignore_ascii_case("addresses")
        })
        && !network.trim().is_empty()
    {
        return Ok(Target::Address(network.trim().to_lowercase()));
    }
    if matches!(
        item_type,
        "login" | "password" | "wifi" | "custom" | "customTemplate"
    ) {
        return Ok(Target::Custom(name.to_owned()));
    }
    let wallet = if item_type == "cryptoWallet" {
        ", and address.<network> (address.bitcoin, address.ethereum…)"
    } else {
        ""
    };
    Err(CliError::usage(format!(
        "A {item_type} has no field called \"{name}\". It has: {}{wallet}.",
        fields.join(", ")
    )))
}

/// A list field's value as the table writes it, or a usage error naming the choices.
fn choice_value(item_type: &str, field: &str, value: &str) -> Result<String> {
    let Some(spec) = item_fields::fields_of(item_type)
        .iter()
        .find(|spec| spec.key == field && spec.kind == FieldKind::Choice)
    else {
        return Ok(value.to_owned());
    };
    if value.is_empty() {
        return Ok(String::new());
    }
    spec.choices
        .iter()
        .find(|choice| same_name(choice, value))
        .map(|choice| (*choice).to_owned())
        .ok_or_else(|| CliError::usage(format!("{field} is one of: {}.", spec.choices.join(", "))))
}

/// What the core's checks say about the item's values, in words, or nothing when it can be saved.
fn check_values(item_type: &str, details: &Value) -> Result<()> {
    let problems: Vec<String> = item_fields::validate(item_type, details)
        .into_iter()
        .map(|(field, problem)| {
            let what = match problem {
                "date" => "isn't a date: write YYYY-MM-DD",
                "port" => "isn't a port: 1 to 65535",
                "email" => "isn't an email address",
                "iban" => "isn't a valid IBAN: its check digits don't match",
                "swift" => "isn't a SWIFT code: 8 or 11 letters and digits",
                "walletAddress" => "isn't an address: it has a space or isn't one line",
                _ => "can't be saved",
            };
            let field = match field.strip_prefix("addresses.") {
                Some(index) => details["addresses"][index.parse::<usize>().unwrap_or(0)]["network"]
                    .as_str()
                    .map_or(field.clone(), |network| format!("address.{network}")),
                None => field,
            };
            format!("{field} {what}")
        })
        .collect();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(CliError::usage(format!("{}.", problems.join("; "))))
    }
}

/// A wallet's address on `network`, added or changed.
fn set_address(details: &mut Value, network: &str, value: &str) {
    let list = object(details)
        .entry("addresses")
        .or_insert_with(|| json!([]));
    if !list.is_array() {
        *list = json!([]);
    }
    let list = list.as_array_mut().expect("just made a list");
    let on = |entry: &&mut Value| {
        entry
            .get("network")
            .and_then(Value::as_str)
            .is_some_and(|existing| existing.eq_ignore_ascii_case(network))
    };
    match list.iter_mut().find(|entry| on(entry)) {
        Some(entry) => entry["address"] = json!(value),
        None => list.push(json!({ "network": network, "address": value })),
    }
}

fn unset_address(details: &mut Value, network: &str) -> bool {
    let details = object(details);
    let Some(list) = details.get_mut("addresses").and_then(Value::as_array_mut) else {
        return false;
    };
    let before = list.len();
    list.retain(|entry| {
        entry
            .get("network")
            .and_then(Value::as_str)
            .is_none_or(|existing| !existing.eq_ignore_ascii_case(network))
    });
    let removed = list.len() != before;
    if list.is_empty() {
        details.remove("addresses");
    }
    removed
}

/// A custom item's field, or a template's (whose "value" is the field's kind), by label.
fn set_typed_field(
    details: &mut Value,
    template: bool,
    label: &str,
    value: &str,
    plain: bool,
) -> Result<()> {
    if template && !CUSTOM_FIELD_KINDS.contains(&value) {
        return Err(CliError::usage(format!(
            "A template field's value is its kind: {}.",
            CUSTOM_FIELD_KINDS.join(", ")
        )));
    }
    let list = object(details).entry("fields").or_insert_with(|| json!([]));
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
    match (list.iter_mut().find(|field| same(field)), template) {
        (Some(field), true) => field["kind"] = json!(value),
        (Some(field), false) => {
            field["value"] = json!(value);
            if plain {
                field["kind"] = json!("text");
            }
        }
        (None, true) => list.push(json!({ "label": label, "kind": value })),
        (None, false) => {
            let kind = if plain { "text" } else { "hidden" };
            list.push(json!({ "label": label, "value": value, "kind": kind }));
        }
    }
    Ok(())
}

fn unset_typed_field(details: &mut Value, label: &str) -> bool {
    let Some(list) = object(details)
        .get_mut("fields")
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
    list.len() != before
}

/// Puts one typed value where it goes on an item of `item_type`.
fn apply(
    item_type: &str,
    details: &mut Value,
    target: &Target,
    value: &str,
    plain: bool,
) -> Result<()> {
    match target {
        Target::Detail(field) => {
            let value = choice_value(item_type, field, value)?;
            set_detail(details, field, &value);
        }
        Target::Address(network) => set_address(details, network, value),
        Target::Custom(label) if matches!(item_type, "custom" | "customTemplate") => {
            set_typed_field(details, item_type == "customTemplate", label, value, plain)?;
        }
        Target::Custom(label) => set_custom(details, label, value, plain),
    }
    Ok(())
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
        // The newer types take theirs from one field that is never a secret, as the web vault does.
        Some(kind) if TABLE_TYPES.contains(&kind) || kind == "custom" => {
            item_fields::subtitle_key(kind).and_then(|key| text(details, key))
        }
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
                // A template's fields are named, not filled: `Locker` alone is a text field.
                Assignment::Ask(name) if item_type == "customTemplate" => {
                    target(item_type, &name)?;
                    (name, Zeroizing::new("text".to_owned()))
                }
                Assignment::Set(name, value) => {
                    let secret = item_type != "customTemplate"
                        && (matches!(target(item_type, &name)?, Target::Custom(_)) && !args.plain
                            || is_secret_field(item_type, &name));
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
                "Octa Pass can't make a {item_type} from the command line. Choose {CREATABLE}."
            )));
        }
        if args.template.is_some() && item_type != "custom" {
            return Err(CliError::usage(
                "--template is for custom items: octapass create custom --template NAME.",
            ));
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
            "custom" | "customTemplate" => details["fields"] = json!([]),
            _ => {}
        }
        if let Some(name) = &args.template {
            self.copy_template(&opened, name, &mut details)?;
        }
        let mut overview = json!({ "schemaVersion": 1, "type": item_type, "title": "" });
        for (target, value) in &values {
            apply(&item_type, &mut details, target, value, args.values.plain)?;
        }
        check_values(&item_type, &details)?;
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

    /// A custom item starts with its template's fields, empty, as the apps make one (plan 01).
    fn copy_template(&self, opened: &Opened, name: &str, details: &mut Value) -> Result<()> {
        let rows = opened.vault.list_items()?;
        let templates: Vec<_> = rows
            .into_iter()
            .filter(|row| row.deleted_at.is_none() && row.item_type == "customTemplate")
            .collect();
        let row = items::find_item(&templates, name).map_err(|error| match error.exit {
            Exit::NotFound => CliError::not_found(format!("No template is called \"{name}\".")),
            _ => error,
        })?;
        let template = opened.vault.get_item(&row.id)?;
        let fields: Vec<Value> = template.details["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|field| {
                let label = field.get("label")?.as_str()?;
                let kind = field.get("kind").and_then(Value::as_str).unwrap_or("text");
                Some(json!({ "label": label, "value": "", "kind": kind }))
            })
            .collect();
        details["templateId"] = json!(template.id);
        details["templateName"] = json!(template.title());
        details["fields"] = json!(fields);
        Ok(())
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
            apply(&item_type, &mut details, target, value, args.values.plain)?;
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
                    let removed = if matches!(item_type.as_str(), "custom" | "customTemplate") {
                        unset_typed_field(&mut details, &label)
                    } else {
                        unset_custom(&mut details, &label)
                    };
                    if !removed {
                        return Err(CliError::not_found(format!(
                            "“{}” has no field called \"{label}\".",
                            item.title()
                        )));
                    }
                }
                Target::Address(network) => {
                    if !unset_address(&mut details, &network) {
                        return Err(CliError::not_found(format!(
                            "“{}” has no {network} address.",
                            item.title()
                        )));
                    }
                }
            }
        }
        check_values(&item_type, &details)?;
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
        for (name, item_type) in [
            ("bank-account", "bankAccount"),
            ("bank", "bankAccount"),
            ("api-credential", "apiCredential"),
            ("licence", "softwareLicense"),
            ("license", "softwareLicense"),
            ("id-document", "idDocument"),
            ("wallet", "cryptoWallet"),
            ("db", "database"),
            ("Database", "database"),
            ("custom", "custom"),
            ("template", "customTemplate"),
        ] {
            assert_eq!(normalize_type(name), item_type, "{name}");
            assert!(fields_of(item_type).is_some(), "{item_type}");
        }
    }

    #[test]
    fn the_newer_types_take_the_core_tables_fields() {
        assert_eq!(
            target("softwareLicense", "license-key").unwrap(),
            Target::Detail("licenseKey".into())
        );
        assert_eq!(
            target("bankAccount", "IBAN").unwrap(),
            Target::Detail("iban".into())
        );
        assert_eq!(
            target("database", "connection_string").unwrap(),
            Target::Detail("connectionString".into())
        );
        assert_eq!(
            target("idDocument", "expiryDate").unwrap(),
            Target::Detail("expiryDate".into())
        );
        assert_eq!(
            target("cryptoWallet", "address.Bitcoin").unwrap(),
            Target::Address("bitcoin".into())
        );
        assert_eq!(
            target("custom", "Locker").unwrap(),
            Target::Custom("Locker".into())
        );
        let unknown = target("apiCredential", "colour").unwrap_err();
        assert!(unknown.message.contains("key, secret, host"), "{unknown:?}");
        assert!(is_secret_field("cryptoWallet", "seed-phrase"));
        assert!(is_secret_field("database", "password"));
        assert!(!is_secret_field("bankAccount", "iban"));
        assert!(is_secret_field("bankAccount", "pin"));
    }

    #[test]
    fn lists_take_their_choices_and_values_are_checked() {
        assert_eq!(
            choice_value("bankAccount", "accountType", "Savings").unwrap(),
            "savings"
        );
        assert_eq!(
            choice_value("idDocument", "documentType", "driver-license").unwrap(),
            "driverLicense"
        );
        assert!(
            choice_value("database", "databaseType", "excel")
                .unwrap_err()
                .message
                .contains("postgresql")
        );
        assert!(
            check_values(
                "bankAccount",
                &json!({ "iban": "DE89 3704 0044 0532 0130 00", "swift": "COBADEFFXXX" })
            )
            .is_ok()
        );
        let bad = check_values(
            "bankAccount",
            &json!({ "iban": "DE00 3704 0044 0532 0130 00", "swift": "x" }),
        )
        .unwrap_err();
        assert!(bad.message.contains("iban isn't a valid IBAN") && bad.message.contains("swift"));
        assert!(check_values("softwareLicense", &json!({ "expiryDate": "2027-02-30" })).is_err());
        assert!(check_values("database", &json!({ "port": "70000" })).is_err());
        let wallet = check_values(
            "cryptoWallet",
            &json!({ "addresses": [{ "network": "bitcoin", "address": "two words" }] }),
        )
        .unwrap_err();
        assert!(wallet.message.starts_with("address.bitcoin"), "{wallet:?}");
    }

    #[test]
    fn wallet_addresses_and_custom_fields() {
        let mut wallet = json!({});
        set_address(&mut wallet, "bitcoin", "bc1one");
        set_address(&mut wallet, "ethereum", "0xtwo");
        set_address(&mut wallet, "Bitcoin", "bc1three");
        assert_eq!(
            wallet["addresses"],
            json!([
                { "network": "bitcoin", "address": "bc1three" },
                { "network": "ethereum", "address": "0xtwo" }
            ])
        );
        assert!(unset_address(&mut wallet, "ethereum"));
        assert!(!unset_address(&mut wallet, "ethereum"));

        let mut custom = json!({ "fields": [{ "label": "Locker", "value": "", "kind": "text" }] });
        set_typed_field(&mut custom, false, "locker", "12", false).unwrap();
        set_typed_field(&mut custom, false, "Combination", "4-8-15", false).unwrap();
        set_typed_field(&mut custom, false, "Gym", "North", true).unwrap();
        assert_eq!(
            custom["fields"],
            json!([
                { "label": "Locker", "value": "12", "kind": "text" },
                { "label": "Combination", "value": "4-8-15", "kind": "hidden" },
                { "label": "Gym", "value": "North", "kind": "text" }
            ])
        );
        let mut template = json!({ "fields": [] });
        set_typed_field(&mut template, true, "Combination", "hidden", false).unwrap();
        assert_eq!(
            template["fields"],
            json!([{ "label": "Combination", "kind": "hidden" }])
        );
        assert!(set_typed_field(&mut template, true, "Odd", "colour", false).is_err());
    }

    #[test]
    fn the_newer_types_subtitles_come_from_their_field() {
        let mut bank = json!({ "type": "bankAccount" });
        subtitle(
            &mut bank,
            &json!({ "bankName": "Example Bank", "iban": "DE89" }),
            None,
        );
        assert_eq!(bank["subtitle"], "Example Bank");
        let mut database = json!({ "type": "database", "subtitle": "old" });
        subtitle(&mut database, &json!({ "password": "pw" }), None);
        assert!(database.get("subtitle").is_none());
        let mut custom = json!({ "type": "custom" });
        subtitle(&mut custom, &json!({ "templateName": "Gym locker" }), None);
        assert_eq!(custom["subtitle"], "Gym locker");
    }
}
