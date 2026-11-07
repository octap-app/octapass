//! Item types the apps show from a table instead of a screen of their own: bank accounts, API
//! credentials, software licences, ID documents, crypto wallets, databases, custom items and
//! custom templates (plan 01). `fieldSpecs` gives the table (`octapass_core::item_fields`), and the
//! values travel by key, so Swift and Kotlin have one editor and one detail screen for all of them.
//! Labels are the catalog's `itemFields.<key>` and `itemChoices.<key>.<choice>`.

use octapass_core::item_fields::{self, CUSTOM_FIELD_KINDS, FieldKind};
use serde_json::{Map, Value};

use crate::items::{
    CustomField, ItemType, PasswordHistoryEntry, object, set_list, set_text, text,
    write_custom_fields,
};

/// How a field is edited and shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FieldStyle {
    Text,
    /// A number or code: left to right in every language, in the mono font.
    Code,
    /// One of `choices`, or the words another app used.
    Choice,
    /// `YYYY-MM-DD`
    Date,
    Email,
    Port,
    /// Hidden until revealed.
    Secret,
    /// Hidden until revealed, over several lines.
    SecretLong,
}

/// One field of a type. The label is the catalog's `itemFields.<key>`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FieldSpec {
    pub key: String,
    pub style: FieldStyle,
    /// The catalog has `itemChoices.<key>.<choice>` for each.
    pub choices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FieldValue {
    pub key: String,
    pub value: String,
}

/// One receiving address of a crypto wallet.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct WalletAddress {
    /// `bitcoin`, `ethereum`, or the name of another chain.
    pub network: String,
    pub address: String,
    pub label: Option<String>,
}

/// A field of a custom item, or of a template (whose values stay empty). `kind` is one of
/// `customFieldKinds()`, or a newer one, which counts as hidden.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct TypedField {
    pub label: String,
    pub value: String,
    pub kind: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Record)]
pub struct StructuredDetails {
    /// The table's fields that have a value, in table order.
    pub values: Vec<FieldValue>,
    /// Crypto wallets.
    pub addresses: Vec<WalletAddress>,
    /// Custom items and templates.
    pub fields: Vec<TypedField>,
    /// The template a custom item was made from, and its name then.
    pub template_id: Option<String>,
    pub template_name: Option<String>,
    pub notes: Option<String>,
    pub custom_fields: Vec<CustomField>,
    /// Newest first. Read-only: a save moves a changed password here.
    pub password_history: Vec<PasswordHistoryEntry>,
}

fn style_of(kind: FieldKind) -> FieldStyle {
    match kind {
        FieldKind::Text => FieldStyle::Text,
        FieldKind::Code => FieldStyle::Code,
        FieldKind::Choice => FieldStyle::Choice,
        FieldKind::Date => FieldStyle::Date,
        FieldKind::Email => FieldStyle::Email,
        FieldKind::Port => FieldStyle::Port,
        FieldKind::Secret => FieldStyle::Secret,
        FieldKind::SecretLong => FieldStyle::SecretLong,
    }
}

/// The fields of `itemType`, in the order they're shown. Empty for a type without a table.
#[uniffi::export]
pub fn field_specs(item_type: ItemType) -> Vec<FieldSpec> {
    item_fields::fields_of(item_type.name())
        .iter()
        .map(|spec| FieldSpec {
            key: spec.key.to_owned(),
            style: style_of(spec.kind),
            choices: spec.choices.iter().map(|c| (*c).to_owned()).collect(),
        })
        .collect()
}

/// A custom item's field kinds, in the order the editor offers them. The catalog has
/// `itemChoices.customKind.<kind>` for each.
#[uniffi::export]
pub fn custom_field_kinds() -> Vec<String> {
    CUSTOM_FIELD_KINDS.iter().map(|k| (*k).to_owned()).collect()
}

/// Only these show without asking. Every other kind, a newer one included, counts as a secret.
#[uniffi::export]
pub fn custom_kind_is_plain(kind: String) -> bool {
    item_fields::custom_kind_is_plain(&kind)
}

/// The fields a new custom item starts with, from a template's: same names and kinds, no values.
#[uniffi::export]
pub fn fields_from_template(template: StructuredDetails) -> Vec<TypedField> {
    template
        .fields
        .into_iter()
        .map(|field| TypedField {
            value: String::new(),
            ..field
        })
        .collect()
}

/// What a custom item saves as a template: field names and kinds, never its values.
#[uniffi::export]
pub fn template_from_item(item: StructuredDetails) -> StructuredDetails {
    StructuredDetails {
        fields: item
            .fields
            .into_iter()
            .filter(|field| !field.label.trim().is_empty())
            .map(|field| TypedField {
                label: field.label.trim().to_owned(),
                value: String::new(),
                kind: field.kind,
            })
            .collect(),
        ..StructuredDetails::default()
    }
}

/// A value of the table, by key.
pub(crate) fn value<'a>(details: &'a StructuredDetails, key: &str) -> Option<&'a str> {
    details
        .values
        .iter()
        .find(|entry| entry.key == key)
        .map(|entry| entry.value.as_str())
        .filter(|value| !value.is_empty())
}

fn entries(details: &Value, key: &str) -> Vec<Map<String, Value>> {
    details
        .get(key)
        .and_then(Value::as_array)
        .map(|list| list.iter().map(object).collect())
        .unwrap_or_default()
}

pub(crate) fn read(item_type: &str, details: &Value) -> StructuredDetails {
    let map = object(details);
    StructuredDetails {
        values: item_fields::fields_of(item_type)
            .iter()
            .filter_map(|spec| {
                let value = text(&map, spec.key).filter(|value| !value.is_empty())?;
                Some(FieldValue {
                    key: spec.key.to_owned(),
                    value,
                })
            })
            .collect(),
        addresses: entries(details, "addresses")
            .iter()
            .map(|entry| WalletAddress {
                network: text(entry, "network").unwrap_or_default(),
                address: text(entry, "address").unwrap_or_default(),
                label: text(entry, "label"),
            })
            .collect(),
        fields: entries(details, "fields")
            .iter()
            .map(|entry| TypedField {
                label: text(entry, "label").unwrap_or_default(),
                value: text(entry, "value").unwrap_or_default(),
                kind: text(entry, "kind").unwrap_or_else(|| "text".into()),
            })
            .collect(),
        template_id: text(&map, "templateId"),
        template_name: text(&map, "templateName"),
        notes: text(&map, "notes"),
        custom_fields: entries(details, "customFields")
            .iter()
            .map(|entry| CustomField {
                label: text(entry, "label").unwrap_or_default(),
                value: text(entry, "value").unwrap_or_default(),
                hidden: entry.get("hidden") == Some(&Value::Bool(true)),
            })
            .collect(),
        password_history: entries(details, "passwordHistory")
            .iter()
            .map(|entry| PasswordHistoryEntry {
                password: text(entry, "password").unwrap_or_default(),
                changed_at: text(entry, "changedAt").unwrap_or_default(),
            })
            .collect(),
    }
}

/// Secrets stay exactly as typed: spaces can be part of them. Everything else is trimmed.
fn set_value(map: &mut Map<String, Value>, key: &str, secret: bool, value: &str) {
    let value = if secret { value } else { value.trim() };
    if value.is_empty() {
        map.remove(key);
    } else {
        map.insert(key.into(), Value::String(value.into()));
    }
}

pub(crate) fn write(item_type: &str, map: &mut Map<String, Value>, details: &StructuredDetails) {
    for spec in item_fields::fields_of(item_type) {
        let value = details
            .values
            .iter()
            .find(|entry| entry.key == spec.key)
            .map_or("", |entry| entry.value.as_str());
        set_value(map, spec.key, spec.kind.is_secret(), value);
    }
    match item_type {
        "cryptoWallet" => set_list(
            map,
            "addresses",
            &details.addresses,
            |entry, address| {
                entry.insert(
                    "network".into(),
                    Value::String(address.network.trim().into()),
                );
                entry.insert(
                    "address".into(),
                    Value::String(address.address.trim().into()),
                );
                set_text(entry, "label", &address.label);
            },
            |entry| {
                entry
                    .get("address")
                    .and_then(Value::as_str)
                    .is_some_and(|address| !address.is_empty())
            },
        ),
        "custom" => {
            write_typed_fields(map, &details.fields, true);
            set_text(map, "templateId", &details.template_id);
            set_text(map, "templateName", &details.template_name);
        }
        "customTemplate" => write_typed_fields(map, &details.fields, false),
        _ => {}
    }
    if item_type != "customTemplate" {
        set_text(map, "notes", &details.notes);
    }
    if !matches!(item_type, "custom" | "customTemplate") {
        write_custom_fields(map, &details.custom_fields);
    }
}

/// The list is written whole, and stays when empty: the model requires it. A template's fields have
/// no values.
fn write_typed_fields(map: &mut Map<String, Value>, fields: &[TypedField], with_values: bool) {
    set_list(
        map,
        "fields",
        fields,
        |entry, field| {
            entry.insert("label".into(), Value::String(field.label.trim().into()));
            entry.insert("kind".into(), Value::String(field.kind.clone()));
            if with_values {
                entry.insert("value".into(), Value::String(field.value.clone()));
            } else {
                entry.remove("value");
            }
        },
        |entry| {
            ["label", "value"].iter().any(|key| {
                entry
                    .get(*key)
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.is_empty())
            })
        },
    );
    map.entry("fields")
        .or_insert_with(|| Value::Array(Vec::new()));
}

/// `(field, message)` under the catalog's `validation` group.
pub(crate) fn validate(
    item_type: &str,
    details: &StructuredDetails,
) -> Vec<(String, &'static str)> {
    let mut map = Map::new();
    for entry in &details.values {
        map.insert(entry.key.clone(), Value::String(entry.value.clone()));
    }
    map.insert(
        "addresses".into(),
        Value::Array(
            details
                .addresses
                .iter()
                .map(|entry| serde_json::json!({ "address": entry.address.trim() }))
                .collect(),
        ),
    );
    item_fields::validate(item_type, &Value::Object(map))
}
