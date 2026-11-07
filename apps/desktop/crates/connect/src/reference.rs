//! `octapass://<vault>/<item>/<field>` references, and finding a field in an item.

use octapass_core::item_fields;
use octapass_desktop_vault::model::Item;
use serde_json::Value;

pub const SCHEME: &str = "octapass://";

/// Details fields that are shown without asking. Everything else counts as a secret.
const PLAIN_FIELDS: &[&str] = &[
    "username",
    "email",
    "phone",
    "firstName",
    "lastName",
    "cardholder",
    "brand",
    "expiry",
    "birthDate",
    // Environments: which project and stage an environment is for.
    "project",
    "projectName",
    "stage",
    // Custom items: which of the user's types this is.
    "templateName",
];

/// `octapass://<vault>/<item>/<field>`. Each part is a name or an id; `%2F` stands for a `/`
/// inside a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub vault: String,
    pub item: String,
    pub field: String,
}

impl Reference {
    /// `None` for anything that isn't a whole reference.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.trim().strip_prefix(SCHEME)?;
        let parts: Vec<&str> = rest.split('/').collect();
        let [vault, item, field] = parts.as_slice() else {
            return None;
        };
        let decode = |part: &str| percent_decode(part).filter(|part| !part.trim().is_empty());
        Some(Self {
            vault: decode(vault)?,
            item: decode(item)?,
            field: decode(field)?,
        })
    }

    pub fn is_reference(text: &str) -> bool {
        text.trim().starts_with(SCHEME)
    }

    /// The reference as written, for messages.
    pub fn text(&self) -> String {
        format!(
            "{SCHEME}{}/{}/{}",
            encode(&self.vault),
            encode(&self.item),
            encode(&self.field)
        )
    }
}

fn encode(part: &str) -> String {
    part.replace('%', "%25").replace('/', "%2F")
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A field's value and whether it's a secret (a warning is shown before a secret is printed to a
/// terminal).
#[derive(Debug, PartialEq, Eq)]
pub struct Field {
    pub value: String,
    pub secret: bool,
}

/// The field `name`, by the names people use. `totp` is the current code, which callers compute.
pub fn field(item: &Item, name: &str) -> Option<Field> {
    let lower = name.trim().to_lowercase();
    let plain = |value: Option<&str>| {
        value.filter(|value| !value.is_empty()).map(|value| Field {
            value: value.to_owned(),
            secret: false,
        })
    };
    // An environment's variables come first, by exact name, then by name in any case after the
    // usual fields.
    if let Some(found) = variable(item, |key| key == name.trim()) {
        return Some(found);
    }
    match lower.as_str() {
        "title" => plain(Some(title(item))),
        "url" | "website" => plain(
            item.overview
                .get("urls")
                .and_then(Value::as_array)
                .and_then(|urls| urls.first())
                .and_then(Value::as_str),
        ),
        "notes" => item.detail("notes").map(|notes| Field {
            value: notes.to_owned(),
            // A secure note's text is the secret it keeps.
            secret: item.overview.get("type").and_then(Value::as_str) == Some("secureNote"),
        }),
        _ => detail(item, &lower)
            .or_else(|| typed_field(item, &lower))
            .or_else(|| wallet_address(item, &lower))
            .or_else(|| custom_field(item, &lower))
            .or_else(|| variable(item, |key| key.to_lowercase() == lower)),
    }
}

fn title(item: &Item) -> &str {
    item.overview
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

pub fn is_environment(item: &Item) -> bool {
    item.overview.get("type").and_then(Value::as_str) == Some("environment")
}

/// An environment's variable whose name passes `matches`. Empty values count: an environment
/// can set a variable to nothing.
fn variable(item: &Item, matches: impl Fn(&str) -> bool) -> Option<Field> {
    if !is_environment(item) {
        return None;
    }
    item.details
        .get("variables")?
        .as_array()?
        .iter()
        .find(|var| var.get("key").and_then(Value::as_str).is_some_and(&matches))
        .map(|var| Field {
            value: var
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            secret: var.get("concealed") != Some(&Value::Bool(false)),
        })
}

fn item_type(item: &Item) -> &str {
    item.overview
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn detail(item: &Item, lower: &str) -> Option<Field> {
    let kind = item_type(item);
    let (key, value) = item
        .details
        .as_object()?
        .iter()
        .find(|(key, _)| key.to_lowercase() == lower)?;
    let value = value.as_str().filter(|value| !value.is_empty())?;
    Some(Field {
        value: value.to_owned(),
        secret: if item_fields::fields_of(kind).is_empty() {
            !PLAIN_FIELDS.contains(&key.as_str())
        } else {
            !item_fields::is_plain_field(kind, key)
        },
    })
}

/// A custom item's field, by its label. A kind this version doesn't know counts as a secret.
fn typed_field(item: &Item, lower: &str) -> Option<Field> {
    if item_type(item) != "custom" {
        return None;
    }
    item.details
        .get("fields")?
        .as_array()?
        .iter()
        .find(|field| {
            field
                .get("label")
                .and_then(Value::as_str)
                .is_some_and(|label| label.trim().to_lowercase() == lower)
        })
        .and_then(|field| {
            let value = field.get("value").and_then(Value::as_str)?;
            let kind = field.get("kind").and_then(Value::as_str).unwrap_or("text");
            (!value.is_empty()).then(|| Field {
                value: value.to_owned(),
                secret: !item_fields::custom_kind_is_plain(kind),
            })
        })
}

/// A crypto wallet's address: `address` is the first, and a network name or a label picks one.
/// Addresses are how a wallet gets paid, so they aren't secrets.
fn wallet_address(item: &Item, lower: &str) -> Option<Field> {
    if item_type(item) != "cryptoWallet" {
        return None;
    }
    let matches = |entry: &&Value, key: &str| {
        entry
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|name| name.trim().to_lowercase() == lower)
    };
    let list = item.details.get("addresses")?.as_array()?;
    list.iter()
        .find(|entry| lower == "address" || matches(entry, "network") || matches(entry, "label"))
        .and_then(|entry| entry.get("address")?.as_str())
        .map(|value| Field {
            value: value.to_owned(),
            secret: false,
        })
}

fn custom_field(item: &Item, lower: &str) -> Option<Field> {
    item.details
        .get("customFields")?
        .as_array()?
        .iter()
        .find(|field| {
            field
                .get("label")
                .and_then(Value::as_str)
                .is_some_and(|label| label.trim().to_lowercase() == lower)
        })
        .and_then(|field| {
            let value = field.get("value").and_then(Value::as_str)?;
            (!value.is_empty()).then(|| Field {
                value: value.to_owned(),
                secret: field.get("hidden") != Some(&Value::Bool(false)),
            })
        })
}

/// The names of an item's fields, for tools that browse references. Never values, and leaves out
/// structures no reference can name.
pub fn field_names(item: &Item) -> Vec<FieldName> {
    let mut names = Vec::new();
    let mut add = |name: &str, secret: bool| {
        if !names.iter().any(|field: &FieldName| field.name == name) {
            names.push(FieldName {
                name: name.to_owned(),
                secret,
            });
        }
    };
    if let Some(details) = item.details.as_object() {
        for (key, value) in details {
            if value.as_str().is_some_and(|value| !value.is_empty()) {
                // The same answer `field` gives: only a secure note's notes are its secret.
                let secret = if key == "notes" {
                    item.overview.get("type").and_then(Value::as_str) == Some("secureNote")
                } else {
                    !PLAIN_FIELDS.contains(&key.as_str())
                };
                add(key, secret);
            }
        }
    }
    let list = |key: &str| item.details.get(key).and_then(Value::as_array);
    // Blank labels and empty values can't be read back, so they aren't offered.
    for field in list("customFields").into_iter().flatten() {
        let label = field.get("label").and_then(Value::as_str);
        let value = field.get("value").and_then(Value::as_str);
        if let (Some(label), Some(false)) = (
            label.filter(|label| !label.trim().is_empty()),
            value.map(str::is_empty),
        ) {
            add(label, field.get("hidden") != Some(&Value::Bool(false)));
        }
    }
    if is_environment(item) {
        for var in list("variables").into_iter().flatten() {
            if let Some(key) = var.get("key").and_then(Value::as_str) {
                add(key, var.get("concealed") != Some(&Value::Bool(false)));
            }
        }
    }
    if crate::oauth::has_live_token(item) {
        add("accessToken", true);
    }
    names
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FieldName {
    pub name: String,
    pub secret: bool,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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
    fn references_round_trip_and_reject_the_rest() {
        let parsed = Reference::parse("octapass://Work/CI%2FCD/password").unwrap();
        assert_eq!(parsed.item, "CI/CD");
        assert_eq!(parsed.text(), "octapass://Work/CI%2FCD/password");
        for bad in [
            "",
            "octapass://",
            "octapass://a/b",
            "octapass://a/b/c/d",
            "octapass://a//c",
            "http://a/b/c",
            "octapass://a/b/%zz",
        ] {
            assert_eq!(Reference::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn field_names_never_carry_values() {
        let item = item(
            json!({ "title": "Deploy", "type": "login" }),
            json!({
                "username": "ci",
                "password": "hunter2",
                "schemaVersion": 1,
                "notes": "just a note",
                "customFields": [
                    { "label": "Region", "value": "eu", "hidden": false },
                    { "label": "Key", "value": "s3cret", "hidden": true },
                    { "label": "Empty", "value": "", "hidden": true },
                    { "label": "  ", "value": "x", "hidden": true },
                ],
            }),
        );
        let names = field_names(&item);
        // Every name offered must resolve, with the same secrecy `field` reports.
        for name in &names {
            let found = field(&item, &name.name).unwrap_or_else(|| panic!("{}", name.name));
            assert_eq!(found.secret, name.secret, "{}", name.name);
        }
        assert_eq!(names.len(), 5, "{names:?}");
        let text = serde_json::to_string(&names).unwrap();
        assert!(!text.contains("hunter2") && !text.contains("s3cret") && !text.contains("\"eu\""));
        let by = |name: &str| {
            names
                .iter()
                .find(|field| field.name == name)
                .unwrap()
                .secret
        };
        assert!(!by("username"));
        assert!(by("password"));
        assert!(!by("Region"));
        assert!(by("Key"));
    }
}
