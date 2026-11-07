//! The web vault's CSV export (`packages/vault-client/src/tools/export.ts`), so a file from either
//! reads the same: a lossy CSV with one row per item. JSON, CXF and the encrypted export come from
//! the core, through the vault.

use octapass_desktop_vault::model::{Item, Vault};
use serde_json::Value;

use crate::items::vault_name;

/// How many attached files an item lists.
pub fn attachment_count(item: &Item) -> usize {
    item.details
        .get("attachments")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

const CSV_HEADER: [&str; 10] = [
    "vault", "type", "title", "url", "username", "password", "totp", "notes", "tags", "favorite",
];

pub fn csv(vaults: &[Vault], items: &[Item]) -> String {
    let mut rows = vec![CSV_HEADER.map(str::to_owned).to_vec()];
    for item in items {
        let overview = &item.overview;
        let login = item.is_login_like();
        let login_field = |key: &str| {
            if login {
                text(&item.details, key)
            } else {
                String::new()
            }
        };
        rows.push(vec![
            vault_name(vaults, &item.vault_id).to_owned(),
            text(overview, "type"),
            text(overview, "title"),
            strings(overview, "urls").join(" "),
            login_field("username"),
            login_field("password"),
            login_field("totp"),
            notes_of(item),
            strings(overview, "tags").join(","),
            (overview.get("favorite") == Some(&Value::Bool(true))).to_string(),
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

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `Label: value` lines for the non-empty fields.
fn lines(fields: &[(&str, String)]) -> Vec<String> {
    fields
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(label, value)| format!("{label}: {value}"))
        .collect()
}

/// Fields without a CSV column go into the notes as `Label: value` lines, ahead of the item's
/// own notes.
fn notes_of(item: &Item) -> String {
    let details = &item.details;
    let field = |key: &str| text(details, key);
    let summary = match text(&item.overview, "type").as_str() {
        "card" => lines(&[
            ("Cardholder", field("cardholder")),
            ("Number", field("number")),
            ("Expiry", field("expiry")),
            ("CVV", field("cvv")),
            ("PIN", field("pin")),
            ("Brand", field("brand")),
        ]),
        "identity" => {
            let name = [field("firstName"), field("lastName")]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            lines(&[
                ("Name", name),
                ("Email", field("email")),
                ("Phone", field("phone")),
                ("Address", address(details.get("address"))),
                ("Birth date", field("birthDate")),
            ])
        }
        "secureNote" => return field("notes"),
        "environment" => {
            let mut summary = lines(&[("Project", field("project")), ("Stage", field("stage"))]);
            summary.extend(
                details
                    .get("variables")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|variable| (text(variable, "key"), text(variable, "value")))
                    .filter(|(_, value)| !value.is_empty())
                    .map(|(key, value)| format!("{key}: {value}")),
            );
            summary
        }
        "login" | "password" => {
            let custom: Vec<(String, String)> = details
                .get("customFields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|custom| (text(custom, "label"), text(custom, "value")))
                .collect();
            let borrowed: Vec<(&str, String)> = custom
                .iter()
                .map(|(label, value)| (label.as_str(), value.clone()))
                .collect();
            lines(&borrowed)
        }
        kind @ ("bankAccount" | "apiCredential" | "softwareLicense" | "idDocument"
        | "cryptoWallet" | "database") => {
            let mut rows: Vec<(String, String)> = octapass_core::item_fields::fields_of(kind)
                .iter()
                .map(|spec| {
                    (
                        octapass_core::item_fields::english_label(spec.key),
                        field(spec.key),
                    )
                })
                .collect();
            let list = |key: &str| {
                details
                    .get(key)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            };
            rows.extend(
                list("addresses")
                    .iter()
                    .map(|entry| (text(entry, "network"), text(entry, "address"))),
            );
            rows.extend(
                list("customFields")
                    .iter()
                    .map(|entry| (text(entry, "label"), text(entry, "value"))),
            );
            let borrowed: Vec<(&str, String)> = rows
                .iter()
                .map(|(label, value)| (label.as_str(), value.clone()))
                .collect();
            lines(&borrowed)
        }
        "custom" => {
            let rows: Vec<(String, String)> = details
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|entry| (text(entry, "label"), text(entry, "value")))
                .collect();
            let borrowed: Vec<(&str, String)> = rows
                .iter()
                .map(|(label, value)| (label.as_str(), value.clone()))
                .collect();
            lines(&borrowed)
        }
        _ => return String::new(),
    };
    summary
        .into_iter()
        .chain(Some(field("notes")))
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn address(address: Option<&Value>) -> String {
    let Some(address) = address else {
        return String::new();
    };
    let join = |parts: Vec<String>, separator: &str| {
        parts
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(separator)
    };
    let city = join(
        vec![
            text(address, "postalCode"),
            text(address, "city"),
            text(address, "region"),
        ],
        " ",
    );
    join(
        vec![
            text(address, "line1"),
            text(address, "line2"),
            city,
            text(address, "country"),
        ],
        ", ",
    )
}

/// RFC 4180, quoting only where needed. Cells starting with `=` `+` `-` `@` are left as they are,
/// as in the web vault: a guard against formula injection would change passwords on re-import.
fn quote(cell: &str) -> String {
    if cell.contains(['"', ',', '\r', '\n']) || cell != cell.trim() {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use octapass_api::{VaultRole, VaultType};
    use serde_json::json;

    use super::*;

    fn vaults() -> Vec<Vault> {
        vec![Vault {
            id: "v1".into(),
            name: "Personal".into(),
            vault_type: VaultType::Personal,
            role: VaultRole::Owner,
            untrusted: false,
        }]
    }

    fn item(id: &str, overview: Value, details: Value) -> Item {
        Item {
            id: id.into(),
            vault_id: "v1".into(),
            revision: 3,
            created_at: "2026-01-01T00:00:00.000Z".into(),
            updated_at: "2026-02-01T00:00:00.000Z".into(),
            deleted_at: None,
            overview,
            details,
        }
    }

    fn items() -> Vec<Item> {
        vec![
            item(
                "i1",
                json!({ "schemaVersion": 1, "title": "GitHub", "type": "login", "urls": ["https://github.com", "https://gist.github.com"], "tags": ["dev", "work"], "favorite": true, "futureField": 1 }),
                json!({ "schemaVersion": 1, "username": "octocat", "password": "p,\"w\"", "totp": "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP", "notes": "Main account", "customFields": [{ "label": "PIN", "value": "1234", "hidden": true }] }),
            ),
            item(
                "i2",
                json!({ "schemaVersion": 1, "title": "Visa", "type": "card" }),
                json!({ "schemaVersion": 1, "cardholder": "Sam Doe", "number": "4111111111111111", "expiry": "04/29", "cvv": "123", "notes": "Joint card" }),
            ),
            item(
                "i3",
                json!({ "schemaVersion": 1, "title": "Me", "type": "identity" }),
                json!({ "schemaVersion": 1, "firstName": "Sam", "lastName": "Doe", "email": "sam@example.com", "address": { "line1": "1 Main St", "city": "Springfield", "postalCode": "12345", "country": "US" } }),
            ),
            item(
                "i4",
                json!({ "schemaVersion": 1, "title": "Wi-Fi", "type": "secureNote" }),
                json!({ "schemaVersion": 1, "notes": "SSID: home\nKey: secret" }),
            ),
            item(
                "i5",
                json!({ "schemaVersion": 1, "title": "Shop API (production)", "type": "environment" }),
                json!({ "schemaVersion": 1, "project": "shop-api", "projectName": "Shop API", "stage": "production", "variables": [{ "key": "DATABASE_URL", "value": "postgres://db" }, { "key": "PORT", "value": "8080" }, { "key": "EMPTY", "value": "" }], "notes": "Prod env" }),
            ),
        ]
    }

    #[test]
    fn csv_matches_the_web_vault() {
        // The same rows `packages/vault-client/src/tools/export.test.ts` expects.
        let expected = concat!(
            "vault,type,title,url,username,password,totp,notes,tags,favorite\r\n",
            "Personal,login,GitHub,https://github.com https://gist.github.com,octocat,\"p,\"\"w\"\"\",otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP,\"PIN: 1234\nMain account\",\"dev,work\",true\r\n",
            "Personal,card,Visa,,,,,\"Cardholder: Sam Doe\nNumber: 4111111111111111\nExpiry: 04/29\nCVV: 123\nJoint card\",,false\r\n",
            "Personal,identity,Me,,,,,\"Name: Sam Doe\nEmail: sam@example.com\nAddress: 1 Main St, 12345 Springfield, US\",,false\r\n",
            "Personal,secureNote,Wi-Fi,,,,,\"SSID: home\nKey: secret\",,false\r\n",
            "Personal,environment,Shop API (production),,,,,\"Project: shop-api\nStage: production\nDATABASE_URL: postgres://db\nPORT: 8080\nProd env\",,false\r\n",
        );
        assert_eq!(csv(&vaults(), &items()), expected);
    }

    #[test]
    fn cells_are_quoted_only_when_needed() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote(" padded"), "\" padded\"");
        assert_eq!(quote("=1+1"), "=1+1");
        assert_eq!(quote("a\"b"), "\"a\"\"b\"");
    }
}
