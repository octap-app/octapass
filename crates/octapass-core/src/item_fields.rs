//! The fields of the item types that have no screen of their own: bank accounts, API credentials,
//! software licences, ID documents, crypto wallets and databases.
//!
//! One table says what each field is, and the apps build their generic editor and detail screens
//! from it: `FIELD_KINDS` decides how a value is shown and whether it counts as a secret, and the
//! labels are the catalog's `itemFields.<key>` and `itemChoices.<key>.<choice>`. The web vault keeps
//! the same table in `packages/vault-client/src/itemFields.ts`; both are checked against
//! `tests/vectors/item-fields.json`.

use serde_json::{Map, Value};

/// How a field is edited and shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Plain text.
    Text,
    /// A number or code that reads left to right in every language.
    Code,
    /// One of `choices`, or the words another app used.
    Choice,
    /// `YYYY-MM-DD`.
    Date,
    Email,
    /// A TCP port.
    Port,
    /// Hidden until revealed.
    Secret,
    /// Hidden until revealed, over several lines.
    SecretLong,
}

impl FieldKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Code => "code",
            Self::Choice => "choice",
            Self::Date => "date",
            Self::Email => "email",
            Self::Port => "port",
            Self::Secret => "secret",
            Self::SecretLong => "secretLong",
        }
    }

    pub const fn is_secret(self) -> bool {
        matches!(self, Self::Secret | Self::SecretLong)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    /// The JSON key in the item's details.
    pub key: &'static str,
    pub kind: FieldKind,
    pub choices: &'static [&'static str],
}

const fn field(key: &'static str, kind: FieldKind) -> FieldSpec {
    FieldSpec {
        key,
        kind,
        choices: &[],
    }
}

const fn choice(key: &'static str, choices: &'static [&'static str]) -> FieldSpec {
    FieldSpec {
        key,
        kind: FieldKind::Choice,
        choices,
    }
}

use FieldKind::{Code, Date, Email, Port, Secret, SecretLong, Text};

const BANK_ACCOUNT: &[FieldSpec] = &[
    field("bankName", Text),
    field("accountHolder", Text),
    choice("accountType", &["checking", "savings", "business", "other"]),
    field("iban", Code),
    field("accountNumber", Code),
    field("routingNumber", Code),
    field("swift", Code),
    field("branch", Text),
    field("pin", Secret),
];

const API_CREDENTIAL: &[FieldSpec] = &[
    choice(
        "credentialType",
        &[
            "apiKey",
            "bearerToken",
            "oauth",
            "jwt",
            "basicAuth",
            "other",
        ],
    ),
    field("username", Text),
    field("key", SecretLong),
    field("secret", SecretLong),
    field("host", Code),
    field("expiryDate", Date),
];

const SOFTWARE_LICENSE: &[FieldSpec] = &[
    field("product", Text),
    field("version", Text),
    field("licenseKey", SecretLong),
    field("licensedTo", Text),
    field("email", Email),
    field("publisher", Text),
    field("orderNumber", Code),
    field("purchaseDate", Date),
    field("expiryDate", Date),
];

const ID_DOCUMENT: &[FieldSpec] = &[
    choice(
        "documentType",
        &["passport", "driverLicense", "nationalId", "other"],
    ),
    field("number", Secret),
    field("fullName", Text),
    field("birthDate", Date),
    field("issuer", Text),
    field("country", Text),
    field("issueDate", Date),
    field("expiryDate", Date),
];

const CRYPTO_WALLET: &[FieldSpec] = &[
    field("walletName", Text),
    field("seedPhrase", SecretLong),
    field("passphrase", Secret),
];

const DATABASE: &[FieldSpec] = &[
    choice(
        "databaseType",
        &[
            "postgresql",
            "mysql",
            "sqlServer",
            "oracle",
            "mongodb",
            "redis",
            "sqlite",
            "server",
            "other",
        ],
    ),
    field("host", Code),
    field("port", Port),
    field("database", Code),
    field("username", Text),
    field("password", Secret),
    field("connectionString", SecretLong),
];

/// The types built from this table, in the order apps list them.
pub const TABLE_TYPES: [&str; 6] = [
    "bankAccount",
    "apiCredential",
    "softwareLicense",
    "idDocument",
    "cryptoWallet",
    "database",
];

/// A custom item's fields' kinds, in the order the editor offers them.
pub const CUSTOM_FIELD_KINDS: [&str; 8] = [
    "text",
    "hidden",
    "multiline",
    "url",
    "date",
    "email",
    "phone",
    "totp",
];

/// Only these show without asking. Every other kind, a newer one included, counts as a secret.
pub fn custom_kind_is_plain(kind: &str) -> bool {
    matches!(kind, "text" | "url" | "date" | "email" | "phone")
}

/// The fields of `item_type`, or none for a type the table doesn't cover.
pub fn fields_of(item_type: &str) -> &'static [FieldSpec] {
    match item_type {
        "bankAccount" => BANK_ACCOUNT,
        "apiCredential" => API_CREDENTIAL,
        "softwareLicense" => SOFTWARE_LICENSE,
        "idDocument" => ID_DOCUMENT,
        "cryptoWallet" => CRYPTO_WALLET,
        "database" => DATABASE,
        _ => &[],
    }
}

/// Whether a field of a table type shows without asking. Anything else, a field from a newer client
/// included, counts as a secret.
pub fn is_plain_field(item_type: &str, key: &str) -> bool {
    fields_of(item_type)
        .iter()
        .any(|field| field.key == key && !field.kind.is_secret())
}

/// A field or type name in English, for formats with no catalog: `accountHolder` is
/// `Account holder`.
pub fn english_label(key: &str) -> String {
    match key {
        "iban" => return "IBAN".into(),
        "pin" => return "PIN".into(),
        "swift" => return "SWIFT code".into(),
        "softwareLicense" => return "Software licence".into(),
        "database" => return "Database".into(),
        _ => {}
    }
    let mut label = String::with_capacity(key.len() + 4);
    for (i, c) in key.chars().enumerate() {
        match (i, c.is_ascii_uppercase()) {
            (0, _) => label.push(c.to_ascii_uppercase()),
            (_, true) => {
                label.push(' ');
                label.push(c.to_ascii_lowercase());
            }
            _ => label.push(c),
        }
    }
    label
}

/// The field the list subtitle comes from. Never a secret: lists and search read subtitles.
pub fn subtitle_key(item_type: &str) -> Option<&'static str> {
    match item_type {
        "bankAccount" => Some("bankName"),
        "apiCredential" | "database" => Some("host"),
        "softwareLicense" => Some("licensedTo"),
        "idDocument" => Some("fullName"),
        "cryptoWallet" => Some("walletName"),
        "custom" => Some("templateName"),
        _ => None,
    }
}

/// A date as `YYYY-MM-DD`, a real one.
pub fn is_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| {
        bytes[range.clone()]
            .iter()
            .all(u8::is_ascii_digit)
            .then(|| text[range].parse::<u32>().ok())
            .flatten()
    };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// A TCP port, 1 to 65535.
pub fn is_port(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && text
            .parse::<u32>()
            .is_ok_and(|port| (1..=65535).contains(&port))
}

/// A SWIFT code: 4 letters, the 2-letter country, 2 location characters, and an optional branch.
pub fn is_swift(text: &str) -> bool {
    let bytes = text.as_bytes();
    (bytes.len() == 8 || bytes.len() == 11)
        && bytes[..6].iter().all(u8::is_ascii_alphabetic)
        && bytes[6..].iter().all(u8::is_ascii_alphanumeric)
}

/// An IBAN without spaces, in capitals.
pub fn normalize_iban(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase()
}

/// An IBAN's shape and its ISO 7064 mod-97 check digits (spaces and case don't matter).
pub fn is_iban(text: &str) -> bool {
    let iban = normalize_iban(text);
    let bytes = iban.as_bytes();
    if !(15..=34).contains(&bytes.len())
        || !bytes[..2].iter().all(u8::is_ascii_uppercase)
        || !bytes[2..4].iter().all(u8::is_ascii_digit)
        || !bytes[4..].iter().all(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    let mut remainder = 0u32;
    for byte in bytes[4..].iter().chain(&bytes[..4]) {
        let value = u32::from(*byte);
        // Letters count as 10 to 35, so they take two digits.
        remainder = if byte.is_ascii_digit() {
            (remainder * 10 + value - 48) % 97
        } else {
            (remainder * 100 + value - 55) % 97
        };
    }
    remainder == 1
}

/// `Some((field, message))` for each value that can't be saved. `message` is the key under the
/// catalog's `validation` group; `field` is the JSON key, or `addresses.<i>` and `fields.<i>`.
pub fn validate(item_type: &str, details: &Value) -> Vec<(String, &'static str)> {
    let empty = Map::new();
    let map = details.as_object().unwrap_or(&empty);
    let text = |key: &str| {
        map.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default()
    };
    let mut errors = Vec::new();
    for spec in fields_of(item_type) {
        let value = text(spec.key);
        if value.is_empty() {
            continue;
        }
        let failed = match spec.kind {
            FieldKind::Date => (!is_date(value)).then_some("date"),
            FieldKind::Port => (!is_port(value)).then_some("port"),
            FieldKind::Email => (!is_email(value)).then_some("email"),
            _ => None,
        };
        if let Some(message) = failed {
            errors.push((spec.key.to_owned(), message));
        }
    }
    if item_type == "bankAccount" {
        if !text("iban").is_empty() && !is_iban(text("iban")) {
            errors.push(("iban".to_owned(), "iban"));
        }
        if !text("swift").is_empty() && !is_swift(text("swift")) {
            errors.push(("swift".to_owned(), "swift"));
        }
    }
    if item_type == "cryptoWallet" {
        let list = map.get("addresses").and_then(Value::as_array);
        for (i, entry) in list.into_iter().flatten().enumerate() {
            let address = entry
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !address.is_empty() && !crate::tools::payment_qr::looks_like_address(address) {
                errors.push((format!("addresses.{i}"), "walletAddress"));
            }
        }
    }
    errors
}

fn is_email(text: &str) -> bool {
    text.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && !domain.contains('@')
            && !text.chars().any(char::is_whitespace)
            && domain
                .split_once('.')
                .is_some_and(|(name, rest)| !name.is_empty() && !rest.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_table_and_the_web_vault_agree() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/vectors/item-fields.json")).unwrap();
        for item_type in TABLE_TYPES {
            let expected = vectors["types"][item_type].as_array().unwrap();
            let actual: Vec<Value> = fields_of(item_type)
                .iter()
                .map(|f| json!({ "key": f.key, "kind": f.kind.name(), "choices": f.choices }))
                .collect();
            assert_eq!(&actual, expected, "{item_type}");
        }
        assert_eq!(vectors["customKinds"], json!(CUSTOM_FIELD_KINDS));
        for case in vectors["validate"].as_array().unwrap() {
            let found: Vec<Value> = validate(case["type"].as_str().unwrap(), &case["details"])
                .into_iter()
                .map(|(field, message)| json!([field, message]))
                .collect();
            assert_eq!(&json!(found), &case["errors"], "{case}");
        }
    }

    #[test]
    fn secrets_are_not_plain() {
        for (item_type, key) in [
            ("cryptoWallet", "seedPhrase"),
            ("cryptoWallet", "passphrase"),
            ("bankAccount", "pin"),
            ("apiCredential", "secret"),
            ("database", "password"),
            ("database", "connectionString"),
            ("idDocument", "number"),
            // Not in the table.
            ("cryptoWallet", "somethingNew"),
            ("sshKey", "publicKey"),
        ] {
            assert!(!is_plain_field(item_type, key), "{item_type} {key}");
        }
        assert!(is_plain_field("bankAccount", "iban"));
        assert!(is_plain_field("database", "host"));
    }

    #[test]
    fn subtitles_are_never_secrets() {
        for item_type in TABLE_TYPES {
            let key = subtitle_key(item_type).unwrap();
            assert!(is_plain_field(item_type, key), "{item_type} {key}");
        }
    }

    #[test]
    fn unknown_custom_kinds_count_as_secrets() {
        assert!(custom_kind_is_plain("text"));
        for kind in ["hidden", "totp", "multiline", "quantumKey", ""] {
            assert!(!custom_kind_is_plain(kind), "{kind}");
        }
    }

    #[test]
    fn dates_ports_and_codes() {
        assert!(is_date("2024-02-29"));
        for bad in [
            "2023-02-29",
            "2024-13-01",
            "2024-1-01",
            "01/02/2024",
            "2024-00-10",
        ] {
            assert!(!is_date(bad), "{bad}");
        }
        assert!(is_port("1") && is_port("65535"));
        for bad in ["0", "65536", "80a", "", "99999999999"] {
            assert!(!is_port(bad), "{bad}");
        }
        assert!(is_swift("COBADEFF") && is_swift("COBADEFFXXX"));
        for bad in ["COBADEF", "COBADEFFXX", "1OBADEFF", "COBADE-F"] {
            assert!(!is_swift(bad), "{bad}");
        }
    }

    #[test]
    fn ibans_are_checked() {
        for good in [
            "DE89370400440532013000",
            "de89 3704 0044 0532 0130 00",
            "GB82WEST12345698765432",
            "JO94CBJO0010000000000131000302",
        ] {
            assert!(is_iban(good), "{good}");
        }
        for bad in [
            "DE89370400440532013001",
            "DE8937040044",
            "XX",
            "1234567890123456",
        ] {
            assert!(!is_iban(bad), "{bad}");
        }
    }
}
