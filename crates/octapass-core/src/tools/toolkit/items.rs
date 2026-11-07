//! Toolkit results as vault items (plan 16 §1): every client saves the same `certificate` and `key`
//! items. Nothing here is encrypted yet; the caller hands the item to its vault, which does.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::time::Duration;
use zeroize::Zeroizing;

use super::x509;
use crate::error::{Error, Result};
use crate::item::SCHEMA_VERSION;

/// An item ready for the vault: `{ overview, details }`, as `Item::from_json` reads it.
#[derive(Debug, Clone, Serialize)]
pub struct Draft {
    pub overview: Value,
    pub details: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInput {
    #[serde(default)]
    pub title: Option<String>,
    /// PEM. The first certificate is the item's; any others join the chain.
    pub certificate: String,
    #[serde(default)]
    pub chain: Option<String>,
    #[serde(default)]
    pub private_key: Option<Zeroizing<String>>,
    /// `selfSigned`, `localCa`, `acme` or `imported`.
    #[serde(default)]
    pub source: Option<String>,
    /// ACME: what's needed to renew.
    #[serde(default)]
    pub acme: Option<Value>,
    #[serde(default)]
    pub notes: Option<String>,
}

fn rfc3339(unix_seconds: u64) -> Result<String> {
    der::DateTime::from_unix_duration(Duration::from_secs(unix_seconds))
        .map(|date| date.to_string())
        .map_err(|_| Error::InvalidCertificate)
}

/// A `certificate` item from PEM, with what lists and reminders need read out of it.
pub fn certificate(input: &CertificateInput, now_seconds: u64) -> Result<Draft> {
    let ders = x509::parse_certificates(&input.certificate)?;
    let leaf = ders.first().ok_or(Error::InvalidCertificate)?;
    let info = x509::inspect(leaf, now_seconds)?;
    if let Some(key) = &input.private_key {
        let key = x509::private_key_of(key, None)?;
        x509::check_key_matches(leaf, &key)?;
    }
    let mut chain = ders[1..]
        .iter()
        .map(|der| x509::der_to_pem(der))
        .collect::<Result<Vec<_>>>()?
        .concat();
    if let Some(extra) = input.chain.as_deref() {
        chain.push_str(extra.trim());
        chain.push('\n');
    }
    let name = info
        .common_name
        .clone()
        .or_else(|| info.sans.first().map(|san| san.value.clone()))
        .unwrap_or_else(|| info.subject.clone());
    let title = input
        .title
        .as_deref()
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map_or_else(|| name.clone(), str::to_owned);
    let not_after = rfc3339(info.not_after)?;
    let mut details = Map::new();
    details.insert("schemaVersion".into(), json!(SCHEMA_VERSION));
    details.insert("certificate".into(), json!(x509::der_to_pem(leaf)?));
    if !chain.is_empty() {
        details.insert("chain".into(), json!(chain));
    }
    if let Some(key) = &input.private_key {
        details.insert("privateKey".into(), json!(key.as_str()));
    }
    details.insert("commonName".into(), json!(name));
    details.insert(
        "sans".into(),
        json!(info.sans.iter().map(|san| &san.value).collect::<Vec<_>>()),
    );
    details.insert("issuer".into(), json!(info.issuer));
    details.insert("notBefore".into(), json!(rfc3339(info.not_before)?));
    details.insert("notAfter".into(), json!(not_after));
    details.insert("keyType".into(), json!(key_label(&info)));
    details.insert("fingerprint".into(), json!(info.sha256));
    details.insert("isCa".into(), json!(info.is_ca));
    if let Some(source) = &input.source {
        details.insert("source".into(), json!(source));
    }
    if let Some(acme) = &input.acme {
        details.insert("acme".into(), acme.clone());
    }
    if let Some(notes) = input.notes.as_deref().filter(|notes| !notes.is_empty()) {
        details.insert("notes".into(), json!(notes));
    }
    Ok(Draft {
        overview: json!({
            "schemaVersion": SCHEMA_VERSION,
            "type": "certificate",
            "title": title,
            "subtitle": format!("{} · {}", key_label(&info), &not_after[..10]),
        }),
        details: Value::Object(details),
    })
}

fn key_label(info: &x509::CertificateInfo) -> String {
    match (&info.curve, info.key_type.as_str()) {
        (Some(curve), _) => format!("ECDSA {curve}"),
        (None, "rsa") => format!("RSA {}", info.key_bits),
        (None, "ed25519") => "Ed25519".to_owned(),
        (None, other) => other.to_owned(),
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInput {
    pub title: String,
    /// `jwt`, `openpgp`, `age` or `asymmetric`.
    pub kind: String,
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub private_key: Option<Zeroizing<String>>,
    #[serde(default)]
    pub public_key: Option<String>,
    /// HMAC secrets, which have no public half.
    #[serde(default)]
    pub secret: Option<Zeroizing<String>>,
    /// The key as a JWK. Holds private material unless the kind says otherwise.
    #[serde(default)]
    pub jwk: Option<Zeroizing<String>>,
    /// Only public parts.
    #[serde(default)]
    pub jwks: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// OpenPGP: `Name <email>`.
    #[serde(default)]
    pub user_id: Option<String>,
    /// Protects copies written out of the vault; the stored key has none.
    #[serde(default)]
    pub passphrase: Option<Zeroizing<String>>,
    #[serde(default)]
    pub notes: Option<String>,
}

/// A `key` item. A key with neither private nor public part has nothing to keep.
pub fn key(input: &KeyInput) -> Result<Draft> {
    let title = input.title.trim();
    if title.is_empty()
        || !matches!(
            input.kind.as_str(),
            "jwt" | "openpgp" | "age" | "asymmetric"
        )
        || (input.private_key.is_none() && input.secret.is_none() && input.public_key.is_none())
    {
        return Err(Error::InvalidToolInput);
    }
    let mut details = Map::new();
    details.insert("schemaVersion".into(), json!(SCHEMA_VERSION));
    details.insert("kind".into(), json!(input.kind));
    let text = [
        ("algorithm", input.algorithm.as_deref()),
        (
            "privateKey",
            input.private_key.as_ref().map(|key| key.as_str()),
        ),
        ("publicKey", input.public_key.as_deref()),
        (
            "secret",
            input.secret.as_ref().map(|secret| secret.as_str()),
        ),
        ("jwk", input.jwk.as_ref().map(|jwk| jwk.as_str())),
        ("jwks", input.jwks.as_deref()),
        ("keyId", input.key_id.as_deref()),
        ("fingerprint", input.fingerprint.as_deref()),
        ("userId", input.user_id.as_deref()),
        ("passphrase", input.passphrase.as_ref().map(|p| p.as_str())),
        ("notes", input.notes.as_deref()),
    ];
    for (name, value) in text {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            details.insert(name.into(), json!(value));
        }
    }
    let subtitle = input
        .algorithm
        .as_deref()
        .or(input.fingerprint.as_deref())
        .unwrap_or(input.kind.as_str());
    Ok(Draft {
        overview: json!({
            "schemaVersion": SCHEMA_VERSION,
            "type": "key",
            "title": title,
            "subtitle": subtitle,
        }),
        details: Value::Object(details),
    })
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::item::{Item, ItemDetails, ItemType};
    use crate::tools::toolkit::run;

    const NOW_MS: u64 = 1_793_000_000_000;

    fn call(op: &str, input: Value) -> Value {
        serde_json::from_str(&run(op, &input.to_string(), NOW_MS, &mut OsRng).unwrap()).unwrap()
    }

    #[test]
    fn a_certificate_becomes_an_item_the_core_reads_back() {
        let made = call("cert.selfSigned", json!({ "sans": ["a.test"] }));
        let draft = call(
            "item.certificate",
            json!({
                "certificate": made["certificate"],
                "privateKey": made["privateKey"],
                "source": "selfSigned",
            }),
        );
        assert_eq!(draft["overview"]["type"], "certificate");
        assert_eq!(draft["overview"]["title"], "a.test");
        let item = Item::from_json(&draft.to_string()).unwrap();
        assert_eq!(item.overview.item_type, ItemType::Certificate);
        let ItemDetails::Certificate(details) = &item.details else {
            panic!("not a certificate");
        };
        assert_eq!(details.common_name.as_deref(), Some("a.test"));
        assert_eq!(details.key_type.as_deref(), Some("ECDSA P-256"));
        assert!(details.not_after.as_deref().unwrap().ends_with('Z'));
        assert_eq!(details.sans.as_deref(), Some(&["a.test".to_owned()][..]));
        assert!(details.private_key.is_some());
    }

    #[test]
    fn a_mismatched_key_cant_be_saved_with_a_certificate() {
        let made = call("cert.selfSigned", json!({ "sans": ["a.test"] }));
        let other = call("key.generate", json!({ "type": "p256" }));
        let input =
            json!({ "certificate": made["certificate"], "privateKey": other["privateKey"] });
        assert_eq!(
            run("item.certificate", &input.to_string(), NOW_MS, &mut OsRng).err(),
            Some(Error::CertificateKeyMismatch)
        );
    }

    #[test]
    fn keys_become_items() {
        let made = call("jwt.generateKey", json!({ "algorithm": "EdDSA" }));
        let draft = call(
            "item.key",
            json!({
                "title": "API signing key",
                "kind": "jwt",
                "algorithm": "EdDSA",
                "privateKey": made["privateKey"],
                "publicKey": made["publicKey"],
                "jwk": made["jwk"],
                "jwks": made["jwks"],
                "keyId": made["keyId"],
            }),
        );
        let item = Item::from_json(&draft.to_string()).unwrap();
        assert_eq!(item.overview.item_type, ItemType::Key);
        let ItemDetails::Key(details) = &item.details else {
            panic!("not a key");
        };
        assert_eq!(details.kind.as_deref(), Some("jwt"));
        assert_eq!(details.algorithm.as_deref(), Some("EdDSA"));
        assert!(item.overview.subtitle.as_deref() == Some("EdDSA"));
        // Nothing to keep.
        let empty = json!({ "title": "x", "kind": "age" });
        assert!(run("item.key", &empty.to_string(), NOW_MS, &mut OsRng).is_err());
        let bad_kind = json!({ "title": "x", "kind": "nope", "secret": "s" });
        assert!(run("item.key", &bad_kind.to_string(), NOW_MS, &mut OsRng).is_err());
    }
}
