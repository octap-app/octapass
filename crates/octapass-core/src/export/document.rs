//! The Octa Pass JSON export (`"format": "octapass-export"`): every item with its overview and
//! details exactly as stored, plus ids, vaults and dates. The web vault writes the same document
//! (`packages/vault-client/src/tools/export.ts`); the encrypted export holds it as `export.json`.
//!
//! Attachments are listed by id, name, type and size. Their keys are left out: they open nothing
//! outside the item. Only the encrypted export carries the files themselves.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, Result};

pub const FORMAT: &str = "octapass-export";
/// Open Pass, which Octa Pass is a fork of, writes the same document under its own name; both read
/// either.
const SIBLING_FORMAT: &str = "openpass-export";
pub const VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportDocument {
    pub format: String,
    pub version: u32,
    pub exported_at: String,
    pub vaults: Vec<ExportVault>,
    pub items: Vec<ExportItem>,
    /// Fields from newer versions, kept so a document reads back the same.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportVault {
    pub id: String,
    pub name: String,
    /// `personal | shared | family`
    #[serde(rename = "type")]
    pub vault_type: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An item as stored: `overview` and `details` stay raw JSON so nothing is reordered or lost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportItem {
    pub id: String,
    pub vault_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub overview: Value,
    pub details: Value,
}

impl ExportDocument {
    pub fn new(exported_at: String, vaults: Vec<ExportVault>, items: Vec<ExportItem>) -> Self {
        Self {
            format: FORMAT.into(),
            version: VERSION,
            exported_at,
            vaults,
            items: items
                .into_iter()
                .map(|item| ExportItem {
                    details: without_attachment_keys(item.details),
                    ..item
                })
                .collect(),
            extra: Map::new(),
        }
    }

    /// Pretty-printed with two spaces, like the web vault's `JSON.stringify(…, null, 2)`.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("documents serialize")
    }

    /// Reads a document. A newer major version is refused rather than half read.
    pub fn parse(json: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(json).map_err(|_| Error::InvalidImportFile)?;
        let format = value.get("format").and_then(Value::as_str);
        if format != Some(FORMAT) && format != Some(SIBLING_FORMAT) {
            return Err(Error::InvalidImportFile);
        }
        if value
            .get("version")
            .and_then(Value::as_u64)
            .is_some_and(|version| version > u64::from(VERSION))
        {
            return Err(Error::UnsupportedVersion);
        }
        serde_json::from_value(value).map_err(|_| Error::InvalidImportFile)
    }
}

/// Details with each attachment's `key` removed.
pub fn without_attachment_keys(mut details: Value) -> Value {
    if let Some(files) = details.get_mut("attachments").and_then(Value::as_array_mut) {
        for file in files.iter_mut().filter_map(Value::as_object_mut) {
            file.remove("key");
        }
    }
    details
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn document() -> ExportDocument {
        ExportDocument::new(
            "2026-10-24T00:00:00.000Z".into(),
            vec![ExportVault {
                id: "v1".into(),
                name: "Personal".into(),
                vault_type: "personal".into(),
                extra: Map::new(),
            }],
            vec![ExportItem {
                id: "i1".into(),
                vault_id: "v1".into(),
                created_at: "2026-01-01T00:00:00.000Z".into(),
                updated_at: "2026-02-01T00:00:00.000Z".into(),
                overview: json!({ "schemaVersion": 1, "title": "Lease", "type": "document" }),
                details: json!({ "schemaVersion": 1, "attachments": [{ "id": "a1", "name": "lease.pdf", "type": "application/pdf", "size": 3, "key": "secret" }] }),
            }],
        )
    }

    #[test]
    fn writes_the_web_vaults_layout() {
        let text = document().to_json();
        assert!(text.starts_with(
            "{\n  \"format\": \"octapass-export\",\n  \"version\": 1,\n  \"exportedAt\""
        ));
        assert!(!text.contains("secret"), "attachment keys are left out");
        assert_eq!(ExportDocument::parse(text.as_bytes()).unwrap(), document());
    }

    #[test]
    fn refuses_other_files_and_newer_versions() {
        assert_eq!(
            ExportDocument::parse(b"{\"items\": []}").unwrap_err(),
            Error::InvalidImportFile
        );
        assert_eq!(
            ExportDocument::parse(b"not json").unwrap_err(),
            Error::InvalidImportFile
        );
        let mut newer = serde_json::to_value(document()).unwrap();
        newer["version"] = json!(2);
        assert_eq!(
            ExportDocument::parse(newer.to_string().as_bytes()).unwrap_err(),
            Error::UnsupportedVersion
        );
    }
}
