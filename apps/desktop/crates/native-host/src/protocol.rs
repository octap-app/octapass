//! The messages between the browser extension, this host and the desktop app.
//!
//! Extension → host (native messaging):
//!
//! ```json
//! { "id": 1, "type": "unlock-status" }
//! { "id": 2, "type": "unlock" }
//! { "id": 3, "type": "get-session-key-wrap", "publicKey": "<base64url X25519 public key>" }
//! { "id": 4, "type": "local-chip-secret", "publicKey": "…", "vaultId": "…", "context": "…" }
//! ```
//!
//! Host → extension: `{ "id": 1, "ok": true, "result": {…} }` or
//! `{ "id": 1, "ok": false, "error": { "code": "locked", "message": "…" } }`.
//!
//! Host → app: one line of JSON, [`Forwarded`], on the app's local socket; the app answers with
//! one line holding the [`Reply`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Request {
    /// Whether the app runs, is signed in, locked or unlocked, and can unlock with the device.
    UnlockStatus,
    /// Unlock the app with Touch ID / Windows Hello / polkit.
    Unlock,
    /// The account key wrapped for the extension's X25519 public key, after the user confirms.
    #[serde(rename_all = "camelCase")]
    GetSessionKeyWrap { public_key: String },
    /// The device chip's secret for a local vault in the extension, sealed to its X25519 public
    /// key. Without `context`, makes a new chip key.
    #[serde(rename_all = "camelCase")]
    LocalChipSecret {
        public_key: String,
        vault_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Echoed back so the extension can match replies to requests.
    #[serde(default)]
    pub id: Value,
    #[serde(flatten)]
    pub request: Request,
}

/// What the host sends the app: the request and the extension it came from, already checked
/// against the allowed extensions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Forwarded {
    pub origin: String,
    pub message: Message,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reply {
    pub id: Value,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ReplyError>,
}

/// The error code for a browser the host or the app won't unlock through (an unknown browser, or
/// one without its vendor's signature in a release build). The extension tells the user, instead
/// of saying the app isn't running.
pub const BROWSER_NOT_TRUSTED: &str = "browserNotTrusted";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyError {
    /// `appNotRunning`, `invalidRequest`, `forbidden`, [`BROWSER_NOT_TRUSTED`], or one of the
    /// vault's error codes (`locked`, `deviceUnlockCancelled`, …).
    pub code: String,
    pub message: String,
}

impl Reply {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: &str, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: None,
            error: Some(ReplyError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn requests_use_the_documented_json() {
        let message: Message = serde_json::from_value(json!({
            "id": 3, "type": "get-session-key-wrap", "publicKey": "abc"
        }))
        .unwrap();
        assert_eq!(message.id, json!(3));
        assert_eq!(
            message.request,
            Request::GetSessionKeyWrap {
                public_key: "abc".into()
            }
        );
        let chip: Message = serde_json::from_value(json!({
            "id": 4, "type": "local-chip-secret", "publicKey": "abc", "vaultId": "v"
        }))
        .unwrap();
        assert_eq!(
            chip.request,
            Request::LocalChipSecret {
                public_key: "abc".into(),
                vault_id: "v".into(),
                context: None,
            }
        );
        let status: Message = serde_json::from_value(json!({ "type": "unlock-status" })).unwrap();
        assert_eq!(status.request, Request::UnlockStatus);
        assert!(serde_json::from_value::<Message>(json!({ "type": "export-vault" })).is_err());
    }

    #[test]
    fn replies_carry_a_result_or_an_error() {
        assert_eq!(
            serde_json::to_value(Reply::ok(json!(1), json!({ "status": "locked" }))).unwrap(),
            json!({ "id": 1, "ok": true, "result": { "status": "locked" } })
        );
        assert_eq!(
            serde_json::to_value(Reply::error(json!(2), "locked", "Octa Pass is locked")).unwrap(),
            json!({ "id": 2, "ok": false, "error": { "code": "locked", "message": "Octa Pass is locked" } })
        );
    }
}
