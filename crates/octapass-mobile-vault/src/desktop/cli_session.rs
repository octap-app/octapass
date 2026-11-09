//! The app's session for the CLI (plan 05), as the Tauri app's `octapass_desktop_vault::
//! cli_session` serves it, with the same requests: while the app runs, `octapass` uses its
//! account and opens with it instead of asking for the master password or keeping a session in
//! the keyring.
//!
//! The app listens on a second socket, separate from the browser's, readable only by the user.
//! Unlike the browser's it answers any program of this user, since the CLI can live anywhere.
//! **The CLI follows the app** (maintainer decision, 2026-11-09, plan 03 History): while the app is
//! unlocked, `session` hands the account key over without a prompt; while it's locked, the request
//! asks Touch ID or the Mac's password, which unlocks the app. Locking the app locks every CLI with
//! it, and `octapass lock` (`end`) locks the app. The key travels exactly as it does to the
//! extension (`super::wrap`), wrapped for a fresh X25519 key of the CLI's.
//!
//! A CLI that isn't signed in sends `link`: the app makes it a server session of its own
//! (`POST /v1/devices/link`) and seals that session and the Secret Key for the CLI with a second
//! exchange ([`CLI_LINK_INFO`], context `cli-link`), next to the wrapped account key.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use octapass_api::{DeviceInfo, LoginFinishResponse};
use octapass_core::encoding::{b64_decode_array, b64_encode};
use octapass_core::envelope::{Context, seal_b64};
use octapass_core::keys::SymmetricKey;
use octapass_native_host::trust::System;
use rand_core::OsRng;
use zeroize::Zeroizing;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::bridge::error_code;
use super::socket::{self, Service};
use super::wrap::exchange;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::SessionStatus;
use crate::vault::Vault;

/// For what `link` seals besides the account key, so the two keys never coincide. The CLI derives
/// it the same way (`octapass_desktop_vault::cli_session::CLI_LINK_INFO`).
pub const CLI_LINK_INFO: &[u8] = b"openpass/v1/cli-link";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum CliRequest {
    /// Whether the CLI could open now, without prompting.
    Status { email: String, server_url: String },
    /// The account key, wrapped for `public_key`.
    Session {
        email: String,
        server_url: String,
        public_key: String,
    },
    /// Sign this CLI in with the app's account: a server session of its own and the Secret Key,
    /// sealed for `public_key`, with the account key wrapped for it as `session` does.
    Link {
        public_key: String,
        device: DeviceInfo,
    },
    /// Lock the app, and every CLI with it.
    End,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CliReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CliReplyError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliReplyError {
    /// `locked`, `otherAccount`, `invalidRequest`, `forbidden`, or a vault error code.
    pub code: String,
    pub message: String,
}

impl CliReply {
    fn ok(result: Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(CliReplyError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

/// Who is on the other end of the socket, as the operating system reports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CliPeer {
    pub executable: PathBuf,
    /// The Unix session (one terminal window or tab), so an approval doesn't reach other terminals.
    pub session: Option<u32>,
}

fn reply_for(error: &VaultError) -> CliReply {
    CliReply::error(&error_code(error), &error.message)
}

fn same_account(vault: &Vault, email: &str, server_url: &str) -> bool {
    let session = vault.snapshot().session;
    session.email.as_deref() == Some(email) && session.server_url.as_deref() == Some(server_url)
}

/// Answers one request from the CLI's socket.
pub fn answer(vault: &Vault, request: CliRequest) -> CliReply {
    let reply = match request {
        CliRequest::Status { email, server_url } => {
            let same = same_account(vault, &email, &server_url);
            let unlocked = vault.snapshot().session.status == SessionStatus::Unlocked;
            Ok(CliReply::ok(
                json!({ "granted": same && unlocked, "sameAccount": same }),
            ))
        }
        CliRequest::Session {
            email,
            server_url,
            public_key,
        } => session_for_cli(vault, &email, &server_url, &public_key),
        CliRequest::Link { public_key, device } => link_cli(vault, &public_key, device),
        CliRequest::End => {
            vault.lock();
            Ok(CliReply::ok(json!({})))
        }
    };
    reply.unwrap_or_else(|error| reply_for(&error))
}

/// Unlocked, nothing asks. Locked, Touch ID or the Mac's password unlocks the app for it.
fn open_for_cli(vault: &Vault) -> Result<()> {
    vault.unlock_with_device_if_locked().map_err(|error| {
        VaultError::new(
            ErrorCode::Locked,
            format!("The Octa Pass app is locked: {}", error.message),
        )
    })
}

fn session_for_cli(
    vault: &Vault,
    email: &str,
    server_url: &str,
    public_key: &str,
) -> Result<CliReply> {
    if !same_account(vault, email, server_url) {
        return Ok(CliReply::error(
            "otherAccount",
            "The Octa Pass app is signed in to another account.",
        ));
    }
    open_for_cli(vault)?;
    let (wrap, _) = vault.wrap_for_peer(public_key)?;
    Ok(CliReply::ok(
        serde_json::to_value(wrap).expect("serializes"),
    ))
}

/// What `link` seals for the CLI.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LinkSecrets<'a> {
    secret_key: &'a str,
    login: &'a LoginFinishResponse,
}

fn link_cli(vault: &Vault, public_key: &str, device: DeviceInfo) -> Result<CliReply> {
    if vault.snapshot().session.status == SessionStatus::SignedOut {
        return Ok(CliReply::error(
            "signedOut",
            "The Octa Pass app isn't signed in.",
        ));
    }
    open_for_cli(vault)?;
    let (secret_key, login) = match vault.link_device(device) {
        Err(error) if error.code == ErrorCode::NeedsSync => {
            return Ok(CliReply::error(
                "localVault",
                "The Octa Pass app has a vault on this Mac only, which the CLI can't share.",
            ));
        }
        other => other?,
    };
    let (wrap, _) = vault.wrap_for_peer(public_key)?;
    let cli_public: [u8; 32] = b64_decode_array(public_key)
        .map_err(|_| VaultError::unexpected("invalid CLI public key"))?;
    let (link_public, key) = exchange(&cli_public, CLI_LINK_INFO)?;
    let secrets = Zeroizing::new(
        serde_json::to_vec(&LinkSecrets {
            secret_key: &secret_key,
            login: &login,
        })
        .expect("serializes"),
    );
    let sealed = SymmetricKey::from_slice(key.as_ref())
        .and_then(|key| seal_b64(&key, &Context::CliLink, &secrets, &mut OsRng))
        .map_err(|error| VaultError::unexpected(error.to_string()))?;
    let mut reply = serde_json::to_value(wrap).expect("serializes");
    reply["linkPublicKey"] = json!(b64_encode(&link_public));
    reply["sealed"] = json!(sealed);
    Ok(CliReply::ok(reply))
}

/// Where the app listens for the CLI: `cli.sock` in its data folder, or a temporary path with a
/// name derived from it when that's too long for a socket address. The CLI works it out the
/// same way (`octapass_desktop_vault::cli_session::endpoint`).
pub fn endpoint(app_data_dir: &Path) -> PathBuf {
    socket::endpoint(app_data_dir, "cli.sock", "octapass-cli")
}

/// Who connected, as the browser bridge looks it up: the executable and its terminal session.
pub fn cli_peer(stream: &UnixStream) -> io::Result<CliPeer> {
    let peer = octapass_native_host::system::peer(stream)?;
    Ok(CliPeer {
        executable: octapass_native_host::system::OsSystem.executable(peer.pid)?,
        session: octapass_native_host::system::session(peer.pid),
    })
}

fn handle(vault: &Vault, stream: &UnixStream, peer: io::Result<CliPeer>) {
    let Some(line) = socket::read_request(stream) else {
        return;
    };
    let reply = match (peer, serde_json::from_str::<CliRequest>(&line)) {
        // Any program of this user may ask; one the OS can't name is refused.
        (Ok(_), Ok(request)) => answer(vault, request),
        (Ok(_), Err(error)) => CliReply::error("invalidRequest", error.to_string()),
        (Err(error), _) => CliReply::error(
            "forbidden",
            format!("Octa Pass couldn't tell which program this is: {error}"),
        ),
    };
    socket::write_reply(stream, &reply);
}

/// Serves the CLI on `endpoint` until the service is stopped or dropped. `identify` asks the OS
/// who connected: the app passes [`cli_peer`].
pub fn start(
    vault: Arc<Vault>,
    endpoint: PathBuf,
    identify: impl Fn(&UnixStream) -> io::Result<CliPeer> + Send + Sync + 'static,
) -> io::Result<Service> {
    Service::start(endpoint, move |stream| {
        let peer = identify(&stream);
        handle(&vault, &stream, peer);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_use_the_documented_json() {
        assert_eq!(
            serde_json::to_value(CliRequest::Session {
                email: "a".into(),
                server_url: "s".into(),
                public_key: "k".into()
            })
            .unwrap(),
            json!({ "type": "session", "email": "a", "serverUrl": "s", "publicKey": "k" })
        );
        assert_eq!(
            serde_json::from_value::<CliRequest>(json!({ "type": "end" })).unwrap(),
            CliRequest::End
        );
        assert_eq!(
            serde_json::from_value::<CliRequest>(
                json!({ "type": "status", "email": "a", "serverUrl": "s" })
            )
            .unwrap(),
            CliRequest::Status {
                email: "a".into(),
                server_url: "s".into()
            }
        );
        assert_eq!(
            serde_json::to_value(CliReply::error("otherAccount", "x")).unwrap(),
            json!({ "ok": false, "error": { "code": "otherAccount", "message": "x" } })
        );
    }
}
