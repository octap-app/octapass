//! The app's session for the CLI (plan 05), as the Tauri app's `octapass_desktop_vault::
//! cli_session` serves it: while the app runs, `octapass` can unlock through it instead of
//! asking for the master password or keeping a session in the keyring. The CLI's side is
//! unchanged.
//!
//! The app listens on a second socket, separate from the browser's, readable only by the user.
//! Unlike the browser's it answers any program of this user, since the CLI can live anywhere; what
//! protects the account key is the device lock. The first request from a terminal asks for Touch
//! ID or the Mac's password, naming the program; the key then travels exactly as it does to the
//! extension (`super::wrap`), wrapped for a fresh X25519 key of the CLI's.
//!
//! An approval is a **grant** for that program in that terminal session, kept in the app's memory
//! with an idle timeout, so each command doesn't prompt. Locking the app ends every grant (a grant
//! belongs to the unlock it was given in), and the CLI keeps nothing on disk: one lock covers
//! both. `octapass lock` ends its own grant.

use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use octapass_ffi::Session;
use octapass_native_host::trust::System;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::bridge::error_code;
use super::socket::{self, Service};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::SessionStatus;
use crate::vault::Vault;

/// How long a grant lasts without a command: the CLI's default session.
pub const GRANT_IDLE: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum CliRequest {
    /// Whether this program could unlock now, without prompting.
    Status { email: String, server_url: String },
    /// The account key, wrapped for `public_key`.
    Session {
        email: String,
        server_url: String,
        public_key: String,
    },
    /// Forget this program's grant.
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

struct Grant<S> {
    used: Instant,
    /// The unlock it was given in. Holding it keeps its address from being reused, so a later
    /// unlock is never mistaken for this one.
    session: Weak<S>,
}

/// The approvals the app remembers, each for one unlock (`S`, the vault's session). Only ever in
/// memory.
pub struct CliGrants<S = Session> {
    idle: Duration,
    live: Mutex<HashMap<CliPeer, Grant<S>>>,
}

impl<S> Default for CliGrants<S> {
    fn default() -> Self {
        Self::new(GRANT_IDLE)
    }
}

impl<S> CliGrants<S> {
    pub fn new(idle: Duration) -> Self {
        Self {
            idle,
            live: Mutex::new(HashMap::new()),
        }
    }

    fn live(&self) -> MutexGuard<'_, HashMap<CliPeer, Grant<S>>> {
        self.live.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Whether `peer` holds a grant in the unlock `current`. `touch` counts as using it. Grants
    /// from an earlier unlock, or idle too long, are forgotten.
    fn check(&self, peer: &CliPeer, current: Option<&Arc<S>>, touch: bool) -> bool {
        let mut live = self.live();
        live.retain(|_, grant| {
            grant.used.elapsed() < self.idle
                && current.is_some_and(|current| grant.session.as_ptr() == Arc::as_ptr(current))
        });
        match live.get_mut(peer) {
            Some(grant) => {
                if touch {
                    grant.used = Instant::now();
                }
                true
            }
            None => false,
        }
    }

    fn grant(&self, peer: CliPeer, session: Weak<S>) {
        self.live().insert(
            peer,
            Grant {
                used: Instant::now(),
                session,
            },
        );
    }

    fn end(&self, peer: &CliPeer) {
        self.live().remove(peer);
    }
}

fn reply_for(error: &VaultError) -> CliReply {
    CliReply::error(&error_code(error), &error.message)
}

fn same_account(vault: &Vault, email: &str, server_url: &str) -> bool {
    let session = vault.snapshot().session;
    session.email.as_deref() == Some(email) && session.server_url.as_deref() == Some(server_url)
}

/// Answers one request from the CLI's socket.
pub fn answer(vault: &Vault, grants: &CliGrants, peer: &CliPeer, request: CliRequest) -> CliReply {
    match request {
        CliRequest::Status { email, server_url } => {
            let same = same_account(vault, &email, &server_url);
            let unlocked = vault.snapshot().session.status == SessionStatus::Unlocked;
            let granted =
                same && unlocked && grants.check(peer, vault.open_session().as_ref(), false);
            CliReply::ok(json!({ "granted": granted, "sameAccount": same }))
        }
        CliRequest::Session {
            email,
            server_url,
            public_key,
        } => match session_for_cli(vault, grants, peer, &email, &server_url, &public_key) {
            Ok(reply) => reply,
            Err(error) => reply_for(&error),
        },
        CliRequest::End => {
            grants.end(peer);
            CliReply::ok(json!({}))
        }
    }
}

fn session_for_cli(
    vault: &Vault,
    grants: &CliGrants,
    peer: &CliPeer,
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
    let program = peer.executable.display().to_string();
    let mut approved = false;
    if vault.snapshot().session.status != SessionStatus::Unlocked {
        // Device unlock is the approval: one prompt, not two.
        vault.unlock_with_device_if_locked().map_err(|error| {
            VaultError::new(
                ErrorCode::Locked,
                format!("The Octa Pass app is locked: {}", error.message),
            )
        })?;
        approved = true;
    }
    if !approved && !grants.check(peer, vault.open_session().as_ref(), true) {
        vault.verify_user(&format!(
            "unlock the Octa Pass command-line tool ({program})"
        ))?;
    }
    let (wrap, session) = vault.wrap_for_peer(public_key)?;
    grants.grant(peer.clone(), session);
    Ok(CliReply::ok(
        serde_json::to_value(wrap).expect("serializes"),
    ))
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

fn handle(vault: &Vault, grants: &CliGrants, stream: &UnixStream, peer: io::Result<CliPeer>) {
    let Some(line) = socket::read_request(stream) else {
        return;
    };
    let reply = match (peer, serde_json::from_str::<CliRequest>(&line)) {
        (Ok(peer), Ok(request)) => answer(vault, grants, &peer, request),
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
    grants: Arc<CliGrants>,
    endpoint: PathBuf,
    identify: impl Fn(&UnixStream) -> io::Result<CliPeer> + Send + Sync + 'static,
) -> io::Result<Service> {
    Service::start(endpoint, move |stream| {
        let peer = identify(&stream);
        handle(&vault, &grants, &stream, peer);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, session: u32) -> CliPeer {
        CliPeer {
            executable: name.into(),
            session: Some(session),
        }
    }

    /// Stands for one unlock's session.
    fn unlock() -> Arc<()> {
        Arc::new(())
    }

    #[test]
    fn grants_are_per_program_and_terminal() {
        let grants = CliGrants::<()>::default();
        let session = unlock();
        grants.grant(peer("/bin/octapass", 1), Arc::downgrade(&session));
        assert!(grants.check(&peer("/bin/octapass", 1), Some(&session), false));
        assert!(!grants.check(&peer("/bin/octapass", 2), Some(&session), false));
        assert!(!grants.check(&peer("/tmp/other", 1), Some(&session), false));
        grants.end(&peer("/bin/octapass", 1));
        assert!(!grants.check(&peer("/bin/octapass", 1), Some(&session), false));
    }

    #[test]
    fn locking_and_idling_end_grants() {
        let grants = CliGrants::<()>::default();
        let first = unlock();
        grants.grant(peer("a", 1), Arc::downgrade(&first));
        let second = unlock();
        assert!(
            !grants.check(&peer("a", 1), Some(&second), false),
            "the app locked and unlocked again"
        );
        assert!(
            !grants.check(&peer("a", 1), Some(&first), false),
            "and it doesn't return"
        );
        grants.grant(peer("a", 1), Arc::downgrade(&second));
        assert!(!grants.check(&peer("a", 1), None, false), "locked");

        let grants = CliGrants::new(Duration::ZERO);
        grants.grant(peer("a", 1), Arc::downgrade(&second));
        assert!(!grants.check(&peer("a", 1), Some(&second), true));
    }

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
