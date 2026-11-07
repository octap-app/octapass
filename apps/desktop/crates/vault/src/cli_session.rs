//! The desktop app's session, for the CLI (plan 05): while the app runs, `octapass` can unlock
//! through it instead of asking for the master password or keeping a session in the keyring.
//!
//! The app listens on a second socket, separate from the browser's, readable only by the user.
//! Unlike the browser's it answers any program of this user, since the CLI can live anywhere; what
//! protects the account key is the device lock. The first request from a terminal asks for Touch
//! ID, Windows Hello or the system password, naming the program; the key then travels exactly as
//! it does to the extension (`bridge`), wrapped for a fresh X25519 key of the CLI's.
//!
//! An approval is a **grant** for that program in that terminal session, kept in the app's memory
//! with an idle timeout, so each command doesn't prompt. Locking the app ends every grant, and the
//! CLI keeps nothing on disk: this makes one lock cover both. `octapass lock` ends its own grant.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use octapass_core::encoding::{b64_decode, b64_decode_array, b64_encode};
use octapass_core::session::Session;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::bridge::wrap_key;
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::SessionStatus;
use crate::vault::{Vault, blocking};

/// How long a grant lasts without a command: the CLI's default session.
pub const GRANT_IDLE: Duration = Duration::from_secs(30 * 60);
/// Requests are a few hundred bytes; a longer line is refused.
pub const MAX_LINE: u64 = 64 * 1024;
/// The user may take a while to answer the prompt.
const REPLY_TIMEOUT: Duration = Duration::from_secs(120);

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
    /// `locked`, `otherAccount`, `invalidRequest`, or a vault error code.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CliAppStatus {
    /// This program can unlock without a prompt.
    pub granted: bool,
    pub same_account: bool,
}

/// Who is on the other end of the socket, as the operating system reports it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CliPeer {
    pub executable: PathBuf,
    /// The Unix session (one terminal window or tab), so an approval doesn't reach other terminals.
    pub session: Option<u32>,
}

struct Grant {
    used: Instant,
    /// Locking bumps the vault's generation, which ends the grant.
    generation: u64,
}

/// The approvals the app remembers. Only ever in memory.
pub struct CliGrants {
    idle: Duration,
    live: Mutex<HashMap<CliPeer, Grant>>,
}

impl Default for CliGrants {
    fn default() -> Self {
        Self::new(GRANT_IDLE)
    }
}

impl CliGrants {
    pub fn new(idle: Duration) -> Self {
        Self {
            idle,
            live: Mutex::new(HashMap::new()),
        }
    }

    fn live(&self) -> std::sync::MutexGuard<'_, HashMap<CliPeer, Grant>> {
        self.live.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Whether `peer` holds a grant. `touch` counts as using it.
    fn check(&self, peer: &CliPeer, generation: u64, touch: bool) -> bool {
        let mut live = self.live();
        live.retain(|_, grant| grant.generation == generation && grant.used.elapsed() < self.idle);
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

    fn grant(&self, peer: CliPeer, generation: u64) {
        self.live().insert(
            peer,
            Grant {
                used: Instant::now(),
                generation,
            },
        );
    }

    fn end(&self, peer: &CliPeer) {
        self.live().remove(peer);
    }
}

fn reply_for(error: &VaultError) -> CliReply {
    let code = serde_json::to_value(error.code).expect("serializes");
    CliReply::error(code.as_str().unwrap_or("unexpected"), &error.message)
}

impl Vault {
    fn same_account(&self, email: &str, server_url: &str) -> bool {
        let session = self.snapshot().session;
        session.email.as_deref() == Some(email) && session.server_url.as_deref() == Some(server_url)
    }

    /// Answers one request from the CLI's socket.
    pub async fn answer_cli(
        self: &Arc<Self>,
        grants: &CliGrants,
        peer: &CliPeer,
        request: CliRequest,
    ) -> CliReply {
        match request {
            CliRequest::Status { email, server_url } => {
                let same = self.same_account(&email, &server_url);
                let unlocked = self.snapshot().session.status == SessionStatus::Unlocked;
                let granted =
                    same && unlocked && grants.check(peer, self.state_generation(), false);
                CliReply::ok(json!({ "granted": granted, "sameAccount": same }))
            }
            CliRequest::Session {
                email,
                server_url,
                public_key,
            } => match self
                .session_for_cli(grants, peer, &email, &server_url, &public_key)
                .await
            {
                Ok(reply) => reply,
                Err(error) => reply_for(&error),
            },
            CliRequest::End => {
                grants.end(peer);
                CliReply::ok(json!({}))
            }
        }
    }

    async fn session_for_cli(
        self: &Arc<Self>,
        grants: &CliGrants,
        peer: &CliPeer,
        email: &str,
        server_url: &str,
        public_key: &str,
    ) -> Result<CliReply> {
        if !self.same_account(email, server_url) {
            return Ok(CliReply::error(
                "otherAccount",
                "The Octa Pass app is signed in to another account.",
            ));
        }
        let program = peer.executable.display().to_string();
        let mut approved = false;
        if self.snapshot().session.status != SessionStatus::Unlocked {
            // Device unlock is the approval: one prompt, not two.
            self.unlock_with_device().await.map_err(|error| {
                VaultError::new(
                    ErrorCode::Locked,
                    format!("The Octa Pass app is locked: {}", error.message),
                )
            })?;
            approved = true;
        }
        if !approved && !grants.check(peer, self.state_generation(), true) {
            let device_unlock = Arc::clone(&self.device_unlock);
            let reason = format!("unlock the Octa Pass command-line tool ({program})");
            blocking(move || Ok(device_unlock.verify_user(&reason)?)).await?;
        }
        let wrap = self.wrap_for_peer(public_key)?;
        grants.grant(peer.clone(), self.state_generation());
        Ok(CliReply::ok(
            serde_json::to_value(wrap).expect("serializes"),
        ))
    }

    /// Unlocks with the account key wrapped by the desktop app (the CLI's half of the above).
    pub async fn unlock_with_wrap(
        self: &Arc<Self>,
        wrap_key: &[u8; 32],
        device_salt: &str,
        wrapped_ask: &str,
    ) -> Result<()> {
        let account = self.current_account()?;
        if self.snapshot().session.status == SessionStatus::Unlocked {
            return Ok(());
        }
        let session = Session::unlock_with_device_key(
            account.bundle.clone(),
            wrap_key,
            &b64_decode(device_salt)?,
            wrapped_ask,
        )?;
        self.install(account.key.clone(), session)?;
        let vault = Arc::clone(self);
        tokio::spawn(async move {
            let result = vault.resume_server_session(&account.key, None).await;
            vault.report(result);
        });
        Ok(())
    }
}

/// How asking the app ended.
#[derive(Debug, PartialEq, Eq)]
pub enum AppUnlock {
    Unlocked,
    /// No app is listening.
    NotRunning,
    /// It answered no: the reason, for the person.
    Declined {
        code: String,
        message: String,
    },
}

/// The account the CLI is signed in to, as the app compares it.
fn account_of(vault: &Vault) -> Option<(String, String)> {
    let session = vault.snapshot().session;
    Some((session.email?, session.server_url?))
}

/// Unlocks `vault` through the app listening on `endpoint`. This can wait for a person.
pub async fn unlock_through_app(vault: &Arc<Vault>, endpoint: &Path) -> Result<AppUnlock> {
    let Some((email, server_url)) = account_of(vault) else {
        return Err(ErrorCode::Locked.into());
    };
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&ephemeral);
    let request = CliRequest::Session {
        email,
        server_url,
        public_key: b64_encode(public.as_bytes()),
    };
    let target = endpoint.to_owned();
    let reply = blocking(move || Ok(ask_app(&target, &request))).await?;
    let Ok(reply) = reply else {
        return Ok(AppUnlock::NotRunning);
    };
    let Some(result) = reply.result.filter(|_| reply.ok) else {
        let error = reply.error.unwrap_or(CliReplyError {
            code: "unexpected".into(),
            message: "The Octa Pass app didn't answer.".into(),
        });
        return Ok(AppUnlock::Declined {
            code: error.code,
            message: error.message,
        });
    };
    let wrap: WrapFields =
        serde_json::from_value(result).map_err(|_| VaultError::unexpected("bad wrap"))?;
    let app_public: [u8; 32] = b64_decode_array(&wrap.ephemeral_public_key)?;
    let shared = ephemeral.diffie_hellman(&PublicKey::from(app_public));
    if !shared.was_contributory() {
        return Err(VaultError::unexpected("invalid public key from the app"));
    }
    let key = wrap_key(shared.as_bytes(), &app_public, public.as_bytes());
    vault
        .unlock_with_wrap(&key, &wrap.device_salt, &wrap.wrapped_ask)
        .await?;
    Ok(AppUnlock::Unlocked)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrapFields {
    ephemeral_public_key: String,
    device_salt: String,
    wrapped_ask: Zeroizing<String>,
}

/// What the app says about this program and account, without prompting. `None` when no app runs.
pub fn app_status(endpoint: &Path, email: &str, server_url: &str) -> Option<CliAppStatus> {
    let reply = ask_app(
        endpoint,
        &CliRequest::Status {
            email: email.to_owned(),
            server_url: server_url.to_owned(),
        },
    )
    .ok()?;
    serde_json::from_value(reply.result?).ok()
}

/// Tells the app to forget this program's approval. Quietly does nothing when no app runs.
pub fn end_app_session(endpoint: &Path) {
    let _ = ask_app(endpoint, &CliRequest::End);
}

/// Where the app listens for the CLI: `cli.sock` in its data folder, or a temporary path with a
/// name derived from it when that's too long for a socket address.
#[cfg(unix)]
pub fn endpoint(app_data_dir: &Path) -> PathBuf {
    const MAX_SOCKET_PATH: usize = 100;
    let path = app_data_dir.join("cli.sock");
    if path.as_os_str().len() <= MAX_SOCKET_PATH {
        return path;
    }
    std::env::temp_dir().join(format!(
        "octapass-cli-{:016x}.sock",
        path_hash(app_data_dir)
    ))
}

/// Where the app listens for the CLI: a pipe named after its data folder.
#[cfg(windows)]
pub fn endpoint(app_data_dir: &Path) -> PathBuf {
    PathBuf::from(format!(
        r"\\.\pipe\octapass-cli-{:016x}",
        path_hash(app_data_dir)
    ))
}

/// Stable across processes: the app and the CLI must agree on it.
fn path_hash(path: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

#[cfg(unix)]
fn connect(endpoint: &Path) -> io::Result<std::os::unix::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::connect(endpoint)?;
    stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
    Ok(stream)
}

#[cfg(windows)]
fn connect(endpoint: &Path) -> io::Result<std::fs::File> {
    // Named pipes have no read timeout; the app answers every request.
    let _ = REPLY_TIMEOUT;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
}

/// One request line, one reply line.
pub fn ask_app(endpoint: &Path, request: &CliRequest) -> io::Result<CliReply> {
    use std::io::{BufRead, BufReader, Write};
    let stream = connect(endpoint)?;
    let mut line = serde_json::to_vec(request).expect("requests serialize");
    line.push(b'\n');
    (&stream).write_all(&line)?;
    let mut reply = Zeroizing::new(String::new());
    BufReader::new(&stream).read_line(&mut reply)?;
    serde_json::from_str(&reply).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

async fn handle(
    vault: Arc<Vault>,
    grants: Arc<CliGrants>,
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    peer: io::Result<CliPeer>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let (reader, mut writer) = tokio::io::split(stream);
    let mut line = String::new();
    let mut reader = BufReader::new(reader).take(MAX_LINE);
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let reply = match (peer, serde_json::from_str::<CliRequest>(&line)) {
        (Ok(peer), Ok(request)) => vault.answer_cli(&grants, &peer, request).await,
        (Ok(_), Err(error)) => CliReply::error("invalidRequest", error.to_string()),
        (Err(error), _) => CliReply::error(
            "forbidden",
            format!("Octa Pass couldn't tell which program this is: {error}"),
        ),
    };
    let mut bytes = serde_json::to_vec(&reply).expect("replies serialize");
    bytes.push(b'\n');
    let _ = writer.write_all(&bytes).await;
}

/// Serves the CLI until the listener fails. `identify` asks the OS who connected; the app passes
/// the same process lookup the browser bridge uses.
#[cfg(unix)]
pub async fn serve(
    vault: Arc<Vault>,
    grants: Arc<CliGrants>,
    endpoint: PathBuf,
    identify: impl Fn(&tokio::net::UnixStream) -> io::Result<CliPeer>,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // A socket left by a previous run (or a crash) would make bind fail.
    match std::fs::remove_file(&endpoint) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    if let Some(dir) = endpoint.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = tokio::net::UnixListener::bind(&endpoint)?;
    std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let peer = identify(&stream);
        let (vault, grants) = (Arc::clone(&vault), Arc::clone(&grants));
        tokio::spawn(handle(vault, grants, stream, peer));
    }
}

/// Serves the CLI until the listener fails.
#[cfg(windows)]
pub async fn serve(
    vault: Arc<Vault>,
    grants: Arc<CliGrants>,
    endpoint: PathBuf,
    identify: impl Fn(&tokio::net::windows::named_pipe::NamedPipeServer) -> io::Result<CliPeer>,
) -> io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let name = endpoint.as_os_str();
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(name)?;
    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new()
            .reject_remote_clients(true)
            .create(name)?;
        let peer = identify(&connected);
        let (vault, grants) = (Arc::clone(&vault), Arc::clone(&grants));
        tokio::spawn(handle(vault, grants, connected, peer));
    }
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

    #[test]
    fn grants_are_per_program_and_terminal() {
        let grants = CliGrants::default();
        grants.grant(peer("/bin/octapass", 1), 7);
        assert!(grants.check(&peer("/bin/octapass", 1), 7, false));
        assert!(!grants.check(&peer("/bin/octapass", 2), 7, false));
        assert!(!grants.check(&peer("/tmp/other", 1), 7, false));
        grants.end(&peer("/bin/octapass", 1));
        assert!(!grants.check(&peer("/bin/octapass", 1), 7, false));
    }

    #[test]
    fn locking_and_idling_end_grants() {
        let grants = CliGrants::default();
        grants.grant(peer("a", 1), 7);
        assert!(!grants.check(&peer("a", 1), 8, false), "the app locked");
        assert!(
            !grants.check(&peer("a", 1), 7, false),
            "and it doesn't return"
        );

        let grants = CliGrants::new(Duration::ZERO);
        grants.grant(peer("a", 1), 7);
        assert!(!grants.check(&peer("a", 1), 7, true));
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
    }
}
