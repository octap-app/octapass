//! The desktop app's session, for the CLI (plan 05): while the app runs, `octapass` uses its
//! account and opens with it instead of asking for the master password or keeping a session in
//! the keyring.
//!
//! The app listens on a second socket, separate from the browser's, readable only by the user.
//! Unlike the browser's it answers any program of this user, since the CLI can live anywhere.
//! **The CLI follows the app** (maintainer decision, 2026-11-09, plan 03 History): while the app is
//! unlocked, `session` hands the account key over without a prompt; while it's locked, the request
//! asks the device lock, which unlocks the app. Locking the app locks every CLI with it, and
//! `octapass lock` (`end`) locks the app. The key travels exactly as it does to the extension
//! (`bridge`), wrapped for a fresh X25519 key of the CLI's.
//!
//! A CLI that isn't signed in sends `link`: the app makes it a server session of its own
//! (`POST /v1/devices/link`) and seals that session and the Secret Key for the CLI with a second
//! exchange ([`CLI_LINK_INFO`], context `cli-link`), next to the wrapped account key.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use octapass_api::{DeviceInfo, LoginFinishResponse};
use octapass_core::encoding::{b64_decode, b64_decode_array, b64_encode};
use octapass_core::envelope::{Context, open_b64, seal_b64};
use octapass_core::keys::SymmetricKey;
use octapass_core::session::Session;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::bridge::{derive_wrap_key, wrap_key};
use crate::error::{ErrorCode, Result, VaultError};
use crate::model::SessionStatus;
use crate::store::AccountKey;
use crate::vault::cli_link::{LinkWrap, LinkedAccount};
use crate::vault::{Vault, blocking};

/// For what `link` seals besides the account key, so the two keys never coincide.
pub const CLI_LINK_INFO: &[u8] = b"openpass/v1/cli-link";
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
    /// `locked`, `otherAccount`, `localVault`, `invalidRequest`, or a vault error code.
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
    /// The app is unlocked with this account, so the CLI opens without a prompt.
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
    pub async fn answer_cli(self: &Arc<Self>, request: CliRequest) -> CliReply {
        let reply = match request {
            CliRequest::Status { email, server_url } => {
                let same = self.same_account(&email, &server_url);
                let unlocked = self.snapshot().session.status == SessionStatus::Unlocked;
                Ok(CliReply::ok(
                    json!({ "granted": same && unlocked, "sameAccount": same }),
                ))
            }
            CliRequest::Session {
                email,
                server_url,
                public_key,
            } => self.session_for_cli(&email, &server_url, &public_key).await,
            CliRequest::Link { public_key, device } => self.link_cli(&public_key, device).await,
            CliRequest::End => {
                self.lock();
                Ok(CliReply::ok(json!({})))
            }
        };
        reply.unwrap_or_else(|error| reply_for(&error))
    }

    /// Unlocked, nothing asks. Locked, the device lock unlocks the app for it.
    async fn open_for_cli(self: &Arc<Self>) -> Result<()> {
        if self.snapshot().session.status == SessionStatus::Unlocked {
            return Ok(());
        }
        self.unlock_with_device().await.map_err(|error| {
            VaultError::new(
                ErrorCode::Locked,
                format!("The Octa Pass app is locked: {}", error.message),
            )
        })
    }

    async fn session_for_cli(
        self: &Arc<Self>,
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
        self.open_for_cli().await?;
        let wrap = self.wrap_for_peer(public_key)?;
        Ok(CliReply::ok(
            serde_json::to_value(wrap).expect("serializes"),
        ))
    }

    async fn link_cli(self: &Arc<Self>, public_key: &str, device: DeviceInfo) -> Result<CliReply> {
        if self.snapshot().session.status == SessionStatus::SignedOut {
            return Ok(CliReply::error(
                "signedOut",
                "The Octa Pass app isn't signed in.",
            ));
        }
        self.open_for_cli().await?;
        let linked = match self.link_device(device).await {
            Err(error) if error.code == ErrorCode::NotAllowed => {
                return Ok(CliReply::error(
                    "localVault",
                    "The Octa Pass app has a vault on this computer only, which the CLI can't share.",
                ));
            }
            other => other?,
        };
        let wrap = self.wrap_for_peer(public_key)?;
        let (link_public, sealed) = seal_link(public_key, &linked)?;
        let mut reply = serde_json::to_value(wrap).expect("serializes");
        reply["linkPublicKey"] = json!(link_public);
        reply["sealed"] = json!(sealed);
        Ok(CliReply::ok(reply))
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

/// What `link` seals for the CLI.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkSecrets {
    secret_key: Zeroizing<String>,
    login: LoginFinishResponse,
}

/// The app's half of the second exchange: a fresh key of its own, and the sealed session.
fn seal_link(cli_public_key: &str, linked: &LinkedAccount) -> Result<(String, String)> {
    let cli_public: [u8; 32] = b64_decode_array(cli_public_key)?;
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let app_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(cli_public));
    if !shared.was_contributory() {
        return Err(VaultError::unexpected("invalid CLI public key"));
    }
    let key = derive_wrap_key(
        shared.as_bytes(),
        app_public.as_bytes(),
        &cli_public,
        CLI_LINK_INFO,
    );
    let secrets = Zeroizing::new(
        serde_json::to_vec(&LinkSecrets {
            secret_key: linked.secret_key.clone(),
            login: linked.login.clone(),
        })
        .expect("serializes"),
    );
    let sealed = seal_b64(
        &SymmetricKey::from_slice(key.as_ref())?,
        &Context::CliLink,
        &secrets,
        &mut OsRng,
    )?;
    Ok((b64_encode(app_public.as_bytes()), sealed))
}

/// How asking the app to link ended.
#[derive(Debug, PartialEq, Eq)]
pub enum AppLink {
    /// Signed in with the app's account, and unlocked.
    Linked { email: String },
    /// No app is listening.
    NotRunning,
    /// It answered no: the reason, for the person.
    Declined { code: String, message: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkFields {
    email: String,
    server_url: String,
    link_public_key: String,
    sealed: String,
    #[serde(flatten)]
    wrap: WrapFields,
}

/// Signs the CLI's `vault`, which isn't signed in, in with the account of the app listening on
/// `endpoint`. `device` is how the CLI shows in the account's device list.
pub async fn link_through_app(
    vault: &Arc<Vault>,
    endpoint: &Path,
    device: DeviceInfo,
) -> Result<AppLink> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&ephemeral);
    let request = CliRequest::Link {
        public_key: b64_encode(public.as_bytes()),
        device,
    };
    let target = endpoint.to_owned();
    let Ok(reply) = blocking(move || Ok(ask_app(&target, &request))).await? else {
        return Ok(AppLink::NotRunning);
    };
    let Some(result) = reply.result.filter(|_| reply.ok) else {
        let error = reply.error.unwrap_or(CliReplyError {
            code: "unexpected".into(),
            message: "The Octa Pass app didn't answer.".into(),
        });
        return Ok(AppLink::Declined {
            code: error.code,
            message: error.message,
        });
    };
    let fields: LinkFields =
        serde_json::from_value(result).map_err(|_| VaultError::unexpected("bad link reply"))?;
    let exchange = |app_public: &str, info: &[u8]| -> Result<Zeroizing<[u8; 32]>> {
        let app_public: [u8; 32] = b64_decode_array(app_public)?;
        let shared = ephemeral.diffie_hellman(&PublicKey::from(app_public));
        if !shared.was_contributory() {
            return Err(VaultError::unexpected("invalid public key from the app"));
        }
        Ok(derive_wrap_key(
            shared.as_bytes(),
            &app_public,
            public.as_bytes(),
            info,
        ))
    };
    let link_key = exchange(&fields.link_public_key, CLI_LINK_INFO)?;
    let secrets = open_b64(
        &SymmetricKey::from_slice(link_key.as_ref())?,
        &Context::CliLink,
        &fields.sealed,
    )?;
    let secrets: LinkSecrets =
        serde_json::from_slice(&secrets).map_err(|_| VaultError::unexpected("bad link reply"))?;
    let wrap_key = exchange(&fields.wrap.ephemeral_public_key, crate::bridge::WRAP_INFO)?;
    let email = fields.email.clone();
    vault
        .sign_in_linked(
            LinkedAccount {
                key: AccountKey {
                    server_url: fields.server_url,
                    email: fields.email,
                },
                secret_key: secrets.secret_key,
                login: secrets.login,
            },
            LinkWrap {
                wrap_key: &wrap_key,
                device_salt: &fields.wrap.device_salt,
                wrapped_ask: &fields.wrap.wrapped_ask,
            },
        )
        .await?;
    Ok(AppLink::Linked { email })
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

/// Locks the app, which locks the CLI with it. `false` when no app runs.
pub fn end_app_session(endpoint: &Path) -> bool {
    ask_app(endpoint, &CliRequest::End).is_ok_and(|reply| reply.ok)
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
        // Any program of this user may ask; one the OS can't name is refused.
        (Ok(_), Ok(request)) => vault.answer_cli(request).await,
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
        tokio::spawn(handle(Arc::clone(&vault), stream, peer));
    }
}

/// Serves the CLI until the listener fails.
#[cfg(windows)]
pub async fn serve(
    vault: Arc<Vault>,
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
        tokio::spawn(handle(Arc::clone(&vault), connected, peer));
    }
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
            serde_json::to_value(CliRequest::Link {
                public_key: "k".into(),
                device: DeviceInfo {
                    name: "Octa Pass CLI (linux)".into(),
                    platform: "cli".into()
                }
            })
            .unwrap(),
            json!({
                "type": "link",
                "publicKey": "k",
                "device": { "name": "Octa Pass CLI (linux)", "platform": "cli" }
            })
        );
    }
}
