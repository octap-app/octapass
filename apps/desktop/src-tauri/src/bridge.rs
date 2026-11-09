//! The app's side of native messaging: listens on the local socket (or named pipe) the
//! `octapass-native-host` relays to, and answers with the vault.
//!
//! Every connection is checked before its request is read: it must come from the host binary
//! bundled with this app, started by a known browser (`octapass_native_host::trust`). The
//! socket's file permissions only keep other users out; this keeps out the user's other programs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use octapass_desktop_vault::cli_session::CliPeer;
use octapass_desktop_vault::{Vault, VaultError};
use octapass_native_host::browsers::KnownBrowser;
use octapass_native_host::caller::Caller;
use octapass_native_host::protocol::{BROWSER_NOT_TRUSTED, Forwarded, Reply, Request};
use octapass_native_host::seen;
use octapass_native_host::system::{self, OsSystem};
use octapass_native_host::trust::{HostCheck, Process, Refusal, System, Vouching};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Requests are a few hundred bytes; a longer line is refused.
const MAX_LINE: u64 = 64 * 1024;

/// The check for this build: the host next to the app's executable.
pub fn host_check() -> HostCheck {
    let vouching = Vouching::for_this_build();
    if vouching == Vouching::Nothing {
        eprintln!(
            "browser bridge: development build, so only the native host's path and the browser's \
             name are checked, not their signatures"
        );
    }
    // A missing host never matches anything: process paths are canonical and absolute.
    let host = crate::integration::bundled_host().unwrap_or_else(|error| {
        eprintln!("browser bridge: no native host: {error}");
        PathBuf::new()
    });
    HostCheck {
        host: std::fs::canonicalize(&host).unwrap_or(host),
        team: host_team(vouching),
        vouching,
    }
}

fn host_team(_: Vouching) -> Option<String> {
    None
}

/// Who connected to the CLI's socket (`octapass_desktop_vault::cli_session`): any program of this
/// user may ask, and the device lock answers, so this names it and scopes its approval.
#[cfg(unix)]
pub fn cli_peer(stream: &tokio::net::UnixStream) -> std::io::Result<CliPeer> {
    cli_process(system::peer(stream)?)
}

#[cfg(windows)]
pub fn cli_peer(
    pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> std::io::Result<CliPeer> {
    cli_process(system::peer(pipe)?)
}

fn cli_process(peer: Process) -> std::io::Result<CliPeer> {
    Ok(CliPeer {
        executable: OsSystem.executable(peer.pid)?,
        session: system::session(peer.pid),
    })
}

/// Answers a request from the host `browser` started.
pub async fn dispatch(vault: &Arc<Vault>, browser: &KnownBrowser, forwarded: Forwarded) -> Reply {
    let id = forwarded.message.id;
    if !Caller::from_origin(&forwarded.origin).is_some_and(|caller| caller.is_allowed()) {
        return Reply::error(id, "forbidden", "this extension may not use Octa Pass");
    }
    let result = match forwarded.message.request {
        Request::UnlockStatus => Ok(status(vault.bridge_status().await)),
        Request::Unlock => vault.bridge_unlock().await.map(status),
        // The prompt names the browser: "unlock Octa Pass in Google Chrome".
        Request::GetSessionKeyWrap { public_key } => vault
            .wrap_session_key(&public_key, browser.name)
            .await
            .map(|wrap| serde_json::to_value(wrap).expect("serializes")),
        Request::LocalChipSecret {
            public_key,
            vault_id,
            context,
        } => vault
            .extension_chip(&public_key, &vault_id, context.as_deref())
            .await
            .map(|wrap| serde_json::to_value(wrap).expect("serializes")),
    };
    match result {
        Ok(result) => Reply::ok(id, result),
        Err(error) => vault_error(id, &error),
    }
}

fn status(status: impl serde::Serialize) -> Value {
    let mut value = serde_json::to_value(status).expect("serializes");
    value["appRunning"] = json!(true);
    value
}

fn vault_error(id: Value, error: &VaultError) -> Reply {
    let code = serde_json::to_value(error.code).expect("serializes");
    Reply::error(id, code.as_str().unwrap_or("unexpected"), &error.message)
}

/// The reply to a connection the check refused: `browserNotTrusted` when it's the browser, so the
/// extension can say so.
fn refused(refusal: &Refusal) -> Reply {
    let message = match refusal.code() {
        BROWSER_NOT_TRUSTED => format!("Octa Pass can't unlock through this browser: {refusal}."),
        _ => format!("Octa Pass refused this connection: {refusal}"),
    };
    Reply::error(Value::Null, refusal.code(), message)
}

/// Who is on the other end, by the check above.
async fn verify(
    check: Arc<HostCheck>,
    peer: std::io::Result<Process>,
) -> Result<&'static KnownBrowser, Refusal> {
    let peer = peer?;
    tokio::task::spawn_blocking(move || check.check(&OsSystem, &peer))
        .await
        .map_err(|error| Refusal::Inspect(error.to_string()))?
}

/// Notes the browser in `seen_dir` (`octapass_native_host::seen`) when the request is from an
/// allowed extension: the app stops offering the extension once one has reached it.
fn note_extension(seen_dir: &Path, browser: &KnownBrowser, forwarded: &Forwarded) {
    if !Caller::from_origin(&forwarded.origin).is_some_and(|caller| caller.is_allowed()) {
        return;
    }
    if let Err(error) = seen::record(seen_dir, browser.name) {
        eprintln!(
            "browser bridge: couldn't note the extension in {}: {error}",
            browser.name
        );
    }
}

/// One connection: one request line, one reply line.
async fn handle(
    vault: Arc<Vault>,
    stream: impl AsyncRead + AsyncWrite + Unpin,
    peer: Result<&'static KnownBrowser, Refusal>,
    seen_dir: Arc<PathBuf>,
) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut line = String::new();
    let mut reader = BufReader::new(reader).take(MAX_LINE);
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let reply = match (peer, serde_json::from_str::<Forwarded>(&line)) {
        (Err(refusal), _) => {
            eprintln!("browser bridge: refused a connection: {refusal}");
            refused(&refusal)
        }
        (Ok(browser), Ok(forwarded)) => {
            note_extension(&seen_dir, browser, &forwarded);
            dispatch(&vault, browser, forwarded).await
        }
        (Ok(_), Err(error)) => Reply::error(Value::Null, "invalidRequest", error.to_string()),
    };
    let mut bytes = serde_json::to_vec(&reply).expect("replies serialize");
    bytes.push(b'\n');
    let _ = writer.write_all(&bytes).await;
}

#[cfg(unix)]
pub async fn serve(
    vault: Arc<Vault>,
    endpoint: PathBuf,
    check: HostCheck,
    seen_dir: PathBuf,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // A socket left by a previous run (or a crash) would make bind fail.
    match std::fs::remove_file(&endpoint) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    if let Some(dir) = endpoint.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = tokio::net::UnixListener::bind(&endpoint)?;
    std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))?;
    let check = Arc::new(check);
    let seen_dir = Arc::new(seen_dir);
    loop {
        let (stream, _) = listener.accept().await?;
        let peer = system::peer(&stream);
        let (vault, check, seen_dir) = (
            Arc::clone(&vault),
            Arc::clone(&check),
            Arc::clone(&seen_dir),
        );
        tokio::spawn(
            async move { handle(vault, stream, verify(check, peer).await, seen_dir).await },
        );
    }
}

#[cfg(windows)]
pub async fn serve(
    vault: Arc<Vault>,
    endpoint: PathBuf,
    check: HostCheck,
    seen_dir: PathBuf,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let name = endpoint.as_os_str();
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(name)?;
    let check = Arc::new(check);
    let seen_dir = Arc::new(seen_dir);
    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new()
            .reject_remote_clients(true)
            .create(name)?;
        let peer = system::peer(&connected);
        let (vault, check, seen_dir) = (
            Arc::clone(&vault),
            Arc::clone(&check),
            Arc::clone(&seen_dir),
        );
        tokio::spawn(
            async move { handle(vault, connected, verify(check, peer).await, seen_dir).await },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use octapass_api::DeviceInfo;
    use octapass_desktop_vault::Config;
    use octapass_device_unlock::fake::FakeDeviceUnlock;
    use octapass_native_host::browsers::KNOWN;
    use octapass_native_host::manifests::{DEV_CHROME_ID, DEV_FIREFOX_ID};
    use octapass_native_host::protocol::Message;

    use super::*;

    fn vault(dir: &Path) -> Arc<Vault> {
        Vault::new(
            Config {
                data_dir: dir.to_owned(),
                device: DeviceInfo {
                    name: "Test".into(),
                    platform: "macos".into(),
                },
                pwned_passwords_url: "http://127.0.0.1:9".into(),
            },
            Arc::new(FakeDeviceUnlock::default()),
            Box::new(|_| {}),
        )
        .unwrap()
    }

    fn forwarded(origin: String, request: Request) -> Forwarded {
        Forwarded {
            origin,
            message: Message {
                id: json!(1),
                request,
            },
        }
    }

    fn browser() -> &'static KnownBrowser {
        &KNOWN[0]
    }

    #[tokio::test]
    async fn the_allowed_extensions_get_the_status() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        for origin in [
            format!("chrome-extension://{DEV_CHROME_ID}/"),
            format!("moz-extension://{DEV_FIREFOX_ID}"),
        ] {
            let reply = dispatch(&vault, browser(), forwarded(origin, Request::UnlockStatus)).await;
            let result = reply.result.unwrap();
            assert_eq!(result["appRunning"], true);
            assert_eq!(result["status"], "signedOut");
        }
    }

    #[tokio::test]
    async fn other_origins_are_forbidden() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        for origin in [
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
            "chrome-extension://PLACEHOLDER:chrome-web-store-id/",
            "https://example.com",
            "",
        ] {
            let reply = dispatch(
                &vault,
                browser(),
                forwarded(origin.into(), Request::UnlockStatus),
            )
            .await;
            assert_eq!(reply.error.unwrap().code, "forbidden");
        }
    }

    #[tokio::test]
    async fn vault_errors_keep_their_codes() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let origin = format!("chrome-extension://{DEV_CHROME_ID}/");
        let reply = dispatch(
            &vault,
            browser(),
            forwarded(
                origin.clone(),
                Request::GetSessionKeyWrap {
                    public_key: "AAAA".into(),
                },
            ),
        )
        .await;
        assert!(!reply.ok);
        let reply = dispatch(&vault, browser(), forwarded(origin, Request::Unlock)).await;
        assert_eq!(reply.error.unwrap().code, "locked");
    }

    #[test]
    fn a_refused_browser_gets_its_own_code() {
        let reply = refused(&Refusal::UnsignedBrowser("Chromium"));
        let error = reply.error.unwrap();
        assert_eq!(error.code, "browserNotTrusted");
        assert_eq!(
            error.message,
            "Octa Pass can't unlock through this browser: Chromium isn't signed by its vendor, so it can't unlock Octa Pass."
        );
        let reply = refused(&Refusal::NotTheHost("/tmp/impostor".into()));
        assert_eq!(reply.error.unwrap().code, "forbidden");
    }

    #[test]
    fn a_development_build_checks_the_host_by_path_only() {
        let check = host_check();
        assert_eq!(check.vouching, Vouching::Nothing);
        assert_eq!(check.team, None);
        assert_eq!(
            check.host.file_stem(),
            Some("octapass-native-host".as_ref())
        );
    }

    /// The real socket, the real host binary, and a stand-in browser that starts it.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn the_socket_answers_only_the_bundled_host() {
        use std::process::{Command, Stdio};

        use octapass_native_host::framing::{read_message, write_message};
        use octapass_native_host::ipc::{self, DATA_DIR_ENV};
        use octapass_native_host::testing::{fake_browser, host_binary};

        let dir = tempfile::tempdir().unwrap();
        let endpoint = ipc::endpoint(dir.path());
        let check = HostCheck {
            host: std::fs::canonicalize(host_binary()).unwrap(),
            team: None,
            vouching: Vouching::Nothing,
        };
        tokio::spawn(serve(
            vault(dir.path()),
            endpoint.clone(),
            check,
            dir.path().to_owned(),
        ));
        while !endpoint.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // This test process isn't the host: it gets a refusal, even with an allowed origin.
        let origin = format!("chrome-extension://{DEV_CHROME_ID}/");
        let direct = endpoint.clone();
        let reply = tokio::task::spawn_blocking(move || {
            ipc::request(&direct, &forwarded(origin, Request::UnlockStatus))
        })
        .await
        .unwrap()
        .unwrap();
        let error = reply.error.unwrap();
        assert_eq!(error.code, "forbidden");
        assert!(
            error
                .message
                .contains("only Octa Pass's own native host may connect"),
            "{}",
            error.message
        );

        // The host, started by a browser, gets the vault's answer.
        let data_dir = dir.path().to_owned();
        let reply = tokio::task::spawn_blocking(move || {
            let mut child = Command::new(fake_browser(&data_dir))
                .arg(host_binary())
                .arg(format!("chrome-extension://{DEV_CHROME_ID}/"))
                .env(DATA_DIR_ENV, &data_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let request = json!({ "id": 7, "type": "unlock-status" });
            write_message(
                child.stdin.as_mut().unwrap(),
                &serde_json::to_vec(&request).unwrap(),
            )
            .unwrap();
            let reply = read_message(child.stdout.as_mut().unwrap())
                .unwrap()
                .unwrap();
            drop(child.stdin.take());
            assert!(child.wait().unwrap().success());
            serde_json::from_slice::<Value>(&reply).unwrap()
        })
        .await
        .unwrap();
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["result"]["appRunning"], true);
        assert_eq!(reply["result"]["status"], "signedOut");
        // Only the host's connection was noted, under the browser that started it.
        assert_eq!(seen::read(dir.path()).len(), 1);
    }
}
