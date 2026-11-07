//! The browser extension's bridge (native messaging, plan 13, J), as the Tauri app's
//! `src-tauri/src/bridge.rs` serves it: the app listens on the local socket the
//! `octapass-native-host` relays to, and answers with the vault. The host binary and the
//! protocol (`octapass_native_host::protocol`) are unchanged.
//!
//! Every connection is checked before its request is read: it must come from the host binary
//! bundled with this app, started by a known browser (`octapass_native_host::trust`). The
//! socket's file permissions only keep other users out; this keeps out the user's other programs.
//! Then the request's origin must be one of the allowed extensions, and handing over the account
//! key asks for Touch ID or the Mac's password unless the app stays unlocked (plan 18).

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use octapass_native_host::browsers::KnownBrowser;
use octapass_native_host::caller::Caller;
use octapass_native_host::manifests::{self, Browser, Locations};
use octapass_native_host::protocol::{BROWSER_NOT_TRUSTED, Forwarded, Reply, Request};
use octapass_native_host::trust::{HostCheck, Process, Refusal, Vouching};
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::socket::{self, Service};
use crate::error::VaultError;
use crate::model::SessionStatus;
use crate::vault::Vault;

pub use octapass_native_host::ipc::endpoint;

/// `unlock-status`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeStatus {
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    /// Device unlock is set up, so `unlock` can ask for Touch ID.
    pub device_unlock: bool,
    pub label: String,
    /// Stay unlocked is on here (plan 18): `get-session-key-wrap` answers without a prompt while
    /// the app is unlocked.
    pub stay_unlocked: bool,
}

/// `get-session-key-wrap`: the account key wrapped for the extension (`super::wrap`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionKeyWrap {
    pub email: String,
    pub server_url: String,
    pub ephemeral_public_key: String,
    pub device_salt: String,
    pub wrapped_ask: Zeroizing<String>,
}

/// `local-chip-secret`: the chip secret for the extension's own local vault, sealed to the
/// extension. `context` goes with the vault in the extension; nothing else is kept there.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChipSecretWrap {
    pub context: String,
    pub ephemeral_public_key: String,
    pub sealed_secret: String,
}

/// The host binary's name in the bundle, next to the app's executable (`Contents/MacOS`).
pub const HOST_BINARY: &str = "octapass-native-host";

/// Where the bundled host is: next to this process's executable.
pub fn bundled_host() -> io::Result<PathBuf> {
    Ok(std::env::current_exe()?.with_file_name(HOST_BINARY))
}

/// The check for this build: the host at `host`, signed by the app's own team in release
/// builds on macOS; development builds check only the host's path and the browser's name.
pub fn host_check(host: &Path) -> HostCheck {
    let vouching = Vouching::for_this_build();
    if vouching == Vouching::Nothing {
        eprintln!(
            "browser bridge: development build, so only the native host's path and the browser's \
             name are checked, not their signatures"
        );
    }
    HostCheck {
        // A missing host never matches anything: process paths are canonical and absolute.
        host: std::fs::canonicalize(host).unwrap_or_else(|_| host.to_owned()),
        team: host_team(vouching),
        vouching,
    }
}

#[cfg(target_os = "macos")]
fn host_team(vouching: Vouching) -> Option<String> {
    if vouching == Vouching::Nothing {
        return None;
    }
    let team = octapass_native_host::system::own_team();
    if team.is_none() {
        eprintln!(
            "browser bridge: this build isn't signed by a developer team, so the native host's \
             signature isn't checked"
        );
    }
    team
}

#[cfg(not(target_os = "macos"))]
fn host_team(_: Vouching) -> Option<String> {
    None
}

/// Answers a request from the host `browser` started.
pub fn dispatch(vault: &Vault, browser: &KnownBrowser, forwarded: Forwarded) -> Reply {
    dispatch_with(vault, browser, forwarded, false)
}

/// [`dispatch`], answering the development extension too when `development`: the Mac app's
/// development builds say so, since this library is built for release in every build of it
/// (`octapass_native_host::manifests::allowed_chrome_ids`).
pub fn dispatch_with(
    vault: &Vault,
    browser: &KnownBrowser,
    forwarded: Forwarded,
    development: bool,
) -> Reply {
    let id = forwarded.message.id;
    if !Caller::from_origin(&forwarded.origin)
        .is_some_and(|caller| caller.is_allowed_with(development))
    {
        return Reply::error(id, "forbidden", "this extension may not use Octa Pass");
    }
    let result = match forwarded.message.request {
        Request::UnlockStatus => Ok(status(vault.bridge_status())),
        Request::Unlock => vault.bridge_unlock().map(status),
        // The prompt names the browser: "unlock Octa Pass in Google Chrome".
        Request::GetSessionKeyWrap { public_key } => vault
            .wrap_session_key(&public_key, browser.name)
            .map(|wrap| serde_json::to_value(wrap).expect("serializes")),
        Request::LocalChipSecret {
            public_key,
            vault_id,
            context,
        } => vault
            .extension_chip(&public_key, &vault_id, context.as_deref())
            .map(|wrap| serde_json::to_value(wrap).expect("serializes")),
    };
    match result {
        Ok(result) => Reply::ok(id, result),
        Err(error) => vault_error(id, &error),
    }
}

fn status(status: impl Serialize) -> Value {
    let mut value = serde_json::to_value(status).expect("serializes");
    value["appRunning"] = json!(true);
    value
}

pub(crate) fn error_code(error: &VaultError) -> String {
    serde_json::to_value(error.code)
        .ok()
        .and_then(|code| code.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unexpected".into())
}

fn vault_error(id: Value, error: &VaultError) -> Reply {
    Reply::error(id, &error_code(error), &error.message)
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

/// Who is on the other end, by `check`.
fn verify(check: &HostCheck, peer: io::Result<Process>) -> Result<&'static KnownBrowser, Refusal> {
    check.check(&octapass_native_host::system::OsSystem, &peer?)
}

/// One connection: one request line, one reply line.
fn handle(
    vault: &Vault,
    stream: &UnixStream,
    peer: Result<&'static KnownBrowser, Refusal>,
    development: bool,
) {
    let Some(line) = socket::read_request(stream) else {
        return;
    };
    let reply = match (peer, serde_json::from_str::<Forwarded>(&line)) {
        (Err(refusal), _) => {
            eprintln!("browser bridge: refused a connection: {refusal}");
            refused(&refusal)
        }
        (Ok(browser), Ok(forwarded)) => dispatch_with(vault, browser, forwarded, development),
        (Ok(_), Err(error)) => Reply::error(Value::Null, "invalidRequest", error.to_string()),
    };
    socket::write_reply(stream, &reply);
}

/// Serves the extension on `endpoint` (`endpoint(data_dir)`, where the host looks) until the
/// service is stopped or dropped.
pub fn start(vault: Arc<Vault>, endpoint: PathBuf, check: HostCheck) -> io::Result<Service> {
    start_with(vault, endpoint, check, false)
}

/// [`start`], answering the development extension too when `development` ([`dispatch_with`]).
pub fn start_with(
    vault: Arc<Vault>,
    endpoint: PathBuf,
    check: HostCheck,
    development: bool,
) -> io::Result<Service> {
    Service::start(endpoint, move |stream| {
        let peer = verify(&check, octapass_native_host::system::peer(&stream));
        handle(&vault, &stream, peer, development);
    })
}

/// Where the browsers look for this user's native messaging manifests: the real home folder,
/// not the sandboxed app's container (`octapass_native_host::ipc::user_home`). `data_dir` is the
/// app's (Windows keeps the manifests there).
pub fn manifest_locations(data_dir: &Path) -> io::Result<Locations> {
    Ok(Locations {
        home: octapass_native_host::ipc::user_home()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no home folder"))?,
        data_dir: data_dir.to_owned(),
        applications: PathBuf::from("/Applications"),
    })
}

/// Connects the browser extension: a manifest for each browser on this computer, pointing at
/// `host` (the bundled host). Returns the browsers' names; none means no supported browser.
pub fn install_manifests(
    data_dir: &Path,
    host: &Path,
    development: bool,
) -> io::Result<Vec<String>> {
    let installed = manifests::install_with(&manifest_locations(data_dir)?, host, development)?;
    Ok(names(&installed))
}

/// Disconnects it: removes every manifest. Returns the browsers it was removed from.
pub fn uninstall_manifests(data_dir: &Path) -> io::Result<Vec<String>> {
    Ok(names(&manifests::uninstall(&manifest_locations(
        data_dir,
    )?)?))
}

/// The browsers that have the manifest now.
pub fn installed_manifests(data_dir: &Path) -> Vec<String> {
    manifest_locations(data_dir)
        .map(|locations| names(&manifests::installed(&locations)))
        .unwrap_or_default()
}

fn names(browsers: &[Browser]) -> Vec<String> {
    browsers
        .iter()
        .map(|browser| browser.name().to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use octapass_native_host::browsers::KNOWN;
    use octapass_native_host::manifests::{DEV_CHROME_ID, DEV_FIREFOX_ID};
    use octapass_native_host::protocol::Message;

    use super::*;
    use crate::native::fake::FakeNative;
    use crate::vault::Config;

    fn vault(dir: &Path) -> Arc<Vault> {
        Vault::new(
            Config {
                data_dir: dir.join("data"),
                temp_dir: dir.join("temp"),
                device: octapass_ffi::DeviceInfo {
                    name: "Test Mac".into(),
                    platform: "macos".into(),
                },
                pwned_passwords_url: "http://127.0.0.1:9".into(),
            },
            Arc::new(FakeNative::default()),
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

    #[test]
    fn the_allowed_extensions_get_the_status() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        for origin in [
            format!("chrome-extension://{DEV_CHROME_ID}/"),
            format!("moz-extension://{DEV_FIREFOX_ID}"),
        ] {
            let reply = dispatch(&vault, browser(), forwarded(origin, Request::UnlockStatus));
            let result = reply.result.unwrap();
            assert_eq!(result["appRunning"], true);
            assert_eq!(result["status"], "signedOut");
            assert_eq!(result["stayUnlocked"], false);
        }
    }

    #[test]
    fn a_development_app_answers_the_development_extension() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let origin = format!("chrome-extension://{DEV_CHROME_ID}/");
        let reply = dispatch_with(
            &vault,
            browser(),
            forwarded(origin.clone(), Request::UnlockStatus),
            true,
        );
        assert_eq!(reply.result.unwrap()["appRunning"], true);
        let other = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";
        let reply = dispatch_with(
            &vault,
            browser(),
            forwarded(other.into(), Request::UnlockStatus),
            true,
        );
        assert_eq!(reply.error.unwrap().code, "forbidden");
    }

    #[test]
    fn manifests_go_in_the_real_home_folder() {
        let dir = tempfile::tempdir().unwrap();
        let locations = manifest_locations(dir.path()).unwrap();
        assert_eq!(Some(locations.home), octapass_native_host::ipc::user_home());
        assert_eq!(locations.data_dir, dir.path());
    }

    #[test]
    fn other_origins_are_forbidden() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        for origin in [
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
            "chrome-extension://PLACEHOLDER:chrome-web-store-id/",
            "https://example.com",
            "",
        ] {
            for request in [
                Request::UnlockStatus,
                Request::Unlock,
                Request::GetSessionKeyWrap {
                    public_key: "AAAA".into(),
                },
            ] {
                let reply = dispatch(&vault, browser(), forwarded(origin.into(), request));
                assert_eq!(reply.error.unwrap().code, "forbidden");
            }
        }
    }

    #[test]
    fn vault_errors_keep_their_codes() {
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
        );
        assert_eq!(reply.error.unwrap().code, "locked");
        let reply = dispatch(&vault, browser(), forwarded(origin, Request::Unlock));
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
        let check = host_check(&bundled_host().unwrap());
        assert_eq!(check.vouching, Vouching::Nothing);
        assert_eq!(check.team, None);
        assert_eq!(check.host.file_name(), Some(HOST_BINARY.as_ref()));
    }

    /// The real socket: this test process isn't the host, so it gets a refusal, even with an
    /// allowed origin, and the vault is never asked.
    #[test]
    fn the_socket_refuses_anything_but_the_bundled_host() {
        let dir = tempfile::tempdir().unwrap();
        let endpoint = endpoint(dir.path());
        let check = HostCheck {
            host: "/Applications/Octa Pass.app/Contents/MacOS/octapass-native-host".into(),
            team: None,
            vouching: Vouching::Nothing,
        };
        let service = start(vault(dir.path()), endpoint.clone(), check).unwrap();
        let origin = format!("chrome-extension://{DEV_CHROME_ID}/");
        let reply = octapass_native_host::ipc::request(
            &endpoint,
            &forwarded(origin, Request::UnlockStatus),
        )
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
        assert_eq!(reply.id, Value::Null, "refused before the request is read");
        service.stop();
    }
}
