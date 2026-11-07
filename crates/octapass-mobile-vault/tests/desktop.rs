//! The desktop services on the native vault (plan 19, phase 3): the browser extension's bridge
//! and the CLI session, on a vault on this computer only, with `FakeNative` for the Keychain and
//! the device lock. The same cases as the Tauri app's tests of `octapass-desktop-vault`.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use octapass_core::encoding::{b64_decode, b64_decode_array, b64_encode};
use octapass_core::kdf::KdfParams;
use octapass_core::keys::SymmetricKey;
use octapass_ffi::{DeviceInfo, LocalStore};
use octapass_mobile_vault::accounts::{Accounts, store_path};
use octapass_mobile_vault::desktop::bridge::SessionKeyWrap;
use octapass_mobile_vault::desktop::cli_session::{self, CliGrants, CliPeer};
use octapass_mobile_vault::desktop::wrap::{CHIP_WRAP_INFO, WRAP_INFO, wrap_key};
use octapass_mobile_vault::model::SessionStatus;
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::{Config, ErrorCode, Vault};
use rand_core::OsRng;
use serde_json::{Value, json};
use tempfile::TempDir;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const STRONG: &str = "vexed-kiwi-trumpet-galaxy-oboe";
const UNLOCK: &str = "Unlock Octa Pass";

struct Mac {
    vault: Arc<Vault>,
    native: Arc<FakeNative>,
    dir: TempDir,
}

impl Mac {
    fn new(native: FakeNative) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let native = Arc::new(native);
        let vault = Vault::new(
            Config {
                data_dir: dir.path().join("group"),
                temp_dir: dir.path().join("temp"),
                device: DeviceInfo {
                    name: "Test Mac".into(),
                    platform: "macos".into(),
                },
                pwned_passwords_url: "http://127.0.0.1:9".into(),
            },
            native.clone(),
            Box::new(|_| {}),
        )
        .unwrap();
        Self { vault, native, dir }
    }

    /// With a local vault, open.
    fn with_vault() -> Self {
        let mac = Self::new(FakeNative::default());
        mac.vault
            .create_local_vault_with("Home", Zeroizing::new(STRONG.into()), KdfParams::DEFAULT)
            .unwrap();
        mac
    }

    fn prompts(&self) -> Vec<String> {
        self.native.prompts.lock().unwrap().clone()
    }

    fn cancel_next_prompt(&self) {
        *self.native.cancel_next_prompt.lock().unwrap() = true;
    }

    fn data_dir(&self) -> PathBuf {
        self.dir.path().join("group")
    }

    /// What a second program (the extension, the CLI) holding the same account's store does
    /// with a wrap: unwrap it with its own half of the exchange.
    fn opens(&self, peer: &StaticSecret, wrap: &Value) -> bool {
        let app_public: [u8; 32] =
            b64_decode_array(wrap["ephemeralPublicKey"].as_str().unwrap()).unwrap();
        let shared = peer.diffie_hellman(&PublicKey::from(app_public));
        let key = wrap_key(
            shared.as_bytes(),
            &app_public,
            PublicKey::from(peer).as_bytes(),
            WRAP_INFO,
        );
        let accounts = Accounts::load(&self.data_dir()).unwrap();
        let path = store_path(&self.data_dir(), accounts.current().unwrap());
        let store = LocalStore::open(path.to_string_lossy().into_owned()).unwrap();
        store
            .unlock_with_device_wrap(
                key.as_ref(),
                &b64_decode(wrap["deviceSalt"].as_str().unwrap()).unwrap(),
                wrap["wrappedAsk"].as_str().unwrap(),
            )
            .is_ok()
    }
}

fn keypair() -> (StaticSecret, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = b64_encode(PublicKey::from(&secret).as_bytes());
    (secret, public)
}

fn json_of(wrap: &SessionKeyWrap) -> Value {
    serde_json::to_value(wrap).unwrap()
}

// ---------- The browser extension ----------

#[test]
fn the_extension_gets_the_account_key_after_the_prompt() {
    let mac = Mac::with_vault();
    let (extension, public) = keypair();
    let wrap = mac.vault.wrap_session_key(&public, "Firefox").unwrap();
    assert_eq!(mac.prompts(), ["unlock Octa Pass in Firefox"]);
    assert_eq!(wrap.email, "Home");
    let wrap = json_of(&wrap);
    assert_eq!(
        wrap.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "deviceSalt",
            "email",
            "ephemeralPublicKey",
            "serverUrl",
            "wrappedAsk"
        ]
    );
    assert!(mac.opens(&extension, &wrap), "the extension opens it");
    let (stranger, _) = keypair();
    assert!(!mac.opens(&stranger, &wrap), "nobody else does");

    mac.cancel_next_prompt();
    assert_eq!(
        mac.vault
            .wrap_session_key(&public, "Firefox")
            .unwrap_err()
            .code,
        ErrorCode::DeviceUnlockCancelled
    );
    assert!(
        mac.vault
            .wrap_session_key(&b64_encode(&[0; 32]), "Firefox")
            .is_err()
    );
    mac.vault.lock();
    let asked = mac.prompts().len();
    assert_eq!(
        mac.vault
            .wrap_session_key(&public, "Firefox")
            .unwrap_err()
            .code,
        ErrorCode::Locked
    );
    assert_eq!(mac.prompts().len(), asked, "locked, nothing asks");
}

#[test]
fn a_mac_without_a_lock_to_ask_hands_nothing_over() {
    let mac = Mac::new(FakeNative {
        lock: octapass_mobile_vault::DeviceLock {
            available: false,
            label: "Password".into(),
        },
        ..FakeNative::default()
    });
    mac.vault
        .create_local_vault_with("Home", Zeroizing::new(STRONG.into()), KdfParams::DEFAULT)
        .unwrap();
    let (_, public) = keypair();
    assert_eq!(
        mac.vault
            .wrap_session_key(&public, "Firefox")
            .unwrap_err()
            .code,
        ErrorCode::DeviceUnlockUnsupported
    );
}

#[test]
fn staying_unlocked_hands_the_key_over_without_a_prompt() {
    let mac = Mac::with_vault();
    assert!(!mac.vault.bridge_status().stay_unlocked);
    mac.vault.enable_stay_unlocked().unwrap();
    assert!(mac.vault.bridge_status().stay_unlocked);
    let (extension, public) = keypair();
    let wrap = mac.vault.wrap_session_key(&public, "Firefox").unwrap();
    assert!(mac.prompts().is_empty());
    assert!(mac.opens(&extension, &json_of(&wrap)));

    // Off, it asks again; locked, it hands nothing over either way.
    mac.vault.disable_stay_unlocked().unwrap();
    mac.vault.wrap_session_key(&public, "Firefox").unwrap();
    assert_eq!(mac.prompts(), ["unlock Octa Pass in Firefox"]);
    mac.vault.enable_stay_unlocked().unwrap();
    mac.vault.lock();
    assert_eq!(
        mac.vault
            .wrap_session_key(&public, "Firefox")
            .unwrap_err()
            .code,
        ErrorCode::Locked
    );
}

#[test]
fn the_extension_sees_the_status_and_can_ask_for_device_unlock() {
    let mac = Mac::with_vault();
    mac.vault.enable_device_unlock().unwrap();
    mac.vault.lock();
    let status = serde_json::to_value(mac.vault.bridge_status()).unwrap();
    assert_eq!(status["status"], "locked");
    assert_eq!(status["deviceUnlock"], true);
    assert_eq!(status["label"], "Face ID");
    assert_eq!(status["email"], "Home");

    mac.cancel_next_prompt();
    assert_eq!(
        mac.vault.bridge_unlock().unwrap_err().code,
        ErrorCode::DeviceUnlockCancelled
    );
    let status = mac.vault.bridge_unlock().unwrap();
    assert_eq!(status.status, SessionStatus::Unlocked);
    assert_eq!(mac.prompts(), [UNLOCK, UNLOCK]);
    // Already open, nothing asks.
    mac.vault.bridge_unlock().unwrap();
    assert_eq!(mac.prompts().len(), 2);
}

/// Opens a `local-chip-secret` reply with the extension's half of the exchange.
fn chip_secret(extension: &StaticSecret, wrap: &Value) -> Zeroizing<Vec<u8>> {
    let app_public: [u8; 32] =
        b64_decode_array(wrap["ephemeralPublicKey"].as_str().unwrap()).unwrap();
    let shared = extension.diffie_hellman(&PublicKey::from(app_public));
    let key = wrap_key(
        shared.as_bytes(),
        &app_public,
        PublicKey::from(extension).as_bytes(),
        CHIP_WRAP_INFO,
    );
    octapass_core::local::keys::open_chip_secret(
        &SymmetricKey::from_slice(key.as_ref()).unwrap(),
        wrap["sealedSecret"].as_str().unwrap(),
    )
    .unwrap()
}

#[test]
fn the_extensions_local_vault_gets_the_same_chip_secret_again() {
    // Locked and signed out: the chip secret needs neither, nor a prompt.
    let mac = Mac::new(FakeNative::default());
    let (extension, public) = keypair();
    let first = mac
        .vault
        .extension_chip(&public, "vault-1", None)
        .unwrap()
        .unwrap();
    let first = serde_json::to_value(first).unwrap();
    let context = first["context"].as_str().unwrap().to_owned();
    let secret = chip_secret(&extension, &first);
    assert_eq!(secret.len(), 32);

    let (extension, public) = keypair();
    let again = mac
        .vault
        .extension_chip(&public, "vault-1", Some(&context))
        .unwrap()
        .unwrap();
    let again = serde_json::to_value(again).unwrap();
    assert_eq!(again["context"], context.as_str());
    assert_eq!(chip_secret(&extension, &again), secret);
    assert!(mac.prompts().is_empty());

    // Another vault has another key; a bad id or a key that's gone gets nothing.
    let other = mac
        .vault
        .extension_chip(&public, "vault-2", None)
        .unwrap()
        .unwrap();
    assert_ne!(
        chip_secret(&extension, &serde_json::to_value(other).unwrap()),
        secret
    );
    assert_eq!(
        mac.vault
            .extension_chip(&public, "../x", None)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        mac.vault
            .extension_chip(&public, "vault-3", Some(&context))
            .unwrap_err()
            .code,
        ErrorCode::DeviceUnlockFailed
    );

    let no_chip = Mac::new(FakeNative {
        chip: false,
        ..FakeNative::default()
    });
    assert!(
        no_chip
            .vault
            .extension_chip(&public, "vault-1", None)
            .unwrap()
            .is_none()
    );
}

/// The real host binary, started by a stand-in browser, through the real socket and its checks.
/// The host isn't part of this workspace, so build it into this target folder first:
///
/// ```text
/// cargo build --manifest-path apps/desktop/Cargo.toml -p octapass-native-host \
///     --bin octapass-native-host --example fake-browser --target-dir target
/// cargo test -p octapass-mobile-vault --test integration desktop:: -- --ignored
/// ```
#[test]
#[ignore = "needs octapass-native-host built into target/ (see the comment)"]
fn the_bundled_host_started_by_a_browser_gets_the_vaults_answer() {
    use std::process::{Command, Stdio};

    use octapass_mobile_vault::desktop::bridge;
    use octapass_native_host::framing::{read_message, write_message};
    use octapass_native_host::ipc::DATA_DIR_ENV;
    use octapass_native_host::manifests::DEV_CHROME_ID;
    use octapass_native_host::testing::{fake_browser, host_binary};

    let mac = Mac::with_vault();
    let app_dir = tempfile::Builder::new()
        .prefix("opb")
        .tempdir_in("/tmp")
        .unwrap();
    let endpoint = bridge::endpoint(app_dir.path());
    let check = bridge::host_check(&host_binary());
    let _service = bridge::start(Arc::clone(&mac.vault), endpoint, check).unwrap();

    let ask = |request: Value| {
        let mut child = Command::new(fake_browser(app_dir.path()))
            .arg(host_binary())
            .arg(format!("chrome-extension://{DEV_CHROME_ID}/"))
            .env(DATA_DIR_ENV, app_dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
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
    };

    let reply = ask(json!({ "id": 7, "type": "unlock-status" }));
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["result"]["appRunning"], true);
    assert_eq!(reply["result"]["status"], "unlocked");

    let (extension, public) = keypair();
    let reply = ask(json!({ "id": 8, "type": "get-session-key-wrap", "publicKey": public }));
    assert_eq!(reply["ok"], true, "{reply}");
    assert!(mac.opens(&extension, &reply["result"]));
    assert_eq!(mac.prompts(), ["unlock Octa Pass in Firefox"]);

    // Run directly, the host refuses before the app is asked.
    let direct = Command::new(host_binary())
        .arg(format!("chrome-extension://{DEV_CHROME_ID}/"))
        .env(DATA_DIR_ENV, app_dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut direct = direct;
    write_message(
        direct.stdin.as_mut().unwrap(),
        &serde_json::to_vec(&json!({ "id": 9, "type": "unlock-status" })).unwrap(),
    )
    .unwrap();
    let reply = read_message(direct.stdout.as_mut().unwrap())
        .unwrap()
        .unwrap();
    drop(direct.stdin.take());
    direct.wait().unwrap();
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(reply["error"]["code"], "browserNotTrusted", "{reply}");
}

// ---------- The CLI ----------

/// The app's CLI socket, with the program on the other end set by the test.
struct CliApp {
    mac: Mac,
    endpoint: PathBuf,
    peer: Arc<Mutex<Option<CliPeer>>>,
    _service: octapass_mobile_vault::desktop::Service,
}

fn octapass(session: u32) -> CliPeer {
    CliPeer {
        executable: "/usr/local/bin/octapass".into(),
        session: Some(session),
    }
}

impl CliApp {
    fn new(mac: Mac) -> Self {
        // Short, so it fits a socket address.
        let endpoint = cli_session::endpoint(&mac.dir.path().join("app"));
        let peer = Arc::new(Mutex::new(Some(octapass(42))));
        let identify = Arc::clone(&peer);
        let service = cli_session::start(
            Arc::clone(&mac.vault),
            Arc::new(CliGrants::default()),
            endpoint.clone(),
            move |_| {
                identify
                    .lock()
                    .unwrap()
                    .clone()
                    .ok_or_else(|| std::io::Error::other("no such process"))
            },
        )
        .unwrap();
        Self {
            mac,
            endpoint,
            peer,
            _service: service,
        }
    }

    fn ask(&self, request: Value) -> Value {
        ask(&self.endpoint, &format!("{request}\n"))
    }

    fn account(&self) -> (String, String) {
        let session = self.mac.vault.snapshot().session;
        (session.email.unwrap(), session.server_url.unwrap())
    }

    /// A `session` request with a fresh key, as `octapass` sends it.
    fn session(&self) -> (StaticSecret, Value) {
        let (email, server_url) = self.account();
        let (secret, public) = keypair();
        let reply = self.ask(json!({
            "type": "session", "email": email, "serverUrl": server_url, "publicKey": public
        }));
        (secret, reply)
    }

    fn status(&self) -> Value {
        let (email, server_url) = self.account();
        self.ask(json!({ "type": "status", "email": email, "serverUrl": server_url }))
    }

    fn as_peer(&self, peer: Option<CliPeer>) {
        *self.peer.lock().unwrap() = peer;
    }
}

/// One request line, one reply line.
fn ask(endpoint: &Path, line: &str) -> Value {
    let mut stream = UnixStream::connect(endpoint).unwrap();
    stream.write_all(line.as_bytes()).unwrap();
    let mut reply = String::new();
    BufReader::new(&stream).read_line(&mut reply).unwrap();
    serde_json::from_str(&reply).unwrap()
}

const CLI_PROMPT: &str = "unlock the Octa Pass command-line tool (/usr/local/bin/octapass)";

#[test]
fn one_approval_covers_this_terminal() {
    let app = CliApp::new(Mac::with_vault());
    assert_eq!(
        app.status()["result"],
        json!({ "granted": false, "sameAccount": true })
    );
    let (cli, reply) = app.session();
    assert_eq!(reply["ok"], true, "{reply}");
    assert!(app.mac.opens(&cli, &reply["result"]));
    assert_eq!(app.mac.prompts(), [CLI_PROMPT]);

    // The next commands from this terminal use the grant.
    let (cli, reply) = app.session();
    assert!(app.mac.opens(&cli, &reply["result"]));
    assert_eq!(app.mac.prompts().len(), 1);
    assert_eq!(app.status()["result"]["granted"], true);

    // Another terminal, or another program, asks again.
    app.as_peer(Some(octapass(43)));
    assert_eq!(app.status()["result"]["granted"], false);
    app.session();
    app.as_peer(Some(CliPeer {
        executable: "/tmp/other".into(),
        session: Some(42),
    }));
    app.session();
    assert_eq!(app.mac.prompts().len(), 3);

    // `octapass lock` ends its own grant.
    app.as_peer(Some(octapass(42)));
    assert_eq!(
        app.ask(json!({ "type": "end" })),
        json!({ "ok": true, "result": {} })
    );
    assert_eq!(app.status()["result"]["granted"], false);
    app.session();
    assert_eq!(app.mac.prompts().len(), 4);
}

#[test]
fn locking_the_app_ends_every_grant() {
    let mac = Mac::with_vault();
    mac.vault.enable_device_unlock().unwrap();
    let app = CliApp::new(mac);
    app.session();
    assert_eq!(app.status()["result"]["granted"], true);
    app.mac.vault.lock();
    assert_eq!(app.status()["result"]["granted"], false);

    // Locked, the device unlock is the approval: one prompt, and the app is open again.
    let (cli, reply) = app.session();
    assert!(app.mac.opens(&cli, &reply["result"]));
    assert_eq!(app.mac.prompts(), [CLI_PROMPT, UNLOCK]);
    assert_eq!(
        app.mac.vault.snapshot().session.status,
        SessionStatus::Unlocked
    );
    app.session();
    assert_eq!(app.mac.prompts().len(), 2, "the grant is for this unlock");

    // Unlocked again some other way, the old grant doesn't come back.
    app.mac.vault.lock();
    app.mac.vault.unlock_with_device().unwrap();
    app.session();
    assert_eq!(app.mac.prompts(), [CLI_PROMPT, UNLOCK, UNLOCK, CLI_PROMPT]);
}

#[test]
fn a_refused_prompt_gives_nothing() {
    let app = CliApp::new(Mac::with_vault());
    app.mac.cancel_next_prompt();
    let (_, reply) = app.session();
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"]["code"], "deviceUnlockCancelled");
    assert!(reply.get("result").is_none());
    assert_eq!(app.status()["result"]["granted"], false);

    // Locked without device unlock: `locked`, and the master password is the CLI's to ask.
    app.mac.vault.lock();
    let (_, reply) = app.session();
    assert_eq!(reply["error"]["code"], "locked");
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("The Octa Pass app is locked: "),
        "{reply}"
    );
}

#[test]
fn another_account_gets_nothing_from_the_app() {
    let app = CliApp::new(Mac::with_vault());
    let (_, public) = keypair();
    let reply = app.ask(json!({
        "type": "session", "email": "ada@example.com", "serverUrl": "https://octap.app",
        "publicKey": public
    }));
    assert_eq!(reply["error"]["code"], "otherAccount");
    let status = app.ask(json!({
        "type": "status", "email": "ada@example.com", "serverUrl": "https://octap.app"
    }));
    assert_eq!(
        status["result"],
        json!({ "granted": false, "sameAccount": false })
    );
    assert!(app.mac.prompts().is_empty());
}

#[test]
fn bad_requests_and_unknown_programs_are_refused() {
    let app = CliApp::new(Mac::with_vault());
    let reply = ask(&app.endpoint, "{\"type\":\"export-vault\"}\n");
    assert_eq!(reply["error"]["code"], "invalidRequest");
    app.as_peer(None);
    let (_, reply) = app.session();
    assert_eq!(reply["error"]["code"], "forbidden");
    assert!(app.mac.prompts().is_empty());
}

// ---------- The SSH agent ----------

mod ssh_agent {
    use std::io::Read;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use octapass_core::tools::ssh::{self, SshKey, SshKeyKind};
    use octapass_mobile_vault::desktop::ssh_agent::{Language, SshAgent, SshPrompts};
    use octapass_mobile_vault::model::ItemDraft;

    use super::*;

    fn save(mac: &Mac, title: &str, key: &SshKey, extra: Value) -> String {
        let mut details = json!({
            "schemaVersion": 1,
            "privateKey": key.private_key.as_str(),
            "publicKey": key.info.public_key,
            "keyType": key.info.key_type,
            "fingerprint": key.info.fingerprint,
            "comment": "me@laptop",
        });
        for (name, value) in extra.as_object().unwrap() {
            details[name] = value.clone();
        }
        mac.vault
            .save_item(ItemDraft {
                id: None,
                vault_id: mac.vault.list_vaults().unwrap()[0].id.clone(),
                revision: None,
                overview: json!({ "schemaVersion": 1, "type": "sshKey", "title": title }),
                details,
            })
            .unwrap()
            .id
    }

    fn key() -> SshKey {
        ssh::generate(SshKeyKind::Ed25519, "a", &mut OsRng).unwrap()
    }

    #[test]
    fn the_agent_offers_usable_keys_and_signs_while_unlocked() {
        let mac = Mac::with_vault();
        let offered = key();
        let held_back = key();
        save(&mac, "Laptop", &offered, json!({}));
        save(&mac, "Quiet", &held_back, json!({ "sshAgent": false }));
        let gone = save(&mac, "Gone", &key(), json!({}));
        mac.vault.delete_item(&gone).unwrap();

        let keys = mac.vault.ssh_agent_keys().unwrap();
        assert_eq!(keys.len(), 1, "{keys:?}");
        assert_eq!(keys[0].title, "Laptop");
        assert_eq!(keys[0].comment, "me@laptop");
        assert_eq!(keys[0].fingerprint, offered.info.fingerprint);
        let blob = keys[0].blob.clone();
        assert_eq!(
            blob,
            ssh::public_key_blob(&offered.info.public_key).unwrap()
        );
        let signature = mac.vault.ssh_agent_sign(&blob, b"data", 0).unwrap();
        assert_eq!(&signature[4..15], b"ssh-ed25519");

        // A key that's held back can't be used by naming it.
        let quiet = ssh::public_key_blob(&held_back.info.public_key).unwrap();
        assert_eq!(
            mac.vault
                .ssh_agent_sign(&quiet, b"data", 0)
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );

        mac.vault.lock();
        assert_eq!(
            mac.vault.ssh_agent_keys().unwrap_err().code,
            ErrorCode::Locked
        );
        assert_eq!(
            mac.vault
                .ssh_agent_sign(&blob, b"data", 0)
                .unwrap_err()
                .code,
            ErrorCode::Locked
        );
    }

    #[derive(Default)]
    struct Window {
        allow: bool,
        asked: Mutex<Vec<String>>,
        shown: AtomicUsize,
    }

    impl SshPrompts for Window {
        fn approve(&self, text: &str) -> bool {
            self.asked.lock().unwrap().push(text.into());
            self.allow
        }

        fn show_unlock(&self) {
            self.shown.fetch_add(1, Ordering::SeqCst);
        }

        fn language(&self) -> Language {
            Language::English
        }
    }

    /// An SSH client's side: one request, one answer, in the agent protocol's framing.
    struct Client(UnixStream);

    impl Client {
        fn connect(agent: &SshAgent) -> Self {
            for _ in 0..200 {
                if let Ok(stream) = UnixStream::connect(agent.endpoint()) {
                    return Self(stream);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("the agent didn't start: {:?}", agent.error());
        }

        fn ask(&mut self, body: &[u8]) -> Vec<u8> {
            self.0
                .write_all(&[&(body.len() as u32).to_be_bytes()[..], body].concat())
                .unwrap();
            let mut length = [0u8; 4];
            self.0.read_exact(&mut length).unwrap();
            let mut answer = vec![0u8; u32::from_be_bytes(length) as usize];
            self.0.read_exact(&mut answer).unwrap();
            answer
        }

        /// `SSH_AGENTC_REQUEST_IDENTITIES`: how many keys came back.
        fn identities(&mut self) -> u32 {
            let answer = self.ask(&[11]);
            assert_eq!(answer[0], 12, "SSH_AGENT_IDENTITIES_ANSWER");
            u32::from_be_bytes(answer[1..5].try_into().unwrap())
        }

        /// `SSH_AGENTC_SIGN_REQUEST`: the signature, or `None` for `SSH_AGENT_FAILURE`.
        fn sign(&mut self, blob: &[u8], data: &[u8]) -> Option<Vec<u8>> {
            let string = |bytes: &[u8]| [&(bytes.len() as u32).to_be_bytes()[..], bytes].concat();
            let request = [&[13u8][..], &string(blob), &string(data), &[0, 0, 0, 0]].concat();
            let answer = self.ask(&request);
            match answer[0] {
                14 => Some(answer[5..].to_vec()),
                5 => None,
                other => panic!("unexpected answer {other}"),
            }
        }
    }

    fn agent(mac: &Mac, window: Arc<Window>) -> (SshAgent, TempDir) {
        let dir = tempfile::Builder::new()
            .prefix("opa")
            .tempdir_in("/tmp")
            .unwrap();
        let agent = SshAgent::start(
            Arc::clone(&mac.vault),
            window,
            dir.path().join("agent.sock"),
        )
        .unwrap();
        (agent, dir)
    }

    #[test]
    fn every_signature_asks_the_device_lock_naming_the_key() {
        let mac = Mac::with_vault();
        mac.vault.enable_device_unlock().unwrap();
        let laptop = key();
        save(&mac, "Laptop", &laptop, json!({}));
        let blob = ssh::public_key_blob(&laptop.info.public_key).unwrap();
        let window = Arc::new(Window::default());
        let (agent, dir) = agent(&mac, Arc::clone(&window));
        let mut client = Client::connect(&agent);

        assert_eq!(client.identities(), 1);
        let signature = client.sign(&blob, b"data").expect("approved");
        assert_eq!(&signature[4..15], b"ssh-ed25519");
        let prompts = mac.prompts();
        assert_eq!(prompts.len(), 1);
        assert!(
            prompts[0].starts_with("use the SSH key “Laptop”, for "),
            "{prompts:?}"
        );

        mac.cancel_next_prompt();
        assert_eq!(client.sign(&blob, b"data"), None);
        assert!(
            window.asked.lock().unwrap().is_empty(),
            "the Mac has a lock to ask"
        );

        // Locked, the first request opens the device unlock prompt.
        mac.vault.lock();
        assert_eq!(client.identities(), 1);
        assert_eq!(mac.prompts().last().unwrap(), UNLOCK);
        assert_eq!(mac.vault.snapshot().session.status, SessionStatus::Unlocked);

        // Cancelled, the agent stays quiet instead of asking again at once.
        mac.vault.lock();
        mac.cancel_next_prompt();
        let asked = mac.prompts().len();
        assert_eq!(client.identities(), 0);
        assert_eq!(client.identities(), 0);
        assert_eq!(mac.prompts().len(), asked + 1);
        assert_eq!(window.shown.load(Ordering::SeqCst), 0);

        agent.stop();
        assert!(UnixStream::connect(dir.path().join("agent.sock")).is_err());
    }

    #[test]
    fn a_mac_without_a_lock_asks_in_the_apps_window() {
        let mac = Mac::new(FakeNative {
            lock: octapass_mobile_vault::DeviceLock {
                available: false,
                label: "Password".into(),
            },
            ..FakeNative::default()
        });
        mac.vault
            .create_local_vault_with("Home", Zeroizing::new(STRONG.into()), KdfParams::DEFAULT)
            .unwrap();
        let laptop = key();
        save(&mac, "Laptop", &laptop, json!({}));
        let blob = ssh::public_key_blob(&laptop.info.public_key).unwrap();

        let window = Arc::new(Window {
            allow: true,
            ..Window::default()
        });
        let (agent, _dir) = agent(&mac, Arc::clone(&window));
        let mut client = Client::connect(&agent);
        assert!(client.sign(&blob, b"data").is_some());
        let asked = window.asked.lock().unwrap().clone();
        assert_eq!(asked.len(), 1);
        assert!(
            asked[0].starts_with("use the SSH key “Laptop”"),
            "{asked:?}"
        );
        assert!(mac.prompts().is_empty());

        // Locked with no device unlock: only the window can open it, so it's brought forward.
        mac.vault.lock();
        assert_eq!(client.identities(), 0);
        assert_eq!(window.shown.load(Ordering::SeqCst), 1);
        drop(agent);

        let refusing = Arc::new(Window::default());
        mac.vault.unlock(Zeroizing::new(STRONG.into())).unwrap();
        let (agent, _dir) = self::agent(&mac, Arc::clone(&refusing));
        let mut client = Client::connect(&agent);
        assert_eq!(client.sign(&blob, b"data"), None);
        assert_eq!(refusing.asked.lock().unwrap().len(), 1);
    }
}
