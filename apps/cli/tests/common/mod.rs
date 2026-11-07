//! The real sync server on a temporary SQLite database, an account made by another device (the
//! desktop vault), and the CLI's commands run in-process with an in-memory keyring and a clock
//! the tests move.

#![allow(dead_code)] // Each test binary uses a different subset.

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use octapass_api::DeviceInfo;
use octapass_cli::session::SecretStore;
use octapass_cli::{Context, Terminal};
use octapass_desktop_vault::model::{Item, ItemDraft};
use octapass_desktop_vault::{Config, Vault};
use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

pub const EMAIL: &str = "ada@example.com";
pub const PASSWORD: &str = "correct horse battery staple";

pub struct Server {
    pub url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    _data: TempDir,
}

impl Server {
    /// Stops accepting connections, as when the computer goes offline.
    pub fn stop(&mut self) {
        let _ = self.stop.take().map(|stop| stop.send(()));
    }
}

pub async fn server() -> Server {
    let data = tempfile::tempdir().unwrap();
    let data_dir = data.path().to_str().unwrap().to_owned();
    let config = octapass_server::Config::from_lookup(|name| match name {
        "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
        "OCTAPASS_DEV_MODE" => Some("true".into()),
        _ => None,
    })
    .unwrap();
    let state = octapass_server::AppState::new(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let app = octapass_server::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = stopped.await;
            })
            .await
            .unwrap()
    });
    Server {
        url,
        stop: Some(stop),
        _data: data,
    }
}

/// Another of the user's devices: it signs up (with the dev-mode verification code) and edits
/// items the CLI then syncs.
pub struct OtherDevice {
    pub vault: Arc<Vault>,
    pub secret_key: String,
    pub recovery_code: String,
    _dir: TempDir,
}

impl OtherDevice {
    pub async fn sign_up(server: &Server) -> Self {
        Self::sign_up_with(server, Arc::new(octapass_device_unlock::Unsupported)).await
    }

    pub async fn sign_up_as(server: &Server, email: &str) -> Self {
        Self::sign_up_full(server, email, Arc::new(octapass_device_unlock::Unsupported)).await
    }

    /// Another device with this device lock: the desktop app, in tests of unlocking through it.
    pub async fn sign_up_with(
        server: &Server,
        device_unlock: Arc<dyn octapass_device_unlock::DeviceUnlock>,
    ) -> Self {
        Self::sign_up_full(server, EMAIL, device_unlock).await
    }

    async fn sign_up_full(
        server: &Server,
        email: &str,
        device_unlock: Arc<dyn octapass_device_unlock::DeviceUnlock>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(
            Config {
                data_dir: dir.path().to_owned(),
                device: DeviceInfo {
                    name: "Test browser".into(),
                    platform: "web".into(),
                },
                pwned_passwords_url: server.url.clone(),
            },
            device_unlock,
            Box::new(|_| {}),
        )
        .unwrap();
        let started = vault
            .start_signup(&server.url, email, Zeroizing::new(PASSWORD.into()))
            .await
            .unwrap();
        let code = started
            .dev_verification_code
            .expect("dev mode returns the code");
        let kit = vault
            .finish_signup(&started.signup_id, &code)
            .await
            .unwrap();
        Self {
            vault,
            secret_key: kit.secret_key,
            recovery_code: kit.recovery_code,
            _dir: dir,
        }
    }

    pub fn personal_vault(&self) -> String {
        self.vault.list_vaults().unwrap()[0].id.clone()
    }

    pub async fn save(&self, overview: Value, details: Value) -> Item {
        let draft: ItemDraft = serde_json::from_value(json!({
            "vaultId": self.personal_vault(),
            "overview": overview,
            "details": details,
        }))
        .unwrap();
        self.vault.save_item(draft).await.unwrap()
    }

    pub async fn save_in(&self, vault_id: &str, overview: Value, details: Value) -> Item {
        let draft: ItemDraft = serde_json::from_value(json!({
            "vaultId": vault_id,
            "overview": overview,
            "details": details,
        }))
        .unwrap();
        self.vault.save_item(draft).await.unwrap()
    }

    pub async fn save_login(&self, title: &str, username: &str, password: &str) -> Item {
        self.save(
            json!({ "schemaVersion": 1, "type": "login", "title": title, "urls": ["https://example.com"] }),
            json!({ "schemaVersion": 1, "username": username, "password": password }),
        )
        .await
    }
}

#[derive(Default)]
pub struct MemoryKeyring(pub Mutex<HashMap<String, Vec<u8>>>);

impl MemoryKeyring {
    pub fn entries(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn contents(&self) -> Vec<u8> {
        self.0.lock().unwrap().values().flatten().copied().collect()
    }
}

impl SecretStore for MemoryKeyring {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .map(Zeroizing::new))
    }
    fn set(&self, name: &str, value: &[u8]) -> Result<(), String> {
        self.0.lock().unwrap().insert(name.into(), value.to_vec());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), String> {
        self.0.lock().unwrap().remove(name);
        Ok(())
    }
}

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Buffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

/// A person at a terminal who gives these answers, in order.
struct ScriptedTerminal {
    interactive: bool,
    answers: VecDeque<String>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Terminal for ScriptedTerminal {
    fn interactive(&self) -> bool {
        self.interactive
    }
    fn ask(&mut self, prompt: &str) -> io::Result<String> {
        self.asked.lock().unwrap().push(prompt.to_owned());
        self.answers
            .pop_front()
            .ok_or_else(|| io::Error::other("no answer left"))
    }
    fn ask_hidden(&mut self, prompt: &str) -> io::Result<Zeroizing<String>> {
        self.ask(prompt).map(Zeroizing::new)
    }
}

#[derive(Debug)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    /// The prompts the terminal was asked.
    pub asked: Vec<String>,
}

impl Output {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", self.stdout))
    }

    #[track_caller]
    pub fn ok(self) -> Self {
        assert_eq!(self.code, 0, "{self:#?}");
        self
    }
}

/// One user's CLI on one computer: its data folder, keyring and clock.
pub struct Cli {
    pub dir: TempDir,
    pub keyring: Option<Arc<MemoryKeyring>>,
    pub time: Arc<AtomicU64>,
    pub server_url: String,
}

/// How one command is run.
#[derive(Default, Clone)]
pub struct Run {
    pub stdin: String,
    pub stdout_is_terminal: bool,
    pub interactive: bool,
    pub answers: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    pub desktop_app: Option<PathBuf>,
}

impl Cli {
    pub fn new(server: &Server) -> Self {
        Self::with_keyring(server, Some(Arc::new(MemoryKeyring::default())))
    }

    pub fn with_keyring(server: &Server, keyring: Option<Arc<MemoryKeyring>>) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            keyring,
            time: Arc::new(AtomicU64::new(1_800_000_000)),
            server_url: server.url.clone(),
        }
    }

    /// A computer with no account on it.
    pub fn new_signed_out() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            keyring: None,
            time: Arc::new(AtomicU64::new(1_800_000_000)),
            server_url: String::new(),
        }
    }

    pub fn data_dir(&self) -> &Path {
        self.dir.path()
    }

    pub fn advance(&self, seconds: u64) {
        self.time.fetch_add(seconds, Ordering::SeqCst);
    }

    pub async fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, Run::default()).await
    }

    /// Runs with `stdin` as the command's input.
    pub async fn run_stdin(&self, args: &[&str], stdin: &str) -> Output {
        self.run_with(
            args,
            Run {
                stdin: stdin.to_owned(),
                ..Run::default()
            },
        )
        .await
    }

    /// Runs with the master password on stdin.
    pub async fn run_password(&self, args: &[&str]) -> Output {
        let mut all = vec!["--password-stdin"];
        all.extend_from_slice(args);
        self.run_with(
            &all,
            Run {
                stdin: format!("{PASSWORD}\n"),
                ..Run::default()
            },
        )
        .await
    }

    pub async fn login(&self, secret_key: &str) -> Output {
        self.login_with(PASSWORD, secret_key).await
    }

    pub async fn login_with(&self, password: &str, secret_key: &str) -> Output {
        self.login_full(EMAIL, password, secret_key).await
    }

    pub async fn login_as(&self, email: &str, secret_key: &str) -> Output {
        self.login_full(email, PASSWORD, secret_key).await
    }

    async fn login_full(&self, email: &str, password: &str, secret_key: &str) -> Output {
        self.run_with(
            &[
                "login",
                "--server",
                &self.server_url,
                "--email",
                email,
                "--password-stdin",
            ],
            Run {
                stdin: format!("{password}\n"),
                env: vec![("OCTAPASS_SECRET_KEY".into(), secret_key.into())],
                ..Run::default()
            },
        )
        .await
    }

    /// Starts a command that doesn't end, such as `connect serve`, on a thread of its own. It goes
    /// when the test process does.
    pub fn spawn_with(&self, args: &[&str], run: Run) {
        let (context, ..) = self.context(run);
        let mut argv = vec!["octapass".to_owned()];
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        std::thread::spawn(move || octapass_cli::run(argv, context));
    }

    pub async fn run_with(&self, args: &[&str], run: Run) -> Output {
        let (context, stdout, stderr, asked) = self.context(run);
        let mut argv = vec!["octapass".to_owned()];
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        let code = tokio::task::spawn_blocking(move || octapass_cli::run(argv, context))
            .await
            .unwrap();
        let asked = asked.lock().unwrap().clone();
        Output {
            code,
            stdout: stdout.text(),
            stderr: stderr.text(),
            asked,
        }
    }

    fn context(&self, run: Run) -> (Context, Buffer, Buffer, Arc<Mutex<Vec<String>>>) {
        let stdout = Buffer::default();
        let stderr = Buffer::default();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let keyring = self.keyring.clone();
        let time = Arc::clone(&self.time);
        let mut env: Vec<(OsString, OsString)> =
            vec![("PATH".into(), std::env::var_os("PATH").unwrap())];
        env.extend(run.env.iter().map(|(k, v)| (k.into(), v.into())));
        let cwd = run.cwd.clone();
        let context = Context {
            data_dir: self.dir.path().to_owned(),
            keyring: Box::new(move || {
                keyring
                    .clone()
                    .map(|keyring| keyring as Arc<dyn SecretStore>)
            }),
            clock: Arc::new(move || time.load(Ordering::SeqCst)),
            env,
            cwd: run
                .cwd
                .clone()
                .unwrap_or_else(|| std::env::current_dir().unwrap()),
            stdin: Box::new(io::Cursor::new(run.stdin.clone().into_bytes())),
            stdout: Box::new(stdout.clone()),
            stderr: Box::new(stderr.clone()),
            stdout_is_terminal: run.stdout_is_terminal,
            terminal: Box::new(ScriptedTerminal {
                interactive: run.interactive,
                answers: run.answers.into(),
                asked: Arc::clone(&asked),
            }),
            exec: Box::new(move |mut process| {
                if let Some(cwd) = cwd {
                    process.current_dir(cwd);
                }
                octapass_cli::spawn_and_wait(&mut process)
            }),
            desktop_app: run.desktop_app,
        };
        (context, stdout, stderr, asked)
    }

    /// Every byte the CLI keeps on disk.
    pub fn files_on_disk(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for entry in std::fs::read_dir(self.dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                bytes.extend(std::fs::read(path).unwrap());
            }
        }
        bytes
    }
}

pub fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}
