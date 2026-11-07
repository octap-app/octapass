//! SSH in the desktop app: the agent, `~/.ssh`, and the key operations the vault window needs.
//!
//! The agent ([`octapass_ssh_agent`]) is off until turned on in Settings, a per-device choice kept
//! in the app's data folder. It offers the vault's usable keys while unlocked, and every signature
//! asks the device lock, naming the key and the program. A device with no lock gets the app's own
//! Allow / Deny window instead. While locked, a request opens the device unlock prompt; if that's
//! cancelled the agent stays quiet for a minute, so tools that poll it don't nag.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use octapass_core::tools::ssh::{self, SshKey, SshKeyKind};
use octapass_desktop_vault::model::SessionStatus;
use octapass_desktop_vault::ssh_agent::AgentKey;
use octapass_desktop_vault::{ErrorCode, Vault, VaultError};
use octapass_native_host::system::{self, OsSystem};
use octapass_native_host::trust::System;
use octapass_ssh_agent::home::{self, FoundKey};
use octapass_ssh_agent::wire::{self, Purpose};
use octapass_ssh_agent::{Backend, Identity, Peer, server};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tauri::async_runtime::JoinHandle;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use zeroize::Zeroizing;

use crate::menu::{self, Language};

type Result<T> = std::result::Result<T, VaultError>;

/// How long a cancelled unlock keeps the agent quiet.
const QUIET_AFTER_CANCEL: Duration = Duration::from_secs(60);

#[derive(Default, Serialize, Deserialize)]
struct Settings {
    enabled: bool,
}

pub struct SshState {
    app: AppHandle,
    vault: Arc<Vault>,
    settings_path: PathBuf,
    /// In-flight connections outlive the listener: they check this.
    serving: Arc<AtomicBool>,
    task: Mutex<Option<JoinHandle<()>>>,
    /// Why the agent isn't running, for Settings.
    error: Arc<Mutex<Option<String>>>,
}

impl SshState {
    pub fn new(app: AppHandle, vault: Arc<Vault>, data_dir: PathBuf) -> Self {
        Self {
            app,
            vault,
            settings_path: data_dir.join("ssh-agent.json"),
            serving: Arc::new(AtomicBool::new(false)),
            task: Mutex::new(None),
            error: Arc::new(Mutex::new(None)),
        }
    }

    fn settings(&self) -> Settings {
        std::fs::read(&self.settings_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn start(&self) {
        let mut task = self.task.lock().unwrap();
        if task.is_some() {
            return;
        }
        let Some(endpoint) = server::endpoint() else {
            *self.error.lock().unwrap() = Some("This user has no home folder.".into());
            return;
        };
        self.serving.store(true, Ordering::SeqCst);
        *self.error.lock().unwrap() = None;
        let backend = Arc::new(AppBackend {
            vault: Arc::clone(&self.vault),
            app: self.app.clone(),
            serving: Arc::clone(&self.serving),
            prompt: tokio::sync::Mutex::new(None),
        });
        let error = Arc::clone(&self.error);
        *task = Some(tauri::async_runtime::spawn(async move {
            if let Err(failure) = server::serve(backend, endpoint, peer_of).await {
                eprintln!("SSH agent stopped: {failure}");
                *error.lock().unwrap() = Some(failure.to_string());
            }
        }));
    }

    fn stop(&self) {
        self.serving.store(false, Ordering::SeqCst);
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
        if let Some(endpoint) = server::endpoint() {
            server::remove(&endpoint);
        }
    }
}

pub fn start_if_enabled(app: &AppHandle) {
    let state = app.state::<SshState>();
    if state.settings().enabled {
        state.start();
    }
}

#[cfg(unix)]
fn peer_of(stream: &tokio::net::UnixStream) -> Peer {
    system::peer(stream).map_or_else(|_| Peer::default(), process_peer)
}

#[cfg(windows)]
fn peer_of(pipe: &tokio::net::windows::named_pipe::NamedPipeServer) -> Peer {
    system::peer(pipe).map_or_else(|_| Peer::default(), process_peer)
}

fn process_peer(process: octapass_native_host::trust::Process) -> Peer {
    let parent = OsSystem
        .parent(process.pid)
        .ok()
        .flatten()
        .and_then(|pid| OsSystem.executable(pid).ok());
    Peer {
        pid: process.pid,
        executable: OsSystem.executable(process.pid).ok(),
        parent,
    }
}

fn file_name(path: &Option<PathBuf>) -> Option<String> {
    path.as_deref()?
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

/// Who's asking, as the person knows it: `ssh`, or `ssh (started by git)`.
fn program(peer: &Peer, language: Language) -> String {
    let name = file_name(&peer.executable).unwrap_or_else(|| match language {
        Language::English => "a program".to_owned(),
        Language::Arabic => "برنامج".to_owned(),
    });
    match (file_name(&peer.parent), language) {
        (Some(parent), Language::English) => format!("{name} (started by {parent})"),
        (Some(parent), Language::Arabic) => format!("{name} (شغّله {parent})"),
        (None, _) => name,
    }
}

/// The approval's sentence. The system's prompt continues "Octa Pass is trying to …" in English.
/// What the data claims comes from the program asking, which is why the program is named too.
fn approval_text(title: &str, purpose: &Purpose, who: &str, language: Language) -> String {
    match (purpose, language) {
        (Purpose::Login { user }, Language::English) => {
            format!("use the SSH key “{title}” to log in as {user}, for {who}")
        }
        (Purpose::Signature { namespace }, Language::English) => {
            format!("use the SSH key “{title}” to sign for {namespace}, for {who}")
        }
        (Purpose::Unknown, Language::English) => {
            format!("use the SSH key “{title}”, for {who}")
        }
        (Purpose::Login { user }, Language::Arabic) => {
            format!("استخدام مفتاح SSH «{title}» لتسجيل الدخول باسم {user}، بطلب من {who}")
        }
        (Purpose::Signature { namespace }, Language::Arabic) => {
            format!("استخدام مفتاح SSH «{title}» للتوقيع لصالح {namespace}، بطلب من {who}")
        }
        (Purpose::Unknown, Language::Arabic) => {
            format!("استخدام مفتاح SSH «{title}»، بطلب من {who}")
        }
    }
}

fn dialog_words(language: Language) -> (&'static str, &'static str, &'static str) {
    match language {
        Language::English => ("SSH key request", "Allow", "Deny"),
        Language::Arabic => ("طلب مفتاح SSH", "سماح", "رفض"),
    }
}

struct AppBackend {
    vault: Arc<Vault>,
    app: AppHandle,
    serving: Arc<AtomicBool>,
    /// One prompt at a time, and when an unlock was last cancelled.
    prompt: tokio::sync::Mutex<Option<Instant>>,
}

impl AppBackend {
    /// The vault is open, or the user just opened it.
    async fn ready(&self) -> bool {
        if !self.serving.load(Ordering::SeqCst) {
            return false;
        }
        if self.vault.snapshot().session.status == SessionStatus::Unlocked {
            return true;
        }
        let mut cancelled = self.prompt.lock().await;
        if self.vault.snapshot().session.status == SessionStatus::Unlocked {
            return true;
        }
        if cancelled.is_some_and(|at| at.elapsed() < QUIET_AFTER_CANCEL) {
            return false;
        }
        match self.vault.ssh_agent_unlock().await {
            Ok(()) => true,
            Err(error) => {
                // The master password, or no device unlock: only the window can do that.
                if error.code != ErrorCode::DeviceUnlockCancelled {
                    crate::show_main(&self.app);
                }
                *cancelled = Some(Instant::now());
                false
            }
        }
    }

    async fn approve(&self, key: &AgentKey, purpose: &Purpose, peer: &Peer) -> bool {
        let language = menu::current_language(&self.app);
        let text = approval_text(&key.title, purpose, &program(peer, language), language);
        let _one_at_a_time = self.prompt.lock().await;
        match self.vault.approve_with_device(text.clone()).await {
            Ok(true) => true,
            Ok(false) => self.approve_in_window(text, language).await,
            Err(_) => false,
        }
    }

    /// For a device with no lock to ask.
    async fn approve_in_window(&self, text: String, language: Language) -> bool {
        let (title, allow, deny) = dialog_words(language);
        let app = self.app.clone();
        tauri::async_runtime::spawn_blocking(move || {
            app.dialog()
                .message(text)
                .title(title)
                .buttons(MessageDialogButtons::OkCancelCustom(
                    allow.to_owned(),
                    deny.to_owned(),
                ))
                .blocking_show()
        })
        .await
        .unwrap_or(false)
    }
}

impl Backend for AppBackend {
    async fn identities(&self, _peer: &Peer) -> Vec<Identity> {
        if !self.ready().await {
            return Vec::new();
        }
        self.vault
            .ssh_agent_keys()
            .unwrap_or_default()
            .into_iter()
            .map(|key| Identity {
                blob: key.blob,
                comment: if key.comment.is_empty() {
                    key.title
                } else {
                    key.comment
                },
            })
            .collect()
    }

    async fn sign(&self, peer: &Peer, blob: Vec<u8>, data: Vec<u8>, flags: u32) -> Option<Vec<u8>> {
        if !self.ready().await {
            return None;
        }
        let keys = self.vault.ssh_agent_keys().ok()?;
        let key = keys.into_iter().find(|key| key.blob == blob)?;
        if !self.approve(&key, &wire::purpose(&data), peer).await {
            return None;
        }
        self.vault.ssh_agent_sign(&blob, data, flags).await.ok()
    }
}

fn failure(message: impl ToString) -> VaultError {
    VaultError::unexpected(message.to_string())
}

// ---------- The key operations ----------

#[tauri::command]
pub async fn ssh_generate(kind: SshKeyKind, comment: String) -> Result<SshKey> {
    tauri::async_runtime::spawn_blocking(move || {
        ssh::generate(kind, &comment, &mut OsRng).map_err(VaultError::from)
    })
    .await
    .map_err(failure)?
}

#[tauri::command]
pub fn ssh_read(text: String, passphrase: Option<String>) -> Result<SshKey> {
    let text = Zeroizing::new(text);
    let passphrase = passphrase.map(Zeroizing::new);
    Ok(ssh::read_private_key(
        &text,
        passphrase.as_deref().map(String::as_str),
    )?)
}

#[tauri::command]
pub fn ssh_write(
    private_key: String,
    comment: String,
    passphrase: Option<String>,
) -> Result<String> {
    let private_key = Zeroizing::new(private_key);
    let passphrase = passphrase.map(Zeroizing::new);
    let text = ssh::write_private_key(
        &private_key,
        &comment,
        passphrase.as_deref().map(String::as_str),
        &mut OsRng,
    )?;
    Ok(text.to_string())
}

// ---------- The agent ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferedKey {
    title: String,
    fingerprint: String,
    key_type: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatus {
    enabled: bool,
    running: bool,
    endpoint: Option<String>,
    /// `~/.ssh/config` points at the agent.
    config_connected: bool,
    error: Option<String>,
    /// Empty while locked.
    keys: Vec<OfferedKey>,
    windows: bool,
}

fn status_of(state: &SshState) -> AgentStatus {
    let keys = state.vault.ssh_agent_keys().unwrap_or_default();
    let error = state.error.lock().unwrap().clone();
    AgentStatus {
        enabled: state.settings().enabled,
        running: state.task.lock().unwrap().is_some() && error.is_none(),
        endpoint: server::endpoint().map(|path| path.display().to_string()),
        config_connected: home::ssh_dir().is_some_and(|dir| home::config_connected(&dir)),
        error,
        keys: keys
            .into_iter()
            .map(|key| OfferedKey {
                title: key.title,
                fingerprint: key.fingerprint,
                key_type: key.key_type,
            })
            .collect(),
        windows: cfg!(windows),
    }
}

#[tauri::command]
pub fn ssh_agent_status(state: State<'_, SshState>) -> AgentStatus {
    status_of(&state)
}

#[tauri::command]
pub fn ssh_agent_set_enabled(state: State<'_, SshState>, enabled: bool) -> Result<AgentStatus> {
    let bytes = serde_json::to_vec(&Settings { enabled }).map_err(failure)?;
    std::fs::write(&state.settings_path, bytes).map_err(failure)?;
    if enabled {
        state.start();
    } else {
        state.stop();
    }
    Ok(status_of(&state))
}

fn ssh_dir() -> Result<PathBuf> {
    home::ssh_dir().ok_or_else(|| failure("This user has no home folder."))
}

#[tauri::command]
pub fn ssh_config_connect(state: State<'_, SshState>) -> Result<AgentStatus> {
    let socket = server::endpoint().ok_or_else(|| failure("This user has no home folder."))?;
    home::connect_config(&ssh_dir()?, &socket).map_err(failure)?;
    Ok(status_of(&state))
}

#[tauri::command]
pub fn ssh_config_disconnect(state: State<'_, SshState>) -> Result<AgentStatus> {
    home::disconnect_config(&ssh_dir()?).map_err(failure)?;
    Ok(status_of(&state))
}

// ---------- ~/.ssh ----------

#[tauri::command]
pub fn ssh_home_scan() -> Result<Vec<FoundKey>> {
    Ok(home::scan(&ssh_dir()?))
}

/// Only a file directly in `~/.ssh`: the window names keys [`ssh_home_scan`] found.
#[tauri::command]
pub fn ssh_home_read(name: String, passphrase: Option<String>) -> Result<SshKey> {
    if Path::new(&name).file_name().and_then(|file| file.to_str()) != Some(name.as_str()) {
        return Err(ErrorCode::InvalidSshKey.into());
    }
    let passphrase = passphrase.map(Zeroizing::new);
    Ok(home::read(
        &ssh_dir()?.join(&name),
        passphrase.as_deref().map(String::as_str),
    )?)
}

/// Writes an item's key to `~/.ssh`. The window has confirmed it's the user, as for showing the
/// private key (plan 16 §6). Comes from the vault, not the window.
#[tauri::command]
pub fn ssh_home_write(
    state: State<'_, SshState>,
    item_id: String,
    name: String,
    passphrase: Option<String>,
    replace: bool,
) -> Result<String> {
    let item = state.vault.get_item(&item_id)?;
    let private_key = item.detail("privateKey").ok_or(ErrorCode::NotFound)?;
    let comment = item.detail("comment").unwrap_or_default();
    let public = item.detail("publicKey").unwrap_or_default();
    let passphrase = passphrase
        .filter(|passphrase| !passphrase.is_empty())
        .map(Zeroizing::new);
    let text = ssh::write_private_key(
        private_key,
        comment,
        passphrase.as_deref().map(String::as_str),
        &mut OsRng,
    )?;
    let line = ssh::authorized_keys_line(public, comment);
    match home::write(&ssh_dir()?, &name, &text, &line, replace) {
        Ok(path) => Ok(path.display().to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(ErrorCode::AlreadyExists.into())
        }
        Err(error) => Err(failure(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_name_the_key_the_purpose_and_the_program() {
        let peer = Peer {
            pid: 1,
            executable: Some("/usr/bin/ssh".into()),
            parent: Some("/usr/bin/git".into()),
        };
        let who = program(&peer, Language::English);
        assert_eq!(who, "ssh (started by git)");
        assert_eq!(
            approval_text(
                "GitHub",
                &Purpose::Login { user: "git".into() },
                &who,
                Language::English
            ),
            "use the SSH key “GitHub” to log in as git, for ssh (started by git)"
        );
        assert_eq!(
            approval_text(
                "GitHub",
                &Purpose::Signature {
                    namespace: "git".into()
                },
                "ssh-keygen",
                Language::English
            ),
            "use the SSH key “GitHub” to sign for git, for ssh-keygen"
        );
        assert!(
            approval_text("GitHub", &Purpose::Unknown, "x", Language::Arabic).contains("مفتاح SSH")
        );
        assert_eq!(program(&Peer::default(), Language::English), "a program");
    }
}
