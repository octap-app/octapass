//! The SSH agent (plans 05 and 16), as the Tauri app's `src-tauri/src/ssh.rs` and
//! `octapass_desktop_vault::ssh_agent` run it. The protocol and the listener are
//! `octapass-ssh-agent`'s, unchanged; this answers it from the vault.
//!
//! It offers the vault's usable keys while unlocked, and every signature asks the device lock,
//! naming the key and the program. A Mac with no lock to ask gets the app's own Allow / Deny
//! window instead ([`SshPrompts::approve`]). While locked, a request opens the device unlock
//! prompt; if that's cancelled the agent stays quiet for a minute, so tools that poll it don't
//! nag. Private keys stay in the vault and are read for the length of one signature.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use octapass_core::tools::ssh;
use octapass_native_host::system::{self, OsSystem};
use octapass_native_host::trust::System;
use octapass_ssh_agent::wire::{self, Purpose};
use octapass_ssh_agent::{Backend, Identity, Peer, server};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};
use crate::model::{Item, SessionStatus};
use crate::vault::Vault;

/// How long a cancelled unlock keeps the agent quiet.
const QUIET_AFTER_CANCEL: Duration = Duration::from_secs(60);

/// A key the agent offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentKey {
    pub item_id: String,
    pub title: String,
    /// The public key's wire form: what SSH names it by.
    pub blob: Vec<u8>,
    pub comment: String,
    pub fingerprint: String,
    pub key_type: String,
}

fn agent_key(item: &Item) -> Option<AgentKey> {
    if item.overview.get("type").and_then(Value::as_str) != Some("sshKey")
        || item.details.get("sshAgent") == Some(&Value::Bool(false))
    {
        return None;
    }
    item.detail("privateKey")?;
    let public = item.detail("publicKey")?;
    let info = ssh::read_public_key(public).ok()?;
    info.usable.then_some(())?;
    Some(AgentKey {
        item_id: item.id.clone(),
        title: item.title().to_owned(),
        blob: ssh::public_key_blob(public).ok()?,
        comment: item.detail("comment").unwrap_or_default().to_owned(),
        fingerprint: info.fingerprint,
        key_type: info.key_type,
    })
}

impl Vault {
    /// The keys to offer, by title. Fails with `locked` while locked: the agent asks then.
    pub fn ssh_agent_keys(&self) -> Result<Vec<AgentKey>> {
        let mut keys: Vec<AgentKey> = self.live_items()?.iter().filter_map(agent_key).collect();
        keys.sort_by(|a, b| {
            a.title
                .to_lowercase()
                .cmp(&b.title.to_lowercase())
                .then_with(|| a.item_id.cmp(&b.item_id))
        });
        Ok(keys)
    }

    /// Signs `data` with the key `blob` names. The caller has the user's approval. Returns the
    /// signature in SSH's wire form.
    pub fn ssh_agent_sign(&self, blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        let item = self
            .live_items()?
            .into_iter()
            .find(|item| agent_key(item).is_some_and(|key| key.blob == blob))
            .ok_or(ErrorCode::NotFound)?;
        let private_key = item
            .detail("privateKey")
            .map(|key| Zeroizing::new(key.to_owned()))
            .ok_or(ErrorCode::NotFound)?;
        ssh::sign(&private_key, data, flags).map_err(|error| {
            crate::error::VaultError::from(octapass_ffi::OctaPassError::from(error))
        })
    }

    /// Asks the device lock to approve something. `Ok(false)` when the Mac has no lock to ask:
    /// the app then asks in a window of its own.
    pub fn approve_with_device(&self, reason: &str) -> Result<bool> {
        if !self.unlock_methods().device_unlock_supported {
            return Ok(false);
        }
        self.verify_user(reason)?;
        Ok(true)
    }
}

/// The language of the agent's prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    Arabic,
}

/// What the agent needs from the app's UI.
pub trait SshPrompts: Send + Sync + 'static {
    /// The app's own Allow / Deny window, for a Mac with no lock to ask. `text` is the
    /// approval's sentence ([`approval_text`]). `true` allows.
    fn approve(&self, text: &str) -> bool;
    /// A request came while locked and only the window can unlock (the master password, or no
    /// device unlock): bring it forward.
    fn show_unlock(&self);
    fn language(&self) -> Language;
}

fn file_name(path: &Option<PathBuf>) -> Option<String> {
    path.as_deref()?
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

/// Who's asking, as the person knows it: `ssh`, or `ssh (started by git)`.
pub fn program(peer: &Peer, language: Language) -> String {
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
pub fn approval_text(title: &str, purpose: &Purpose, who: &str, language: Language) -> String {
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

/// Runs a vault call off the agent's async threads: they block (decryption, RSA, prompts).
async fn blocking<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(run).await.ok()
}

struct AgentBackend<P> {
    vault: Arc<Vault>,
    prompts: Arc<P>,
    /// In-flight connections outlive the listener: they check this.
    serving: Arc<AtomicBool>,
    /// One prompt at a time, and when an unlock was last cancelled.
    prompt: tokio::sync::Mutex<Option<Instant>>,
}

impl<P: SshPrompts> AgentBackend<P> {
    fn unlocked(&self) -> bool {
        self.vault.snapshot().session.status == SessionStatus::Unlocked
    }

    /// The vault is open, or the user just opened it.
    async fn ready(&self) -> bool {
        if !self.serving.load(Ordering::SeqCst) {
            return false;
        }
        if self.unlocked() {
            return true;
        }
        let mut cancelled = self.prompt.lock().await;
        if self.unlocked() {
            return true;
        }
        if cancelled.is_some_and(|at| at.elapsed() < QUIET_AFTER_CANCEL) {
            return false;
        }
        let vault = Arc::clone(&self.vault);
        match blocking(move || vault.unlock_with_device_if_locked()).await {
            Some(Ok(())) => true,
            Some(Err(error)) => {
                // The master password, or no device unlock: only the window can do that.
                if error.code != ErrorCode::DeviceUnlockCancelled {
                    self.prompts.show_unlock();
                }
                *cancelled = Some(Instant::now());
                false
            }
            None => false,
        }
    }

    async fn approve(&self, key: &AgentKey, purpose: &Purpose, peer: &Peer) -> bool {
        let language = self.prompts.language();
        let text = approval_text(&key.title, purpose, &program(peer, language), language);
        let _one_at_a_time = self.prompt.lock().await;
        let (vault, prompts) = (Arc::clone(&self.vault), Arc::clone(&self.prompts));
        blocking(move || match vault.approve_with_device(&text) {
            Ok(true) => true,
            Ok(false) => prompts.approve(&text),
            Err(_) => false,
        })
        .await
        .unwrap_or(false)
    }

    async fn keys(&self) -> Vec<AgentKey> {
        let vault = Arc::clone(&self.vault);
        blocking(move || vault.ssh_agent_keys().unwrap_or_default())
            .await
            .unwrap_or_default()
    }
}

impl<P: SshPrompts> Backend for AgentBackend<P> {
    async fn identities(&self, _peer: &Peer) -> Vec<Identity> {
        if !self.ready().await {
            return Vec::new();
        }
        self.keys()
            .await
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
        let key = self.keys().await.into_iter().find(|key| key.blob == blob)?;
        if !self.approve(&key, &wire::purpose(&data), peer).await {
            return None;
        }
        let vault = Arc::clone(&self.vault);
        blocking(move || vault.ssh_agent_sign(&blob, &data, flags).ok())
            .await
            .flatten()
    }
}

/// Who connected: the program, and the one that started it.
fn peer_of(stream: &tokio::net::UnixStream) -> Peer {
    let Ok(process) = system::peer(stream) else {
        return Peer::default();
    };
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

/// Where `IdentityAgent` and `SSH_AUTH_SOCK` point (`~/.octapass/agent.sock`), as for the
/// Tauri app.
pub fn endpoint() -> Option<PathBuf> {
    server::endpoint()
}

/// The running agent. Stopping (or dropping) it closes the socket.
pub struct SshAgent {
    endpoint: PathBuf,
    serving: Arc<AtomicBool>,
    runtime: Option<tokio::runtime::Runtime>,
    /// Why the agent stopped, for Settings.
    error: Arc<Mutex<Option<String>>>,
}

impl SshAgent {
    /// Starts the agent on `endpoint` (normally [`endpoint`]).
    pub fn start<P: SshPrompts>(
        vault: Arc<Vault>,
        prompts: Arc<P>,
        endpoint: PathBuf,
    ) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("octapass-ssh-agent")
            .enable_io()
            .build()?;
        let serving = Arc::new(AtomicBool::new(true));
        let error = Arc::new(Mutex::new(None));
        let backend = Arc::new(AgentBackend {
            vault,
            prompts,
            serving: Arc::clone(&serving),
            prompt: tokio::sync::Mutex::new(None),
        });
        let (path, failed) = (endpoint.clone(), Arc::clone(&error));
        runtime.spawn(async move {
            if let Err(failure) = server::serve(backend, path, peer_of).await {
                eprintln!("SSH agent stopped: {failure}");
                *failed.lock().unwrap_or_else(|e| e.into_inner()) = Some(failure.to_string());
            }
        });
        Ok(Self {
            endpoint,
            serving,
            runtime: Some(runtime),
            error,
        })
    }

    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Why it isn't answering, if it stopped by itself (the socket couldn't be made).
    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn stop(mut self) {
        self.shut_down();
    }

    fn shut_down(&mut self) {
        self.serving.store(false, Ordering::SeqCst);
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
            server::remove(&self.endpoint);
        }
    }
}

impl Drop for SshAgent {
    fn drop(&mut self) {
        self.shut_down();
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
