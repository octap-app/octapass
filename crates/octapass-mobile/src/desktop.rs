//! The desktop services (plan 19, phase 3), for the Mac app: the browser extension's bridge
//! (native messaging through the bundled `octapass-native-host`), the CLI's session and the SSH
//! agent. Each listens on a socket in the app's App Group container and answers from the open
//! vault in Rust (`octapass_mobile_vault::desktop`); keys and secrets never reach Swift.
//!
//! The API is the same on every platform, since the generated bindings check every export when
//! they load. Only the Mac's library has the services: elsewhere the calls fail with
//! `deviceUnlockUnsupported`, and the phones never make them.

use std::sync::{Arc, Mutex};

use crate::error::{ErrorCode, Result, VaultError};
use crate::vault::OctaPassVault;

/// The browser bridge or the CLI session, listening until `stop` (or until it's dropped).
#[derive(uniffi::Object)]
pub struct DesktopService {
    endpoint: String,
    #[cfg(target_os = "macos")]
    service: Mutex<Option<octapass_mobile_vault::desktop::Service>>,
    #[cfg(not(target_os = "macos"))]
    service: Mutex<Option<()>>,
}

#[uniffi::export]
impl DesktopService {
    /// The socket it listens on.
    pub fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    /// Stops listening and removes the socket. Requests being answered finish.
    pub fn stop(&self) {
        let service = self
            .service
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        #[cfg(target_os = "macos")]
        if let Some(service) = service {
            service.stop();
        }
        #[cfg(not(target_os = "macos"))]
        drop(service);
    }
}

/// The running SSH agent. Stops when `stop` is called or it's dropped.
#[derive(uniffi::Object)]
pub struct SshAgentHandle {
    endpoint: String,
    #[cfg(target_os = "macos")]
    agent: Mutex<Option<octapass_mobile_vault::desktop::ssh_agent::SshAgent>>,
    #[cfg(not(target_os = "macos"))]
    agent: Mutex<Option<()>>,
}

#[uniffi::export]
impl SshAgentHandle {
    /// What `IdentityAgent` and `SSH_AUTH_SOCK` point to.
    pub fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    /// Why the agent isn't answering, when it stopped by itself (its socket couldn't be made).
    pub fn error(&self) -> Option<String> {
        #[cfg(target_os = "macos")]
        {
            self.agent
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .and_then(|agent| agent.error())
        }
        #[cfg(not(target_os = "macos"))]
        None
    }

    /// Stops the agent and removes its socket.
    pub fn stop(&self) {
        let agent = self.agent.lock().unwrap_or_else(|p| p.into_inner()).take();
        #[cfg(target_os = "macos")]
        if let Some(agent) = agent {
            agent.stop();
        }
        #[cfg(not(target_os = "macos"))]
        drop(agent);
    }
}

/// The language of the SSH agent's prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SshLanguage {
    English,
    Arabic,
}

/// What the SSH agent needs from the app's UI. Called on the agent's threads, never the main
/// one, so `approve` may wait for the person.
#[uniffi::export(with_foreign)]
pub trait SshPromptsCallback: Send + Sync {
    /// The app's own Allow / Deny window, for a Mac with no lock to ask (no password, no Touch
    /// ID). `text` is the request ("use the SSH key “GitHub” to log in as git, for ssh"); true
    /// allows. Every other Mac asks with Touch ID or its password instead (`verifyUser`).
    fn approve(&self, text: String) -> bool;
    /// A request came while locked and only the window can unlock (the master password): bring
    /// it forward.
    fn show_unlock(&self);
    fn language(&self) -> SshLanguage;
}

/// A key the SSH agent offers, for Settings. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SshAgentKey {
    pub item_id: String,
    pub title: String,
    pub fingerprint: String,
    /// `ssh-ed25519`, `ssh-rsa`, …
    pub key_type: String,
    pub comment: String,
}

#[cfg(not(target_os = "macos"))]
fn unsupported<T>() -> Result<T> {
    Err(VaultError::new(
        ErrorCode::DeviceUnlockUnsupported,
        "the desktop services run in the Mac app only",
    ))
}

#[cfg(target_os = "macos")]
fn failed(what: &str, error: impl std::fmt::Display) -> VaultError {
    VaultError::new(ErrorCode::Unexpected, format!("{what}: {error}"))
}

#[cfg(target_os = "macos")]
struct Prompts(Arc<dyn SshPromptsCallback>);

#[cfg(target_os = "macos")]
impl octapass_mobile_vault::desktop::ssh_agent::SshPrompts for Prompts {
    fn approve(&self, text: &str) -> bool {
        self.0.approve(text.to_owned())
    }

    fn show_unlock(&self) {
        self.0.show_unlock();
    }

    fn language(&self) -> octapass_mobile_vault::desktop::ssh_agent::Language {
        use octapass_mobile_vault::desktop::ssh_agent::Language;
        match self.0.language() {
            SshLanguage::English => Language::English,
            SshLanguage::Arabic => Language::Arabic,
        }
    }
}

#[uniffi::export]
impl OctaPassVault {
    /// Serves the browser extension (plan 13) on `native-host.sock` in `data_dir` (the App Group
    /// container), answering only `host_path`, the `octapass-native-host` in the app's bundle,
    /// started by a known browser; in a release build only when it's signed by the app's own
    /// team. `development` also answers the development extension: true in the app's debug
    /// builds only. Works while locked: the extension can ask to unlock with Touch ID.
    pub fn start_browser_bridge(
        &self,
        data_dir: String,
        host_path: String,
        development: bool,
    ) -> Result<Arc<DesktopService>> {
        #[cfg(target_os = "macos")]
        {
            use octapass_mobile_vault::desktop::bridge;
            let host = std::path::Path::new(&host_path);
            if !host.is_file() {
                return Err(failed("browser bridge", format!("{host_path} is missing")));
            }
            let endpoint = bridge::endpoint(std::path::Path::new(&data_dir));
            let service = bridge::start_with(
                Arc::clone(&self.vault),
                endpoint.clone(),
                bridge::host_check(host),
                development,
            )
            .map_err(|error| failed("browser bridge", error))?;
            Ok(Arc::new(DesktopService {
                endpoint: endpoint.to_string_lossy().into_owned(),
                service: Mutex::new(Some(service)),
            }))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (data_dir, host_path, development);
            unsupported()
        }
    }

    /// Serves the `octapass` CLI (plan 05) on `cli.sock` in `data_dir`: the first request from a
    /// terminal asks for Touch ID or the Mac's password, naming the program, and the approval lasts
    /// for that program in that terminal until it's idle for 30 minutes or the vault locks.
    pub fn start_cli_session(&self, data_dir: String) -> Result<Arc<DesktopService>> {
        #[cfg(target_os = "macos")]
        {
            use octapass_mobile_vault::desktop::cli_session::{self, CliGrants};
            let endpoint = cli_session::endpoint(std::path::Path::new(&data_dir));
            let service = cli_session::start(
                Arc::clone(&self.vault),
                Arc::new(CliGrants::default()),
                endpoint.clone(),
                cli_session::cli_peer,
            )
            .map_err(|error| failed("CLI session", error))?;
            Ok(Arc::new(DesktopService {
                endpoint: endpoint.to_string_lossy().into_owned(),
                service: Mutex::new(Some(service)),
            }))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = data_dir;
            unsupported()
        }
    }

    /// Starts the SSH agent (plans 05 and 16) on `endpoint`: the vault's SSH keys while unlocked,
    /// each signature asking Touch ID or the Mac's password (or `prompts.approve` on a Mac with
    /// neither). A request while locked asks to unlock. `None` is `~/.octapass/agent.sock`, which
    /// the sandboxed app can't make: the Mac app passes `agent.sock` in its App Group container.
    pub fn start_ssh_agent(
        &self,
        prompts: Arc<dyn SshPromptsCallback>,
        endpoint: Option<String>,
    ) -> Result<Arc<SshAgentHandle>> {
        #[cfg(target_os = "macos")]
        {
            use octapass_mobile_vault::desktop::ssh_agent::{self, SshAgent};
            let endpoint = endpoint
                .map(std::path::PathBuf::from)
                .or_else(ssh_agent::endpoint)
                .ok_or_else(|| failed("SSH agent", "this user has no home folder"))?;
            let agent = SshAgent::start(
                Arc::clone(&self.vault),
                Arc::new(Prompts(prompts)),
                endpoint.clone(),
            )
            .map_err(|error| failed("SSH agent", error))?;
            Ok(Arc::new(SshAgentHandle {
                endpoint: endpoint.to_string_lossy().into_owned(),
                agent: Mutex::new(Some(agent)),
            }))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (prompts, endpoint);
            unsupported()
        }
    }

    /// The keys the SSH agent offers, by title. Fails with `locked` while locked.
    pub async fn ssh_agent_keys(self: Arc<Self>) -> Result<Vec<SshAgentKey>> {
        self.run(|this| {
            #[cfg(target_os = "macos")]
            {
                Ok(this
                    .vault
                    .ssh_agent_keys()?
                    .into_iter()
                    .map(|key| SshAgentKey {
                        item_id: key.item_id,
                        title: key.title,
                        fingerprint: key.fingerprint,
                        key_type: key.key_type,
                        comment: key.comment,
                    })
                    .collect())
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = this;
                unsupported()
            }
        })
        .await
    }
}

/// The browsers the extension is connected in: those with Octa Pass's native messaging manifest.
/// `data_dir` is the App Group container.
#[uniffi::export]
pub fn browser_extension_browsers(data_dir: String) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        octapass_mobile_vault::desktop::bridge::installed_manifests(std::path::Path::new(&data_dir))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = data_dir;
        Vec::new()
    }
}

/// Connects the browser extension: writes the manifest that points each browser on this Mac at
/// `host_path` (the bundled `octapass-native-host`). Returns the browsers' names; none means no
/// supported browser was found. `development` allows the development extension too.
#[uniffi::export]
pub fn connect_browser_extension(
    data_dir: String,
    host_path: String,
    development: bool,
) -> Result<Vec<String>> {
    #[cfg(target_os = "macos")]
    {
        octapass_mobile_vault::desktop::bridge::install_manifests(
            std::path::Path::new(&data_dir),
            std::path::Path::new(&host_path),
            development,
        )
        .map_err(|error| failed("browser extension", error))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (data_dir, host_path, development);
        unsupported()
    }
}

/// Disconnects it: removes the manifests. Returns the browsers they were removed from.
#[uniffi::export]
pub fn disconnect_browser_extension(data_dir: String) -> Result<Vec<String>> {
    #[cfg(target_os = "macos")]
    {
        octapass_mobile_vault::desktop::bridge::uninstall_manifests(std::path::Path::new(&data_dir))
            .map_err(|error| failed("browser extension", error))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = data_dir;
        unsupported()
    }
}
