//! The `octapass` command-line tool. It runs the desktop app's vault (`octapass-desktop-vault`:
//! the core, sync with the server and the encrypted local copy) in a short-lived process, and
//! keeps an unlocked session between commands in the OS keyring (see [`session`]).
//!
//! [`run`] takes everything from the outside world through a [`Context`], so the end-to-end tests
//! drive the real commands against a real server with an in-memory keyring.

pub mod cli;
mod connect_commands;
mod env_commands;
pub mod env_file;
pub mod environments;
pub mod error;
pub mod export;
mod file_commands;
mod git;
mod gpg;
mod integrations;
mod item_commands;
pub mod items;
pub mod masking;
mod oauth_commands;
mod org_commands;
mod service_commands;
pub mod session;
mod ssh;
mod tools;
pub mod tools_cli;

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use clap::Parser;
use octapass_api::{DeviceInfo, VaultRole, VaultType};
use octapass_core::Error as CoreError;
use octapass_core::export::EXPORT_KDF;
use octapass_core::import::{ExistingItem, ExistingLogin, ImportOptions, import_file};
use octapass_core::tools::generator::{
    GeneratorOptions, PassphraseOptions, RandomOptions, generate,
};
use octapass_desktop_vault::api::Api;
use octapass_desktop_vault::cli_session::{self, AppUnlock};
use octapass_desktop_vault::model::{
    Item, ItemDraft, ItemSummary, SessionStatus, SignInResult, TwoStepMethod, TwoStepProof, now,
    rfc3339,
};
use octapass_desktop_vault::service_account::ServiceSession;
use octapass_desktop_vault::store::Store;
use octapass_desktop_vault::vault::{FileExport, document};
use octapass_desktop_vault::{Config, ErrorCode, Vault};
use rand_core::OsRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cli::{Cli, Command, ExportFormat, GenerateArgs, Global, ImportFormat};
use crate::error::{CliError, Exit, Result};
use crate::items::{Field, Reference};
use crate::masking::Masker;
use crate::session::{Clock, DEFAULT_IDLE, KeyringUnlock, OsKeyring, SecretStore};

/// The hosted service, as in `packages/vault-client/src/serverUrl.ts`.
pub const HOSTED_SERVER_URL: &str = "https://vault.octap.app";
pub const DATA_DIR_ENV: &str = "OCTAPASS_CLI_DATA_DIR";
pub const NO_KEYRING_ENV: &str = "OCTAPASS_NO_KEYRING";
/// A service account token: commands that read work from it alone, with no sign-in or keyring.
pub const SERVICE_TOKEN_ENV: &str = "OCTAPASS_SERVICE_ACCOUNT_TOKEN";
pub const NO_DESKTOP_ENV: &str = "OCTAPASS_NO_DESKTOP";
/// The desktop app's own data folder: the same names as `octapass_native_host::ipc`.
const DESKTOP_DATA_DIR_ENV: &str = "OCTAPASS_DESKTOP_DATA_DIR";
#[cfg(not(target_os = "macos"))]
const DESKTOP_APP_IDENTIFIER: &str = "app.octap.desktop";
/// The app's socket for the CLI, in its data folder.
#[cfg(target_os = "macos")]
const DESKTOP_CLI_SOCKET: &str = "cli.sock";
const APP_IDENTIFIER: &str = "com.octapass.cli";
const PWNED_PASSWORDS_URL: &str = "https://api.pwnedpasswords.com";
/// zxcvbn's "strong", as in the web vault's sign-up.
const MIN_PASSWORD_SCORE: u8 = 3;

/// Where the desktop app keeps its sockets. On macOS that's the native Mac app's App Group
/// container (plan 19), `~/Library/Group Containers/<team>.app.octap`: the CLI doesn't know the
/// team that signed the app, so it's the container that has the socket.
#[cfg(target_os = "macos")]
fn desktop_data_dir() -> Option<PathBuf> {
    octapass_native_host::ipc::app_group_container(DESKTOP_CLI_SOCKET, None)
}

#[cfg(not(target_os = "macos"))]
fn desktop_data_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|dir| dir.join(DESKTOP_APP_IDENTIFIER))
}

/// The app's socket for the CLI. The sandboxed Mac app's is always in its container: its temporary
/// folder is its own, so the short path elsewhere (`cli_session::endpoint`) wouldn't reach it.
#[cfg(target_os = "macos")]
fn desktop_endpoint(dir: &std::path::Path) -> PathBuf {
    dir.join(DESKTOP_CLI_SOCKET)
}

#[cfg(not(target_os = "macos"))]
fn desktop_endpoint(dir: &std::path::Path) -> PathBuf {
    cli_session::endpoint(dir)
}

/// Someone to ask for input, when there is one.
pub trait Terminal: Send {
    fn interactive(&self) -> bool;
    fn ask(&mut self, prompt: &str) -> io::Result<String>;
    fn ask_hidden(&mut self, prompt: &str) -> io::Result<Zeroizing<String>>;
    /// A terminal can be reached even if stdin isn't one (`git` starts its helpers with a pipe);
    /// `ask_hidden` uses it.
    fn has_tty(&self) -> bool {
        self.interactive()
    }
}

/// The keyring to keep sessions in, if any. Called only by commands that open the vault.
pub type KeyringFactory = Box<dyn Fn() -> Option<Arc<dyn SecretStore>> + Send>;
/// Runs `octapass run`'s command and returns its exit code. The real one replaces this process
/// on Unix, so it only returns on failure.
pub type Exec = Box<dyn FnOnce(Process) -> io::Result<i32> + Send>;

/// Everything a command reads from or writes to the outside world.
pub struct Context {
    pub data_dir: PathBuf,
    pub keyring: KeyringFactory,
    pub clock: Clock,
    /// The environment the command started with (`octapass run` passes it on).
    pub env: Vec<(OsString, OsString)>,
    /// The current folder, where `octapass.toml` is looked for.
    pub cwd: PathBuf,
    pub stdin: Box<dyn BufRead + Send>,
    pub stdout: Box<dyn Write + Send>,
    pub stderr: Box<dyn Write + Send>,
    pub stdout_is_terminal: bool,
    pub terminal: Box<dyn Terminal>,
    pub exec: Exec,
    /// Where a running desktop app answers, if one may be asked (plan 05).
    pub desktop_app: Option<PathBuf>,
}

impl Context {
    /// This process's real terminal, environment and keyring.
    pub fn system() -> std::result::Result<Self, String> {
        let env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        let var = |name: &str| {
            env.iter()
                .find(|(key, _)| key == name)
                .and_then(|(_, value)| value.to_str())
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let data_dir = match var(DATA_DIR_ENV) {
            Some(dir) => PathBuf::from(dir),
            None => dirs::data_dir()
                .ok_or("this user has no data folder; set OCTAPASS_CLI_DATA_DIR")?
                .join(APP_IDENTIFIER),
        };
        let no_keyring = var(NO_KEYRING_ENV).is_some_and(|value| value != "0");
        let desktop_app = (!var(NO_DESKTOP_ENV).is_some_and(|value| value != "0"))
            .then(|| {
                var(DESKTOP_DATA_DIR_ENV)
                    .map(PathBuf::from)
                    .or_else(desktop_data_dir)
            })
            .flatten()
            .map(|dir| desktop_endpoint(&dir));
        Ok(Self {
            data_dir,
            keyring: Box::new(move || {
                if no_keyring {
                    return None;
                }
                OsKeyring::open().map(|keyring| Arc::new(keyring) as Arc<dyn SecretStore>)
            }),
            clock: session::system_clock(),
            env,
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            stdin: Box::new(io::BufReader::new(io::stdin())),
            stdout: Box::new(io::stdout()),
            stderr: Box::new(io::stderr()),
            stdout_is_terminal: io::stdout().is_terminal(),
            terminal: Box::new(SystemTerminal),
            exec: Box::new(exec),
            desktop_app,
        })
    }

    fn var(&self, name: &str) -> Option<String> {
        self.env
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| value.to_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    }
}

struct SystemTerminal;

impl Terminal for SystemTerminal {
    fn interactive(&self) -> bool {
        io::stdin().is_terminal()
    }

    fn ask(&mut self, prompt: &str) -> io::Result<String> {
        eprint!("{prompt}");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        Ok(line.trim().to_owned())
    }

    fn ask_hidden(&mut self, prompt: &str) -> io::Result<Zeroizing<String>> {
        rpassword::prompt_password(prompt).map(Zeroizing::new)
    }

    #[cfg(unix)]
    fn has_tty(&self) -> bool {
        File::open("/dev/tty").is_ok()
    }

    #[cfg(not(unix))]
    fn has_tty(&self) -> bool {
        self.interactive()
    }
}

#[cfg(unix)]
fn exec(mut process: Process) -> io::Result<i32> {
    use std::os::unix::process::CommandExt;
    Err(process.exec())
}

#[cfg(not(unix))]
fn exec(mut process: Process) -> io::Result<i32> {
    spawn_and_wait(&mut process)
}

/// Starts the command and waits for it. Its exit code, or 128 + the signal that ended it.
pub fn spawn_and_wait(process: &mut Process) -> io::Result<i32> {
    exit_code(process.status()?)
}

fn exit_code(status: std::process::ExitStatus) -> io::Result<i32> {
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return Ok(128 + signal);
    }
    Ok(status.code().unwrap_or(1))
}

/// Runs one command line and returns the process exit code.
pub fn run(args: impl IntoIterator<Item = impl Into<OsString> + Clone>, context: Context) -> i32 {
    let mut context = context;
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let text = error.render().to_string();
            let _ = if error.use_stderr() {
                context.stderr.write_all(text.as_bytes())
            } else {
                context.stdout.write_all(text.as_bytes())
            };
            return error.exit_code();
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(context.stderr, "octapass: {error}");
            return Exit::Error as i32;
        }
    };
    let mut app = App::new(context, cli.global);
    let result = runtime.block_on(app.dispatch(cli.command));
    let code = match result {
        Ok(code) => code,
        Err(error) => {
            app.note(&format!("octapass: {}", error.message));
            error.exit as i32
        }
    };
    let _ = app.context.stdout.flush();
    let _ = app.context.stderr.flush();
    code
}

struct App {
    context: Context,
    global: Global,
    exec: Option<Exec>,
    /// Read from stdin once, for commands that need it twice.
    password: Option<Zeroizing<String>>,
    /// Git's helpers: stdin is Git's, but the password can still be asked on the terminal.
    ask_on_tty: bool,
}

/// The vault for one command, with the lock that keeps other `octapass` processes out until the
/// command is done (they'd present the same rotating refresh token).
struct Opened {
    vault: Arc<Vault>,
    unlock: Arc<KeyringUnlock>,
    _lock: File,
    /// Set when a service account token does the reading instead of a person's vault.
    service: OnceLock<ServiceSession>,
    /// Live OAuth2 tokens to save back into their items.
    live_saves: Mutex<Vec<oauth_commands::LiveSave>>,
}

impl Opened {
    fn account_id(&self) -> Option<String> {
        let session = self.vault.snapshot().session;
        Some(format!("{}|{}", session.server_url?, session.email?))
    }

    fn vaults(&self) -> octapass_desktop_vault::Result<Vec<octapass_desktop_vault::model::Vault>> {
        match self.service.get() {
            Some(service) => Ok(service.vaults()),
            None => self.vault.list_vaults(),
        }
    }

    fn summaries(&self) -> octapass_desktop_vault::Result<Vec<ItemSummary>> {
        match self.service.get() {
            Some(service) => Ok(service.summaries()),
            None => self.vault.list_items(),
        }
    }

    fn live_items(&self) -> octapass_desktop_vault::Result<Vec<Item>> {
        match self.service.get() {
            Some(service) => Ok(service.items().to_vec()),
            None => self.vault.live_items(),
        }
    }

    fn item(&self, id: &str) -> octapass_desktop_vault::Result<Item> {
        match self.service.get() {
            Some(service) => service.item(id),
            None => self.vault.get_item(id),
        }
    }
}

impl App {
    fn new(mut context: Context, global: Global) -> Self {
        let exec = std::mem::replace(&mut context.exec, Box::new(|_| Ok(0)));
        Self {
            context,
            global,
            exec: Some(exec),
            password: None,
            ask_on_tty: false,
        }
    }

    // ---------- Output ----------

    fn out(&mut self, text: &str) -> Result<()> {
        writeln!(self.context.stdout, "{text}").map_err(output_error)
    }

    fn out_json(&mut self, value: &Value) -> Result<()> {
        let text = serde_json::to_string_pretty(value).expect("values serialize");
        self.out(&text)
    }

    /// A message for the person, on stderr.
    fn note(&mut self, text: &str) {
        let _ = writeln!(self.context.stderr, "{text}");
    }

    /// Prints a secret the user asked for, warning first when it lands on a terminal.
    fn out_secret(&mut self, text: &str, secret: bool, newline: bool) -> Result<()> {
        if secret && self.context.stdout_is_terminal {
            self.note("Warning: showing a secret in the terminal.");
        }
        let stdout = &mut self.context.stdout;
        if newline {
            writeln!(stdout, "{text}")
        } else {
            write!(stdout, "{text}")
        }
        .map_err(output_error)
    }

    // ---------- Input ----------

    fn master_password(&mut self) -> Result<Zeroizing<String>> {
        if let Some(password) = &self.password {
            return Ok(password.clone());
        }
        let password = if self.global.password_stdin {
            let mut line = Zeroizing::new(String::new());
            self.context
                .stdin
                .read_line(&mut line)
                .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
            Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned())
        } else if self.can_ask_on_terminal() {
            self.context
                .terminal
                .ask_hidden("Master password: ")
                .map_err(input_error)?
        } else {
            return Err(CliError::locked());
        };
        if password.is_empty() {
            return Err(CliError::usage("The master password is empty."));
        }
        self.password = Some(password.clone());
        Ok(password)
    }

    /// The password of a file being imported or exported: the next line of stdin with
    /// `--password-stdin`, otherwise asked for (twice when `confirm`, for a new one).
    fn file_password(&mut self, prompt: &str, confirm: bool) -> Result<Zeroizing<String>> {
        if self.global.password_stdin {
            let mut line = Zeroizing::new(String::new());
            self.context
                .stdin
                .read_line(&mut line)
                .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
            let password = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned());
            if password.is_empty() {
                return Err(CliError::usage(
                    "With --password-stdin, put the file's password on the line after the master password.",
                ));
            }
            return Ok(password);
        }
        if !self.context.terminal.interactive() {
            return Err(CliError::usage(
                "This needs the file's password: run it in a terminal, or pass --password-stdin.",
            ));
        }
        let password = self
            .context
            .terminal
            .ask_hidden(prompt)
            .map_err(input_error)?;
        if confirm {
            let again = self
                .context
                .terminal
                .ask_hidden("Again: ")
                .map_err(input_error)?;
            if again != password {
                return Err(CliError::usage("The two passwords don't match."));
            }
        }
        Ok(password)
    }

    fn can_ask_on_terminal(&self) -> bool {
        self.context.terminal.interactive() || (self.ask_on_tty && self.context.terminal.has_tty())
    }

    fn can_ask_password(&self) -> bool {
        self.global.password_stdin || self.can_ask_on_terminal()
    }

    /// A new master password: on stdin it's the next line, otherwise asked for twice.
    fn new_master_password(&mut self) -> Result<Zeroizing<String>> {
        if self.global.password_stdin {
            let mut line = Zeroizing::new(String::new());
            self.context
                .stdin
                .read_line(&mut line)
                .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
            let password = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned());
            if password.is_empty() {
                return Err(CliError::usage(
                    "With --password-stdin, put the new master password on the next line.",
                ));
            }
            return Ok(password);
        }
        if !self.context.terminal.interactive() {
            return Err(CliError::usage(
                "This needs a new master password: run it in a terminal, or pass --password-stdin.",
            ));
        }
        let password = self
            .context
            .terminal
            .ask_hidden("New master password: ")
            .map_err(input_error)?;
        if password.is_empty() {
            return Err(CliError::usage("The new master password is empty."));
        }
        let again = self
            .context
            .terminal
            .ask_hidden("Again: ")
            .map_err(input_error)?;
        if again != password {
            return Err(CliError::usage("The two passwords don't match."));
        }
        Ok(password)
    }

    /// The recovery code from the Recovery Kit: on stdin it's the next line, otherwise asked for.
    fn recovery_code(&mut self) -> Result<Zeroizing<String>> {
        if self.global.password_stdin {
            let mut line = Zeroizing::new(String::new());
            self.context
                .stdin
                .read_line(&mut line)
                .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
            let code = Zeroizing::new(line.trim().to_owned());
            if code.is_empty() {
                return Err(CliError::usage(
                    "With --password-stdin, put the recovery code on the next line.",
                ));
            }
            return Ok(code);
        }
        if !self.context.terminal.interactive() {
            return Err(CliError::usage(
                "This needs the recovery code: run it in a terminal, or pass --password-stdin.",
            ));
        }
        let code = self
            .context
            .terminal
            .ask_hidden("Recovery code from your Recovery Kit: ")
            .map_err(input_error)?;
        if code.trim().is_empty() {
            return Err(CliError::usage("The recovery code is empty."));
        }
        Ok(Zeroizing::new(code.trim().to_owned()))
    }

    // ---------- The vault ----------

    fn open(&self, idle: Duration) -> Result<Opened> {
        self.open_with(idle, true)
    }

    /// The vault, with a keyring session that moves on with use, or doesn't (Connect).
    fn open_with(&self, idle: Duration, keep_alive: bool) -> Result<Opened> {
        let dir = &self.context.data_dir;
        create_private_dir(dir)
            .map_err(|error| CliError::other(format!("Can't use {}: {error}", dir.display())))?;
        let lock = private_file(&dir.join("cli.lock"), false)
            .and_then(|file| file.lock().map(|()| file))
            .map_err(|error| CliError::other(format!("Can't lock {}: {error}", dir.display())))?;
        // A runner has no keyring, and asking for one can hang on a headless Linux.
        let keyring = match self.service_token() {
            Some(_) => None,
            None => (self.context.keyring)(),
        };
        let unlock = KeyringUnlock::new(keyring, idle, Arc::clone(&self.context.clock));
        let unlock = Arc::new(if keep_alive {
            unlock
        } else {
            unlock.without_keep_alive()
        });
        let vault = Vault::new(
            Config {
                data_dir: dir.clone(),
                device: device_info(),
                pwned_passwords_url: PWNED_PASSWORDS_URL.into(),
            },
            unlock.clone(),
            Box::new(|_| {}),
        )?;
        Ok(Opened {
            vault,
            unlock,
            _lock: lock,
            service: OnceLock::new(),
            live_saves: Mutex::new(Vec::new()),
        })
    }

    fn service_token(&self) -> Option<String> {
        self.context.var(SERVICE_TOKEN_ENV)
    }

    /// Unlocks with the keyring session, or else the master password, then syncs. With a service
    /// account token, reads its vault instead.
    async fn unlocked(&mut self, opened: &Opened) -> Result<()> {
        if let Some(token) = self.service_token() {
            if opened.service.get().is_none() {
                let http = reqwest::Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .map_err(|error| CliError::other(error.to_string()))?;
                let session = ServiceSession::open(http, &token).await?;
                let _ = opened.service.set(session);
            }
            return Ok(());
        }
        match opened.vault.snapshot().session.status {
            SessionStatus::SignedOut => return Err(CliError::signed_out()),
            SessionStatus::Unlocked => return Ok(()),
            SessionStatus::Locked => {}
        }
        let recheck = match opened.vault.unlock_with_device().await {
            Ok(()) => return self.sync(&opened.vault).await,
            Err(error) => error.code == ErrorCode::PasswordRequired,
        };
        if self.unlock_through_app(opened).await? {
            return self.sync(&opened.vault).await;
        }
        if recheck && self.can_ask_password() {
            self.note("Enter your master password: it's needed every 14 days.");
        }
        let password = self.master_password()?;
        opened.vault.unlock(password).await?;
        self.sync(&opened.vault).await
    }

    /// Asks the running desktop app, if there is one. `false` when that doesn't open the vault, so
    /// the caller goes on to the master password; saying why, unless no app is running.
    async fn unlock_through_app(&mut self, opened: &Opened) -> Result<bool> {
        let Some(endpoint) = self.context.desktop_app.clone() else {
            return Ok(false);
        };
        match cli_session::unlock_through_app(&opened.vault, &endpoint).await? {
            AppUnlock::Unlocked => Ok(true),
            AppUnlock::NotRunning => Ok(false),
            AppUnlock::Declined { code, .. } if code == "otherAccount" => Ok(false),
            AppUnlock::Declined { message, .. } => {
                self.note(&format!("The Octa Pass app didn't unlock this: {message}"));
                Ok(false)
            }
        }
    }

    /// Pulls changes from the server. Offline, the copy on this device is used.
    async fn sync(&mut self, vault: &Vault) -> Result<()> {
        // Let the sync that unlocking started take the server session first, so a refresh is
        // never cut short when the process exits.
        tokio::task::yield_now().await;
        match vault.sync().await {
            Ok(()) => Ok(()),
            Err(error) if error.code == ErrorCode::AccountDeleted => Err(error.into()),
            Err(error) => {
                let error = CliError::from(error);
                self.note(&format!(
                    "Couldn't sync, so this is the copy saved on this device. {}",
                    error.message
                ));
                Ok(())
            }
        }
    }

    /// Starts a keyring session. `false` when there's no keyring.
    async fn keep_unlocked(&mut self, opened: &Opened) -> Result<bool> {
        if !opened.unlock.available() {
            return Ok(false);
        }
        opened.vault.enable_device_unlock().await?;
        Ok(true)
    }

    // ---------- Commands ----------

    async fn dispatch(&mut self, command: Command) -> Result<i32> {
        if self.service_token().is_some() && !command.works_with_service_account() {
            return Err(CliError::usage(format!(
                "With {SERVICE_TOKEN_ENV} set, only commands that read work: list, get, totp, read, run, inject, env list/show/export/diff, oauth token, aws, kube and docker-credential get/list."
            )));
        }
        match command {
            Command::Signup {
                server,
                email,
                code,
                timeout,
            } => self.signup(server, email, code, timeout).await,
            Command::Login {
                server,
                email,
                timeout,
            } => self.login(server, email, timeout).await,
            Command::Unlock { timeout } => self.unlock(timeout).await,
            Command::Lock => self.lock(),
            Command::Logout => self.logout().await,
            Command::Status => self.status().await,
            Command::ChangeMasterPassword => self.change_master_password().await,
            Command::RotateSecretKey { new_recovery_code } => {
                self.rotate_secret_key(new_recovery_code).await
            }
            Command::RotateVaultKey { vault } => self.rotate_vault_key(&vault).await,
            Command::ResetMasterPassword {
                server,
                email,
                code,
            } => self.reset_master_password(server, email, code).await,
            Command::List { vault, search } => self.list(vault, search).await,
            Command::Get {
                item,
                field,
                vault,
                no_newline,
            } => self.get(item, field, vault, !no_newline).await,
            Command::Totp { item, vault } => self.totp(item, vault).await,
            Command::Create(args) => self.create_item(args).await,
            Command::Edit(args) => self.edit_item(args).await,
            Command::Delete { item, vault } => self.delete_item(item, vault).await,
            Command::Restore { item } => self.restore_item(item).await,
            Command::Generate(args) => self.generate(args),
            Command::Read {
                reference,
                no_newline,
            } => self.read(reference, !no_newline).await,
            Command::Run {
                env,
                project,
                stage,
                env_file,
                env_file_out,
                yes,
                no_masking,
                command,
            } => {
                self.run_command(RunArgs {
                    env,
                    project,
                    stage,
                    env_files: env_file,
                    env_file_out,
                    yes,
                    no_masking,
                    command,
                })
                .await
            }
            Command::Env(command) => self.env_command(command).await,
            Command::Inject {
                input,
                output,
                force,
            } => self.inject(input, output, force).await,
            Command::Import {
                format,
                file,
                vault,
                key_file,
                dry_run,
            } => self.import(format, file, vault, key_file, dry_run).await,
            Command::Ssh { command } => self.ssh(command).await,
            Command::ServiceAccount(command) => self.service_account(command).await,
            Command::Org(command) => self.org(command).await,
            Command::Connect(command) => self.connect(command).await,
            Command::Aws(command) => self.aws(command).await,
            Command::Kube(command) => self.kube(command).await,
            Command::DockerCredential { operation } => self.docker_credential(operation).await,
            Command::Oauth(command) => self.oauth(command).await,
            Command::Gpg { command } => self.gpg(command).await,
            Command::Git { command } => self.git(command).await,
            Command::Tool(command) => self.tool(command).await,
            Command::Encrypt(args) => self.encrypt(args).await,
            Command::Decrypt(args) => self.decrypt(args).await,
            Command::Shred { paths, yes } => self.shred(paths, yes),
            Command::FileKey {
                export,
                output,
                force,
            } => self.file_key(export, output, force).await,
            Command::Safe { command } => self.safe(command).await,
            Command::ContextMenu { command } => self.context_menu(command),
            Command::Export {
                format,
                encrypted,
                output,
            } => self.export(format, encrypted, output).await,
        }
        .map(|code| code.unwrap_or(Exit::Ok as i32))
    }

    async fn signup(
        &mut self,
        server: Option<String>,
        email: Option<String>,
        code: Option<String>,
        timeout: Option<String>,
    ) -> Result<Option<i32>> {
        let idle = idle_timeout(timeout)?;
        let server = server
            .or_else(|| self.context.var("OCTAPASS_SERVER"))
            .unwrap_or_else(|| HOSTED_SERVER_URL.into());
        let email = match email.or_else(|| self.context.var("OCTAPASS_EMAIL")) {
            Some(email) => email,
            None if self.context.terminal.interactive() => {
                self.context.terminal.ask("Email: ").map_err(input_error)?
            }
            None => return Err(CliError::usage("Pass --email, or set OCTAPASS_EMAIL.")),
        };
        let opened = self.open(idle)?;
        if opened.vault.snapshot().session.status != SessionStatus::SignedOut {
            return Err(CliError::usage(
                "This device is signed in to an account. Run `octapass logout` first.",
            ));
        }
        let password = self.new_master_password()?;
        // The same bar as the web vault's sign-up: the Secret Key protects the server's copy, this
        // protects the device's.
        let estimate = octapass_core::tools::strength::estimate(&password, &[email.as_str()]);
        if estimate.score < MIN_PASSWORD_SCORE {
            return Err(CliError::usage(match estimate.feedback {
                Some(feedback) => format!("That master password is too weak. {feedback}"),
                None => "That master password is too weak. Try a longer passphrase.".to_owned(),
            }));
        }
        let started = opened.vault.start_signup(&server, &email, password).await?;
        let mut code = code;
        if code.is_none() {
            if let Some(dev) = &started.dev_verification_code {
                self.note(&format!("Development code: {dev}"));
            }
            code = started.dev_verification_code;
        }
        let kit = loop {
            let typed = match code.take() {
                Some(code) => code,
                None if self.context.terminal.interactive() => self
                    .context
                    .terminal
                    .ask("Code from the email: ")
                    .map_err(input_error)?,
                None => {
                    return Err(CliError::usage(
                        "Pass --code with the 6-digit code we emailed you.",
                    ));
                }
            };
            match opened.vault.finish_signup(&started.signup_id, &typed).await {
                Ok(kit) => break kit,
                Err(error)
                    if error.code == ErrorCode::InvalidVerificationCode
                        && self.context.terminal.interactive() =>
                {
                    self.note(&error.message);
                }
                Err(error) => return Err(error.into()),
            }
        };
        if self.global.json {
            if self.context.stdout_is_terminal {
                self.note("Warning: showing secrets in the terminal.");
            }
            self.out_json(&json!({ "recoveryKit": kit }))?;
        } else {
            let text = format!(
                "Your Recovery Kit (store it somewhere safe: it's the only way back into your account):\n  Email: {}\n  Server: {}\n  Secret Key: {}\n  Recovery code: {}\n  Created: {}",
                kit.email, kit.server_url, kit.secret_key, kit.recovery_code, kit.created_at
            );
            self.out_secret(&text, true, true)?;
        }
        match self.keep_unlocked(&opened).await {
            Ok(true) => self.note(&format!(
                "Signed in as {}. Unlocked until {} without a command, or `octapass lock`.",
                kit.email,
                describe_duration(idle)
            )),
            Ok(false) => self.note(&format!(
                "Signed in as {}. There's no OS keyring here, so each command asks for your master password.",
                kit.email
            )),
            Err(error) => self.note(&format!(
                "Signed in as {}, but the vault can't stay unlocked ({}).",
                kit.email, error.message
            )),
        }
        Ok(None)
    }

    async fn login(
        &mut self,
        server: Option<String>,
        email: Option<String>,
        timeout: Option<String>,
    ) -> Result<Option<i32>> {
        let idle = idle_timeout(timeout)?;
        let server = server
            .or_else(|| self.context.var("OCTAPASS_SERVER"))
            .unwrap_or_else(|| HOSTED_SERVER_URL.into());
        let email = match email.or_else(|| self.context.var("OCTAPASS_EMAIL")) {
            Some(email) => email,
            None if self.context.terminal.interactive() => {
                self.context.terminal.ask("Email: ").map_err(input_error)?
            }
            None => return Err(CliError::usage("Pass --email, or set OCTAPASS_EMAIL.")),
        };
        if !self.can_ask_password() {
            return Err(CliError::usage(
                "Pass the master password with --password-stdin.",
            ));
        }
        let opened = self.open(idle)?;
        let password = self.master_password()?;
        let mut secret_key = self.context.var("OCTAPASS_SECRET_KEY").map(Zeroizing::new);
        let signed_in = loop {
            match opened
                .vault
                .sign_in(&server, &email, password.clone(), secret_key.clone())
                .await
            {
                Err(error)
                    if error.code == ErrorCode::SecretKeyRequired
                        && secret_key.is_none()
                        && self.context.terminal.interactive() =>
                {
                    secret_key = Some(
                        self.context
                            .terminal
                            .ask_hidden("Secret Key (on your Recovery Kit): ")
                            .map_err(input_error)?,
                    );
                }
                result => break result?,
            }
        };
        let signed_in = if let SignInResult::SsoRequired { url, org_name } = signed_in {
            self.note(&format!(
                "{org_name} asks you to sign in with its identity provider. Open this address in a browser:\n{url}"
            ));
            let code = match self.context.var("OCTAPASS_SSO_CODE") {
                Some(code) => code,
                None if self.context.terminal.interactive() => self
                    .context
                    .terminal
                    .ask("Code from the sign-in page: ")
                    .map_err(input_error)?,
                None => {
                    return Err(CliError::usage(
                        "This account signs in through its organisation. Run `octapass login` in a terminal.",
                    ));
                }
            };
            opened.vault.finish_sso(&code).await?
        } else {
            signed_in
        };
        if let SignInResult::TwoStepRequired { methods } = signed_in {
            let code = match self.context.var("OCTAPASS_TWO_STEP_CODE") {
                Some(code) => Zeroizing::new(code),
                None if self.context.terminal.interactive() => {
                    let prompt = if methods.contains(&TwoStepMethod::Totp) {
                        "Code from your authenticator app, or a two-step recovery code: "
                    } else {
                        "Two-step recovery code: "
                    };
                    self.context
                        .terminal
                        .ask_hidden(prompt)
                        .map_err(input_error)?
                }
                None => {
                    return Err(CliError::usage(
                        "This account uses two-step sign-in. Set OCTAPASS_TWO_STEP_CODE to a code from your authenticator app.",
                    ));
                }
            };
            opened.vault.finish_two_step(two_step_proof(&code)).await?;
        }
        let session = opened.vault.snapshot().session;
        let who = format!(
            "Signed in as {} on {}.",
            session.email.unwrap_or_default(),
            session.server_url.unwrap_or_default()
        );
        match self.keep_unlocked(&opened).await {
            Ok(true) => self.note(&format!(
                "{who} Unlocked until {} without a command, or `octapass lock`.",
                describe_duration(idle)
            )),
            Ok(false) => self.note(&format!(
                "{who} There's no OS keyring here, so each command asks for your master password."
            )),
            Err(error) => self.note(&format!(
                "{who} Couldn't keep the vault unlocked ({}), so each command asks for your master password.",
                error.message
            )),
        }
        Ok(None)
    }

    async fn unlock(&mut self, timeout: Option<String>) -> Result<Option<i32>> {
        let new_timeout = timeout.is_some();
        let idle = idle_timeout(timeout)?;
        let opened = self.open(idle)?;
        if opened.vault.snapshot().session.status == SessionStatus::SignedOut {
            return Err(CliError::signed_out());
        }
        if !opened.unlock.available() {
            if self.unlock_through_app(&opened).await? {
                self.sync(&opened.vault).await?;
                self.note("Unlocked through the Octa Pass app. Locking the app locks this too.");
                return Ok(None);
            }
            return Err(CliError::other(
                "There's no OS keyring here, so Octa Pass can't stay unlocked. Each command asks for the master password instead, or reads it with --password-stdin.",
            ));
        }
        if opened.vault.unlock_with_device().await.is_ok() {
            if !new_timeout {
                self.sync(&opened.vault).await?;
                self.note("Already unlocked.");
                return Ok(None);
            }
            // A new session secret with the new timeout; the vault is open, so no password.
        } else if !new_timeout && self.unlock_through_app(&opened).await? {
            self.sync(&opened.vault).await?;
            self.note("Unlocked through the Octa Pass app. Locking the app locks this too.");
            return Ok(None);
        } else {
            let password = self.master_password()?;
            opened.vault.unlock(password).await?;
        }
        self.keep_unlocked(&opened).await?;
        self.sync(&opened.vault).await?;
        self.note(&format!(
            "Unlocked. Locks after {} without a command, or with `octapass lock`.",
            describe_duration(idle)
        ));
        Ok(None)
    }

    fn lock(&mut self) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        if opened.vault.snapshot().session.status == SessionStatus::SignedOut {
            self.note("Not signed in.");
            return Ok(None);
        }
        opened.vault.disable_device_unlock()?;
        if let Some(endpoint) = &self.context.desktop_app {
            cli_session::end_app_session(endpoint);
        }
        self.note("Locked.");
        Ok(None)
    }

    async fn logout(&mut self) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        let session = opened.vault.snapshot().session;
        let (Some(email), Some(server_url)) = (session.email, session.server_url) else {
            self.note("Not signed in.");
            return Ok(None);
        };
        // End the server session too. Best effort: this device forgets the account either way.
        let refresh_token = Store::new(&self.context.data_dir)
            .load_state()
            .ok()
            .and_then(|state| {
                state.accounts.into_iter().find(|account| {
                    account.key.email == email && account.key.server_url == server_url
                })
            })
            .and_then(|account| account.refresh_token);
        if let (Some(refresh_token), Ok(http)) = (
            refresh_token,
            reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build(),
        ) {
            let api = Api::new(http, &server_url);
            if let Ok(refreshed) = api.refresh(&refresh_token).await {
                let _ = api.logout(&refreshed.access_token).await;
            }
        }
        opened.vault.sign_out().await?;
        self.note(&format!(
            "Signed out of {email}. This device no longer keeps your Secret Key or vault."
        ));
        Ok(None)
    }

    async fn status(&mut self) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        let session = opened.vault.snapshot().session;
        let methods = opened.vault.unlock_methods().await;
        let locks_at = opened
            .account_id()
            .filter(|_| methods.device_unlock_enabled && !methods.password_required)
            .and_then(|account| opened.unlock.expires_at(&account));
        let through_app = match (
            &self.context.desktop_app,
            &session.email,
            &session.server_url,
        ) {
            (Some(endpoint), Some(email), Some(server)) => {
                cli_session::app_status(endpoint, email, server)
                    .is_some_and(|status| status.granted)
            }
            _ => false,
        };
        let (status, exit) = match (session.status, locks_at) {
            (SessionStatus::SignedOut, _) => ("signedOut", Exit::SignedOut),
            (_, Some(_)) => ("unlocked", Exit::Ok),
            _ if through_app => ("unlocked", Exit::Ok),
            _ => ("locked", Exit::Locked),
        };
        let locks_at = locks_at.and_then(|at| {
            time::OffsetDateTime::from_unix_timestamp(i64::try_from(at).ok()?)
                .ok()
                .map(rfc3339)
        });
        if self.global.json {
            self.out_json(&json!({
                "status": status,
                "email": session.email,
                "serverUrl": session.server_url,
                "locksAt": locks_at,
                "keyring": opened.unlock.available(),
                "desktopApp": through_app,
            }))?;
        } else {
            let account = match (&session.email, &session.server_url) {
                (Some(email), Some(server)) => format!(" as {email} on {server}"),
                _ => String::new(),
            };
            let text = match exit {
                Exit::SignedOut => "Not signed in.".to_owned(),
                Exit::Ok => match locks_at {
                    Some(at) => {
                        format!("Signed in{account}. Unlocked until {at} (UTC) unless used.")
                    }
                    None => format!("Signed in{account}. Unlocked through the Octa Pass app."),
                },
                _ => format!("Signed in{account}. Locked."),
            };
            self.out(&text)?;
        }
        Ok(Some(exit as i32))
    }

    async fn change_master_password(&mut self) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let current = self.master_password()?;
        let new = self.new_master_password()?;
        if *new == *current {
            return Err(CliError::usage(
                "The new master password is the same as the current one.",
            ));
        }
        opened.vault.change_master_password(current, new).await?;
        let session = opened.vault.snapshot().session;
        let kept = match self.keep_unlocked(&opened).await {
            Ok(kept) => kept,
            Err(error) => {
                self.note(&format!(
                    "Changed the master password, but couldn't keep this terminal unlocked ({}).",
                    error.message
                ));
                false
            }
        };
        if self.global.json {
            self.out_json(&json!({
                "changed": true,
                "email": session.email,
                "serverUrl": session.server_url,
                "unlocked": kept,
            }))?;
        } else {
            self.out("Master password changed. Your Secret Key and recovery code stay the same; every other device was signed out.")?;
            if kept {
                self.note(
                    "This terminal stays unlocked until you're idle, or run `octapass lock`.",
                );
            }
        }
        Ok(None)
    }

    async fn rotate_secret_key(&mut self, new_recovery_code: bool) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let password = self.master_password()?;
        let kit = opened
            .vault
            .rotate_secret_key(password, new_recovery_code)
            .await?;
        // The kit first: it's the only copy of the new key off this device.
        if self.global.json {
            if self.context.stdout_is_terminal {
                self.note("Warning: showing secrets in the terminal.");
            }
            self.out_json(&json!({ "recoveryKit": kit }))?;
        } else {
            let recovery = kit.recovery_code.as_deref().map_or_else(
                || "unchanged: keep using the one from your previous kit".to_owned(),
                str::to_owned,
            );
            let text = format!(
                "Your new Recovery Kit (store it somewhere safe: the old Secret Key no longer works):\n  Email: {}\n  Server: {}\n  Secret Key: {}\n  Recovery code: {}\n  Created: {}",
                kit.email, kit.server_url, kit.secret_key, recovery, kit.created_at
            );
            self.out_secret(&text, true, true)?;
        }
        if let Err(error) = self.keep_unlocked(&opened).await {
            self.note(&format!(
                "Replaced the Secret Key, but couldn't keep this terminal unlocked ({}).",
                error.message
            ));
        }
        self.note("Every other device was signed out, and needs the new Secret Key to sign in.");
        Ok(None)
    }

    async fn rotate_vault_key(&mut self, query: &str) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let vaults = opened.vault.list_vaults()?;
        let target = items::find_vault(&vaults, query)?.clone();
        opened.vault.rotate_vault_key(&target.id).await?;
        if self.global.json {
            self.out_json(&json!({ "rotated": true, "vault": target.id }))?;
        } else {
            self.out(&format!(
                "\"{}\" has a new key. Your other devices pick it up by themselves.",
                target.name
            ))?;
        }
        Ok(None)
    }

    async fn reset_master_password(
        &mut self,
        server: Option<String>,
        email: Option<String>,
        code: Option<String>,
    ) -> Result<Option<i32>> {
        let server = server
            .or_else(|| self.context.var("OCTAPASS_SERVER"))
            .unwrap_or_else(|| HOSTED_SERVER_URL.into());
        let email = match email.or_else(|| self.context.var("OCTAPASS_EMAIL")) {
            Some(email) => email,
            None if self.context.terminal.interactive() => {
                self.context.terminal.ask("Email: ").map_err(input_error)?
            }
            None => return Err(CliError::usage("Pass --email, or set OCTAPASS_EMAIL.")),
        };
        let opened = self.open(DEFAULT_IDLE)?;
        let started = opened.vault.start_password_reset(&server, &email).await?;
        let reset_id = started.reset_id;
        let mut code = code;
        if code.is_none() {
            if let Some(dev) = &started.dev_verification_code {
                self.note(&format!("Development code: {dev}"));
            }
            code = started.dev_verification_code;
        }
        loop {
            let typed = match code.take() {
                Some(code) => code,
                None if self.context.terminal.interactive() => self
                    .context
                    .terminal
                    .ask("Code from the email: ")
                    .map_err(input_error)?,
                None => {
                    return Err(CliError::usage(
                        "Pass --code with the 6-digit code we emailed you.",
                    ));
                }
            };
            match opened.vault.verify_password_reset(&reset_id, &typed).await {
                Ok(()) => break,
                Err(error)
                    if error.code == ErrorCode::InvalidVerificationCode
                        && self.context.terminal.interactive() =>
                {
                    self.note(&error.message);
                }
                Err(error) => return Err(error.into()),
            }
        }
        let recovery = self.recovery_code()?;
        let password = self.new_master_password()?;
        let result = opened
            .vault
            .finish_password_reset(&reset_id, recovery.as_str(), password)
            .await?;
        let kit = result.recovery_kit;
        let sign_in = result.sign_in;
        if self.global.json {
            if self.context.stdout_is_terminal {
                self.note("Warning: showing secrets in the terminal.");
            }
            self.out_json(&json!({
                "recoveryKit": kit,
                "signedIn": sign_in.is_some(),
            }))?;
        } else {
            let text = format!(
                "Your new Recovery Kit (store it somewhere safe: the old one no longer works):\n  Email: {}\n  Server: {}\n  Secret Key: {}\n  Recovery code: {}\n  Created: {}",
                kit.email, kit.server_url, kit.secret_key, kit.recovery_code, kit.created_at
            );
            self.out_secret(&text, true, true)?;
        }
        match sign_in {
            Some(SignInResult::TwoStepRequired { methods }) => {
                let code = match self.context.var("OCTAPASS_TWO_STEP_CODE") {
                    Some(code) => Zeroizing::new(code),
                    None if self.context.terminal.interactive() => {
                        let prompt = if methods.contains(&TwoStepMethod::Totp) {
                            "Code from your authenticator app, or a two-step recovery code: "
                        } else {
                            "Two-step recovery code: "
                        };
                        self.context
                            .terminal
                            .ask_hidden(prompt)
                            .map_err(input_error)?
                    }
                    None => {
                        self.note("Two-step sign-in is on: run `octapass login` with the new password and a code from your authenticator app.");
                        return Ok(None);
                    }
                };
                opened.vault.finish_two_step(two_step_proof(&code)).await?;
                self.keep_unlocked(&opened).await.ok();
            }
            Some(SignInResult::SsoRequired { org_name, .. }) => self.note(&format!(
                "The new master password is set. {org_name} requires single sign-on: run `octapass login` to finish signing in."
            )),
            Some(SignInResult::SignedIn) => match self.keep_unlocked(&opened).await {
                Ok(true) => self.note(&format!("Signed in as {}.", kit.email)),
                Ok(false) => self.note(
                    "There's no OS keyring here, so each command asks for your master password.",
                ),
                Err(error) => self.note(&format!(
                    "Signed in, but the vault can't stay unlocked ({}).",
                    error.message
                )),
            },
            None => self.note("The new master password is set. Sign in with `octapass login`."),
        }
        Ok(None)
    }

    async fn list(
        &mut self,
        vault_query: Option<String>,
        search: Option<String>,
    ) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let vaults = opened.vaults()?;
        let only = vault_query
            .map(|query| items::find_vault(&vaults, &query).map(|vault| vault.id.clone()))
            .transpose()?;
        let rows: Vec<_> = items::live(opened.summaries()?)
            .into_iter()
            .filter(|row| only.as_ref().is_none_or(|id| &row.vault_id == id))
            // A Safe's key is an item, but it's managed through `octapass safe`.
            .filter(|row| row.item_type != "fileSafe")
            .filter(|row| {
                search
                    .as_deref()
                    .is_none_or(|query| items::matches_search(row, query))
            })
            .collect();
        if self.global.json {
            let rows: Vec<Value> = rows
                .iter()
                .map(|row| {
                    let mut value = serde_json::to_value(row).expect("rows serialize");
                    value["vault"] = json!(items::vault_name(&vaults, &row.vault_id));
                    value
                })
                .collect();
            return self.out_json(&Value::Array(rows)).map(|()| None);
        }
        if rows.is_empty() {
            self.note("No items.");
            return Ok(None);
        }
        let table: Vec<[String; 4]> = rows
            .iter()
            .map(|row| {
                [
                    row.title.clone(),
                    row.subtitle.clone().unwrap_or_default(),
                    items::vault_name(&vaults, &row.vault_id).to_owned(),
                    row.id.clone(),
                ]
            })
            .collect();
        for line in format_table(["TITLE", "USERNAME", "VAULT", "ID"], &table) {
            self.out(&line)?;
        }
        Ok(None)
    }

    /// The item `query` names, in `vault_query` when given.
    fn find_item(&self, opened: &Opened, query: &str, vault_query: Option<&str>) -> Result<Item> {
        let vaults = opened.vaults()?;
        let only = vault_query
            .map(|vault| items::find_vault(&vaults, vault).map(|vault| vault.id.clone()))
            .transpose()?;
        let rows: Vec<_> = items::live(opened.summaries()?)
            .into_iter()
            .filter(|row| only.as_ref().is_none_or(|id| &row.vault_id == id))
            .collect();
        let row = items::find_item(&rows, query)?;
        Ok(opened.item(&row.id)?)
    }

    /// A field by name; `totp` is the current one-time code.
    fn field(&self, opened: &Opened, item: &Item, name: &str) -> Result<Field> {
        if octapass_connect::oauth::wants_live_token(name)
            && octapass_connect::oauth::has_live_token(item)
        {
            return self.live_token(opened, item);
        }
        if matches!(name.trim().to_lowercase().as_str(), "totp" | "otp" | "code") {
            return Ok(Field {
                value: self.code(opened, item)?.code,
                secret: false,
            });
        }
        items::field(item, name)
    }

    fn code(
        &self,
        opened: &Opened,
        item: &Item,
    ) -> Result<octapass_desktop_vault::tools::TotpCode> {
        let totp = item.detail("totp").ok_or_else(|| {
            CliError::not_found(format!("\"{}\" has no one-time code.", item.title()))
        })?;
        opened.vault.totp(totp, None).map_err(|_| {
            CliError::other(format!(
                "The one-time code setup of \"{}\" can't be read.",
                item.title()
            ))
        })
    }

    async fn get(
        &mut self,
        query: String,
        field: Option<String>,
        vault_query: Option<String>,
        newline: bool,
    ) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let item = self.find_item(&opened, &query, vault_query.as_deref())?;
        if let Some(name) = field {
            let field = self.field(&opened, &item, &name)?;
            if self.global.json {
                if field.secret && self.context.stdout_is_terminal {
                    self.note("Warning: showing a secret in the terminal.");
                }
                return self
                    .out_json(&json!({ "field": name, "value": field.value }))
                    .map(|()| None);
            }
            return self
                .out_secret(&field.value, field.secret, newline)
                .map(|()| None);
        }
        let vaults = opened.vaults()?;
        let vault = items::vault_name(&vaults, &item.vault_id).to_owned();
        if self.global.json {
            if self.context.stdout_is_terminal {
                self.note("Warning: showing the item's secrets in the terminal.");
            }
            let mut value = serde_json::to_value(&item).expect("items serialize");
            value["vault"] = json!(vault);
            return self.out_json(&value).map(|()| None);
        }
        for line in describe(&item, &vault) {
            self.out(&line)?;
        }
        Ok(None)
    }

    async fn totp(&mut self, query: String, vault_query: Option<String>) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let item = self.find_item(&opened, &query, vault_query.as_deref())?;
        let code = self.code(&opened, &item)?;
        if self.global.json {
            self.out_json(&serde_json::to_value(&code).expect("codes serialize"))?;
        } else {
            self.out(&code.code)?;
        }
        Ok(None)
    }

    fn generate(&mut self, args: GenerateArgs) -> Result<Option<i32>> {
        let options = match args.words {
            Some(words) => GeneratorOptions::Passphrase(PassphraseOptions {
                words,
                separator: args.separator.unwrap_or_else(|| "-".into()),
                capitalize: args.capitalize,
                include_number: args.number,
            }),
            None => GeneratorOptions::Random(RandomOptions {
                length: args.length.unwrap_or(RandomOptions::default().length),
                lowercase: !args.no_lowercase,
                uppercase: !args.no_uppercase,
                digits: !args.no_digits,
                symbols: !args.no_symbols,
                avoid_ambiguous: args.avoid_ambiguous,
            }),
        };
        let password = generate(&options, &mut OsRng).map_err(|_| {
            CliError::usage(
                "Use 4 to 128 characters with at least one kind of character, or 3 to 20 words with a separator of at most 3 characters.",
            )
        })?;
        if self.global.json {
            self.out_json(&json!({ "password": password.as_str() }))?;
        } else {
            self.out(&password)?;
        }
        Ok(None)
    }

    /// What a reference points to, in an unlocked vault. A value that is itself a reference (an
    /// environment's variable set to a login's password) is followed once; a third is an error,
    /// so references can't loop.
    fn resolve(&self, opened: &Opened, reference: &Reference) -> Result<Field> {
        let field = self.resolve_once(opened, reference)?;
        if !Reference::is_reference(&field.value) {
            return Ok(field);
        }
        let target = self.resolve_once(opened, &items::parse_reference(&field.value)?)?;
        if Reference::is_reference(&target.value) {
            return Err(CliError::usage(format!(
                "{} points to {}, which is another reference. Only one step is followed.",
                reference.text(),
                field.value.trim()
            )));
        }
        Ok(Field {
            value: target.value,
            secret: field.secret || target.secret,
        })
    }

    fn resolve_once(&self, opened: &Opened, reference: &Reference) -> Result<Field> {
        let item = self.find_item(opened, &reference.item, Some(&reference.vault))?;
        self.field(opened, &item, &reference.field)
    }

    async fn read(&mut self, reference: String, newline: bool) -> Result<Option<i32>> {
        let reference = items::parse_reference(&reference)?;
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let field = self.resolve(&opened, &reference)?;
        self.save_live_tokens(&opened).await?;
        self.out_secret(&field.value, field.secret, newline)?;
        Ok(None)
    }

    async fn run_command(&mut self, args: RunArgs) -> Result<Option<i32>> {
        let RunArgs {
            env: env_specs,
            project,
            stage,
            env_files,
            env_file_out,
            yes,
            no_masking,
            command,
        } = args;
        let mut env = self.context.env.clone();
        // Values to keep out of the command's output, and the variables they came from.
        let mut secrets: Vec<String> = Vec::new();
        let mut concealed: Vec<String> = Vec::new();
        // The names Octa Pass adds, for --env-file-out.
        let mut added: Vec<String> = Vec::new();
        let mut add = |env: &mut Vec<(OsString, OsString)>, key: String, value: String| {
            if !added.contains(&key) {
                added.push(key.clone());
            }
            set_var(env, key.into(), value.into());
        };
        let plan = self.plan(env_specs, project, stage)?;
        let mut opened = None;
        if !plan.is_empty() {
            let vault = self.open(DEFAULT_IDLE)?;
            self.unlocked(&vault).await?;
            for var in self.load_environments(&vault, &plan, yes)? {
                if var.concealed {
                    concealed.push(var.key.clone());
                    if !Reference::is_reference(&var.value) {
                        secrets.push(var.value.clone());
                    }
                }
                add(&mut env, var.key, var.value);
            }
            opened = Some(vault);
        }
        for path in &env_files {
            let text = fs::read_to_string(path).map_err(|error| {
                CliError::usage(format!("Can't read {}: {error}", path.display()))
            })?;
            for (key, value) in env_file::parse(&text, &path.display().to_string())? {
                add(&mut env, key, value);
            }
        }
        let mut references = Vec::new();
        for (index, (key, value)) in env.iter().enumerate() {
            if let Some(value) = value
                .to_str()
                .filter(|value| Reference::is_reference(value))
            {
                let reference = items::parse_reference(value).map_err(|error| {
                    CliError::new(
                        error.exit,
                        format!("{}: {}", key.to_string_lossy(), error.message),
                    )
                })?;
                references.push((index, reference));
            }
        }
        if !references.is_empty() {
            let opened = match opened.take() {
                Some(opened) => opened,
                None => {
                    let opened = self.open(DEFAULT_IDLE)?;
                    self.unlocked(&opened).await?;
                    opened
                }
            };
            for (index, reference) in references {
                let value = self.resolve(&opened, &reference).map_err(|error| {
                    CliError::new(
                        error.exit,
                        format!("{}: {}", env[index].0.to_string_lossy(), error.message),
                    )
                })?;
                let name = env[index].0.to_string_lossy();
                if value.secret || concealed.iter().any(|key| *key == name) {
                    secrets.push(value.value.clone());
                }
                env[index].1 = value.value.into();
            }
            self.save_live_tokens(&opened).await?;
            // Closes the vault and lets other `octapass` commands (perhaps the child) run.
            drop(opened);
        }
        if let Some(opened) = &opened {
            self.save_live_tokens(opened).await?;
        }
        drop(opened);

        let mut process = Process::new(&command[0]);
        process
            .args(&command[1..])
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k, v)))
            .current_dir(&self.context.cwd);
        let _ = self.context.stdout.flush();
        let _ = self.context.stderr.flush();
        let off = no_masking
            || self
                .context
                .var("OCTAPASS_NO_MASKING")
                .is_some_and(|value| value != "0");
        let masked = !off && !Masker::new(secrets.iter().cloned()).is_empty();
        let secrets = masked.then_some(secrets);
        if let Some(path) = env_file_out {
            let path = self.context.cwd.join(path);
            let lookup = |key: &str| {
                env.iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            let values: Vec<(String, String)> =
                added.iter().map(|key| (key.clone(), lookup(key))).collect();
            let text = octapass_core::environment::write(
                values.iter().map(|(k, v)| (k.as_str(), v.as_str())),
                octapass_core::environment::EnvFormat::Dotenv,
            )
            .map_err(|error| CliError::usage(error.to_string()))?;
            return self.run_with_file(process, &command[0], &path, text.as_bytes(), secrets);
        }
        let result = match secrets {
            Some(secrets) => self.run_masked(process, &secrets),
            None => {
                let exec = self.exec.take().expect("run executes once");
                exec(process)
            }
        };
        self.command_finished(result, &command[0])
    }

    fn command_finished(&mut self, result: io::Result<i32>, name: &str) -> Result<Option<i32>> {
        match result {
            Ok(code) => Ok(Some(code)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.note(&format!("octapass: command not found: {name}"));
                Ok(Some(127))
            }
            Err(error) => {
                self.note(&format!("octapass: can't run {name}: {error}"));
                Ok(Some(126))
            }
        }
    }

    /// Runs the command as a child with its stdout and stderr filtered. Its stdin stays the
    /// terminal, and its exit code is passed on.
    fn run_masked(&mut self, mut process: Process, secrets: &[String]) -> io::Result<i32> {
        use std::process::Stdio;
        wait_through_signals();
        process.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = process.spawn()?;
        let forwarding = forward_termination(child.id());
        let mut child_out = child.stdout.take().expect("piped");
        let mut child_err = child.stderr.take().expect("piped");
        let (stdout, stderr) = (&mut self.context.stdout, &mut self.context.stderr);
        std::thread::scope(|scope| {
            scope.spawn(|| filter(&mut child_out, stdout, secrets));
            scope.spawn(|| filter(&mut child_err, stderr, secrets));
        });
        let status = child.wait();
        drop(forwarding);
        exit_code(status?)
    }

    /// Writes the variables to `path` (readable only by the user) for the command's lifetime: the
    /// command runs as a child, and the file is deleted when it ends, also when Ctrl-C or a
    /// termination signal ends it (Octa Pass waits for the child instead of dying first).
    fn run_with_file(
        &mut self,
        mut process: Process,
        name: &str,
        path: &Path,
        bytes: &[u8],
        secrets: Option<Vec<String>>,
    ) -> Result<Option<i32>> {
        environments::create_secret_file(path, bytes).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CliError::usage(format!(
                    "{} already exists, and --env-file-out deletes its file afterwards. Choose a new path.",
                    path.display()
                ))
            } else {
                CliError::other(format!("Can't write {}: {error}", path.display()))
            }
        })?;
        wait_through_signals();
        let result = match secrets {
            Some(secrets) => self.run_masked(process, &secrets),
            None => spawn_and_wait(&mut process),
        };
        let removed = fs::remove_file(path);
        if let Err(error) = removed {
            self.note(&format!(
                "octapass: couldn't delete {}: {error}. Delete it yourself: it holds secrets.",
                path.display()
            ));
        }
        self.command_finished(result, name)
    }

    async fn import(
        &mut self,
        format: ImportFormat,
        file: PathBuf,
        vault_query: Option<String>,
        key_file: Option<PathBuf>,
        dry_run: bool,
    ) -> Result<Option<i32>> {
        let read = |path: &Path| {
            fs::read(path)
                .map(Zeroizing::new)
                .map_err(|error| CliError::usage(format!("Can't read {}: {error}", path.display())))
        };
        let bytes = read(&file)?;
        let key_file = key_file.as_deref().map(read).transpose()?;
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let vaults = opened.vaults()?;
        let target = match &vault_query {
            Some(query) => items::find_vault(&vaults, query)?,
            None => vaults
                .iter()
                .find(|vault| vault.vault_type == VaultType::Personal)
                .ok_or_else(|| CliError::not_found("No Personal vault. Pass --vault."))?,
        }
        .clone();
        if target.role == VaultRole::Read {
            return Err(CliError::other(format!(
                "You can only read the {} vault, not import into it.",
                target.name
            )));
        }
        let existing_logins = opened
            .vault
            .live_items()?
            .iter()
            .filter(|item| item.is_login_like())
            .map(|item| ExistingLogin {
                id: item.id.clone(),
                title: item.title().to_owned(),
                urls: serde_json::from_value(
                    item.overview.get("urls").cloned().unwrap_or_default(),
                )
                .unwrap_or_default(),
                username: item.detail("username").map(str::to_owned),
                subtitle: item
                    .overview
                    .get("subtitle")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                has_totp: item.detail("totp").is_some(),
                totp: item.detail("totp").map(str::to_owned),
            })
            .collect();
        // Items already in the vaults, so a dry run tells what importing the file again would
        // update. Only the target's are compared, except that an Octa Pass export finds its own
        // items by id in every vault.
        let existing_items = opened
            .vault
            .live_items()?
            .into_iter()
            .filter_map(|item| {
                Some(ExistingItem {
                    overview: serde_json::from_value(item.overview).ok()?,
                    details: item.details,
                    id: item.id,
                    vault_id: Some(item.vault_id),
                    updated_at: Some(item.updated_at),
                })
            })
            .collect();
        let mut options = ImportOptions {
            existing_logins,
            existing_items,
            vault_id: Some(target.id.clone()),
            key_file,
            ..ImportOptions::default()
        };
        let result = loop {
            match import_file(format.into(), &bytes, &options) {
                Err(error)
                    if error.code == CoreError::ImportPasswordRequired
                        && options.password.is_none()
                        && self.can_ask_password() =>
                {
                    options.password = Some(self.file_password("Password of the file: ", false)?);
                }
                Err(error) if error.code == CoreError::ImportPasswordRequired => {
                    return Err(CliError::usage(
                        "This file is password-protected. Run the import in a terminal to enter its password, or pass --password-stdin.",
                    ));
                }
                Err(error) if error.code == CoreError::WrongImportPassword => {
                    return Err(CliError::new(
                        Exit::InvalidCredentials,
                        "Wrong password for the file.",
                    ));
                }
                Err(error) => return Err(CliError::usage(error.detail)),
                Ok(result) => break result,
            }
        };
        let (mut count, codes) = (result.items.len(), result.totp_updates.len());
        let (mut updated, mut unchanged) = (result.updates.len(), result.unchanged);
        let (warnings, skipped, files) = if dry_run {
            (result.warnings, result.skipped, result.files.len())
        } else {
            // The vault reads the file again to save the items and upload any attached files.
            let summary = opened
                .vault
                .import_file(format.into(), &bytes, options, &target.id)
                .await?;
            count = summary.imported.saturating_sub(codes);
            updated = summary.updated.unwrap_or(0);
            unchanged = summary.unchanged.unwrap_or(0);
            (
                summary.warnings,
                summary.skipped,
                summary.files.unwrap_or(0),
            )
        };
        for warning in &warnings {
            self.note(&format!("Warning: {warning}"));
        }
        if self.global.json {
            self.out_json(&json!({
                "dryRun": dry_run,
                "vault": target.name,
                "items": count,
                "updated": updated,
                "unchanged": unchanged,
                "totpUpdates": codes,
                "files": files,
                "skipped": skipped,
                "warnings": warnings,
            }))?;
        } else {
            let verb = if dry_run { "Would import" } else { "Imported" };
            let mut text = format!(
                "{verb} {count} {} into {}",
                plural(count, "item"),
                target.name
            );
            if files > 0 {
                text += &format!(" with {files} attached {}", plural(files, "file"));
            }
            if codes > 0 {
                text += &format!(
                    ", and one-time codes for {codes} existing {}",
                    plural(codes, "login")
                );
            }
            if updated > 0 || unchanged > 0 {
                let update = if dry_run { "to update" } else { "updated" };
                text += &format!("; {updated} {update} and {unchanged} unchanged");
            }
            text += ".";
            if skipped > 0 {
                text += &format!(" Skipped {skipped} {}.", plural(skipped, "entry"));
            }
            self.note(&text);
        }
        Ok(None)
    }

    async fn export(
        &mut self,
        format: ExportFormat,
        encrypted: bool,
        output: Option<PathBuf>,
    ) -> Result<Option<i32>> {
        if encrypted && format != ExportFormat::Json {
            return Err(CliError::usage(
                "Only the Octa Pass export can be encrypted: leave out --format, or use --format json.",
            ));
        }
        if encrypted && output.is_none() && self.context.stdout_is_terminal {
            return Err(CliError::usage(
                "The encrypted export is a binary file: pass --output.",
            ));
        }
        let opened = self.open(DEFAULT_IDLE)?;
        if opened.vault.snapshot().session.status == SessionStatus::SignedOut {
            return Err(CliError::signed_out());
        }
        // Exporting always asks for the master password, even when unlocked (plan 07).
        if !self.can_ask_password() {
            return Err(CliError::usage(
                "Exporting needs your master password: run it in a terminal, or pass --password-stdin.",
            ));
        }
        let password = self.master_password()?;
        opened.vault.unlock(password).await?;
        let export_password = encrypted
            .then(|| self.file_password("Password for the export file: ", true))
            .transpose()?;
        self.sync(&opened.vault).await?;
        let vaults = opened.vaults()?;
        let mut items = opened.live_items()?;
        items.retain(|item| !octapass_desktop_vault::health::is_health_settings(item));
        items.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let files: usize = items.iter().map(export::attachment_count).sum();
        let bytes = match (format, encrypted) {
            (_, true) => {
                opened
                    .vault
                    .export_file(
                        FileExport::Encrypted,
                        export_password.as_deref().map(String::as_str),
                        EXPORT_KDF,
                    )
                    .await?
            }
            (ExportFormat::Cxf, _) => {
                opened
                    .vault
                    .export_file(FileExport::Cxf, None, EXPORT_KDF)
                    .await?
            }
            (ExportFormat::Json, _) => Zeroizing::new(
                (document(&vaults, &items, &rfc3339(now())).to_json() + "\n").into_bytes(),
            ),
            (ExportFormat::Csv, _) => Zeroizing::new(export::csv(&vaults, &items).into_bytes()),
        };
        match output {
            Some(path) => {
                write_private(&path, &bytes).map_err(|error| {
                    CliError::other(format!("Can't write {}: {error}", path.display()))
                })?;
                let what = format!("{} {}", items.len(), plural(items.len(), "item"));
                self.note(&if encrypted {
                    format!(
                        "Exported {what} and {files} attached {} to {}, encrypted with the password you chose.",
                        plural(files, "file"),
                        path.display()
                    )
                } else {
                    format!(
                        "Exported {what} to {}. It isn't encrypted: keep it safe and delete it when you're done.",
                        path.display()
                    )
                });
            }
            None => {
                if self.context.stdout_is_terminal {
                    self.note("Warning: showing every secret in the terminal. Use --output to write a file.");
                }
                self.context
                    .stdout
                    .write_all(&bytes)
                    .map_err(output_error)?;
            }
        }
        // "Vault exported" in the security log, with only the format. The file is out already,
        // so a server that can't be reached doesn't fail the export.
        let logged = match (format, encrypted) {
            (_, true) => octapass_api::ExportFormat::Encrypted,
            (ExportFormat::Json, _) => octapass_api::ExportFormat::Json,
            (ExportFormat::Csv, _) => octapass_api::ExportFormat::Csv,
            (ExportFormat::Cxf, _) => octapass_api::ExportFormat::Cxf,
        };
        if opened.vault.record_export(logged).await.is_err() {
            self.note(
                "The export isn't in your account's security log: the server couldn't be reached.",
            );
        }
        Ok(None)
    }
}

/// `octapass run`'s options.
struct RunArgs {
    env: Vec<String>,
    project: Option<String>,
    stage: Option<String>,
    env_files: Vec<PathBuf>,
    env_file_out: Option<PathBuf>,
    yes: bool,
    no_masking: bool,
    command: Vec<String>,
}

/// Copies one of the child's outputs to ours through a [`Masker`], flushing as it goes so progress
/// and prompts show up. Stops writing, not reading, when our output fails, so the child never
/// blocks on a full pipe.
fn filter(input: &mut impl Read, output: &mut Box<dyn Write + Send>, secrets: &[String]) {
    let mut masker = Masker::new(secrets.iter().cloned());
    let mut chunk = [0u8; 8192];
    let mut shown = Vec::new();
    let mut open = true;
    loop {
        shown.clear();
        match input.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => masker.feed(&chunk[..read], &mut shown),
        }
        open = open
            && output
                .write_all(&shown)
                .and_then(|()| output.flush())
                .is_ok();
    }
    shown.clear();
    masker.finish(&mut shown);
    if open {
        let _ = output.write_all(&shown).and_then(|()| output.flush());
    }
}

/// Passes SIGTERM and SIGHUP on to the child while it runs: Ctrl-C reaches it through the process
/// group, but `kill`, `docker stop` or a closed CI job only reach Octa Pass.
#[cfg(unix)]
fn forward_termination(child: u32) -> Option<ForwardedSignals> {
    use signal_hook::consts::{SIGHUP, SIGTERM};
    let mut signals = signal_hook::iterator::Signals::new([SIGTERM, SIGHUP]).ok()?;
    let handle = signals.handle();
    let thread = std::thread::spawn(move || {
        for signal in signals.forever() {
            // SAFETY: plain call. The child is still ours: this thread stops before it's reaped.
            unsafe { libc::kill(child as libc::pid_t, signal) };
        }
    });
    Some(ForwardedSignals {
        handle,
        thread: Some(thread),
    })
}

#[cfg(not(unix))]
fn forward_termination(_child: u32) -> Option<()> {
    None
}

#[cfg(unix)]
struct ForwardedSignals {
    handle: signal_hook::iterator::Handle,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl Drop for ForwardedSignals {
    fn drop(&mut self) {
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// From now on Ctrl-C and termination signals don't end this process: the child gets them too
/// (it's in the same process group) and Octa Pass cleans up when it exits. A handler, unlike
/// ignoring the signal, isn't inherited by the child.
fn wait_through_signals() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = ctrlc::set_handler(|| {});
    });
}

fn device_info() -> DeviceInfo {
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    };
    DeviceInfo {
        name: format!("Octa Pass CLI ({os})"),
        platform: "cli".into(),
    }
}

fn idle_timeout(text: Option<String>) -> Result<Duration> {
    text.map_or(Ok(DEFAULT_IDLE), |text| {
        session::parse_duration(&text).map_err(CliError::usage)
    })
}

fn describe_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds.is_multiple_of(3600) {
        format!(
            "{} {}",
            seconds / 3600,
            plural((seconds / 3600) as usize, "hour")
        )
    } else if seconds.is_multiple_of(60) {
        format!(
            "{} {}",
            seconds / 60,
            plural((seconds / 60) as usize, "minute")
        )
    } else {
        format!("{seconds} {}", plural(seconds as usize, "second"))
    }
}

fn plural(count: usize, word: &str) -> String {
    match (count, word) {
        (1, _) => word.to_owned(),
        (_, "entry") => "entries".to_owned(),
        _ => format!("{word}s"),
    }
}

fn set_var(env: &mut Vec<(OsString, OsString)>, key: OsString, value: OsString) {
    match env.iter_mut().find(|(existing, _)| *existing == key) {
        Some(entry) => entry.1 = value,
        None => env.push((key, value)),
    }
}

/// Columns padded to their widest cell, two spaces apart.
fn format_table<const N: usize>(header: [&str; N], rows: &[[String; N]]) -> Vec<String> {
    let mut widths = header.map(|cell| cell.chars().count());
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let padded: Vec<String> = cells
            .iter()
            .zip(widths)
            .map(|(cell, width)| format!("{cell:width$}"))
            .collect();
        padded.join("  ").trim_end().to_owned()
    };
    std::iter::once(line(header.to_vec()))
        .chain(
            rows.iter()
                .map(|row| line(row.iter().map(String::as_str).collect())),
        )
        .collect()
}

/// An item as text, with secrets left out and the command that shows each one.
fn describe(item: &Item, vault: &str) -> Vec<String> {
    let mut rows: Vec<(String, String)> = Vec::new();
    let title = item.title();
    let quoted = if title.contains([' ', '"', '\'']) {
        format!("\"{}\"", title.replace('"', "\\\""))
    } else {
        title.to_owned()
    };
    let hidden = |field: &str| format!("hidden: octapass get {quoted} --field \"{field}\"");
    rows.push(("Title".into(), title.to_owned()));
    if let Some(item_type) = item.overview.get("type").and_then(Value::as_str) {
        rows.push(("Type".into(), item_type.to_owned()));
    }
    rows.push(("Vault".into(), vault.to_owned()));
    for url in item
        .overview
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        rows.push(("URL".into(), url.to_owned()));
    }
    if let Some(details) = item.details.as_object() {
        for (key, value) in details {
            match (key.as_str(), value) {
                (
                    "schemaVersion" | "passwordHistory" | "notes" | "customFields" | "templateId",
                    _,
                ) => {}
                ("addresses", Value::Array(addresses)) => {
                    for entry in addresses {
                        let text = |name: &str| entry.get(name).and_then(Value::as_str);
                        if let Some(address) = text("address") {
                            let name = text("label").or(text("network")).unwrap_or("Address");
                            rows.push((name.to_owned(), address.to_owned()));
                        }
                    }
                }
                ("fields", Value::Array(fields)) => {
                    for entry in fields {
                        let Some(name) = entry.get("label").and_then(Value::as_str) else {
                            continue;
                        };
                        match items::field(item, name) {
                            Ok(field) if field.secret => rows.push((name.to_owned(), hidden(name))),
                            Ok(field) => rows.push((name.to_owned(), field.value)),
                            Err(_) => {}
                        }
                    }
                }
                ("totp", Value::String(totp)) if !totp.is_empty() => {
                    rows.push(("One-time code".into(), format!("octapass totp {quoted}")));
                }
                ("passkeys", Value::Array(passkeys)) if !passkeys.is_empty() => {
                    rows.push(("Passkeys".into(), passkeys.len().to_string()));
                }
                ("variables", Value::Array(variables)) => {
                    rows.push((
                        "Variables".into(),
                        format!("{} (octapass env show {quoted})", variables.len()),
                    ));
                }
                ("address", Value::Object(_)) => {
                    let address = export::address(Some(value));
                    if !address.is_empty() {
                        rows.push(("Address".into(), address));
                    }
                }
                (_, Value::String(text)) if !text.is_empty() => {
                    let secret = items::field(item, key).is_ok_and(|field| field.secret);
                    let shown = if secret { hidden(key) } else { text.clone() };
                    rows.push((label(key), shown));
                }
                _ => {}
            }
        }
    }
    for custom in item
        .details
        .get("customFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let field_label = custom
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let value = custom
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if field_label.is_empty() || value.is_empty() {
            continue;
        }
        let secret = custom.get("hidden") != Some(&Value::Bool(false));
        let shown = if secret {
            hidden(field_label)
        } else {
            value.to_owned()
        };
        rows.push((field_label.to_owned(), shown));
    }
    if let Ok(notes) = items::field(item, "notes") {
        let shown = if notes.secret {
            hidden("notes")
        } else {
            notes.value
        };
        rows.push(("Notes".into(), shown));
    }
    if let Some(tags) = item.overview.get("tags").and_then(Value::as_array)
        && !tags.is_empty()
    {
        let tags: Vec<&str> = tags.iter().filter_map(Value::as_str).collect();
        rows.push(("Tags".into(), tags.join(", ")));
    }
    rows.push(("Updated".into(), item.updated_at.clone()));
    rows.push(("ID".into(), item.id.clone()));

    let width = rows
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    rows.iter()
        .flat_map(|(label, value)| {
            // Multi-line values (notes) line up under the first line.
            let mut lines = value.lines();
            let first = format!("{label:width$}  {}", lines.next().unwrap_or_default());
            std::iter::once(first.trim_end().to_owned()).chain(
                lines
                    .map(|line| format!("{:width$}  {line}", ""))
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

/// `firstName` → `First name`, with the usual abbreviations.
fn label(key: &str) -> String {
    match key {
        "cvv" => return "CVV".into(),
        "pin" => return "PIN".into(),
        _ => {}
    }
    let mut out = String::new();
    for (i, c) in key.chars().enumerate() {
        if i == 0 {
            out.extend(c.to_uppercase());
        } else if c.is_uppercase() {
            out.push(' ');
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn output_error(error: io::Error) -> CliError {
    CliError::other(format!("Couldn't write the output: {error}"))
}

fn input_error(error: io::Error) -> CliError {
    CliError::usage(format!("Couldn't read the answer: {error}"))
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

fn private_file(path: &Path, truncate: bool) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(truncate);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Writes an export readable only by the user, also when the file already existed.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = private_file(path, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    restrict_to_owner(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Unix files get mode 0600 when they're created. On Windows the file's inherited permissions are
/// replaced by full control for the user alone.
#[cfg(not(windows))]
fn restrict_to_owner(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn restrict_to_owner(path: &Path) -> io::Result<()> {
    let user = std::env::var("USERNAME").map_err(io::Error::other)?;
    let status = Process::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(format!("{user}:F"))
        .stdout(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("icacls couldn't make the file private"))
    }
}

/// Six digits are an authenticator code; anything else is taken as a two-step recovery code.
fn two_step_proof(code: &str) -> TwoStepProof {
    let code = code.trim();
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        TwoStepProof::Totp {
            code: code.to_owned(),
        }
    } else {
        TwoStepProof::RecoveryCode {
            code: code.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_line_up() {
        let rows = [
            ["GitHub".to_owned(), "octocat".to_owned()],
            ["A much longer title".to_owned(), String::new()],
        ];
        assert_eq!(
            format_table(["TITLE", "USERNAME"], &rows),
            [
                "TITLE                USERNAME",
                "GitHub               octocat",
                "A much longer title",
            ]
        );
    }

    #[test]
    fn items_are_described_without_their_secrets() {
        let item = Item {
            id: "0190a6c4-7d00-7000-8000-000000000001".into(),
            vault_id: "v".into(),
            revision: 1,
            created_at: "t".into(),
            updated_at: "2026-10-24T08:00:00Z".into(),
            deleted_at: None,
            overview: json!({ "type": "login", "title": "My Bank", "urls": ["https://bank.example"], "tags": ["money"] }),
            details: json!({
                "username": "ada", "password": "hunter2", "totp": "JBSWY3DPEHPK3PXP",
                "notes": "line one\nline two",
                "customFields": [{ "label": "PIN", "value": "1234", "hidden": true }, { "label": "Branch", "value": "Main St", "hidden": false }],
            }),
        };
        let text = describe(&item, "Personal").join("\n");
        assert!(!text.contains("hunter2") && !text.contains("1234") && !text.contains("JBSWY3"));
        assert!(
            text.contains("Password       hidden: octapass get \"My Bank\" --field \"password\"")
        );
        assert!(text.contains("One-time code  octapass totp \"My Bank\""));
        assert!(text.contains("Branch         Main St"));
        assert!(text.contains("Notes          line one\n               line two"));
        assert!(text.contains("Username       ada"));
    }

    #[test]
    fn labels_and_durations_read_naturally() {
        assert_eq!(label("firstName"), "First name");
        assert_eq!(label("cvv"), "CVV");
        assert_eq!(describe_duration(Duration::from_secs(1800)), "30 minutes");
        assert_eq!(describe_duration(Duration::from_secs(3600)), "1 hour");
        assert_eq!(describe_duration(Duration::from_secs(90)), "90 seconds");
        assert_eq!(plural(2, "entry"), "entries");
    }
}
