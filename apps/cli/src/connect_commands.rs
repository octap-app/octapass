//! `octapass connect …`. `serve` runs the shared service on a thread of its own and answers its
//! requests here, one at a time: each opens the vault with the keyring session and closes it
//! again, so `octapass lock` or the idle timeout stop Connect at once, and other `octapass`
//! commands get their turn. Connect never asks for the master password and never unlocks.

use std::sync::Arc;

use octapass_connect::client::{ClientError, ConnectClient, Endpoint};
use octapass_connect::clients::{Client, Clients, TOKEN_LIFETIME_SECONDS};
use octapass_connect::log::{BATCH, Entry, Queue};
use octapass_connect::reference::field_names;
use octapass_connect::server::{self, Approval, Backend, BoxFuture, ConnectError, ItemRef, Secret};
use octapass_connect::{ENDPOINT_ENV, folder};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use super::*;
use crate::cli::ConnectCommand;

/// Where Connect's files are, instead of this user's data folder. For tests.
pub const FOLDER_ENV: &str = "OCTAPASS_CONNECT_DIR";
const TOKEN_ENV: &str = "OCTAPASS_CONNECT_TOKEN";

/// A request from the service's thread, answered on the command's.
enum Job {
    Unlocked(oneshot::Sender<bool>),
    Approve(Approval, oneshot::Sender<bool>),
    Items(oneshot::Sender<Result<Vec<ItemRef>, ConnectError>>),
    Read(
        Client,
        Vec<String>,
        oneshot::Sender<Result<Vec<Secret>, ConnectError>>,
    ),
}

struct Channel(mpsc::Sender<Job>);

fn gone() -> ConnectError {
    ConnectError::failed("Connect is shutting down.")
}

impl Channel {
    async fn ask<T: Send + 'static>(
        &self,
        job: impl FnOnce(oneshot::Sender<T>) -> Job,
    ) -> Option<T> {
        let (reply, answer) = oneshot::channel();
        self.0.send(job(reply)).await.ok()?;
        answer.await.ok()
    }
}

impl Backend for Channel {
    fn unlocked(&self) -> BoxFuture<'_, bool> {
        Box::pin(async { self.ask(Job::Unlocked).await.unwrap_or(false) })
    }

    fn approve(&self, request: Approval) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            self.ask(|reply| Job::Approve(request, reply))
                .await
                .unwrap_or(false)
        })
    }

    fn items(&self, _: Client) -> BoxFuture<'_, Result<Vec<ItemRef>, ConnectError>> {
        Box::pin(async { self.ask(Job::Items).await.unwrap_or_else(|| Err(gone())) })
    }

    fn read(
        &self,
        client: Client,
        references: Vec<String>,
    ) -> BoxFuture<'_, Result<Vec<Secret>, ConnectError>> {
        Box::pin(async move {
            self.ask(|reply| Job::Read(client, references, reply))
                .await
                .unwrap_or_else(|| Err(gone()))
        })
    }
}

fn from_cli(error: CliError) -> ConnectError {
    match error.exit {
        Exit::Locked | Exit::SignedOut => ConnectError::locked(),
        Exit::NotFound => ConnectError::not_found(error.message),
        _ => ConnectError::failed(error.message),
    }
}

impl App {
    fn connect_folder(&self) -> Result<PathBuf> {
        match self.context.var(FOLDER_ENV) {
            Some(dir) => Ok(PathBuf::from(dir)),
            None => dirs::data_dir()
                .map(folder)
                .ok_or_else(|| CliError::other("This user has no data folder.")),
        }
    }

    fn connect_endpoint(&self) -> Result<Endpoint> {
        let env = self.context.var(ENDPOINT_ENV);
        Endpoint::find(env.as_deref(), &self.connect_folder()?)
            .ok_or_else(|| CliError::other("Octa Pass Connect isn't running. Start it with `octapass connect serve`, or turn it on in the desktop app."))
    }

    pub(crate) async fn connect(&mut self, command: ConnectCommand) -> Result<Option<i32>> {
        match command {
            ConnectCommand::Serve { port } => self.connect_serve(port).await,
            ConnectCommand::Status => self.connect_status().await,
            ConnectCommand::Clients => self.connect_clients(),
            ConnectCommand::Revoke { id } => {
                let found = Clients::open(&self.connect_folder()?)
                    .revoke(&id)
                    .map_err(|error| CliError::other(error.to_string()))?;
                if !found {
                    return Err(CliError::not_found(format!("No client with id {id}.")));
                }
                self.note("Revoked. Its token no longer works.");
                Ok(None)
            }
            ConnectCommand::Approve { name } => self.connect_approve(name).await,
            ConnectCommand::Pair { name } => {
                let client = ConnectClient::new(self.connect_endpoint()?, None);
                self.note("Waiting for approval…");
                let paired = client.pair(&name).await.map_err(client_error)?;
                self.out_secret(&paired.token, true, true)?;
                Ok(None)
            }
            ConnectCommand::Read { references } => {
                let token = self.context.var(TOKEN_ENV).ok_or_else(|| {
                    CliError::usage(format!("Set {TOKEN_ENV} to this client's token."))
                })?;
                let client = ConnectClient::new(self.connect_endpoint()?, Some(token));
                let secrets = client.read(references).await.map_err(client_error)?;
                if self.global.json {
                    let value = serde_json::to_value(&secrets).expect("secrets serialize");
                    return self.out_json(&value).map(|()| None);
                }
                let mut failed = None;
                for secret in secrets {
                    match (secret.value, secret.error) {
                        (Some(value), _) => self.out_secret(&value, true, true)?,
                        (None, error) => {
                            let error = error.unwrap_or_default();
                            self.note(&format!("{}: {error}", secret.reference));
                            failed = Some(Exit::NotFound as i32);
                        }
                    }
                }
                Ok(failed)
            }
        }
    }

    async fn connect_status(&mut self) -> Result<Option<i32>> {
        let client = ConnectClient::new(self.connect_endpoint()?, None);
        let status = client.status().await.map_err(client_error)?;
        if self.global.json {
            return self.out_json(&status).map(|()| None);
        }
        let unlocked = status["unlocked"] == Value::Bool(true);
        self.out(if unlocked {
            "Connect is running, and the vault is unlocked."
        } else {
            "Connect is running. The vault is locked, so it hands nothing out."
        })?;
        Ok(None)
    }

    fn connect_clients(&mut self) -> Result<Option<i32>> {
        let clients = Clients::open(&self.connect_folder()?).list();
        if self.global.json {
            let value = serde_json::to_value(&clients).expect("clients serialize");
            return self.out_json(&value).map(|()| None);
        }
        if clients.is_empty() {
            self.note("No approved clients.");
            return Ok(None);
        }
        let when = |at: Option<u64>| {
            at.and_then(|at| i64::try_from(at).ok())
                .and_then(|at| time::OffsetDateTime::from_unix_timestamp(at).ok())
                .map_or_else(|| "never".to_owned(), rfc3339)
        };
        let table: Vec<[String; 5]> = clients
            .iter()
            .map(|client| {
                [
                    client.name.clone(),
                    client.program.clone().unwrap_or_else(|| "—".to_owned()),
                    when(client.last_used_at),
                    when(Some(client.expires_at)),
                    client.id.clone(),
                ]
            })
            .collect();
        for line in format_table(["NAME", "PROGRAM", "LAST USED", "EXPIRES", "ID"], &table) {
            self.out(&line)?;
        }
        Ok(None)
    }

    async fn connect_approve(&mut self, name: String) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        if opened.vault.snapshot().session.status == SessionStatus::SignedOut {
            return Err(CliError::signed_out());
        }
        if !self.can_ask_password() {
            return Err(CliError::usage(
                "Approving needs your master password: run it in a terminal, or pass --password-stdin.",
            ));
        }
        let password = self.master_password()?;
        opened.vault.unlock(password).await?;
        let dir = self.connect_folder()?;
        server::private_folder(&dir).map_err(|error| CliError::other(error.to_string()))?;
        let (client, token) = Clients::open(&dir)
            .approve(&name, None, (self.context.clock)())
            .map_err(|error| CliError::other(error.to_string()))?;
        self.note(&format!(
            "Approved {} for {} days. It isn't bound to a program, so keep the token safe.",
            client.name,
            TOKEN_LIFETIME_SECONDS / 86_400
        ));
        self.out_secret(&token, true, true)?;
        Ok(None)
    }

    async fn connect_serve(&mut self, port: Option<u16>) -> Result<Option<i32>> {
        let dir = self.connect_folder()?;
        server::private_folder(&dir).map_err(|error| CliError::other(error.to_string()))?;
        let (send, mut jobs) = mpsc::channel(16);
        let backend: Arc<dyn Backend> = Arc::new(Channel(send));
        let (ready, started) = oneshot::channel::<std::result::Result<String, String>>();
        let folder = dir.clone();
        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready.send(Err(error.to_string()));
                    return;
                }
            };
            let _ = runtime.block_on(listen(port, folder, backend, ready));
        });
        let listening = started
            .await
            .map_err(|_| CliError::other("Connect stopped."))?
            .map_err(CliError::other)?;
        // Ctrl-C and termination: the socket file goes with the process.
        let cleanup = dir.clone();
        let _ = ctrlc::set_handler(move || {
            let _ = fs::remove_file(server::socket_path(&cleanup));
            let _ = fs::remove_file(server::port_path(&cleanup));
            std::process::exit(0);
        });
        self.note(&format!(
            "Octa Pass Connect is listening on {listening}. Approvals are asked here. Ctrl-C stops it."
        ));
        while let Some(job) = jobs.recv().await {
            match job {
                Job::Unlocked(reply) => {
                    let _ = reply.send(self.connect_opened().await.is_ok());
                }
                Job::Approve(approval, reply) => {
                    let answer = self.connect_prompt(&approval);
                    let _ = reply.send(answer);
                }
                Job::Items(reply) => {
                    let _ = reply.send(self.connect_items().await);
                }
                Job::Read(client, references, reply) => {
                    let _ = reply.send(self.connect_read(client, references).await);
                }
            }
        }
        Ok(None)
    }

    fn connect_prompt(&mut self, approval: &Approval) -> bool {
        if !self.context.terminal.interactive() {
            self.note(&format!(
                "Refused \"{}\": there's no terminal to ask in. Use `octapass connect approve`.",
                approval.name
            ));
            return false;
        }
        let peer = &approval.peer;
        let program = match (&peer.program, peer.pid) {
            (Some(program), Some(pid)) => format!("{program} (process {pid})"),
            (Some(program), None) => program.clone(),
            _ if peer.loopback => {
                "unknown: over 127.0.0.1 the system can't say which program this is".to_owned()
            }
            _ => "unknown".to_owned(),
        };
        self.note(&format!(
            "A program wants to read secrets through Octa Pass Connect.\n  It calls itself: {} (anyone can claim any name)\n  Program: {program}",
            approval.name
        ));
        match self.context.terminal.ask("Allow it? [y/N] ") {
            Ok(answer) => matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"),
            Err(_) => false,
        }
    }

    /// The vault, opened from the keyring session alone. Doesn't extend the session.
    async fn connect_opened(&mut self) -> Result<Opened> {
        let opened = self.open_with(DEFAULT_IDLE, false)?;
        match opened.vault.snapshot().session.status {
            SessionStatus::SignedOut => return Err(CliError::signed_out()),
            SessionStatus::Unlocked => {}
            SessionStatus::Locked => opened
                .vault
                .unlock_with_device()
                .await
                .map_err(|_| CliError::locked())?,
        }
        self.sync(&opened.vault).await?;
        Ok(opened)
    }

    async fn connect_items(&mut self) -> Result<Vec<ItemRef>, ConnectError> {
        let opened = self.connect_opened().await.map_err(from_cli)?;
        let vaults = opened.vaults().map_err(|e| from_cli(e.into()))?;
        Ok(opened
            .live_items()
            .map_err(|e| from_cli(e.into()))?
            .iter()
            .map(|item| ItemRef {
                vault: items::vault_name(&vaults, &item.vault_id).to_owned(),
                vault_id: item.vault_id.clone(),
                item: item.title().to_owned(),
                item_id: item.id.clone(),
                item_type: item
                    .overview
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                fields: field_names(item),
            })
            .collect())
    }

    async fn connect_read(
        &mut self,
        client: Client,
        references: Vec<String>,
    ) -> Result<Vec<Secret>, ConnectError> {
        let opened = self.connect_opened().await.map_err(from_cli)?;
        let account = opened.account_id().ok_or_else(ConnectError::locked)?;
        let queue = Queue::open(&self.connect_folder().map_err(from_cli)?, &account);
        let now = (self.context.clock)();
        let mut secrets = Vec::with_capacity(references.len());
        for reference in references {
            let resolved = if crate::integrations::looks_like_reference(&reference) {
                items::parse_reference(&reference).and_then(|parsed| self.resolve(&opened, &parsed))
            } else {
                Err(CliError::usage(format!(
                    "\"{reference}\" isn't a reference."
                )))
            };
            match resolved {
                Ok(field) => {
                    // On disk first: no entry, no secret.
                    record(&opened, &queue, &client, &reference, now)?;
                    secrets.push(Secret {
                        reference,
                        value: Some(field.value),
                        error: None,
                    });
                }
                // A locked vault ends the request; a missing item is that reference's answer.
                Err(error) if matches!(error.exit, Exit::Locked | Exit::SignedOut) => {
                    return Err(from_cli(error));
                }
                Err(error) => secrets.push(Secret {
                    reference,
                    value: None,
                    error: Some(error.message),
                }),
            }
        }
        self.save_live_tokens(&opened).await.map_err(from_cli)?;
        send_queue(&opened, &queue).await;
        Ok(secrets)
    }
}

fn record(
    opened: &Opened,
    queue: &Queue,
    client: &Client,
    reference: &str,
    at: u64,
) -> Result<(), ConnectError> {
    let entry = Entry {
        at,
        client_id: client.id.clone(),
        client_name: client.name.clone(),
        reference: reference.to_owned(),
    };
    let bytes = serde_json::to_vec(&entry).expect("entries serialize");
    let sealed = opened
        .vault
        .seal_audit_detail(&bytes)
        .map_err(|error| from_cli(error.into()))?;
    queue.push(&sealed).map_err(|error| {
        ConnectError::failed(format!(
            "Can't record this in the security log, so it wasn't handed out: {error}"
        ))
    })
}

/// Sends what's waiting. Offline it stays queued for the next read.
async fn send_queue(opened: &Opened, queue: &Queue) {
    loop {
        let Ok(batch) = queue.peek() else { return };
        if batch.is_empty() {
            return;
        }
        let count = batch.len();
        if opened.vault.record_connect_events(batch).await.is_err() || queue.remove(count).is_err()
        {
            return;
        }
        if count < BATCH {
            return;
        }
    }
}

fn client_error(error: ClientError) -> CliError {
    match error {
        ClientError::Refused {
            status: 423,
            message,
            ..
        } => CliError::new(Exit::Locked, message),
        ClientError::Refused {
            status: 404,
            message,
            ..
        } => CliError::not_found(message),
        other => CliError::other(other.to_string()),
    }
}

/// Binds and serves. Tells `ready` where, or why it couldn't.
async fn listen(
    port: Option<u16>,
    folder: PathBuf,
    backend: Arc<dyn Backend>,
    ready: oneshot::Sender<std::result::Result<String, String>>,
) -> io::Result<()> {
    #[cfg(unix)]
    if port.is_none() {
        let listener = match server::bind_socket(&folder).await {
            Ok(listener) => listener,
            Err(error) => {
                let _ = ready.send(Err(error.to_string()));
                return Ok(());
            }
        };
        let path = server::socket_path(&folder);
        let _ = ready.send(Ok(format!("unix:{}", path.display())));
        return server::serve_socket(listener, &folder, backend, std::future::pending()).await;
    }
    let listener = match server::bind_loopback(port.unwrap_or(0)).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return Ok(());
        }
    };
    let address = listener.local_addr()?;
    let _ = ready.send(Ok(format!("http://{address}")));
    server::serve_loopback(listener, &folder, backend, std::future::pending()).await
}
