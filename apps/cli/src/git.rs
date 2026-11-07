//! Git: `git-credential-octapass` and commit signing with keys from the vault (plan 16).
//!
//! The credential helper is stricter than autofill: Git names a host, so a login is used only for
//! that exact host, scheme and port, and passwords are never sent over `http://` unless the login
//! itself says `http://`.
//!
//! `octapass-git-sign` stands in for `ssh-keygen` and `gpg`: Git runs it with their arguments.
//! Signing with a key from the vault happens here, on the device; anything else (verifying, or a
//! key that isn't in the vault) goes to the real program.

use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as Process;

use octapass_core::tools::{gpg, ssh};
use octapass_desktop_vault::model::{Item, ItemDraft, now, unix_ms};
use reqwest::Url;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cli::GitCommand;
use crate::error::{CliError, Result};
use crate::gpg::ITEM_TYPE as GPG_KEY;
use crate::session::DEFAULT_IDLE;
use crate::{App, Opened};

/// What Git tells a credential helper.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CredentialRequest {
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
}

impl CredentialRequest {
    /// `key=value` lines up to an empty line or the end. Unknown keys are ignored, as Git asks.
    pub fn read(input: &mut impl BufRead) -> std::io::Result<Self> {
        let mut request = Self::default();
        let mut line = Zeroizing::new(String::new());
        loop {
            line.clear();
            if input.read_line(&mut line)? == 0 {
                break;
            }
            let text = line.trim_end_matches(['\r', '\n']);
            if text.is_empty() {
                break;
            }
            let Some((key, value)) = text.split_once('=') else {
                continue;
            };
            match key {
                "protocol" => request.protocol = value.to_owned(),
                "host" => request.host = value.to_owned(),
                "path" => request.path = value.to_owned(),
                "username" => request.username = Some(value.to_owned()),
                "password" => request.password = Some(Zeroizing::new(value.to_owned())),
                _ => {}
            }
        }
        Ok(request)
    }

    /// The URL Git is talking to, for comparing with a login's.
    fn url(&self) -> Option<Url> {
        Url::parse(&format!("{}://{}/{}", self.protocol, self.host, self.path)).ok()
    }
}

/// How well a saved URL fits: `None` when it's another site, more for a longer path match. A URL
/// without a scheme is taken as `https://`.
pub fn url_score(saved: &str, wanted: &Url) -> Option<usize> {
    let saved = saved.trim();
    let saved = if saved.contains("://") {
        Url::parse(saved).ok()?
    } else {
        Url::parse(&format!("https://{saved}")).ok()?
    };
    if saved.scheme() != wanted.scheme()
        || saved.port_or_known_default() != wanted.port_or_known_default()
    {
        return None;
    }
    let host = saved.host_str()?.to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    if host != wanted.host_str()?.to_ascii_lowercase() {
        return None;
    }
    let path = saved.path().trim_end_matches('/').trim_end_matches(".git");
    let on_path = wanted.path().trim_end_matches('/').trim_end_matches(".git");
    // Git leaves the path out unless `credential.useHttpPath` is set: then any login for the host
    // may answer. With one, a login saved for a repository only answers for that repository.
    if on_path.is_empty() || path.is_empty() {
        return Some(0);
    }
    (on_path == path || on_path.starts_with(&format!("{path}/"))).then_some(path.len())
}

fn urls_of(item: &Item) -> Vec<&str> {
    item.overview
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// The secret Git should send: a custom field called "Git token", for sites that take a token
/// instead of the password, otherwise the password.
fn git_secret(item: &Item) -> Option<String> {
    let token = item
        .details
        .get("customFields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|field| {
            field
                .get("label")
                .and_then(Value::as_str)
                .is_some_and(|label| label.trim().eq_ignore_ascii_case("git token"))
        })
        .and_then(|field| field.get("value").and_then(Value::as_str));
    token
        .or_else(|| item.detail("password"))
        .filter(|secret| !secret.is_empty())
        .map(str::to_owned)
}

/// The logins that answer `request`, best first. With a username, only that username's.
fn matching_logins<'a>(
    items: &'a [Item],
    request: &CredentialRequest,
    wanted: &Url,
) -> Vec<&'a Item> {
    let mut found: Vec<(usize, &Item)> = items
        .iter()
        .filter(|item| item.is_login_like() && git_secret(item).is_some())
        .filter(|item| {
            request
                .username
                .as_deref()
                .is_none_or(|name| item.detail("username") == Some(name))
        })
        .filter_map(|item| {
            let score = urls_of(item)
                .into_iter()
                .filter_map(|url| url_score(url, wanted))
                .max()?;
            Some((score, item))
        })
        .collect();
    let best = found.iter().map(|(score, _)| *score).max().unwrap_or(0);
    found.retain(|(score, _)| *score == best);
    found.into_iter().map(|(_, item)| item).collect()
}

/// A value that can't go in Git's line protocol: a line break would let a value add its own keys
/// (CVE-2020-5260 is this bug in Git itself).
fn safe_value(value: &str) -> bool {
    !value.contains(['\n', '\r', '\0'])
}

/// A public key's `type blob`, from a `.pub` file or the temporary file `key::` becomes.
fn public_key_in(text: &str) -> Option<String> {
    let mut parts = text.split_whitespace();
    let (kind, blob) = (parts.next()?, parts.next()?);
    (kind.starts_with("ssh-") || kind.starts_with("ecdsa-")).then(|| format!("{kind} {blob}"))
}

/// `ssh-keygen -Y sign` as Git runs it.
#[derive(Debug, Default, PartialEq, Eq)]
struct SshSign {
    namespace: String,
    key_file: PathBuf,
    files: Vec<PathBuf>,
}

fn parse_ssh_sign(args: &[String]) -> Option<SshSign> {
    let mut sign = SshSign::default();
    let mut operation = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-Y" => operation = args.next().cloned(),
            "-n" => sign.namespace.clone_from(args.next()?),
            "-f" => sign.key_file = PathBuf::from(args.next()?),
            "-O" => {
                args.next()?;
            }
            "-U" | "-q" => {}
            other if other.starts_with('-') => return None,
            other => sign.files.push(PathBuf::from(other)),
        }
    }
    (operation.as_deref() == Some("sign") && !sign.namespace.is_empty()).then_some(sign)
}

/// `gpg --status-fd=2 -bsau <key>` as Git runs it.
#[derive(Debug, Default, PartialEq, Eq)]
struct GpgSign {
    key: String,
    status_fd: Option<u32>,
}

fn parse_gpg_sign(args: &[String]) -> Option<GpgSign> {
    let mut sign = GpgSign::default();
    let mut detached = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if let Some(fd) = arg.strip_prefix("--status-fd=") {
            sign.status_fd = fd.parse().ok();
        } else if arg == "--status-fd" {
            sign.status_fd = args.next()?.parse().ok();
        } else if let Some(key) = arg.strip_prefix("--local-user=") {
            sign.key = key.to_owned();
        } else if arg == "--local-user" {
            sign.key.clone_from(args.next()?);
        } else if arg == "--detach-sign" {
            detached = true;
        } else if arg.starts_with("--") {
            match arg.as_str() {
                "--armor" | "--sign" | "--no-tty" | "--batch" => {}
                other if other.starts_with("--keyid-format") => {}
                _ => return None,
            }
        } else {
            // Short flags, possibly bundled (`-bsau KEY`); anything else isn't for us.
            let flags = arg.strip_prefix('-')?;
            if !flags.bytes().all(|flag| b"bsau".contains(&flag)) {
                return None;
            }
            detached = detached || flags.contains('b');
            if flags.ends_with('u') {
                sign.key.clone_from(args.next()?);
            }
        }
    }
    (detached && !sign.key.is_empty()).then_some(sign)
}

/// `user.signingkey` names a key by fingerprint or id (hex, perhaps `0x…` or with a `!`), or by
/// the committer's `Name <email>`.
fn gpg_key_matches(item: &Item, query: &str) -> bool {
    let query = query.trim().trim_end_matches('!');
    let hex = query.strip_prefix("0x").unwrap_or(query).to_uppercase();
    let is_hex = hex.len() >= 16 && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
    let fingerprints = item
        .details
        .get("fingerprints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    if is_hex {
        return fingerprints
            .into_iter()
            .any(|fingerprint| fingerprint.ends_with(&hex));
    }
    let user = item.detail("userId").unwrap_or_default();
    let email = query.rsplit_once('<').map_or(query, |(_, email)| email);
    let email = email.trim_end_matches('>').trim();
    !email.is_empty() && user.to_lowercase().contains(&email.to_lowercase())
}

fn sibling(name: &str) -> Option<PathBuf> {
    let name = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let path = std::env::current_exe().ok()?.parent()?.join(name);
    path.exists().then_some(path)
}

/// How a program goes in Git's settings: its full path when it's next to this one, so `PATH`
/// doesn't matter.
fn program(name: &str) -> String {
    sibling(name).map_or(name.to_owned(), |path| path.display().to_string())
}

impl App {
    pub(crate) async fn git(&mut self, command: GitCommand) -> Result<Option<i32>> {
        match command {
            GitCommand::Credential { store, operation } => {
                self.git_credential(&operation, store).await
            }
            GitCommand::Sign { args } => self.git_sign(args).await,
            GitCommand::Setup {
                global,
                signing_key,
                agent,
                no_credentials,
                dry_run,
            } => {
                self.git_setup(global, signing_key, agent, no_credentials, dry_run)
                    .await
            }
        }
    }

    /// Unlocks for a helper Git started: its stdin belongs to Git, so a password is asked on the
    /// terminal itself, unless `GIT_TERMINAL_PROMPT=0`. A password typed here starts a session.
    async fn helper_unlocked(&mut self, opened: &Opened) -> Result<()> {
        self.ask_on_tty = self.context.var("GIT_TERMINAL_PROMPT").as_deref() != Some("0");
        self.unlocked(opened).await?;
        if self.password.is_some() {
            self.keep_unlocked(opened).await.ok();
        }
        Ok(())
    }

    async fn git_credential(&mut self, operation: &str, store: bool) -> Result<Option<i32>> {
        let request = CredentialRequest::read(&mut self.context.stdin)
            .map_err(|error| CliError::usage(format!("Couldn't read Git's request: {error}")))?;
        match operation {
            "get" => self.credential_get(&request).await,
            "store" if store => self.credential_store(&request).await,
            // A rejected password says nothing about the login, so nothing is ever deleted.
            "store" | "erase" => Ok(None),
            other => Err(CliError::usage(format!(
                "Git asked for `{other}`; this helper knows get, store and erase."
            ))),
        }
    }

    async fn credential_get(&mut self, request: &CredentialRequest) -> Result<Option<i32>> {
        let Some(wanted) = request.url() else {
            return Ok(None);
        };
        if !matches!(wanted.scheme(), "https" | "http") {
            return Ok(None);
        }
        let opened = self.open(DEFAULT_IDLE)?;
        self.helper_unlocked(&opened).await?;
        let items = opened.vault.live_items()?;
        let found = matching_logins(&items, request, &wanted);
        let item = match found.as_slice() {
            [] => return Ok(None),
            [item] => *item,
            many => {
                let titles: Vec<&str> = many.iter().map(|item| item.title()).collect();
                self.note(&format!(
                    "octapass: {} logins fit {} ({}). Put the username in the remote's URL, or set credential.username.",
                    many.len(),
                    request.host,
                    titles.join(", ")
                ));
                return Ok(None);
            }
        };
        let username = item
            .detail("username")
            .map(str::to_owned)
            .or_else(|| request.username.clone());
        let password = git_secret(item).map(Zeroizing::new);
        let (Some(username), Some(password)) = (username, password) else {
            return Ok(None);
        };
        if !safe_value(&username) || !safe_value(&password) {
            return Err(CliError::other(format!(
                "“{}” has a line break in its username or password, which Git can't take.",
                item.title()
            )));
        }
        let answer = Zeroizing::new(format!("username={username}\npassword={}\n", *password));
        self.context
            .stdout
            .write_all(answer.as_bytes())
            .map_err(crate::output_error)?;
        Ok(None)
    }

    /// Saves what worked, when asked to with `--store`: a new login, or a changed password on the
    /// one login that fits.
    async fn credential_store(&mut self, request: &CredentialRequest) -> Result<Option<i32>> {
        let (Some(wanted), Some(username), Some(password)) = (
            request.url(),
            request.username.as_deref(),
            request.password.as_deref(),
        ) else {
            return Ok(None);
        };
        let opened = self.open(DEFAULT_IDLE)?;
        self.helper_unlocked(&opened).await?;
        let items = opened.vault.live_items()?;
        let found = matching_logins(&items, request, &wanted);
        let draft = match found.as_slice() {
            [] => {
                let vault_id = self.writable_vault(&opened, None)?;
                let origin = wanted.origin().ascii_serialization();
                ItemDraft {
                    id: None,
                    vault_id,
                    revision: None,
                    overview: json!({
                        "schemaVersion": 1, "type": "login", "title": request.host,
                        "subtitle": username, "urls": [origin],
                    }),
                    details: json!({
                        "schemaVersion": 1, "username": username, "password": password.as_str(),
                    }),
                }
            }
            [item] if git_secret(item).as_deref() == Some(password.as_str()) => return Ok(None),
            [item] if item.detail("password").is_some() => {
                let mut details = item.details.clone();
                details["password"] = json!(password.as_str());
                ItemDraft {
                    id: Some(item.id.clone()),
                    vault_id: item.vault_id.clone(),
                    revision: Some(item.revision),
                    overview: item.overview.clone(),
                    details,
                }
            }
            _ => return Ok(None),
        };
        opened.vault.save_item(draft).await?;
        Ok(None)
    }

    async fn git_sign(&mut self, args: Vec<String>) -> Result<Option<i32>> {
        if args.iter().any(|arg| arg == "-Y") {
            let Some(sign) = parse_ssh_sign(&args) else {
                return self.real_program("ssh-keygen", &args);
            };
            let Some(public) = fs::read_to_string(&sign.key_file)
                .ok()
                .as_deref()
                .and_then(public_key_in)
            else {
                return self.real_program("ssh-keygen", &args);
            };
            let opened = self.open(DEFAULT_IDLE)?;
            self.helper_unlocked(&opened).await?;
            let found = opened.vault.live_items()?.into_iter().find(|item| {
                item.overview.get("type").and_then(Value::as_str) == Some("sshKey")
                    && item.detail("publicKey").map(str::trim) == Some(public.as_str())
            });
            drop(opened);
            let Some(item) = found else {
                return self.real_program("ssh-keygen", &args);
            };
            return self.ssh_sign_files(&sign, &item);
        }
        let Some(sign) = parse_gpg_sign(&args) else {
            return self.real_program("gpg", &args);
        };
        let opened = self.open(DEFAULT_IDLE)?;
        self.helper_unlocked(&opened).await?;
        let found = self
            .gpg_items(&opened)?
            .into_iter()
            .find(|item| gpg_key_matches(item, &sign.key));
        drop(opened);
        let Some(item) = found else {
            return self.real_program("gpg", &args);
        };
        self.gpg_sign_stdin(&sign, &item)
    }

    fn ssh_sign_files(&mut self, sign: &SshSign, item: &Item) -> Result<Option<i32>> {
        let key = item
            .detail("privateKey")
            .map(|key| Zeroizing::new(key.to_owned()))
            .ok_or_else(|| {
                CliError::not_found(format!("“{}” has no private key.", item.title()))
            })?;
        let refused = |item: &Item, error: octapass_core::Error| {
            CliError::other(format!("“{}” can't sign: {error}.", item.title()))
        };
        if sign.files.is_empty() {
            let mut data = Vec::new();
            self.context
                .stdin
                .read_to_end(&mut data)
                .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
            let armored = ssh::sign_sshsig(&key, &sign.namespace, &data)
                .map_err(|error| refused(item, error))?;
            self.context
                .stdout
                .write_all(armored.as_bytes())
                .map_err(crate::output_error)?;
            return Ok(None);
        }
        for path in &sign.files {
            let data = fs::read(path).map_err(|error| {
                CliError::usage(format!("Can't read {}: {error}", path.display()))
            })?;
            let armored = ssh::sign_sshsig(&key, &sign.namespace, &data)
                .map_err(|error| refused(item, error))?;
            let mut target = path.as_os_str().to_owned();
            target.push(".sig");
            fs::write(Path::new(&target), armored)
                .map_err(|error| CliError::other(format!("Can't write the signature: {error}")))?;
        }
        Ok(None)
    }

    fn gpg_sign_stdin(&mut self, sign: &GpgSign, item: &Item) -> Result<Option<i32>> {
        let key = item
            .detail("privateKey")
            .map(|key| Zeroizing::new(key.to_owned()))
            .ok_or_else(|| {
                CliError::not_found(format!("“{}” has no private key.", item.title()))
            })?;
        let mut data = Vec::new();
        self.context
            .stdin
            .read_to_end(&mut data)
            .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
        let armored = gpg::sign_detached(&key, item.detail("passphrase"), &data)
            .map_err(|error| CliError::other(format!("“{}” can't sign: {error}.", item.title())))?;
        let (fingerprint, algorithm) = gpg::signing_key(&key)
            .map_err(|error| CliError::other(format!("“{}”: {error}.", item.title())))?;
        self.context
            .stdout
            .write_all(armored.as_bytes())
            .map_err(crate::output_error)?;
        // Git looks for SIG_CREATED on the status descriptor, and only there.
        let status = format!(
            "[GNUPG:] BEGIN_SIGNING H10\n[GNUPG:] SIG_CREATED D {algorithm} 10 00 {} {fingerprint}\n",
            unix_ms(now()) / 1000
        );
        let written = match sign.status_fd {
            Some(1) => self.context.stdout.write_all(status.as_bytes()),
            Some(2) => self.context.stderr.write_all(status.as_bytes()),
            _ => Ok(()),
        };
        written.map_err(crate::output_error)?;
        Ok(None)
    }

    /// Hands over to `ssh-keygen` or `gpg`: verifying, and keys that aren't in the vault.
    fn real_program(&mut self, name: &str, args: &[String]) -> Result<Option<i32>> {
        let mut process = Process::new(name);
        process
            .args(args)
            .env_clear()
            .envs(self.context.env.iter().map(|(key, value)| (key, value)))
            .current_dir(&self.context.cwd);
        let _ = self.context.stdout.flush();
        let _ = self.context.stderr.flush();
        let exec = self.exec.take().expect("runs once");
        self.command_finished(exec(process), name)
    }

    fn git_config(&mut self, global: bool, args: &[&str]) -> Result<std::process::Output> {
        let mut process = Process::new("git");
        process.arg("config");
        if global {
            process.arg("--global");
        }
        process
            .args(args)
            .env_clear()
            .envs(self.context.env.iter().map(|(key, value)| (key, value)))
            .current_dir(&self.context.cwd)
            .output()
            .map_err(|error| CliError::other(format!("Can't run git: {error}")))
    }

    async fn git_setup(
        &mut self,
        global: bool,
        signing_key: Option<String>,
        agent: bool,
        no_credentials: bool,
        dry_run: bool,
    ) -> Result<Option<i32>> {
        let mut settings: Vec<(&str, String)> = Vec::new();
        if let Some(query) = &signing_key {
            let opened = self.opened_unlocked().await?;
            let item = self.find_item(&opened, query, None)?;
            match item.overview.get("type").and_then(Value::as_str) {
                Some("sshKey") => {
                    let public = item
                        .detail("publicKey")
                        .unwrap_or_default()
                        .trim()
                        .to_owned();
                    if public.is_empty() {
                        return Err(CliError::not_found(format!(
                            "“{}” has no public key.",
                            item.title()
                        )));
                    }
                    settings.push(("gpg.format", "ssh".into()));
                    settings.push(("user.signingkey", format!("key::{public}")));
                    if !agent {
                        settings.push(("gpg.ssh.program", program("octapass-git-sign")));
                    }
                }
                Some(GPG_KEY) if agent => {
                    return Err(CliError::usage(
                        "The SSH agent serves SSH keys. Leave out --agent for an OpenPGP key.",
                    ));
                }
                Some(GPG_KEY) => {
                    let fingerprint = item.detail("fingerprint").unwrap_or_default().to_owned();
                    settings.push(("gpg.format", "openpgp".into()));
                    settings.push(("user.signingkey", fingerprint));
                    settings.push(("gpg.program", program("octapass-git-sign")));
                }
                _ => {
                    return Err(CliError::usage(format!(
                        "“{}” isn't an SSH or OpenPGP key.",
                        item.title()
                    )));
                }
            }
            settings.push(("commit.gpgsign", "true".into()));
        }
        let helper = program("git-credential-octapass");
        let helper = if helper.contains(' ') {
            format!("\"{helper}\"")
        } else {
            helper
        };
        let add_helper = !no_credentials
            && !String::from_utf8_lossy(
                &self
                    .git_config(global, &["--get-all", "credential.helper"])?
                    .stdout,
            )
            .contains("octapass");
        if dry_run {
            if add_helper {
                self.out(&format!("credential.helper {helper}"))?;
            }
            for (key, value) in &settings {
                self.out(&format!("{key} {value}"))?;
            }
            return Ok(None);
        }
        if add_helper {
            self.set_config(global, &["--add", "credential.helper", &helper])?;
        }
        for (key, value) in &settings {
            self.set_config(global, &[key, value])?;
        }
        if agent {
            // A program left by an earlier setup would skip the agent.
            self.git_config(global, &["--unset", "gpg.ssh.program"])?;
            self.note("Commits are signed by the SSH agent in the Octa Pass desktop app, which asks you each time. Point SSH_AUTH_SOCK at it (Settings → SSH agent).");
        }
        self.note("Git now uses Octa Pass.");
        Ok(None)
    }

    fn set_config(&mut self, global: bool, args: &[&str]) -> Result<()> {
        let output = self.git_config(global, args)?;
        if output.status.success() {
            return Ok(());
        }
        Err(CliError::other(format!(
            "git config failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    fn login(id: &str, urls: &[&str], username: &str, password: &str) -> Item {
        Item {
            id: id.into(),
            vault_id: "v".into(),
            revision: 1,
            created_at: "t".into(),
            updated_at: "t".into(),
            deleted_at: None,
            overview: json!({ "type": "login", "title": id, "urls": urls }),
            details: json!({ "username": username, "password": password }),
        }
    }

    #[test]
    fn requests_are_key_value_lines() {
        let text = "protocol=https\nhost=github.com\npath=octap-app/octapass.git\nusername=ada\nwwwauth[]=Basic\n\nignored=1\n";
        let request = CredentialRequest::read(&mut text.as_bytes()).unwrap();
        assert_eq!(request.protocol, "https");
        assert_eq!(request.host, "github.com");
        assert_eq!(request.path, "octap-app/octapass.git");
        assert_eq!(request.username.as_deref(), Some("ada"));
        assert_eq!(request.password, None);
    }

    #[test]
    fn urls_match_exactly_by_host_scheme_and_port() {
        let git = url("https://github.com/");
        assert_eq!(url_score("https://github.com/login", &git), Some(0));
        assert_eq!(url_score("github.com", &git), Some(0));
        assert_eq!(url_score("https://www.github.com", &git), Some(0));
        assert_eq!(url_score("https://GitHub.com:443/", &git), Some(0));
        for other in [
            "https://github.com.evil.example",
            "https://evil.example/github.com",
            "https://gist.github.com",
            "http://github.com",
            "https://github.com:8443",
            "not a url at all",
        ] {
            assert_eq!(url_score(other, &git), None, "{other}");
        }
        // Self-hosted on a port.
        assert_eq!(
            url_score(
                "https://git.example:8443",
                &url("https://git.example:8443/")
            ),
            Some(0)
        );
        // Unencrypted only when the login itself says so.
        assert_eq!(
            url_score("https://intranet", &url("http://intranet/")),
            None
        );
        assert_eq!(
            url_score("http://intranet", &url("http://intranet/")),
            Some(0)
        );
    }

    #[test]
    fn paths_narrow_a_login_when_git_sends_one() {
        let repo = url("https://git.example/team/app.git");
        assert_eq!(url_score("https://git.example/team/app", &repo), Some(9));
        assert_eq!(url_score("https://git.example/team", &repo), Some(5));
        assert_eq!(url_score("https://git.example/other", &repo), None);
        assert_eq!(
            url_score("https://git.example/team/application", &repo),
            None
        );
        assert_eq!(url_score("https://git.example/", &repo), Some(0));
    }

    #[test]
    fn the_most_specific_login_answers() {
        let items = vec![
            login("host", &["https://git.example"], "a", "1"),
            login("repo", &["https://git.example/team/app"], "b", "2"),
            login("other", &["https://example.org"], "c", "3"),
        ];
        let wanted = url("https://git.example/team/app.git");
        let request = CredentialRequest::default();
        let found = matching_logins(&items, &request, &wanted);
        assert_eq!(
            found.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            ["repo"]
        );
        let request = CredentialRequest {
            username: Some("a".into()),
            ..CredentialRequest::default()
        };
        let found = matching_logins(&items, &request, &wanted);
        assert_eq!(
            found.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            ["host"]
        );
    }

    #[test]
    fn a_git_token_wins_over_the_password() {
        let mut item = login("x", &[], "a", "password");
        assert_eq!(git_secret(&item).as_deref(), Some("password"));
        item.details["customFields"] =
            json!([{ "label": "Git token", "value": "ghp_123", "hidden": true }]);
        assert_eq!(git_secret(&item).as_deref(), Some("ghp_123"));
    }

    #[test]
    fn values_with_line_breaks_are_refused() {
        assert!(safe_value("hunter2"));
        assert!(!safe_value("a\nhost=evil.example"));
        assert!(!safe_value("a\rb"));
        assert!(!safe_value("a\0b"));
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn git_s_ssh_keygen_arguments() {
        let sign = parse_ssh_sign(&strings(&[
            "-Y",
            "sign",
            "-n",
            "git",
            "-f",
            "/tmp/key",
            "-U",
            "/tmp/buffer",
        ]))
        .unwrap();
        assert_eq!(sign.namespace, "git");
        assert_eq!(sign.key_file, PathBuf::from("/tmp/key"));
        assert_eq!(sign.files, [PathBuf::from("/tmp/buffer")]);
        assert_eq!(
            parse_ssh_sign(&strings(&["-Y", "verify", "-n", "git", "-f", "x"])),
            None
        );
        assert_eq!(
            parse_ssh_sign(&strings(&["-Y", "sign", "-n", "git", "-Z", "x"])),
            None
        );
    }

    #[test]
    fn git_s_gpg_arguments() {
        assert_eq!(
            parse_gpg_sign(&strings(&["--status-fd=2", "-bsau", "ABCD"])).unwrap(),
            GpgSign {
                key: "ABCD".into(),
                status_fd: Some(2)
            }
        );
        assert_eq!(
            parse_gpg_sign(&strings(&["--detach-sign", "--armor", "--local-user=x"]))
                .unwrap()
                .key,
            "x"
        );
        assert_eq!(
            parse_gpg_sign(&strings(&[
                "--status-fd=1",
                "--keyid-format=long",
                "--verify",
                "sig",
                "-"
            ])),
            None
        );
    }

    #[test]
    fn gpg_keys_by_fingerprint_id_or_email() {
        let item = Item {
            id: "i".into(),
            vault_id: "v".into(),
            revision: 1,
            created_at: "t".into(),
            updated_at: "t".into(),
            deleted_at: None,
            overview: json!({ "type": "gpgKey", "title": "Commits" }),
            details: json!({
                "userId": "Ada <ada@example.com>",
                "fingerprints": ["AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555", "FFFF1111BBBB2222CCCC3333DDDD4444EEEE6666"],
            }),
        };
        assert!(gpg_key_matches(
            &item,
            "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        ));
        assert!(gpg_key_matches(&item, "0xdddd4444eeee6666"));
        assert!(gpg_key_matches(&item, "DDDD4444EEEE5555!"));
        assert!(gpg_key_matches(&item, "Ada Lovelace <ada@example.com>"));
        assert!(!gpg_key_matches(&item, "1111222233334444"));
        assert!(!gpg_key_matches(&item, "someone@example.com"));
    }

    #[test]
    fn public_keys_in_files() {
        assert_eq!(
            public_key_in("ssh-ed25519 AAAA ada@example.com\n").as_deref(),
            Some("ssh-ed25519 AAAA")
        );
        assert_eq!(
            public_key_in("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"),
            None
        );
    }
}
