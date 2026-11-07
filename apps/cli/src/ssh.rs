//! `octapass ssh`: SSH keys in the vault (plan 16). Keys are made and read by the core on this
//! device; private keys are written only with permissions for the user alone, and never over an
//! existing file unless asked.

use std::fs;
use std::path::{Path, PathBuf};

use octapass_api::{VaultRole, VaultType};
use octapass_core::Error as CoreError;
use octapass_core::tools::ssh::{self, SshKey, SshKeyKind};
use octapass_desktop_vault::model::{Item, ItemDraft};
use rand_core::OsRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cli::{KeyType, SshCommand};
use crate::error::{CliError, Result};
use crate::session::DEFAULT_IDLE;
use crate::{App, Opened, format_table, items};

/// Key files are a few kilobytes; `--scan` skips anything much bigger.
const MAX_KEY_FILE: u64 = 64 * 1024;

impl From<KeyType> for SshKeyKind {
    fn from(kind: KeyType) -> Self {
        match kind {
            KeyType::Ed25519 => SshKeyKind::Ed25519,
            KeyType::EcdsaP256 => SshKeyKind::EcdsaP256,
            KeyType::EcdsaP384 => SshKeyKind::EcdsaP384,
            KeyType::Rsa3072 => SshKeyKind::Rsa3072,
            KeyType::Rsa4096 => SshKeyKind::Rsa4096,
        }
    }
}

/// What a key file's problem means for the person running the command.
fn key_error(path: &Path, error: CoreError) -> CliError {
    let name = path.display();
    CliError::usage(match error {
        CoreError::SshPassphraseRequired | CoreError::WrongPassphrase => {
            format!("{name}: wrong passphrase.")
        }
        CoreError::SshPublicKeyOnly => {
            format!("{name} is a public key. Import the private key file, without .pub.")
        }
        CoreError::UnsupportedSshKey => format!(
            "{name}: Octa Pass can't read this kind of key file. Convert PuTTY or 3DES keys with ssh-keygen first."
        ),
        _ => format!("{name} isn't an SSH private key, or it's damaged."),
    })
}

fn details(item: &Item, field: &str) -> String {
    item.detail(field).unwrap_or_default().to_owned()
}

impl App {
    pub(crate) async fn ssh(&mut self, command: SshCommand) -> Result<Option<i32>> {
        match command {
            SshCommand::List { vault } => self.ssh_list(vault).await,
            SshCommand::Generate {
                key_type,
                title,
                comment,
                vault,
                passphrase,
            } => {
                self.ssh_generate(key_type.into(), title, comment, vault, passphrase)
                    .await
            }
            SshCommand::Import { files, scan, vault } => self.ssh_import(files, scan, vault).await,
            SshCommand::Export {
                item,
                out,
                passphrase,
                no_passphrase,
                force,
                vault,
            } => {
                self.ssh_export(item, out, passphrase, no_passphrase, force, vault)
                    .await
            }
            SshCommand::Public { item, vault } => self.ssh_public(item, vault).await,
        }
    }

    pub(crate) async fn opened_unlocked(&mut self) -> Result<Opened> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        Ok(opened)
    }

    /// The SSH keys, oldest first, in `vault` when given.
    fn ssh_items(&self, opened: &Opened, vault: Option<&str>) -> Result<Vec<Item>> {
        let vaults = opened.vault.list_vaults()?;
        let only = vault
            .map(|query| items::find_vault(&vaults, query).map(|vault| vault.id.clone()))
            .transpose()?;
        let mut keys: Vec<Item> = opened
            .vault
            .live_items()?
            .into_iter()
            .filter(|item| item.overview.get("type").and_then(Value::as_str) == Some("sshKey"))
            .filter(|item| only.as_ref().is_none_or(|id| &item.vault_id == id))
            .collect();
        keys.sort_by(|a, b| {
            a.title()
                .to_lowercase()
                .cmp(&b.title().to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(keys)
    }

    /// One SSH key by title or id.
    fn ssh_item(&self, opened: &Opened, query: &str, vault: Option<&str>) -> Result<Item> {
        let item = self.find_item(opened, query, vault)?;
        if item.overview.get("type").and_then(Value::as_str) != Some("sshKey") {
            return Err(CliError::not_found(format!(
                "“{}” isn't an SSH key.",
                item.title()
            )));
        }
        Ok(item)
    }

    /// The vault new keys go to: `query`, or Personal.
    pub(crate) fn ssh_target(&self, opened: &Opened, query: Option<&str>) -> Result<String> {
        let vaults = opened.vault.list_vaults()?;
        let target = match query {
            Some(query) => items::find_vault(&vaults, query)?,
            None => vaults
                .iter()
                .find(|vault| vault.vault_type == VaultType::Personal)
                .ok_or_else(|| CliError::not_found("No Personal vault. Pass --vault."))?,
        };
        if target.role == VaultRole::Read {
            return Err(CliError::other(format!(
                "You can only read the {} vault, not add to it.",
                target.name
            )));
        }
        Ok(target.id.clone())
    }

    async fn save_key(
        &self,
        opened: &Opened,
        vault_id: &str,
        title: &str,
        key: &SshKey,
        passphrase: Option<&str>,
    ) -> Result<Item> {
        let mut details = json!({
            "schemaVersion": 1,
            "privateKey": key.private_key.as_str(),
            "publicKey": key.info.public_key,
            "keyType": key.info.key_type,
            "fingerprint": key.info.fingerprint,
        });
        if !key.info.comment.is_empty() {
            details["comment"] = json!(key.info.comment);
        }
        if let Some(passphrase) = passphrase.filter(|p| !p.is_empty()) {
            details["passphrase"] = json!(passphrase);
        }
        let draft = ItemDraft {
            id: None,
            vault_id: vault_id.to_owned(),
            revision: None,
            overview: json!({ "schemaVersion": 1, "type": "sshKey", "title": title, "subtitle": key.info.fingerprint }),
            details,
        };
        Ok(opened.vault.save_item(draft).await?)
    }

    fn key_json(item: &Item, vault: &str) -> Value {
        json!({
            "id": item.id,
            "title": item.title(),
            "vault": vault,
            "keyType": item.detail("keyType"),
            "fingerprint": item.detail("fingerprint"),
            "publicKey": ssh::authorized_keys_line(&details(item, "publicKey"), &details(item, "comment")),
            "comment": item.detail("comment"),
        })
    }

    async fn ssh_list(&mut self, vault: Option<String>) -> Result<Option<i32>> {
        let opened = self.opened_unlocked().await?;
        let vaults = opened.vault.list_vaults()?;
        let keys = self.ssh_items(&opened, vault.as_deref())?;
        if self.global.json {
            let rows: Vec<Value> = keys
                .iter()
                .map(|item| Self::key_json(item, items::vault_name(&vaults, &item.vault_id)))
                .collect();
            return self.out_json(&Value::Array(rows)).map(|()| None);
        }
        if keys.is_empty() {
            self.note("No SSH keys.");
            return Ok(None);
        }
        let table: Vec<[String; 4]> = keys
            .iter()
            .map(|item| {
                [
                    item.title().to_owned(),
                    type_label(item.detail("keyType").unwrap_or_default()),
                    details(item, "fingerprint"),
                    items::vault_name(&vaults, &item.vault_id).to_owned(),
                ]
            })
            .collect();
        for line in format_table(["TITLE", "TYPE", "FINGERPRINT", "VAULT"], &table) {
            self.out(&line)?;
        }
        Ok(None)
    }

    async fn ssh_generate(
        &mut self,
        kind: SshKeyKind,
        title: Option<String>,
        comment: Option<String>,
        vault: Option<String>,
        ask_passphrase: bool,
    ) -> Result<Option<i32>> {
        let opened = self.opened_unlocked().await?;
        let vault_id = self.ssh_target(&opened, vault.as_deref())?;
        let passphrase = ask_passphrase
            .then(|| self.file_password("Passphrase to keep for exports: ", true))
            .transpose()?;
        let key = ssh::generate(kind, comment.as_deref().unwrap_or_default(), &mut OsRng)
            .map_err(|_| CliError::other("Couldn't make the key."))?;
        let title = title.unwrap_or_else(|| default_title(&key.info.comment, &key.info.key_type));
        let item = self
            .save_key(
                &opened,
                &vault_id,
                &title,
                &key,
                passphrase.as_deref().map(String::as_str),
            )
            .await?;
        self.report_saved(&opened, &item)
    }

    fn report_saved(&mut self, opened: &Opened, item: &Item) -> Result<Option<i32>> {
        let vaults = opened.vault.list_vaults()?;
        if self.global.json {
            return self
                .out_json(&Self::key_json(
                    item,
                    items::vault_name(&vaults, &item.vault_id),
                ))
                .map(|()| None);
        }
        self.note(&format!(
            "Saved “{}” ({}).",
            item.title(),
            details(item, "fingerprint")
        ));
        let line =
            ssh::authorized_keys_line(&details(item, "publicKey"), &details(item, "comment"));
        self.out(&line)?;
        Ok(None)
    }

    async fn ssh_import(
        &mut self,
        files: Vec<PathBuf>,
        scan: bool,
        vault: Option<String>,
    ) -> Result<Option<i32>> {
        if files.is_empty() && !scan {
            return Err(CliError::usage(
                "Name the key files to import, or pass --scan to import ~/.ssh.",
            ));
        }
        let mut paths = files.clone();
        if scan {
            let dir = self.ssh_dir()?;
            paths.extend(scan_candidates(&dir));
        }
        let opened = self.opened_unlocked().await?;
        let vault_id = self.ssh_target(&opened, vault.as_deref())?;
        // Keys already in the vault, by fingerprint: anywhere, so a key isn't stored twice.
        let mut known: Vec<String> = opened
            .vault
            .live_items()?
            .iter()
            .filter(|item| item.overview.get("type").and_then(Value::as_str) == Some("sshKey"))
            .filter_map(|item| item.detail("fingerprint").map(str::to_owned))
            .collect();
        let mut results: Vec<Value> = Vec::new();
        let mut failed = false;
        for path in paths {
            let named = files.contains(&path);
            let text = match fs::read_to_string(&path) {
                Ok(text) => Zeroizing::new(text),
                Err(error) if named => {
                    return Err(CliError::usage(format!(
                        "Can't read {}: {error}",
                        path.display()
                    )));
                }
                Err(_) => continue,
            };
            let key = match ssh::read_private_key(&text, None) {
                Ok(key) => key,
                Err(CoreError::SshPassphraseRequired) if self.can_ask_password() => {
                    let prompt = format!("Passphrase for {}: ", path.display());
                    let passphrase = self.file_password(&prompt, false)?;
                    match ssh::read_private_key(&text, Some(&passphrase)) {
                        Ok(key) => key,
                        Err(error) => {
                            self.note(&key_error(&path, error).message);
                            failed = true;
                            continue;
                        }
                    }
                }
                // `--scan` only takes what reads as a private key; named files must.
                Err(error) if named => {
                    self.note(&key_error(&path, error).message);
                    failed = true;
                    continue;
                }
                Err(CoreError::SshPassphraseRequired) => {
                    self.note(&format!(
                        "{} is protected by a passphrase: run this in a terminal to import it.",
                        path.display()
                    ));
                    continue;
                }
                Err(_) => continue,
            };
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("SSH key");
            if known.contains(&key.info.fingerprint) {
                results.push(json!({ "file": path.display().to_string(), "fingerprint": key.info.fingerprint, "skipped": "alreadyInVault" }));
                if !self.global.json {
                    self.note(&format!("{} is already in the vault.", path.display()));
                }
                continue;
            }
            // A PEM or PKCS#8 file has no comment: the .pub next to it may.
            let mut key = key;
            if key.info.comment.is_empty()
                && let Some(comment) = pub_comment(&path, &key.info.public_key)
            {
                key.info.comment = comment;
            }
            let title = file_name.to_owned();
            let item = self
                .save_key(&opened, &vault_id, &title, &key, None)
                .await?;
            known.push(key.info.fingerprint.clone());
            if !key.info.usable && !self.global.json {
                self.note(&format!(
                    "{}: Octa Pass keeps {} keys but can't use them yet.",
                    path.display(),
                    type_label(&key.info.key_type)
                ));
            }
            results.push(json!({ "file": path.display().to_string(), "id": item.id, "title": item.title(), "fingerprint": key.info.fingerprint, "keyType": key.info.key_type }));
            if !self.global.json {
                self.note(&format!(
                    "Imported {} as “{}”.",
                    path.display(),
                    item.title()
                ));
            }
        }
        if self.global.json {
            self.out_json(&Value::Array(results))?;
        } else if !results.iter().any(|r| r.get("id").is_some()) && !failed {
            self.note("No new keys to import.");
        }
        Ok(failed.then_some(crate::error::Exit::Usage as i32))
    }

    /// `~/.ssh`.
    fn ssh_dir(&self) -> Result<PathBuf> {
        self.context
            .var("HOME")
            .or_else(|| self.context.var("USERPROFILE"))
            .map(PathBuf::from)
            .or_else(dirs::home_dir)
            .map(|home| home.join(".ssh"))
            .ok_or_else(|| CliError::other("This user has no home folder."))
    }

    async fn ssh_export(
        &mut self,
        query: String,
        out: Option<PathBuf>,
        new_passphrase: bool,
        no_passphrase: bool,
        force: bool,
        vault: Option<String>,
    ) -> Result<Option<i32>> {
        if let Some(path) = &out {
            if path.exists() && !force {
                return Err(CliError::usage(format!(
                    "{} already exists. Pass --force to replace it.",
                    path.display()
                )));
            }
        } else if self.context.stdout_is_terminal {
            return Err(CliError::usage(
                "Pass --out with a file name: private keys aren't printed in the terminal.",
            ));
        }
        let opened = self.open(DEFAULT_IDLE)?;
        if opened.vault.snapshot().session.status
            == octapass_desktop_vault::model::SessionStatus::SignedOut
        {
            return Err(CliError::signed_out());
        }
        // Like `octapass export`, a private key asks for the master password again (plan 16).
        if !self.can_ask_password() {
            return Err(CliError::usage(
                "Exporting a private key needs your master password: run it in a terminal, or pass --password-stdin.",
            ));
        }
        let password = self.master_password()?;
        opened.vault.unlock(password).await?;
        self.sync(&opened.vault).await?;
        let item = self.ssh_item(&opened, &query, vault.as_deref())?;
        let Some(private_key) = item
            .detail("privateKey")
            .map(|k| Zeroizing::new(k.to_owned()))
        else {
            return Err(CliError::not_found(format!(
                "“{}” has no private key.",
                item.title()
            )));
        };
        let passphrase = if new_passphrase {
            Some(self.file_password("Passphrase for the file: ", true)?)
        } else if no_passphrase {
            None
        } else {
            item.detail("passphrase")
                .map(|p| Zeroizing::new(p.to_owned()))
        };
        let text = ssh::write_private_key(
            &private_key,
            &details(&item, "comment"),
            passphrase.as_deref().map(String::as_str),
            &mut OsRng,
        )
        .map_err(|_| CliError::other("Couldn't write the key."))?;
        match out {
            Some(path) => {
                crate::write_private(&path, text.as_bytes()).map_err(|error| {
                    CliError::other(format!("Couldn't write {}: {error}", path.display()))
                })?;
                if self.global.json {
                    self.out_json(&json!({ "file": path.display().to_string(), "fingerprint": item.detail("fingerprint"), "passphrase": passphrase.is_some() }))?;
                } else {
                    let protected = if passphrase.is_some() {
                        ", protected by a passphrase"
                    } else {
                        ""
                    };
                    self.note(&format!(
                        "Wrote {}{protected}. Only you can read it.",
                        path.display()
                    ));
                }
            }
            None => self.out_secret(text.trim_end(), true, true)?,
        }
        Ok(None)
    }

    async fn ssh_public(&mut self, query: String, vault: Option<String>) -> Result<Option<i32>> {
        let opened = self.opened_unlocked().await?;
        let item = self.ssh_item(&opened, &query, vault.as_deref())?;
        let line =
            ssh::authorized_keys_line(&details(&item, "publicKey"), &details(&item, "comment"));
        if line.is_empty() {
            return Err(CliError::not_found(format!(
                "“{}” has no public key.",
                item.title()
            )));
        }
        if self.global.json {
            let vaults = opened.vault.list_vaults()?;
            return self
                .out_json(&Self::key_json(
                    &item,
                    items::vault_name(&vaults, &item.vault_id),
                ))
                .map(|()| None);
        }
        self.out(&line).map(|()| None)
    }
}

/// Private key files in `~/.ssh`: everything except public keys, `known_hosts`, `config` and the
/// like. What doesn't read as a key is skipped quietly.
fn scan_candidates(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .metadata()
                .is_ok_and(|m| m.is_file() && m.len() <= MAX_KEY_FILE)
        })
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            !name.ends_with(".pub")
                && !name.starts_with("known_hosts")
                && !matches!(
                    name,
                    "config" | "authorized_keys" | "authorized_keys2" | "environment"
                )
        })
        .collect();
    paths.sort();
    paths
}

/// The comment in `<path>.pub`, when it's the same key.
fn pub_comment(path: &Path, public_key: &str) -> Option<String> {
    let mut name = path.as_os_str().to_owned();
    name.push(".pub");
    let line = fs::read_to_string(PathBuf::from(name)).ok()?;
    let mut parts = line.split_whitespace();
    let (kind, blob) = (parts.next()?, parts.next()?);
    if format!("{kind} {blob}") != public_key {
        return None;
    }
    let comment = parts.collect::<Vec<_>>().join(" ");
    (!comment.is_empty()).then_some(comment)
}

fn type_label(key_type: &str) -> String {
    match key_type {
        "ssh-ed25519" => "Ed25519",
        "ecdsa-sha2-nistp256" => "ECDSA P-256",
        "ecdsa-sha2-nistp384" => "ECDSA P-384",
        "ecdsa-sha2-nistp521" => "ECDSA P-521",
        "ssh-rsa" => "RSA",
        "ssh-dss" => "DSA",
        "sk-ssh-ed25519@openssh.com" => "Ed25519 (security key)",
        "sk-ecdsa-sha2-nistp256@openssh.com" => "ECDSA P-256 (security key)",
        other => other,
    }
    .to_owned()
}

/// A title for a new key: its comment, else its type.
fn default_title(comment: &str, key_type: &str) -> String {
    if comment.trim().is_empty() {
        format!("{} key", type_label(key_type))
    } else {
        comment.trim().to_owned()
    }
}
