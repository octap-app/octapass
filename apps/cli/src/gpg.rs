//! `octapass gpg`: OpenPGP keys in the vault, for signing Git commits (plan 16). The vault keeps a
//! key as it was exported, with its passphrase; both are only ever decrypted on the device.

use std::fs;
use std::path::PathBuf;

use octapass_core::Error as CoreError;
use octapass_core::tools::gpg;
use octapass_desktop_vault::model::{Item, ItemDraft};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::cli::GpgCommand;
use crate::error::{CliError, Exit, Result};
use crate::{App, Opened, format_table, items};

pub(crate) const ITEM_TYPE: &str = "gpgKey";

fn is_gpg_key(item: &Item) -> bool {
    item.overview.get("type").and_then(Value::as_str) == Some(ITEM_TYPE)
}

impl App {
    pub(crate) async fn gpg(&mut self, command: GpgCommand) -> Result<Option<i32>> {
        match command {
            GpgCommand::List { vault } => self.gpg_list(vault).await,
            GpgCommand::Import { file, title, vault } => self.gpg_import(file, title, vault).await,
            GpgCommand::Public { item, vault } => self.gpg_public(item, vault).await,
        }
    }

    /// The OpenPGP keys, by title.
    pub(crate) fn gpg_items(&self, opened: &Opened) -> Result<Vec<Item>> {
        let mut keys: Vec<Item> = opened
            .vault
            .live_items()?
            .into_iter()
            .filter(is_gpg_key)
            .collect();
        keys.sort_by(|a, b| {
            a.title()
                .to_lowercase()
                .cmp(&b.title().to_lowercase())
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(keys)
    }

    async fn gpg_list(&mut self, vault: Option<String>) -> Result<Option<i32>> {
        let opened = self.opened_unlocked().await?;
        let vaults = opened.vault.list_vaults()?;
        let only = vault
            .map(|query| items::find_vault(&vaults, &query).map(|vault| vault.id.clone()))
            .transpose()?;
        let mut keys = self.gpg_items(&opened)?;
        keys.retain(|item| only.as_ref().is_none_or(|id| &item.vault_id == id));
        if self.global.json {
            let rows: Vec<Value> = keys
                .iter()
                .map(|item| {
                    json!({
                        "id": item.id,
                        "title": item.title(),
                        "vault": items::vault_name(&vaults, &item.vault_id),
                        "keyId": item.detail("keyId"),
                        "fingerprint": item.detail("fingerprint"),
                        "userId": item.detail("userId"),
                    })
                })
                .collect();
            return self.out_json(&Value::Array(rows)).map(|()| None);
        }
        if keys.is_empty() {
            self.note("No OpenPGP keys.");
            return Ok(None);
        }
        let table: Vec<[String; 4]> = keys
            .iter()
            .map(|item| {
                let text = |key: &str| item.detail(key).unwrap_or_default().to_owned();
                [
                    item.title().to_owned(),
                    text("keyId"),
                    text("userId"),
                    items::vault_name(&vaults, &item.vault_id).to_owned(),
                ]
            })
            .collect();
        for line in format_table(["TITLE", "KEY ID", "USER ID", "VAULT"], &table) {
            self.out(&line)?;
        }
        Ok(None)
    }

    async fn gpg_import(
        &mut self,
        file: PathBuf,
        title: Option<String>,
        vault: Option<String>,
    ) -> Result<Option<i32>> {
        let text = fs::read_to_string(&file)
            .map(Zeroizing::new)
            .map_err(|error| CliError::usage(format!("Can't read {}: {error}", file.display())))?;
        let unreadable = |file: &PathBuf| {
            CliError::usage(format!(
                "{} isn't an OpenPGP private key. Export one with gpg --armor --export-secret-keys.",
                file.display()
            ))
        };
        let opened = self.opened_unlocked().await?;
        let vault_id = self.writable_vault(&opened, vault.as_deref())?;
        let mut passphrase = None;
        let key = match gpg::read_private_key(&text, None) {
            Ok(key) => key,
            Err(CoreError::WrongPassphrase) if self.can_ask_password() => {
                let prompt = format!("Passphrase for {}: ", file.display());
                let typed = self.file_password(&prompt, false)?;
                let key =
                    gpg::read_private_key(&text, Some(&typed)).map_err(|error| match error {
                        CoreError::WrongPassphrase => CliError::new(
                            Exit::InvalidCredentials,
                            format!("Wrong passphrase for {}.", file.display()),
                        ),
                        _ => unreadable(&file),
                    })?;
                passphrase = Some(typed);
                key
            }
            Err(CoreError::WrongPassphrase) => {
                return Err(CliError::usage(format!(
                    "{} is protected by a passphrase: run this in a terminal, or pass --password-stdin.",
                    file.display()
                )));
            }
            Err(_) => return Err(unreadable(&file)),
        };
        let known = self
            .gpg_items(&opened)?
            .iter()
            .any(|item| item.detail("fingerprint") == Some(key.fingerprint.as_str()));
        if known {
            return Err(CliError::usage("That key is already in the vault."));
        }
        if !key.can_sign {
            self.note("Warning: this key can't sign here. Octa Pass doesn't sign with RSA OpenPGP keys yet: use an Ed25519 or ECDSA key for commits.");
        }
        let mut details = json!({
            "schemaVersion": 1,
            "privateKey": text.as_str(),
            "publicKey": key.public_key,
            "fingerprint": key.fingerprint,
            "fingerprints": key.fingerprints,
            "keyId": key.key_id,
            "userId": key.user_id,
        });
        if let Some(passphrase) = &passphrase {
            details["passphrase"] = json!(passphrase.as_str());
        }
        let title = title
            .filter(|title| !title.trim().is_empty())
            .unwrap_or_else(|| key.user_id.clone());
        let item = opened
            .vault
            .save_item(ItemDraft {
                id: None,
                vault_id,
                revision: None,
                overview: json!({ "schemaVersion": 1, "type": ITEM_TYPE, "title": title, "subtitle": key.key_id }),
                details,
            })
            .await?;
        if self.global.json {
            return self
                .out_json(&json!({ "id": item.id, "title": item.title(), "fingerprint": key.fingerprint, "canSign": key.can_sign }))
                .map(|()| None);
        }
        self.note(&format!("Imported “{}” ({}).", item.title(), key.key_id));
        self.out(&item.id).map(|()| None)
    }

    async fn gpg_public(&mut self, query: String, vault: Option<String>) -> Result<Option<i32>> {
        let opened = self.opened_unlocked().await?;
        let item = self.find_item(&opened, &query, vault.as_deref())?;
        if !is_gpg_key(&item) {
            return Err(CliError::not_found(format!(
                "“{}” isn't an OpenPGP key.",
                item.title()
            )));
        }
        let public = item.detail("publicKey").unwrap_or_default().to_owned();
        self.out(public.trim_end()).map(|()| None)
    }
}
