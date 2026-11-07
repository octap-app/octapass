//! Reading from an unlocked [`Vault`] held in memory, as the desktop app does. The vault stays
//! open only while the app is unlocked; a locked vault answers `locked`, and Connect never
//! unlocks it.

use std::path::PathBuf;
use std::sync::Arc;

use octapass_desktop_vault::model::{Item, SessionStatus, Vault as VaultView};
use octapass_desktop_vault::{ErrorCode, Vault, VaultError};
use serde_json::Value;
use time::OffsetDateTime;

use crate::clients::Client;
use crate::log::{Entry, Queue};
use crate::oauth::{self, Token};
use crate::reference::{Field, Reference, field, field_names};
use crate::server::{Approval, Backend, BoxFuture, ConnectError, ItemRef, Secret};

/// How the app asks the person.
pub type Ask = Arc<dyn Fn(Approval) -> BoxFuture<'static, bool> + Send + Sync>;

pub struct VaultBackend {
    vault: Arc<Vault>,
    folder: PathBuf,
    ask: Ask,
}

fn from_vault(error: VaultError) -> ConnectError {
    match error.code {
        ErrorCode::Locked | ErrorCode::SessionExpired | ErrorCode::PasswordRequired => {
            ConnectError::locked()
        }
        ErrorCode::NotFound => ConnectError::not_found("Not in the vault."),
        _ => ConnectError::failed(error.message),
    }
}

fn find_vault<'a>(vaults: &'a [VaultView], query: &str) -> Result<&'a VaultView, String> {
    let mut matches = vaults
        .iter()
        .filter(|vault| vault.id == query || vault.name.eq_ignore_ascii_case(query));
    match (matches.next(), matches.next()) {
        (Some(vault), None) => Ok(vault),
        (Some(_), Some(_)) => Err(format!(
            "More than one vault is called \"{query}\". Use its id instead."
        )),
        (None, _) => Err(format!("No vault called \"{query}\".")),
    }
}

fn find_item<'a>(items: &'a [Item], vault_id: &str, query: &str) -> Result<&'a Item, String> {
    let in_vault = || items.iter().filter(|item| item.vault_id == vault_id);
    if let Some(item) = in_vault().find(|item| item.id == query) {
        return Ok(item);
    }
    let titled: Vec<&Item> = in_vault()
        .filter(|item| item.title().eq_ignore_ascii_case(query.trim()))
        .collect();
    match titled.as_slice() {
        [item] => Ok(item),
        [] => Err(format!("No item called \"{query}\".")),
        many => Err(format!(
            "{} items are called \"{query}\". Use an id instead.",
            many.len()
        )),
    }
}

impl VaultBackend {
    pub fn new(vault: Arc<Vault>, folder: PathBuf, ask: Ask) -> Self {
        Self { vault, folder, ask }
    }

    fn account(&self) -> Result<String, ConnectError> {
        let session = self.vault.snapshot().session;
        match (session.server_url, session.email) {
            (Some(server), Some(email)) => Ok(format!("{server}|{email}")),
            _ => Err(ConnectError::locked()),
        }
    }

    fn snapshot(&self) -> Result<(Vec<VaultView>, Vec<Item>), ConnectError> {
        if self.vault.snapshot().session.status != SessionStatus::Unlocked {
            return Err(ConnectError::locked());
        }
        let vaults = self.vault.list_vaults().map_err(from_vault)?;
        let items = self.vault.live_items().map_err(from_vault)?;
        Ok((vaults, items))
    }

    async fn field_of(&self, item: &Item, name: &str) -> Result<Field, String> {
        if oauth::wants_live_token(name) && oauth::has_live_token(item) {
            return self.live_token(item).await;
        }
        if matches!(name.trim().to_lowercase().as_str(), "totp" | "otp" | "code") {
            let totp = item
                .detail("totp")
                .ok_or_else(|| format!("\"{}\" has no one-time code.", item.title()))?;
            let code = self
                .vault
                .totp(totp, None)
                .map_err(|_| format!("The one-time code of \"{}\" can't be read.", item.title()))?;
            return Ok(Field {
                value: code.code,
                secret: false,
            });
        }
        field(item, name)
            .ok_or_else(|| format!("\"{}\" has no field called \"{name}\".", item.title()))
    }

    /// The cached token, or a new one saved back into the item.
    async fn live_token(&self, item: &Item) -> Result<Field, String> {
        let mut config = oauth::config(item).ok_or("This item has no OAuth2 client.")?;
        let now = OffsetDateTime::now_utc().unix_timestamp().unsigned_abs();
        if let Some(token) = config.cached(now) {
            return Ok(Field {
                value: token.to_owned(),
                secret: true,
            });
        }
        let token: Token = config.fetch(now).await.map_err(|error| error.to_string())?;
        config.apply(&token);
        let mut details = item.details.clone();
        details["oauth2"] = config.to_value();
        let draft = octapass_desktop_vault::model::ItemDraft {
            id: Some(item.id.clone()),
            vault_id: item.vault_id.clone(),
            revision: Some(item.revision),
            overview: item.overview.clone(),
            details,
        };
        let saved = self.vault.save_item(draft).await;
        // A lost access token costs one more request; a lost rotated refresh token ends the
        // connection, so that can't go unnoticed.
        if saved.is_err() && token.refresh_token.is_some() {
            return Err("Couldn't save the provider's new refresh token.".into());
        }
        Ok(Field {
            value: token.access_token.to_string(),
            secret: true,
        })
    }

    async fn resolve(
        &self,
        vaults: &[VaultView],
        items: &[Item],
        reference: &Reference,
    ) -> Result<Field, String> {
        let vault = find_vault(vaults, &reference.vault)?;
        let item = find_item(items, &vault.id, &reference.item)?;
        self.field_of(item, &reference.field).await
    }

    /// A value that is itself a reference is followed once, as `octapass read` does.
    async fn resolve_one(
        &self,
        vaults: &[VaultView],
        items: &[Item],
        text: &str,
    ) -> Result<String, String> {
        let reference =
            Reference::parse(text).ok_or_else(|| format!("\"{text}\" isn't a reference."))?;
        let found = self.resolve(vaults, items, &reference).await?;
        if !Reference::is_reference(&found.value) {
            return Ok(found.value);
        }
        let next = Reference::parse(&found.value)
            .ok_or_else(|| format!("\"{}\" isn't a reference.", found.value))?;
        let target = self.resolve(vaults, items, &next).await?;
        if Reference::is_reference(&target.value) {
            return Err("It points to another reference. Only one step is followed.".into());
        }
        Ok(target.value)
    }

    fn record(&self, queue: &Queue, client: &Client, reference: &str) -> Result<(), ConnectError> {
        let entry = Entry {
            at: OffsetDateTime::now_utc().unix_timestamp().unsigned_abs(),
            client_id: client.id.clone(),
            client_name: client.name.clone(),
            reference: reference.to_owned(),
        };
        let bytes = serde_json::to_vec(&entry).expect("entries serialize");
        let sealed = self.vault.seal_audit_detail(&bytes).map_err(from_vault)?;
        queue.push(&sealed).map_err(|error| {
            ConnectError::failed(format!(
                "Can't record this in the security log, so it wasn't handed out: {error}"
            ))
        })
    }

    async fn send_queue(&self, queue: &Queue) {
        loop {
            let Ok(batch) = queue.peek() else { return };
            let count = batch.len();
            if count == 0
                || self.vault.record_connect_events(batch).await.is_err()
                || queue.remove(count).is_err()
                || count < crate::log::BATCH
            {
                return;
            }
        }
    }
}

impl Backend for VaultBackend {
    fn unlocked(&self) -> BoxFuture<'_, bool> {
        let unlocked = self.vault.snapshot().session.status == SessionStatus::Unlocked;
        Box::pin(async move { unlocked })
    }

    fn approve(&self, request: Approval) -> BoxFuture<'_, bool> {
        (self.ask)(request)
    }

    fn items(&self, _: Client) -> BoxFuture<'_, Result<Vec<ItemRef>, ConnectError>> {
        Box::pin(async {
            let (vaults, items) = self.snapshot()?;
            let name = |id: &str| {
                vaults
                    .iter()
                    .find(|vault| vault.id == id)
                    .map_or("", |vault| vault.name.as_str())
                    .to_owned()
            };
            Ok(items
                .iter()
                .map(|item| ItemRef {
                    vault: name(&item.vault_id),
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
        })
    }

    fn read(
        &self,
        client: Client,
        references: Vec<String>,
    ) -> BoxFuture<'_, Result<Vec<Secret>, ConnectError>> {
        Box::pin(async move {
            let (vaults, items) = self.snapshot()?;
            let queue = Queue::open(&self.folder, &self.account()?);
            let mut secrets = Vec::with_capacity(references.len());
            for reference in references {
                match self.resolve_one(&vaults, &items, &reference).await {
                    Ok(value) => {
                        // On disk first: no entry, no secret.
                        self.record(&queue, &client, &reference)?;
                        secrets.push(Secret {
                            reference,
                            value: Some(value),
                            error: None,
                        });
                    }
                    Err(error) => secrets.push(Secret {
                        reference,
                        value: None,
                        error: Some(error),
                    }),
                }
            }
            self.send_queue(&queue).await;
            Ok(secrets)
        })
    }
}
