//! `octapass oauth …`, and the live token behind a reference's `accessToken` field.

use octapass_connect::oauth::{self, Flow, OAuth2, OAuthError, Token};
use serde_json::{Value, json};

use super::*;
use crate::cli::{OauthCommand, OauthFlow};

/// A fetched token to save back into its item.
pub(crate) struct LiveSave {
    draft: ItemDraft,
    /// The provider replaced the refresh token: losing this one breaks the next refresh.
    rotated: bool,
}

/// The token endpoint runs on a thread of its own, so references can stay synchronous: this is
/// called from inside the command's single-threaded runtime.
fn fetch_blocking(config: OAuth2, now: u64) -> Result<Token, OAuthError> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| OAuthError::Network(error.to_string()))?;
        runtime.block_on(config.fetch(now))
    })
    .join()
    .unwrap_or_else(|_| Err(OAuthError::Network("the request failed".into())))
}

fn oauth_error(error: OAuthError) -> CliError {
    let message = error.to_string();
    match error {
        OAuthError::NotConfigured(_) => CliError::not_found(message),
        OAuthError::Network(_) => CliError::new(Exit::ServerUnreachable, message),
        _ => CliError::other(message),
    }
}

impl App {
    fn unix_now(&self) -> u64 {
        (self.context.clock)()
    }

    /// The item's current token, cached until it's near its end. A new one is queued to be saved
    /// by [`App::save_live_tokens`].
    pub(crate) fn live_token(&self, opened: &Opened, item: &Item) -> Result<Field> {
        let not_configured = || OAuthError::NotConfigured(item.title().to_owned());
        let mut config = oauth::config(item).ok_or_else(|| oauth_error(not_configured()))?;
        // What's queued for this item is newer than what the item says.
        if let Some(save) = opened
            .live_saves
            .lock()
            .expect("live saves lock")
            .iter()
            .find(|save| save.draft.id.as_deref() == Some(&item.id))
            && let Some(queued) = save
                .draft
                .details
                .get("oauth2")
                .and_then(|value| serde_json::from_value::<OAuth2>(value.clone()).ok())
        {
            config = queued;
        }
        let now = self.unix_now();
        if let Some(token) = config.cached(now) {
            return Ok(Field {
                value: token.to_owned(),
                secret: true,
            });
        }
        let token = fetch_blocking(config.clone(), now).map_err(oauth_error)?;
        let rotated = token.refresh_token.is_some();
        config.apply(&token);
        let mut details = item.details.clone();
        details["oauth2"] = config.to_value();
        opened
            .live_saves
            .lock()
            .expect("live saves lock")
            .push(LiveSave {
                draft: ItemDraft {
                    id: Some(item.id.clone()),
                    vault_id: item.vault_id.clone(),
                    revision: Some(item.revision),
                    overview: item.overview.clone(),
                    details,
                },
                rotated,
            });
        Ok(Field {
            value: token.access_token.to_string(),
            secret: true,
        })
    }

    /// Saves fetched tokens into their items, so the next command reuses them. A lost access token
    /// costs one more request; a lost rotated refresh token would end the connection, so that
    /// failure stops the command before the token is used.
    pub(crate) async fn save_live_tokens(&mut self, opened: &Opened) -> Result<()> {
        let saves = std::mem::take(&mut *opened.live_saves.lock().expect("live saves lock"));
        for save in saves {
            let result = match opened.service.get() {
                Some(service) if service.can_write() => {
                    service.save_item(&save.draft).await.map(drop)
                }
                Some(_) if save.rotated => {
                    self.note("Warning: the provider replaced the refresh token, and this read-only service account can't save the new one. Use a client-credentials client, or a service account with --write.");
                    Ok(())
                }
                Some(_) => Ok(()),
                None => opened.vault.save_item(save.draft).await.map(drop),
            };
            match result {
                Err(error) if save.rotated => return Err(error.into()),
                Err(error) => self.note(&format!(
                    "Couldn't save the new token for later: {}",
                    CliError::from(error).message
                )),
                Ok(()) => {}
            }
        }
        Ok(())
    }

    fn oauth_secret(&mut self, env: &str, prompt: &str) -> Result<Option<String>> {
        if let Some(secret) = self.context.var(env) {
            return Ok(Some(secret));
        }
        if !self.context.terminal.interactive() {
            return Ok(None);
        }
        let secret = self
            .context
            .terminal
            .ask_hidden(prompt)
            .map_err(input_error)?;
        Ok(Some(secret.to_string()).filter(|secret| !secret.is_empty()))
    }

    pub(crate) async fn oauth(&mut self, command: OauthCommand) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        match command {
            OauthCommand::Create {
                title,
                flow,
                token_url,
                client_id,
                scope,
                audience,
                vault,
            } => {
                let vault_id = self.target_vault(&opened, vault.as_deref())?;
                let client_secret = self.oauth_secret(
                    "OCTAPASS_OAUTH_CLIENT_SECRET",
                    "Client secret (leave empty for none): ",
                )?;
                let refresh_token = match flow {
                    OauthFlow::RefreshToken => {
                        self.oauth_secret("OCTAPASS_OAUTH_REFRESH_TOKEN", "Refresh token: ")?
                    }
                    OauthFlow::ClientCredentials => None,
                };
                let config = OAuth2 {
                    flow: match flow {
                        OauthFlow::ClientCredentials => Flow::ClientCredentials,
                        OauthFlow::RefreshToken => Flow::RefreshToken,
                    },
                    token_url,
                    client_id,
                    client_secret,
                    refresh_token,
                    scope,
                    audience,
                    access_token: None,
                    expires_at: None,
                    extra: serde_json::Map::new(),
                };
                // Fetching proves it works before it's saved.
                let token = config.fetch(self.unix_now()).await.map_err(oauth_error)?;
                let mut config = config;
                config.apply(&token);
                let saved = opened
                    .vault
                    .save_item(ItemDraft {
                        id: None,
                        vault_id,
                        revision: None,
                        overview: json!({
                            "schemaVersion": 1,
                            "type": "apiCredential",
                            "title": title,
                        }),
                        details: json!({ "schemaVersion": 1, "oauth2": config.to_value() }),
                    })
                    .await?;
                self.note(&format!(
                    "Saved \"{}\". Its token is at the field accessToken of the item.",
                    saved.title()
                ));
                Ok(None)
            }
            OauthCommand::Token {
                item,
                vault,
                no_newline,
            } => {
                let item = self.find_item(&opened, &item, vault.as_deref())?;
                let field = self.live_token(&opened, &item)?;
                self.save_live_tokens(&opened).await?;
                self.out_secret(&field.value, true, !no_newline)?;
                Ok(None)
            }
            OauthCommand::Show { item, vault } => {
                let item = self.find_item(&opened, &item, vault.as_deref())?;
                let field = self.live_token(&opened, &item)?;
                self.save_live_tokens(&opened).await?;
                let config = oauth::config(&item);
                let queued_expiry = oauth::jwt_claims(&field.value)
                    .and_then(|claims| claims.get("exp").and_then(Value::as_u64))
                    .or(config.and_then(|config| config.expires_at));
                let description = oauth::describe(&field.value, queued_expiry);
                self.out_json(&description)?;
                Ok(None)
            }
        }
    }
}
