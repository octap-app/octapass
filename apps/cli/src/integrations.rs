//! Credential plugins other tools run: AWS `credential_process`, the kubectl exec plugin and the
//! Docker credential helper. Each prints one tool's fixed format from a vault item, so the secret
//! stays out of config files. With `SERVICE_TOKEN_ENV` they read a service account's vault.

use std::io::Read;

use serde_json::{Value, json};

use super::*;
use crate::cli::{AwsCommand, DockerOperation, KubeCommand};
use crate::items::SCHEME;

const ACCESS_KEY_FIELDS: &[&str] = &[
    "accessKeyId",
    "access key id",
    "access_key_id",
    "AWS_ACCESS_KEY_ID",
    "username",
];
const SECRET_KEY_FIELDS: &[&str] = &[
    "secretAccessKey",
    "secret access key",
    "secret_access_key",
    "AWS_SECRET_ACCESS_KEY",
    "password",
];
const SESSION_TOKEN_FIELDS: &[&str] = &[
    "sessionToken",
    "session token",
    "session_token",
    "AWS_SESSION_TOKEN",
];
const KUBE_TOKEN_FIELDS: &[&str] = &["accessToken", "token", "password"];
const DEFAULT_KUBE_API: &str = "client.authentication.k8s.io/v1";
/// What marks a login as Docker's.
const DOCKER_TAG: &str = "docker-credential";
/// Docker's helper library matches this text.
const NOT_FOUND: &str = "credentials not found in native keychain";

impl App {
    /// The first of `names` the item has, or the error of the last.
    fn first_field(&self, opened: &Opened, item: &Item, names: &[&str]) -> Result<Option<Field>> {
        for name in names {
            match self.field(opened, item, name) {
                Ok(field) => return Ok(Some(field)),
                Err(error) if error.exit == Exit::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn required_field(
        &self,
        opened: &Opened,
        item: &Item,
        names: &[&str],
        what: &str,
    ) -> Result<Field> {
        self.first_field(opened, item, names)?.ok_or_else(|| {
            CliError::not_found(format!(
                "\"{}\" has no {what}. Give it a field called {}.",
                item.title(),
                names[0]
            ))
        })
    }

    pub(crate) async fn aws(&mut self, command: AwsCommand) -> Result<Option<i32>> {
        let AwsCommand::CredentialProcess { item, vault } = command;
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let item = self.find_item(&opened, &item, vault.as_deref())?;
        let access = self.required_field(&opened, &item, ACCESS_KEY_FIELDS, "access key id")?;
        let secret = self.required_field(&opened, &item, SECRET_KEY_FIELDS, "secret access key")?;
        let session = self.first_field(&opened, &item, SESSION_TOKEN_FIELDS)?;
        let expiration = self.first_field(&opened, &item, &["expiration"])?;
        let mut output = json!({
            "Version": 1,
            "AccessKeyId": access.value,
            "SecretAccessKey": secret.value,
        });
        if let Some(session) = session {
            output["SessionToken"] = json!(session.value);
        }
        if let Some(expiration) = expiration {
            output["Expiration"] = json!(expiration.value);
        }
        self.save_live_tokens(&opened).await?;
        self.out(&output.to_string())?;
        Ok(None)
    }

    pub(crate) async fn kube(&mut self, command: KubeCommand) -> Result<Option<i32>> {
        let KubeCommand::Credential { item, vault } = command;
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let item = self.find_item(&opened, &item, vault.as_deref())?;
        let token = self.first_field(&opened, &item, KUBE_TOKEN_FIELDS)?;
        let certificate = self.first_field(&opened, &item, &["clientCertificateData"])?;
        let key = self.first_field(&opened, &item, &["clientKeyData"])?;
        let mut status = match (token, certificate, key) {
            (_, Some(certificate), Some(key)) => json!({
                "clientCertificateData": certificate.value,
                "clientKeyData": key.value,
            }),
            (Some(token), _, _) => json!({ "token": token.value }),
            _ => {
                return Err(CliError::not_found(format!(
                    "\"{}\" has no token, and no clientCertificateData with clientKeyData.",
                    item.title()
                )));
            }
        };
        // A live token says when it ends, so kubectl asks again in time.
        if let Some(config) = octapass_connect::oauth::config(&item)
            && let Some(expires) = status["token"].as_str().and_then(|token| {
                let claims = octapass_connect::oauth::jwt_claims(token)?;
                claims.get("exp")?.as_u64().or(config.expires_at)
            })
            && let Some(at) = i64::try_from(expires)
                .ok()
                .and_then(|at| time::OffsetDateTime::from_unix_timestamp(at).ok())
        {
            status["expirationTimestamp"] = json!(rfc3339(at));
        }
        self.save_live_tokens(&opened).await?;
        // kubectl says which version it speaks; the answer has to match it.
        let api_version = self
            .context
            .var("KUBERNETES_EXEC_INFO")
            .and_then(|info| serde_json::from_str::<Value>(&info).ok())
            .and_then(|info| info.get("apiVersion")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| DEFAULT_KUBE_API.to_owned());
        let output = json!({
            "apiVersion": api_version,
            "kind": "ExecCredential",
            "status": status,
        });
        self.out(&output.to_string())?;
        Ok(None)
    }

    fn read_stdin(&mut self) -> Result<String> {
        let mut text = String::new();
        self.context
            .stdin
            .read_to_string(&mut text)
            .map_err(|error| CliError::usage(format!("Couldn't read stdin: {error}")))?;
        Ok(text)
    }

    /// Logins this helper saved, and any login the user tagged for it.
    fn docker_logins(&self, opened: &Opened) -> Result<Vec<Item>> {
        Ok(opened
            .live_items()?
            .into_iter()
            .filter(Item::is_login_like)
            .filter(|item| {
                item.overview
                    .get("tags")
                    .and_then(Value::as_array)
                    .is_some_and(|tags| tags.iter().any(|tag| tag == DOCKER_TAG))
            })
            .collect())
    }

    pub(crate) async fn docker_credential(
        &mut self,
        operation: DockerOperation,
    ) -> Result<Option<i32>> {
        let input = match operation {
            DockerOperation::List => String::new(),
            _ => self.read_stdin()?,
        };
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let logins = self.docker_logins(&opened)?;
        let host_of = |item: &Item| {
            item.overview
                .get("urls")
                .and_then(Value::as_array)
                .and_then(|urls| urls.first())
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        match operation {
            DockerOperation::Get => {
                let server = input.trim();
                let Some(item) = logins
                    .iter()
                    .find(|item| host_of(item).as_deref() == Some(server))
                else {
                    self.out(NOT_FOUND)?;
                    return Ok(Some(1));
                };
                let output = json!({
                    "ServerURL": server,
                    "Username": item.detail("username").unwrap_or_default(),
                    "Secret": item.detail("password").unwrap_or_default(),
                });
                self.out(&output.to_string())?;
            }
            DockerOperation::List => {
                let list: serde_json::Map<String, Value> = logins
                    .iter()
                    .filter_map(|item| {
                        let username = item.detail("username").unwrap_or_default();
                        Some((host_of(item)?, json!(username)))
                    })
                    .collect();
                self.out(&Value::Object(list).to_string())?;
            }
            DockerOperation::Store => {
                let value: Value = serde_json::from_str(&input)
                    .map_err(|_| CliError::usage("Docker sent something that isn't JSON."))?;
                let text = |key: &str| value[key].as_str().unwrap_or_default().to_owned();
                let (server, username, secret) =
                    (text("ServerURL"), text("Username"), text("Secret"));
                if server.is_empty() {
                    return Err(CliError::usage("Docker sent no ServerURL."));
                }
                let existing = logins
                    .iter()
                    .find(|item| host_of(item).as_deref() == Some(server.as_str()));
                let vault_id = match existing {
                    Some(item) => item.vault_id.clone(),
                    None => self.target_vault(&opened, None)?,
                };
                let mut details = existing.map_or_else(
                    || json!({ "schemaVersion": 1 }),
                    |item| item.details.clone(),
                );
                details["username"] = json!(username);
                details["password"] = json!(secret);
                let draft = ItemDraft {
                    id: existing.map(|item| item.id.clone()),
                    vault_id,
                    revision: existing.map(|item| item.revision),
                    overview: existing.map_or_else(
                        || {
                            json!({
                                "schemaVersion": 1,
                                "type": "login",
                                "title": format!("Docker: {server}"),
                                "urls": [server],
                                "tags": [DOCKER_TAG],
                            })
                        },
                        |item| item.overview.clone(),
                    ),
                    details,
                };
                opened.vault.save_item(draft).await?;
            }
            DockerOperation::Erase => {
                let server = input.trim();
                if let Some(item) = logins
                    .iter()
                    .find(|item| host_of(item).as_deref() == Some(server))
                {
                    opened.vault.delete_item(&item.id).await?;
                }
            }
        }
        Ok(None)
    }
}

/// For `octapass connect`: whether text is a reference at all, without parsing it.
pub(crate) fn looks_like_reference(text: &str) -> bool {
    text.trim_start().starts_with(SCHEME)
}
