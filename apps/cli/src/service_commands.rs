//! `octapass service-account …`: people making, listing and revoking service accounts. A service
//! account's own reading happens through `SERVICE_TOKEN_ENV`, in [`crate::App::unlocked`].

use octapass_api::{VaultRole, VaultType};
use octapass_desktop_vault::vault::ServiceAccount;
use serde_json::{Value, json};

use super::*;
use crate::cli::ServiceAccountCommand;

/// `90d`, `12h` or `30m`.
fn parse_expiry(text: &str) -> Result<Duration> {
    let bad = || CliError::usage(format!("`{text}` isn't a duration (try 90d or 12h)."));
    let text = text.trim();
    let split = text.find(|c: char| !c.is_ascii_digit()).ok_or_else(bad)?;
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().map_err(|_| bad())?;
    let seconds = match unit {
        "m" => number.checked_mul(60),
        "h" => number.checked_mul(3600),
        "d" => number.checked_mul(86_400),
        _ => None,
    }
    .filter(|seconds| *seconds > 0)
    .ok_or_else(bad)?;
    Ok(Duration::from_secs(seconds))
}

fn describe_account(account: &ServiceAccount) -> Value {
    json!({
        "id": account.id,
        "name": account.name,
        "vaultId": account.vault_id,
        "role": account.role.as_str(),
        "createdAt": account.created_at,
        "expiresAt": account.expires_at,
        "lastUsedAt": account.last_used_at,
        "revokedAt": account.revoked_at,
        "needsNewToken": account.needs_new_token,
    })
}

impl App {
    pub(crate) async fn service_account(
        &mut self,
        command: ServiceAccountCommand,
    ) -> Result<Option<i32>> {
        let opened = self.open(DEFAULT_IDLE)?;
        self.unlocked(&opened).await?;
        let vaults = opened.vaults()?;
        let (query, command) = match command {
            ServiceAccountCommand::Create { ref vault, .. }
            | ServiceAccountCommand::List { ref vault }
            | ServiceAccountCommand::Revoke { ref vault, .. } => (vault.clone(), command),
        };
        let vault = items::find_vault(&vaults, &query)?.clone();
        if vault.vault_type != VaultType::Shared {
            return Err(CliError::usage(format!(
                "Service accounts read shared vaults only, and {} isn't one: a personal vault's key can't be rotated, so access to it could never be taken back. Make a shared vault with only what the job needs.",
                vault.name
            )));
        }
        match command {
            ServiceAccountCommand::Create {
                name,
                write,
                expires,
                ..
            } => {
                let expires_at = expires
                    .map(|text| {
                        let after = parse_expiry(&text)?;
                        Ok::<_, CliError>(rfc3339(now() + after))
                    })
                    .transpose()?;
                let role = if write {
                    VaultRole::Write
                } else {
                    VaultRole::Read
                };
                let created = opened
                    .vault
                    .create_service_account(&vault.id, &name, role, expires_at.as_deref())
                    .await?;
                if self.context.stdout_is_terminal {
                    self.note("Warning: showing the token in the terminal. It's shown only now.");
                }
                self.note(&format!(
                    "Made service account {} for {} ({}). Keep the token in your CI system's secret store and give it to the job as {SERVICE_TOKEN_ENV}. Octa Pass can't show it again.",
                    created.account.id,
                    vault.name,
                    role.as_str(),
                ));
                if self.global.json {
                    let mut value = describe_account(&created.account);
                    value["token"] = json!(created.token.as_str());
                    self.out_json(&value)?;
                } else {
                    self.out(&created.token)?;
                }
            }
            ServiceAccountCommand::List { .. } => {
                let accounts = opened.vault.list_service_accounts(&vault.id).await?;
                if self.global.json {
                    let list = accounts.iter().map(describe_account).collect();
                    return self.out_json(&Value::Array(list)).map(|()| None);
                }
                if accounts.is_empty() {
                    self.note("No service accounts.");
                    return Ok(None);
                }
                let table: Vec<[String; 5]> = accounts
                    .iter()
                    .map(|account| {
                        let state = if account.revoked_at.is_some() {
                            "revoked"
                        } else if account.needs_new_token {
                            "needs a new token"
                        } else {
                            "active"
                        };
                        [
                            account.name.clone().unwrap_or_else(|| "—".to_owned()),
                            account.role.as_str().to_owned(),
                            state.to_owned(),
                            account
                                .last_used_at
                                .clone()
                                .unwrap_or_else(|| "never".to_owned()),
                            account.id.clone(),
                        ]
                    })
                    .collect();
                for line in format_table(["NAME", "ROLE", "STATE", "LAST USED", "ID"], &table) {
                    self.out(&line)?;
                }
            }
            ServiceAccountCommand::Revoke { id, .. } => {
                opened
                    .vault
                    .revoke_service_account(&vault.id, &id)
                    .await
                    .map_err(|error| {
                        let error = CliError::from(error);
                        CliError::new(
                            error.exit,
                            format!(
                                "If the server took the revocation, the token no longer works, but the vault's key may not have rotated. Check `octapass service-account list`. {}",
                                error.message
                            ),
                        )
                    })?;
                self.note(&format!(
                    "Revoked it and rotated the key of {}. Anything it read before is still known to whoever held the token: change those secrets if the token leaked.",
                    vault.name
                ));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiries() {
        assert_eq!(parse_expiry("90d").unwrap().as_secs(), 90 * 86_400);
        assert_eq!(parse_expiry("12h").unwrap().as_secs(), 43_200);
        for bad in ["", "90", "d", "0d", "-1d", "1y"] {
            assert!(parse_expiry(bad).is_err(), "{bad}");
        }
    }
}
