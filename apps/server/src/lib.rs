//! The Octa Pass sync server. It stores and syncs ciphertext, and has no code
//! path that could decrypt it.

mod account_deletion;
mod backup;
pub mod breach_email;
mod clock;
pub mod config;
mod crypto;
mod db;
mod emergency;
mod error;
mod events;
mod extract;
pub mod icons;
mod key_log;
mod login;
mod mail;
mod middleware;
pub mod openapi;
mod rate_limit;
mod relay;
mod routes;
mod secrets;
mod sso;
mod state;
mod storage;
mod two_step;
mod validate;
mod web;

pub use config::Config;
pub use routes::router;
pub use state::{AppState, StartupError};
pub use storage::{S3Config, StorageConfig};

pub mod admin {
    //! Operator commands behind `octapass-server admin …`.

    use std::path::{Path, PathBuf};

    use crate::Config;
    use crate::account_deletion::{self, Authorization};
    use crate::db;
    use crate::state::AppState;
    use crate::validate;

    #[derive(Debug, thiserror::Error)]
    pub enum AdminError {
        #[error("{0}")]
        Invalid(String),
        #[error("no account with that email")]
        NoSuchAccount,
        #[error("{0}")]
        Failed(String),
    }

    fn email(raw: &str) -> Result<String, AdminError> {
        validate::email(raw).map_err(|e| AdminError::Invalid(e.to_string()))
    }

    /// Lets `email` sign up while `OCTAPASS_SIGNUPS=invite`.
    pub async fn invite(state: &AppState, raw_email: &str) -> Result<(), AdminError> {
        let email = email(raw_email)?;
        db::accounts::add_invite(&state.db, &email, db::now())
            .await
            .map_err(|e| AdminError::Failed(e.to_string()))
    }

    /// Invites each `OCTAPASS_INVITES` email that has no account yet. Runs at every start; an
    /// invite is used up when its account is created, so this doesn't invite it again.
    pub async fn invite_configured(state: &AppState) -> Result<(), AdminError> {
        let failed = |e: sqlx::Error| AdminError::Failed(e.to_string());
        for email in &state.config.invites {
            if !db::accounts::email_exists(&state.db, email)
                .await
                .map_err(failed)?
            {
                db::accounts::add_invite(&state.db, email, db::now())
                    .await
                    .map_err(failed)?;
            }
        }
        Ok(())
    }

    /// Writes a backup into `dir` (SQLite only) and returns its folder.
    pub async fn backup(state: &AppState, dir: &Path) -> Result<PathBuf, AdminError> {
        crate::backup::create(state, dir)
            .await
            .map_err(|e| AdminError::Failed(e.to_string()))
    }

    /// Puts the backup in `dir` in place of the data; the server must be stopped. Returns where
    /// the replaced data was moved.
    pub fn restore(config: &Config, dir: &Path) -> Result<PathBuf, AdminError> {
        crate::backup::restore(config, dir).map_err(|e| AdminError::Failed(e.to_string()))
    }

    /// Turns two-step sign-in off for someone who lost every method, after the
    /// operator has checked who they are. The owner is emailed.
    pub async fn reset_two_step(state: &AppState, raw_email: &str) -> Result<(), AdminError> {
        let email = email(raw_email)?;
        let failed = |e: crate::error::ApiError| AdminError::Failed(e.to_string());
        let account = db::accounts::find_by_email(&state.db, &email)
            .await
            .map_err(|e| AdminError::Failed(e.to_string()))?
            .ok_or(AdminError::NoSuchAccount)?;
        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|e| AdminError::Failed(e.to_string()))?;
        let was_on = crate::routes::two_step::turn_off(state, &mut tx, &account.id)
            .await
            .map_err(failed)?;
        // Whoever might have been trusted along the way has to prove themselves again.
        db::two_step::forget_devices(&mut *tx, &account.id, None)
            .await
            .map_err(|e| AdminError::Failed(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AdminError::Failed(e.to_string()))?;
        if was_on {
            state.send_email(&email, crate::mail::Email::TwoStepDisabled);
        }
        Ok(())
    }

    /// Deletes the account exactly as the API would, minus the reauthentication.
    pub async fn delete_account(state: &AppState, raw_email: &str) -> Result<(), AdminError> {
        let email = email(raw_email)?;
        let account = db::accounts::find_by_email(&state.db, &email)
            .await
            .map_err(|e| AdminError::Failed(e.to_string()))?
            .ok_or(AdminError::NoSuchAccount)?;
        account_deletion::delete_account(state, &account.id, Authorization::Admin)
            .await
            .map_err(|e| AdminError::Failed(e.to_string()))
    }
}

/// Runs maintenance every few minutes for as long as the server lives, and backups when
/// `OCTAPASS_BACKUP_DIR` is set.
pub fn spawn_maintenance(state: AppState) {
    if let Some(backups) = state.config.backups.clone() {
        backup::spawn_schedule(state.clone(), backups);
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            if let Err(error) = state.run_maintenance().await {
                tracing::error!(%error, "maintenance failed");
            }
        }
    });
}
