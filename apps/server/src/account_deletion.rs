//! Deleting an account: everything linked to it, in one transaction, then a
//! confirmation email.

use octapass_api::ReauthPurpose;

use crate::db;
use crate::error::{ApiError, ApiResult};
use crate::events::Event;
use crate::mail::Email;
use crate::state::AppState;
use crate::validate;

pub enum Authorization<'a> {
    /// The account holder, who proved their master password moments ago.
    User {
        reauth_token: &'a str,
        confirm_email: &'a str,
    },
    /// The server operator, through the admin CLI.
    Admin,
}

pub async fn delete_account(
    state: &AppState,
    account_id: &str,
    authorization: Authorization<'_>,
) -> ApiResult<()> {
    let now = db::now();
    let mut tx = state.db.begin().await?;
    if let Authorization::User {
        reauth_token,
        confirm_email,
    } = authorization
    {
        // Consuming the token is a write, so it also takes the write lock up front.
        let purpose = ReauthPurpose::DeleteAccount.as_str();
        if !db::sessions::consume_reauth_token(&mut tx, reauth_token, account_id, purpose, now)
            .await?
        {
            return Err(ApiError::ReauthRequired);
        }
        // A mismatch returns early, rolling back and so keeping the token usable.
        let email = db::accounts::email_for(&mut tx, account_id).await?;
        if email.is_none() || validate::email(confirm_email).ok() != email {
            return Err(ApiError::BadRequest(
                "confirmEmail doesn't match the account email".into(),
            ));
        }
    }
    let deleted = db::deletion::delete_account(&mut tx, account_id, now)
        .await?
        .ok_or(ApiError::NotFound)?;
    let email = deleted.email;
    db::accounts::delete_counters(&mut tx, &state.signup_counter_key(&email)).await?;
    // In the same transaction: an account can't go without its aliases being queued to go too.
    crate::relay::queue_deletion(state, &mut tx, account_id, now).await?;
    tx.commit().await?;
    // The account's files go from storage now, or on a later try if it's unreachable.
    crate::storage::drain_soon(state);
    crate::relay::drain_soon(state);
    if let Err(error) = db::checkpoint(&state.db).await {
        tracing::warn!(%error, "WAL checkpoint after account deletion failed");
    }

    tracing::info!("account deleted");
    state.events.send(account_id, Event::AccountDeleted);
    for (vault_id, members) in deleted.vault_members {
        for member in members {
            let event = Event::MembershipChanged {
                vault_id: vault_id.clone(),
            };
            state.events.send(&member, event);
        }
    }
    state.send_email(&email, Email::AccountDeleted);
    Ok(())
}
