//! The parts of the emergency-access timeline that happen without a request:
//! the release once the waiting period is over, and the daily reminders to
//! the grantor while a request waits. Maintenance runs both; the endpoints
//! also release due requests before answering, so nobody waits for the next
//! maintenance run.

use octapass_api::SecurityEventType;

use crate::db::{self, emergency::ContactRow};
use crate::mail::{Email, readable_time};
use crate::state::AppState;

/// Releases every request whose waiting period is over.
pub async fn release_due(state: &AppState, now: i64) -> Result<(), sqlx::Error> {
    for row in db::emergency::due(&state.db, now).await? {
        release(
            state,
            &row,
            SecurityEventType::EmergencyAccessReleased,
            now,
            true,
        )
        .await?;
    }
    Ok(())
}

/// Releases one pending request, logs it for the grantor and tells both
/// sides. Does nothing if the request is no longer pending or, with
/// `due_only` (automatic releases), if its waiting period isn't over.
pub async fn release(
    state: &AppState,
    row: &ContactRow,
    event: SecurityEventType,
    now: i64,
    due_only: bool,
) -> Result<bool, sqlx::Error> {
    let mut tx = state.db.begin().await?;
    if !db::emergency::release(&mut tx, &row.id, now, due_only).await? {
        return Ok(false);
    }
    db::audit::record(
        &mut *tx,
        &row.grantor_id,
        event,
        Some(&row.contact_id),
        Some(&row.id),
        now,
    )
    .await?;
    tx.commit().await?;
    state.send_email(
        &row.contact_email,
        Email::EmergencyAccessReleased {
            other: row.grantor_email.clone(),
            to_grantor: false,
        },
    );
    state.send_email(
        &row.grantor_email,
        Email::EmergencyAccessReleased {
            other: row.contact_email.clone(),
            to_grantor: true,
        },
    );
    Ok(true)
}

/// Reminds grantors, once a day, of requests they haven't answered.
pub async fn send_reminders(state: &AppState, now: i64) -> Result<(), sqlx::Error> {
    for row in db::emergency::take_reminders(&state.db, now).await? {
        let email = requested_email(&row, true);
        state.send_email(&row.grantor_email, email);
    }
    Ok(())
}

pub fn requested_email(row: &ContactRow, reminder: bool) -> Email {
    Email::EmergencyAccessRequested {
        contact: row.contact_email.clone(),
        releases_on: row.releases_at.map(readable_time).unwrap_or_default(),
        reminder,
    }
}
