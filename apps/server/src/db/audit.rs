//! The account's own security log. Entries name the other account involved
//! only by id, and lose it when that account is deleted.

use octapass_api::{ExportFormat, SecurityEvent, SecurityEventType};
use sqlx::FromRow;

use super::{Conn, Db, days, rfc3339};

/// Entries older than this are dropped.
const RETENTION: i64 = days(365);
/// The most entries one response returns.
const MAX_LISTED: i64 = 500;

pub async fn record<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Any>,
    account_id: &str,
    event: SecurityEventType,
    other_account_id: Option<&str>,
    emergency_contact_id: Option<&str>,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (id, account_id, event_type, other_account_id, emergency_contact_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(account_id)
    .bind(event.as_str())
    .bind(other_account_id)
    .bind(emergency_contact_id)
    .bind(now)
    .execute(executor)
    .await?;
    Ok(())
}

/// A device saved an export: its name and platform are copied in, so the entry still names it
/// after the device signs out.
pub async fn record_export(
    db: &Db,
    account_id: &str,
    device_id: &str,
    format: ExportFormat,
    attachments: bool,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (id, account_id, event_type, device_name, device_platform, export_format, export_attachments, created_at) \
         SELECT $1, $2, $3, d.name, d.platform, $4, $5, $6 FROM devices d WHERE d.id = $7",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(account_id)
    .bind(SecurityEventType::VaultExported.as_str())
    .bind(format.as_str())
    .bind(i64::from(attachments))
    .bind(now)
    .bind(device_id)
    .execute(db)
    .await?;
    Ok(())
}

/// A service account's entry, in the log of the account that made it.
pub async fn record_service_account<'e>(
    executor: impl sqlx::Executor<'e, Database = sqlx::Any>,
    account_id: &str,
    event: SecurityEventType,
    service_account_id: &str,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events (id, account_id, event_type, service_account_id, created_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(account_id)
    .bind(event.as_str())
    .bind(service_account_id)
    .bind(now)
    .execute(executor)
    .await?;
    Ok(())
}

/// What Octa Pass Connect handed out: blobs only the account can open.
pub async fn record_connect(
    conn: &mut Conn,
    account_id: &str,
    sealed_details: &[String],
    now: i64,
) -> Result<(), sqlx::Error> {
    for sealed in sealed_details {
        sqlx::query(
            "INSERT INTO audit_events (id, account_id, event_type, sealed_detail, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(uuid::Uuid::now_v7().to_string())
        .bind(account_id)
        .bind(SecurityEventType::ConnectSecretRead.as_str())
        .bind(sealed)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

#[derive(FromRow)]
struct EventRow {
    id: String,
    event_type: String,
    created_at: i64,
    other_email: Option<String>,
    emergency_contact_id: Option<String>,
    device_name: Option<String>,
    device_platform: Option<String>,
    export_format: Option<String>,
    export_attachments: Option<i64>,
    service_account_id: Option<String>,
    sealed_detail: Option<String>,
}

const SELECT_EVENTS: &str = "SELECT e.id, e.event_type, e.created_at, o.email AS other_email, e.emergency_contact_id, \
     e.device_name, e.device_platform, e.export_format, e.export_attachments, e.service_account_id, \
     e.sealed_detail FROM audit_events e LEFT JOIN accounts o ON o.id = e.other_account_id";

/// Busy machines write these all day; they're listed apart, so they can't push a password change
/// out of the response.
const FREQUENT: &str = "('service-account-read', 'service-account-wrote', 'connect-secret-read')";

/// Newest first: the last entries of each kind, so at most twice `MAX_LISTED`.
pub async fn list(db: &Db, account_id: &str) -> Result<Vec<SecurityEvent>, sqlx::Error> {
    let mut rows: Vec<EventRow> = Vec::new();
    for filter in ["NOT IN", "IN"] {
        let query = format!(
            "{SELECT_EVENTS} WHERE e.account_id = $1 AND e.event_type {filter} {FREQUENT} \
             ORDER BY e.created_at DESC, e.id DESC LIMIT $2"
        );
        rows.extend(
            sqlx::query_as::<_, EventRow>(sqlx::AssertSqlSafe(query))
                .bind(account_id)
                .bind(MAX_LISTED)
                .fetch_all(db)
                .await?,
        );
    }
    rows.sort_by(|a, b| (b.created_at, b.id.as_str()).cmp(&(a.created_at, a.id.as_str())));
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            Some(SecurityEvent {
                event_type: SecurityEventType::parse(&row.event_type)?,
                created_at: rfc3339(row.created_at),
                other_account_email: row.other_email,
                emergency_contact_id: row.emergency_contact_id,
                device_name: row.device_name,
                device_platform: row.device_platform,
                export_format: row.export_format.as_deref().and_then(ExportFormat::parse),
                export_attachments: row.export_attachments.map(|value| value != 0),
                service_account_id: row.service_account_id,
                sealed_detail: row.sealed_detail,
            })
        })
        .collect())
}

/// For account deletion: the account's own log goes, and other logs forget it.
pub async fn forget_account(conn: &mut Conn, account_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM audit_events WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE audit_events SET other_account_id = NULL WHERE other_account_id = $1")
        .bind(account_id)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn purge_old(db: &Db, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM audit_events WHERE created_at <= $1")
        .bind(now - RETENTION)
        .execute(db)
        .await?;
    Ok(())
}
