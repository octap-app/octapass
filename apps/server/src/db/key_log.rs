//! The key log's storage: leaves, the perfect subtrees proofs are built from, and the tree size.
//!
//! Nothing here changes once written, except a record forgotten with its account, so a reader that
//! takes the size first can read the rest without a transaction.

use octapass_core::encoding::{b64_decode_array, b64_encode};
use octapass_core::transparency::merkle::{Hash, NodeId, completed_parents, node_hash};

use super::{Conn, Db};

/// One appender at a time. Writes first, so SQLite's transaction doesn't start on a read snapshot
/// that a concurrent write could make stale.
pub async fn lock(conn: &mut Conn) -> Result<u64, sqlx::Error> {
    let size: i64 = sqlx::query_scalar(
        "UPDATE key_log_state SET tree_size = tree_size WHERE id = 1 RETURNING tree_size",
    )
    .fetch_one(conn)
    .await?;
    Ok(to_u64(size))
}

pub async fn size(db: &Db) -> Result<u64, sqlx::Error> {
    let size: i64 = sqlx::query_scalar("SELECT tree_size FROM key_log_state WHERE id = 1")
        .fetch_one(db)
        .await?;
    Ok(to_u64(size))
}

fn to_u64(value: i64) -> u64 {
    u64::try_from(value).expect("tree positions aren't negative")
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).expect("tree positions fit in i64")
}

fn decode(hash: &str) -> Hash {
    b64_decode_array(hash).expect("stored hashes are 32 bytes of base64url")
}

async fn put_node(conn: &mut Conn, node: NodeId, hash: &Hash) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO key_log_nodes (level, idx, hash) VALUES ($1, $2, $3)")
        .bind(i64::from(node.level))
        .bind(to_i64(node.index))
        .bind(b64_encode(hash))
        .execute(conn)
        .await?;
    Ok(())
}

async fn node(conn: &mut Conn, node: NodeId) -> Result<Hash, sqlx::Error> {
    let hash: String =
        sqlx::query_scalar("SELECT hash FROM key_log_nodes WHERE level = $1 AND idx = $2")
            .bind(i64::from(node.level))
            .bind(to_i64(node.index))
            .fetch_one(conn)
            .await?;
    Ok(decode(&hash))
}

/// What a new leaf holds.
pub struct NewLeaf<'a> {
    pub index: u64,
    pub label: &'a str,
    pub record_hash: &'a str,
    pub leaf_hash: Hash,
    pub record: &'a str,
    pub account_id: &'a str,
}

/// Appends a leaf at the size `lock` returned, inside the caller's transaction.
pub async fn append(conn: &mut Conn, leaf: NewLeaf<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO key_log_leaves (leaf_index, label, record_hash, record, account_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(to_i64(leaf.index))
    .bind(leaf.label)
    .bind(leaf.record_hash)
    .bind(leaf.record)
    .bind(leaf.account_id)
    .execute(&mut *conn)
    .await?;
    put_node(
        conn,
        NodeId {
            level: 0,
            index: leaf.index,
        },
        &leaf.leaf_hash,
    )
    .await?;
    let mut below = leaf.leaf_hash;
    for (parent, left) in completed_parents(leaf.index) {
        below = node_hash(&node(conn, left).await?, &below);
        put_node(conn, parent, &below).await?;
    }
    sqlx::query("UPDATE key_log_state SET tree_size = $1 WHERE id = 1")
        .bind(to_i64(leaf.index + 1))
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn nodes(conn: &mut Conn, ids: &[NodeId]) -> Result<Vec<Hash>, sqlx::Error> {
    let mut hashes = Vec::with_capacity(ids.len());
    for id in ids {
        hashes.push(node(conn, *id).await?);
    }
    Ok(hashes)
}

/// The newest leaf under a label below `size`, while its record is still kept.
pub async fn latest(
    conn: &mut Conn,
    label: &str,
    size: u64,
) -> Result<Option<(u64, String)>, sqlx::Error> {
    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT leaf_index, record FROM key_log_leaves \
         WHERE label = $1 AND leaf_index < $2 AND record IS NOT NULL \
         ORDER BY leaf_index DESC LIMIT 1",
    )
    .bind(label)
    .bind(to_i64(size))
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(index, record)| (to_u64(index), record)))
}

/// The leaf of an account's own record, by its hash.
pub async fn leaf_of(
    conn: &mut Conn,
    label: &str,
    record_hash: &str,
) -> Result<Option<u64>, sqlx::Error> {
    let index: Option<i64> = sqlx::query_scalar(
        "SELECT leaf_index FROM key_log_leaves WHERE label = $1 AND record_hash = $2",
    )
    .bind(label)
    .bind(record_hash)
    .fetch_optional(conn)
    .await?;
    Ok(index.map(to_u64))
}

/// Leaves `start..end` as `(label, record hash)`.
pub async fn leaves(
    conn: &mut Conn,
    start: u64,
    end: u64,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT label, record_hash FROM key_log_leaves \
         WHERE leaf_index >= $1 AND leaf_index < $2 ORDER BY leaf_index",
    )
    .bind(to_i64(start))
    .bind(to_i64(end))
    .fetch_all(conn)
    .await
}

/// Keeps the account's key material and its pairing with a leaf from outliving it.
pub async fn forget_records(conn: &mut Conn, account_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE key_log_leaves SET record = NULL, account_id = NULL WHERE account_id = $1")
        .bind(account_id)
        .execute(conn)
        .await?;
    Ok(())
}

/// Stores the account's ML-KEM key and key record.
pub async fn set_account_keys(
    conn: &mut Conn,
    account_id: &str,
    wrapped_pq_private_key: &str,
    record: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE accounts SET wrapped_pq_private_key = $1, key_record = $2 WHERE id = $3")
        .bind(wrapped_pq_private_key)
        .bind(record)
        .bind(account_id)
        .execute(conn)
        .await?;
    Ok(())
}

/// The account's stored record, read inside the appender's transaction.
pub async fn account_record(
    conn: &mut Conn,
    account_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    let record: Option<Option<String>> =
        sqlx::query_scalar("SELECT key_record FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_optional(conn)
            .await?;
    Ok(record.flatten())
}

/// The size a witness last cosigned, as far as this server knows.
pub async fn witness_size(db: &Db, vkey: &str) -> Result<Option<u64>, sqlx::Error> {
    let size: Option<i64> =
        sqlx::query_scalar("SELECT tree_size FROM key_log_witness_sizes WHERE vkey = $1")
            .bind(vkey)
            .fetch_optional(db)
            .await?;
    Ok(size.map(to_u64))
}

pub async fn set_witness_size(db: &Db, vkey: &str, size: u64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO key_log_witness_sizes (vkey, tree_size) VALUES ($1, $2) \
         ON CONFLICT (vkey) DO UPDATE SET tree_size = excluded.tree_size",
    )
    .bind(vkey)
    .bind(to_i64(size))
    .execute(db)
    .await?;
    Ok(())
}

/// The newest checkpoint a quorum of witnesses cosigned: its size and the signed note.
pub async fn witnessed(db: &Db) -> Result<Option<(u64, String)>, sqlx::Error> {
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT tree_size, checkpoint FROM key_log_witnessed WHERE id = 1")
            .fetch_optional(db)
            .await?;
    Ok(row.map(|(size, checkpoint)| (to_u64(size), checkpoint)))
}

pub async fn set_witnessed(db: &Db, size: u64, checkpoint: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO key_log_witnessed (id, tree_size, checkpoint) VALUES (1, $1, $2) \
         ON CONFLICT (id) DO UPDATE SET tree_size = excluded.tree_size, \
         checkpoint = excluded.checkpoint",
    )
    .bind(to_i64(size))
    .bind(checkpoint)
    .execute(db)
    .await?;
    Ok(())
}
