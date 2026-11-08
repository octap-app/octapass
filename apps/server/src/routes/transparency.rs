//! The key log (plan 03). Clients check what comes out of here; the server's job is to append,
//! prove and never rewrite. Everything needs a signed-in account.

use axum::Json;
use axum::extract::State;
use octapass_api::problem::Problem;
use octapass_api::{
    KeyLogEntriesResponse, KeyLogEntry, KeyLogHead, KeyLogHeadResponse, KeyLogIdentity,
    KeyLogLabelRequest, KeyLogLabelResponse, KeyLogProofResponse, KeyLogWitnessPolicy,
    KeyLogWitnessed, KeyRecord, PublishKeysRequest, PublishKeysResponse,
};
use octapass_core::encoding::b64_encode;
use octapass_core::sharing::pq::PqPublicKey;
use octapass_core::transparency::merkle::{
    self, Hash, consistency_ranges, inclusion_ranges, range_nodes,
};
use octapass_core::transparency::record::{self, OfferedKeys};
use rand_core::OsRng;
use serde::Deserialize;

use crate::db::key_log::NewLeaf;
use crate::db::{Conn, accounts, key_log};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiQuery, Authenticated};
use crate::state::AppState;
use crate::validate;

/// Monitors read at most this many leaves a request (640 KB).
const MAX_PAGE: u64 = 10_000;
const LABEL_LEN: usize = 32;
const MAX_WRAPPED_PQ_KEY: usize = 256;

fn identity(state: &AppState) -> KeyLogIdentity {
    let log = &state.key_log.identity;
    KeyLogIdentity {
        sign_key: log.sign_key.clone(),
        oprf_key: log.oprf_key.clone(),
    }
}

pub(crate) async fn subtree_hash(
    conn: &mut Conn,
    range: core::ops::Range<u64>,
) -> Result<Hash, sqlx::Error> {
    let hashes = key_log::nodes(conn, &range_nodes(range)).await?;
    Ok(merkle::fold_nodes(&hashes).unwrap_or_else(merkle::empty_root))
}

async fn proof_hashes(
    conn: &mut Conn,
    ranges: Vec<core::ops::Range<u64>>,
) -> Result<Vec<String>, sqlx::Error> {
    let mut hashes = Vec::with_capacity(ranges.len());
    for range in ranges {
        hashes.push(b64_encode(&subtree_hash(conn, range).await?));
    }
    Ok(hashes)
}

/// A head of `size` signed now, and the proof from `since`. Heads are signed on demand: signing is
/// cheap, and a fresh timestamp is what tells clients the log hasn't been frozen.
async fn head_at(
    state: &AppState,
    conn: &mut Conn,
    size: u64,
    since: u64,
) -> ApiResult<(KeyLogHead, Vec<String>)> {
    let root = subtree_hash(conn, 0..size).await?;
    let head = state.key_log.sign_head(
        size,
        &root,
        u64::try_from(state.clock.now()).unwrap_or_default(),
    );
    let consistency = proof_hashes(conn, consistency_ranges(since, size)).await?;
    Ok((
        KeyLogHead {
            tree_size: head.tree_size,
            root_hash: head.root_hash,
            timestamp: head.timestamp,
            signature: head.signature,
        },
        consistency,
    ))
}

/// What clients need to hold the log to its witnesses: which ones, and the newest checkpoint a
/// quorum of them cosigned with the proof that a head of `size` extends it. Read `witnessed`
/// before the size: the tree only grows, so the size read afterwards can't be smaller. Nothing
/// is offered until a quorum has cosigned once.
struct Witnessing {
    witnesses: Option<KeyLogWitnessPolicy>,
    witnessed: Option<(u64, String)>,
}

async fn witnessing(state: &AppState) -> ApiResult<Witnessing> {
    let Some(config) = &state.config.key_log_witnesses else {
        return Ok(Witnessing {
            witnesses: None,
            witnessed: None,
        });
    };
    Ok(Witnessing {
        witnesses: Some(KeyLogWitnessPolicy {
            witnesses: config.witnesses.iter().map(|w| w.vkey.clone()).collect(),
            quorum: config.quorum,
        }),
        witnessed: key_log::witnessed(&state.db).await?,
    })
}

impl Witnessing {
    async fn at(
        self,
        conn: &mut Conn,
        size: u64,
    ) -> ApiResult<(Option<KeyLogWitnessPolicy>, Option<KeyLogWitnessed>)> {
        // The policy is offered only once a quorum has cosigned: devices pin it, and a server
        // still waiting for its witnesses to add the log mustn't make every device refuse it.
        match self.witnessed {
            Some((at, checkpoint)) if at <= size => Ok((
                self.witnesses,
                Some(KeyLogWitnessed {
                    checkpoint,
                    consistency: proof_hashes(conn, consistency_ranges(at, size)).await?,
                }),
            )),
            _ => Ok((None, None)),
        }
    }
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HeadQuery {
    /// The size of the head this device pinned, for a consistency proof.
    #[serde(default)]
    since: u64,
}

#[utoipa::path(
    get, path = "/v1/transparency/head", tag = "transparency",
    security(("bearer" = [])),
    params(HeadQuery),
    responses(
        (status = 200, body = KeyLogHeadResponse, description = "The newest signed head, with a consistency proof from `since`, and the log's witnesses and newest witnessed checkpoint when it has witnesses"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn head(
    State(state): State<AppState>,
    Authenticated(_): Authenticated,
    ApiQuery(query): ApiQuery<HeadQuery>,
) -> ApiResult<Json<KeyLogHeadResponse>> {
    let witnessing = witnessing(&state).await?;
    let size = key_log::size(&state.db).await?;
    let mut conn = state.db.acquire().await?;
    let (head, consistency) = head_at(&state, &mut conn, size, query.since.min(size)).await?;
    let (witnesses, witnessed) = witnessing.at(&mut conn, size).await?;
    Ok(Json(KeyLogHeadResponse {
        log: identity(&state),
        head,
        consistency,
        witnesses,
        witnessed,
    }))
}

#[utoipa::path(
    post, path = "/v1/transparency/label", tag = "transparency",
    security(("bearer" = [])),
    request_body = KeyLogLabelRequest,
    responses(
        (status = 200, body = KeyLogLabelResponse, description = "The VOPRF evaluation and its proof. The server never sees the email"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 429, body = Problem, content_type = "application/problem+json", description = "One label per email tried: this budget is what stops labels being used to test a list of emails"),
    )
)]
pub async fn label(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<KeyLogLabelRequest>,
) -> ApiResult<Json<KeyLogLabelResponse>> {
    state
        .key_log_label_limiter
        .check(&session.account_id)
        .map_err(ApiError::RateLimited)?;
    let evaluated = state
        .key_log
        .label_key
        .evaluate(&request.blinded, &mut OsRng)
        .map_err(|_| ApiError::BadRequest("blinded must be a blinded element".into()))?;
    Ok(Json(KeyLogLabelResponse {
        evaluated: evaluated.evaluated,
        proof: evaluated.proof,
    }))
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ProofQuery {
    /// base64url label.
    label: String,
    /// The size of the head this device pinned, for a consistency proof.
    #[serde(default)]
    since: u64,
}

#[utoipa::path(
    get, path = "/v1/transparency/proof", tag = "transparency",
    security(("bearer" = [])),
    params(ProofQuery),
    responses(
        (status = 200, body = KeyLogProofResponse, description = "The newest head and the label's newest record with its audit path, if it has one"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn proof(
    State(state): State<AppState>,
    Authenticated(_): Authenticated,
    ApiQuery(query): ApiQuery<ProofQuery>,
) -> ApiResult<Json<KeyLogProofResponse>> {
    validate::exact_bytes("label", &query.label, LABEL_LEN)?;
    let witnessing = witnessing(&state).await?;
    let size = key_log::size(&state.db).await?;
    let mut conn = state.db.acquire().await?;
    let (head, consistency) = head_at(&state, &mut conn, size, query.since.min(size)).await?;
    let (witnesses, witnessed) = witnessing.at(&mut conn, size).await?;
    let entry = match key_log::latest(&mut conn, &query.label, size).await? {
        Some((leaf_index, record)) => Some(KeyLogEntry {
            leaf_index,
            record: accounts::key_record(&record),
            inclusion: proof_hashes(&mut conn, inclusion_ranges(leaf_index, size)).await?,
        }),
        None => None,
    };
    Ok(Json(KeyLogProofResponse {
        log: identity(&state),
        head,
        consistency,
        witnesses,
        witnessed,
        entry,
    }))
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EntriesQuery {
    start: u64,
    /// Exclusive. At most 10,000 leaves are returned.
    end: u64,
}

#[utoipa::path(
    get, path = "/v1/transparency/entries", tag = "transparency",
    security(("bearer" = [])),
    params(EntriesQuery),
    responses(
        (status = 200, body = KeyLogEntriesResponse, description = "Leaves from `start`, and the frontier before them. Leaves hold no email and no public key"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn entries(
    State(state): State<AppState>,
    Authenticated(_): Authenticated,
    ApiQuery(query): ApiQuery<EntriesQuery>,
) -> ApiResult<Json<KeyLogEntriesResponse>> {
    let size = key_log::size(&state.db).await?;
    if query.start > query.end || query.end > size {
        return Err(ApiError::BadRequest(
            "start and end must lie within the log".into(),
        ));
    }
    let end = query.end.min(query.start + MAX_PAGE);
    let mut conn = state.db.acquire().await?;
    let frontier = key_log::nodes(&mut conn, &range_nodes(0..query.start))
        .await?
        .iter()
        .map(|hash| b64_encode(hash))
        .collect();
    let mut leaves = Vec::with_capacity((end - query.start) as usize * record::LEAF_LEN);
    for (label, record_hash) in key_log::leaves(&mut conn, query.start, end).await? {
        for part in [label, record_hash] {
            let bytes: [u8; 32] = octapass_core::encoding::b64_decode_array(&part)
                .expect("stored hashes are 32 bytes of base64url");
            leaves.extend_from_slice(&bytes);
        }
    }
    Ok(Json(KeyLogEntriesResponse {
        start: query.start,
        frontier,
        leaves: b64_encode(&leaves),
    }))
}

fn core_record(record: &KeyRecord) -> record::KeyRecord {
    record::KeyRecord {
        log_id: record.log_id.clone(),
        account_id: record.account_id.clone(),
        label: record.label.clone(),
        public_enc_key: record.public_enc_key.clone(),
        public_sign_key: record.public_sign_key.clone(),
        public_pq_key: record.public_pq_key.clone(),
        created_at: record.created_at,
        signature: record.signature.clone(),
    }
}

#[utoipa::path(
    post, path = "/v1/transparency/publish", tag = "transparency",
    security(("bearer" = [])),
    request_body = PublishKeysRequest,
    responses(
        (status = 200, body = PublishKeysResponse, description = "The record is in the log, and the account's ML-KEM key and record are stored. Sending the same record again answers the same"),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "The record isn't for this account, this log or this account's email, or isn't validly signed"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: another device published first. Take its record from `GET /v1/account`"),
    )
)]
pub async fn publish(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<PublishKeysRequest>,
) -> ApiResult<Json<PublishKeysResponse>> {
    let account = accounts::find_by_id(&state.db, &session.account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?
        .into_bundle();
    let refuse = |reason: &str| ApiError::BadRequest(format!("record {reason}"));
    let record = core_record(&request.record);
    validate::envelope(
        "wrappedPqPrivateKey",
        &request.wrapped_pq_private_key,
        MAX_WRAPPED_PQ_KEY,
    )?;
    if record.log_id != state.key_log.log_id_b64 {
        return Err(refuse("is for another log"));
    }
    let offered = OfferedKeys {
        account_id: &session.account_id,
        public_enc_key: &account.public_enc_key,
        public_sign_key: &account.public_sign_key,
    };
    record
        .verify_for(&offered)
        .map_err(|_| refuse("isn't this account's, or isn't validly signed"))?;
    PqPublicKey::from_b64(&record.public_pq_key)
        .map_err(|_| refuse("has a malformed ML-KEM key"))?;
    let label = state
        .key_log
        .label_key
        .label(&account.email)
        .map_err(|_| refuse("has an email that can't be labelled"))?;
    if record.label != b64_encode(&label) {
        return Err(refuse("isn't under this account's label"));
    }

    let record_hash = b64_encode(&record.record_hash());
    let leaf_hash = record
        .leaf_hash()
        .map_err(|_| refuse("has a malformed label"))?;
    let json = serde_json::to_string(&request.record).expect("records serialize");

    let mut tx = state.db.begin().await?;
    let size = key_log::lock(&mut tx).await?;
    if let Some(existing) = key_log::account_record(&mut tx, &session.account_id).await? {
        let existing = accounts::key_record(&existing);
        if existing == request.record {
            let index = key_log::leaf_of(&mut tx, &record.label, &record_hash)
                .await?
                .ok_or(ApiError::NotFound)?;
            return Ok(Json(PublishKeysResponse { leaf_index: index }));
        }
        // A record for this log stands: account keys don't change. One for an earlier log
        // (the server secret was lost) gives way.
        if existing.log_id == state.key_log.log_id_b64 {
            return Err(ApiError::AlreadyExists(
                "this account already has a key record: use the one in GET /v1/account",
            ));
        }
    }
    key_log::append(
        &mut tx,
        NewLeaf {
            index: size,
            label: &record.label,
            record_hash: &record_hash,
            leaf_hash,
            record: &json,
            account_id: &session.account_id,
        },
    )
    .await?;
    key_log::set_account_keys(
        &mut tx,
        &session.account_id,
        &request.wrapped_pq_private_key,
        &json,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(PublishKeysResponse { leaf_index: size }))
}
