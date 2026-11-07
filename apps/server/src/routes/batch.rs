//! Many item writes in one request, for imports. Atomic per vault: if any
//! operation on a vault fails, none of that vault's operations are applied.

use std::collections::HashSet;

use axum::Json;
use axum::extract::State;
use octapass_api::problem::Problem;
use octapass_api::{BatchOp, BatchOperation, BatchRequest, BatchResponse, BatchResult, IfMatch};

use crate::db;
use crate::db::items::{self, ItemWrite, Precondition, WriteError};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, Authenticated};
use crate::routes::vaults::validate_item;
use crate::state::AppState;
use crate::validate;

pub const MAX_OPERATIONS: usize = 1000;
/// 1,000 typical items fit easily; larger imports are split by the client.
pub const MAX_BODY: usize = 16 * 1024 * 1024;

#[utoipa::path(
    post, path = "/v1/batch", tag = "sync",
    security(("bearer" = [])),
    request_body = BatchRequest,
    responses(
        (status = 200, body = BatchResponse, description = "One result per operation, in order. \
            Operations on a vault where another operation failed answer 424 batch-aborted."),
        (status = 400, body = Problem, content_type = "application/problem+json", description = "Too many operations, a malformed id, or an item twice"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 413, body = Problem, content_type = "application/problem+json", description = "Body over 16 MiB"),
    )
)]
pub async fn batch(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiJson(request): ApiJson<BatchRequest>,
) -> ApiResult<Json<BatchResponse>> {
    let operations = request.operations;
    if operations.len() > MAX_OPERATIONS {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_OPERATIONS} operations per batch"
        )));
    }
    let mut seen = HashSet::with_capacity(operations.len());
    for (i, op) in operations.iter().enumerate() {
        validate::id(&format!("operations[{i}].vaultId"), &op.vault_id)?;
        validate::id(&format!("operations[{i}].itemId"), &op.item_id)?;
        if !seen.insert((op.vault_id.as_str(), op.item_id.as_str())) {
            return Err(ApiError::BadRequest(format!(
                "operations[{i}] repeats an item that's already in this batch"
            )));
        }
    }

    let mut outcomes: Vec<Option<ApiResult<u64>>> = operations.iter().map(|_| None).collect();
    let now = db::now();
    for indices in by_vault(&operations) {
        let vault_id = operations[indices[0]].vault_id.as_str();
        let writes: Vec<ApiResult<ItemWrite<'_>>> = indices
            .iter()
            .map(|&i| item_write(&operations[i]))
            .collect();
        let results: Vec<ApiResult<u64>> = if writes.iter().any(Result::is_err) {
            writes.into_iter().map(|w| w.map(|_| 0)).collect()
        } else {
            let writes = indices
                .iter()
                .zip(writes)
                .map(|(&i, w)| (operations[i].item_id.as_str(), w.expect("checked above")))
                .collect();
            write_vault(&state, &session.account_id, vault_id, writes, now).await?
        };
        let failed = results.iter().any(Result::is_err);
        for (&i, result) in indices.iter().zip(results) {
            outcomes[i] = Some(match result {
                Ok(_) if failed => Err(ApiError::BatchAborted),
                result => result,
            });
        }
    }

    let results = operations
        .into_iter()
        .zip(outcomes)
        .map(
            |(op, outcome)| match outcome.expect("every operation has an outcome") {
                Ok(revision) => BatchResult {
                    item_id: op.item_id,
                    status: 200,
                    revision: Some(revision),
                    problem: None,
                },
                Err(error) => {
                    let problem = error.into_problem();
                    BatchResult {
                        item_id: op.item_id,
                        status: problem.status,
                        revision: None,
                        problem: Some(problem),
                    }
                }
            },
        )
        .collect();
    Ok(Json(BatchResponse { results }))
}

/// Operation indices grouped by vault, in order of first appearance.
fn by_vault(operations: &[BatchOperation]) -> Vec<Vec<usize>> {
    let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
    for (i, op) in operations.iter().enumerate() {
        match groups
            .iter_mut()
            .find(|(vault_id, _)| *vault_id == op.vault_id)
        {
            Some((_, indices)) => indices.push(i),
            None => groups.push((&op.vault_id, vec![i])),
        }
    }
    groups.into_iter().map(|(_, indices)| indices).collect()
}

/// The checks the single-item endpoints make, for one operation.
fn item_write(op: &BatchOperation) -> ApiResult<ItemWrite<'_>> {
    match op.op {
        BatchOp::Put => {
            let item = op
                .item
                .as_ref()
                .ok_or_else(|| ApiError::BadRequest("put needs an item".into()))?;
            validate_item(item)?;
            let precondition = match op.if_match {
                None => Precondition::Create,
                Some(IfMatch::Revision(revision)) => Precondition::Revision(revision),
                Some(IfMatch::Any(_)) => Precondition::Any,
            };
            Ok(ItemWrite::Put(precondition, item))
        }
        BatchOp::Delete => match op.if_match {
            None => Err(ApiError::PreconditionRequired),
            Some(IfMatch::Revision(revision)) => Ok(ItemWrite::Delete(Some(revision))),
            Some(IfMatch::Any(_)) => Ok(ItemWrite::Delete(None)),
        },
        BatchOp::Restore => Ok(ItemWrite::Restore),
    }
}

/// Writes one vault's operations in a transaction and announces the new
/// revision. A vault-wide refusal (no access, read-only, over quota) becomes
/// every operation's result; a database error fails the whole request.
async fn write_vault(
    state: &AppState,
    account_id: &str,
    vault_id: &str,
    writes: Vec<(&str, ItemWrite<'_>)>,
    now: i64,
) -> ApiResult<Vec<ApiResult<u64>>> {
    let count = writes.len();
    let quota = state.config.quota;
    let results = match items::write_all(&state.db, account_id, vault_id, writes, quota, now).await
    {
        Ok(results) => results,
        Err(WriteError::Db(error)) => return Err(error.into()),
        Err(error) => {
            let refusal: fn() -> ApiError = match error {
                WriteError::ReadOnly => || ApiError::Forbidden,
                WriteError::QuotaExceeded => || ApiError::QuotaExceeded,
                _ => || ApiError::NotFound,
            };
            return Ok((0..count).map(|_| Err(refusal())).collect());
        }
    };
    let committed = results.iter().all(Result::is_ok);
    let revision = results
        .iter()
        .flatten()
        .filter(|w| w.changed)
        .map(|w| w.revision)
        .max();
    if committed && let Some(revision) = revision {
        state.vault_changed(vault_id, revision).await;
    }
    Ok(results
        .into_iter()
        .map(|r| r.map(|w| w.revision).map_err(ApiError::from))
        .collect())
}
