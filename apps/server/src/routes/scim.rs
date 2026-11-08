//! SCIM 2.0 provisioning (RFC 7643, RFC 7644; plan 03, "SCIM provisioning"): an organisation's
//! identity provider says who should be a member and who is in which group. Each organisation has
//! its own bearer tokens, made by an owner, and a token reaches only its organisation.
//!
//! The provider never sees or moves a key. Provisioning a user invites them, and only the person
//! accepting on their own device makes them a member. Groups decide who *should* have a vault, and
//! a key holder still reviews and seals each grant. Deprovisioning removes a member at once, and
//! their organisation vaults are marked for rotation, as when an admin removes them.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use octapass_api::problem::Problem;
use octapass_api::{
    CreateScimTokenRequest, CreatedScimToken, OrgRole, OrgScimResponse, OrgScimTokenRecord,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::auth::charge;
use super::orgs::{locked, notify};
use crate::crypto::{random_token, token_hash};
use crate::db::orgs::{self, Reconciled, record_event_by};
use crate::db::scim::{self, Applied, Filter, ScimGroup, ScimUser};
use crate::db::{self, Conn};
use crate::error::{ApiError, ApiResult};
use crate::extract::{ApiJson, ApiPath, Authenticated, ClientIp};
use crate::mail::Email;
use crate::state::AppState;
use crate::validate;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const TOKEN_PREFIX: &str = "opscim_";
const MAX_TOKENS: i64 = 10;
const MAX_TOKEN_NAME: usize = 64;
const MAX_GROUP_NAME: usize = 64;
const MAX_FIELD: usize = 256;
const DEFAULT_COUNT: i64 = 100;
const MAX_COUNT: i64 = 200;
const MAX_OPERATIONS: usize = 1000;

// Errors, as SCIM wants them.

pub struct ScimError {
    status: StatusCode,
    scim_type: Option<&'static str>,
    detail: String,
}

type ScimResult<T> = Result<T, ScimError>;

impl ScimError {
    fn new(status: StatusCode, scim_type: Option<&'static str>, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type,
            detail: detail.into(),
        }
    }

    fn invalid(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some("invalidValue"), detail)
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, None, "no such resource")
    }

    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            None,
            "missing or invalid SCIM token",
        )
    }
}

impl From<sqlx::Error> for ScimError {
    fn from(error: sqlx::Error) -> Self {
        match error.as_database_error() {
            Some(db_error) if db_error.is_unique_violation() => Self::new(
                StatusCode::CONFLICT,
                Some("uniqueness"),
                "another resource already has this userName or displayName",
            ),
            _ => {
                tracing::error!(%error, "a SCIM request failed");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, None, "internal error")
            }
        }
    }
}

impl From<ApiError> for ScimError {
    fn from(error: ApiError) -> Self {
        let problem = error.into_problem();
        let status =
            StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Self::new(status, None, problem.detail.unwrap_or_default())
    }
}

fn scim_json(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/scim+json"),
    );
    response
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.as_u16().to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        scim_json(self.status, body)
    }
}

// Authentication.

/// The organisation an `Authorization: Bearer opscim_…` token belongs to.
pub struct ScimOrg(String);

impl FromRequestParts<AppState> for ScimOrg {
    type Rejection = ScimError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ScimError> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                value
                    .strip_prefix("Bearer ")
                    .or_else(|| value.strip_prefix("bearer "))
            })
            .map(str::trim)
            .filter(|token| token.starts_with(TOKEN_PREFIX));
        let org = match token {
            Some(token) => {
                scim::org_for_token(&state.db, &token_hash(token), state.clock.now()).await?
            }
            None => None,
        };
        match org {
            Some(org_id) => Ok(Self(org_id)),
            None => {
                // Wrong guesses spend the address's budget.
                let ClientIp(ip) = ClientIp::from_request_parts(parts, state).await?;
                charge(&state.ip_limiter, &ip)?;
                Err(ScimError::unauthorized())
            }
        }
    }
}

fn base_url(state: &AppState) -> String {
    format!(
        "{}/v1/scim/v2",
        state.config.public_url.trim_end_matches('/')
    )
}

/// Takes the organisation's lock first, as every organisation change does.
async fn begin(
    state: &AppState,
    org_id: &str,
) -> ScimResult<sqlx::Transaction<'static, sqlx::Any>> {
    let mut tx = state.db.begin().await?;
    if !orgs::lock(&mut tx, org_id).await? {
        return Err(ScimError::unauthorized());
    }
    Ok(tx)
}

/// Takes vault access away from everyone who no longer should have it. A provider's
/// deprovisioning goes ahead even if it leaves a vault with nobody to manage it: access must stop.
async fn reconcile(conn: &mut Conn, org_id: &str, now: i64) -> ScimResult<Reconciled> {
    let reconciled = orgs::reconcile(conn, org_id, now).await?;
    for vault_id in &reconciled.orphaned {
        record_event_by(
            conn,
            org_id,
            None,
            "scim-vault-orphaned",
            Some(vault_id),
            now,
        )
        .await?;
    }
    Ok(reconciled)
}

/// After the commit: notifications and emails.
async fn after(state: &AppState, reconciled: &Reconciled, applied: Applied) {
    notify(state, reconciled).await;
    for email in applied.invited {
        state.send_email(&email, Email::OrgProvisioned);
    }
    for email in applied.removed {
        state.send_email(&email, Email::OrgRemoved);
    }
}

// Parsing requests.

fn parse_body(body: &Bytes) -> ScimResult<Map<String, Value>> {
    match serde_json::from_slice(body) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(ScimError::new(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "the body must be a JSON object",
        )),
    }
}

/// Attribute names are case-insensitive.
fn get<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn string(object: &Map<String, Value>, name: &str) -> ScimResult<Option<String>> {
    match get(object, name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.trim().is_empty() => Ok(None),
        Some(Value::String(text)) if text.chars().count() <= MAX_FIELD => {
            Ok(Some(text.trim().to_owned()))
        }
        Some(_) => Err(ScimError::invalid(format!(
            "{name} must be a string of up to {MAX_FIELD} characters"
        ))),
    }
}

/// Some providers send booleans as strings ("False").
fn boolean(value: &Value) -> ScimResult<bool> {
    match value {
        Value::Bool(value) => Ok(*value),
        Value::String(text) if text.eq_ignore_ascii_case("true") => Ok(true),
        Value::String(text) if text.eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(ScimError::invalid("active must be true or false")),
    }
}

/// The address to invite: the primary email, else a work one, else the first, else the user name
/// if it's an email address.
fn email_of(object: &Map<String, Value>, user_name: &str) -> ScimResult<String> {
    let emails: Vec<&Map<String, Value>> = match get(object, "emails") {
        Some(Value::Array(emails)) => emails.iter().filter_map(Value::as_object).collect(),
        _ => Vec::new(),
    };
    let value = |email: &&Map<String, Value>| {
        get(email, "value")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let primary = emails
        .iter()
        .find(|email| {
            get(email, "primary").is_some_and(|primary| boolean(primary).unwrap_or(false))
        })
        .and_then(value);
    let work = emails
        .iter()
        .find(|email| get(email, "type").and_then(Value::as_str) == Some("work"))
        .and_then(value);
    let candidate = primary
        .or(work)
        .or_else(|| emails.first().and_then(value))
        .unwrap_or_else(|| user_name.to_owned());
    validate::email(&candidate).map_err(|_| ScimError::invalid("a user needs an email address"))
}

fn display_name_of(object: &Map<String, Value>) -> ScimResult<Option<String>> {
    if let Some(name) = string(object, "displayName")? {
        return Ok(Some(name));
    }
    let Some(Value::Object(name)) = get(object, "name") else {
        return Ok(None);
    };
    if let Some(formatted) = string(name, "formatted")? {
        return Ok(Some(formatted));
    }
    let parts: Vec<String> = [string(name, "givenName")?, string(name, "familyName")?]
        .into_iter()
        .flatten()
        .collect();
    Ok((!parts.is_empty()).then(|| parts.join(" ")))
}

/// A user resource from a POST or PUT body, onto `user`.
fn read_user(object: &Map<String, Value>, user: &mut ScimUser) -> ScimResult<()> {
    let user_name =
        string(object, "userName")?.ok_or_else(|| ScimError::invalid("userName is required"))?;
    if user_name.chars().any(char::is_control) {
        return Err(ScimError::invalid("userName can't hold control characters"));
    }
    user.email = email_of(object, &user_name)?;
    user.user_name = user_name;
    user.external_id = string(object, "externalId")?;
    user.display_name = display_name_of(object)?;
    user.set_active(match get(object, "active") {
        None | Some(Value::Null) => true,
        Some(value) => boolean(value)?,
    });
    Ok(())
}

/// `attr eq "value"`, the one filter providers use to find a resource before creating it.
fn parse_filter(filter: Option<&str>, group: bool) -> ScimResult<Filter> {
    let Some(filter) = filter.map(str::trim).filter(|filter| !filter.is_empty()) else {
        return Ok(Filter::None);
    };
    let invalid = || {
        ScimError::new(
            StatusCode::BAD_REQUEST,
            Some("invalidFilter"),
            "only `attribute eq \"value\"` filters are supported",
        )
    };
    let (attribute, rest) = filter.split_once(char::is_whitespace).ok_or_else(invalid)?;
    let rest = rest.trim_start();
    let (operator, value) = rest.split_once(char::is_whitespace).ok_or_else(invalid)?;
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(invalid());
    }
    let value: String = serde_json::from_str::<String>(value.trim()).map_err(|_| invalid())?;
    let attribute = attribute.to_ascii_lowercase();
    Ok(match (attribute.as_str(), group) {
        ("id", _) => Filter::Id(value),
        ("externalid", _) => Filter::ExternalId(value),
        ("displayname", _) => Filter::DisplayName(value),
        ("username", false) => Filter::UserName(value),
        ("emails" | "emails.value", false) => Filter::Email(value),
        _ => return Err(invalid()),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    #[serde(default)]
    filter: Option<String>,
    #[serde(default)]
    start_index: Option<i64>,
    #[serde(default)]
    count: Option<i64>,
    #[serde(default)]
    excluded_attributes: Option<String>,
}

impl ListQuery {
    fn page(&self) -> (i64, i64) {
        let start = self.start_index.unwrap_or(1).max(1);
        let count = self.count.unwrap_or(DEFAULT_COUNT).clamp(0, MAX_COUNT);
        (start, count)
    }
}

fn list_response(total: i64, start: i64, resources: Vec<Value>) -> Response {
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": [LIST_SCHEMA],
            "totalResults": total,
            "startIndex": start,
            "itemsPerPage": resources.len(),
            "Resources": resources,
        }),
    )
}

// Users.

fn user_json(state: &AppState, user: &ScimUser) -> Value {
    let mut value = json!({
        "schemas": [USER_SCHEMA],
        "id": user.id,
        "userName": user.user_name,
        "active": user.active(),
        "emails": [{ "value": user.email, "primary": true, "type": "work" }],
        "meta": {
            "resourceType": "User",
            "created": db::rfc3339(user.created_at),
            "lastModified": db::rfc3339(user.updated_at),
            "location": format!("{}/Users/{}", base_url(state), user.id),
        },
    });
    if let Some(external_id) = &user.external_id {
        value["externalId"] = json!(external_id);
    }
    if let Some(display_name) = &user.display_name {
        value["displayName"] = json!(display_name);
    }
    value
}

fn scim_id(raw: &str) -> ScimResult<String> {
    validate::id("id", raw).map_err(|_| ScimError::not_found())
}

pub async fn list_users(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let filter = parse_filter(query.filter.as_deref(), false)?;
    let (start, count) = query.page();
    let mut conn = state.db.acquire().await?;
    let (total, users) = scim::list_users(&mut conn, &org_id, &filter, start - 1, count).await?;
    let resources = users.iter().map(|user| user_json(&state, user)).collect();
    Ok(list_response(total, start, resources))
}

pub async fn get_user(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    ApiPath(id): ApiPath<String>,
) -> ScimResult<Response> {
    let id = scim_id(&id)?;
    let mut conn = state.db.acquire().await?;
    let user = scim::find_user(&mut conn, &org_id, &id)
        .await?
        .ok_or_else(ScimError::not_found)?;
    Ok(scim_json(StatusCode::OK, user_json(&state, &user)))
}

/// Stores the user and applies it, then reconciles: one transaction.
async fn save_user(
    state: &AppState,
    mut user: ScimUser,
    status: StatusCode,
    event: Option<&str>,
) -> ScimResult<Response> {
    let now = state.clock.now();
    user.updated_at = now;
    let org_id = user.org_id.clone();
    let mut tx = begin(state, &org_id).await?;
    let mut applied = Applied::default();
    scim::put_user(&mut tx, &user).await?;
    if let Some(event) = event {
        record_event_by(&mut tx, &org_id, None, event, Some(&user.email), now).await?;
    }
    scim::apply_user(&mut tx, &mut user, now, &mut applied).await?;
    let reconciled = reconcile(&mut tx, &org_id, now).await?;
    tx.commit().await?;
    after(state, &reconciled, applied).await;
    Ok(scim_json(status, user_json(state, &user)))
}

pub async fn create_user(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    body: Bytes,
) -> ScimResult<Response> {
    let object = parse_body(&body)?;
    let now = state.clock.now();
    let mut user = ScimUser::new(
        uuid::Uuid::now_v7().to_string(),
        org_id.clone(),
        String::new(),
        String::new(),
        now,
    );
    read_user(&object, &mut user)?;
    // A user name another user has is a unique violation, answered 409 uniqueness.
    save_user(
        &state,
        user,
        StatusCode::CREATED,
        Some("scim-user-provisioned"),
    )
    .await
}

async fn existing_user(state: &AppState, org_id: &str, id: &str) -> ScimResult<ScimUser> {
    let id = scim_id(id)?;
    let mut conn = state.db.acquire().await?;
    scim::find_user(&mut conn, org_id, &id)
        .await?
        .ok_or_else(ScimError::not_found)
}

pub async fn replace_user(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    ApiPath(id): ApiPath<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let object = parse_body(&body)?;
    let mut user = existing_user(&state, &org_id, &id).await?;
    read_user(&object, &mut user)?;
    save_user(&state, user, StatusCode::OK, None).await
}

struct Operation {
    op: String,
    path: Option<String>,
    value: Option<Value>,
}

fn operations(object: &Map<String, Value>) -> ScimResult<Vec<Operation>> {
    let schemas_ok = get(object, "schemas")
        .and_then(Value::as_array)
        .is_none_or(|schemas| schemas.iter().any(|schema| schema == PATCH_SCHEMA));
    let Some(Value::Array(list)) = get(object, "Operations").filter(|_| schemas_ok) else {
        return Err(ScimError::new(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "a PatchOp needs Operations",
        ));
    };
    if list.len() > MAX_OPERATIONS {
        return Err(ScimError::new(
            StatusCode::BAD_REQUEST,
            Some("tooMany"),
            "too many operations",
        ));
    }
    list.iter()
        .map(|operation| {
            let operation = operation.as_object().ok_or_else(|| {
                ScimError::new(
                    StatusCode::BAD_REQUEST,
                    Some("invalidSyntax"),
                    "an operation must be an object",
                )
            })?;
            let op = get(operation, "op")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                .filter(|op| matches!(op.as_str(), "add" | "replace" | "remove"))
                .ok_or_else(|| {
                    ScimError::new(
                        StatusCode::BAD_REQUEST,
                        Some("invalidSyntax"),
                        "op must be add, replace or remove",
                    )
                })?;
            Ok(Operation {
                op,
                path: get(operation, "path")
                    .and_then(Value::as_str)
                    .map(|path| path.trim().to_owned()),
                value: get(operation, "value").cloned(),
            })
        })
        .collect()
}

/// Sets one attribute of a user resource from a PATCH path. Attributes Octa Pass doesn't keep
/// (titles, phone numbers, the enterprise extension) are ignored, as RFC 7644 allows.
fn patch_user_attribute(resource: &mut Map<String, Value>, path: &str, value: Option<Value>) {
    let path = path
        .strip_prefix(USER_SCHEMA)
        .map_or(path, |rest| rest.trim_start_matches(':'));
    let lower = path.to_ascii_lowercase();
    let set = |resource: &mut Map<String, Value>, key: &str, value: Option<Value>| {
        resource.retain(|existing, _| !existing.eq_ignore_ascii_case(key));
        if let Some(value) = value {
            resource.insert(key.to_owned(), value);
        }
    };
    match lower.as_str() {
        "active" | "username" | "externalid" | "displayname" | "emails" | "name" => {
            let key = match lower.as_str() {
                "active" => "active",
                "username" => "userName",
                "externalid" => "externalId",
                "displayname" => "displayName",
                "emails" => "emails",
                _ => "name",
            };
            set(resource, key, value);
        }
        _ if lower.starts_with("emails[") => {
            // emails[type eq "work"].value and the like: the one email Octa Pass keeps.
            if let Some(Value::String(email)) = value {
                set(
                    resource,
                    "emails",
                    Some(json!([{ "value": email, "primary": true, "type": "work" }])),
                );
            }
        }
        _ if lower.starts_with("name.") => {
            let field = &path["name.".len()..];
            let name = resource.entry("name").or_insert_with(|| json!({}));
            if let Value::Object(name) = name {
                name.retain(|existing, _| !existing.eq_ignore_ascii_case(field));
                if let Some(value) = value {
                    name.insert(field.to_owned(), value);
                }
            }
        }
        _ => {}
    }
}

pub async fn patch_user(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    ApiPath(id): ApiPath<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let operations = operations(&parse_body(&body)?)?;
    let mut user = existing_user(&state, &org_id, &id).await?;
    let Value::Object(mut resource) = user_json(&state, &user) else {
        unreachable!("a user is an object");
    };
    for Operation { op, path, value } in operations {
        let value = if op == "remove" { None } else { value };
        match (path, value) {
            (Some(path), value) => patch_user_attribute(&mut resource, &path, value),
            (None, Some(Value::Object(values))) => {
                for (key, value) in values {
                    patch_user_attribute(&mut resource, &key, Some(value));
                }
            }
            (None, _) => {
                return Err(ScimError::new(
                    StatusCode::BAD_REQUEST,
                    Some("noTarget"),
                    "an operation without a path needs an object value",
                ));
            }
        }
    }
    read_user(&resource, &mut user)?;
    save_user(&state, user, StatusCode::OK, None).await
}

pub async fn delete_user(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    ApiPath(id): ApiPath<String>,
) -> ScimResult<StatusCode> {
    let mut user = existing_user(&state, &org_id, &id).await?;
    let now = state.clock.now();
    let mut tx = begin(&state, &org_id).await?;
    let mut applied = Applied::default();
    user.set_active(false);
    user.updated_at = now;
    scim::apply_user(&mut tx, &mut user, now, &mut applied).await?;
    scim::delete_user(&mut tx, &user.id).await?;
    let reconciled = reconcile(&mut tx, &org_id, now).await?;
    tx.commit().await?;
    after(&state, &reconciled, applied).await;
    Ok(StatusCode::NO_CONTENT)
}

// Groups.

fn group_json(state: &AppState, group: &ScimGroup, members: bool) -> Value {
    let base = base_url(state);
    let mut value = json!({
        "schemas": [GROUP_SCHEMA],
        "id": group.id,
        "displayName": group.name,
        "meta": {
            "resourceType": "Group",
            "created": db::rfc3339(group.created_at),
            "lastModified": db::rfc3339(group.created_at),
            "location": format!("{base}/Groups/{}", group.id),
        },
    });
    if members {
        value["members"] = group
            .members
            .iter()
            .map(|(id, user_name)| json!({ "value": id, "display": user_name, "$ref": format!("{base}/Users/{id}") }))
            .collect();
    }
    if let Some(external_id) = &group.external_id {
        value["externalId"] = json!(external_id);
    }
    value
}

fn group_name(value: Option<String>) -> ScimResult<String> {
    let name = value.ok_or_else(|| ScimError::invalid("displayName is required"))?;
    validate::text("displayName", &name, MAX_GROUP_NAME).map_err(|_| {
        ScimError::invalid(format!(
            "displayName must be 1 to {MAX_GROUP_NAME} printable characters"
        ))
    })
}

/// User ids from a `members` value: `[{ "value": id }, …]`.
fn member_ids(value: Option<&Value>) -> ScimResult<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let list = match value {
        Value::Array(list) => list.as_slice(),
        Value::Object(_) => std::slice::from_ref(value),
        Value::Null => &[],
        _ => return Err(ScimError::invalid("members must be a list")),
    };
    list.iter()
        .map(|member| {
            member
                .as_object()
                .and_then(|member| get(member, "value"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| ScimError::invalid("each member needs a value"))
        })
        .collect()
}

pub async fn list_groups(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let filter = parse_filter(query.filter.as_deref(), true)?;
    let (start, count) = query.page();
    let members = !query
        .excluded_attributes
        .as_deref()
        .is_some_and(|excluded| {
            excluded
                .split(',')
                .any(|name| name.trim().eq_ignore_ascii_case("members"))
        });
    let mut conn = state.db.acquire().await?;
    let (total, groups) =
        scim::list_groups(&mut conn, &org_id, &filter, start - 1, count, members).await?;
    let resources = groups
        .iter()
        .map(|group| group_json(&state, group, members))
        .collect();
    Ok(list_response(total, start, resources))
}

async fn existing_group(conn: &mut Conn, org_id: &str, id: &str) -> ScimResult<ScimGroup> {
    let id = scim_id(id)?;
    scim::find_group(conn, org_id, &id)
        .await?
        .ok_or_else(ScimError::not_found)
}

pub async fn get_group(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    ApiPath(id): ApiPath<String>,
) -> ScimResult<Response> {
    let mut conn = state.db.acquire().await?;
    let group = existing_group(&mut conn, &org_id, &id).await?;
    Ok(scim_json(StatusCode::OK, group_json(&state, &group, true)))
}

/// Applies a group's new member list, reconciles and answers with the group.
async fn finish_group(
    state: &AppState,
    mut tx: sqlx::Transaction<'static, sqlx::Any>,
    org_id: &str,
    group_id: &str,
    status: StatusCode,
) -> ScimResult<Response> {
    let now = state.clock.now();
    scim::apply_group(&mut tx, org_id, group_id).await?;
    let reconciled = reconcile(&mut tx, org_id, now).await?;
    let group = existing_group(&mut tx, org_id, group_id).await?;
    tx.commit().await?;
    after(state, &reconciled, Applied::default()).await;
    Ok(scim_json(status, group_json(state, &group, true)))
}

async fn set_members(
    conn: &mut Conn,
    org_id: &str,
    group_id: &str,
    ids: &[String],
) -> ScimResult<()> {
    scim::clear_group_members(conn, group_id).await?;
    for id in scim::known_users(conn, org_id, ids).await? {
        scim::add_group_member(conn, group_id, &id).await?;
    }
    Ok(())
}

pub async fn create_group(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    body: Bytes,
) -> ScimResult<Response> {
    let object = parse_body(&body)?;
    let name = group_name(string(&object, "displayName")?)?;
    let external_id = string(&object, "externalId")?;
    let members = member_ids(get(&object, "members"))?;
    let id = uuid::Uuid::now_v7().to_string();
    let now = state.clock.now();
    let mut tx = begin(&state, &org_id).await?;
    scim::create_group(&mut tx, &org_id, &id, &name, external_id.as_deref(), now).await?;
    set_members(&mut tx, &org_id, &id, &members).await?;
    record_event_by(
        &mut tx,
        &org_id,
        None,
        "scim-group-created",
        Some(&name),
        now,
    )
    .await?;
    finish_group(&state, tx, &org_id, &id, StatusCode::CREATED).await
}

pub async fn replace_group(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    ApiPath(id): ApiPath<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let object = parse_body(&body)?;
    let name = group_name(string(&object, "displayName")?)?;
    let external_id = string(&object, "externalId")?;
    let members = member_ids(get(&object, "members"))?;
    let mut tx = begin(&state, &org_id).await?;
    let group = existing_group(&mut tx, &org_id, &id).await?;
    scim::update_group(&mut tx, &group.id, &name, external_id.as_deref()).await?;
    set_members(&mut tx, &org_id, &group.id, &members).await?;
    let now = state.clock.now();
    record_event_by(
        &mut tx,
        &org_id,
        None,
        "scim-group-changed",
        Some(&name),
        now,
    )
    .await?;
    finish_group(&state, tx, &org_id, &group.id, StatusCode::OK).await
}

/// `members[value eq "id"]`: the id.
fn member_in_path(path: &str) -> Option<String> {
    let inner = path.strip_prefix("members[")?.strip_suffix(']')?.trim();
    let (attribute, rest) = inner.split_once(char::is_whitespace)?;
    let (operator, value) = rest.trim_start().split_once(char::is_whitespace)?;
    if !attribute.eq_ignore_ascii_case("value") || !operator.eq_ignore_ascii_case("eq") {
        return None;
    }
    serde_json::from_str(value.trim()).ok()
}

pub async fn patch_group(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    ApiPath(id): ApiPath<String>,
    body: Bytes,
) -> ScimResult<Response> {
    let operations = operations(&parse_body(&body)?)?;
    let mut tx = begin(&state, &org_id).await?;
    let group = existing_group(&mut tx, &org_id, &id).await?;
    let (mut name, mut external_id) = (group.name.clone(), group.external_id.clone());
    let mut members: Vec<String> = group.members.iter().map(|(id, _)| id.clone()).collect();
    for Operation { op, path, value } in operations {
        let lower = path.as_deref().map(str::to_ascii_lowercase);
        match (op.as_str(), lower.as_deref(), value) {
            (_, Some("displayname"), value) if op != "remove" => {
                name = group_name(value.and_then(|value| value.as_str().map(str::to_owned)))?;
            }
            (_, Some("externalid"), value) => {
                external_id = value.and_then(|value| value.as_str().map(str::to_owned));
            }
            ("add", Some("members"), value) => {
                for id in member_ids(value.as_ref())? {
                    if !members.contains(&id) {
                        members.push(id);
                    }
                }
            }
            ("replace", Some("members"), value) => members = member_ids(value.as_ref())?,
            ("remove", Some("members"), None) => members.clear(),
            ("remove", Some("members"), Some(value)) => {
                let gone = member_ids(Some(&value))?;
                members.retain(|id| !gone.contains(id));
            }
            ("remove", Some(path), _) if path.starts_with("members[") => {
                let id = member_in_path(path).ok_or_else(|| {
                    ScimError::new(
                        StatusCode::BAD_REQUEST,
                        Some("invalidPath"),
                        "unsupported members filter",
                    )
                })?;
                members.retain(|member| !member.eq_ignore_ascii_case(&id));
            }
            (_, None, Some(Value::Object(values))) => {
                if let Some(value) = get(&values, "displayName") {
                    name = group_name(value.as_str().map(str::to_owned))?;
                }
                if let Some(value) = get(&values, "externalId") {
                    external_id = value.as_str().map(str::to_owned);
                }
                if let Some(value) = get(&values, "members") {
                    let listed = member_ids(Some(value))?;
                    if op == "add" {
                        for id in listed {
                            if !members.contains(&id) {
                                members.push(id);
                            }
                        }
                    } else {
                        members = listed;
                    }
                }
            }
            _ => {
                return Err(ScimError::new(
                    StatusCode::BAD_REQUEST,
                    Some("invalidPath"),
                    "unsupported operation on a group",
                ));
            }
        }
    }
    scim::update_group(&mut tx, &group.id, &name, external_id.as_deref()).await?;
    set_members(&mut tx, &org_id, &group.id, &members).await?;
    let now = state.clock.now();
    record_event_by(
        &mut tx,
        &org_id,
        None,
        "scim-group-changed",
        Some(&name),
        now,
    )
    .await?;
    finish_group(&state, tx, &org_id, &group.id, StatusCode::OK).await
}

pub async fn delete_group(
    State(state): State<AppState>,
    ScimOrg(org_id): ScimOrg,
    ApiPath(id): ApiPath<String>,
) -> ScimResult<StatusCode> {
    let now = state.clock.now();
    let mut tx = begin(&state, &org_id).await?;
    let group = existing_group(&mut tx, &org_id, &id).await?;
    orgs::delete_group(&mut tx, &group.id).await?;
    record_event_by(
        &mut tx,
        &org_id,
        None,
        "scim-group-deleted",
        Some(&group.name),
        now,
    )
    .await?;
    let reconciled = reconcile(&mut tx, &org_id, now).await?;
    tx.commit().await?;
    after(&state, &reconciled, Applied::default()).await;
    Ok(StatusCode::NO_CONTENT)
}

// What this service provider supports (RFC 7644 section 4).

pub async fn service_provider_config(
    State(state): State<AppState>,
    ScimOrg(_): ScimOrg,
) -> Response {
    scim_json(
        StatusCode::OK,
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://octapass.app/docs/admin/scim/",
            "patch": { "supported": true },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            "filter": { "supported": true, "maxResults": MAX_COUNT },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "Bearer token",
                "description": "A SCIM token an organisation owner made in Octa Pass",
                "primary": true,
            }],
            "meta": { "resourceType": "ServiceProviderConfig", "location": format!("{}/ServiceProviderConfig", base_url(&state)) },
        }),
    )
}

pub async fn resource_types(State(state): State<AppState>, ScimOrg(_): ScimOrg) -> Response {
    let base = base_url(&state);
    let resources = vec![
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User",
                "endpoint": "/Users", "schema": USER_SCHEMA, "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/User") } }),
        json!({ "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "Group", "name": "Group",
                "endpoint": "/Groups", "schema": GROUP_SCHEMA, "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") } }),
    ];
    list_response(2, 1, resources)
}

pub async fn schemas(ScimOrg(_): ScimOrg) -> Response {
    let attribute = |name: &str, kind: &str, required: bool| {
        json!({ "name": name, "type": kind, "multiValued": false, "required": required, "caseExact": false,
                "mutability": "readWrite", "returned": "default", "uniqueness": if name == "userName" { "server" } else { "none" } })
    };
    let resources = vec![
        json!({ "id": USER_SCHEMA, "name": "User", "attributes": [
            attribute("userName", "string", true), attribute("displayName", "string", false),
            attribute("externalId", "string", false), attribute("active", "boolean", false),
            { "name": "emails", "type": "complex", "multiValued": true, "required": false },
        ] }),
        json!({ "id": GROUP_SCHEMA, "name": "Group", "attributes": [
            attribute("displayName", "string", true), attribute("externalId", "string", false),
            { "name": "members", "type": "complex", "multiValued": true, "required": false },
        ] }),
    ];
    list_response(2, 1, resources)
}

// Owners' management of tokens, with their own sessions.

#[utoipa::path(
    get, path = "/v1/orgs/{orgId}/scim", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    responses(
        (status = 200, body = OrgScimResponse, description = "The base URL to give the identity provider, and the tokens (never their secrets)"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_scim(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
) -> ApiResult<Json<OrgScimResponse>> {
    let org_id = validate::id("orgId", &org_id)?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, &session.account_id, OrgRole::Owner).await?;
    tx.commit().await?;
    Ok(Json(OrgScimResponse {
        base_url: base_url(&state),
        tokens: scim::tokens(&state.db, &org_id).await?,
    }))
}

#[utoipa::path(
    post, path = "/v1/orgs/{orgId}/scim/tokens", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path)),
    request_body = CreateScimTokenRequest,
    responses(
        (status = 201, body = CreatedScimToken, description = "The secret is in this answer only"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json", description = "already-exists: 10 tokens at most"),
    )
)]
pub async fn create_token(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath(org_id): ApiPath<String>,
    ApiJson(request): ApiJson<CreateScimTokenRequest>,
) -> ApiResult<(StatusCode, Json<CreatedScimToken>)> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let name = validate::text("name", &request.name, MAX_TOKEN_NAME)?;
    let now = db::now();
    let secret = format!("{TOKEN_PREFIX}{}", random_token());
    let id = uuid::Uuid::now_v7().to_string();
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    if scim::token_count(&mut tx, &org_id).await? >= MAX_TOKENS {
        return Err(ApiError::AlreadyExists(
            "an organisation has 10 SCIM tokens at most: revoke one first",
        ));
    }
    scim::create_token(&mut tx, &id, &org_id, &token_hash(&secret), &name, me, now).await?;
    orgs::record_event(&mut tx, &org_id, me, "scim-token-created", Some(&name), now).await?;
    tx.commit().await?;
    let created_by = crate::db::accounts::find_by_id(&state.db, me)
        .await?
        .map(|account| account.email);
    Ok((
        StatusCode::CREATED,
        Json(CreatedScimToken {
            token: OrgScimTokenRecord {
                id,
                name,
                created_by,
                created_at: db::rfc3339(now),
                last_used_at: None,
            },
            secret,
        }),
    ))
}

#[utoipa::path(
    delete, path = "/v1/orgs/{orgId}/scim/tokens/{tokenId}", tag = "organisations",
    security(("bearer" = [])),
    params(("orgId" = String, Path), ("tokenId" = String, Path)),
    responses(
        (status = 204, description = "Revoked: the identity provider can't use it any more"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json", description = "Only owners can"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn delete_token(
    State(state): State<AppState>,
    Authenticated(session): Authenticated,
    ApiPath((org_id, token_id)): ApiPath<(String, String)>,
) -> ApiResult<StatusCode> {
    let me = session.account_id.as_str();
    let org_id = validate::id("orgId", &org_id)?;
    let token_id = validate::id("tokenId", &token_id)?;
    let mut tx = state.db.begin().await?;
    locked(&mut tx, &org_id, me, OrgRole::Owner).await?;
    let name = scim::delete_token(&mut tx, &org_id, &token_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    orgs::record_event(
        &mut tx,
        &org_id,
        me,
        "scim-token-revoked",
        Some(&name),
        db::now(),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
