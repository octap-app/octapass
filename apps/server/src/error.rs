//! API errors, rendered as `application/problem+json`.

use std::time::Duration;

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use octapass_api::problem::{Problem, types};
use octapass_api::{ItemRecord, SecondFactorChallenge, SsoChallenge};

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("missing or invalid access token")]
    Unauthorized,
    #[error("login failed")]
    LoginFailed,
    #[error("this account asks for a second step when signing in on a new device")]
    SecondFactorRequired(Box<SecondFactorChallenge>),
    #[error("the code or security key wasn't accepted")]
    InvalidSecondFactor,
    #[error("your organisation asks you to sign in through its identity provider")]
    SsoRequired(Box<SsoChallenge>),
    #[error("the identity provider hasn't finished yet")]
    SsoPending,
    #[error("{0}")]
    SsoConfig(String),
    #[error("{0}")]
    OrgPolicy(&'static str),
    #[error("this would leave organisation vaults with nobody able to manage them")]
    OrgVaultOrphaned(Vec<String>),
    #[error("this account was deleted")]
    AccountDeleted,
    #[error("confirm with your master password first")]
    ReauthRequired,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("this server doesn't fetch website icons")]
    IconsOff,
    #[error("this server has no masked email service")]
    MaskedEmailOff,
    #[error("this account has as many masked email aliases as the server allows")]
    MaskedEmailLimit,
    #[error("the item changed on the server")]
    Conflict(Box<ItemRecord>),
    #[error("another operation on this vault failed, so this one wasn't applied")]
    BatchAborted,
    #[error("an account with this email already exists")]
    AccountExists,
    #[error("a vault with this id already exists")]
    VaultExists,
    #[error("{0}")]
    AlreadyExists(&'static str),
    #[error("{0}")]
    VaultKeyChanged(&'static str),
    #[error("the vault changed since that revision: sync and try again")]
    VaultChanged,
    #[error("the family has no room for more members")]
    FamilyFull,
    #[error("request body too large")]
    PayloadTooLarge,
    #[error("send the body's size in Content-Length")]
    LengthRequired,
    #[error("this would go over the vault owner's storage quota")]
    QuotaExceeded,
    #[error("send If-Match with the item revision, or If-None-Match: * to create")]
    PreconditionRequired,
    #[error("the verification code is wrong or expired")]
    InvalidVerificationCode,
    #[error("this reset expired or was already used: start again")]
    RecoveryExpired,
    #[error("this server doesn't accept new accounts")]
    SignupsClosed,
    #[error("this server only accepts invited email addresses")]
    InviteRequired,
    #[error("too many requests")]
    RateLimited(Duration),
    #[error("this server can't send email, so it can't verify new accounts")]
    EmailUnavailable,
    #[error("service unavailable")]
    Unavailable,
    #[error("internal error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl ApiError {
    pub fn internal(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Internal(error.into())
    }

    fn parts(&self) -> (StatusCode, &'static str, &'static str) {
        use ApiError::*;
        match self {
            BadRequest(_) => (
                StatusCode::BAD_REQUEST,
                types::INVALID_REQUEST,
                "Invalid request",
            ),
            Unauthorized => (
                StatusCode::UNAUTHORIZED,
                types::UNAUTHORIZED,
                "Unauthorized",
            ),
            LoginFailed => (
                StatusCode::UNAUTHORIZED,
                types::LOGIN_FAILED,
                "Login failed",
            ),
            SecondFactorRequired(_) => (
                StatusCode::UNAUTHORIZED,
                types::SECOND_FACTOR_REQUIRED,
                "Second factor required",
            ),
            InvalidSecondFactor => (
                StatusCode::UNAUTHORIZED,
                types::INVALID_SECOND_FACTOR,
                "Invalid second factor",
            ),
            SsoRequired(_) => (
                StatusCode::UNAUTHORIZED,
                types::SSO_REQUIRED,
                "Single sign-on required",
            ),
            SsoPending => (
                StatusCode::CONFLICT,
                types::SSO_PENDING,
                "Single sign-on pending",
            ),
            SsoConfig(_) => (
                StatusCode::BAD_REQUEST,
                types::SSO_CONFIG,
                "Identity provider settings",
            ),
            OrgPolicy(_) => (
                StatusCode::FORBIDDEN,
                types::ORG_POLICY,
                "Organisation policy",
            ),
            OrgVaultOrphaned(_) => (
                StatusCode::CONFLICT,
                types::ORG_VAULT_ORPHANED,
                "Vault would have no manager",
            ),
            AccountDeleted => (
                StatusCode::UNAUTHORIZED,
                types::ACCOUNT_DELETED,
                "Account deleted",
            ),
            ReauthRequired => (
                StatusCode::FORBIDDEN,
                types::REAUTH_REQUIRED,
                "Reauthentication required",
            ),
            Forbidden => (StatusCode::FORBIDDEN, types::FORBIDDEN, "Forbidden"),
            NotFound => (StatusCode::NOT_FOUND, types::NOT_FOUND, "Not found"),
            IconsOff => (StatusCode::NOT_FOUND, types::ICONS_OFF, "Icons off"),
            MaskedEmailOff => (
                StatusCode::NOT_FOUND,
                types::MASKED_EMAIL_OFF,
                "Masked email off",
            ),
            MaskedEmailLimit => (
                StatusCode::CONFLICT,
                types::MASKED_EMAIL_LIMIT,
                "Masked email limit",
            ),
            MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                types::METHOD_NOT_ALLOWED,
                "Method not allowed",
            ),
            Conflict(_) => (StatusCode::CONFLICT, types::CONFLICT, "Conflict"),
            BatchAborted => (
                StatusCode::FAILED_DEPENDENCY,
                types::BATCH_ABORTED,
                "Batch aborted",
            ),
            AccountExists => (
                StatusCode::CONFLICT,
                types::ACCOUNT_EXISTS,
                "Account exists",
            ),
            VaultExists => (StatusCode::CONFLICT, types::VAULT_EXISTS, "Vault exists"),
            AlreadyExists(_) => (
                StatusCode::CONFLICT,
                types::ALREADY_EXISTS,
                "Already exists",
            ),
            VaultKeyChanged(_) => (
                StatusCode::CONFLICT,
                types::VAULT_KEY_CHANGED,
                "Vault key changed",
            ),
            VaultChanged => (StatusCode::CONFLICT, types::VAULT_CHANGED, "Vault changed"),
            FamilyFull => (StatusCode::CONFLICT, types::FAMILY_FULL, "Family full"),
            PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                types::PAYLOAD_TOO_LARGE,
                "Payload too large",
            ),
            LengthRequired => (
                StatusCode::LENGTH_REQUIRED,
                types::LENGTH_REQUIRED,
                "Length required",
            ),
            QuotaExceeded => (
                StatusCode::FORBIDDEN,
                types::QUOTA_EXCEEDED,
                "Quota exceeded",
            ),
            PreconditionRequired => (
                StatusCode::PRECONDITION_REQUIRED,
                types::PRECONDITION_REQUIRED,
                "Precondition required",
            ),
            InvalidVerificationCode => (
                StatusCode::BAD_REQUEST,
                types::INVALID_VERIFICATION_CODE,
                "Invalid verification code",
            ),
            RecoveryExpired => (
                StatusCode::BAD_REQUEST,
                types::RECOVERY_EXPIRED,
                "Recovery expired",
            ),
            SignupsClosed => (
                StatusCode::FORBIDDEN,
                types::SIGNUPS_CLOSED,
                "Signups closed",
            ),
            InviteRequired => (
                StatusCode::FORBIDDEN,
                types::INVITE_REQUIRED,
                "Invite required",
            ),
            RateLimited(_) => (
                StatusCode::TOO_MANY_REQUESTS,
                types::RATE_LIMITED,
                "Too many requests",
            ),
            EmailUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                types::EMAIL_UNAVAILABLE,
                "Email unavailable",
            ),
            Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                types::UNAVAILABLE,
                "Unavailable",
            ),
            Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                types::INTERNAL,
                "Internal error",
            ),
        }
    }
}

impl ApiError {
    /// The problem details for this error. Internal errors are logged here,
    /// since the response only says "internal error".
    pub fn into_problem(self) -> Problem {
        if let ApiError::Internal(source) = &self {
            tracing::error!(error = %source, "request failed");
        }
        let (status, problem_type, title) = self.parts();
        let detail = self.to_string();
        let (mut current, mut second_factor, mut sso, mut vault_ids) =
            (None, None, None, Vec::new());
        match self {
            ApiError::Conflict(item) => current = Some(*item),
            ApiError::SecondFactorRequired(challenge) => second_factor = Some(*challenge),
            ApiError::SsoRequired(challenge) => sso = Some(*challenge),
            ApiError::OrgVaultOrphaned(ids) => vault_ids = ids,
            _ => {}
        }
        Problem {
            problem_type: problem_type.into(),
            title: title.into(),
            status: status.as_u16(),
            detail: Some(detail),
            current,
            second_factor,
            sso,
            vault_ids,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let retry_after = match &self {
            ApiError::RateLimited(wait) => Some(wait.as_secs().max(1)),
            _ => None,
        };
        let status = self.parts().0;
        let mut response = (status, axum::Json(self.into_problem())).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if let Some(seconds) = retry_after {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal(error)
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        match rejection.status() {
            StatusCode::PAYLOAD_TOO_LARGE => Self::PayloadTooLarge,
            _ => Self::BadRequest(rejection.body_text()),
        }
    }
}

impl From<QueryRejection> for ApiError {
    fn from(rejection: QueryRejection) -> Self {
        Self::BadRequest(rejection.body_text())
    }
}

impl From<PathRejection> for ApiError {
    fn from(rejection: PathRejection) -> Self {
        Self::BadRequest(rejection.body_text())
    }
}
