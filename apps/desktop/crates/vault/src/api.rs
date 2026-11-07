//! A small client for the sync API v1, on the request and response types of `octapass-api`.
//! Everything it sends is either public (email, KDF parameters), an OPAQUE message or ciphertext.

use octapass_api::problem::{Problem, types};
use octapass_api::{
    AttachmentRecord, BreachEmailRequest, BreachEmailResponse, ChangePasswordRequest,
    DeleteAccountRequest, EmergencyTakeoverRequest, ItemHistoryResponse, LoginFinishRequest,
    LoginFinishResponse, LoginStartRequest, LoginStartResponse, PasswordRegistrationRequest,
    PasswordRegistrationResponse, PreloginRequest, PreloginResponse, PutItemRequest,
    REAUTH_TOKEN_HEADER, ReauthFinishRequest, ReauthFinishResponse, ReauthStartRequest,
    ReauthStartResponse, RecoverFinishRequest, RecoverStartRequest, RecoverStartResponse,
    RecoverVerifyRequest, RecoverVerifyResponse, RecoveryCodesResponse, RefreshRequest,
    RefreshResponse, RegisterFinishRequest, RegisterFinishResponse, RegisterStartRequest,
    RegisterStartResponse, RevisionResponse, SecondFactorChallenge, SecondFactorRequest,
    SecurityLogResponse, ServerInfo, SsoChallenge, SsoLoginRequest, SyncResponse,
    TotpConfirmRequest, TotpConfirmResponse, TotpSetupResponse, TwoStepStatus, UsageResponse,
    VaultExportedRequest,
};
use reqwest::{Body, Client, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub use reqwest::Method;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ApiError {
    #[error("network error: {0}")]
    Network(String),
    #[error("server answered {status}: {}", problem.problem_type)]
    Problem { status: u16, problem: Box<Problem> },
    #[error("server answered {status} without a problem document")]
    Unexpected { status: u16 },
}

impl ApiError {
    pub fn is(&self, problem_type: &str) -> bool {
        matches!(self, ApiError::Problem { problem, .. } if problem.problem_type == problem_type)
    }

    /// The access token expired or was revoked (not: the account is gone).
    pub fn is_unauthorized(&self) -> bool {
        self.is(types::UNAUTHORIZED)
    }

    pub fn is_account_deleted(&self) -> bool {
        self.is(types::ACCOUNT_DELETED)
    }

    /// The password was right and the account asks for a second step: how to give it.
    pub fn second_factor(&self) -> Option<&SecondFactorChallenge> {
        match self {
            ApiError::Problem { problem, .. }
                if problem.problem_type == types::SECOND_FACTOR_REQUIRED =>
            {
                problem.second_factor.as_ref()
            }
            _ => None,
        }
    }

    /// The password was right and the account's organisation requires SSO: how to give it.
    pub fn sso(&self) -> Option<&SsoChallenge> {
        match self {
            ApiError::Problem { problem, .. } if problem.problem_type == types::SSO_REQUIRED => {
                problem.sso.as_ref()
            }
            _ => None,
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// How a `PUT` of an item is guarded.
#[derive(Debug, Clone, Copy)]
pub enum Precondition {
    /// `If-None-Match: *`
    Create,
    /// `If-Match: "<revision>"`
    Revision(u64),
}

#[derive(Clone)]
pub struct Api {
    http: Client,
    /// The server origin, without a trailing slash.
    base: String,
}

impl Api {
    pub fn new(http: Client, server_url: &str) -> Self {
        Self {
            http,
            base: server_url.trim_end_matches('/').to_owned(),
        }
    }

    fn request(&self, method: Method, path: &str, token: Option<&str>) -> RequestBuilder {
        let request = self.http.request(method, format!("{}{path}", self.base));
        match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    async fn send<T: DeserializeOwned>(request: RequestBuilder) -> ApiResult<T> {
        let response = Self::send_raw(request).await?;
        let status = response.status();
        let mut body = if status == StatusCode::NO_CONTENT {
            String::new()
        } else {
            response
                .text()
                .await
                .map_err(|error| ApiError::Network(error.without_url().to_string()))?
        };
        // `204`, and a `202` that only says the server took it (an invitation), have no body.
        if body.trim().is_empty() {
            body = "null".into();
        }
        serde_json::from_str(&body).map_err(|_| ApiError::Unexpected {
            status: status.as_u16(),
        })
    }

    /// A successful response, unread; anything else becomes an `ApiError`.
    async fn send_raw(request: RequestBuilder) -> ApiResult<Response> {
        let response = request
            .send()
            .await
            .map_err(|error| ApiError::Network(error.without_url().to_string()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let problem = response.json::<Problem>().await.ok();
        Err(match problem {
            Some(problem) => ApiError::Problem {
                status: status.as_u16(),
                problem: Box::new(problem),
            },
            None => ApiError::Unexpected {
                status: status.as_u16(),
            },
        })
    }

    async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &B,
    ) -> ApiResult<T> {
        Self::send(self.request(Method::POST, path, token).json(body)).await
    }

    pub async fn server_info(&self) -> ApiResult<ServerInfo> {
        Self::send(self.request(Method::GET, "/v1/server-info", None)).await
    }

    pub async fn prelogin(&self, email: &str) -> ApiResult<PreloginResponse> {
        let body = PreloginRequest {
            email: email.into(),
        };
        self.post("/v1/auth/prelogin", None, &body).await
    }

    pub async fn register_start(
        &self,
        body: &RegisterStartRequest,
    ) -> ApiResult<RegisterStartResponse> {
        self.post("/v1/auth/register/start", None, body).await
    }

    pub async fn register_finish(
        &self,
        body: &RegisterFinishRequest,
    ) -> ApiResult<RegisterFinishResponse> {
        self.post("/v1/auth/register/finish", None, body).await
    }

    pub async fn login_start(&self, body: &LoginStartRequest) -> ApiResult<LoginStartResponse> {
        self.post("/v1/auth/login/start", None, body).await
    }

    pub async fn login_finish(&self, body: &LoginFinishRequest) -> ApiResult<LoginFinishResponse> {
        self.post("/v1/auth/login/finish", None, body).await
    }

    pub async fn login_second_factor(
        &self,
        body: &SecondFactorRequest,
    ) -> ApiResult<LoginFinishResponse> {
        self.post("/v1/auth/login/second-factor", None, body).await
    }

    pub async fn login_sso(&self, body: &SsoLoginRequest) -> ApiResult<LoginFinishResponse> {
        self.post("/v1/auth/login/sso", None, body).await
    }

    pub async fn refresh(&self, refresh_token: &str) -> ApiResult<RefreshResponse> {
        let body = RefreshRequest {
            refresh_token: refresh_token.into(),
        };
        self.post("/v1/auth/refresh", None, &body).await
    }

    pub async fn logout(&self, token: &str) -> ApiResult<()> {
        Self::send(self.request(Method::POST, "/v1/auth/logout", Some(token))).await
    }

    pub async fn reauth_start(
        &self,
        token: &str,
        body: &ReauthStartRequest,
    ) -> ApiResult<ReauthStartResponse> {
        self.post("/v1/auth/reauth/start", Some(token), body).await
    }

    pub async fn reauth_finish(
        &self,
        token: &str,
        body: &ReauthFinishRequest,
    ) -> ApiResult<ReauthFinishResponse> {
        self.post("/v1/auth/reauth/finish", Some(token), body).await
    }

    pub async fn delete_account(
        &self,
        token: &str,
        reauth_token: &str,
        body: &DeleteAccountRequest,
    ) -> ApiResult<()> {
        Self::send(
            self.request(Method::DELETE, "/v1/account", Some(token))
                .header(REAUTH_TOKEN_HEADER, reauth_token)
                .json(body),
        )
        .await
    }

    /// The OPAQUE registration for a new master password, while signed in. Nothing is stored.
    pub async fn password_registration(
        &self,
        token: &str,
        registration_request: &str,
    ) -> ApiResult<PasswordRegistrationResponse> {
        let body = PasswordRegistrationRequest {
            recovery_id: None,
            registration_request: registration_request.into(),
        };
        self.post("/v1/account/password/registration", Some(token), &body)
            .await
    }

    /// Sets the new master password. Every other device is signed out.
    pub async fn change_password(
        &self,
        token: &str,
        reauth_token: &str,
        body: &ChangePasswordRequest,
    ) -> ApiResult<()> {
        Self::send(
            self.request(Method::PUT, "/v1/account/password", Some(token))
                .header(REAUTH_TOKEN_HEADER, reauth_token)
                .json(body),
        )
        .await
    }

    /// Sets a new Secret Key. Every other device is signed out.
    pub async fn rotate_secret_key(
        &self,
        token: &str,
        reauth_token: &str,
        body: &ChangePasswordRequest,
    ) -> ApiResult<()> {
        Self::send(
            self.request(Method::PUT, "/v1/account/secret-key", Some(token))
                .header(REAUTH_TOKEN_HEADER, reauth_token)
                .json(body),
        )
        .await
    }

    /// Replaces the credentials of a released emergency record's grantor.
    pub async fn emergency_takeover(
        &self,
        token: &str,
        record_id: &str,
        reauth_token: &str,
        body: &EmergencyTakeoverRequest,
    ) -> ApiResult<()> {
        let path = format!("/v1/emergency-contacts/{record_id}/takeover");
        Self::send(
            self.request(Method::POST, &path, Some(token))
                .header(REAUTH_TOKEN_HEADER, reauth_token)
                .json(body),
        )
        .await
    }

    /// Starts a reset with the recovery code: emails a code. The answer is the same for an email
    /// without an account.
    pub async fn recover_start(&self, email: &str) -> ApiResult<RecoverStartResponse> {
        let body = RecoverStartRequest {
            email: email.into(),
        };
        self.post("/v1/auth/recover/start", None, &body).await
    }

    pub async fn recover_verify(
        &self,
        body: &RecoverVerifyRequest,
    ) -> ApiResult<RecoverVerifyResponse> {
        self.post("/v1/auth/recover/verify", None, body).await
    }

    pub async fn recover_registration(
        &self,
        recovery_id: &str,
        registration_request: &str,
    ) -> ApiResult<PasswordRegistrationResponse> {
        let body = PasswordRegistrationRequest {
            recovery_id: Some(recovery_id.into()),
            registration_request: registration_request.into(),
        };
        self.post("/v1/auth/recover/registration", None, &body)
            .await
    }

    /// Sets the new master password. Every device is signed out.
    pub async fn recover_finish(&self, body: &RecoverFinishRequest) -> ApiResult<()> {
        self.post("/v1/auth/recover/finish", None, body).await
    }

    pub async fn two_step_status(&self, token: &str) -> ApiResult<TwoStepStatus> {
        Self::send(self.request(Method::GET, "/v1/account/two-step", Some(token))).await
    }

    /// A new authenticator secret; nothing changes until `confirm_totp`.
    pub async fn start_totp(
        &self,
        token: &str,
        reauth_token: &str,
    ) -> ApiResult<TotpSetupResponse> {
        Self::send(
            self.request(Method::POST, "/v1/account/two-step/totp", Some(token))
                .header(REAUTH_TOKEN_HEADER, reauth_token),
        )
        .await
    }

    pub async fn confirm_totp(
        &self,
        token: &str,
        body: &TotpConfirmRequest,
    ) -> ApiResult<TotpConfirmResponse> {
        self.post("/v1/account/two-step/totp/confirm", Some(token), body)
            .await
    }

    pub async fn renew_recovery_codes(
        &self,
        token: &str,
        reauth_token: &str,
    ) -> ApiResult<RecoveryCodesResponse> {
        Self::send(
            self.request(
                Method::POST,
                "/v1/account/two-step/recovery-codes",
                Some(token),
            )
            .header(REAUTH_TOKEN_HEADER, reauth_token),
        )
        .await
    }

    pub async fn disable_two_step(&self, token: &str, reauth_token: &str) -> ApiResult<()> {
        Self::send(
            self.request(Method::DELETE, "/v1/account/two-step", Some(token))
                .header(REAUTH_TOKEN_HEADER, reauth_token),
        )
        .await
    }

    pub async fn remove_security_key(
        &self,
        token: &str,
        reauth_token: &str,
        id: &str,
    ) -> ApiResult<()> {
        Self::send(
            self.request(
                Method::DELETE,
                &format!("/v1/account/two-step/security-keys/{id}"),
                Some(token),
            )
            .header(REAUTH_TOKEN_HEADER, reauth_token),
        )
        .await
    }

    /// `since` holds the last known revision of each vault; vaults left out come back in full.
    pub async fn sync(&self, token: &str, since: &[(String, u64)]) -> ApiResult<SyncResponse> {
        let since = since
            .iter()
            .map(|(vault, revision)| format!("{vault}:{revision}"))
            .collect::<Vec<_>>()
            .join(",");
        Self::send(
            self.request(Method::GET, "/v1/sync", Some(token))
                .query(&[("since", since)]),
        )
        .await
    }

    pub async fn put_item(
        &self,
        token: &str,
        vault_id: &str,
        item_id: &str,
        precondition: Precondition,
        body: &PutItemRequest,
    ) -> ApiResult<RevisionResponse> {
        let request = self.request(
            Method::PUT,
            &format!("/v1/vaults/{vault_id}/items/{item_id}"),
            Some(token),
        );
        let request = match precondition {
            Precondition::Create => request.header("if-none-match", "*"),
            Precondition::Revision(revision) => {
                request.header("if-match", format!("\"{revision}\""))
            }
        };
        Self::send(request.json(body)).await
    }

    pub async fn item_history(
        &self,
        token: &str,
        vault_id: &str,
        item_id: &str,
    ) -> ApiResult<ItemHistoryResponse> {
        Self::send(self.request(
            Method::GET,
            &format!("/v1/vaults/{vault_id}/items/{item_id}/history"),
            Some(token),
        ))
        .await
    }

    pub async fn delete_item(
        &self,
        token: &str,
        vault_id: &str,
        item_id: &str,
        revision: u64,
    ) -> ApiResult<RevisionResponse> {
        Self::send(
            self.request(
                Method::DELETE,
                &format!("/v1/vaults/{vault_id}/items/{item_id}"),
                Some(token),
            )
            .header("if-match", format!("\"{revision}\"")),
        )
        .await
    }

    pub async fn security_log(&self, token: &str) -> ApiResult<SecurityLogResponse> {
        Self::send(self.request(Method::GET, "/v1/security-log", Some(token))).await
    }

    /// A "vault exported" entry in the account's security log, naming this device.
    pub async fn record_export(&self, token: &str, body: &VaultExportedRequest) -> ApiResult<()> {
        self.post("/v1/security-log/exports", Some(token), body)
            .await
    }

    /// Sends the address to the server, which asks HIBP. Only called after the user opted in.
    pub async fn email_breaches(&self, token: &str, email: &str) -> ApiResult<BreachEmailResponse> {
        let body = BreachEmailRequest {
            email: email.into(),
        };
        self.post("/v1/health/breach-email", Some(token), &body)
            .await
    }

    pub async fn usage(&self, token: &str) -> ApiResult<UsageResponse> {
        Self::send(self.request(Method::GET, "/v1/account/usage", Some(token))).await
    }

    /// Uploads an encrypted file of `len` bytes, streamed from `body`.
    pub async fn upload_attachment(
        &self,
        token: &str,
        (vault_id, item_id, id): (&str, &str, &str),
        len: u64,
        body: Body,
    ) -> ApiResult<AttachmentRecord> {
        let path = format!("/v1/vaults/{vault_id}/items/{item_id}/attachments/{id}");
        let request = self
            .request(Method::PUT, &path, Some(token))
            .header("content-type", "application/octet-stream")
            .header("content-length", len)
            .body(body);
        Self::send(request).await
    }

    /// The encrypted file, as a response to read in chunks.
    pub async fn download_attachment(
        &self,
        token: &str,
        (vault_id, item_id, id): (&str, &str, &str),
    ) -> ApiResult<Response> {
        let path = format!("/v1/vaults/{vault_id}/items/{item_id}/attachments/{id}");
        Self::send_raw(self.request(Method::GET, &path, Some(token))).await
    }

    /// What's stored for an item, oldest first.
    pub async fn list_attachments(
        &self,
        token: &str,
        (vault_id, item_id): (&str, &str),
    ) -> ApiResult<octapass_api::AttachmentsResponse> {
        let path = format!("/v1/vaults/{vault_id}/items/{item_id}/attachments");
        Self::send(self.request(Method::GET, &path, Some(token))).await
    }

    pub async fn delete_attachment(
        &self,
        token: &str,
        (vault_id, item_id, id): (&str, &str, &str),
    ) -> ApiResult<()> {
        let path = format!("/v1/vaults/{vault_id}/items/{item_id}/attachments/{id}");
        Self::send(self.request(Method::DELETE, &path, Some(token))).await
    }

    /// An authenticated JSON call: the sharing, family, share link, emergency access, device
    /// and security log endpoints, whose bodies are built and read by their callers.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> ApiResult<T> {
        let request = self.request(method, path, Some(token));
        Self::send(match body {
            Some(body) => request.json(body),
            None => request,
        })
        .await
    }

    /// A `POST` with no session: a service account signing in.
    pub async fn post_public<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> ApiResult<T> {
        Self::send(self.request(Method::POST, path, None).json(body)).await
    }

    /// A conditional `PUT` to `path`, as item writes are.
    pub async fn put_json<T: DeserializeOwned>(
        &self,
        path: &str,
        token: &str,
        precondition: Precondition,
        body: &impl Serialize,
    ) -> ApiResult<T> {
        let request = self.request(Method::PUT, path, Some(token)).json(body);
        Self::send(match precondition {
            Precondition::Create => request.header("if-none-match", "*"),
            Precondition::Revision(revision) => {
                request.header("if-match", format!("\"{revision}\""))
            }
        })
        .await
    }

    /// A share link's ciphertext: no session, since the viewer may not have an account. Counts
    /// as a view.
    pub async fn view_share_link<T: DeserializeOwned>(&self, path: &str) -> ApiResult<T> {
        Self::send(self.request(Method::GET, path, None)).await
    }

    /// A file (still encrypted) from an authenticated `GET`, as a response to read in chunks.
    pub async fn download(&self, token: &str, path: &str) -> ApiResult<Response> {
        Self::send_raw(self.request(Method::GET, path, Some(token))).await
    }

    pub async fn restore_item(
        &self,
        token: &str,
        vault_id: &str,
        item_id: &str,
    ) -> ApiResult<RevisionResponse> {
        Self::send(self.request(
            Method::POST,
            &format!("/v1/vaults/{vault_id}/items/{item_id}/restore"),
            Some(token),
        ))
        .await
    }
}
