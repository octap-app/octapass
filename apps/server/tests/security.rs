//! Rate limiting, account enumeration resistance, verification codes, signup
//! modes, CORS and security headers.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::*;
use opaque_ke::{ClientLogin, ClientRegistration};
use octapass_api::SignupMode;
use octapass_server::config::{Bucket, RateLimits};
use rand_core::OsRng;
use serde_json::{Value, json};

const EMAIL: &str = "alice@example.com";

/// A bucket that doesn't refill during a test.
fn slow(burst: u32) -> Bucket {
    Bucket {
        burst,
        refill: Duration::from_secs(3600),
    }
}

fn login_start_body(email: &str) -> Value {
    let start = ClientLogin::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
    json!({ "email": email, "credentialRequest": b64(start.message.serialize()) })
}

#[tokio::test]
async fn auth_endpoints_are_rate_limited_per_ip() {
    let server = TestServer::with_config(|config| {
        config.rate_limits = RateLimits {
            per_ip: slow(3),
            ..RateLimits::default()
        }
    })
    .await;
    let prelogin = |ip: &'static str| {
        server.call_from(
            ip,
            Method::POST,
            "/v1/auth/prelogin",
            None,
            &[],
            Some(json!({ "email": EMAIL })),
        )
    };
    for _ in 0..3 {
        assert_eq!(prelogin("198.51.100.1").await.status, StatusCode::OK);
    }
    let limited = prelogin("198.51.100.1").await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.is_problem("rate-limited"));
    assert!(
        limited.headers["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    assert_eq!(
        prelogin("198.51.100.2").await.status,
        StatusCode::OK,
        "other IPs are unaffected"
    );

    // Every address in one IPv6 /64 shares a bucket.
    for _ in 0..3 {
        assert_eq!(prelogin("2001:db8::1").await.status, StatusCode::OK);
    }
    assert_eq!(
        prelogin("2001:db8::2").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn a_login_start_costs_one_ip_token() {
    let server = TestServer::with_config(|config| {
        config.rate_limits = RateLimits {
            per_ip: slow(4),
            ..RateLimits::default()
        }
    })
    .await;
    let mut statuses = Vec::new();
    for _ in 0..5 {
        let response = server
            .call_from(
                "198.51.100.7",
                Method::POST,
                "/v1/auth/login/start",
                None,
                &[],
                Some(login_start_body(EMAIL)),
            )
            .await;
        statuses.push(response.status);
    }
    assert_eq!(statuses[..4], [StatusCode::OK; 4]);
    assert_eq!(statuses[4], StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn prelogin_does_not_reveal_accounts() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;

    let real = server
        .post("/v1/auth/prelogin", json!({ "email": EMAIL }))
        .await
        .body;
    let fake = server
        .post(
            "/v1/auth/prelogin",
            json!({ "email": "nobody@example.com" }),
        )
        .await
        .body;
    let fake_again = server
        .post(
            "/v1/auth/prelogin",
            json!({ "email": " NOBODY@example.com" }),
        )
        .await
        .body;
    let other_fake = server
        .post(
            "/v1/auth/prelogin",
            json!({ "email": "someone@example.com" }),
        )
        .await
        .body;

    assert_eq!(fake, fake_again, "fake salts are deterministic");
    assert_ne!(fake["accountSalt"], other_fake["accountSalt"]);
    assert_eq!(
        unb64(&fake["accountSalt"]).len(),
        unb64(&real["accountSalt"]).len()
    );
    assert_eq!(fake["kdf"], real["kdf"]);
    assert_eq!(
        fake["kdf"],
        json!({ "algorithm": "argon2id", "memoryKib": 65536, "iterations": 3, "parallelism": 1 })
    );
}

#[tokio::test]
async fn login_does_not_reveal_accounts() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;

    let known = server
        .post("/v1/auth/login/start", login_start_body(EMAIL))
        .await;
    let unknown = server
        .post(
            "/v1/auth/login/start",
            login_start_body("nobody@example.com"),
        )
        .await;
    assert_eq!(known.status, StatusCode::OK);
    assert_eq!(unknown.status, StatusCode::OK);
    assert_eq!(
        unb64(&known.body["credentialResponse"]).len(),
        unb64(&unknown.body["credentialResponse"]).len()
    );

    // Wrong password, unknown email, replayed or made-up login ids: one answer.
    let wrong_password = server.login_with(EMAIL, b"wrong password", "Laptop").await;
    let unknown_email = server
        .login_with("nobody@example.com", PASSWORD, "Laptop")
        .await;
    let made_up = server
        .post(
            "/v1/auth/login/finish",
            json!({ "loginId": "made-up", "credentialFinalization": b64([0u8; 64]), "device": { "name": "x", "platform": "y" } }),
        )
        .await;
    for response in [&wrong_password, &unknown_email, &made_up] {
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert!(response.is_problem("login-failed"));
        assert_eq!(response.body, wrong_password.body);
    }
}

#[tokio::test]
async fn login_ids_are_single_use() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let client = ClientLogin::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
    let started = server
        .post(
            "/v1/auth/login/start",
            json!({ "email": EMAIL, "credentialRequest": b64(client.message.serialize()) }),
        )
        .await;
    let finish = json!({
        "loginId": started.body["loginId"],
        "credentialFinalization": client_finish(client.state, PASSWORD, &started.body["credentialResponse"]),
        "device": { "name": "Laptop", "platform": "test" }
    });
    assert_eq!(
        server
            .post("/v1/auth/login/finish", finish.clone())
            .await
            .status,
        StatusCode::OK
    );
    assert!(
        server
            .post("/v1/auth/login/finish", finish)
            .await
            .is_problem("login-failed")
    );
}

async fn register_start(server: &TestServer, email: &str) -> (ClientRegistration<Suite>, Response) {
    let start = ClientRegistration::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
    let response = server
        .post(
            "/v1/auth/register/start",
            json!({ "email": email, "registrationRequest": b64(start.message.serialize()) }),
        )
        .await;
    (start.state, response)
}

#[tokio::test]
async fn register_start_does_not_reveal_accounts() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let (_, existing) = register_start(&server, EMAIL).await;
    let (_, new) = register_start(&server, "new@example.com").await;
    assert_eq!(existing.status, StatusCode::OK);
    assert_eq!(new.status, StatusCode::OK);
    assert_eq!(existing.body["verificationRequired"], true);
    let keys = |body: &Value| {
        body.as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(keys(&existing.body), keys(&new.body));
    assert_eq!(
        unb64(&existing.body["registrationResponse"]).len(),
        unb64(&new.body["registrationResponse"]).len()
    );
}

#[tokio::test]
async fn verification_codes_are_checked_and_limited() {
    let server = TestServer::new().await;
    let (state, started) = register_start(&server, EMAIL).await;
    let code = started.body["devVerificationCode"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(code.len(), 6);
    let response = opaque_ke::RegistrationResponse::<Suite>::deserialize(&unb64(
        &started.body["registrationResponse"],
    ))
    .unwrap();
    let upload = state
        .finish(
            &mut OsRng,
            PASSWORD,
            response,
            opaque_ke::ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let upload = b64(upload.message.serialize());
    let wrong_code = if code == "000000" { "111111" } else { "000000" };

    for _ in 0..5 {
        let attempt = server
            .post(
                "/v1/auth/register/finish",
                register_finish_body(EMAIL, wrong_code, &upload, &new_id()),
            )
            .await;
        assert_eq!(attempt.status, StatusCode::BAD_REQUEST);
        assert!(attempt.is_problem("invalid-verification-code"));
    }
    // After five wrong guesses even the right code is refused.
    let locked = server
        .post(
            "/v1/auth/register/finish",
            register_finish_body(EMAIL, &code, &upload, &new_id()),
        )
        .await;
    assert!(locked.is_problem("invalid-verification-code"));

    // A new code doesn't bring new guesses while the old one is still valid.
    let (_, resent) = register_start(&server, EMAIL).await;
    let resent_code = resent.body["devVerificationCode"].as_str().unwrap();
    let still_locked = server
        .post(
            "/v1/auth/register/finish",
            register_finish_body(EMAIL, resent_code, &upload, &new_id()),
        )
        .await;
    assert!(still_locked.is_problem("invalid-verification-code"));

    // Once it has expired, asking for a new code starts over.
    sqlx::query("UPDATE pending_registrations SET expires_at = 0")
        .execute(&server.state.db)
        .await
        .unwrap();
    server.register(EMAIL).await;

    // A second sign-up for the same email gets past the code but not the account check.
    let (state, started) = register_start(&server, EMAIL).await;
    let response = opaque_ke::RegistrationResponse::<Suite>::deserialize(&unb64(
        &started.body["registrationResponse"],
    ))
    .unwrap();
    let upload = state
        .finish(
            &mut OsRng,
            PASSWORD,
            response,
            opaque_ke::ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let code = started.body["devVerificationCode"].as_str().unwrap();
    let body = register_finish_body(EMAIL, code, &b64(upload.message.serialize()), &new_id());
    let duplicate = server.post("/v1/auth/register/finish", body).await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    assert!(duplicate.is_problem("account-exists"));
}

#[tokio::test]
async fn registration_rejects_malformed_bundles() {
    let server = TestServer::new().await;
    let (_, started) = register_start(&server, EMAIL).await;
    let code = started.body["devVerificationCode"].as_str().unwrap();
    let mut body = register_finish_body(EMAIL, code, &b64([0u8; 192]), &new_id());
    body["account"]["wrappedAsk"] = json!(b64(b"not an envelope"));
    let response = server.post("/v1/auth/register/finish", body).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.is_problem("invalid-request"));

    let mut weak = register_finish_body(EMAIL, code, &b64([0u8; 192]), &new_id());
    weak["account"]["kdf"]["memoryKib"] = json!(1024);
    assert!(
        server
            .post("/v1/auth/register/finish", weak)
            .await
            .is_problem("invalid-request")
    );
}

#[tokio::test]
async fn signup_modes() {
    let closed = TestServer::with_config(|config| config.signups = SignupMode::Closed).await;
    let (_, response) = register_start(&closed, EMAIL).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response.is_problem("signups-closed"));

    let invite = TestServer::with_config(|config| config.signups = SignupMode::Invite).await;
    let info = invite
        .call(Method::GET, "/v1/server-info", None, &[], None)
        .await;
    assert_eq!(info.body["signups"], "invite");
    let (_, response) = register_start(&invite, EMAIL).await;
    assert!(response.is_problem("invite-required"));
    octapass_server::admin::invite(&invite.state, EMAIL)
        .await
        .unwrap();
    invite.register(EMAIL).await;
}

#[tokio::test]
async fn without_smtp_or_dev_mode_signups_need_email() {
    let server = TestServer::with_config(|config| config.dev_mode = false).await;
    let (_, response) = register_start(&server, EMAIL).await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(response.is_problem("email-unavailable"));
}

#[tokio::test]
async fn cors_allows_only_configured_origins() {
    let server = &TestServer::new().await;
    let preflight = |origin: &'static str| async move {
        let headers = [
            ("origin", origin),
            ("access-control-request-method", "PUT"),
            ("access-control-request-headers", "authorization,if-match"),
        ];
        server
            .call(Method::OPTIONS, "/v1/sync", None, &headers, None)
            .await
    };
    let allowed = preflight("http://localhost:5173").await;
    assert_eq!(
        allowed.headers["access-control-allow-origin"],
        "http://localhost:5173"
    );
    let denied = preflight("https://evil.example").await;
    assert!(denied.headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn responses_carry_security_headers() {
    let server =
        TestServer::with_config(|config| config.public_url = "https://vault.example.com".into())
            .await;
    let response = server
        .call(Method::GET, "/v1/server-info", None, &[], None)
        .await;
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cache-control", "no-store"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
    ] {
        assert_eq!(response.headers[name], value, "{name}");
    }
    let error = server.call(Method::GET, "/v1/nope", None, &[], None).await;
    assert_eq!(error.headers["x-content-type-options"], "nosniff");
}
