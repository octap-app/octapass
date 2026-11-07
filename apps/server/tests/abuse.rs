//! Brute force and lockout resistance: verification codes, login limits and
//! the pending-login store.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::*;
use opaque_ke::{ClientLogin, ClientRegistration, ClientRegistrationFinishParameters};
use octapass_server::config::{Bucket, RateLimits};
use rand_core::OsRng;
use serde_json::json;

const EMAIL: &str = "alice@example.com";

fn slow(burst: u32) -> Bucket {
    Bucket {
        burst,
        refill: Duration::from_secs(3600),
    }
}

/// Starts a sign-up and finishes the client side of OPAQUE. Returns the
/// emailed code and the registration upload, or the failed start response.
async fn start_signup(server: &TestServer, email: &str) -> Result<(String, String), Box<Response>> {
    let start = ClientRegistration::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
    let started = server
        .post(
            "/v1/auth/register/start",
            json!({ "email": email, "registrationRequest": b64(start.message.serialize()) }),
        )
        .await;
    if started.status != StatusCode::OK {
        return Err(Box::new(started));
    }
    let response = opaque_ke::RegistrationResponse::<Suite>::deserialize(&unb64(
        &started.body["registrationResponse"],
    ))
    .unwrap();
    let upload = start
        .state
        .finish(
            &mut OsRng,
            PASSWORD,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let code = started.body["devVerificationCode"].as_str().unwrap();
    Ok((code.to_owned(), b64(upload.message.serialize())))
}

async fn finish_signup(server: &TestServer, email: &str, code: &str, upload: &str) -> Response {
    server
        .post(
            "/v1/auth/register/finish",
            register_finish_body(email, code, upload, &new_id()),
        )
        .await
}

fn wrong(code: &str) -> &'static str {
    if code == "000000" { "111111" } else { "000000" }
}

/// Room for many guesses, so only the per-code and daily limits apply.
async fn generous_server() -> TestServer {
    TestServer::with_config(|config| {
        config.rate_limits = RateLimits {
            signup_per_email: slow(100),
            ..RateLimits::default()
        }
    })
    .await
}

async fn expire_codes(server: &TestServer) {
    sqlx::query("UPDATE pending_registrations SET expires_at = 0")
        .execute(&server.state.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn concurrent_guesses_share_five_attempts() {
    let server = generous_server().await;
    let (code, upload) = start_signup(&server, EMAIL).await.unwrap();
    let guesses = (0..20).map(|_| finish_signup(&server, EMAIL, wrong(&code), &upload));
    for response in futures_util::future::join_all(guesses).await {
        assert!(response.is_problem("invalid-verification-code"));
    }
    let attempts: i64 = sqlx::query_scalar("SELECT attempts FROM pending_registrations")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(attempts, 5);
    let right = finish_signup(&server, EMAIL, &code, &upload).await;
    assert!(right.is_problem("invalid-verification-code"));
}

#[tokio::test]
async fn wrong_codes_are_capped_per_day_across_resends() {
    let server = generous_server().await;
    // Four codes, five wrong guesses each: the day's budget of 20.
    for _ in 0..4 {
        let (code, upload) = start_signup(&server, EMAIL).await.unwrap();
        for _ in 0..5 {
            finish_signup(&server, EMAIL, wrong(&code), &upload).await;
        }
        expire_codes(&server).await;
    }
    let (code, upload) = start_signup(&server, EMAIL).await.unwrap();
    let right = finish_signup(&server, EMAIL, &code, &upload).await;
    assert!(right.is_problem("invalid-verification-code"));

    // Another email is unaffected.
    let (code, upload) = start_signup(&server, "bob@example.com").await.unwrap();
    let other = finish_signup(&server, "bob@example.com", &code, &upload).await;
    assert_eq!(other.status, StatusCode::OK, "{:?}", other.body);
}

#[tokio::test]
async fn codes_sent_are_capped_per_day() {
    let server = TestServer::new().await;
    for _ in 0..10 {
        start_signup(&server, EMAIL).await.unwrap();
    }
    let capped = start_signup(&server, EMAIL).await.unwrap_err();
    assert_eq!(capped.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(capped.is_problem("rate-limited"));
    let retry: u64 = capped.headers["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=86_400).contains(&retry), "{retry}");
    assert!(start_signup(&server, "bob@example.com").await.is_ok());

    // The counters hold no email addresses.
    let keys: Vec<String> = sqlx::query_scalar("SELECT email_key FROM signup_counters")
        .fetch_all(&server.state.db)
        .await
        .unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|key| !key.contains('@')));
}

#[tokio::test]
async fn register_finish_is_limited_per_email() {
    let server = TestServer::with_config(|config| {
        config.rate_limits = RateLimits {
            signup_per_email: slow(3),
            ..RateLimits::default()
        }
    })
    .await;
    let (code, upload) = start_signup(&server, EMAIL).await.unwrap();
    for _ in 0..2 {
        let guess = finish_signup(&server, EMAIL, wrong(&code), &upload).await;
        assert!(guess.is_problem("invalid-verification-code"));
    }
    let limited = finish_signup(&server, EMAIL, &code, &upload).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);

    // Malformed requests don't spend the budget.
    let other = "bob@example.com";
    let bad_start = server
        .post(
            "/v1/auth/register/start",
            json!({ "email": other, "registrationRequest": "not base64!" }),
        )
        .await;
    assert_eq!(bad_start.status, StatusCode::BAD_REQUEST);
    let (code, upload) = start_signup(&server, other).await.unwrap();
    let mut bad_finish = register_finish_body(other, &code, &upload, &new_id());
    bad_finish["account"]["publicEncKey"] = json!("short");
    let rejected = server.post("/v1/auth/register/finish", bad_finish).await;
    assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
    let signed_up = finish_signup(&server, other, &code, &upload).await;
    assert_eq!(signed_up.status, StatusCode::OK, "{:?}", signed_up.body);
}

#[tokio::test]
async fn flooding_starts_cannot_lock_an_account() {
    let server = TestServer::with_config(|config| {
        config.rate_limits = RateLimits {
            login_per_email_ip: slow(2),
            login_per_email: slow(3),
            signup_per_email: slow(2),
            ..RateLimits::default()
        }
    })
    .await;
    server.register(EMAIL).await;
    let attacker = "203.0.113.66";

    // Starts alone, for login or sign-up, cost the email nothing.
    for _ in 0..10 {
        let start = ClientLogin::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
        let body = json!({ "email": EMAIL, "credentialRequest": b64(start.message.serialize()) });
        let started = server
            .call_from(
                attacker,
                Method::POST,
                "/v1/auth/login/start",
                None,
                &[],
                Some(body),
            )
            .await;
        assert_eq!(started.status, StatusCode::OK);
    }
    let signup_flood = start_signup(&server, EMAIL).await.unwrap_err();
    assert_eq!(signup_flood.status, StatusCode::TOO_MANY_REQUESTS);
    let owner = server
        .login_from("192.0.2.10", EMAIL, PASSWORD, "Laptop")
        .await
        .unwrap();
    assert_eq!(owner.status, StatusCode::OK);

    // Failed finishes count against the attacker's (email, IP) bucket...
    for _ in 0..2 {
        let failed = server
            .login_from(attacker, EMAIL, b"guess", "x")
            .await
            .unwrap();
        assert!(failed.is_problem("login-failed"));
    }
    let blocked = server
        .login_from(attacker, EMAIL, b"guess", "x")
        .await
        .unwrap_err();
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);
    // ...while the owner, on another IP, still signs in.
    let owner = server
        .login_from("192.0.2.10", EMAIL, PASSWORD, "Phone")
        .await
        .unwrap();
    assert_eq!(owner.status, StatusCode::OK);

    // Failures from many IPs hit the per-email ceiling.
    let failed = server
        .login_from("203.0.113.67", EMAIL, b"guess", "x")
        .await
        .unwrap();
    assert!(failed.is_problem("login-failed"));
    let ceiling = server
        .login_from("203.0.113.68", EMAIL, PASSWORD, "x")
        .await
        .unwrap_err();
    assert_eq!(ceiling.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn one_ip_cannot_crowd_out_other_logins() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let flooder = "203.0.113.99";
    let mut login_ids = Vec::new();
    for _ in 0..25 {
        let start = ClientLogin::<Suite>::start(&mut OsRng, PASSWORD).unwrap();
        let body = json!({ "email": EMAIL, "credentialRequest": b64(start.message.serialize()) });
        let started = server
            .call_from(
                flooder,
                Method::POST,
                "/v1/auth/login/start",
                None,
                &[],
                Some(body),
            )
            .await;
        assert_eq!(started.status, StatusCode::OK);
        login_ids.push(started.body["loginId"].clone());
    }
    // The flooder's oldest logins made room for its newest ones.
    let evicted = server
        .call_from(
            flooder,
            Method::POST,
            "/v1/auth/login/finish",
            None,
            &[],
            Some(json!({
                "loginId": login_ids[0],
                "credentialFinalization": b64([0u8; 64]),
                "device": { "name": "x", "platform": "y" }
            })),
        )
        .await;
    assert!(evicted.is_problem("login-failed"));
    let other = server
        .login_from("192.0.2.20", EMAIL, PASSWORD, "Laptop")
        .await
        .unwrap();
    assert_eq!(other.status, StatusCode::OK);
}
