//! The SSO step against the real sync server and a small OpenID Connect provider: the password
//! first, then the browser, then the code it ends on, with two-step sign-in after that. The CLI
//! signs in through this same vault.

use crate::common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Form, State};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::model::{SessionStatus, SignInResult, TwoStepProof};
use serde_json::{Value, json};

const CLIENT_ID: &str = "octa-pass";

#[derive(Default)]
struct Provider {
    issuer: String,
    nonce: String,
}

type Idp = Arc<Mutex<Provider>>;

async fn discovery(State(idp): State<Idp>) -> axum::Json<Value> {
    let issuer = idp.lock().unwrap().issuer.clone();
    axum::Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
    }))
}

async fn token(
    State(idp): State<Idp>,
    Form(_form): Form<HashMap<String, String>>,
) -> axum::Json<Value> {
    let idp = idp.lock().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({
        "iss": idp.issuer, "sub": "ada", "aud": CLIENT_ID, "exp": now + 300, "iat": now,
        "nonce": idp.nonce, "email": EMAIL,
    });
    let part = |value: Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let id_token = format!("{}.{}.sig", part(json!({ "alg": "RS256" })), part(claims));
    axum::Json(json!({ "id_token": id_token }))
}

async fn serve_idp() -> Idp {
    let idp: Idp = Arc::default();
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/token", post(token))
        .with_state(idp.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    idp.lock().unwrap().issuer = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

/// Puts the account in an organisation that requires SSO, as an owner's screens would.
async fn require_sso(server: &Server, idp: &Idp) {
    let db = &server.state.db;
    let (org, now) = (
        "0192f0c8-0000-7000-8000-00000000aaaa",
        server.state.clock.now(),
    );
    let issuer = idp.lock().unwrap().issuer.clone();
    sqlx::query(
        "INSERT INTO organisations (id, name, require_sso, created_at) VALUES ($1, 'Acme', 1, $2)",
    )
    .bind(org)
    .bind(now)
    .execute(db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO org_members (org_id, account_id, role, joined_at) \
         SELECT $1, id, 'member', $2 FROM accounts WHERE email = $3",
    )
    .bind(org)
    .bind(now)
    .bind(EMAIL)
    .execute(db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO org_sso (org_id, issuer, client_id, tested_at, updated_at) \
         VALUES ($1, $2, $3, $4, $4)",
    )
    .bind(org)
    .bind(issuer)
    .bind(CLIENT_ID)
    .bind(now)
    .execute(db)
    .await
    .unwrap();
}

/// Plays the browser: the link, the provider, back. Returns the code on the last page.
async fn browser(server: &Server, url: &str, idp: &Idp) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    // The link is built from the server's public URL, which isn't this test's random port.
    let path = url::Url::parse(url).unwrap().path().to_owned();
    let redirect = client
        .get(format!("{}{path}", server.url))
        .send()
        .await
        .unwrap();
    assert_eq!(redirect.status(), 302);
    let location = redirect.headers()["location"].to_str().unwrap().to_owned();
    let location = url::Url::parse(&location).unwrap();
    let query: HashMap<String, String> = location.query_pairs().into_owned().collect();
    idp.lock().unwrap().nonce = query["nonce"].clone();
    let page = client
        .get(format!(
            "{}/v1/sso/callback?code=c&state={}",
            server.url, query["state"]
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("Test Mac"), "{html}");
    let start = html.find("class=\"code\">").expect("a code on the page") + 13;
    html[start..start + 6].to_owned()
}

/// An account in an organisation requiring SSO, on a device starting a sign-in. Returns the device,
/// the address to open and the Secret Key.
async fn waiting(
    server: &Server,
    idp: &Idp,
    before: impl AsyncFnOnce(&Device),
) -> (Device, String) {
    let first = Device::new(server);
    let secret_key = first.sign_up(server).await;
    before(&first).await;
    require_sso(server, idp).await;

    let device = Device::new(server);
    let result = device.sign_in(server, Some(&secret_key)).await.unwrap();
    let SignInResult::SsoRequired { url, org_name } = result else {
        panic!("expected the SSO step, got {result:?}");
    };
    assert_eq!(org_name, "Acme");
    assert_eq!(device.status(), SessionStatus::SignedOut);
    (device, url)
}

#[tokio::test]
async fn sso_comes_after_the_password_and_ends_with_the_browsers_code() {
    let (server, idp) = (server().await, serve_idp().await);
    let (device, url) = waiting(&server, &idp, async |_| ()).await;

    // Too early, then a wrong code: the sign-in keeps waiting through both.
    let early = device.vault.finish_sso("000000").await.unwrap_err();
    assert_eq!(early.code, ErrorCode::SsoPending);
    let code = browser(&server, &url, &idp).await;
    let wrong = if code == "000000" { "000001" } else { "000000" };
    let refused = device.vault.finish_sso(wrong).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::InvalidTwoStepCode);

    let spaced = format!("{} {}", &code[..3], &code[3..]);
    assert_eq!(
        device.vault.finish_sso(&spaced).await.unwrap(),
        SignInResult::SignedIn
    );
    assert_eq!(device.status(), SessionStatus::Unlocked);

    // Finished: nothing is waiting any more.
    let again = device.vault.finish_sso(&code).await.unwrap_err();
    assert_eq!(again.code, ErrorCode::TwoStepExpired);
}

#[tokio::test]
async fn two_step_sign_in_still_follows_sso() {
    let (server, idp) = (server().await, serve_idp().await);
    let authenticator: Mutex<String> = Mutex::default();
    let (device, url) = waiting(&server, &idp, async |first| {
        let setup = first
            .vault
            .start_totp_setup(secret(PASSWORD))
            .await
            .unwrap();
        first
            .vault
            .confirm_totp_setup(&server.totp(&setup.secret))
            .await
            .unwrap();
        *authenticator.lock().unwrap() = setup.secret;
    })
    .await;

    let code = browser(&server, &url, &idp).await;
    let next = device.vault.finish_sso(&code).await.unwrap();
    assert!(
        matches!(next, SignInResult::TwoStepRequired { .. }),
        "{next:?}"
    );
    assert_eq!(device.status(), SessionStatus::SignedOut);

    let secret = authenticator.lock().unwrap().clone();
    device
        .vault
        .finish_two_step(TwoStepProof::Totp {
            code: server.totp(&secret),
        })
        .await
        .unwrap();
    assert_eq!(device.status(), SessionStatus::Unlocked);
}

#[tokio::test]
async fn a_session_older_than_the_policy_signs_in_again() {
    let (server, idp) = (server().await, serve_idp().await);
    let (device, url) = waiting(&server, &idp, async |_| ()).await;
    let code = browser(&server, &url, &idp).await;
    device.vault.finish_sso(&code).await.unwrap();

    server
        .state
        .clock
        .advance(std::time::Duration::from_secs(169 * 60 * 60));
    sqlx::query("UPDATE sessions SET access_expires_at = 0")
        .execute(&server.state.db)
        .await
        .unwrap();
    let expired = device.vault.sync().await.unwrap_err();
    assert_eq!(expired.code, ErrorCode::SessionExpired);
}
