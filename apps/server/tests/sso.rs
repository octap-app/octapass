//! Single sign-on: an extra step after OPAQUE, never a replacement for it. A small OpenID Connect
//! provider runs in-process, so the whole flow is real HTTP from `login/finish` to the code the
//! browser shows.

use crate::common;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::people::Person;
use common::two_step::{enable, second_factor, totp};
use common::*;
use octapass_server::config::RateLimits;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const CLIENT_ID: &str = "octa-pass";
const CLIENT_SECRET: &str = "shh: a secret";

/// What the provider says about the next person to sign in, and what it was sent.
#[derive(Default)]
struct IdpState {
    issuer: String,
    subject: String,
    email: String,
    email_verified: Option<bool>,
    nonce: String,
    challenge: String,
    /// `client_id` from Basic authentication, to check it was form-encoded.
    basic_password: Option<String>,
    /// Refuse the next token request, as a provider does for a disabled user.
    refuse: bool,
    /// Sign the token with this issuer instead.
    wrong_issuer: bool,
}

type Idp = Arc<Mutex<IdpState>>;

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
    headers: HeaderMap,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let mut idp = idp.lock().unwrap();
    if idp.refuse {
        return (StatusCode::BAD_REQUEST, "{}").into_response();
    }
    // PKCE, as the provider would check it.
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    if challenge != idp.challenge {
        return (StatusCode::BAD_REQUEST, "{}").into_response();
    }
    if form.get("code").map(String::as_str) != Some("the-code") {
        return (StatusCode::BAD_REQUEST, "{}").into_response();
    }
    idp.basic_password = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .map(|value| {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(value)
                .unwrap();
            String::from_utf8(decoded).unwrap()
        });
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issuer = if idp.wrong_issuer {
        "https://evil.example".to_owned()
    } else {
        idp.issuer.clone()
    };
    let mut claims = json!({
        "iss": issuer, "sub": idp.subject, "aud": CLIENT_ID, "exp": now + 300, "iat": now,
        "nonce": idp.nonce, "email": idp.email,
    });
    if let Some(verified) = idp.email_verified {
        claims["email_verified"] = json!(verified);
    }
    let part = |value: Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let id_token = format!("{}.{}.sig", part(json!({ "alg": "RS256" })), part(claims));
    axum::Json(json!({ "id_token": id_token, "access_token": "unused", "token_type": "Bearer" }))
        .into_response()
}

async fn serve_idp() -> (String, Idp) {
    let idp: Idp = Arc::default();
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/token", post(token))
        .with_state(idp.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp.lock().unwrap().issuer = issuer.clone();
    (issuer, idp)
}

async fn server() -> TestServer {
    TestServer::with_config(|config| {
        config.sso_private_network = true;
        config.rate_limits = RateLimits::unlimited();
    })
    .await
}

fn device_of(person: &Person) -> Device {
    Device {
        access_token: person.token.clone(),
        refresh_token: String::new(),
        account: json!({}),
        trusted_device_token: None,
    }
}

fn query(url: &url::Url, key: &str) -> String {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}

fn path_of(url: &str) -> String {
    let url = url::Url::parse(url).unwrap();
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

/// Plays the browser: the start link, the provider, and back. Returns the callback's page.
async fn browser(server: &TestServer, idp: &Idp, url: &str) -> (StatusCode, String) {
    let request = axum::http::Request::builder()
        .uri(path_of(url))
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, headers, body) = server.send_raw(request).await;
    if status != StatusCode::FOUND {
        return (status, String::from_utf8(body).unwrap());
    }
    let location = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
    assert_eq!(query(&location, "response_type"), "code");
    assert_eq!(query(&location, "client_id"), CLIENT_ID);
    assert_eq!(query(&location, "code_challenge_method"), "S256");
    assert!(query(&location, "scope").contains("openid"));
    {
        let mut idp = idp.lock().unwrap();
        idp.nonce = query(&location, "nonce");
        idp.challenge = query(&location, "code_challenge");
    }
    let state = query(&location, "state");
    let request = axum::http::Request::builder()
        .uri(format!("/v1/sso/callback?code=the-code&state={state}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _, body) = server.send_raw(request).await;
    (status, String::from_utf8(body).unwrap())
}

fn code_in(page: &str) -> String {
    let start = page.find("class=\"code\">").expect("a code on the page") + 13;
    page[start..start + 6].to_owned()
}

/// An organisation with SSO settings, a finished test sign-in and `requireSso` on, with `member`
/// in it.
async fn with_sso(
    server: &TestServer,
    owner: &Person,
    member: &Person,
    issuer: &str,
    idp: &Idp,
) -> String {
    let org = new_id();
    let body = json!({ "id": org, "name": "Acme" });
    let created = server
        .send_as(owner, Method::POST, "/v1/orgs", Some(body))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let path = format!("/v1/orgs/{org}/invites");
    let body = json!({ "email": member.email, "role": "member" });
    server.send_as(owner, Method::POST, &path, Some(body)).await;
    let orgs = server.get_as(member, "/v1/orgs").await;
    let invite = orgs.body["invitations"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("/v1/orgs/{org}/invites/{invite}/accept");
    server.send_as(member, Method::POST, &path, None).await;

    configure(server, owner, &org, issuer).await;
    test_sign_in(server, owner, &org, idp).await;
    require_sso(server, owner, &org, 168).await;
    org
}

async fn configure(server: &TestServer, owner: &Person, org: &str, issuer: &str) {
    let path = format!("/v1/orgs/{org}/sso");
    let body = json!({ "issuer": issuer, "clientId": CLIENT_ID, "clientSecret": CLIENT_SECRET });
    let saved = server.send_as(owner, Method::PUT, &path, Some(body)).await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    assert_eq!(saved.body["hasClientSecret"], true);
    assert!(saved.body.get("clientSecret").is_none());
    assert!(saved.body.get("testedAt").is_none());
}

async fn test_sign_in(server: &TestServer, owner: &Person, org: &str, idp: &Idp) {
    let path = format!("/v1/orgs/{org}/sso/test");
    let started = server.send_as(owner, Method::POST, &path, None).await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    let url = started.body["url"].as_str().unwrap();
    let (status, page) = browser(server, idp, url).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("It works"), "{page}");
}

async fn require_sso(server: &TestServer, owner: &Person, org: &str, hours: u32) -> Response {
    let path = format!("/v1/orgs/{org}/policies");
    let body = json!({
        "requireTwoStep": false, "requireSso": true, "ssoMaxAgeHours": hours,
        "disableShareLinks": false, "disableEmergencyAccess": false, "disableExport": false,
    });
    server.send_as(owner, Method::PUT, &path, Some(body)).await
}

/// A login that must stop for the identity provider. Returns the `sso` member.
async fn stops_for_sso(server: &TestServer, email: &str) -> Value {
    let response = server.login_with(email, PASSWORD, "Phone").await;
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        response.body
    );
    assert!(response.is_problem("sso-required"), "{:?}", response.body);
    response.body["sso"].clone()
}

fn set_person(idp: &Idp, subject: &str, email: &str) {
    let mut idp = idp.lock().unwrap();
    idp.subject = subject.to_owned();
    idp.email = email.to_owned();
}

#[tokio::test]
async fn sso_is_a_step_after_the_password_not_instead_of_it() {
    let server = server().await;
    let (issuer, idp) = serve_idp().await;
    let owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    set_person(&idp, "owner-sub", "owner@example.com");
    with_sso(&server, &owner, &member, &issuer, &idp).await;
    set_person(&idp, "member-sub", "member@example.com");

    // Nothing about SSO shows without the password: a wrong one is the usual failure.
    let wrong = server
        .login_with("member@example.com", b"wrong", "Phone")
        .await;
    assert!(wrong.is_problem("login-failed"), "{:?}", wrong.body);

    let sso = stops_for_sso(&server, "member@example.com").await;
    assert_eq!(sso["orgName"], "Acme");
    assert!(sso["url"].as_str().unwrap().contains("/v1/sso/start/"));
    assert!(
        !sso["url"]
            .as_str()
            .unwrap()
            .contains(sso["challengeId"].as_str().unwrap()),
        "the browser never sees the device's challenge id"
    );

    // Before the browser finishes, the device is told to wait.
    let body = json!({ "challengeId": sso["challengeId"], "code": "000000" });
    let early = server.post("/v1/auth/login/sso", body).await;
    assert!(early.is_problem("sso-pending"), "{:?}", early.body);

    let (status, page) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("Phone"), "the page names the device: {page}");
    let code = code_in(&page);

    // A wrong code doesn't sign in; the right one does, with no key from anywhere but OPAQUE.
    let body = json!({ "challengeId": sso["challengeId"], "code": "000000" });
    let wrong = server.post("/v1/auth/login/sso", body).await;
    assert!(
        wrong.is_problem("invalid-second-factor"),
        "{:?}",
        wrong.body
    );
    let body = json!({ "challengeId": sso["challengeId"], "code": code });
    let finished = server.post("/v1/auth/login/sso", body.clone()).await;
    assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.body);
    assert!(finished.body["accessToken"].is_string());
    assert_eq!(finished.body["account"]["email"], "member@example.com");
    assert!(
        finished.body["account"]["wrappedAsk"].is_string(),
        "the ASK stays wrapped for the master password"
    );

    // Used once.
    let again = server.post("/v1/auth/login/sso", body).await;
    assert!(again.is_problem("login-failed"), "{:?}", again.body);

    // The provider got a client secret, form-encoded, over the token endpoint.
    let basic = idp.lock().unwrap().basic_password.clone().unwrap();
    assert_eq!(basic, "octa-pass:shh%3A+a+secret");
}

#[tokio::test]
async fn owners_skip_it_so_a_broken_provider_cannot_lock_the_organisation_out() {
    let server = server().await;
    let (issuer, idp) = serve_idp().await;
    let owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    set_person(&idp, "owner-sub", "owner@example.com");
    with_sso(&server, &owner, &member, &issuer, &idp).await;
    let response = server
        .login_with("owner@example.com", PASSWORD, "Phone")
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
}

#[tokio::test]
async fn requiring_sso_needs_a_finished_test_with_the_current_settings() {
    let server = server().await;
    let (issuer, idp) = serve_idp().await;
    let owner = server.person("owner@example.com").await;
    set_person(&idp, "owner-sub", "owner@example.com");
    let org = new_id();
    let body = json!({ "id": org, "name": "Acme" });
    server
        .send_as(&owner, Method::POST, "/v1/orgs", Some(body))
        .await;

    let refused = require_sso(&server, &owner, &org, 168).await;
    assert!(refused.is_problem("sso-config"), "{:?}", refused.body);
    configure(&server, &owner, &org, &issuer).await;
    let refused = require_sso(&server, &owner, &org, 168).await;
    assert!(refused.is_problem("sso-config"), "{:?}", refused.body);

    test_sign_in(&server, &owner, &org, &idp).await;
    let saved = require_sso(&server, &owner, &org, 168).await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);

    // Settings can't be changed or removed under members' feet.
    let path = format!("/v1/orgs/{org}/sso");
    let body = json!({ "issuer": issuer, "clientId": "other" });
    let refused = server.send_as(&owner, Method::PUT, &path, Some(body)).await;
    assert!(refused.is_problem("sso-config"), "{:?}", refused.body);
    let refused = server.send_as(&owner, Method::DELETE, &path, None).await;
    assert!(refused.is_problem("sso-config"), "{:?}", refused.body);

    // A failed provider leaves the settings unsaved, and only owners touch any of this.
    let bad = json!({ "issuer": "http://127.0.0.1:9", "clientId": "x" });
    let refused = server.send_as(&owner, Method::PUT, &path, Some(bad)).await;
    assert!(refused.is_problem("sso-config"), "{:?}", refused.body);
    let record = server.get_as(&owner, &path).await;
    assert_eq!(record.body["clientId"], CLIENT_ID);
    assert!(record.body["testedAt"].is_string());
    assert!(
        record.body["callbackUrl"]
            .as_str()
            .unwrap()
            .ends_with("/v1/sso/callback")
    );
}

#[tokio::test]
async fn a_bad_answer_from_the_provider_gets_no_code() {
    let server = server().await;
    let (issuer, idp) = serve_idp().await;
    let owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    set_person(&idp, "owner-sub", "owner@example.com");
    with_sso(&server, &owner, &member, &issuer, &idp).await;

    // The provider refuses: someone disabled there.
    set_person(&idp, "member-sub", "member@example.com");
    idp.lock().unwrap().refuse = true;
    let sso = stops_for_sso(&server, "member@example.com").await;
    let (status, page) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!page.contains("class=\"code\""));
    idp.lock().unwrap().refuse = false;

    // A token from another issuer.
    idp.lock().unwrap().wrong_issuer = true;
    let sso = stops_for_sso(&server, "member@example.com").await;
    let (status, page) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!page.contains("class=\"code\""));
    idp.lock().unwrap().wrong_issuer = false;

    // A first sign-in with someone else's email links nothing.
    set_person(&idp, "stranger-sub", "stranger@example.com");
    let sso = stops_for_sso(&server, "member@example.com").await;
    let (status, page) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("different account"), "{page}");

    // An email the provider says isn't verified links nothing either.
    set_person(&idp, "member-sub", "member@example.com");
    idp.lock().unwrap().email_verified = Some(false);
    let sso = stops_for_sso(&server, "member@example.com").await;
    let (status, _) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    idp.lock().unwrap().email_verified = None;

    // After the first link, the subject decides, even if the email later changes...
    let sso = stops_for_sso(&server, "member@example.com").await;
    let (status, _) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    set_person(&idp, "member-sub", "renamed@example.com");
    let sso = stops_for_sso(&server, "member@example.com").await;
    let (status, _) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);

    // ...and another subject with the right email isn't them.
    set_person(&idp, "other-sub", "member@example.com");
    let sso = stops_for_sso(&server, "member@example.com").await;
    let (status, page) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("different account"), "{page}");

    // A link and a callback work once, and made-up ones get nothing.
    let request = axum::http::Request::builder()
        .uri("/v1/sso/callback?code=x&state=made-up")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _, body) = server.send_raw(request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8(body).unwrap().contains("expired"));
}

#[tokio::test]
async fn five_wrong_codes_end_the_sign_in() {
    let server = server().await;
    let (issuer, idp) = serve_idp().await;
    let owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    set_person(&idp, "owner-sub", "owner@example.com");
    with_sso(&server, &owner, &member, &issuer, &idp).await;
    set_person(&idp, "member-sub", "member@example.com");

    let sso = stops_for_sso(&server, "member@example.com").await;
    let (_, page) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    let code = code_in(&page);
    let wrong = if code == "000000" { "000001" } else { "000000" };
    for _ in 0..5 {
        let body = json!({ "challengeId": sso["challengeId"], "code": wrong });
        let answer = server.post("/v1/auth/login/sso", body).await;
        assert!(
            answer.is_problem("invalid-second-factor"),
            "{:?}",
            answer.body
        );
    }
    let body = json!({ "challengeId": sso["challengeId"], "code": code });
    let answer = server.post("/v1/auth/login/sso", body).await;
    assert!(answer.is_problem("login-failed"), "{:?}", answer.body);
}

#[tokio::test]
async fn two_step_sign_in_still_runs_after_sso() {
    let server = server().await;
    let (issuer, idp) = serve_idp().await;
    let owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let (secret, _) = enable(&server, &device_of(&member)).await;
    set_person(&idp, "owner-sub", "owner@example.com");
    with_sso(&server, &owner, &member, &issuer, &idp).await;
    set_person(&idp, "member-sub", "member@example.com");

    let sso = stops_for_sso(&server, "member@example.com").await;
    let (_, page) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    let body = json!({ "challengeId": sso["challengeId"], "code": code_in(&page) });
    let next = server.post("/v1/auth/login/sso", body).await;
    assert!(next.is_problem("second-factor-required"), "{:?}", next.body);

    server
        .state
        .clock
        .advance(std::time::Duration::from_secs(31));
    let code = totp(&secret, server.state_now());
    let finished = second_factor(
        &server,
        &next.body["secondFactor"]["challengeId"],
        json!({ "totpCode": code }),
    )
    .await;
    assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.body);

    // That session passed SSO: it refreshes.
    let refresh = finished.body["refreshToken"].as_str().unwrap();
    let refreshed = server
        .post("/v1/auth/refresh", json!({ "refreshToken": refresh }))
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
}

#[tokio::test]
async fn sessions_end_when_their_sso_sign_in_is_too_old() {
    let server = server().await;
    let (issuer, idp) = serve_idp().await;
    let owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let before = server.login("member@example.com", "Tablet").await;
    set_person(&idp, "owner-sub", "owner@example.com");
    let org = with_sso(&server, &owner, &member, &issuer, &idp).await;
    set_person(&idp, "member-sub", "member@example.com");

    // A session from before the policy never passed SSO.
    let body = json!({ "refreshToken": before.refresh_token });
    let refused = server.post("/v1/auth/refresh", body).await;
    assert!(refused.is_problem("unauthorized"), "{:?}", refused.body);

    let sso = stops_for_sso(&server, "member@example.com").await;
    let (_, page) = browser(&server, &idp, sso["url"].as_str().unwrap()).await;
    let body = json!({ "challengeId": sso["challengeId"], "code": code_in(&page) });
    let finished = server.post("/v1/auth/login/sso", body).await;
    assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.body);
    let refresh = finished.body["refreshToken"].as_str().unwrap().to_owned();

    let refreshed = server
        .post("/v1/auth/refresh", json!({ "refreshToken": refresh }))
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    let refresh = refreshed.body["refreshToken"].as_str().unwrap().to_owned();

    // A week later the provider has to be asked again.
    server
        .state
        .clock
        .advance(std::time::Duration::from_secs(169 * 3600));
    let refused = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": refresh.clone() }),
        )
        .await;
    assert!(refused.is_problem("unauthorized"), "{:?}", refused.body);

    // Out of the organisation, none of this applies any more.
    let path = format!("/v1/orgs/{org}/members/{}", member.account_id);
    let removed = server.send_as(&owner, Method::DELETE, &path, None).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{:?}", removed.body);
    let refreshed = server
        .post("/v1/auth/refresh", json!({ "refreshToken": refresh }))
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    let response = server
        .login_with("member@example.com", PASSWORD, "Phone")
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
}

#[tokio::test]
async fn private_addresses_are_refused_unless_the_server_allows_them() {
    let server = TestServer::new().await;
    let (issuer, _idp) = serve_idp().await;
    let owner = server.person("owner@example.com").await;
    let org = new_id();
    let body = json!({ "id": org, "name": "Acme" });
    server
        .send_as(&owner, Method::POST, "/v1/orgs", Some(body))
        .await;
    let path = format!("/v1/orgs/{org}/sso");
    for issuer in [
        issuer.as_str(),
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/",
        "file:///etc/passwd",
    ] {
        let body = json!({ "issuer": issuer, "clientId": "x" });
        let refused = server.send_as(&owner, Method::PUT, &path, Some(body)).await;
        assert!(
            refused.is_problem("sso-config"),
            "{issuer}: {:?}",
            refused.body
        );
    }
}

#[tokio::test]
async fn the_client_secret_is_sealed_at_rest() {
    let server = server().await;
    let (issuer, idp) = serve_idp().await;
    let owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    set_person(&idp, "owner-sub", "owner@example.com");
    with_sso(&server, &owner, &member, &issuer, &idp).await;
    let stored: String = sqlx::query_scalar("SELECT client_secret FROM org_sso")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert!(!stored.contains("secret"));
    assert!(stored.len() > CLIENT_SECRET.len());
}
