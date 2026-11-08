//! Two-step sign-in: turning it on, the second step on new devices, trusted
//! devices, recovery codes, security keys, lockout, the security log and
//! emails, and turning it off.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::two_step::{SoftKey, enable, reauth, second_factor, totp};
use common::{Device, PASSWORD, TestServer};
use serde_json::{Value, json};
use sha2::Digest;

const EMAIL: &str = "ada@example.com";
const NEW_SIGN_IN: &str = "New sign-in to your Octa Pass account";

/// Moves the server clock to the next 30-second step, so a new code isn't a replay.
fn next_step(server: &TestServer) {
    server.state.clock.advance(Duration::from_secs(30));
}

async fn security_log(server: &TestServer, device: &Device) -> Vec<String> {
    let log = server.get("/v1/security-log", &device.access_token).await;
    assert_eq!(log.status, StatusCode::OK);
    log.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap().to_owned())
        .collect()
}

fn subjects(server: &TestServer) -> Vec<String> {
    server
        .state
        .dev_outbox()
        .into_iter()
        .filter(|(to, _)| to == EMAIL)
        .map(|(_, subject)| subject)
        .collect()
}

/// A login that must stop at the second step. Returns the `secondFactor` member.
async fn challenged(server: &TestServer, device: &str, trusted: Option<&str>) -> Value {
    let response = server
        .login_trusted("192.0.2.1", EMAIL, PASSWORD, device, trusted)
        .await
        .unwrap();
    assert_eq!(
        response.status,
        StatusCode::UNAUTHORIZED,
        "{:?}",
        response.body
    );
    assert!(
        response.is_problem("second-factor-required"),
        "{:?}",
        response.body
    );
    response.body["secondFactor"].clone()
}

async fn status(server: &TestServer, device: &Device) -> Value {
    let response = server
        .get("/v1/account/two-step", &device.access_token)
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    response.body
}

#[tokio::test]
async fn turning_on_needs_reauth_and_a_correct_code() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let off = status(&server, &laptop).await;
    assert_eq!(off["enabled"], false);
    assert_eq!(off["methods"], json!([]));
    assert_eq!(off["rpId"], "localhost");

    // Without a reauth token, or with one for another purpose: refused.
    let bare = server
        .call(
            Method::POST,
            "/v1/account/two-step/totp",
            Some(&laptop.access_token),
            &[],
            None,
        )
        .await;
    assert!(bare.is_problem("reauth-required"), "{:?}", bare.body);
    let delete_token = reauth(&server, &laptop, "delete-account").await;
    let wrong_purpose = server
        .call(
            Method::POST,
            "/v1/account/two-step/totp",
            Some(&laptop.access_token),
            &[("x-reauth-token", &delete_token)],
            None,
        )
        .await;
    assert!(wrong_purpose.is_problem("reauth-required"));

    let token = reauth(&server, &laptop, "two-step").await;
    let setup = server
        .call(
            Method::POST,
            "/v1/account/two-step/totp",
            Some(&laptop.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    assert_eq!(setup.status, StatusCode::OK, "{:?}", setup.body);
    let secret = setup.body["secret"].as_str().unwrap();
    assert_eq!(secret.len(), 32, "160 bits of base32");
    let uri = setup.body["otpauthUri"].as_str().unwrap();
    assert!(uri.starts_with("otpauth://totp/Octa%20Pass:ada@example.com?secret="));
    assert!(uri.contains(secret));

    // The reauth token was used up.
    let again = server
        .call(
            Method::POST,
            "/v1/account/two-step/totp",
            Some(&laptop.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    assert!(again.is_problem("reauth-required"));

    // A wrong code leaves it off and the setup usable.
    let confirm = |code: String| {
        let body = json!({ "setupId": setup.body["setupId"], "code": code });
        let token = laptop.access_token.clone();
        let server = &server;
        async move {
            server
                .call(
                    Method::POST,
                    "/v1/account/two-step/totp/confirm",
                    Some(&token),
                    &[],
                    Some(body),
                )
                .await
        }
    };
    let now = server.state.clock.now();
    let wrong = confirm(totp(secret, now - 120_000)).await;
    assert!(
        wrong.is_problem("invalid-second-factor"),
        "{:?}",
        wrong.body
    );
    assert_eq!(status(&server, &laptop).await["enabled"], false);
    let right = confirm(totp(secret, now)).await;
    assert_eq!(right.status, StatusCode::OK, "{:?}", right.body);
    let codes = right.body["recoveryCodes"].as_array().unwrap();
    assert_eq!(codes.len(), 10);

    let on = status(&server, &laptop).await;
    assert_eq!(on["enabled"], true);
    assert_eq!(on["methods"], json!(["totp", "recovery-code"]));
    assert_eq!(on["recoveryCodesLeft"], 10);
    // The setup was used up.
    assert!(
        confirm(totp(secret, now))
            .await
            .is_problem("invalid-request")
    );

    assert_eq!(security_log(&server, &laptop).await, ["two-step-enabled"]);
    assert!(subjects(&server).contains(&"Two-step sign-in turned on".to_owned()));
    // The secret is sealed at rest, not stored as typed.
    let stored: String = sqlx::query_scalar("SELECT totp_secret FROM two_step")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert!(!stored.contains(secret));
}

#[tokio::test]
async fn new_devices_need_the_second_step_and_trusted_ones_skip_it() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let laptop_trust = laptop.trusted_device_token.clone().expect("always issued");
    let (secret, _) = enable(&server, &laptop).await;

    // The laptop, signed in before, keeps working.
    let refreshed = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": laptop.refresh_token }),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK);
    assert!(
        refreshed.body.get("trustedDeviceToken").is_none(),
        "already trusted"
    );

    // A new device stops after the password, and isn't news until it's past the second step.
    let challenge = challenged(&server, "phone", None).await;
    assert!(!subjects(&server).contains(&NEW_SIGN_IN.to_owned()));
    assert_eq!(challenge["methods"], json!(["totp", "recovery-code"]));
    assert!(challenge.get("webauthn").is_none());
    assert_eq!(challenge["expiresIn"], 300);

    // A wrong code, then the right one.
    next_step(&server);
    let wrong = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "totpCode": "000000" }),
    )
    .await;
    let wrong = if wrong.is_problem("invalid-second-factor") {
        wrong
    } else {
        // 000000 was the real code: astronomically unlikely, but try another.
        second_factor(
            &server,
            &challenge["challengeId"],
            json!({ "totpCode": "000001" }),
        )
        .await
    };
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(
        wrong.is_problem("invalid-second-factor"),
        "{:?}",
        wrong.body
    );
    let code = totp(&secret, server.state.clock.now());
    let phone = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "totpCode": code }),
    )
    .await;
    assert_eq!(phone.status, StatusCode::OK, "{:?}", phone.body);
    let phone = Device::from_login(&phone.body);
    assert_eq!(phone.account["email"], EMAIL);
    let new_sign_ins = || {
        subjects(&server)
            .into_iter()
            .filter(|s| s == NEW_SIGN_IN)
            .count()
    };
    assert_eq!(new_sign_ins(), 1);
    assert!(
        server
            .get("/v1/sync", &phone.access_token)
            .await
            .status
            .is_success()
    );

    // The challenge is single use, and the code can't be replayed on a new one.
    let reused = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "totpCode": code }),
    )
    .await;
    assert!(reused.is_problem("login-failed"));
    let replay = challenged(&server, "tablet", None).await;
    let replayed =
        second_factor(&server, &replay["challengeId"], json!({ "totpCode": code })).await;
    assert!(replayed.is_problem("invalid-second-factor"));

    // The laptop signs in again with its trusted-device token: no second step,
    // and the token is replaced.
    let again = server
        .login_trusted("192.0.2.1", EMAIL, PASSWORD, "laptop", Some(&laptop_trust))
        .await
        .unwrap();
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    let new_trust = again.body["trustedDeviceToken"].as_str().unwrap();
    assert_ne!(new_trust, laptop_trust);
    assert_eq!(new_sign_ins(), 1, "a trusted device isn't news");
    // The old token was used up; another account can't use the new one.
    challenged(&server, "laptop", Some(&laptop_trust)).await;
    server.register("bob@example.com").await;
    let bob = server.login("bob@example.com", "bob").await;
    enable(&server, &bob).await;
    let stolen = server
        .login_trusted(
            "192.0.2.1",
            "bob@example.com",
            PASSWORD,
            "x",
            Some(new_trust),
        )
        .await
        .unwrap();
    assert!(stolen.is_problem("second-factor-required"));

    // Signing a device out forgets its trust.
    server
        .call(
            Method::POST,
            "/v1/auth/logout",
            Some(&phone.access_token),
            &[],
            None,
        )
        .await;
    let phone_trust = phone.trusted_device_token.unwrap();
    challenged(&server, "phone", Some(&phone_trust)).await;
}

/// Lets the device's session lapse and runs maintenance, which forgets the device.
async fn lapse(server: &TestServer, device: &Device) {
    sqlx::query("UPDATE sessions SET refresh_expires_at = 0 WHERE access_token_hash = $1")
        .bind(common::b64(sha2::Sha256::digest(
            device.access_token.as_bytes(),
        )))
        .execute(&server.state.db)
        .await
        .unwrap();
    server.state.run_maintenance().await.unwrap();
}

async fn trusted_rows(server: &TestServer) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM trusted_devices")
        .fetch_one(&server.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn trust_ends_with_its_device() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let attacker = server.login(EMAIL, "attacker").await;

    // Refreshing never hands out trust: only a device's own sign-in does.
    let refreshed = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": laptop.refresh_token }),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK);
    assert!(refreshed.body.get("trustedDeviceToken").is_none());
    let laptop = Device {
        access_token: refreshed.body["accessToken"].as_str().unwrap().to_owned(),
        refresh_token: refreshed.body["refreshToken"].as_str().unwrap().to_owned(),
        ..laptop
    };

    // A session that lapses takes the device, and its trust, with it: it no
    // longer shows in the device list, so it can't skip the second step either.
    lapse(&server, &attacker).await;
    let devices = server.get("/v1/devices", &laptop.access_token).await;
    assert_eq!(devices.body.as_array().unwrap().len(), 1);
    assert_eq!(trusted_rows(&server).await, 1);
    enable(&server, &laptop).await;
    challenged(
        &server,
        "attacker",
        attacker.trusted_device_token.as_deref(),
    )
    .await;
}

#[tokio::test]
async fn turning_on_forgets_other_devices_but_keeps_their_sessions() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let phone = server.login(EMAIL, "phone").await;
    enable(&server, &laptop).await;

    // The phone stays signed in, but its next sign-in needs the second step.
    let refreshed = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": phone.refresh_token }),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK);
    challenged(&server, "phone", phone.trusted_device_token.as_deref()).await;
    // The laptop, which turned it on, is still trusted.
    let again = server
        .login_trusted(
            "192.0.2.1",
            EMAIL,
            PASSWORD,
            "laptop",
            laptop.trusted_device_token.as_deref(),
        )
        .await
        .unwrap();
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
}

#[tokio::test]
async fn forgetting_trusted_devices_keeps_only_this_one() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let (secret, _) = enable(&server, &laptop).await;
    let challenge = challenged(&server, "phone", None).await;
    next_step(&server);
    let code = totp(&secret, server.state.clock.now());
    let phone = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "totpCode": code }),
    )
    .await;
    let phone = Device::from_login(&phone.body);

    let forgotten = server
        .call(
            Method::DELETE,
            "/v1/account/two-step/trusted-devices",
            Some(&laptop.access_token),
            &[],
            None,
        )
        .await;
    assert_eq!(
        forgotten.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        forgotten.body
    );
    challenged(&server, "phone", phone.trusted_device_token.as_deref()).await;
    // Sessions aren't touched.
    assert!(
        server
            .get("/v1/sync", &phone.access_token)
            .await
            .status
            .is_success()
    );
    let again = server
        .login_trusted(
            "192.0.2.1",
            EMAIL,
            PASSWORD,
            "laptop",
            laptop.trusted_device_token.as_deref(),
        )
        .await
        .unwrap();
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert!(
        security_log(&server, &laptop)
            .await
            .contains(&"trusted-devices-forgotten".to_owned())
    );
}

#[tokio::test]
async fn a_reused_refresh_token_forgets_every_trusted_device() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let phone = server.login(EMAIL, "phone").await;
    enable(&server, &laptop).await;
    let body = json!({ "refreshToken": laptop.refresh_token });
    assert_eq!(
        server.post("/v1/auth/refresh", body.clone()).await.status,
        StatusCode::OK
    );
    let reused = server.post("/v1/auth/refresh", body).await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(trusted_rows(&server).await, 0);
    challenged(&server, "laptop", laptop.trusted_device_token.as_deref()).await;
    challenged(&server, "phone", phone.trusted_device_token.as_deref()).await;
}

#[tokio::test]
async fn a_trusted_device_token_works_for_one_sign_in_even_at_once() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    enable(&server, &laptop).await;
    let token = laptop.trusted_device_token.clone().unwrap();
    let logins = (0..4).map(|i| {
        let token = token.clone();
        let server = &server;
        async move {
            server
                .login_trusted(
                    "192.0.2.1",
                    EMAIL,
                    PASSWORD,
                    &format!("copy {i}"),
                    Some(&token),
                )
                .await
                .unwrap()
        }
    });
    let results = futures_util::future::join_all(logins).await;
    let signed_in = results
        .iter()
        .filter(|r| r.status == StatusCode::OK)
        .count();
    let challenged = results
        .iter()
        .filter(|r| r.is_problem("second-factor-required"))
        .count();
    let statuses: Vec<_> = results.iter().map(|r| r.status).collect();
    assert_eq!((signed_in, challenged), (1, 3), "{statuses:?}");
}

#[tokio::test]
async fn concurrent_wrong_codes_stay_within_the_budget() {
    // Only the account's budget is under test, not the per-IP one.
    let server = TestServer::with_config(|config| {
        config.rate_limits.per_ip = octapass_server::config::Bucket {
            burst: 10_000,
            refill: Duration::from_millis(1),
        };
    })
    .await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    enable(&server, &laptop).await;
    // 20: one IP can hold that many waiting sign-ins.
    let mut challenges = Vec::new();
    for i in 0..20 {
        challenges.push(challenged(&server, &format!("guesser {i}"), None).await);
    }
    let guesses = challenges.iter().map(|challenge| {
        second_factor(
            &server,
            &challenge["challengeId"],
            json!({ "recoveryCode": "00000-00000" }),
        )
    });
    let results = futures_util::future::join_all(guesses).await;
    let checked = results
        .iter()
        .filter(|r| r.is_problem("invalid-second-factor"))
        .count();
    let paused = results
        .iter()
        .filter(|r| r.status == StatusCode::TOO_MANY_REQUESTS)
        .count();
    let statuses: Vec<_> = results.iter().map(|r| r.status).collect();
    assert_eq!((checked, paused), (10, 10), "{statuses:?}");
}

#[tokio::test]
async fn a_failed_sign_in_doesnt_use_up_the_recovery_code() {
    let server = TestServer::new().await;
    if server.is_postgres() {
        return; // The failure is injected with an SQLite trigger.
    }
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let (_, codes) = enable(&server, &laptop).await;
    sqlx::query(
        "CREATE TRIGGER no_devices BEFORE INSERT ON devices BEGIN SELECT RAISE(ABORT, 'no'); END",
    )
    .execute(&server.state.db)
    .await
    .unwrap();
    let challenge = challenged(&server, "phone", None).await;
    let failed = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "recoveryCode": codes[0] }),
    )
    .await;
    assert!(failed.is_problem("login-failed"), "{:?}", failed.body);
    sqlx::query("DROP TRIGGER no_devices")
        .execute(&server.state.db)
        .await
        .unwrap();
    assert_eq!(status(&server, &laptop).await["recoveryCodesLeft"], 10);
    let challenge = challenged(&server, "phone", None).await;
    let phone = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "recoveryCode": codes[0] }),
    )
    .await;
    assert_eq!(phone.status, StatusCode::OK, "{:?}", phone.body);
}

#[tokio::test]
async fn recovery_codes_work_once_and_can_be_renewed() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let (_, codes) = enable(&server, &laptop).await;

    let challenge = challenged(&server, "phone", None).await;
    // Case, spaces and dashes don't matter.
    let typed = codes[0].to_lowercase().replace('-', " ");
    let phone = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "recoveryCode": typed }),
    )
    .await;
    assert_eq!(phone.status, StatusCode::OK, "{:?}", phone.body);
    assert_eq!(status(&server, &laptop).await["recoveryCodesLeft"], 9);
    assert!(
        security_log(&server, &laptop)
            .await
            .contains(&"recovery-code-used".to_owned())
    );
    assert!(
        subjects(&server).contains(&"A recovery code was used to sign in to Octa Pass".to_owned())
    );
    // That email already covers the new device.
    assert!(!subjects(&server).contains(&NEW_SIGN_IN.to_owned()));

    let challenge = challenged(&server, "tablet", None).await;
    let reused = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "recoveryCode": codes[0] }),
    )
    .await;
    assert!(reused.is_problem("invalid-second-factor"));

    // New codes replace the old ones, and need a reauth.
    let bare = server
        .call(
            Method::POST,
            "/v1/account/two-step/recovery-codes",
            Some(&laptop.access_token),
            &[],
            None,
        )
        .await;
    assert!(bare.is_problem("reauth-required"));
    let token = reauth(&server, &laptop, "two-step").await;
    let renewed = server
        .call(
            Method::POST,
            "/v1/account/two-step/recovery-codes",
            Some(&laptop.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    assert_eq!(renewed.status, StatusCode::OK, "{:?}", renewed.body);
    let fresh = renewed.body["recoveryCodes"].as_array().unwrap();
    assert_eq!(fresh.len(), 10);
    assert_eq!(status(&server, &laptop).await["recoveryCodesLeft"], 10);
    let old = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "recoveryCode": codes[1] }),
    )
    .await;
    assert!(old.is_problem("invalid-second-factor"));
    let new = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "recoveryCode": fresh[0] }),
    )
    .await;
    assert_eq!(new.status, StatusCode::OK, "{:?}", new.body);
    assert!(
        security_log(&server, &laptop)
            .await
            .contains(&"recovery-codes-renewed".to_owned())
    );
}

#[tokio::test]
async fn security_keys_register_and_sign_in() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;

    // Security keys come after the authenticator app.
    let token = reauth(&server, &laptop, "two-step").await;
    let too_early = server
        .call(
            Method::POST,
            "/v1/account/two-step/security-keys/options",
            Some(&laptop.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    assert!(
        too_early.is_problem("invalid-request"),
        "{:?}",
        too_early.body
    );
    enable(&server, &laptop).await;

    // The refused request didn't use the token up.
    let options = server
        .call(
            Method::POST,
            "/v1/account/two-step/security-keys/options",
            Some(&laptop.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    assert_eq!(options.status, StatusCode::OK, "{:?}", options.body);
    assert_eq!(options.body["publicKey"]["algorithms"], json!([-7, -8]));
    assert_eq!(options.body["publicKey"]["user"]["name"], EMAIL);
    assert_ne!(
        options.body["publicKey"]["user"]["id"], laptop.account["accountId"],
        "the user handle isn't the account id"
    );

    let mut key = SoftKey::new();
    let add = |body: Value| {
        let token = laptop.access_token.clone();
        let server = &server;
        async move {
            server
                .call(
                    Method::POST,
                    "/v1/account/two-step/security-keys",
                    Some(&token),
                    &[],
                    Some(body),
                )
                .await
        }
    };
    // A wrong credential id, then the real answer.
    let mut mismatched = key.create(&options.body, "YubiKey");
    mismatched["credentialId"] = json!("AAAA");
    assert!(add(mismatched).await.is_problem("invalid-request"));
    let added = add(key.create(&options.body, "YubiKey")).await;
    assert_eq!(added.status, StatusCode::OK, "{:?}", added.body);
    assert_eq!(added.body["name"], "YubiKey");
    let key_id = added.body["id"].as_str().unwrap().to_owned();
    // The setup is single use.
    assert!(
        add(key.create(&options.body, "again"))
            .await
            .is_problem("invalid-request")
    );

    let listed = status(&server, &laptop).await;
    assert_eq!(
        listed["methods"],
        json!(["totp", "webauthn", "recovery-code"])
    );
    assert_eq!(listed["securityKeys"][0]["name"], "YubiKey");
    assert!(listed["securityKeys"][0].get("lastUsedAt").is_none());

    // The same key can't be registered twice.
    let token = reauth(&server, &laptop, "two-step").await;
    let options = server
        .call(
            Method::POST,
            "/v1/account/two-step/security-keys/options",
            Some(&laptop.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    assert_eq!(
        options.body["publicKey"]["excludeCredentials"],
        json!([common::b64(&key.id)])
    );
    let duplicate = add(key.create(&options.body, "same")).await;
    assert!(
        duplicate.is_problem("already-exists"),
        "{:?}",
        duplicate.body
    );

    // Sign in with it.
    let challenge = challenged(&server, "phone", None).await;
    assert_eq!(
        challenge["methods"],
        json!(["totp", "webauthn", "recovery-code"])
    );
    assert_eq!(challenge["webauthn"]["userVerification"], "discouraged");
    let assertion = key.get(&challenge);
    let phone = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "webauthn": assertion }),
    )
    .await;
    assert_eq!(phone.status, StatusCode::OK, "{:?}", phone.body);
    assert!(status(&server, &laptop).await["securityKeys"][0]["lastUsedAt"].is_string());

    // An assertion for another challenge, or replayed, is refused.
    let challenge = challenged(&server, "tablet", None).await;
    let replayed = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "webauthn": assertion }),
    )
    .await;
    assert!(replayed.is_problem("invalid-second-factor"));

    // Removing needs a reauth.
    let path = format!("/v1/account/two-step/security-keys/{key_id}");
    let bare = server
        .call(Method::DELETE, &path, Some(&laptop.access_token), &[], None)
        .await;
    assert!(bare.is_problem("reauth-required"));
    let token = reauth(&server, &laptop, "two-step").await;
    let removed = server
        .call(
            Method::DELETE,
            &path,
            Some(&laptop.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{:?}", removed.body);
    let challenge = challenged(&server, "tablet", None).await;
    assert_eq!(challenge["methods"], json!(["totp", "recovery-code"]));
    let log = security_log(&server, &laptop).await;
    assert!(log.contains(&"security-key-added".to_owned()));
    assert!(log.contains(&"security-key-removed".to_owned()));
}

#[tokio::test]
async fn wrong_codes_lock_the_challenge_then_the_account() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let (secret, codes) = enable(&server, &laptop).await;

    // Five wrong tries use a challenge up.
    let challenge = challenged(&server, "phone", None).await;
    for _ in 0..5 {
        let wrong = second_factor(
            &server,
            &challenge["challengeId"],
            json!({ "recoveryCode": "00000-00000" }),
        )
        .await;
        assert!(
            wrong.is_problem("invalid-second-factor"),
            "{:?}",
            wrong.body
        );
    }
    let gone = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "recoveryCode": codes[0] }),
    )
    .await;
    assert!(gone.is_problem("login-failed"));

    // Five more (ten for the account) pause the second step everywhere, even with the right code.
    let challenge = challenged(&server, "phone", None).await;
    for _ in 0..5 {
        second_factor(
            &server,
            &challenge["challengeId"],
            json!({ "recoveryCode": "00000-00000" }),
        )
        .await;
    }
    let challenge = challenged(&server, "phone", None).await;
    next_step(&server);
    let code = totp(&secret, server.state.clock.now());
    let locked = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "totpCode": code }),
    )
    .await;
    assert_eq!(
        locked.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{:?}",
        locked.body
    );
    assert!(locked.headers.contains_key("retry-after"));
    // The sign-in still waits: it isn't thrown away by the pause.
    let still = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "totpCode": code }),
    )
    .await;
    assert_eq!(
        still.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{:?}",
        still.body
    );

    let log = security_log(&server, &laptop).await;
    assert_eq!(log.iter().filter(|e| *e == "two-step-locked").count(), 1);
    assert!(
        subjects(&server)
            .contains(&"Several wrong two-step codes for your Octa Pass account".to_owned())
    );

    // Exactly one proof per request.
    let challenge = challenged(&server, "other", None).await;
    let both = second_factor(
        &server,
        &challenge["challengeId"],
        json!({ "totpCode": "123456", "recoveryCode": codes[1] }),
    )
    .await;
    assert!(both.is_problem("invalid-request"));
    let none = second_factor(&server, &challenge["challengeId"], json!({})).await;
    assert!(none.is_problem("invalid-request"));
}

#[tokio::test]
async fn a_long_guessing_run_alerts_the_owner_once_an_hour() {
    let server = TestServer::with_config(|config| {
        config.rate_limits.two_step_per_account = octapass_server::config::Bucket {
            burst: 2,
            refill: Duration::from_secs(1),
        };
    })
    .await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    enable(&server, &laptop).await;
    // Empty the bucket, then each time a token refills, use it up again.
    let challenge = challenged(&server, "phone", None).await;
    for round in 0..3 {
        let tries = if round == 0 { 2 } else { 1 };
        for _ in 0..tries {
            let wrong = second_factor(
                &server,
                &challenge["challengeId"],
                json!({ "recoveryCode": "00000-00000" }),
            )
            .await;
            assert!(
                wrong.is_problem("invalid-second-factor"),
                "{:?}",
                wrong.body
            );
        }
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }
    let log = security_log(&server, &laptop).await;
    assert_eq!(log.iter().filter(|e| *e == "two-step-locked").count(), 1);
    let alerts = subjects(&server)
        .into_iter()
        .filter(|s| s.starts_with("Several wrong two-step codes"))
        .count();
    assert_eq!(alerts, 1);
}

#[tokio::test]
async fn turning_off_removes_every_method() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    let (secret, _) = enable(&server, &laptop).await;

    // Replacing the authenticator keeps it on and the recovery codes as they are.
    let token = reauth(&server, &laptop, "two-step").await;
    let setup = server
        .call(
            Method::POST,
            "/v1/account/two-step/totp",
            Some(&laptop.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    let new_secret = setup.body["secret"].as_str().unwrap().to_owned();
    assert_ne!(new_secret, secret);
    next_step(&server);
    let replaced = server
        .call(
            Method::POST,
            "/v1/account/two-step/totp/confirm",
            Some(&laptop.access_token),
            &[],
            Some(json!({ "setupId": setup.body["setupId"], "code": totp(&new_secret, server.state.clock.now()) })),
        )
        .await;
    assert_eq!(replaced.status, StatusCode::OK, "{:?}", replaced.body);
    assert!(replaced.body.get("recoveryCodes").is_none());
    assert_eq!(status(&server, &laptop).await["recoveryCodesLeft"], 10);

    let bare = server
        .call(
            Method::DELETE,
            "/v1/account/two-step",
            Some(&laptop.access_token),
            &[],
            None,
        )
        .await;
    assert!(bare.is_problem("reauth-required"));
    let token = reauth(&server, &laptop, "two-step").await;
    let off = server
        .call(
            Method::DELETE,
            "/v1/account/two-step",
            Some(&laptop.access_token),
            &[("x-reauth-token", &token)],
            None,
        )
        .await;
    assert_eq!(off.status, StatusCode::NO_CONTENT, "{:?}", off.body);
    let after = status(&server, &laptop).await;
    assert_eq!(after["enabled"], false);
    assert_eq!(after["recoveryCodesLeft"], 0);

    let phone = server.login_with(EMAIL, PASSWORD, "phone").await;
    assert_eq!(phone.status, StatusCode::OK, "{:?}", phone.body);
    assert_eq!(
        security_log(&server, &laptop).await,
        [
            "two-step-disabled",
            "authenticator-changed",
            "two-step-enabled"
        ]
    );
    assert!(subjects(&server).contains(&"Two-step sign-in turned off".to_owned()));
}

#[tokio::test]
async fn the_operator_can_reset_two_step_and_deletion_removes_it() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    enable(&server, &laptop).await;
    octapass_server::admin::reset_two_step(&server.state, EMAIL)
        .await
        .unwrap();
    assert_eq!(status(&server, &laptop).await["enabled"], false);
    assert_eq!(
        trusted_rows(&server).await,
        0,
        "the reset forgets every trusted device"
    );
    assert!(matches!(
        octapass_server::admin::reset_two_step(&server.state, "nobody@example.com").await,
        Err(octapass_server::admin::AdminError::NoSuchAccount)
    ));

    enable(&server, &laptop).await;
    let token = common::reauth_token(&server, &laptop).await;
    let deleted = common::delete_account(&server, &laptop, Some(&token), EMAIL).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    for table in [
        "two_step",
        "recovery_codes",
        "trusted_devices",
        "two_step_setups",
    ] {
        let count: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(&server.state.db)
                .await
                .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

#[tokio::test]
async fn a_wrong_password_never_reaches_the_second_step() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "laptop").await;
    enable(&server, &laptop).await;
    let wrong = server.login_with(EMAIL, b"wrong", "phone").await;
    assert!(wrong.is_problem("login-failed"));
    assert!(wrong.body.get("secondFactor").is_none());
    let unknown = server
        .login_with("nobody@example.com", PASSWORD, "phone")
        .await;
    assert!(unknown.is_problem("login-failed"));
}

/// Migration 0007 on a database that already has trust: rows for devices
/// that are gone or revoked go, long expiries are cut to 30 days, and from
/// then on trust goes with its device. SQLite, and PostgreSQL when
/// `OCTAPASS_TEST_POSTGRES_URL` is set.
#[tokio::test]
async fn migration_0007_ties_existing_trust_to_devices() {
    sqlx::any::install_default_drivers();
    let dir = tempfile::tempdir().unwrap();
    let sqlite = format!("sqlite://{}/db.sqlite?mode=rwc", dir.path().display());
    migrate_existing_trust("sqlite", &sqlite, dir.path()).await;

    if let Ok(admin_url) = std::env::var("OCTAPASS_TEST_POSTGRES_URL") {
        use sqlx::{Connection, Executor};
        let name = format!("octapass_migration_{}", common::new_id().replace('-', ""));
        let mut admin = sqlx::PgConnection::connect(&admin_url).await.unwrap();
        admin
            .execute(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .await
            .unwrap();
        let mut url = url::Url::parse(&admin_url).unwrap();
        url.set_path(&name);
        migrate_existing_trust("postgres", url.as_str(), dir.path()).await;
        admin
            .execute(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE {name} WITH (FORCE)"
            )))
            .await
            .unwrap();
    }
}

async fn migrate_existing_trust(backend: &str, url: &str, scratch: &std::path::Path) {
    use sqlx::migrate::Migrator;
    let all = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("migrations")
        .join(backend);
    let before = scratch.join(format!("before-{backend}"));
    std::fs::create_dir(&before).unwrap();
    for entry in std::fs::read_dir(&all).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if name.as_str() < "0007" {
            std::fs::copy(&path, before.join(&name)).unwrap();
        }
    }
    let is_sqlite = backend == "sqlite";
    let db = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            Box::pin(async move {
                if is_sqlite {
                    sqlx::Executor::execute(conn, "PRAGMA foreign_keys = ON").await?;
                }
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap();
    Migrator::new(before.as_path())
        .await
        .unwrap()
        .run(&db)
        .await
        .unwrap();

    let day = 86_400_000i64;
    for statement in [
        "INSERT INTO accounts (id, email, kdf_memory_kib, kdf_iterations, kdf_parallelism, account_salt, \
         opaque_record, wrapped_ask, public_enc_key, public_sign_key, wrapped_private_keys, recovery_wrapped_ask, \
         email_verified_at, created_at) VALUES ('a', 'a@example.com', 65536, 3, 1, 's', 'o', 'w', 'e', 'p', 'k', 'r', 0, 0)",
        "INSERT INTO devices (id, account_id, name, platform, created_at, last_seen_at) VALUES ('live', 'a', 'n', 'p', 0, 0)",
        "INSERT INTO devices (id, account_id, name, platform, created_at, last_seen_at, revoked_at) VALUES ('revoked', 'a', 'n', 'p', 0, 0, 1)",
    ] {
        sqlx::query(statement).execute(&db).await.unwrap();
    }
    for (token, device) in [
        ("t-live", "live"),
        ("t-revoked", "revoked"),
        ("t-gone", "gone"),
    ] {
        sqlx::query(
            "INSERT INTO trusted_devices (token_hash, account_id, device_id, created_at, expires_at) VALUES ($1, 'a', $2, 0, $3)",
        )
        .bind(token)
        .bind(device)
        .bind(365 * day)
        .execute(&db)
        .await
        .unwrap();
    }

    Migrator::new(all.as_path())
        .await
        .unwrap()
        .run(&db)
        .await
        .unwrap();
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT token_hash, expires_at FROM trusted_devices")
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(rows, [("t-live".to_owned(), 30 * day)], "{backend}");
    sqlx::query("DELETE FROM devices WHERE id = 'live'")
        .execute(&db)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_devices")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(left, 0, "{backend}");
    db.close().await;
}
