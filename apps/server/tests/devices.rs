//! Signed-in devices: list, rename and remote sign-out.

use crate::common;

use axum::http::{Method, StatusCode};
use common::*;
use serde_json::{Value, json};

const EMAIL: &str = "alice@example.com";

async fn devices(server: &TestServer, device: &Device) -> Vec<Value> {
    let response = server.get("/v1/devices", &device.access_token).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    response.body.as_array().unwrap().clone()
}

async fn delete_device(server: &TestServer, device: &Device, id: &str) -> Response {
    server
        .call(
            Method::DELETE,
            &format!("/v1/devices/{id}"),
            Some(&device.access_token),
            &[],
            None,
        )
        .await
}

#[tokio::test]
async fn lists_and_renames_devices() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Laptop").await;
    let phone = server.login(EMAIL, "Phone").await;

    let listed = devices(&server, &laptop).await;
    assert_eq!(listed.len(), 2);
    let names: Vec<&str> = listed.iter().map(|d| d["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"Laptop") && names.contains(&"Phone"));
    for device in &listed {
        assert_eq!(device["platform"], "test");
        assert_eq!(device["current"], device["name"] == "Laptop");
        assert!(device["createdAt"].as_str().unwrap().ends_with('Z'));
        assert!(device["lastSeenAt"].as_str().unwrap().ends_with('Z'));
        assert_eq!(device.as_object().unwrap().len(), 6, "{device:?}");
    }

    let renamed = server
        .call(
            Method::PATCH,
            "/v1/devices/current",
            Some(&phone.access_token),
            &[],
            Some(json!({ "name": "  Work phone " })),
        )
        .await;
    assert_eq!(renamed.status, StatusCode::NO_CONTENT, "{:?}", renamed.body);
    let current: Vec<Value> = devices(&server, &phone)
        .await
        .into_iter()
        .filter(|d| d["current"] == true)
        .collect();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0]["name"], "Work phone");

    for name in ["", "   ", &"x".repeat(65), "tab\there"] {
        let rejected = server
            .call(
                Method::PATCH,
                "/v1/devices/current",
                Some(&phone.access_token),
                &[],
                Some(json!({ "name": name })),
            )
            .await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "{name:?}");
    }

    // Other accounts' devices never show up.
    server.register("bob@example.com").await;
    let bob = server.login("bob@example.com", "Bob's laptop").await;
    assert_eq!(devices(&server, &bob).await.len(), 1);
    assert_eq!(devices(&server, &laptop).await.len(), 2);
}

#[tokio::test]
async fn signs_devices_out_remotely() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Laptop").await;
    let phone = server.login(EMAIL, "Phone").await;
    server.register("bob@example.com").await;
    let bob = server.login("bob@example.com", "Bob's laptop").await;
    let id_of = |list: &[Value], name: &str| {
        list.iter().find(|d| d["name"] == name).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let listed = devices(&server, &laptop).await;
    let phone_id = id_of(&listed, "Phone");
    let laptop_id = id_of(&listed, "Laptop");
    let bob_id = id_of(&devices(&server, &bob).await, "Bob's laptop");

    // Someone else's device is not found, and stays signed in.
    let foreign = delete_device(&server, &laptop, &bob_id).await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    assert_eq!(
        server.get("/v1/sync", &bob.access_token).await.status,
        StatusCode::OK
    );
    assert_eq!(
        delete_device(&server, &laptop, "not-a-uuid").await.status,
        StatusCode::BAD_REQUEST
    );

    let removed = delete_device(&server, &laptop, &phone_id).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{:?}", removed.body);
    assert_eq!(
        server.get("/v1/sync", &phone.access_token).await.status,
        StatusCode::UNAUTHORIZED
    );
    let refresh = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": phone.refresh_token }),
        )
        .await;
    assert_eq!(refresh.status, StatusCode::UNAUTHORIZED);
    assert_eq!(devices(&server, &laptop).await.len(), 1);
    assert_eq!(
        delete_device(&server, &laptop, &phone_id).await.status,
        StatusCode::NOT_FOUND
    );

    // Deleting the current device signs it out.
    let own = delete_device(&server, &laptop, &laptop_id).await;
    assert_eq!(own.status, StatusCode::NO_CONTENT);
    assert_eq!(
        server.get("/v1/devices", &laptop.access_token).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Maintenance forgets devices with no session left.
    server.state.run_maintenance().await.unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM devices")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(remaining, 1, "only Bob's laptop is still signed in");
}

const NEW_SIGN_IN: &str = "New sign-in to your Octa Pass account";

fn new_sign_in_emails(server: &TestServer, to: &str) -> usize {
    server
        .state
        .dev_outbox()
        .iter()
        .filter(|(recipient, subject)| recipient == to && subject == NEW_SIGN_IN)
        .count()
}

#[tokio::test]
async fn new_devices_email_the_owner_and_trusted_devices_dont() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    // The sign-in that finishes sign-up isn't news.
    let laptop = server.login(EMAIL, "laptop").await;
    assert_eq!(new_sign_in_emails(&server, EMAIL), 0);

    let phone = server.login(EMAIL, "phone").await;
    assert_eq!(new_sign_in_emails(&server, EMAIL), 1);
    assert!(phone.trusted_device_token.is_some());

    // The laptop signing in again with its trusted-device token: no email.
    let trust = laptop.trusted_device_token.clone().unwrap();
    let again = server
        .login_trusted("192.0.2.1", EMAIL, PASSWORD, "laptop", Some(&trust))
        .await
        .unwrap();
    assert_eq!(again.status, StatusCode::OK, "{:?}", again.body);
    assert_eq!(new_sign_in_emails(&server, EMAIL), 1);

    // That token was used up, so it doesn't count a second time.
    let replayed = server
        .login_trusted("192.0.2.1", EMAIL, PASSWORD, "laptop", Some(&trust))
        .await
        .unwrap();
    assert_eq!(replayed.status, StatusCode::OK, "{:?}", replayed.body);
    assert_eq!(new_sign_in_emails(&server, EMAIL), 2);

    // A failed sign-in sends nothing.
    let failed = server.login_with(EMAIL, b"wrong password", "tablet").await;
    assert_eq!(failed.status, StatusCode::UNAUTHORIZED);
    assert_eq!(new_sign_in_emails(&server, EMAIL), 2);
}

#[tokio::test]
async fn the_first_device_is_only_exempt_right_after_sign_up() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    server
        .state
        .clock
        .advance(std::time::Duration::from_secs(11 * 60));
    server.login(EMAIL, "laptop").await;
    assert_eq!(new_sign_in_emails(&server, EMAIL), 1);
}

#[tokio::test]
async fn a_signed_in_app_links_a_device_of_its_own() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Laptop").await;
    let emails = new_sign_in_emails(&server, EMAIL);

    let link = |token: Option<String>, name: &str| {
        let body = json!({ "device": { "name": name, "platform": "cli" } });
        let server = &server;
        async move {
            server
                .call(
                    Method::POST,
                    "/v1/devices/link",
                    token.as_deref(),
                    &[],
                    Some(body),
                )
                .await
        }
    };
    // Only a signed-in session can link, and the name is checked like a sign-in's.
    assert_eq!(
        link(None, "CLI").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        link(Some(laptop.access_token.clone()), "").await.status,
        StatusCode::BAD_REQUEST
    );

    let linked = link(Some(laptop.access_token.clone()), "Octa Pass CLI").await;
    assert_eq!(linked.status, StatusCode::OK, "{:?}", linked.body);
    let cli = Device::from_login(&linked.body);
    assert_ne!(cli.access_token, laptop.access_token);
    assert_eq!(cli.account["email"], laptop.account["email"]);
    assert_eq!(new_sign_in_emails(&server, EMAIL), emails + 1);

    // It's a device of its own: listed, working, and signed out without touching the app.
    let listed = devices(&server, &cli).await;
    assert_eq!(listed.len(), 2);
    let current = listed.iter().find(|d| d["current"] == true).unwrap();
    assert_eq!(current["name"], "Octa Pass CLI");
    assert_eq!(current["platform"], "cli");
    let id = current["id"].as_str().unwrap().to_owned();
    let refreshed = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": cli.refresh_token }),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{:?}", refreshed.body);
    assert_eq!(
        delete_device(&server, &laptop, &id).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(devices(&server, &laptop).await.len(), 1);
}
