//! Emergency access: the request → wait → release timeline on the server's
//! clock, denial and approval, reminders, the grantor's security log, and
//! the contact opening what was released with octapass-core.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::people::Person;
use common::*;
use octapass_core::account::AccountBundle;
use octapass_core::sharing::emergency::EmergencyScope;
use octapass_server::config::{Bucket, RateLimits};
use rand_core::OsRng;
use serde_json::{Value, json};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Adds `contact` as the grantor's emergency contact. Returns the record id.
async fn add_contact(
    server: &TestServer,
    grantor: &Person,
    contact: &Person,
    scope: EmergencyScope,
    wait_days: u32,
) -> String {
    let created = post_contact(server, grantor, contact, scope, wait_days).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["status"], "idle");
    created.body["id"].as_str().unwrap().to_owned()
}

async fn post_contact(
    server: &TestServer,
    grantor: &Person,
    contact: &Person,
    scope: EmergencyScope,
    wait_days: u32,
) -> Response {
    let sealed = grantor
        .session
        .seal_for_emergency_contact(
            &contact.account_id,
            &contact.session.key_pairs().public_enc_key(),
            None,
            &scope,
            &mut OsRng,
        )
        .unwrap();
    let body = json!({
        "contactAccountId": contact.account_id,
        "sealedKey": sealed,
        "scope": scope,
        "accessLevel": "view",
        "waitDays": wait_days,
    });
    server
        .send_as(grantor, Method::POST, "/v1/emergency-contacts", Some(body))
        .await
}

async fn act(server: &TestServer, person: &Person, id: &str, action: &str) -> Response {
    let path = format!("/v1/emergency-contacts/{id}/{action}");
    server.send_as(person, Method::POST, &path, None).await
}

async fn release(server: &TestServer, person: &Person, id: &str) -> Response {
    let path = format!("/v1/emergency-contacts/{id}/release");
    server.get_as(person, &path).await
}

async fn log_types(server: &TestServer, person: &Person) -> Vec<String> {
    let log = server.get_as(person, "/v1/security-log").await;
    assert_eq!(log.status, StatusCode::OK);
    log.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .map(|event| event["type"].as_str().unwrap().to_owned())
        .collect()
}

fn emails_to(server: &TestServer, to: &str) -> Vec<String> {
    server
        .state
        .dev_outbox()
        .into_iter()
        .filter(|(recipient, _)| recipient == to)
        .map(|(_, subject)| subject)
        .collect()
}

#[tokio::test]
async fn access_is_released_after_the_waiting_period() {
    let server = TestServer::new().await;
    let grantor = server.person("grace@example.com").await;
    let contact = server.person("carl@example.com").await;
    let saved = server
        .put_new_item(&grantor, &grantor.personal_vault, "Pension")
        .await;
    assert_eq!(saved.status, StatusCode::OK);
    let id = add_contact(&server, &grantor, &contact, EmergencyScope::Account, 3).await;
    assert_eq!(
        emails_to(&server, "carl@example.com").last().unwrap(),
        "grace@example.com chose you as an emergency contact"
    );

    // Nothing is released before a request, and only the contact can request.
    assert_eq!(
        release(&server, &contact, &id).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        act(&server, &grantor, &id, "request").await.status,
        StatusCode::FORBIDDEN
    );
    let requested = act(&server, &contact, &id, "request").await;
    assert_eq!(requested.status, StatusCode::OK);
    assert_eq!(requested.body["status"], "requested");
    assert!(requested.body["releasesAt"].is_string());
    assert!(
        emails_to(&server, "grace@example.com")
            .iter()
            .any(|subject| subject
                == "carl@example.com requested emergency access to your Octa Pass account")
    );

    // Two days in: still waiting, and the grantor gets a daily reminder.
    server.state.clock.advance(2 * DAY);
    server.state.run_maintenance().await.unwrap();
    server.state.run_maintenance().await.unwrap();
    let reminders = emails_to(&server, "grace@example.com")
        .into_iter()
        .filter(|subject| subject.starts_with("Reminder"))
        .count();
    assert_eq!(
        reminders, 1,
        "one reminder per day, however often maintenance runs"
    );
    assert_eq!(
        release(&server, &contact, &id).await.status,
        StatusCode::FORBIDDEN
    );

    // After the third day the key is released, without waiting for maintenance.
    server.state.clock.advance(DAY + Duration::from_secs(1));
    let released = release(&server, &contact, &id).await;
    assert_eq!(released.status, StatusCode::OK, "{:?}", released.body);
    assert_eq!(released.body["contact"]["status"], "released");
    assert_eq!(
        release(&server, &grantor, &id).await.status,
        StatusCode::FORBIDDEN
    );

    // The contact opens the grantor's account and reads the grantor's vault.
    let bundle: AccountBundle = serde_json::from_value(released.body["grantor"].clone()).unwrap();
    let sealed = released.body["sealedKey"].as_str().unwrap();
    let mut as_grantor = contact
        .session
        .open_emergency_account(bundle, sealed)
        .unwrap();
    let synced = server
        .get_as(&contact, &format!("/v1/emergency-contacts/{id}/sync"))
        .await;
    assert_eq!(synced.status, StatusCode::OK, "{:?}", synced.body);
    let vault = &synced.body["vaults"][0];
    assert_eq!(vault["id"], grantor.personal_vault.as_str());
    as_grantor
        .open_vault(
            vault["id"].as_str().unwrap(),
            vault["wrappedVaultKey"].as_str().unwrap(),
        )
        .unwrap();
    let item = &synced.body["items"][0];
    let encrypted = serde_json::from_value(item.clone()).unwrap();
    let overview = as_grantor
        .decrypt_overview(
            vault["id"].as_str().unwrap(),
            item["id"].as_str().unwrap(),
            &encrypted,
        )
        .unwrap();
    assert_eq!(overview.title, "Pension");

    assert_eq!(
        log_types(&server, &grantor).await,
        [
            "emergency-contact-added",
            "emergency-access-requested",
            "emergency-access-released"
        ]
    );
    assert!(
        log_types(&server, &contact).await.is_empty(),
        "the grantor's log"
    );
    let log = server.get_as(&grantor, "/v1/security-log").await;
    assert_eq!(
        log.body["events"][0]["otherAccountEmail"],
        "carl@example.com"
    );
    assert!(
        emails_to(&server, "carl@example.com")
            .iter()
            .any(|subject| subject.contains("is ready"))
    );
}

#[tokio::test]
async fn the_grantor_can_deny_or_approve() {
    let server = TestServer::new().await;
    let grantor = server.person("grace@example.com").await;
    let contact = server.person("carl@example.com").await;
    let stranger = server.person("sid@example.com").await;
    let id = add_contact(&server, &grantor, &contact, EmergencyScope::Account, 30).await;

    let path = format!("/v1/emergency-contacts/{id}/deny");
    let hidden = server.send_as(&stranger, Method::POST, &path, None).await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);

    act(&server, &contact, &id, "request").await;
    assert_eq!(
        act(&server, &contact, &id, "deny").await.status,
        StatusCode::FORBIDDEN
    );
    let denied = act(&server, &grantor, &id, "deny").await;
    assert_eq!(denied.body["status"], "idle");
    assert!(denied.body.get("releasesAt").is_none());
    assert!(
        emails_to(&server, "carl@example.com")
            .iter()
            .any(|subject| subject.contains("denied"))
    );
    server.state.clock.advance(31 * DAY);
    assert_eq!(
        release(&server, &contact, &id).await.status,
        StatusCode::FORBIDDEN
    );

    // Approving releases at once; denying afterwards takes it back.
    let nothing = act(&server, &grantor, &id, "approve").await;
    assert_eq!(nothing.status, StatusCode::BAD_REQUEST);
    act(&server, &contact, &id, "request").await;
    assert_eq!(
        act(&server, &contact, &id, "approve").await.status,
        StatusCode::FORBIDDEN
    );
    let approved = act(&server, &grantor, &id, "approve").await;
    assert_eq!(approved.body["status"], "released");
    assert_eq!(release(&server, &contact, &id).await.status, StatusCode::OK);
    act(&server, &grantor, &id, "deny").await;
    assert_eq!(
        release(&server, &contact, &id).await.status,
        StatusCode::FORBIDDEN
    );

    assert_eq!(
        log_types(&server, &grantor).await,
        [
            "emergency-contact-added",
            "emergency-access-requested",
            "emergency-access-denied",
            "emergency-access-requested",
            "emergency-access-approved",
            "emergency-access-denied",
        ]
    );

    // Either side can end it.
    let path = format!("/v1/emergency-contacts/{id}");
    assert_eq!(
        server
            .send_as(&stranger, Method::DELETE, &path, None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let removed = server.send_as(&contact, Method::DELETE, &path, None).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let listed = server.get_as(&grantor, "/v1/emergency-contacts").await;
    assert_eq!(listed.body, json!({ "granted": [], "received": [] }));
    assert_eq!(
        log_types(&server, &grantor).await.last().unwrap(),
        "emergency-contact-removed"
    );
}

#[tokio::test]
async fn a_vault_scope_releases_only_that_vault() {
    let server = TestServer::new().await;
    let mut grantor = server.person("grace@example.com").await;
    let mut contact = server.person("carl@example.com").await;
    let shared = server.shared_vault(&mut grantor).await;
    server.put_new_item(&grantor, &shared, "Deeds").await;
    server
        .put_new_item(&grantor, &grantor.personal_vault, "Diary")
        .await;
    let scope = EmergencyScope::Vault {
        vault_id: shared.clone(),
    };
    let id = add_contact(&server, &grantor, &contact, scope, 1).await;
    let listed = server.get_as(&contact, "/v1/emergency-contacts").await;
    assert_eq!(
        listed.body["received"][0]["scope"],
        json!({ "type": "vault", "vaultId": shared })
    );
    assert_eq!(
        listed.body["received"][0]["grantorEmail"],
        "grace@example.com"
    );

    act(&server, &contact, &id, "request").await;
    server.state.clock.advance(DAY);
    server.state.run_maintenance().await.unwrap();
    let listed = server.get_as(&contact, "/v1/emergency-contacts").await;
    assert_eq!(listed.body["received"][0]["status"], "released");

    let released = release(&server, &contact, &id).await;
    assert_eq!(released.status, StatusCode::OK, "{:?}", released.body);
    assert!(
        released.body.get("grantor").is_none(),
        "the grantor's bundle would open their other vaults"
    );
    let sealed = released.body["sealedKey"].as_str().unwrap();
    contact
        .session
        .open_emergency_vault(&grantor.account_id, &shared, sealed)
        .unwrap();
    let synced = server
        .get_as(&contact, &format!("/v1/emergency-contacts/{id}/sync"))
        .await;
    let vaults: Vec<&Value> = synced.body["vaults"].as_array().unwrap().iter().collect();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0]["id"], shared.as_str());
    let items = synced.body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(contact.title(&items[0]), "Deeds");
}

#[tokio::test]
async fn contacts_are_checked() {
    let server = TestServer::new().await;
    let grantor = server.person("grace@example.com").await;
    let mut contact = server.person("carl@example.com").await;
    let sealed = grantor
        .session
        .seal_for_emergency_contact(
            &contact.account_id,
            &contact.session.key_pairs().public_enc_key(),
            None,
            &EmergencyScope::Account,
            &mut OsRng,
        )
        .unwrap();
    let body = |contact_id: &str, wait_days: u32, scope: Value| {
        json!({
            "contactAccountId": contact_id,
            "sealedKey": sealed,
            "scope": scope,
            "accessLevel": "takeover",
            "waitDays": wait_days,
        })
    };
    let account = json!({ "type": "account" });
    let others_vault = server.shared_vault(&mut contact).await;
    for (bad, status) in [
        (
            body(&contact.account_id, 0, account.clone()),
            StatusCode::BAD_REQUEST,
        ),
        (
            body(&contact.account_id, 31, account.clone()),
            StatusCode::BAD_REQUEST,
        ),
        (
            body(&grantor.account_id, 7, account.clone()),
            StatusCode::BAD_REQUEST,
        ),
        (body(&new_id(), 7, account.clone()), StatusCode::NOT_FOUND),
        (
            body(
                &contact.account_id,
                7,
                json!({ "type": "vault", "vaultId": others_vault }),
            ),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let refused = server
            .send_as(&grantor, Method::POST, "/v1/emergency-contacts", Some(bad))
            .await;
        assert_eq!(refused.status, status, "{:?}", refused.body);
    }
    let mut bad_key = body(&contact.account_id, 7, account.clone());
    bad_key["sealedKey"] = json!(envelope(48));
    let refused = server
        .send_as(
            &grantor,
            Method::POST,
            "/v1/emergency-contacts",
            Some(bad_key),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);

    let created = server
        .send_as(
            &grantor,
            Method::POST,
            "/v1/emergency-contacts",
            Some(body(&contact.account_id, 7, account.clone())),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.body["accessLevel"], "takeover");
    let again = server
        .send_as(
            &grantor,
            Method::POST,
            "/v1/emergency-contacts",
            Some(body(&contact.account_id, 7, account)),
        )
        .await;
    assert!(again.is_problem("already-exists"));
}

#[tokio::test]
async fn adding_contacts_is_limited() {
    let slow = |burst| Bucket {
        burst,
        refill: Duration::from_secs(3600),
    };
    let server = TestServer::with_config(|config| {
        config.rate_limits = RateLimits {
            emergency_contact_per_account: slow(3),
            emergency_contact_per_recipient: slow(2),
            ..RateLimits::default()
        }
    })
    .await;
    let grace = server.person("grace@example.com").await;
    let kim = server.person("kim@example.com").await;
    let carl = server.person("carl@example.com").await;
    let dan = server.person("dan@example.com").await;
    let eve = server.person("eve@example.com").await;
    let account = || EmergencyScope::Account;

    // Adding, removing and adding again emails the contact each time.
    for _ in 0..2 {
        let id = add_contact(&server, &grace, &carl, account(), 7).await;
        let path = format!("/v1/emergency-contacts/{id}");
        server.send_as(&grace, Method::DELETE, &path, None).await;
    }
    // Carl's address has had its two: nobody can add him for now.
    let limited = post_contact(&server, &kim, &carl, account(), 7).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.is_problem("rate-limited"));
    let retry: u64 = limited.headers["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=3600).contains(&retry), "{retry}");
    let chosen = |to| {
        emails_to(&server, to)
            .iter()
            .filter(|subject| subject.contains("chose you"))
            .count()
    };
    assert_eq!(chosen("carl@example.com"), 2);

    // Grace has one left for someone else, then her own budget is spent.
    add_contact(&server, &grace, &dan, account(), 7).await;
    let limited = post_contact(&server, &grace, &eve, account(), 7).await;
    assert!(limited.is_problem("rate-limited"), "{:?}", limited.body);
    assert_eq!(chosen("eve@example.com"), 0);

    // Malformed requests don't spend Kim's budget (two of three left).
    for _ in 0..5 {
        let refused = post_contact(&server, &kim, &eve, account(), 0).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    }
    add_contact(&server, &kim, &eve, account(), 7).await;
    add_contact(&server, &kim, &dan, account(), 7).await;
}

#[tokio::test]
async fn rate_limits_off_lets_contacts_through() {
    let server =
        TestServer::with_config(|config| config.rate_limits = RateLimits::unlimited()).await;
    let grace = server.person("grace@example.com").await;
    let carl = server.person("carl@example.com").await;
    for _ in 0..20 {
        let id = add_contact(&server, &grace, &carl, EmergencyScope::Account, 7).await;
        let path = format!("/v1/emergency-contacts/{id}");
        server.send_as(&grace, Method::DELETE, &path, None).await;
    }
}
