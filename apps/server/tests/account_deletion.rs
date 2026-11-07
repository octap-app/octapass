//! Account deletion: reauthentication, one transaction, nothing left behind.

use crate::common;

use axum::http::{Method, StatusCode};
use common::people::{Person, now_ms};
use common::*;
use octapass_core::sharing::Role;
use octapass_core::sharing::emergency::EmergencyScope;
use rand_core::OsRng;
use serde_json::{Value, json};

const EMAIL: &str = "alice@example.com";

async fn prelogin(server: &TestServer, email: &str) -> Value {
    let response = server
        .post("/v1/auth/prelogin", json!({ "email": email }))
        .await;
    assert_eq!(response.status, StatusCode::OK);
    response.body
}

/// Every (table, column) whose value equals `needle`, across the whole database.
async fn rows_referencing(server: &TestServer, needle: &str) -> Vec<String> {
    let columns_sql = if server.is_postgres() {
        // Tables only: a view (such as `vault_access`) repeats its tables' rows.
        "SELECT CAST(c.table_name AS TEXT), CAST(c.column_name AS TEXT) FROM information_schema.columns c \
         JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name \
         WHERE c.table_schema = current_schema() AND t.table_type = 'BASE TABLE' \
         AND c.table_name NOT LIKE '\\_sqlx%'"
    } else {
        "SELECT m.name, p.name FROM sqlite_master m JOIN pragma_table_info(m.name) p \
         WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%' AND m.name NOT LIKE '_sqlx_%'"
    };
    let columns: Vec<(String, String)> = sqlx::query_as(columns_sql)
        .fetch_all(&server.state.db)
        .await
        .unwrap();
    assert!(columns.len() > 20, "found the schema");
    let mut found = Vec::new();
    for (table, column) in columns {
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM {table} WHERE CAST({column} AS TEXT) = $1"
        )))
        .bind(needle)
        .fetch_one(&server.state.db)
        .await
        .unwrap();
        if count > 0 {
            found.push(format!("{table}.{column}"));
        }
    }
    found
}

#[tokio::test]
async fn deleting_an_account_leaves_nothing_behind() {
    let server = TestServer::new().await;
    let fake_salt = prelogin(&server, EMAIL).await;

    let vault_id = server.register(EMAIL).await;
    let laptop = server.login(EMAIL, "Laptop").await;
    let phone = server.login(EMAIL, "Phone").await;
    let account_id = laptop.account["accountId"].as_str().unwrap().to_owned();
    for label in 0..3 {
        let created = server
            .put_item(
                &laptop.access_token,
                &vault_id,
                &new_id(),
                ("if-none-match", "*"),
                label,
            )
            .await;
        assert_eq!(created.status, StatusCode::OK);
    }
    assert_ne!(prelogin(&server, EMAIL).await, fake_salt);
    assert!(
        rows_referencing(&server, &account_id)
            .await
            .contains(&"accounts.id".to_owned())
    );

    // Without a reauth token, or with the wrong email, nothing happens.
    let unconfirmed = delete_account(&server, &laptop, None, EMAIL).await;
    assert_eq!(unconfirmed.status, StatusCode::FORBIDDEN);
    assert!(unconfirmed.is_problem("reauth-required"));
    let token = reauth_token(&server, &laptop).await;
    let wrong_email = delete_account(&server, &laptop, Some(&token), "bob@example.com").await;
    assert_eq!(wrong_email.status, StatusCode::BAD_REQUEST);
    assert!(wrong_email.is_problem("invalid-request"));
    assert_eq!(
        server.get("/v1/account", &laptop.access_token).await.status,
        StatusCode::OK
    );

    // The same token still works after the email mismatch, and the email is normalised.
    let deleted = delete_account(&server, &laptop, Some(&token), " Alice@Example.com").await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);

    // Other devices are told the account is gone, on every endpoint.
    let sync = server.get("/v1/sync", &phone.access_token).await;
    assert_eq!(sync.status, StatusCode::UNAUTHORIZED);
    assert!(sync.is_problem("account-deleted"));
    let refresh = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": phone.refresh_token }),
        )
        .await;
    assert_eq!(refresh.status, StatusCode::UNAUTHORIZED);
    assert!(refresh.is_problem("account-deleted"));
    assert!(
        server
            .get("/v1/account", &laptop.access_token)
            .await
            .is_problem("account-deleted")
    );

    // The email is unknown again: fake salt, failed login.
    assert_eq!(prelogin(&server, EMAIL).await, fake_salt);
    let login = server.login_with(EMAIL, PASSWORD, "Laptop").await;
    assert_eq!(login.status, StatusCode::UNAUTHORIZED);
    assert!(login.is_problem("login-failed"));

    // Nothing in the database points at the account or its email.
    assert_eq!(
        rows_referencing(&server, &account_id).await,
        Vec::<String>::new()
    );
    assert_eq!(rows_referencing(&server, EMAIL).await, Vec::<String>::new());
    assert_eq!(
        rows_referencing(&server, &vault_id).await,
        Vec::<String>::new()
    );

    // Nor do the raw SQLite files: deleted rows were zeroed and the WAL emptied.
    let files: &[&str] = if server.is_postgres() {
        &[]
    } else {
        &["octapass.db", "octapass.db-wal"]
    };
    for file in files {
        let bytes = std::fs::read(server.dir.path().join(file)).unwrap_or_default();
        for needle in [EMAIL, &account_id, &vault_id] {
            let found = bytes
                .windows(needle.len())
                .any(|window| window == needle.as_bytes());
            assert!(!found, "{file} still contains {needle}");
        }
    }

    // Only the anonymous counter records that it happened.
    let counts: Vec<(String, i64)> =
        sqlx::query_as("SELECT day, count FROM account_deletions_daily")
            .fetch_all(&server.state.db)
            .await
            .unwrap();
    assert_eq!(counts.len(), 1);
    assert_eq!(counts[0].1, 1);
    for table in [
        "accounts",
        "devices",
        "sessions",
        "vaults",
        "vault_members",
        "items",
        "tombstones",
        "reauth_tokens",
        "pending_registrations",
        "families",
        "family_members",
        "family_invites",
        "share_links",
        "emergency_contacts",
        "audit_events",
    ] {
        let rows: i64 =
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(&server.state.db)
                .await
                .unwrap();
        assert_eq!(rows, 0, "{table} still has rows");
    }

    // The email can be used for a new account right away.
    server.register(EMAIL).await;
    let fresh = server.login(EMAIL, "Laptop").await;
    assert_ne!(fresh.account["accountId"], account_id.as_str());
    let sync = server.get("/v1/sync", &fresh.access_token).await;
    assert_eq!(sync.body["items"], json!([]));
}

#[tokio::test]
async fn reauth_tokens_are_single_use_and_bound_to_the_account() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    server.register("bob@example.com").await;
    let alice = server.login(EMAIL, "Laptop").await;
    let bob = server.login("bob@example.com", "Laptop").await;

    // A wrong password gets the generic login failure.
    let wrong = server
        .reauth_with(&alice.access_token, b"wrong password")
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(wrong.is_problem("login-failed"));

    // Alice's token doesn't let Bob delete his account (or hers).
    let token = reauth_token(&server, &alice).await;
    let stolen = delete_account(&server, &bob, Some(&token), "bob@example.com").await;
    assert!(stolen.is_problem("reauth-required"));

    // A reauth started by one account can't be finished by another.
    let client = opaque_ke::ClientLogin::<Suite>::start(&mut rand_core::OsRng, PASSWORD).unwrap();
    let started = server
        .call(
            Method::POST,
            "/v1/auth/reauth/start",
            Some(&alice.access_token),
            &[],
            Some(json!({ "credentialRequest": b64(client.message.serialize()) })),
        )
        .await;
    let finalization = client_finish(client.state, PASSWORD, &started.body["credentialResponse"]);
    let hijacked = server
        .call(
            Method::POST,
            "/v1/auth/reauth/finish",
            Some(&bob.access_token),
            &[],
            Some(json!({ "reauthId": started.body["reauthId"], "credentialFinalization": finalization, "purpose": "delete-account" })),
        )
        .await;
    assert!(hijacked.is_problem("login-failed"));

    assert_eq!(
        delete_account(&server, &alice, Some(&token), EMAIL)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let bob_still_here = server.get("/v1/account", &bob.access_token).await;
    assert_eq!(bob_still_here.status, StatusCode::OK);

    // Reauth needs a signed-in device.
    let anonymous = server
        .call(
            Method::POST,
            "/v1/auth/reauth/start",
            None,
            &[],
            Some(json!({ "credentialRequest": b64([0u8; 96]) })),
        )
        .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_used_reauth_token_cannot_be_replayed() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let token = reauth_token(&server, &device).await;
    assert_eq!(
        delete_account(&server, &device, Some(&token), EMAIL)
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    server.register(EMAIL).await;
    let new_device = server.login(EMAIL, "Laptop").await;
    let replay = delete_account(&server, &new_device, Some(&token), EMAIL).await;
    assert!(replay.is_problem("reauth-required"));
}

#[tokio::test]
async fn admin_cli_deletes_accounts() {
    let server = TestServer::new().await;
    server.register(EMAIL).await;
    let device = server.login(EMAIL, "Laptop").await;
    let account_id = device.account["accountId"].as_str().unwrap().to_owned();

    octapass_server::admin::delete_account(&server.state, " ALICE@example.com ")
        .await
        .unwrap();
    assert!(
        server
            .get("/v1/sync", &device.access_token)
            .await
            .is_problem("account-deleted")
    );
    assert_eq!(
        rows_referencing(&server, &account_id).await,
        Vec::<String>::new()
    );
    assert!(
        octapass_server::admin::delete_account(&server.state, EMAIL)
            .await
            .is_err()
    );
}

async fn create_family(server: &TestServer, organiser: &mut Person) -> (String, String) {
    let vault = organiser
        .session
        .create_shared_vault(now_ms(), &mut OsRng)
        .unwrap();
    let family_id = new_id();
    let body = json!({ "id": family_id, "vault": vault });
    let created = server
        .send_as(organiser, Method::POST, "/v1/families", Some(body))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    (family_id, vault.id)
}

async fn family_invite(
    server: &TestServer,
    organiser: &Person,
    family: &(String, String),
    to: &Person,
) {
    let body = json!({ "email": to.email, "grant": organiser.grant(&family.1, to, Role::Write) });
    let path = format!("/v1/families/{}/invites", family.0);
    let invited = server
        .send_as(organiser, Method::POST, &path, Some(body))
        .await;
    assert_eq!(invited.status, StatusCode::ACCEPTED);
}

async fn emergency_contact(server: &TestServer, grantor: &Person, contact: &Person) {
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
    let body = json!({
        "contactAccountId": contact.account_id, "sealedKey": sealed,
        "scope": { "type": "account" }, "accessLevel": "view", "waitDays": 7,
    });
    let created = server
        .send_as(grantor, Method::POST, "/v1/emergency-contacts", Some(body))
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
}

async fn count(server: &TestServer, table: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
        .fetch_one(&server.state.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn deleting_an_account_cleans_up_its_sharing() {
    let server = TestServer::new().await;
    let addr = server.listen().await;
    let mut alice = server.person(EMAIL).await;
    let mut bob = server.person("bob@example.com").await;
    let mut carol = server.person("carol@example.com").await;

    // Alice's own shared vault, with Bob in it.
    let alices = server.shared_vault(&mut alice).await;
    server.invite(&alice, &alices, &bob, Role::Write).await;
    // Bob's vault, where Alice manages and added Carol.
    let bobs = server.shared_vault(&mut bob).await;
    server.invite(&bob, &bobs, &alice, Role::Manage).await;
    server.open_shared_vault(&mut alice, &bobs).await;
    server.invite(&alice, &bobs, &carol, Role::Read).await;
    // Alice is in Bob's family and invited to Carol's.
    let bobs_family = create_family(&server, &mut bob).await;
    family_invite(&server, &bob, &bobs_family, &alice).await;
    let path = format!("/v1/families/{}/invites/accept", bobs_family.0);
    let joined = server.send_as(&alice, Method::POST, &path, None).await;
    assert_eq!(joined.status, StatusCode::OK);
    let carols_family = create_family(&server, &mut carol).await;
    family_invite(&server, &carol, &carols_family, &alice).await;
    // A share link, and emergency access both ways.
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::hours(2);
    let expires_at = expires_at
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let link = json!({ "ciphertext": b64([1u8; 64]), "expiresAt": expires_at, "maxViews": 1, "passphraseRequired": false });
    let shared = server
        .send_as(&alice, Method::POST, "/v1/share-links", Some(link))
        .await;
    assert_eq!(shared.status, StatusCode::CREATED, "{:?}", shared.body);
    emergency_contact(&server, &alice, &bob).await;
    emergency_contact(&server, &carol, &alice).await;

    let mut bob_socket = ws_auth(addr, &bob.token).await;
    octapass_server::admin::delete_account(&server.state, EMAIL)
        .await
        .unwrap();

    // Bob hears about both vaults he shared with Alice.
    let mut heard = Vec::new();
    for _ in 0..2 {
        let message = ws_next(&mut bob_socket).await;
        assert_eq!(message["type"], "membership-changed");
        heard.push(message["vaultId"].as_str().unwrap().to_owned());
    }
    heard.sort();
    let mut expected = vec![alices.clone(), bobs.clone()];
    expected.sort();
    assert_eq!(heard, expected);

    // Her solely owned vault is gone; Bob's lives on without her.
    assert_eq!(server.vault_record(&bob, &alices).await, None);
    let path = format!("/v1/vaults/{bobs}/members");
    let members = server.get_as(&bob, &path).await;
    let emails: Vec<&str> = members.body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["email"].as_str().unwrap())
        .collect();
    assert_eq!(emails, ["bob@example.com", "carol@example.com"]);
    // Carol's grant still verifies: Alice signed it, and that stays with it.
    server.open_shared_vault(&mut carol, &bobs).await;

    let families = server.get_as(&bob, "/v1/families").await;
    assert_eq!(
        families.body["family"]["members"].as_array().unwrap().len(),
        1
    );
    let families = server.get_as(&carol, "/v1/families").await;
    assert_eq!(families.body["family"]["invites"], json!([]));
    for table in ["share_links", "emergency_contacts"] {
        assert_eq!(count(&server, table).await, 0, "{table}");
    }
    // Carol's log keeps her own events, without naming the deleted account.
    let log = server.get_as(&carol, "/v1/security-log").await;
    assert_eq!(log.body["events"][0]["type"], "emergency-contact-added");
    assert!(log.body["events"][0].get("otherAccountEmail").is_none());

    // Only the signed grant Alice gave Carol still holds her (random) id.
    assert_eq!(
        rows_referencing(&server, &alice.account_id).await,
        ["vault_members.granted_by"]
    );
    assert_eq!(rows_referencing(&server, EMAIL).await, Vec::<String>::new());
    assert_eq!(
        rows_referencing(&server, &alices).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn deleting_an_organiser_deletes_the_family() {
    let server = TestServer::new().await;
    let mut alice = server.person(EMAIL).await;
    let mut bob = server.person("bob@example.com").await;
    let family = create_family(&server, &mut alice).await;
    family_invite(&server, &alice, &family, &bob).await;
    let path = format!("/v1/families/{}/invites/accept", family.0);
    server.send_as(&bob, Method::POST, &path, None).await;
    server.open_shared_vault(&mut bob, &family.1).await;
    server.put_new_item(&bob, &family.1, "Groceries").await;

    octapass_server::admin::delete_account(&server.state, EMAIL)
        .await
        .unwrap();
    let families = server.get_as(&bob, "/v1/families").await;
    assert!(families.body.get("family").is_none());
    assert_eq!(server.vault_record(&bob, &family.1).await, None);
    for table in ["families", "family_members", "family_invites"] {
        assert_eq!(count(&server, table).await, 0, "{table}");
    }
    assert_eq!(
        rows_referencing(&server, &family.1).await,
        Vec::<String>::new()
    );
}
