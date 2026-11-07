//! Shared vaults end to end: real sealed and signed grants from octapass-core,
//! role checks on every write, invites that don't reveal accounts, member
//! removal with key rotation, and live notifications.

use crate::common;

use axum::http::{Method, StatusCode};
use common::people::{Person, grant_from_record, now_ms};
use common::*;
use octapass_core::sharing::Role;
use octapass_core::sharing::fingerprint::fingerprint;
use octapass_core::sharing::vault::ItemKey;
use rand_core::OsRng;
use serde_json::{Value, json};

fn members_path(vault_id: &str) -> String {
    format!("/v1/vaults/{vault_id}/members")
}

async fn members(server: &TestServer, person: &Person, vault_id: &str) -> Vec<Value> {
    let listed = server.get_as(person, &members_path(vault_id)).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    listed.body["members"].as_array().unwrap().clone()
}

async fn remove(server: &TestServer, by: &Person, vault_id: &str, who: &Person) -> Response {
    let path = format!("/v1/vaults/{vault_id}/members/{}", who.account_id);
    server.send_as(by, Method::DELETE, &path, None).await
}

/// Every item record in the vault, from a full sync.
async fn items_of(server: &TestServer, person: &Person, vault_id: &str) -> Vec<Value> {
    let synced = server.sync_all(person).await;
    synced["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["vaultId"] == vault_id)
        .cloned()
        .collect()
}

#[tokio::test]
async fn members_share_a_vault_through_signed_grants() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let mut bob = server.person("bob@example.com").await;
    let vault_id = server.shared_vault(&mut alice).await;

    let record = server.vault_record(&alice, &vault_id).await.unwrap();
    assert_eq!(record["type"], "shared");
    assert_eq!(record["role"], "owner");
    assert_eq!(
        record["keyId"],
        alice.session.vault_key_id(&vault_id).unwrap()
    );
    assert_eq!(record["grant"]["grantedBy"], alice.account_id.as_str());

    let created = server.put_new_item(&alice, &vault_id, "Router").await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);

    // Alice looks Bob up, and the fingerprint is the one Bob's device shows.
    let found = server
        .get_as(&alice, "/v1/accounts/lookup?email=Bob@Example.com")
        .await;
    assert_eq!(found.status, StatusCode::OK, "{:?}", found.body);
    assert_eq!(found.body["accountId"], bob.account_id.as_str());
    let bob_print = fingerprint(
        &bob.session.key_pairs().public_enc_key(),
        &bob.public_sign_key(),
    );
    assert_eq!(found.body["fingerprint"], bob_print.digits.as_str());

    assert_eq!(server.vault_record(&bob, &vault_id).await, None);
    let invited = server.invite(&alice, &vault_id, &bob, Role::Write).await;
    assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.body);

    // Bob's sync carries the grant; his core checks Alice's signature on it.
    let record = server.vault_record(&bob, &vault_id).await.unwrap();
    assert_eq!(record["role"], "write");
    let (grant, granter) = grant_from_record(&record, &bob.account_id);
    assert_eq!(granter, alice.public_sign_key());
    assert!(
        bob.session
            .open_shared_vault(&grant, &bob.public_sign_key())
            .is_err(),
        "not signed by Bob"
    );
    server.open_shared_vault(&mut bob, &vault_id).await;
    let items = items_of(&server, &bob, &vault_id).await;
    assert_eq!(items.len(), 1);
    assert_eq!(bob.title(&items[0]), "Router");

    let written = server.put_new_item(&bob, &vault_id, "Printer").await;
    assert_eq!(written.status, StatusCode::OK, "{:?}", written.body);
    let titles: Vec<String> = items_of(&server, &alice, &vault_id)
        .await
        .iter()
        .map(|item| alice.title(item))
        .collect();
    assert_eq!(titles.len(), 2);
    assert!(titles.contains(&"Printer".to_owned()));

    let listed = members(&server, &bob, &vault_id).await;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["email"], "alice@example.com");
    assert_eq!(listed[0]["role"], "owner");
    assert_eq!(listed[1]["role"], "write");
    assert_eq!(listed[1]["grantedBy"], alice.account_id.as_str());
    assert_eq!(listed[1]["fingerprint"], bob_print.digits.as_str());
}

#[tokio::test]
async fn roles_are_enforced_on_every_write() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let mut manager = server.person("manager@example.com").await;
    let mut writer = server.person("writer@example.com").await;
    let mut reader = server.person("reader@example.com").await;
    let outsider = server.person("outsider@example.com").await;
    let vault_id = server.shared_vault(&mut owner).await;
    for (person, role) in [
        (&manager, Role::Manage),
        (&writer, Role::Write),
        (&reader, Role::Read),
    ] {
        let invited = server.invite(&owner, &vault_id, person, role).await;
        assert_eq!(invited.status, StatusCode::ACCEPTED);
    }
    for person in [&mut manager, &mut writer, &mut reader] {
        server.open_shared_vault(person, &vault_id).await;
    }

    // read can't write.
    let refused = server.put_new_item(&reader, &vault_id, "Nope").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let written = server.put_new_item(&writer, &vault_id, "Fine").await;
    assert_eq!(written.status, StatusCode::OK);

    // write can't manage members, or rotate.
    let refused = server
        .invite(&writer, &vault_id, &outsider, Role::Read)
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(
        remove(&server, &writer, &vault_id, &reader).await.status,
        StatusCode::FORBIDDEN
    );
    let rotate = json!({ "revision": 1, "keyId": b64([0u8; 16]), "grants": [], "items": [] });
    let path = format!("/v1/vaults/{vault_id}/rotate");
    let refused = server
        .send_as(&writer, Method::POST, &path, Some(rotate))
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    // manage can add and remove, but not touch owners or grant ownership.
    let refused = server
        .invite(&manager, &vault_id, &outsider, Role::Owner)
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(
        remove(&server, &manager, &vault_id, &owner).await.status,
        StatusCode::FORBIDDEN
    );
    let added = server
        .invite(&manager, &vault_id, &outsider, Role::Read)
        .await;
    assert_eq!(added.status, StatusCode::ACCEPTED);
    assert_eq!(
        remove(&server, &manager, &vault_id, &outsider).await.status,
        StatusCode::NO_CONTENT
    );
    // A role change is a new grant.
    let promoted = server
        .invite(&manager, &vault_id, &reader, Role::Write)
        .await;
    assert_eq!(promoted.status, StatusCode::ACCEPTED);
    let record = server.vault_record(&reader, &vault_id).await.unwrap();
    assert_eq!(record["role"], "write");

    // Nobody outside the vault learns it exists.
    let hidden = server.get_as(&outsider, &members_path(&vault_id)).await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    let mut grant = owner.grant(&vault_id, &reader, Role::Read);
    grant["grantedBy"] = json!(outsider.account_id);
    let body = json!({ "email": reader.email, "grant": grant });
    let hidden = server
        .send_as(
            &outsider,
            Method::POST,
            &members_path(&vault_id),
            Some(body),
        )
        .await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);

    // Only the owner grants ownership; the last owner can't leave.
    let made_owner = server
        .invite(&owner, &vault_id, &manager, Role::Owner)
        .await;
    assert_eq!(made_owner.status, StatusCode::ACCEPTED);
    let left = remove(&server, &owner, &vault_id, &owner).await;
    assert_eq!(left.status, StatusCode::NO_CONTENT, "another owner remains");
    let last = remove(&server, &manager, &vault_id, &manager).await;
    assert_eq!(last.status, StatusCode::BAD_REQUEST);
    let left = remove(&server, &reader, &vault_id, &reader).await;
    assert_eq!(left.status, StatusCode::NO_CONTENT, "anyone can leave");
}

#[tokio::test]
async fn personal_vaults_and_bad_grants_are_refused() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let bob = server.person("bob@example.com").await;
    let personal = alice.personal_vault.clone();

    // A personal vault's key is wrapped by the ASK: it can't take members.
    let vault = alice
        .session
        .create_shared_vault(now_ms(), &mut OsRng)
        .unwrap();
    let grant = serde_json::to_value(
        alice
            .session
            .grant_vault(&vault.id, &bob.recipient(Role::Read), now_ms(), &mut OsRng)
            .unwrap(),
    )
    .unwrap();
    let mut wrong_vault = grant.clone();
    wrong_vault["vaultId"] = json!(personal);
    let body = json!({ "email": bob.email, "grant": wrong_vault });
    let refused = server
        .send_as(&alice, Method::POST, &members_path(&personal), Some(body))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        remove(&server, &alice, &personal, &alice).await.status,
        StatusCode::FORBIDDEN
    );

    // A shared vault must start with the creator's own owner grant.
    let mut body = serde_json::to_value(&vault).unwrap();
    body["grant"] = grant.clone();
    let refused = server
        .send_as(&alice, Method::POST, "/v1/vaults", Some(body))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let mut body = serde_json::to_value(&vault).unwrap();
    body["grant"]["signature"] = json!(b64([0u8; 10]));
    let refused = server
        .send_as(&alice, Method::POST, "/v1/vaults", Some(body))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let body = serde_json::to_value(&vault).unwrap();
    let created = server
        .send_as(&alice, Method::POST, "/v1/vaults", Some(body.clone()))
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let again = server
        .send_as(&alice, Method::POST, "/v1/vaults", Some(body))
        .await;
    assert!(again.is_problem("vault-exists"));

    // Grants signed in someone else's name are refused.
    let mut forged = grant;
    forged["grantedBy"] = json!(bob.account_id);
    let body = json!({ "email": bob.email, "grant": forged });
    let refused = server
        .send_as(&alice, Method::POST, &members_path(&vault.id), Some(body))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invites_and_lookups_do_not_enumerate_accounts() {
    let server = TestServer::with_config(|config| {
        config.rate_limits.lookup_per_account.burst = 5;
    })
    .await;
    let mut alice = server.person("alice@example.com").await;
    let bob = server.person("bob@example.com").await;
    let vault_id = server.shared_vault(&mut alice).await;

    let unauthenticated = server
        .call(
            Method::GET,
            "/v1/accounts/lookup?email=bob@example.com",
            None,
            &[],
            None,
        )
        .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    let missing = server
        .get_as(&alice, "/v1/accounts/lookup?email=nobody@example.com")
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    // A grant made for Bob, sent for an email with no account: same answer
    // as a real invite, and nothing is stored.
    let grant = alice.grant(&vault_id, &bob, Role::Read);
    let body = json!({ "email": "nobody@example.com", "grant": grant });
    let unknown = server
        .send_as(&alice, Method::POST, &members_path(&vault_id), Some(body))
        .await;
    // Bob's real email, but a grant for another account id: also nothing.
    let mut misdirected = grant.clone();
    misdirected["recipientAccountId"] = json!(new_id());
    let body = json!({ "email": bob.email, "grant": misdirected });
    let mismatched = server
        .send_as(&alice, Method::POST, &members_path(&vault_id), Some(body))
        .await;
    let real = server.invite(&alice, &vault_id, &bob, Role::Read).await;
    for response in [&unknown, &mismatched, &real] {
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(response.body, Value::Null);
    }
    assert_eq!(members(&server, &alice, &vault_id).await.len(), 2);

    // Lookups and invites share one budget per account.
    let limited = server
        .get_as(&alice, "/v1/accounts/lookup?email=bob@example.com")
        .await;
    assert_eq!(limited.status, StatusCode::OK);
    let limited = server
        .get_as(&alice, "/v1/accounts/lookup?email=bob@example.com")
        .await;
    assert!(limited.is_problem("rate-limited"), "{:?}", limited.body);
    let limited = server.invite(&alice, &vault_id, &bob, Role::Read).await;
    assert!(limited.is_problem("rate-limited"));
    let others = server
        .get_as(&bob, "/v1/accounts/lookup?email=alice@example.com")
        .await;
    assert_eq!(others.status, StatusCode::OK, "budgets are per account");
}

#[tokio::test]
async fn removing_a_member_rotates_the_vault_key() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let mut bob = server.person("bob@example.com").await;
    let mut carol = server.person("carol@example.com").await;
    let vault_id = server.shared_vault(&mut alice).await;
    for person in [&bob, &carol] {
        server.invite(&alice, &vault_id, person, Role::Write).await;
    }
    server.open_shared_vault(&mut bob, &vault_id).await;
    server.open_shared_vault(&mut carol, &vault_id).await;
    server.put_new_item(&alice, &vault_id, "Bank").await;
    server.put_new_item(&carol, &vault_id, "Alarm").await;

    let removed = remove(&server, &alice, &vault_id, &carol).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    assert_eq!(server.vault_record(&carol, &vault_id).await, None);
    assert!(items_of(&server, &carol, &vault_id).await.is_empty());
    let shut_out = server.put_new_item(&carol, &vault_id, "Sneaky").await;
    assert_eq!(shut_out.status, StatusCode::NOT_FOUND);

    let items = items_of(&server, &alice, &vault_id).await;
    let item_keys: Vec<ItemKey> = items
        .iter()
        .map(|item| ItemKey {
            item_id: item["id"].as_str().unwrap().to_owned(),
            encrypted_item_key: item["encryptedItemKey"].as_str().unwrap().to_owned(),
        })
        .collect();
    let stays = [alice.recipient(Role::Owner), bob.recipient(Role::Write)];
    let rotation = alice
        .session
        .rotate_vault_key(&vault_id, &stays, &item_keys, now_ms(), &mut OsRng)
        .unwrap();
    let revision = server.vault_record(&alice, &vault_id).await.unwrap()["revision"].clone();
    let path = format!("/v1/vaults/{vault_id}/rotate");
    let body = |revision: Value, rotation: Value| {
        let mut body = rotation;
        body["revision"] = revision;
        body
    };
    let full = serde_json::to_value(&rotation).unwrap();

    // Everything must match the vault exactly.
    let stale = server
        .send_as(
            &alice,
            Method::POST,
            &path,
            Some(body(json!(0), full.clone())),
        )
        .await;
    assert!(stale.is_problem("vault-changed"), "{:?}", stale.body);
    let mut missing_member = full.clone();
    missing_member["grants"].as_array_mut().unwrap().pop();
    let mut missing_item = full.clone();
    missing_item["items"].as_array_mut().unwrap().pop();
    let mut old_key = full.clone();
    old_key["items"][0]["encryptedItemKey"] = items[0]["encryptedItemKey"].clone();
    let mut wrong_role = full.clone();
    wrong_role["grants"][1]["role"] = json!("read");
    for broken in [missing_member, missing_item, old_key, wrong_role] {
        let refused = server
            .send_as(
                &alice,
                Method::POST,
                &path,
                Some(body(revision.clone(), broken)),
            )
            .await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{:?}",
            refused.body
        );
    }
    let unchanged = server.vault_record(&alice, &vault_id).await.unwrap();
    assert_eq!(
        unchanged["revision"], revision,
        "refused rotations leave no trace"
    );

    let rotated = server
        .send_as(
            &alice,
            Method::POST,
            &path,
            Some(body(revision.clone(), full)),
        )
        .await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);
    let new_revision = rotated.body["revision"].as_u64().unwrap();
    assert_eq!(new_revision, revision.as_u64().unwrap() + 1);

    // Bob, still on the old key, can't store item keys the others can't open.
    let stale_write = server.put_new_item(&bob, &vault_id, "Old key").await;
    assert!(
        stale_write.is_problem("vault-key-changed"),
        "{:?}",
        stale_write.body
    );

    // Bob syncs: new key id, new grant, every item at the new revision.
    let since = format!("/v1/sync?since={vault_id}:{revision}");
    let synced = server.get_as(&bob, &since).await.body;
    let changed: Vec<&Value> = synced["items"].as_array().unwrap().iter().collect();
    assert_eq!(changed.len(), 2);
    assert!(changed.iter().all(|item| item["revision"] == new_revision));
    let record = server.vault_record(&bob, &vault_id).await.unwrap();
    assert_eq!(record["keyId"], rotation.key_id.as_str());
    server.open_shared_vault(&mut bob, &vault_id).await;
    let mut titles: Vec<String> = changed.iter().map(|item| bob.title(item)).collect();
    titles.sort();
    assert_eq!(titles, ["Alarm", "Bank"]);
    let written = server.put_new_item(&bob, &vault_id, "New key").await;
    assert_eq!(written.status, StatusCode::OK, "{:?}", written.body);

    // Carol's old key opens none of the re-wrapped item keys.
    for item in &changed {
        let encrypted = serde_json::from_value((*item).clone()).unwrap();
        let item_id = item["id"].as_str().unwrap();
        assert!(
            carol
                .session
                .decrypt_overview(&vault_id, item_id, &encrypted)
                .is_err()
        );
    }
}

#[tokio::test]
async fn members_hear_about_membership_and_item_changes() {
    let server = TestServer::new().await;
    let addr = server.listen().await;
    let mut alice = server.person("alice@example.com").await;
    let mut bob = server.person("bob@example.com").await;
    let vault_id = server.shared_vault(&mut alice).await;
    let mut socket = ws_auth(addr, &bob.token).await;

    server.invite(&alice, &vault_id, &bob, Role::Write).await;
    let message = ws_next(&mut socket).await;
    assert_eq!(
        message,
        json!({ "type": "membership-changed", "vaultId": vault_id })
    );

    server.open_shared_vault(&mut bob, &vault_id).await;
    server.put_new_item(&alice, &vault_id, "Wi-Fi").await;
    let message = ws_next(&mut socket).await;
    assert_eq!(message["type"], "vault-changed");
    assert_eq!(message["vaultId"], vault_id.as_str());

    remove(&server, &alice, &vault_id, &bob).await;
    let message = ws_next(&mut socket).await;
    assert_eq!(
        message,
        json!({ "type": "membership-changed", "vaultId": vault_id }),
        "the removed member hears it too"
    );
}
