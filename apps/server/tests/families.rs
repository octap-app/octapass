//! Families: the organiser, invites that carry the Family vault grant, the
//! size limit, leaving and removing, and deleting the family.

use crate::common;

use axum::http::{Method, StatusCode};
use common::people::{Person, now_ms};
use common::*;
use octapass_core::sharing::Role;
use octapass_core::sharing::grant::Recipient;
use octapass_core::sharing::vault::ItemKey;
use rand_core::OsRng;
use serde_json::{Value, json};

/// Creates a family organised by `organiser`. Returns (family id, vault id).
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
    assert_eq!(created.body["organiserId"], organiser.account_id.as_str());
    assert_eq!(created.body["vaultId"], vault.id.as_str());
    (family_id, vault.id)
}

async fn invite(
    server: &TestServer,
    organiser: &Person,
    family_id: &str,
    vault_id: &str,
    email: &str,
    to: &Person,
) -> Response {
    let body = json!({ "email": email, "grant": organiser.grant(vault_id, to, Role::Write) });
    let path = format!("/v1/families/{family_id}/invites");
    server
        .send_as(organiser, Method::POST, &path, Some(body))
        .await
}

/// A rotation of the vault's key for `members`, with grants of the new key for the pending
/// invites of `invitees`, as a request body at the vault's current revision.
async fn rotation(
    server: &TestServer,
    organiser: &Person,
    vault_id: &str,
    members: &[Recipient],
    invitees: &[Recipient],
) -> (Value, String) {
    let synced = server.sync_all(organiser).await;
    let item_keys: Vec<ItemKey> = synced["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["vaultId"] == vault_id)
        .map(|item| ItemKey {
            item_id: item["id"].as_str().unwrap().to_owned(),
            encrypted_item_key: item["encryptedItemKey"].as_str().unwrap().to_owned(),
        })
        .collect();
    let everyone = [members, invitees].concat();
    let rotation = organiser
        .session
        .rotate_vault_key(vault_id, &everyone, &item_keys, now_ms(), &mut OsRng)
        .unwrap();
    let mut body = serde_json::to_value(&rotation).unwrap();
    let grants = body["grants"].as_array().unwrap().clone();
    body["grants"] = json!(grants[..members.len()]);
    body["invites"] = json!(grants[members.len()..]);
    let record = server.vault_record(organiser, vault_id).await.unwrap();
    body["revision"] = record["revision"].clone();
    (body, rotation.key_id)
}

async fn rotate(server: &TestServer, organiser: &Person, vault_id: &str, body: Value) -> Response {
    let path = format!("/v1/vaults/{vault_id}/rotate");
    server
        .send_as(organiser, Method::POST, &path, Some(body))
        .await
}

fn invited(family: &Value) -> Vec<String> {
    family["family"]["invites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|invite| invite["email"].as_str().unwrap().to_owned())
        .collect()
}

async fn families(server: &TestServer, person: &Person) -> Value {
    let got = server.get_as(person, "/v1/families").await;
    assert_eq!(got.status, StatusCode::OK, "{:?}", got.body);
    got.body
}

async fn accept(server: &TestServer, person: &Person, family_id: &str) -> Response {
    let path = format!("/v1/families/{family_id}/invites/accept");
    server.send_as(person, Method::POST, &path, None).await
}

async fn leave(server: &TestServer, by: &Person, family_id: &str, who: &Person) -> Response {
    let path = format!("/v1/families/{family_id}/members/{}", who.account_id);
    server.send_as(by, Method::DELETE, &path, None).await
}

#[tokio::test]
async fn a_family_shares_its_vault() {
    let server = TestServer::new().await;
    let mut olivia = server.person("olivia@example.com").await;
    let mut sam = server.person("sam@example.com").await;
    let (family_id, vault_id) = create_family(&server, &mut olivia).await;
    let record = server.vault_record(&olivia, &vault_id).await.unwrap();
    assert_eq!(record["type"], "family");
    assert_eq!(record["role"], "owner");

    let invited = invite(&server, &olivia, &family_id, &vault_id, &sam.email, &sam).await;
    assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.body);
    assert!(
        server
            .state
            .dev_outbox()
            .iter()
            .any(|(to, subject)| to == "sam@example.com" && subject.contains("olivia@example.com"))
    );
    let organiser_view = families(&server, &olivia).await;
    assert_eq!(
        organiser_view["family"]["invites"][0]["email"],
        "sam@example.com"
    );
    let invitee_view = families(&server, &sam).await;
    assert!(invitee_view.get("family").is_none());
    assert_eq!(
        invitee_view["invitations"][0]["familyId"],
        family_id.as_str()
    );
    assert_eq!(
        invitee_view["invitations"][0]["organiserEmail"],
        "olivia@example.com"
    );
    assert_eq!(
        server.vault_record(&sam, &vault_id).await,
        None,
        "not before accepting"
    );

    let joined = accept(&server, &sam, &family_id).await;
    assert_eq!(joined.status, StatusCode::OK, "{:?}", joined.body);
    assert_eq!(joined.body["members"][1]["role"], "member");
    assert_eq!(
        joined.body["invites"],
        json!([]),
        "only the organiser sees invites"
    );
    let record = server.vault_record(&sam, &vault_id).await.unwrap();
    assert_eq!(record["role"], "write");
    server.open_shared_vault(&mut sam, &vault_id).await;
    let written = server.put_new_item(&sam, &vault_id, "Netflix").await;
    assert_eq!(written.status, StatusCode::OK);
    let again = accept(&server, &sam, &family_id).await;
    assert!(again.is_problem("already-exists"));

    // Family vault members come and go through the family, not the vault.
    let path = format!("/v1/vaults/{vault_id}/members/{}", sam.account_id);
    let refused = server.send_as(&olivia, Method::DELETE, &path, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);

    let left = leave(&server, &sam, &family_id, &sam).await;
    assert_eq!(left.status, StatusCode::NO_CONTENT);
    assert_eq!(server.vault_record(&sam, &vault_id).await, None);
    assert!(families(&server, &sam).await.get("family").is_none());
    let organiser_leaves = leave(&server, &olivia, &family_id, &olivia).await;
    assert_eq!(organiser_leaves.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invites_are_limited_and_reveal_nothing() {
    let server = TestServer::with_config(|config| config.family_max_members = 3).await;
    let mut olivia = server.person("olivia@example.com").await;
    let sam = server.person("sam@example.com").await;
    let kim = server.person("kim@example.com").await;
    let lee = server.person("lee@example.com").await;
    let (family_id, vault_id) = create_family(&server, &mut olivia).await;

    // An unknown email, or a grant for someone else: accepted, nothing stored.
    let unknown = invite(
        &server,
        &olivia,
        &family_id,
        &vault_id,
        "ghost@example.com",
        &sam,
    )
    .await;
    let mismatched = invite(&server, &olivia, &family_id, &vault_id, &kim.email, &sam).await;
    for response in [&unknown, &mismatched] {
        assert_eq!(response.status, StatusCode::ACCEPTED);
    }
    assert_eq!(
        families(&server, &olivia).await["family"]["invites"],
        json!([])
    );
    assert_eq!(families(&server, &kim).await["invitations"], json!([]));

    // Only the organiser invites; others don't see the family at all.
    let mut grant = olivia.grant(&vault_id, &kim, Role::Write);
    grant["grantedBy"] = json!(sam.account_id);
    let body = json!({ "email": kim.email, "grant": grant });
    let path = format!("/v1/families/{family_id}/invites");
    let not_organiser = server.send_as(&sam, Method::POST, &path, Some(body)).await;
    assert_eq!(not_organiser.status, StatusCode::NOT_FOUND);

    // The organiser plus two invites fill a family of 3.
    for person in [&sam, &kim] {
        let invited = invite(
            &server,
            &olivia,
            &family_id,
            &vault_id,
            &person.email,
            person,
        )
        .await;
        assert_eq!(invited.status, StatusCode::ACCEPTED);
    }
    let full = invite(&server, &olivia, &family_id, &vault_id, &lee.email, &lee).await;
    assert!(full.is_problem("family-full"), "{:?}", full.body);
    let full = invite(
        &server,
        &olivia,
        &family_id,
        &vault_id,
        "ghost@example.com",
        &lee,
    )
    .await;
    assert!(
        full.is_problem("family-full"),
        "the same answer for any email"
    );

    // Kim declines; that frees a place.
    let path = format!("/v1/families/{family_id}/invites/{}", kim.account_id);
    let declined = server.send_as(&kim, Method::DELETE, &path, None).await;
    assert_eq!(declined.status, StatusCode::NO_CONTENT);
    let path = format!("/v1/families/{family_id}/invites/{}", sam.account_id);
    let not_yours = server.send_as(&kim, Method::DELETE, &path, None).await;
    assert_eq!(not_yours.status, StatusCode::NOT_FOUND);
    let invited = invite(&server, &olivia, &family_id, &vault_id, &lee.email, &lee).await;
    assert_eq!(invited.status, StatusCode::ACCEPTED);
    assert_eq!(
        accept(&server, &kim, &family_id).await.status,
        StatusCode::NOT_FOUND
    );

    // A family invite carries a write grant for the Family vault.
    let mut grant = olivia.grant(&vault_id, &kim, Role::Read);
    grant["role"] = json!("read");
    let body = json!({ "email": kim.email, "grant": grant });
    let path = format!("/v1/families/{family_id}/invites");
    let refused = server
        .send_as(&olivia, Method::POST, &path, Some(body))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn one_family_per_account_and_the_organiser_manages_it() {
    let server = TestServer::new().await;
    let mut olivia = server.person("olivia@example.com").await;
    let mut pat = server.person("pat@example.com").await;
    let sam = server.person("sam@example.com").await;
    let kim = server.person("kim@example.com").await;
    let (family_id, vault_id) = create_family(&server, &mut olivia).await;
    let (other_family, other_vault) = create_family(&server, &mut pat).await;

    let vault = olivia
        .session
        .create_shared_vault(now_ms(), &mut OsRng)
        .unwrap();
    let body = json!({ "id": new_id(), "vault": vault });
    let second = server
        .send_as(&olivia, Method::POST, "/v1/families", Some(body))
        .await;
    assert!(second.is_problem("already-exists"));

    for person in [&sam, &kim] {
        invite(
            &server,
            &olivia,
            &family_id,
            &vault_id,
            &person.email,
            person,
        )
        .await;
        assert_eq!(
            accept(&server, person, &family_id).await.status,
            StatusCode::OK
        );
    }
    // Sam is invited elsewhere too, but must leave first.
    invite(&server, &pat, &other_family, &other_vault, &sam.email, &sam).await;
    assert!(
        accept(&server, &sam, &other_family)
            .await
            .is_problem("already-exists")
    );

    // Members can't remove each other; the organiser can.
    assert_eq!(
        leave(&server, &sam, &family_id, &kim).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        leave(&server, &olivia, &family_id, &kim).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(server.vault_record(&kim, &vault_id).await, None);

    // Only the organiser deletes the family, and its vault goes with it.
    let path = format!("/v1/families/{family_id}");
    assert_eq!(
        server
            .send_as(&sam, Method::DELETE, &path, None)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let deleted = server.send_as(&olivia, Method::DELETE, &path, None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    for person in [&olivia, &sam] {
        assert_eq!(server.vault_record(person, &vault_id).await, None);
        assert!(families(&server, person).await.get("family").is_none());
    }
    assert_eq!(
        accept(&server, &sam, &other_family).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn rotating_reseals_pending_invites_or_cancels_them() {
    let server = TestServer::new().await;
    let mut olivia = server.person("olivia@example.com").await;
    let sam = server.person("sam@example.com").await;
    let mut kim = server.person("kim@example.com").await;
    let lee = server.person("lee@example.com").await;
    let (family_id, vault_id) = create_family(&server, &mut olivia).await;
    invite(&server, &olivia, &family_id, &vault_id, &sam.email, &sam).await;
    accept(&server, &sam, &family_id).await;
    for person in [&kim, &lee] {
        invite(
            &server,
            &olivia,
            &family_id,
            &vault_id,
            &person.email,
            person,
        )
        .await;
    }
    server.put_new_item(&olivia, &vault_id, "Netflix").await;
    let old_key_id = server.vault_record(&olivia, &vault_id).await.unwrap()["keyId"].clone();
    leave(&server, &olivia, &family_id, &sam).await;

    let organiser = [olivia.recipient(Role::Owner)];
    let (body, key_id) = rotation(
        &server,
        &olivia,
        &vault_id,
        &organiser,
        &[kim.recipient(Role::Write)],
    )
    .await;

    // Invite grants must be for pending invites, one each, with the invite's role.
    let (for_sam, _) = rotation(
        &server,
        &olivia,
        &vault_id,
        &organiser,
        &[sam.recipient(Role::Write)],
    )
    .await;
    let (as_read, _) = rotation(
        &server,
        &olivia,
        &vault_id,
        &organiser,
        &[kim.recipient(Role::Read)],
    )
    .await;
    let mut twice = body.clone();
    twice["invites"] = json!([body["invites"][0], body["invites"][0]]);
    let mut not_mine = body.clone();
    not_mine["invites"][0]["grantedBy"] = json!(kim.account_id);
    for broken in [for_sam, as_read, twice, not_mine] {
        let refused = rotate(&server, &olivia, &vault_id, broken).await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{:?}",
            refused.body
        );
    }
    assert_eq!(
        server.vault_record(&olivia, &vault_id).await.unwrap()["keyId"],
        old_key_id,
        "refused rotations leave no trace"
    );
    assert_eq!(
        invited(&families(&server, &olivia).await),
        ["kim@example.com", "lee@example.com"]
    );

    let rotated = rotate(&server, &olivia, &vault_id, body).await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);

    // Kim's invite now holds the new key; Lee's, left out, was cancelled.
    assert_eq!(
        invited(&families(&server, &olivia).await),
        ["kim@example.com"]
    );
    assert_eq!(families(&server, &lee).await["invitations"], json!([]));
    assert_eq!(
        accept(&server, &lee, &family_id).await.status,
        StatusCode::NOT_FOUND
    );
    let joined = accept(&server, &kim, &family_id).await;
    assert_eq!(joined.status, StatusCode::OK, "{:?}", joined.body);
    let record = server.vault_record(&kim, &vault_id).await.unwrap();
    assert_eq!(record["keyId"], key_id.as_str());
    server.open_shared_vault(&mut kim, &vault_id).await;
    let synced = server.sync_all(&kim).await;
    let item = synced["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["vaultId"] == vault_id)
        .unwrap();
    assert_eq!(kim.title(item), "Netflix");

    // Re-sending Lee's invite must name the new key: a grant of the old one is refused.
    let path = format!("/v1/families/{family_id}/invites");
    let grant = olivia.grant(&vault_id, &lee, Role::Write);
    for (key, status) in [
        (json!("short"), StatusCode::BAD_REQUEST),
        (old_key_id, StatusCode::CONFLICT),
        (json!(key_id), StatusCode::ACCEPTED),
    ] {
        let body = json!({ "email": lee.email, "grant": grant, "keyId": key });
        let sent = server
            .send_as(&olivia, Method::POST, &path, Some(body))
            .await;
        assert_eq!(sent.status, status, "{:?}", sent.body);
        if status == StatusCode::CONFLICT {
            assert!(sent.is_problem("vault-key-changed"));
        }
    }
}

#[tokio::test]
async fn shared_vaults_have_no_invites_to_reseal() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let bob = server.person("bob@example.com").await;
    let vault_id = server.shared_vault(&mut alice).await;
    let (body, _) = rotation(
        &server,
        &alice,
        &vault_id,
        &[alice.recipient(Role::Owner)],
        &[bob.recipient(Role::Write)],
    )
    .await;
    let refused = rotate(&server, &alice, &vault_id, body).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );
}

#[tokio::test]
async fn an_invite_racing_a_rotation_never_keeps_the_old_key() {
    let server = TestServer::new().await;
    let mut olivia = server.person("olivia@example.com").await;
    let lee = server.person("lee@example.com").await;
    let (family_id, vault_id) = create_family(&server, &mut olivia).await;
    let path = format!("/v1/families/{family_id}/invites");
    for _ in 0..6 {
        // The invite seals the key before the rotation; which one commits first is up to the race.
        let key_id = server.vault_record(&olivia, &vault_id).await.unwrap()["keyId"].clone();
        let grant = olivia.grant(&vault_id, &lee, Role::Write);
        let body = json!({ "email": lee.email, "grant": grant, "keyId": key_id });
        let (rotation, _) = rotation(
            &server,
            &olivia,
            &vault_id,
            &[olivia.recipient(Role::Owner)],
            &[],
        )
        .await;
        let (sent, rotated) = tokio::join!(
            server.send_as(&olivia, Method::POST, &path, Some(body)),
            rotate(&server, &olivia, &vault_id, rotation),
        );
        assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);
        assert!(
            sent.status == StatusCode::ACCEPTED || sent.is_problem("vault-key-changed"),
            "{:?}",
            sent.body
        );
        // Stored first, then cancelled by the rotation; or refused after it.
        assert!(invited(&families(&server, &olivia).await).is_empty());
        // Olivia's next grant needs the new key.
        server.open_shared_vault(&mut olivia, &vault_id).await;
    }
}
