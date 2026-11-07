//! Organisations: roles, invites, groups, who may reach a vault, reviewed grants, revocation,
//! policies, the activity log and account deletion. Keys are real: grants are sealed and signed
//! by `octapass-core`, and nothing here gives an admin a key.

use crate::common;

use axum::http::{Method, StatusCode};
use common::people::{Person, now_ms};
use common::two_step::{enable, reauth};
use common::*;
use octapass_core::sharing::Role;
use octapass_core::sharing::emergency::EmergencyScope;
use rand_core::OsRng;
use serde_json::{Value, json};

fn device(person: &Person) -> Device {
    Device {
        access_token: person.token.clone(),
        refresh_token: String::new(),
        account: json!({}),
        trusted_device_token: None,
    }
}

async fn create_org(server: &TestServer, owner: &Person, name: &str) -> String {
    let id = new_id();
    let body = json!({ "id": id, "name": name });
    let created = server
        .send_as(owner, Method::POST, "/v1/orgs", Some(body))
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["role"], "owner");
    id
}

/// Invites `person` and accepts as them.
async fn join(server: &TestServer, admin: &Person, org: &str, person: &Person, role: &str) {
    let body = json!({ "email": person.email, "role": role });
    let path = format!("/v1/orgs/{org}/invites");
    let invited = server.send_as(admin, Method::POST, &path, Some(body)).await;
    assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.body);
    let orgs = server.get_as(person, "/v1/orgs").await;
    let invitation = &orgs.body["invitations"][0];
    assert_eq!(invitation["orgId"], org, "{:?}", orgs.body);
    let path = format!(
        "/v1/orgs/{org}/invites/{}/accept",
        invitation["id"].as_str().unwrap()
    );
    let accepted = server.send_as(person, Method::POST, &path, None).await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
}

/// Creates a vault of the organisation, as a client does.
async fn org_vault(server: &TestServer, owner: &mut Person, org: &str) -> String {
    let vault = owner
        .session
        .create_shared_vault(now_ms(), &mut OsRng)
        .unwrap();
    let path = format!("/v1/orgs/{org}/vaults");
    let created = server
        .send_as(
            owner,
            Method::POST,
            &path,
            Some(serde_json::to_value(&vault).unwrap()),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["orgId"], org);
    assert_eq!(created.body["type"], "shared", "it opens as a shared vault");
    vault.id
}

async fn group(server: &TestServer, admin: &Person, org: &str, name: &str) -> String {
    let id = new_id();
    let path = format!("/v1/orgs/{org}/groups");
    let body = json!({ "id": id, "name": name });
    let created = server.send_as(admin, Method::POST, &path, Some(body)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    id
}

async fn add_to_group(
    server: &TestServer,
    admin: &Person,
    org: &str,
    group: &str,
    person: &Person,
) {
    let path = format!(
        "/v1/orgs/{org}/groups/{group}/members/{}",
        person.account_id
    );
    let added = server.send_as(admin, Method::PUT, &path, None).await;
    assert_eq!(added.status, StatusCode::NO_CONTENT, "{:?}", added.body);
}

async fn link(
    server: &TestServer,
    admin: &Person,
    org: &str,
    vault: &str,
    group: &str,
    role: &str,
) {
    let path = format!("/v1/orgs/{org}/vaults/{vault}/groups/{group}");
    let body = json!({ "role": role });
    let linked = server.send_as(admin, Method::PUT, &path, Some(body)).await;
    assert_eq!(linked.status, StatusCode::NO_CONTENT, "{:?}", linked.body);
}

async fn plan(server: &TestServer, person: &Person, org: &str, vault: &str) -> Option<Value> {
    let path = format!("/v1/orgs/{org}/access");
    let access = server.get_as(person, &path).await;
    assert_eq!(access.status, StatusCode::OK, "{:?}", access.body);
    access.body["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["vaultId"] == vault)
        .cloned()
}

/// Seals the vault to `people`, as the key holder's device does after a person reviewed the plan.
async fn apply(
    server: &TestServer,
    holder: &Person,
    org: &str,
    vault: &str,
    people: &[(&Person, Role)],
) -> Response {
    let plan = plan(server, holder, org, vault).await.unwrap();
    let grants: Vec<Value> = people
        .iter()
        .map(|(person, role)| holder.grant(vault, person, *role))
        .collect();
    let path = format!("/v1/orgs/{org}/vaults/{vault}/grants");
    let body = json!({ "keyId": plan["keyId"], "grants": grants });
    server
        .send_as(holder, Method::POST, &path, Some(body))
        .await
}

fn has_vault(synced: &Value, vault: &str) -> bool {
    synced["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .any(|record| record["id"] == vault)
}

#[tokio::test]
async fn an_organisation_has_owners_admins_and_members() {
    let server = TestServer::new().await;
    let owner = server.person("owner@example.com").await;
    let admin = server.person("admin@example.com").await;
    let member = server.person("member@example.com").await;
    let outsider = server.person("outsider@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &admin, "admin").await;
    join(&server, &admin, &org, &member, "member").await;

    let mine = server.get_as(&member, "/v1/orgs").await;
    assert_eq!(mine.body["organisation"]["name"], "Acme");
    assert_eq!(mine.body["organisation"]["role"], "member");
    assert_eq!(mine.body["organisation"]["memberCount"], 3);

    let path = format!("/v1/orgs/{org}/members");
    let list = server.get_as(&admin, &path).await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.body["members"].as_array().unwrap().len(), 3);

    // Members manage nothing, and outsiders see nothing.
    assert_eq!(
        server.get_as(&member, &path).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server.get_as(&outsider, &path).await.status,
        StatusCode::NOT_FOUND
    );

    // Admins can't touch policies or roles; only owners can.
    let policies = json!({
        "requireTwoStep": true, "requireSso": false, "ssoMaxAgeHours": 168,
        "disableShareLinks": false, "disableEmergencyAccess": false, "disableExport": false,
    });
    let path = format!("/v1/orgs/{org}/policies");
    let refused = server
        .send_as(&admin, Method::PUT, &path, Some(policies))
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let path = format!("/v1/orgs/{org}/members/{}", admin.account_id);
    let refused = server
        .send_as(
            &admin,
            Method::PATCH,
            &path,
            Some(json!({ "role": "owner" })),
        )
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    // An admin can't remove an owner, and the last owner can't leave or step down.
    let path = format!("/v1/orgs/{org}/members/{}", owner.account_id);
    let refused = server.send_as(&admin, Method::DELETE, &path, None).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    let refused = server.send_as(&owner, Method::DELETE, &path, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let refused = server
        .send_as(
            &owner,
            Method::PATCH,
            &path,
            Some(json!({ "role": "member" })),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);

    // One organisation per account.
    let body = json!({ "id": new_id(), "name": "Second" });
    let refused = server
        .send_as(&member, Method::POST, "/v1/orgs", Some(body))
        .await;
    assert!(refused.is_problem("already-exists"));
}

#[tokio::test]
async fn invites_answer_the_same_for_any_email() {
    let server = TestServer::new().await;
    let owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;

    let path = format!("/v1/orgs/{org}/invites");
    for email in ["nobody@example.com", "member@example.com"] {
        let body = json!({ "email": email, "role": "member" });
        let answer = server
            .send_as(&owner, Method::POST, &path, Some(body))
            .await;
        assert_eq!(answer.status, StatusCode::ACCEPTED, "{email}");
    }
    let members = format!("/v1/orgs/{org}/members");
    let list = server.get_as(&owner, &members).await;
    let invites = list.body["invites"].as_array().unwrap();
    assert_eq!(invites.len(), 1, "a member isn't invited again");
    assert_eq!(invites[0]["email"], "nobody@example.com");
    assert!(
        server
            .state
            .dev_outbox()
            .iter()
            .any(|(to, subject)| to == "nobody@example.com" && subject.contains("invited")),
        "an email with no account still hears about it"
    );

    // Owners can't be invited, and an invite belongs to its email.
    let body = json!({ "email": "a@example.com", "role": "owner" });
    let refused = server
        .send_as(&owner, Method::POST, &path, Some(body))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let stranger = server.person("stranger@example.com").await;
    let id = invites[0]["id"].as_str().unwrap();
    let path = format!("/v1/orgs/{org}/invites/{id}/accept");
    let refused = server.send_as(&stranger, Method::POST, &path, None).await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND);

    // Someone signing up later with that email finds it, and the policies come with it.
    let newcomer = server.person("nobody@example.com").await;
    let orgs = server.get_as(&newcomer, "/v1/orgs").await;
    assert_eq!(orgs.body["invitations"][0]["orgName"], "Acme");
    assert_eq!(orgs.body["invitations"][0]["policies"]["requireSso"], false);

    // Invites expire.
    server
        .state
        .clock
        .advance(std::time::Duration::from_secs(15 * 86_400));
    let orgs = server.get_as(&newcomer, "/v1/orgs").await;
    assert!(orgs.body["invitations"].as_array().unwrap().is_empty());
    let accepted = server.send_as(&newcomer, Method::POST, &path, None).await;
    assert_eq!(accepted.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn joining_a_group_grants_nothing_until_a_key_holder_seals_it() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let admin = server.person("admin@example.com").await;
    let mut member = server.person("member@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &admin, "admin").await;
    join(&server, &owner, &org, &member, "member").await;
    let vault = org_vault(&server, &mut owner, &org).await;
    let finance = group(&server, &owner, &org, "Finance").await;
    link(&server, &owner, &org, &vault, &finance, "write").await;
    add_to_group(&server, &owner, &org, &finance, &member).await;

    // Being entitled gives neither a key nor access, however often it's asked.
    assert!(!has_vault(&server.sync_all(&member).await, &vault));
    let waiting = plan(&server, &owner, &org, &vault).await.unwrap();
    assert_eq!(waiting["canApply"], true);
    assert_eq!(waiting["grants"][0]["email"], "member@example.com");
    assert_eq!(waiting["grants"][0]["role"], "write");

    // An admin who holds no key sees it's waiting but can't act on it.
    let blocked = plan(&server, &admin, &org, &vault).await.unwrap();
    assert_eq!(blocked["canApply"], false);
    assert!(blocked.get("keyId").is_none());
    let path = format!("/v1/orgs/{org}/vaults/{vault}/grants");
    let body = json!({ "keyId": waiting["keyId"], "grants": [] });
    let refused = server
        .send_as(&admin, Method::POST, &path, Some(body))
        .await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND);

    // The grant must match the entitlement exactly: the role, and the person.
    let wrong = apply(&server, &owner, &org, &vault, &[(&member, Role::Manage)]).await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    let outsider = server.person("outsider@example.com").await;
    let wrong = apply(&server, &owner, &org, &vault, &[(&outsider, Role::Write)]).await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    let applied = apply(&server, &owner, &org, &vault, &[(&member, Role::Write)]).await;
    assert_eq!(applied.status, StatusCode::NO_CONTENT, "{:?}", applied.body);

    // Now it's an ordinary shared vault: its grant verifies and its items open.
    let put = server.put_new_item(&owner, &vault, "Bank").await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.body);
    assert_eq!(
        server.vault_record(&member, &vault).await.unwrap()["orgId"],
        org.as_str()
    );
    server.open_shared_vault(&mut member, &vault).await;
    let synced = server.sync_all(&member).await;
    let synced_item = synced["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["vaultId"] == vault)
        .unwrap();
    assert_eq!(member.title(synced_item), "Bank");
    assert!(plan(&server, &owner, &org, &vault).await.is_none());
}

#[tokio::test]
async fn organisation_owners_are_entitled_to_every_vault() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let second = server.person("second@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &second, "member").await;
    let vault = org_vault(&server, &mut owner, &org).await;
    assert!(plan(&server, &owner, &org, &vault).await.is_none());

    let path = format!("/v1/orgs/{org}/members/{}", second.account_id);
    let promoted = server
        .send_as(
            &owner,
            Method::PATCH,
            &path,
            Some(json!({ "role": "owner" })),
        )
        .await;
    assert_eq!(
        promoted.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        promoted.body
    );
    let waiting = plan(&server, &owner, &org, &vault).await.unwrap();
    assert_eq!(waiting["grants"][0]["role"], "owner");
    // Still by an ordinary reviewed grant: the server can't do it alone.
    assert!(!has_vault(&server.sync_all(&second).await, &vault));
    let applied = apply(&server, &owner, &org, &vault, &[(&second, Role::Owner)]).await;
    assert_eq!(applied.status, StatusCode::NO_CONTENT, "{:?}", applied.body);
    assert!(has_vault(&server.sync_all(&second).await, &vault));
}

#[tokio::test]
async fn losing_access_is_immediate_and_marks_the_vault_for_rotation() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;
    let vault = org_vault(&server, &mut owner, &org).await;
    let team = group(&server, &owner, &org, "Team").await;
    link(&server, &owner, &org, &vault, &team, "write").await;
    add_to_group(&server, &owner, &org, &team, &member).await;
    apply(&server, &owner, &org, &vault, &[(&member, Role::Write)]).await;
    assert!(has_vault(&server.sync_all(&member).await, &vault));

    // Out of the group: gone at once, with no key holder involved.
    let path = format!("/v1/orgs/{org}/groups/{team}/members/{}", member.account_id);
    let removed = server.send_as(&owner, Method::DELETE, &path, None).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{:?}", removed.body);
    assert!(!has_vault(&server.sync_all(&member).await, &vault));
    let waiting = plan(&server, &owner, &org, &vault).await.unwrap();
    assert_eq!(waiting["rotate"], true);
    assert!(waiting["grants"].as_array().unwrap().is_empty());
    let vaults = server
        .get_as(&owner, &format!("/v1/orgs/{org}/vaults"))
        .await;
    assert_eq!(vaults.body["vaults"][0]["rotationPending"], true);

    // Rotating, as plan 15 describes, clears it.
    let rotation = owner
        .session
        .rotate_vault_key(
            &vault,
            &[owner.recipient(Role::Owner)],
            &[],
            now_ms(),
            &mut OsRng,
        )
        .unwrap();
    let revision = server.vault_record(&owner, &vault).await.unwrap()["revision"].clone();
    let mut body = serde_json::to_value(&rotation).unwrap();
    body["revision"] = revision;
    let path = format!("/v1/vaults/{vault}/rotate");
    let rotated = server
        .send_as(&owner, Method::POST, &path, Some(body))
        .await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);
    assert!(plan(&server, &owner, &org, &vault).await.is_none());
}

#[tokio::test]
async fn a_lower_role_takes_effect_at_once() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;
    let vault = org_vault(&server, &mut owner, &org).await;
    let team = group(&server, &owner, &org, "Team").await;
    link(&server, &owner, &org, &vault, &team, "write").await;
    add_to_group(&server, &owner, &org, &team, &member).await;
    apply(&server, &owner, &org, &vault, &[(&member, Role::Write)]).await;

    // A role is signed into the grant, so the server can't lower it: the old grant goes, and a
    // key holder grants the lower role. They keep nothing new, so no rotation is asked for.
    link(&server, &owner, &org, &vault, &team, "read").await;
    assert!(!has_vault(&server.sync_all(&member).await, &vault));
    let waiting = plan(&server, &owner, &org, &vault).await.unwrap();
    assert_eq!(waiting["rotate"], false);
    assert_eq!(waiting["grants"][0]["role"], "read");
    apply(&server, &owner, &org, &vault, &[(&member, Role::Read)]).await;
    assert!(has_vault(&server.sync_all(&member).await, &vault));

    // A higher role is an upgrade: they keep what they have meanwhile.
    link(&server, &owner, &org, &vault, &team, "write").await;
    let waiting = plan(&server, &owner, &org, &vault).await.unwrap();
    assert_eq!(waiting["grants"][0]["upgrade"], true);
    assert!(has_vault(&server.sync_all(&member).await, &vault));
}

#[tokio::test]
async fn leaving_removes_every_vault_and_an_orphan_needs_saying_so() {
    let server = TestServer::new().await;
    let owner = server.person("owner@example.com").await;
    let mut admin = server.person("admin@example.com").await;
    let reader = server.person("reader@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &admin, "admin").await;
    join(&server, &owner, &org, &reader, "member").await;
    let vault = org_vault(&server, &mut admin, &org).await;

    // The admin is the only key holder here: removing them needs saying so out loud.
    let path = format!("/v1/orgs/{org}/members/{}", admin.account_id);
    let refused = server.send_as(&owner, Method::DELETE, &path, None).await;
    assert!(
        refused.is_problem("org-vault-orphaned"),
        "{:?}",
        refused.body
    );
    assert_eq!(refused.body["vaultIds"][0], vault.as_str());
    assert!(has_vault(&server.sync_all(&admin).await, &vault));

    let forced = format!("{path}?orphanVaults=true");
    let removed = server.send_as(&owner, Method::DELETE, &forced, None).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{:?}", removed.body);
    assert!(!has_vault(&server.sync_all(&admin).await, &vault));
    assert!(
        server
            .state
            .dev_outbox()
            .iter()
            .any(|(to, subject)| to == "admin@example.com" && subject.contains("removed"))
    );

    // Nobody can open it now, and an owner can clear it without a key. That needs a reauth.
    let vaults = server
        .get_as(&owner, &format!("/v1/orgs/{org}/vaults"))
        .await;
    assert_eq!(vaults.body["vaults"][0]["managerCount"], 0);
    let path = format!("/v1/orgs/{org}/vaults/{vault}");
    let refused = server.send_as(&owner, Method::DELETE, &path, None).await;
    assert!(refused.is_problem("reauth-required"));
    let token = reauth(&server, &device(&owner), "organisation").await;
    let deleted = server
        .call(
            Method::DELETE,
            &path,
            Some(&owner.token),
            &[("x-reauth-token", token.as_str())],
            None,
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);
}

#[tokio::test]
async fn organisation_vaults_hold_only_organisation_members() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let outsider = server.person("outsider@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;
    let vault = org_vault(&server, &mut owner, &org).await;

    // Adding an outsider answers like an unknown email and stores nothing.
    let answer = server.invite(&owner, &vault, &outsider, Role::Read).await;
    assert_eq!(answer.status, StatusCode::ACCEPTED);
    assert!(!has_vault(&server.sync_all(&outsider).await, &vault));

    // Added directly, a member stays through group changes and removal is remembered.
    let answer = server.invite(&owner, &vault, &member, Role::Read).await;
    assert_eq!(answer.status, StatusCode::ACCEPTED);
    assert!(has_vault(&server.sync_all(&member).await, &vault));
    let team = group(&server, &owner, &org, "Team").await;
    let path = format!("/v1/orgs/{org}/groups/{team}");
    server.send_as(&owner, Method::DELETE, &path, None).await;
    assert!(has_vault(&server.sync_all(&member).await, &vault));

    let path = format!("/v1/vaults/{vault}/members/{}", member.account_id);
    let removed = server.send_as(&owner, Method::DELETE, &path, None).await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{:?}", removed.body);
    assert_eq!(
        plan(&server, &owner, &org, &vault).await.unwrap()["rotate"],
        true
    );

    // Someone who has it through a group can't be taken off behind the group's back.
    let team = group(&server, &owner, &org, "Team2").await;
    link(&server, &owner, &org, &vault, &team, "read").await;
    add_to_group(&server, &owner, &org, &team, &member).await;
    apply(&server, &owner, &org, &vault, &[(&member, Role::Read)]).await;
    let refused = server.send_as(&owner, Method::DELETE, &path, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_two_step_policy_withholds_organisation_vaults_only() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;
    let vault = org_vault(&server, &mut owner, &org).await;
    let answer = server.invite(&owner, &vault, &member, Role::Write).await;
    assert_eq!(answer.status, StatusCode::ACCEPTED);
    let put = server.put_new_item(&owner, &vault, "Bank").await;
    assert_eq!(put.status, StatusCode::OK, "{:?}", put.body);

    enable(&server, &device(&owner)).await;
    let path = format!("/v1/orgs/{org}/policies");
    let body = json!({
        "requireTwoStep": true, "requireSso": false, "ssoMaxAgeHours": 168,
        "disableShareLinks": false, "disableEmergencyAccess": false, "disableExport": false,
    });
    let saved = server.send_as(&owner, Method::PUT, &path, Some(body)).await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);

    // The member keeps their account and personal vault, and loses the organisation's.
    let synced = server.sync_all(&member).await;
    assert!(!has_vault(&synced, &vault));
    assert!(has_vault(&synced, &member.personal_vault));
    assert_eq!(
        server.get_as(&member, "/v1/orgs").await.body["organisation"]["accessWithheld"],
        true
    );
    // Writes and files stop too, not just the list.
    let other = new_id();
    let refused = server
        .call(
            Method::PUT,
            &format!("/v1/vaults/{vault}/items/{other}"),
            Some(&member.token),
            &[("if-none-match", "*")],
            Some(item_body(1)),
        )
        .await;
    assert_ne!(refused.status, StatusCode::CREATED, "{:?}", refused.body);
    assert_eq!(refused.status, StatusCode::NOT_FOUND, "{:?}", refused.body);
    let items = server.sync_all(&owner).await;
    let item_id = items["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["vaultId"] == vault)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = format!("/v1/vaults/{vault}/items/{item_id}/attachments");
    assert_eq!(
        server.get_as(&member, &path).await.status,
        StatusCode::NOT_FOUND
    );

    // The owner, who has two-step on, keeps it. Turning it on brings the vault back.
    assert!(has_vault(&server.sync_all(&owner).await, &vault));
    enable(&server, &device(&member)).await;
    assert!(has_vault(&server.sync_all(&member).await, &vault));

    // It can't be turned off while the policy stands.
    let token = reauth(&server, &device(&member), "two-step").await;
    let refused = server
        .call(
            Method::DELETE,
            "/v1/account/two-step",
            Some(&member.token),
            &[("x-reauth-token", token.as_str())],
            None,
        )
        .await;
    assert!(refused.is_problem("org-policy"), "{:?}", refused.body);
}

#[tokio::test]
async fn share_link_and_emergency_policies_are_enforced_by_the_server() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let contact = server.person("contact@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;
    let vault = org_vault(&server, &mut owner, &org).await;
    server.invite(&owner, &vault, &member, Role::Read).await;

    // A contact from before the policy, with access already released.
    let scope = EmergencyScope::Account;
    let sealed = member
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
        "contactAccountId": contact.account_id, "scope": scope,
        "accessLevel": "view", "waitDays": 1, "sealedKey": sealed,
    });
    let created = server
        .send_as(
            &member,
            Method::POST,
            "/v1/emergency-contacts",
            Some(body.clone()),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let contact_id = created.body["id"].as_str().unwrap().to_owned();
    let path = format!("/v1/emergency-contacts/{contact_id}/request");
    server.send_as(&contact, Method::POST, &path, None).await;
    let path = format!("/v1/emergency-contacts/{contact_id}/approve");
    let approved = server.send_as(&member, Method::POST, &path, None).await;
    assert_eq!(approved.status, StatusCode::OK, "{:?}", approved.body);
    let path = format!("/v1/emergency-contacts/{contact_id}/sync");
    assert!(has_vault(
        &server.get_as(&contact, &path).await.body,
        &vault
    ));

    let policy_path = format!("/v1/orgs/{org}/policies");
    let policies = json!({
        "requireTwoStep": false, "requireSso": false, "ssoMaxAgeHours": 168,
        "disableShareLinks": true, "disableEmergencyAccess": true, "disableExport": true,
        "maxAutoLockMinutes": 15, "minPasswordLength": 14,
    });
    let saved = server
        .send_as(&owner, Method::PUT, &policy_path, Some(policies))
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);

    // The contact keeps what isn't the organisation's.
    let synced = server.get_as(&contact, &path).await.body;
    assert!(!has_vault(&synced, &vault));
    assert!(has_vault(&synced, &member.personal_vault));

    let refused = server
        .send_as(
            &member,
            Method::POST,
            "/v1/share-links",
            Some(json!({
                "ciphertext": b64([&[1u8][..], &random_bytes(80)].concat()),
                "expiresAt": "2099-01-01T00:00:00Z", "maxViews": 1, "passphraseRequired": false,
            })),
        )
        .await;
    assert!(refused.is_problem("org-policy"), "{:?}", refused.body);
    let refused = server
        .send_as(&member, Method::POST, "/v1/emergency-contacts", Some(body))
        .await;
    assert!(refused.is_problem("org-policy"), "{:?}", refused.body);

    // Client-side rules reach members, labelled by the API docs as such.
    let mine = server.get_as(&member, "/v1/orgs").await;
    let policies = &mine.body["organisation"]["policies"];
    assert_eq!(policies["disableExport"], true);
    assert_eq!(policies["maxAutoLockMinutes"], 15);
    assert_eq!(policies["minPasswordLength"], 14);

    // Ranges are checked.
    let bad = json!({
        "requireTwoStep": false, "requireSso": false, "ssoMaxAgeHours": 9000,
        "disableShareLinks": false, "disableEmergencyAccess": false, "disableExport": false,
    });
    let refused = server
        .send_as(&owner, Method::PUT, &policy_path, Some(bad))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleting_an_organisation_takes_its_vaults_but_no_personal_ones() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;
    let vault = org_vault(&server, &mut owner, &org).await;
    let personal_shared = server.shared_vault(&mut owner).await;

    let path = format!("/v1/orgs/{org}");
    let body = json!({ "confirmName": "Wrong" });
    let token = reauth(&server, &device(&owner), "organisation").await;
    let headers = [("x-reauth-token", token.as_str())];
    let refused = server
        .call(
            Method::DELETE,
            &path,
            Some(&owner.token),
            &headers,
            Some(body),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let body = json!({ "confirmName": "Acme" });
    let refused = server
        .send_as(&owner, Method::DELETE, &path, Some(body.clone()))
        .await;
    assert!(refused.is_problem("reauth-required"));
    let deleted = server
        .call(
            Method::DELETE,
            &path,
            Some(&owner.token),
            &headers,
            Some(body),
        )
        .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);

    let synced = server.sync_all(&owner).await;
    assert!(!has_vault(&synced, &vault));
    assert!(has_vault(&synced, &personal_shared));
    assert!(has_vault(&synced, &owner.personal_vault));
    let orgs = server.get_as(&member, "/v1/orgs").await;
    assert!(orgs.body.get("organisation").is_none());
}

#[tokio::test]
async fn an_account_deletion_leaves_the_organisation_standing() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let admin = server.person("admin@example.com").await;
    let member = server.person("member@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;
    join(&server, &owner, &org, &admin, "admin").await;
    let vault = org_vault(&server, &mut owner, &org).await;
    server.invite(&owner, &vault, &admin, Role::Manage).await;

    let leaving = device(&owner);
    let token = reauth_token(&server, &leaving).await;
    let deleted = delete_account(&server, &leaving, Some(&token), &owner.email).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);

    // The longest-serving admin takes over, and the vault outlives its only owner.
    let mine = server.get_as(&admin, "/v1/orgs").await;
    assert_eq!(mine.body["organisation"]["role"], "owner");
    assert_eq!(mine.body["organisation"]["memberCount"], 2);
    assert!(has_vault(&server.sync_all(&admin).await, &vault));
    assert_eq!(
        plan(&server, &admin, &org, &vault).await.unwrap()["rotate"],
        true
    );

    // The last member takes the organisation with them.
    let path = format!("/v1/orgs/{org}/members/{}", member.account_id);
    server.send_as(&admin, Method::DELETE, &path, None).await;
    let leaving = device(&admin);
    let token = reauth_token(&server, &leaving).await;
    let deleted = delete_account(&server, &leaving, Some(&token), &admin.email).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT, "{:?}", deleted.body);
    let orgs: i64 = sqlx::query_scalar("SELECT CAST(COUNT(*) AS BIGINT) FROM organisations")
        .fetch_one(&server.state.db)
        .await
        .unwrap();
    assert_eq!(orgs, 0);
}

#[tokio::test]
async fn admin_actions_are_logged_with_no_vault_contents() {
    let server = TestServer::new().await;
    let mut owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;
    let vault = org_vault(&server, &mut owner, &org).await;

    let path = format!("/v1/orgs/{org}/events");
    let log = server.get_as(&owner, &path).await;
    let events = log.body["events"].as_array().unwrap();
    let types: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    for expected in [
        "org-created",
        "member-invited",
        "member-joined",
        "vault-created",
    ] {
        assert!(types.contains(&expected), "{expected} in {types:?}");
    }
    assert_eq!(events[0]["subject"], vault.as_str(), "newest first");
    assert_eq!(events[0]["actor"], "owner@example.com");
    assert_eq!(
        server.get_as(&member, &path).await.status,
        StatusCode::FORBIDDEN
    );
}
