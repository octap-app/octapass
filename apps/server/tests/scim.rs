//! SCIM provisioning: the identity provider invites people, sorts them into groups and takes them
//! out again, with a token per organisation. It never gives anyone a key: a key holder still seals
//! every grant, and deprovisioning takes vaults away at once and marks them for rotation.

use crate::common;
use crate::orgs::{apply, create_org, join, link, org_vault};

use axum::http::{Method, StatusCode};
use common::people::Person;
use common::*;
use octapass_core::sharing::Role;
use octapass_server::config::RateLimits;
use serde_json::{Value, json};

async fn server() -> TestServer {
    TestServer::with_config(|config| config.rate_limits = RateLimits::unlimited()).await
}

async fn token(server: &TestServer, owner: &Person, org: &str) -> String {
    let path = format!("/v1/orgs/{org}/scim/tokens");
    let body = json!({ "name": "Entra ID" });
    let created = server.send_as(owner, Method::POST, &path, Some(body)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let secret = created.body["secret"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("opscim_"));
    secret
}

async fn scim(
    server: &TestServer,
    token: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Response {
    let path = format!("/v1/scim/v2{path}");
    let headers = [("content-type", "application/scim+json")];
    server
        .call(method, &path, Some(token), &headers, body)
        .await
}

async fn provision(server: &TestServer, token: &str, email: &str) -> String {
    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email.to_uppercase(),
        "externalId": format!("ext-{email}"),
        "name": { "givenName": "Ada", "familyName": "Lovelace" },
        "emails": [{ "value": email, "type": "work", "primary": true }],
        "active": true,
    });
    let created = scim(server, token, Method::POST, "/Users", Some(body)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.headers["content-type"], "application/scim+json");
    assert_eq!(created.body["displayName"], "Ada Lovelace");
    created.body["id"].as_str().unwrap().to_owned()
}

async fn members(server: &TestServer, admin: &Person, org: &str) -> Vec<String> {
    let listed = server
        .get_as(admin, &format!("/v1/orgs/{org}/members"))
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    listed.body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["email"].as_str().unwrap().to_owned())
        .collect()
}

async fn group_members(server: &TestServer, admin: &Person, org: &str, group: &str) -> Vec<String> {
    let listed = server
        .get_as(admin, &format!("/v1/orgs/{org}/groups"))
        .await;
    listed.body["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == group)
        .map(|entry| {
            entry["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| id.as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

async fn accept(server: &TestServer, person: &Person, org: &str) {
    let orgs = server.get_as(person, "/v1/orgs").await;
    let invitation = orgs.body["invitations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|invitation| invitation["orgId"] == org)
        .unwrap_or_else(|| panic!("no invitation: {:?}", orgs.body))
        .clone();
    assert_eq!(invitation["role"], "member");
    assert!(
        invitation.get("invitedBy").is_none(),
        "the provider isn't a person"
    );
    let path = format!(
        "/v1/orgs/{org}/invites/{}/accept",
        invitation["id"].as_str().unwrap()
    );
    let accepted = server.send_as(person, Method::POST, &path, None).await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
}

fn has_vault(synced: &Value, vault: &str) -> bool {
    synced["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .any(|record| record["id"] == vault)
}

#[tokio::test]
async fn tokens_are_per_organisation_owner_only_and_shown_once() {
    let server = server().await;
    let owner = server.person("owner@example.com").await;
    let admin = server.person("admin@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &admin, "admin").await;

    let path = format!("/v1/orgs/{org}/scim/tokens");
    let refused = server
        .send_as(&admin, Method::POST, &path, Some(json!({ "name": "x" })))
        .await;
    assert_eq!(
        refused.status,
        StatusCode::FORBIDDEN,
        "admins can't make provisioning tokens"
    );

    let secret = token(&server, &owner, &org).await;
    let listed = server.get_as(&owner, &format!("/v1/orgs/{org}/scim")).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    assert!(
        listed.body["baseUrl"]
            .as_str()
            .unwrap()
            .ends_with("/v1/scim/v2")
    );
    let tokens = listed.body["tokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["name"], "Entra ID");
    assert_eq!(tokens[0]["createdBy"], "owner@example.com");
    assert!(
        !listed.body.to_string().contains(&secret),
        "the secret is never listed"
    );

    // Without a token, or with a wrong one, SCIM answers with its own error format.
    for bad in [None, Some("opscim_wrong"), Some(owner.token.as_str())] {
        let response = server
            .call(Method::GET, "/v1/scim/v2/Users", bad, &[], None)
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.body["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:Error"
        );
        assert_eq!(response.body["status"], "401");
    }
    let config = scim(
        &server,
        &secret,
        Method::GET,
        "/ServiceProviderConfig",
        None,
    )
    .await;
    assert_eq!(config.body["patch"]["supported"], true);

    // A token reaches only its own organisation.
    let other_owner = server.person("other@example.com").await;
    let other = create_org(&server, &other_owner, "Other").await;
    let other_secret = token(&server, &other_owner, &other).await;
    let user = provision(&server, &secret, "someone@example.com").await;
    let theirs = scim(
        &server,
        &other_secret,
        Method::GET,
        &format!("/Users/{user}"),
        None,
    )
    .await;
    assert_eq!(theirs.status, StatusCode::NOT_FOUND);
    let listed = scim(&server, &other_secret, Method::GET, "/Users", None).await;
    assert_eq!(listed.body["totalResults"], 0);

    // Revoked, it stops working at once.
    let id = tokens[0]["id"].as_str().unwrap();
    let path = format!("/v1/orgs/{org}/scim/tokens/{id}");
    let revoked = server.send_as(&owner, Method::DELETE, &path, None).await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    let after = scim(&server, &secret, Method::GET, "/Users", None).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn provisioning_invites_and_a_member_joins_only_by_accepting() {
    let server = server().await;
    let owner = server.person("owner@example.com").await;
    let ada = server.person("ada@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    let secret = token(&server, &owner, &org).await;

    let id = provision(&server, &secret, "ada@example.com").await;
    assert_eq!(
        members(&server, &owner, &org).await,
        ["owner@example.com"],
        "not a member yet"
    );
    let invites = server
        .get_as(&owner, &format!("/v1/orgs/{org}/members"))
        .await;
    assert_eq!(invites.body["invites"][0]["email"], "ada@example.com");

    // Finding the user the way providers do, by userName, whatever its case.
    let found = scim(
        &server,
        &secret,
        Method::GET,
        "/Users?filter=userName%20eq%20%22ada%40example.com%22",
        None,
    )
    .await;
    assert_eq!(found.status, StatusCode::OK, "{:?}", found.body);
    assert_eq!(found.body["totalResults"], 1);
    assert_eq!(found.body["Resources"][0]["id"], id);
    let none = scim(
        &server,
        &secret,
        Method::GET,
        "/Users?filter=userName%20eq%20%22nobody%22",
        None,
    )
    .await;
    assert_eq!(none.body["totalResults"], 0);
    let bad = scim(
        &server,
        &secret,
        Method::GET,
        "/Users?filter=userName%20co%20%22a%22",
        None,
    )
    .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.body["scimType"], "invalidFilter");

    // The same userName twice is a conflict.
    let again =
        json!({ "userName": "ada@example.com", "emails": [{ "value": "ada@example.com" }] });
    let conflict = scim(&server, &secret, Method::POST, "/Users", Some(again)).await;
    assert_eq!(conflict.status, StatusCode::CONFLICT, "{:?}", conflict.body);
    assert_eq!(conflict.body["scimType"], "uniqueness");

    accept(&server, &ada, &org).await;
    assert_eq!(
        members(&server, &owner, &org).await,
        ["ada@example.com", "owner@example.com"]
    );
    let events = server
        .get_as(&owner, &format!("/v1/orgs/{org}/events"))
        .await;
    let types: Vec<&str> = events.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["type"].as_str().unwrap())
        .collect();
    assert!(types.contains(&"scim-user-provisioned"), "{types:?}");
    assert!(types.contains(&"scim-user-invited"), "{types:?}");
}

#[tokio::test]
async fn groups_follow_the_provider_and_deprovisioning_takes_vaults_away_at_once() {
    let server = server().await;
    let mut owner = server.person("owner@example.com").await;
    let ada = server.person("ada@example.com").await;
    let bob = server.person("bob@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &bob, "member").await;
    let secret = token(&server, &owner, &org).await;

    let ada_id = provision(&server, &secret, "ada@example.com").await;
    let bob_id = provision(&server, &secret, "bob@example.com").await;
    // Bob was already a member, so there's nothing to invite him to.
    let listed = server
        .get_as(&owner, &format!("/v1/orgs/{org}/members"))
        .await;
    assert_eq!(
        listed.body["invites"].as_array().unwrap().len(),
        1,
        "{:?}",
        listed.body
    );

    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Engineering",
        "members": [{ "value": ada_id }, { "value": bob_id }],
    });
    let created = scim(&server, &secret, Method::POST, "/Groups", Some(body)).await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    let group = created.body["id"].as_str().unwrap().to_owned();
    assert_eq!(created.body["members"].as_array().unwrap().len(), 2);
    // Bob is in the Octa Pass group now; Ada joins it when she accepts.
    assert_eq!(
        group_members(&server, &owner, &org, &group).await,
        std::slice::from_ref(&bob.account_id)
    );
    accept(&server, &ada, &org).await;
    let mut both = vec![ada.account_id.clone(), bob.account_id.clone()];
    both.sort();
    let mut now_in = group_members(&server, &owner, &org, &group).await;
    now_in.sort();
    assert_eq!(now_in, both);

    // The group reaches a vault only once a key holder seals it to each person.
    let vault = org_vault(&server, &mut owner, &org).await;
    link(&server, &owner, &org, &vault, &group, "write").await;
    assert!(
        !has_vault(&server.sync_all(&ada).await, &vault),
        "linking gives no key"
    );
    let applied = apply(
        &server,
        &owner,
        &org,
        &vault,
        &[(&ada, Role::Write), (&bob, Role::Write)],
    )
    .await;
    assert_eq!(applied.status, StatusCode::NO_CONTENT, "{:?}", applied.body);
    assert!(has_vault(&server.sync_all(&ada).await, &vault));

    // Taking Bob out of the group in the provider takes the vault away and marks it for rotation.
    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "remove", "path": format!("members[value eq \"{bob_id}\"]") }],
    });
    let patched = scim(
        &server,
        &secret,
        Method::PATCH,
        &format!("/Groups/{group}"),
        Some(patch),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
    assert_eq!(
        group_members(&server, &owner, &org, &group).await,
        std::slice::from_ref(&ada.account_id)
    );
    assert!(!has_vault(&server.sync_all(&bob).await, &vault));
    assert_eq!(
        members(&server, &owner, &org).await.len(),
        3,
        "still a member, just not in the group"
    );
    let vaults = server
        .get_as(&owner, &format!("/v1/orgs/{org}/vaults"))
        .await;
    assert_eq!(vaults.body["vaults"][0]["rotationPending"], true);

    // Deprovisioning Ada, as Entra does (a string boolean), removes her from the organisation.
    let patch = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "Replace", "path": "active", "value": "False" }],
    });
    let patched = scim(
        &server,
        &secret,
        Method::PATCH,
        &format!("/Users/{ada_id}"),
        Some(patch),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
    assert_eq!(patched.body["active"], false);
    assert!(!has_vault(&server.sync_all(&ada).await, &vault));
    assert!(
        !members(&server, &owner, &org)
            .await
            .contains(&"ada@example.com".to_owned())
    );
    let orgs = server.get_as(&ada, "/v1/orgs").await;
    assert!(orgs.body.get("organisation").is_none(), "{:?}", orgs.body);
    assert!(
        orgs.body["invitations"].as_array().unwrap().is_empty(),
        "no invite left behind"
    );

    // Active again, she's invited again, and nothing more.
    let patch = json!({ "Operations": [{ "op": "replace", "value": { "active": true } }] });
    scim(
        &server,
        &secret,
        Method::PATCH,
        &format!("/Users/{ada_id}"),
        Some(patch),
    )
    .await;
    let orgs = server.get_as(&ada, "/v1/orgs").await;
    assert_eq!(orgs.body["invitations"].as_array().unwrap().len(), 1);

    // Deleting the group takes nothing from people outside it; deleting a user is deprovisioning.
    let deleted = scim(
        &server,
        &secret,
        Method::DELETE,
        &format!("/Groups/{group}"),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let groups = server
        .get_as(&owner, &format!("/v1/orgs/{org}/groups"))
        .await;
    assert!(groups.body["groups"].as_array().unwrap().is_empty());
    let deleted = scim(
        &server,
        &secret,
        Method::DELETE,
        &format!("/Users/{bob_id}"),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    assert_eq!(members(&server, &owner, &org).await, ["owner@example.com"]);
    let gone = scim(
        &server,
        &secret,
        Method::GET,
        &format!("/Users/{bob_id}"),
        None,
    )
    .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_provider_cannot_remove_an_owner_or_touch_groups_made_by_hand() {
    let server = server().await;
    let owner = server.person("owner@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    let secret = token(&server, &owner, &org).await;
    let id = provision(&server, &secret, "owner@example.com").await;
    let patch = json!({ "Operations": [{ "op": "replace", "path": "active", "value": false }] });
    let patched = scim(
        &server,
        &secret,
        Method::PATCH,
        &format!("/Users/{id}"),
        Some(patch),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.body);
    assert_eq!(
        members(&server, &owner, &org).await,
        ["owner@example.com"],
        "owners leave by hand"
    );
    let events = server
        .get_as(&owner, &format!("/v1/orgs/{org}/events"))
        .await;
    assert_eq!(events.body["events"][0]["type"], "scim-owner-kept");
    assert!(events.body["events"][0].get("actor").is_none());

    // A group an admin made in Octa Pass isn't the provider's.
    let manual = new_id();
    let path = format!("/v1/orgs/{org}/groups");
    server
        .send_as(
            &owner,
            Method::POST,
            &path,
            Some(json!({ "id": manual, "name": "Finance" })),
        )
        .await;
    let listed = scim(&server, &secret, Method::GET, "/Groups", None).await;
    assert_eq!(listed.body["totalResults"], 0);
    let hidden = scim(
        &server,
        &secret,
        Method::GET,
        &format!("/Groups/{manual}"),
        None,
    )
    .await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    let clash = scim(
        &server,
        &secret,
        Method::POST,
        "/Groups",
        Some(json!({ "displayName": "Finance" })),
    )
    .await;
    assert_eq!(clash.status, StatusCode::CONFLICT, "{:?}", clash.body);
}
