//! Rotating the Secret Key, rotating vault keys on demand, emergency takeover and organiser
//! recovery, with real keys from octapass-core, so what the server ends up with really opens.

use crate::common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::people::{Person, now_ms};
use common::two_step::{enable as enable_two_step, reauth as reauth_device};
use common::*;
use octapass_core::account::{AccountBundle, NewAccount};
use octapass_core::credentials::NewCredentials;
use octapass_core::kdf::{AccountKeys, KdfParams};
use octapass_core::opaque::RegistrationClient;
use octapass_core::secret_key::SecretKey;
use octapass_core::session::Session;
use octapass_core::sharing::Role;
use octapass_core::sharing::emergency::EmergencyScope;
use octapass_core::sharing::vault::ItemKey;
use rand_core::OsRng;
use serde_json::{Value, json};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const EMAIL: &str = "alice@example.com";

// ---------- Helpers ----------

/// Signs up with real keys, so a Secret Key really goes into the OPAQUE secret.
async fn sign_up(server: &TestServer) -> NewAccount {
    let account = NewAccount::create(
        EMAIL,
        "the password",
        KdfParams::DEFAULT,
        now_ms(),
        &mut OsRng,
    )
    .unwrap();
    let (client, request) =
        RegistrationClient::start(&account.keys.auth_secret, &mut OsRng).unwrap();
    let started = server
        .post(
            "/v1/auth/register/start",
            json!({ "email": EMAIL, "registrationRequest": request }),
        )
        .await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    let upload = client
        .finish(
            &account.keys.auth_secret,
            started.body["registrationResponse"].as_str().unwrap(),
            &mut OsRng,
        )
        .unwrap();
    let finished = server
        .post(
            "/v1/auth/register/finish",
            json!({
                "email": EMAIL,
                "verificationCode": started.body["devVerificationCode"],
                "registrationUpload": upload,
                "account": account.bundle,
                "personalVault": account.personal_vault,
            }),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.body);
    account
}

async fn login(server: &TestServer, keys: &AccountKeys, device: &str) -> Response {
    server
        .login_with(EMAIL, keys.auth_secret.as_bytes(), device)
        .await
}

fn bundle_of(device: &Device) -> AccountBundle {
    serde_json::from_value(device.account.clone()).unwrap()
}

/// OPAQUE registration for new credentials through `path`, returning the upload.
async fn register_new(
    server: &TestServer,
    path: &str,
    token: &str,
    new: &NewCredentials,
) -> String {
    let (client, request) = RegistrationClient::start(&new.keys.auth_secret, &mut OsRng).unwrap();
    let response = server
        .call(
            Method::POST,
            path,
            Some(token),
            &[],
            Some(json!({ "registrationRequest": request })),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    client
        .finish(
            &new.keys.auth_secret,
            response.body["registrationResponse"].as_str().unwrap(),
            &mut OsRng,
        )
        .unwrap()
}

async fn log_types(server: &TestServer, token: &str) -> Vec<String> {
    let response = server.get("/v1/security-log", token).await;
    assert_eq!(response.status, StatusCode::OK);
    response.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["type"].as_str().unwrap().to_owned())
        .collect()
}

fn emails_to(server: &TestServer, to: &str) -> Vec<String> {
    server
        .state
        .dev_outbox()
        .into_iter()
        .filter(|(address, _)| address == to)
        .map(|(_, subject)| subject)
        .collect()
}

/// Every item key in `vault_id`, as a rotation needs them.
async fn item_keys(server: &TestServer, person: &Person, vault_id: &str) -> Vec<ItemKey> {
    server.sync_all(person).await["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["vaultId"] == vault_id)
        .map(|item| ItemKey {
            item_id: item["id"].as_str().unwrap().to_owned(),
            encrypted_item_key: item["encryptedItemKey"].as_str().unwrap().to_owned(),
        })
        .collect()
}

async fn vault_record(server: &TestServer, person: &Person, vault_id: &str) -> Value {
    server.sync_all(person).await["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vault| vault["id"] == vault_id)
        .unwrap()
        .clone()
}

/// A rotation of `person`'s personal vault, as a request body at its current revision.
async fn personal_rotation(server: &TestServer, person: &Person) -> Value {
    let vault_id = person.personal_vault.as_str();
    let items = item_keys(server, person, vault_id).await;
    let revision = vault_record(server, person, vault_id).await["revision"].clone();
    let rotation = person
        .session
        .rotate_personal_vault_key(vault_id, &items, &mut OsRng)
        .unwrap();
    json!({
        "revision": revision,
        "keyId": rotation.key_id,
        "grants": [],
        "items": rotation.items,
        "wrappedVaultKey": rotation.wrapped_vault_key,
    })
}

async fn rotate(server: &TestServer, person: &Person, vault_id: &str, body: Value) -> Response {
    let path = format!("/v1/vaults/{vault_id}/rotate");
    server
        .send_as(person, Method::POST, &path, Some(body))
        .await
}

async fn add_contact(
    server: &TestServer,
    grantor: &Person,
    contact: &Person,
    scope: EmergencyScope,
    level: &str,
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
        "accessLevel": level,
        "waitDays": 2,
    });
    server
        .send_as(grantor, Method::POST, "/v1/emergency-contacts", Some(body))
        .await
}

async fn act(server: &TestServer, person: &Person, id: &str, action: &str) -> Response {
    let path = format!("/v1/emergency-contacts/{id}/{action}");
    server.send_as(person, Method::POST, &path, None).await
}

/// Runs the contact's request and the waiting period.
async fn release(server: &TestServer, contact: &Person, id: &str) {
    assert_eq!(
        act(server, contact, id, "request").await.status,
        StatusCode::OK
    );
    server.state.clock.advance(3 * DAY);
}

/// What the contact prepares once the record is released: the grantor's session, opened from the
/// release, and new credentials under it.
struct Prepared {
    grantor_session: Session,
    new: NewCredentials,
    upload: String,
    signature: String,
}

async fn prepare_takeover(server: &TestServer, contact: &Person, id: &str) -> Prepared {
    let released = server
        .get_as(contact, &format!("/v1/emergency-contacts/{id}/release"))
        .await;
    assert_eq!(released.status, StatusCode::OK, "{:?}", released.body);
    let bundle: AccountBundle = serde_json::from_value(released.body["grantor"].clone()).unwrap();
    let sealed = released.body["sealedKey"].as_str().unwrap();
    let grantor_session = contact
        .session
        .open_emergency_account(bundle, sealed)
        .unwrap();
    let new = grantor_session
        .new_credentials(
            "the new password",
            None,
            true,
            KdfParams::DEFAULT,
            &mut OsRng,
        )
        .unwrap();
    let path = format!("/v1/emergency-contacts/{id}/takeover/registration");
    let upload = register_new(server, &path, &contact.token, &new).await;
    let signature = grantor_session
        .sign_takeover(id, &contact.account_id, &upload, &new.update)
        .unwrap();
    Prepared {
        grantor_session,
        new,
        upload,
        signature,
    }
}

async fn takeover_with(
    server: &TestServer,
    contact: &Person,
    id: &str,
    body: Value,
    reauth: Option<String>,
) -> Response {
    let headers: Vec<(&str, String)> = reauth
        .into_iter()
        .map(|token| ("x-reauth-token", token))
        .collect();
    let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    server
        .call(
            Method::POST,
            &format!("/v1/emergency-contacts/{id}/takeover"),
            Some(&contact.token),
            &headers,
            Some(body),
        )
        .await
}

async fn contact_reauth(server: &TestServer, contact: &Person) -> String {
    let response = server
        .reauth_for(&contact.token, PASSWORD, "emergency-takeover")
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    response.body["reauthToken"].as_str().unwrap().to_owned()
}

fn takeover_body(prepared: &Prepared) -> Value {
    json!({
        "registrationUpload": prepared.upload,
        "account": prepared.new.update,
        "signature": prepared.signature,
    })
}

async fn takeover(
    server: &TestServer,
    contact: &Person,
    id: &str,
    prepared: &Prepared,
) -> Response {
    let reauth = contact_reauth(server, contact).await;
    takeover_with(server, contact, id, takeover_body(prepared), Some(reauth)).await
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

async fn join_family(
    server: &TestServer,
    organiser: &Person,
    family_id: &str,
    vault_id: &str,
    member: &Person,
) {
    let body =
        json!({ "email": member.email, "grant": organiser.grant(vault_id, member, Role::Write) });
    let path = format!("/v1/families/{family_id}/invites");
    let invited = server
        .send_as(organiser, Method::POST, &path, Some(body))
        .await;
    assert_eq!(invited.status, StatusCode::ACCEPTED, "{:?}", invited.body);
    let path = format!("/v1/families/{family_id}/invites/accept");
    let accepted = server.send_as(member, Method::POST, &path, None).await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
}

async fn enable_recovery(
    server: &TestServer,
    member: &Person,
    organiser: &Person,
    family_id: &str,
) -> Response {
    let sealed = member
        .session
        .seal_for_emergency_contact(
            &organiser.account_id,
            &organiser.session.key_pairs().public_enc_key(),
            None,
            &EmergencyScope::Account,
            &mut OsRng,
        )
        .unwrap();
    let path = format!("/v1/families/{family_id}/organiser-recovery");
    let body = json!({ "sealedKey": sealed, "waitDays": 2 });
    server
        .send_as(member, Method::POST, &path, Some(body))
        .await
}

// ---------- Rotating the Secret Key ----------

#[tokio::test]
async fn rotating_the_secret_key_keeps_the_password_and_the_vaults() {
    let server = TestServer::new().await;
    let account = sign_up(&server).await;
    let laptop = Device::from_login(&login(&server, &account.keys, "Laptop").await.body);
    let phone = Device::from_login(&login(&server, &account.keys, "Phone").await.body);
    let session = Session::unlock(bundle_of(&laptop), &account.keys.auk).unwrap();

    let new = session
        .new_credentials("the password", None, false, KdfParams::DEFAULT, &mut OsRng)
        .unwrap();
    assert_ne!(new.secret_key, account.secret_key);
    let upload = register_new(
        &server,
        "/v1/account/password/registration",
        &laptop.access_token,
        &new,
    )
    .await;
    let body = json!({ "registrationUpload": upload, "account": new.update });
    let put = |reauth: Option<String>| {
        let headers: Vec<(&str, String)> = reauth
            .into_iter()
            .map(|token| ("x-reauth-token", token))
            .collect();
        let (server, token, body) = (&server, laptop.access_token.clone(), body.clone());
        async move {
            let headers: Vec<(&str, &str)> =
                headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
            server
                .call(
                    Method::PUT,
                    "/v1/account/secret-key",
                    Some(&token),
                    &headers,
                    Some(body),
                )
                .await
        }
    };

    // A reauth is required, and only one for this purpose will do.
    assert!(put(None).await.is_problem("reauth-required"));
    let auth_secret = account.keys.auth_secret.as_bytes();
    let wrong_purpose = server
        .reauth_for(&laptop.access_token, auth_secret, "change-password")
        .await;
    let wrong_purpose = wrong_purpose.body["reauthToken"].as_str().unwrap();
    assert!(
        put(Some(wrong_purpose.to_owned()))
            .await
            .is_problem("reauth-required")
    );
    let right = server
        .reauth_for(&laptop.access_token, auth_secret, "rotate-secret-key")
        .await;
    assert_eq!(right.status, StatusCode::OK, "{:?}", right.body);
    let right = right.body["reauthToken"].as_str().unwrap().to_owned();
    let rotated = put(Some(right.clone())).await;
    assert_eq!(rotated.status, StatusCode::NO_CONTENT, "{:?}", rotated.body);
    assert!(
        put(Some(right)).await.is_problem("reauth-required"),
        "a reauth token works once"
    );

    // This device stays; the other one is signed out.
    assert_eq!(
        server.get("/v1/sync", &laptop.access_token).await.status,
        StatusCode::OK
    );
    let refreshed = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": phone.refresh_token }),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::UNAUTHORIZED);

    // The old Secret Key no longer signs in, with the same password.
    assert_eq!(
        login(&server, &account.keys, "Tablet").await.status,
        StatusCode::UNAUTHORIZED
    );
    let fresh = Device::from_login(&login(&server, &new.keys, "Tablet").await.body);
    let bundle = bundle_of(&fresh);
    assert_eq!(bundle.account_salt, new.update.account_salt);
    let reopened = Session::unlock(bundle.clone(), &new.keys.auk).unwrap();
    assert_eq!(
        reopened.key_pairs().public_sign_key(),
        session.key_pairs().public_sign_key()
    );
    // The recovery code stays.
    assert!(Session::recover(bundle, &account.recovery_code).is_ok());
    assert_eq!(
        emails_to(&server, EMAIL).last().map(String::as_str),
        Some("New sign-in to your Octa Pass account")
    );
    assert!(
        emails_to(&server, EMAIL)
            .iter()
            .any(|subject| subject == "Your Octa Pass Secret Key was changed")
    );
    assert_eq!(
        log_types(&server, &fresh.access_token)
            .await
            .first()
            .map(String::as_str),
        Some("secret-key-rotated")
    );
}

#[tokio::test]
async fn rotating_the_secret_key_can_replace_the_recovery_code() {
    let server = TestServer::new().await;
    let account = sign_up(&server).await;
    let laptop = Device::from_login(&login(&server, &account.keys, "Laptop").await.body);
    let session = Session::unlock(bundle_of(&laptop), &account.keys.auk).unwrap();
    let new = session
        .new_credentials("the password", None, true, KdfParams::DEFAULT, &mut OsRng)
        .unwrap();
    let upload = register_new(
        &server,
        "/v1/account/password/registration",
        &laptop.access_token,
        &new,
    )
    .await;
    let reauth = server
        .reauth_for(
            &laptop.access_token,
            account.keys.auth_secret.as_bytes(),
            "rotate-secret-key",
        )
        .await;
    let reauth = reauth.body["reauthToken"].as_str().unwrap().to_owned();
    let rotated = server
        .call(
            Method::PUT,
            "/v1/account/secret-key",
            Some(&laptop.access_token),
            &[("x-reauth-token", reauth.as_str())],
            Some(json!({ "registrationUpload": upload, "account": new.update })),
        )
        .await;
    assert_eq!(rotated.status, StatusCode::NO_CONTENT, "{:?}", rotated.body);
    let fresh = Device::from_login(&login(&server, &new.keys, "Phone").await.body);
    let bundle = bundle_of(&fresh);
    assert!(Session::recover(bundle.clone(), &account.recovery_code).is_err());
    assert!(Session::recover(bundle, new.recovery_code.as_ref().unwrap()).is_ok());
}

// ---------- Rotating vault keys on demand ----------

#[tokio::test]
async fn a_personal_vault_rotates_on_demand() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let vault_id = alice.personal_vault.clone();
    assert_eq!(
        server.put_new_item(&alice, &vault_id, "Bank").await.status,
        StatusCode::OK
    );
    let before = vault_record(&server, &alice, &vault_id).await;
    assert!(before.get("keyId").is_none_or(Value::is_null));

    let body = personal_rotation(&server, &alice).await;
    let rotated = rotate(&server, &alice, &vault_id, body.clone()).await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);

    let after = vault_record(&server, &alice, &vault_id).await;
    assert_eq!(after["keyId"], body["keyId"]);
    assert_eq!(after["wrappedVaultKey"], body["wrappedVaultKey"]);
    assert_eq!(after["revision"], rotated.body["revision"]);

    // A device still on the old key is refused, as in a shared vault.
    let stale = server.put_new_item(&alice, &vault_id, "Old key").await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert!(stale.is_problem("vault-key-changed"));

    // The rotated record opens with the wrapped key the server now gives.
    alice
        .session
        .open_vault(&vault_id, after["wrappedVaultKey"].as_str().unwrap())
        .unwrap();
    let synced = server.sync_all(&alice).await;
    let item = synced["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["vaultId"] == vault_id.as_str())
        .unwrap();
    assert_eq!(alice.title(item), "Bank");
    assert_eq!(
        server
            .put_new_item(&alice, &vault_id, "New key")
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        log_types(&server, &alice.token)
            .await
            .first()
            .map(String::as_str),
        Some("vault-key-rotated")
    );

    // It rotates again from there, and an old revision is refused.
    let body = personal_rotation(&server, &alice).await;
    let mut stale_body = body.clone();
    stale_body["revision"] = json!(1);
    assert!(
        rotate(&server, &alice, &vault_id, stale_body)
            .await
            .is_problem("vault-changed")
    );
    assert_eq!(
        rotate(&server, &alice, &vault_id, body).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_personal_rotation_is_checked() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let vault_id = alice.personal_vault.clone();
    let shared = server.shared_vault(&mut alice).await;
    assert_eq!(
        server.put_new_item(&alice, &vault_id, "Bank").await.status,
        StatusCode::OK
    );
    let good = personal_rotation(&server, &alice).await;

    // Every item has to come along, trash included.
    let mut body = good.clone();
    body["items"] = json!([]);
    let refused = rotate(&server, &alice, &vault_id, body).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );

    // A personal vault needs its wrapped key, and takes no grants.
    let mut body = good.clone();
    body.as_object_mut().unwrap().remove("wrappedVaultKey");
    let refused = rotate(&server, &alice, &vault_id, body).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );
    let mut body = good.clone();
    body["grants"] = json!([alice.grant(&vault_id, &alice, Role::Owner)]);
    let refused = rotate(&server, &alice, &vault_id, body).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );

    // A shared vault can't take a wrapped key.
    let rotation = alice
        .session
        .rotate_vault_key(
            &shared,
            &[alice.recipient(Role::Owner)],
            &[],
            now_ms(),
            &mut OsRng,
        )
        .unwrap();
    let revision = vault_record(&server, &alice, &shared).await["revision"].clone();
    let body = json!({
        "revision": revision,
        "keyId": rotation.key_id,
        "grants": rotation.grants,
        "items": [],
        "wrappedVaultKey": envelope(48),
    });
    let refused = rotate(&server, &alice, &shared, body).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );

    // Nobody else can rotate it.
    let bob = server.person("bob@example.com").await;
    assert_eq!(
        rotate(&server, &bob, &vault_id, good.clone()).await.status,
        StatusCode::NOT_FOUND
    );
    // And nothing was changed by any of that.
    assert_eq!(
        rotate(&server, &alice, &vault_id, good).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_shared_vault_rotates_on_demand_without_a_member_leaving() {
    let server = TestServer::new().await;
    let mut alice = server.person("alice@example.com").await;
    let mut bob = server.person("bob@example.com").await;
    let vault_id = server.shared_vault(&mut alice).await;
    assert_eq!(
        server
            .invite(&alice, &vault_id, &bob, Role::Write)
            .await
            .status,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        server.put_new_item(&alice, &vault_id, "Wi-Fi").await.status,
        StatusCode::OK
    );
    let items = item_keys(&server, &alice, &vault_id).await;
    let revision = vault_record(&server, &alice, &vault_id).await["revision"].clone();
    let stays = [alice.recipient(Role::Owner), bob.recipient(Role::Write)];
    let rotation = alice
        .session
        .rotate_vault_key(&vault_id, &stays, &items, now_ms(), &mut OsRng)
        .unwrap();
    let body = json!({
        "revision": revision,
        "keyId": rotation.key_id,
        "grants": rotation.grants,
        "items": rotation.items,
    });
    let rotated = rotate(&server, &alice, &vault_id, body).await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.body);
    assert_eq!(
        log_types(&server, &alice.token)
            .await
            .first()
            .map(String::as_str),
        Some("vault-key-rotated")
    );

    let record = vault_record(&server, &bob, &vault_id).await;
    let (grant, granter) = common::people::grant_from_record(&record, &bob.account_id);
    bob.session.open_shared_vault(&grant, &granter).unwrap();
    let synced = server.sync_all(&bob).await;
    let item = synced["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["vaultId"] == vault_id.as_str())
        .unwrap();
    assert_eq!(bob.title(item), "Wi-Fi");
}

#[tokio::test]
async fn a_rotation_marks_a_vault_scoped_contact_until_the_grantor_renews() {
    let server = TestServer::new().await;
    let mut grace = server.person("grace@example.com").await;
    let mut carl = server.person("carl@example.com").await;
    let vault_id = grace.personal_vault.clone();
    let added = add_contact(
        &server,
        &grace,
        &carl,
        EmergencyScope::Vault {
            vault_id: vault_id.clone(),
        },
        "view",
    )
    .await;
    assert_eq!(added.status, StatusCode::CREATED, "{:?}", added.body);
    assert!(added.body.get("keyStale").is_none());
    let id = added.body["id"].as_str().unwrap().to_owned();
    assert_eq!(
        server
            .put_new_item(&grace, &vault_id, "Pension")
            .await
            .status,
        StatusCode::OK
    );

    let body = personal_rotation(&server, &grace).await;
    let old_key_id = grace.session.vault_key_id(&vault_id).unwrap();
    assert_eq!(
        rotate(&server, &grace, &vault_id, body.clone())
            .await
            .status,
        StatusCode::OK
    );
    let listed = server.get_as(&grace, "/v1/emergency-contacts").await;
    assert_eq!(listed.body["granted"][0]["keyStale"], true);

    grace
        .session
        .open_vault(&vault_id, body["wrappedVaultKey"].as_str().unwrap())
        .unwrap();
    let scope = EmergencyScope::Vault {
        vault_id: vault_id.clone(),
    };
    let sealed = grace
        .session
        .seal_for_emergency_contact(
            &carl.account_id,
            &carl.session.key_pairs().public_enc_key(),
            None,
            &scope,
            &mut OsRng,
        )
        .unwrap();
    let path = format!("/v1/emergency-contacts/{id}/key");

    // A key that was rotated away is refused, the contact can't renew, and neither can anyone else.
    let refused = server
        .send_as(
            &grace,
            Method::PUT,
            &path,
            Some(json!({ "sealedKey": sealed, "keyId": old_key_id })),
        )
        .await;
    assert!(
        refused.is_problem("vault-key-changed"),
        "{:?}",
        refused.body
    );
    let good = json!({ "sealedKey": sealed, "keyId": body["keyId"] });
    assert_eq!(
        server
            .send_as(&carl, Method::PUT, &path, Some(good.clone()))
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    let renewed = server.send_as(&grace, Method::PUT, &path, Some(good)).await;
    assert_eq!(renewed.status, StatusCode::OK, "{:?}", renewed.body);
    assert!(renewed.body.get("keyStale").is_none());

    // The renewed key opens the rotated item.
    assert_eq!(
        act(&server, &carl, &id, "request").await.status,
        StatusCode::OK
    );
    assert_eq!(
        act(&server, &grace, &id, "approve").await.status,
        StatusCode::OK
    );
    let released = server
        .get_as(&carl, &format!("/v1/emergency-contacts/{id}/release"))
        .await;
    carl.session
        .open_emergency_vault(
            &grace.account_id,
            &vault_id,
            released.body["sealedKey"].as_str().unwrap(),
        )
        .unwrap();
    let synced = server
        .get_as(&carl, &format!("/v1/emergency-contacts/{id}/sync"))
        .await;
    assert_eq!(carl.title(&synced.body["items"][0]), "Pension");
}

#[tokio::test]
async fn an_account_scope_doesnt_renew() {
    let server = TestServer::new().await;
    let grace = server.person("grace@example.com").await;
    let carl = server.person("carl@example.com").await;
    let added = add_contact(&server, &grace, &carl, EmergencyScope::Account, "view").await;
    let id = added.body["id"].as_str().unwrap();
    let body = personal_rotation(&server, &grace).await;
    assert_eq!(
        rotate(&server, &grace, &grace.personal_vault, body.clone())
            .await
            .status,
        StatusCode::OK
    );
    let listed = server.get_as(&grace, "/v1/emergency-contacts").await;
    assert!(listed.body["granted"][0].get("keyStale").is_none());
    let renewed = server
        .send_as(
            &grace,
            Method::PUT,
            &format!("/v1/emergency-contacts/{id}/key"),
            Some(json!({ "sealedKey": added.body["id"], "keyId": body["keyId"] })),
        )
        .await;
    assert_eq!(
        renewed.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        renewed.body
    );
}

// ---------- Emergency takeover ----------

#[tokio::test]
async fn a_released_contact_takes_over_the_account() {
    let server = TestServer::new().await;
    let mut grace = server.person("grace@example.com").await;
    let carl = server.person("carl@example.com").await;
    let vault_id = grace.personal_vault.clone();
    assert_eq!(
        server
            .put_new_item(&grace, &vault_id, "Pension")
            .await
            .status,
        StatusCode::OK
    );
    // A second contact, whose sealed key has to survive the takeover.
    let dana = server.person("dana@example.com").await;
    let other = add_contact(&server, &grace, &dana, EmergencyScope::Account, "view").await;
    let other = other.body["id"].as_str().unwrap().to_owned();

    let device = server.login("grace@example.com", "Phone").await;
    let (_, _) = enable_two_step(&server, &device).await;

    let added = add_contact(&server, &grace, &carl, EmergencyScope::Account, "takeover").await;
    assert_eq!(added.status, StatusCode::CREATED, "{:?}", added.body);
    let id = added.body["id"].as_str().unwrap().to_owned();
    release(&server, &carl, &id).await;

    let prepared = prepare_takeover(&server, &carl, &id).await;
    let done = takeover(&server, &carl, &id, &prepared).await;
    assert_eq!(done.status, StatusCode::NO_CONTENT, "{:?}", done.body);

    // Every device of the grantor is signed out.
    assert_eq!(
        server.get("/v1/sync", &grace.token).await.status,
        StatusCode::UNAUTHORIZED
    );
    let refreshed = server
        .post(
            "/v1/auth/refresh",
            json!({ "refreshToken": device.refresh_token }),
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::UNAUTHORIZED);

    // The record is gone, and with it the contact's access through it.
    assert_eq!(
        server
            .get_as(&carl, &format!("/v1/emergency-contacts/{id}/sync"))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    // The old sign-in stops working, and the new one works with no second step.
    assert_eq!(
        server
            .login_with("grace@example.com", PASSWORD, "Old")
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let signed_in = server
        .login_with(
            "grace@example.com",
            prepared.new.keys.auth_secret.as_bytes(),
            "New",
        )
        .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{:?}", signed_in.body);
    let fresh = Device::from_login(&signed_in.body);
    let bundle = bundle_of(&fresh);
    let mut session = Session::unlock(bundle.clone(), &prepared.new.keys.auk).unwrap();
    assert_eq!(
        session.key_pairs().public_sign_key(),
        grace.session.key_pairs().public_sign_key()
    );
    assert!(Session::recover(bundle, prepared.new.recovery_code.as_ref().unwrap()).is_ok());

    // The items open under the same keys.
    grace.token = fresh.access_token.clone();
    let record = vault_record(&server, &grace, &vault_id).await;
    session
        .open_vault(&vault_id, record["wrappedVaultKey"].as_str().unwrap())
        .unwrap();
    grace.session = session;
    let synced = server.sync_all(&grace).await;
    assert_eq!(grace.title(&synced["items"][0]), "Pension");

    let log = log_types(&server, &fresh.access_token).await;
    assert!(log.contains(&"emergency-takeover".to_owned()), "{log:?}");
    assert!(log.contains(&"two-step-disabled".to_owned()), "{log:?}");
    assert!(
        emails_to(&server, "grace@example.com")
            .iter()
            .any(|subject| subject == "carl@example.com took over your Octa Pass account")
    );

    // The other contact's sealed key still opens the account.
    assert_eq!(
        act(&server, &dana, &other, "request").await.status,
        StatusCode::OK
    );
    assert_eq!(
        server
            .send_as(
                &grace,
                Method::POST,
                &format!("/v1/emergency-contacts/{other}/approve"),
                None
            )
            .await
            .status,
        StatusCode::OK
    );
    let released = server
        .get_as(&dana, &format!("/v1/emergency-contacts/{other}/release"))
        .await;
    let current: AccountBundle = serde_json::from_value(released.body["grantor"].clone()).unwrap();
    assert!(
        dana.session
            .open_emergency_account(current, released.body["sealedKey"].as_str().unwrap())
            .is_ok()
    );
}

#[tokio::test]
async fn a_takeover_is_refused_unless_it_was_released_for_this_contact() {
    let server = TestServer::new().await;
    let grace = server.person("grace@example.com").await;
    let carl = server.person("carl@example.com").await;

    // A vault's key can't open an account.
    let refused = add_contact(
        &server,
        &grace,
        &carl,
        EmergencyScope::Vault {
            vault_id: grace.personal_vault.clone(),
        },
        "takeover",
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );

    // A view contact can't, even released.
    let view = add_contact(&server, &grace, &carl, EmergencyScope::Account, "view").await;
    let id = view.body["id"].as_str().unwrap().to_owned();
    let registration = format!("/v1/emergency-contacts/{id}/takeover/registration");
    let attempt = json!({ "registrationRequest": b64([0u8; 32]) });
    release(&server, &carl, &id).await;
    let response = server
        .send_as(&carl, Method::POST, &registration, Some(attempt.clone()))
        .await;
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        response.body
    );
    assert_eq!(
        server
            .send_as(
                &grace,
                Method::DELETE,
                &format!("/v1/emergency-contacts/{id}"),
                None
            )
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    // Before the release nobody can, nor can a stranger or the grantor afterwards.
    let added = add_contact(&server, &grace, &carl, EmergencyScope::Account, "takeover").await;
    let id = added.body["id"].as_str().unwrap().to_owned();
    let registration = format!("/v1/emergency-contacts/{id}/takeover/registration");
    let response = server
        .send_as(&carl, Method::POST, &registration, Some(attempt.clone()))
        .await;
    assert_eq!(
        response.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        response.body
    );
    release(&server, &carl, &id).await;
    let stranger = server.person("eve@example.com").await;
    let response = server
        .send_as(
            &stranger,
            Method::POST,
            &registration,
            Some(attempt.clone()),
        )
        .await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    let response = server
        .send_as(&grace, Method::POST, &registration, Some(attempt))
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);

    let prepared = prepare_takeover(&server, &carl, &id).await;
    let body = takeover_body(&prepared);

    // No reauth, a reauth for something else, and a reauth by the wrong account all fail.
    assert!(
        takeover_with(&server, &carl, &id, body.clone(), None)
            .await
            .is_problem("reauth-required")
    );
    let wrong = server
        .reauth_for(&carl.token, PASSWORD, "delete-account")
        .await
        .body["reauthToken"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        takeover_with(&server, &carl, &id, body.clone(), Some(wrong))
            .await
            .is_problem("reauth-required")
    );

    // A signature by anyone but the grantor fails, and leaves the record usable.
    let mut forged = body.clone();
    forged["signature"] = json!(
        carl.session
            .sign_takeover(
                &id,
                &carl.account_id,
                &prepared.upload,
                &prepared.new.update
            )
            .unwrap()
    );
    let reauth = contact_reauth(&server, &carl).await;
    let refused = takeover_with(&server, &carl, &id, forged, Some(reauth)).await;
    assert!(refused.is_problem("forbidden"), "{:?}", refused.body);

    // A tampered update fails too.
    let mut tampered = body.clone();
    tampered["account"]["wrappedAsk"] = json!(envelope(48));
    let reauth = contact_reauth(&server, &carl).await;
    let refused = takeover_with(&server, &carl, &id, tampered, Some(reauth)).await;
    assert!(refused.is_problem("forbidden"), "{:?}", refused.body);

    // A takeover has to replace the recovery code.
    let mut keeps_code = body.clone();
    keeps_code["account"]
        .as_object_mut()
        .unwrap()
        .remove("recoveryWrappedAsk");
    let reauth = contact_reauth(&server, &carl).await;
    let refused = takeover_with(&server, &carl, &id, keeps_code, Some(reauth)).await;
    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "{:?}",
        refused.body
    );

    // Nothing changed: the grantor still signs in, and the right request still works.
    assert_eq!(
        server.get("/v1/sync", &grace.token).await.status,
        StatusCode::OK
    );
    let done = takeover(&server, &carl, &id, &prepared).await;
    assert_eq!(done.status, StatusCode::NO_CONTENT, "{:?}", done.body);

    // It can't be used twice.
    let again = takeover(&server, &carl, &id, &prepared).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "{:?}", again.body);
}

#[tokio::test]
async fn a_denial_beats_a_takeover() {
    let server = TestServer::new().await;
    let grace = server.person("grace@example.com").await;
    let carl = server.person("carl@example.com").await;
    let added = add_contact(&server, &grace, &carl, EmergencyScope::Account, "takeover").await;
    let id = added.body["id"].as_str().unwrap().to_owned();
    release(&server, &carl, &id).await;
    let prepared = prepare_takeover(&server, &carl, &id).await;

    assert_eq!(
        act(&server, &grace, &id, "deny").await.status,
        StatusCode::OK
    );
    let refused = takeover(&server, &carl, &id, &prepared).await;
    assert!(refused.is_problem("forbidden"), "{:?}", refused.body);
    assert_eq!(
        server.get("/v1/sync", &grace.token).await.status,
        StatusCode::OK
    );
    // The bundle wasn't replaced.
    let account = server.get("/v1/account", &grace.token).await;
    assert_eq!(
        account.body["accountSalt"].as_str(),
        Some(prepared.grantor_session.bundle().account_salt.as_str())
    );
}

#[tokio::test]
async fn a_credentials_change_invalidates_a_prepared_takeover() {
    let server = TestServer::new().await;
    let grace = server.person("grace@example.com").await;
    let carl = server.person("carl@example.com").await;
    let added = add_contact(&server, &grace, &carl, EmergencyScope::Account, "takeover").await;
    let id = added.body["id"].as_str().unwrap().to_owned();
    release(&server, &carl, &id).await;
    let prepared = prepare_takeover(&server, &carl, &id).await;

    // The grantor changes their password after the contact prepared.
    let changed = grace
        .session
        .new_credentials(
            "changed",
            Some(SecretKey::generate(&mut OsRng)),
            false,
            KdfParams::DEFAULT,
            &mut OsRng,
        )
        .unwrap();
    let upload = register_new(
        &server,
        "/v1/account/password/registration",
        &grace.token,
        &changed,
    )
    .await;
    let reauth = reauth_token_for(&server, &grace, "change-password").await;
    let put = server
        .call(
            Method::PUT,
            "/v1/account/password",
            Some(&grace.token),
            &[("x-reauth-token", reauth.as_str())],
            Some(json!({ "registrationUpload": upload, "account": changed.update })),
        )
        .await;
    assert_eq!(put.status, StatusCode::NO_CONTENT, "{:?}", put.body);

    let refused = takeover(&server, &carl, &id, &prepared).await;
    assert!(refused.is_problem("forbidden"), "{:?}", refused.body);
    // Reading the release again works: the ASK didn't change.
    let again = prepare_takeover(&server, &carl, &id).await;
    let done = takeover(&server, &carl, &id, &again).await;
    assert_eq!(done.status, StatusCode::NO_CONTENT, "{:?}", done.body);
}

async fn reauth_token_for(server: &TestServer, person: &Person, purpose: &str) -> String {
    let response = server.reauth_for(&person.token, PASSWORD, purpose).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
    response.body["reauthToken"].as_str().unwrap().to_owned()
}

// ---------- Organiser recovery ----------

#[tokio::test]
async fn organiser_recovery_is_opt_in_and_allows_only_the_reset() {
    let server = TestServer::new().await;
    let mut olive = server.person("olive@example.com").await;
    let sam = server.person("sam@example.com").await;
    let (family_id, vault_id) = create_family(&server, &mut olive).await;
    join_family(&server, &olive, &family_id, &vault_id, &sam).await;
    assert_eq!(
        server
            .put_new_item(&sam, &sam.personal_vault, "Diary")
            .await
            .status,
        StatusCode::OK
    );

    // The organiser has nothing until the member opts in, and can't opt in for them.
    let listed = server.get_as(&olive, "/v1/emergency-contacts").await;
    assert_eq!(listed.body["received"].as_array().unwrap().len(), 0);
    let own = enable_recovery(&server, &olive, &sam, &family_id).await;
    assert_eq!(own.status, StatusCode::BAD_REQUEST, "{:?}", own.body);

    let enabled = enable_recovery(&server, &sam, &olive, &family_id).await;
    assert_eq!(enabled.status, StatusCode::CREATED, "{:?}", enabled.body);
    assert_eq!(enabled.body["organiserRecovery"], true);
    assert_eq!(enabled.body["accessLevel"], "takeover");
    assert_eq!(enabled.body["scope"]["type"], "account");
    assert_eq!(enabled.body["contactId"], olive.account_id.as_str());
    let id = enabled.body["id"].as_str().unwrap().to_owned();
    assert_eq!(
        log_types(&server, &sam.token)
            .await
            .first()
            .map(String::as_str),
        Some("organiser-recovery-enabled")
    );
    assert!(
        enable_recovery(&server, &sam, &olive, &family_id)
            .await
            .is_problem("already-exists")
    );

    // The waiting period and the member's denial apply.
    release(&server, &olive, &id).await;
    assert_eq!(
        server
            .get_as(&olive, &format!("/v1/emergency-contacts/{id}/release"))
            .await
            .status,
        StatusCode::OK
    );

    // The organiser can't read the member's vaults, or their files.
    assert_eq!(
        server
            .get_as(&olive, &format!("/v1/emergency-contacts/{id}/sync"))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let file = format!(
        "/v1/emergency-contacts/{id}/vaults/{}/items/{}/attachments/{}",
        sam.personal_vault,
        new_id(),
        new_id()
    );
    assert_eq!(
        server.get_as(&olive, &file).await.status,
        StatusCode::FORBIDDEN
    );

    // The reset works, loudly.
    let prepared = prepare_takeover(&server, &olive, &id).await;
    let done = takeover(&server, &olive, &id, &prepared).await;
    assert_eq!(done.status, StatusCode::NO_CONTENT, "{:?}", done.body);
    assert_eq!(
        server.get("/v1/sync", &sam.token).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert!(
        emails_to(&server, "sam@example.com")
            .iter()
            .any(|subject| subject == "olive@example.com took over your Octa Pass account")
    );
}

#[tokio::test]
async fn organiser_recovery_ends_with_the_membership() {
    let server = TestServer::new().await;
    let mut olive = server.person("olive@example.com").await;
    let sam = server.person("sam@example.com").await;
    let tess = server.person("tess@example.com").await;
    let (family_id, vault_id) = create_family(&server, &mut olive).await;
    join_family(&server, &olive, &family_id, &vault_id, &sam).await;
    join_family(&server, &olive, &family_id, &vault_id, &tess).await;
    for member in [&sam, &tess] {
        let enabled = enable_recovery(&server, member, &olive, &family_id).await;
        assert_eq!(enabled.status, StatusCode::CREATED, "{:?}", enabled.body);
    }

    // Leaving removes it, from the member's side or the organiser's.
    let leave = format!("/v1/families/{family_id}/members/{}", sam.account_id);
    assert_eq!(
        server
            .send_as(&sam, Method::DELETE, &leave, None)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let listed = server.get_as(&olive, "/v1/emergency-contacts").await;
    assert_eq!(listed.body["received"].as_array().unwrap().len(), 1);
    assert_eq!(
        log_types(&server, &sam.token)
            .await
            .first()
            .map(String::as_str),
        Some("organiser-recovery-disabled")
    );

    // Deleting the family removes the rest.
    let path = format!("/v1/families/{family_id}");
    assert_eq!(
        server
            .send_as(&olive, Method::DELETE, &path, None)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    let listed = server.get_as(&olive, "/v1/emergency-contacts").await;
    assert_eq!(listed.body["received"].as_array().unwrap().len(), 0);
    assert_eq!(
        log_types(&server, &tess.token)
            .await
            .first()
            .map(String::as_str),
        Some("organiser-recovery-disabled")
    );
}

#[tokio::test]
async fn organiser_recovery_can_be_turned_off_and_doesnt_reach_other_families() {
    let server = TestServer::new().await;
    let mut olive = server.person("olive@example.com").await;
    let sam = server.person("sam@example.com").await;
    let outsider = server.person("uma@example.com").await;
    let (family_id, vault_id) = create_family(&server, &mut olive).await;
    join_family(&server, &olive, &family_id, &vault_id, &sam).await;

    // Someone outside the family can't name it.
    let refused = enable_recovery(&server, &outsider, &olive, &family_id).await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND, "{:?}", refused.body);

    // The organiser as an existing contact is one record per pair: remove that first.
    let added = add_contact(&server, &sam, &olive, EmergencyScope::Account, "view").await;
    assert_eq!(added.status, StatusCode::CREATED);
    assert!(
        enable_recovery(&server, &sam, &olive, &family_id)
            .await
            .is_problem("already-exists")
    );
    let contact = added.body["id"].as_str().unwrap();
    assert_eq!(
        server
            .send_as(
                &sam,
                Method::DELETE,
                &format!("/v1/emergency-contacts/{contact}"),
                None
            )
            .await
            .status,
        StatusCode::NO_CONTENT
    );

    let enabled = enable_recovery(&server, &sam, &olive, &family_id).await;
    assert_eq!(enabled.status, StatusCode::CREATED, "{:?}", enabled.body);
    let id = enabled.body["id"].as_str().unwrap();
    assert_eq!(
        server
            .send_as(
                &sam,
                Method::DELETE,
                &format!("/v1/emergency-contacts/{id}"),
                None
            )
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        log_types(&server, &sam.token)
            .await
            .first()
            .map(String::as_str),
        Some("organiser-recovery-disabled")
    );
}

#[tokio::test]
async fn two_step_on_the_contact_stays_on() {
    // The takeover turns off the grantor's second step, not the contact's.
    let server = TestServer::new().await;
    let grace = server.person("grace@example.com").await;
    let carl = server.person("carl@example.com").await;
    let phone = server.login("carl@example.com", "Phone").await;
    let (_, _) = enable_two_step(&server, &phone).await;
    let added = add_contact(&server, &grace, &carl, EmergencyScope::Account, "takeover").await;
    let id = added.body["id"].as_str().unwrap().to_owned();
    release(&server, &carl, &id).await;
    let prepared = prepare_takeover(&server, &carl, &id).await;
    assert_eq!(
        takeover(&server, &carl, &id, &prepared).await.status,
        StatusCode::NO_CONTENT
    );
    let status = server
        .get("/v1/account/two-step", &phone.access_token)
        .await;
    assert_eq!(status.body["enabled"], true, "{:?}", status.body);
    let _ = reauth_device(&server, &phone, "two-step").await;
}
