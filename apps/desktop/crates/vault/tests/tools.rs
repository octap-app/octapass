//! Health inputs, the breach check, quick-access copy values, auto-type's view of logins and the
//! native messaging key wrap.

use crate::common;

use axum::extract::Path;
use axum::routing::get;
use common::*;
use octapass_core::account::AccountBundle;
use octapass_core::encoding::{b64_decode, b64_decode_array, b64_encode};
use octapass_core::session::Session;
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::bridge::wrap_key;
use octapass_desktop_vault::model::ItemDraft;
use octapass_desktop_vault::tools::CopyField;
use octapass_device_unlock::Error as UnlockError;
use rand_core::OsRng;
use serde_json::json;
use x25519_dalek::{PublicKey, StaticSecret};

/// A Pwned Passwords range API that knows one password, `password` (SHA-1 5BAA61E4…).
async fn pwned() -> String {
    let app = axum::Router::new().route(
        "/range/{prefix}",
        get(|Path(prefix): Path<String>| async move {
            if prefix == "5BAA6" {
                "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n0000000000000000000000000000000000A:0".to_owned()
            } else {
                "0000000000000000000000000000000000A:0".to_owned()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

#[tokio::test(flavor = "multi_thread")]
async fn health_inputs_group_passwords_without_revealing_them() {
    let mut server = server().await;
    let sync_url = server.url.clone();
    server.url = pwned().await;
    let device = Device::new(&server);
    server.url = sync_url;
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    for (title, password) in [
        ("A", "password"),
        ("B", "password"),
        ("C", "Xq7!vR2#pL9@mK4$"),
    ] {
        device
            .vault
            .save_item(login(&vault_id, title, password))
            .await
            .unwrap();
    }
    let note = serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "secureNote", "title": "Note" },
        "details": { "schemaVersion": 1, "notes": "password" },
    }))
    .unwrap();
    device.vault.save_item(note).await.unwrap();

    let inputs = device.vault.health_inputs().await.unwrap();
    let text = serde_json::to_string(&inputs).unwrap();
    assert!(
        !text.contains("Xq7!") && !text.contains("\"password\":"),
        "{text}"
    );
    assert_eq!(inputs.logins.len(), 3, "notes aren't checked");
    assert!(inputs.breach_check_completed);
    let group = |title: &str| {
        inputs
            .logins
            .iter()
            .find(|login| login.title == title)
            .unwrap()
            .password_group
            .unwrap()
    };
    assert_eq!(group("A"), group("B"));
    assert_ne!(group("A"), group("C"));
    assert_eq!(inputs.groups[group("A")].breach_count, Some(9_545_824));
    assert_eq!(inputs.groups[group("A")].score, 0);
    assert_eq!(inputs.groups[group("C")].breach_count, Some(0));
    assert!(inputs.groups[group("C")].score >= 3);
    assert_eq!(inputs.logins[0].subtitle.as_deref(), Some("ada"));

    assert_eq!(
        device.vault.check_breached("password").await.unwrap(),
        9_545_824
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn health_inputs_carry_recovery_contacts_but_never_backup_codes() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let mut draft = login(&vault_id, "Bank", "pw");
    draft.details["recovery"] = json!({
        "email": "ada@gmail.com",
        "emailSource": { "kind": "identity", "itemId": "me" },
        "phone": "+44 7700 900123",
        "twoFactorMethod": "sms",
        "backupCodes": [{ "code": "otter-velvet-4417", "used": false }],
    });
    device.vault.save_item(draft).await.unwrap();

    let inputs = device.vault.health_inputs().await.unwrap();
    let text = serde_json::to_string(&inputs).unwrap();
    assert!(!text.contains("otter-velvet"), "{text}");
    let row = &inputs.logins[0];
    assert_eq!(row.username.as_deref(), Some("ada"));
    assert_eq!(row.two_factor_method.as_deref(), Some("sms"));
    assert_eq!(
        row.recovery,
        Some(json!({
            "email": "ada@gmail.com",
            "emailSource": { "kind": "identity", "itemId": "me" },
            "phone": "+44 7700 900123",
        }))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn health_inputs_count_backup_codes_and_read_expiries_and_settings() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let mut draft = login(&vault_id, "Bank", "pw");
    draft.details["recovery"] = json!({
        "backupCodes": [
            { "code": "otter-velvet-4417", "used": false },
            { "code": "lantern-ruby-0932", "used": true },
        ],
    });
    draft.details["passwordChangedAt"] = json!("2024-01-02T03:04:05.000Z");
    draft.details["passwordHistory"] = json!([
        { "password": "older", "changedAt": "2023-01-01T00:00:00.000Z" },
    ]);
    device.vault.save_item(draft).await.unwrap();
    let card: ItemDraft = serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "card", "title": "Visa" },
        "details": { "schemaVersion": 1, "expiry": "01/27", "cvv": "123" },
    }))
    .unwrap();
    device.vault.save_item(card).await.unwrap();
    let api_key: ItemDraft = serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "apiCredential", "title": "Key" },
        "details": { "schemaVersion": 1, "expiryDate": "2020-01-01" },
    }))
    .unwrap();
    device.vault.save_item(api_key).await.unwrap();
    let settings: ItemDraft = serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "healthSettings", "title": "Health settings" },
        "details": { "schemaVersion": 1, "dismissed": ["weak:x:1"], "emailBreachAlerts": { "enabled": true } },
    }))
    .unwrap();
    device.vault.save_item(settings).await.unwrap();

    let inputs = device.vault.health_inputs().await.unwrap();
    let text = serde_json::to_string(&inputs).unwrap();
    assert!(
        !text.contains("otter-velvet") && !text.contains("\"123\""),
        "{text}"
    );
    let row = inputs
        .logins
        .iter()
        .find(|row| row.title == "Bank")
        .unwrap();
    assert_eq!(
        row.password_date.as_deref(),
        Some("2024-01-02T03:04:05.000Z")
    );
    assert_eq!(
        row.backup_codes.map(|codes| (codes.total, codes.unused)),
        Some((2, 1))
    );
    assert_eq!(inputs.expiries.len(), 1);
    assert_eq!(inputs.expiries[0].expiry, "01/27");
    assert_eq!(inputs.settings.dismissed, ["weak:x:1"]);
    assert_eq!(
        inputs.settings.email_breach_alerts,
        Some(json!({ "enabled": true }))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn masked_email_requests_only_reach_the_providers_apis() {
    let server = server().await;
    let device = Device::new(&server);
    for url in [
        format!("{}/v1/server-info", server.url),
        "https://evil.example/api/alias/random/new".to_owned(),
        "http://app.simplelogin.io/api/alias/random/new".to_owned(),
    ] {
        let request = serde_json::from_value(
            json!({ "url": url, "method": "POST", "headers": {}, "body": "{}" }),
        )
        .unwrap();
        let error = device
            .vault
            .masked_email_request(request)
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unexpected, "{url}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_breach_lookup_reports_an_incomplete_check() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    device
        .vault
        .save_item(login(&vault_id, "A", "pw"))
        .await
        .unwrap();
    // The sync server has no /range endpoint.
    let inputs = device.vault.health_inputs().await.unwrap();
    assert!(!inputs.breach_check_completed);
    assert_eq!(inputs.groups[0].breach_count, None);
    assert_eq!(
        device.vault.check_breached("pw").await.unwrap_err().code,
        ErrorCode::ServerUnreachable
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn quick_access_copies_usernames_passwords_and_codes() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let mut draft = login(&vault_id, "With code", "pw");
    draft.details["totp"] = json!("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
    let item = device.vault.save_item(draft).await.unwrap();

    let copy = |field| device.vault.copy_value(&item.id, field);
    assert_eq!(copy(CopyField::Username).unwrap().as_str(), "ada");
    assert_eq!(copy(CopyField::Password).unwrap().as_str(), "pw");
    let code = copy(CopyField::Code).unwrap();
    assert_eq!(code.len(), 6);
    assert_eq!(
        *code,
        device.vault.totp("JBSWY3DPEHPK3PXP", None).unwrap().code
    );
    // RFC 6238 test time 59 s with this secret.
    assert_eq!(
        device
            .vault
            .totp("JBSWY3DPEHPK3PXP", Some(59_000))
            .unwrap()
            .code,
        "996554"
    );

    let plain = device
        .vault
        .save_item(login(&vault_id, "No code", "pw"))
        .await
        .unwrap();
    assert_eq!(
        device
            .vault
            .copy_value(&plain.id, CopyField::Code)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    device.vault.lock();
    assert_eq!(
        copy(CopyField::Password).unwrap_err().code,
        ErrorCode::Locked
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_type_reads_the_rules_and_sequence_without_secrets() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let mut draft = login(&vault_id, "Router", "pw");
    draft.overview["urlMatch"] = json!({ "https://example.com": "host" });
    draft.details["autoType"] = json!({
        "sequence": "{PASSWORD}{ENTER}",
        "windowTitles": ["*192.168.1.1*", 7],
    });
    let router = device.vault.save_item(draft).await.unwrap();
    let plain = device
        .vault
        .save_item(login(&vault_id, "Plain", "pw"))
        .await
        .unwrap();
    let note = serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "secureNote", "title": "Note" },
        "details": { "schemaVersion": 1, "notes": "x" },
    }))
    .unwrap();
    let note = device.vault.save_item(note).await.unwrap();

    let item = device.vault.auto_type_item(&router.id).unwrap();
    assert_eq!(
        (item.title.as_str(), item.item_type.as_str()),
        ("Router", "login")
    );
    assert_eq!(item.urls, ["https://example.com"]);
    assert_eq!(
        serde_json::to_value(&item.url_match).unwrap(),
        json!({ "https://example.com": "host" })
    );
    assert_eq!(item.window_titles, ["*192.168.1.1*"]);
    assert_eq!(item.sequence.as_deref(), Some("{PASSWORD}{ENTER}"));
    assert!(!serde_json::to_string(&item).unwrap().contains("pw"));

    let plain = device.vault.auto_type_item(&plain.id).unwrap();
    assert_eq!((plain.sequence, plain.window_titles.len()), (None, 0));
    assert_eq!(
        device.vault.auto_type_item(&note.id).unwrap_err().code,
        ErrorCode::NotFound
    );
    let mut ids: Vec<_> = device
        .vault
        .auto_type_items()
        .unwrap()
        .into_iter()
        .map(|item| item.title)
        .collect();
    ids.sort();
    assert_eq!(ids, ["Plain", "Router"]);

    device.vault.delete_item(&router.id).await.unwrap();
    assert_eq!(
        device.vault.auto_type_item(&router.id).unwrap_err().code,
        ErrorCode::NotFound
    );
    assert_eq!(device.vault.auto_type_items().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_extension_can_unwrap_the_account_key_after_the_user_confirms() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;

    // The extension's side: a fresh X25519 key pair per request.
    let extension = StaticSecret::random_from_rng(OsRng);
    let extension_public = PublicKey::from(&extension);
    let wrap = device
        .vault
        .wrap_session_key(&b64_encode(extension_public.as_bytes()), "Chrome")
        .await
        .unwrap();
    assert_eq!(device.unlock.prompts(), ["unlock Octa Pass in Chrome"]);
    assert_eq!(wrap.email, EMAIL);

    let app_public: [u8; 32] = b64_decode_array(&wrap.ephemeral_public_key).unwrap();
    let shared = extension.diffie_hellman(&PublicKey::from(app_public));
    let key = wrap_key(shared.as_bytes(), &app_public, extension_public.as_bytes());
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(device.dir.path().join("state.json")).unwrap())
            .unwrap();
    let bundle: AccountBundle =
        serde_json::from_value(state["accounts"][0]["bundle"].clone()).unwrap();
    Session::unlock_with_device_key(
        bundle,
        key.as_ref(),
        &b64_decode(&wrap.device_salt).unwrap(),
        &wrap.wrapped_ask,
    )
    .expect("the extension opens the same account");

    device.unlock.refuse_prompts(Some(UnlockError::Cancelled));
    assert_eq!(
        device
            .vault
            .wrap_session_key(&b64_encode(extension_public.as_bytes()), "Chrome")
            .await
            .unwrap_err()
            .code,
        ErrorCode::DeviceUnlockCancelled
    );
    device.unlock.refuse_prompts(None);
    device.vault.lock();
    assert_eq!(
        device
            .vault
            .wrap_session_key(&b64_encode(extension_public.as_bytes()), "Chrome")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Locked
    );
    assert!(
        device
            .vault
            .wrap_session_key(&b64_encode(&[0; 32]), "Chrome")
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_extension_sees_the_unlock_status_and_can_ask_for_device_unlock() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    device.vault.enable_device_unlock().await.unwrap();
    device.vault.lock();
    let status = device.vault.bridge_status().await;
    assert_eq!(serde_json::to_value(&status).unwrap()["status"], "locked");
    assert!(status.device_unlock);
    let status = device.vault.bridge_unlock().await.unwrap();
    assert_eq!(serde_json::to_value(&status).unwrap()["status"], "unlocked");
}
