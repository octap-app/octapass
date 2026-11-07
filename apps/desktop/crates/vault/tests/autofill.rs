//! What the macOS AutoFill extension gets from the vault: logins for a site, passwords and codes,
//! and passkeys created and used with the client data hash the system wrote.

use crate::common;

use common::*;
use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::autofill::PasskeyCreation;
use serde_json::json;
use sha2::{Digest, Sha256};

fn login_for(
    vault_id: &str,
    title: &str,
    url: &str,
    username: &str,
) -> octapass_desktop_vault::model::ItemDraft {
    serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "login", "title": title, "urls": [url] },
        "details": { "schemaVersion": 1, "username": username, "password": format!("{title} password") },
    }))
    .unwrap()
}

fn creation(rp_id: &str, user_name: &str, excluded: Vec<String>) -> PasskeyCreation {
    PasskeyCreation {
        rp_id: rp_id.into(),
        user_name: user_name.into(),
        user_handle: b64_encode(b"user-handle-1"),
        algorithms: vec![-7],
        excluded,
        client_data_hash: b64_encode(&Sha256::digest(b"registration client data")),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn logins_for_the_site_then_the_chosen_password() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let vault = &device.vault;
    let work = vault
        .save_item(login_for(
            &vault_id,
            "Work GitHub",
            "https://github.com/login",
            "ada-work",
        ))
        .await
        .unwrap();
    let mut draft = login_for(&vault_id, "GitHub", "https://github.com", "ada");
    draft.details["totp"] = json!("JBSWY3DPEHPK3PXP");
    let personal = vault.save_item(draft).await.unwrap();
    vault
        .save_item(login_for(
            &vault_id,
            "Look-alike",
            "https://github.com.evil.io",
            "ada",
        ))
        .await
        .unwrap();
    vault
        .save_item(login_for(
            &vault_id,
            "Example",
            "https://example.com",
            "ada",
        ))
        .await
        .unwrap();

    let found = vault
        .autofill_logins(&["https://github.com".into(), "not a url".into()])
        .unwrap();
    let mut titles: Vec<_> = found.iter().map(|login| login.title.as_str()).collect();
    titles.sort();
    assert_eq!(titles, ["GitHub", "Work GitHub"]);
    let github = found
        .iter()
        .find(|login| login.item_id == personal.id)
        .unwrap();
    assert_eq!(
        (
            github.username.as_deref(),
            github.has_totp,
            github.scheme_mismatch
        ),
        (Some("ada"), true, false)
    );
    assert!(!serde_json::to_string(&found).unwrap().contains("password"));

    // An http page gets the https login, with a warning; one site twice lists each login once.
    let http = vault
        .autofill_logins(&["http://gist.github.com".into(), "https://github.com".into()])
        .unwrap();
    assert_eq!(http.len(), 2);
    assert!(http.iter().all(|login| login.scheme_mismatch));

    let search = vault.autofill_search("ADA-WORK").unwrap();
    assert_eq!(
        search
            .iter()
            .map(|login| login.item_id.as_str())
            .collect::<Vec<_>>(),
        [work.id.as_str()]
    );
    assert_eq!(vault.autofill_search("").unwrap().len(), 4);

    let (username, password) = vault.autofill_password(&work.id).unwrap();
    assert_eq!(
        (username.as_str(), password.as_str()),
        ("ada-work", "Work GitHub password")
    );
    assert_eq!(vault.autofill_code(&personal.id).unwrap().len(), 6);
    assert_eq!(
        vault.autofill_code(&work.id).unwrap_err().code,
        ErrorCode::NotFound
    );

    vault.lock();
    assert_eq!(
        vault
            .autofill_logins(&["https://github.com".into()])
            .unwrap_err()
            .code,
        ErrorCode::Locked
    );
    assert_eq!(
        vault.autofill_password(&work.id).unwrap_err().code,
        ErrorCode::Locked
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn passkeys_are_created_saved_and_used_with_the_systems_client_data() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let vault = &device.vault;
    let existing = vault
        .save_item(login_for(
            &vault_id,
            "Example",
            "https://example.com",
            "ada",
        ))
        .await
        .unwrap();

    // The login for the site with the same user name gets the passkey.
    let registration = vault
        .autofill_register(creation("example.com", "ADA", vec![]))
        .await
        .unwrap();
    assert_eq!(registration.item_id, existing.id);
    let saved = vault.get_item(&existing.id).unwrap();
    assert_eq!(saved.details["passkeys"][0]["rpId"], "example.com");
    assert_eq!(saved.detail("password"), Some("Example password"));
    assert!(
        !b64_decode(&registration.attestation_object)
            .unwrap()
            .is_empty()
    );

    let hash = b64_encode(&Sha256::digest(b"assertion client data"));
    let found = vault.autofill_passkeys("example.com", &hash, &[]).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].credential_id, registration.credential_id);
    assert_eq!(found[0].user_handle, b64_encode(b"user-handle-1"));
    assert!(
        vault
            .autofill_passkeys("example.com", &hash, &[b64_encode(b"someone else")])
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .autofill_passkeys("other.example", &hash, &[])
            .unwrap()
            .is_empty()
    );

    let signed = vault
        .autofill_assertion(
            "example.com",
            &hash,
            std::slice::from_ref(&registration.credential_id),
            &registration.credential_id,
        )
        .unwrap();
    assert_eq!(signed.item_id, existing.id);
    assert_eq!(signed.user_handle, b64_encode(b"user-handle-1"));
    let data = b64_decode(&signed.authenticator_data).unwrap();
    assert_eq!(&data[..32], Sha256::digest(b"example.com").as_slice());
    assert_eq!(data[32] & 0b101, 0b101, "user present and verified");
    assert!(!b64_decode(&signed.signature).unwrap().is_empty());

    // A public suffix, a bad hash or an unknown passkey are refused.
    assert!(vault.autofill_passkeys("com", &hash, &[]).is_err());
    assert!(vault.autofill_passkeys("example.com", "AAAA", &[]).is_err());
    assert_eq!(
        vault
            .autofill_assertion("example.com", &hash, &[], &b64_encode(b"nope"))
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );

    // The site already has this passkey.
    let excluded = vault
        .autofill_register(creation(
            "example.com",
            "ada",
            vec![registration.credential_id.clone()],
        ))
        .await
        .unwrap_err();
    assert_eq!(excluded.message, "passkey_excluded");

    // A site with no login gets a new one, titled after it.
    let new = vault
        .autofill_register(creation("shop.example.org", "maya", vec![]))
        .await
        .unwrap();
    let item = vault.get_item(&new.item_id).unwrap();
    assert_eq!(item.title(), "shop.example.org");
    assert_eq!(item.overview["urls"], json!(["https://shop.example.org"]));
    assert_eq!(item.detail("username"), Some("maya"));

    // The system's suggestions: logins with a user name and site, and every passkey.
    let identities = vault.autofill_identities().unwrap();
    assert_eq!(identities.passkeys.len(), 2);
    let example = identities
        .passwords
        .iter()
        .find(|p| p.item_id == existing.id)
        .unwrap();
    assert_eq!(
        (example.username.as_str(), example.hosts.as_slice()),
        ("ada", ["example.com".to_owned()].as_slice())
    );
    assert!(
        !serde_json::to_string(&identities)
            .unwrap()
            .contains("password\"")
    );
}
