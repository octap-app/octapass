//! What the SSH agent asks of the vault, against the real sync server.

use crate::common;

use common::*;
use octapass_core::tools::ssh::{self, SshKey, SshKeyKind, generate};
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::model::ItemDraft;
use rand_core::OsRng;
use serde_json::{Value, json};

fn draft(vault_id: &str, title: &str, key: &SshKey, extra: Value) -> ItemDraft {
    let mut details = json!({
        "schemaVersion": 1,
        "privateKey": key.private_key.as_str(),
        "publicKey": key.info.public_key,
        "keyType": key.info.key_type,
        "fingerprint": key.info.fingerprint,
        "comment": "me@laptop",
    });
    for (name, value) in extra.as_object().unwrap() {
        details[name] = value.clone();
    }
    serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "sshKey", "title": title },
        "details": details,
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_offers_usable_keys_and_signs_while_unlocked() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let offered = generate(SshKeyKind::Ed25519, "a", &mut OsRng).unwrap();
    let held_back = generate(SshKeyKind::Ed25519, "b", &mut OsRng).unwrap();
    let trashed = generate(SshKeyKind::Ed25519, "c", &mut OsRng).unwrap();
    let vault = &device.vault;
    vault
        .save_item(draft(&vault_id, "Laptop", &offered, json!({})))
        .await
        .unwrap();
    vault
        .save_item(draft(
            &vault_id,
            "Quiet",
            &held_back,
            json!({ "sshAgent": false }),
        ))
        .await
        .unwrap();
    let gone = vault
        .save_item(draft(&vault_id, "Gone", &trashed, json!({})))
        .await
        .unwrap();
    vault.delete_item(&gone.id).await.unwrap();

    let keys = vault.ssh_agent_keys().unwrap();
    assert_eq!(keys.len(), 1, "{keys:?}");
    assert_eq!(keys[0].title, "Laptop");
    assert_eq!(keys[0].comment, "me@laptop");
    assert_eq!(keys[0].fingerprint, offered.info.fingerprint);
    let blob = keys[0].blob.clone();
    assert_eq!(
        blob,
        ssh::public_key_blob(&offered.info.public_key).unwrap()
    );

    let signature = vault
        .ssh_agent_sign(&blob, b"data".to_vec(), 0)
        .await
        .unwrap();
    assert_eq!(&signature[4..15], b"ssh-ed25519");

    // A key that's held back can't be used by naming it.
    let quiet = ssh::public_key_blob(&held_back.info.public_key).unwrap();
    assert_eq!(
        vault
            .ssh_agent_sign(&quiet, b"data".to_vec(), 0)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );

    // Each unlock is told apart, so an approval doesn't outlive locking.
    let session = vault.ssh_agent_session().expect("unlocked");
    vault.lock();
    assert_eq!(vault.ssh_agent_session(), None);
    vault.unlock(secret(PASSWORD)).await.unwrap();
    assert_ne!(vault.ssh_agent_session(), Some(session));
    assert!(vault.ssh_agent_session().is_some());

    vault.lock();
    assert_eq!(vault.ssh_agent_keys().unwrap_err().code, ErrorCode::Locked);
    assert_eq!(
        vault
            .ssh_agent_sign(&blob, b"data".to_vec(), 0)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Locked
    );
}
