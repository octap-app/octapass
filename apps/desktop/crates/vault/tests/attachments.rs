//! Attachments and Document items through the desktop vault, against the real sync server.

use crate::common;

use common::*;
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::model::ItemDraft;
use serde_json::json;

fn document(vault_id: &str, title: &str) -> ItemDraft {
    serde_json::from_value(json!({
        "vaultId": vault_id,
        "overview": { "schemaVersion": 1, "type": "document", "title": title },
        "details": { "schemaVersion": 1, "notes": "Signed in March" },
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn add_download_keep_through_edits_and_remove() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let item = device
        .vault
        .save_item(document(&vault_id, "Lease"))
        .await
        .unwrap();

    // Several slices and chunks, so the streaming paths run.
    let file: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();
    let added = device
        .vault
        .add_attachment(&item.id, "lease.pdf", "application/pdf", file.clone())
        .await
        .unwrap();
    let entry = &added.details["attachments"][0];
    assert_eq!(entry["name"], "lease.pdf");
    assert_eq!(entry["type"], "application/pdf");
    assert_eq!(entry["size"], file.len());
    let id = entry["id"].as_str().unwrap().to_owned();

    assert_eq!(
        device.vault.get_attachment(&item.id, &id).await.unwrap(),
        file
    );
    let usage = device.vault.storage_usage().await.unwrap();
    assert!(usage.attachment_bytes > file.len() as u64);
    assert_eq!(usage.max_file_bytes, 100 << 20);

    // An edit from a form that never saw the file keeps it; a new item never starts with one.
    let mut edit = document(&vault_id, "Lease 2026");
    edit.id = Some(item.id.clone());
    edit.revision = Some(added.revision);
    let edited = device.vault.save_item(edit).await.unwrap();
    assert_eq!(edited.details["attachments"][0]["id"], id.as_str());
    let mut copied = document(&vault_id, "Copy");
    copied.details["attachments"] = added.details["attachments"].clone();
    let copy = device.vault.save_item(copied).await.unwrap();
    assert!(copy.details.get("attachments").is_none());

    let removed = device.vault.remove_attachment(&item.id, &id).await.unwrap();
    assert!(removed.details.get("attachments").is_none());
    assert_eq!(
        device
            .vault
            .get_attachment(&item.id, &id)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    assert_eq!(
        device.vault.storage_usage().await.unwrap().attachment_bytes,
        0
    );
}
