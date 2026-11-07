//! Version history, counter-based codes and equivalent domains against the real server.

use crate::common;

use common::*;
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::vault::EquivalentDomainsInput;
use serde_json::json;

const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[tokio::test(flavor = "multi_thread")]
async fn versions_are_kept_restored_and_undone() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let first = device
        .vault
        .save_item(login(&vault_id, "Bank", "first"))
        .await
        .unwrap();
    assert!(
        device
            .vault
            .item_versions(&first.id)
            .await
            .unwrap()
            .is_empty()
    );

    let mut draft = login(&vault_id, "Bank", "second");
    draft.id = Some(first.id.clone());
    draft.revision = Some(first.revision);
    let second = device.vault.save_item(draft).await.unwrap();

    let versions = device.vault.item_versions(&first.id).await.unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].details["password"], "first");

    let restored = device
        .vault
        .restore_item_version(&first.id, versions[0].revision)
        .await
        .unwrap();
    assert_eq!(restored.details["password"], "first");
    assert!(restored.revision > second.revision);
    assert_eq!(restored.details["passwordHistory"][0]["password"], "second");
    let versions = device.vault.item_versions(&first.id).await.unwrap();
    assert_eq!(versions[0].details["password"], "second");

    // A revision the item never had (its first save, revision 1, is in the history).
    let missing = device
        .vault
        .restore_item_version(&first.id, restored.revision + 1000)
        .await;
    assert_eq!(missing.unwrap_err().code, ErrorCode::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn counter_codes_move_save_and_stay_out_of_the_history() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let mut draft = login(&vault_id, "Bank", "pw");
    draft.details["totp"] = json!(format!("otpauth://hotp/x?secret={SECRET}&counter=0"));
    let item = device.vault.save_item(draft).await.unwrap();

    let first = device.vault.next_hotp_code(&item.id).await.unwrap();
    assert_eq!((first.code.as_str(), first.counter), ("755224", 0));
    let second = device.vault.next_hotp_code(&item.id).await.unwrap();
    assert_eq!((second.code.as_str(), second.counter), ("287082", 1));
    assert!(
        device
            .vault
            .item_versions(&item.id)
            .await
            .unwrap()
            .is_empty()
    );

    let set = device.vault.set_hotp_counter(&item.id, 7).await.unwrap();
    assert!(set.detail("totp").unwrap().contains("counter=7"));
    let next = device.vault.next_hotp_code(&item.id).await.unwrap();
    assert_eq!(next.code, "162583");

    let plain = device
        .vault
        .save_item(login(&vault_id, "Plain", "pw"))
        .await
        .unwrap();
    let refused = device.vault.next_hotp_code(&plain.id).await;
    assert_eq!(refused.unwrap_err().code, ErrorCode::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn equivalent_domains_are_cleaned_and_reach_autofill() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let mut draft = login(&vault_id, "Shop", "pw");
    draft.overview["urls"] = json!(["https://example.com"]);
    device.vault.save_item(draft).await.unwrap();

    let saved = device
        .vault
        .save_equivalent_domains(EquivalentDomainsInput {
            groups: vec![vec![
                "mail.example.com".into(),
                "example.org".into(),
                "co.uk".into(),
            ]],
            excluded_defaults: vec!["google.com".into()],
        })
        .await
        .unwrap();
    assert_eq!(saved.groups, [["example.com", "example.org"]]);
    assert_eq!(saved.rejected, ["co.uk"]);
    assert_eq!(saved.excluded_defaults, ["google.com"]);
    assert!(saved.defaults.iter().any(|g| g[0] == "google.com"));

    let found = device
        .vault
        .autofill_logins(&["https://example.org".to_owned()])
        .unwrap();
    assert_eq!(found.len(), 1);

    // Saving again changes the one item instead of making another.
    device
        .vault
        .save_equivalent_domains(EquivalentDomainsInput {
            groups: Vec::new(),
            excluded_defaults: Vec::new(),
        })
        .await
        .unwrap();
    assert!(
        device
            .vault
            .autofill_logins(&["https://example.org".to_owned()])
            .unwrap()
            .is_empty()
    );
    assert_eq!(device.vault.equivalent_domains().unwrap().groups.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn passwords_follow_the_sites_rules() {
    let server = server().await;
    let device = Device::new(&server);
    let options = octapass_core::tools::generator::RandomOptions {
        length: 120,
        ..Default::default()
    };
    let password = device
        .vault
        .generate_password_for_site("https://apple.com", &options)
        .unwrap();
    assert!(password.len() <= 63, "{}", password.len());
}
