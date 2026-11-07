//! The import review: an authenticator import is parsed and kept in memory while the user links
//! each one-time code to a login, then saved with those choices.

use crate::common;

use common::*;
use octapass_core::import::{CodeLink, ImportOptions, ImportSource};
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::model::Item;

const CODES: &str = "otpauth://totp/GitHub:ada?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n\
                     otpauth://totp/Fastmail:ada%40fastmail.com?secret=KRSXG5CTMVRXEZLU&issuer=Fastmail\n";

fn review(
    device: &Device,
    vault_id: &str,
) -> octapass_desktop_vault::Result<octapass_desktop_vault::vault::ImportReview> {
    device.vault.review_import(
        ImportSource::OtpAuth,
        CODES.as_bytes(),
        ImportOptions::default(),
        vault_id,
    )
}

fn items(device: &Device) -> Vec<Item> {
    device.vault.live_items().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_review_links_codes_to_the_logins_the_user_chooses() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();
    let github = device
        .vault
        .save_item(login(&vault_id, "GitHub", "pw"))
        .await
        .unwrap();
    let mail = device
        .vault
        .save_item(login(&vault_id, "Mail", "pw"))
        .await
        .unwrap();

    let review = review(&device, &vault_id).unwrap();
    assert_eq!(review.codes.len(), 2);
    assert_eq!(review.codes[0].title, "GitHub");
    assert_eq!(
        review.codes[0].login_id.as_deref(),
        Some(github.id.as_str())
    );
    assert_eq!(review.codes[1].title, "Fastmail");
    assert_eq!(review.codes[1].account.as_deref(), Some("ada@fastmail.com"));
    assert_eq!(review.codes[1].login_id, None);
    assert_eq!(review.other_items, 0);
    // Nothing is saved before the review is finished, and it holds no secret.
    assert_eq!(items(&device).len(), 2);
    assert!(
        !serde_json::to_string(&review)
            .unwrap()
            .contains("JBSWY3DPEHPK3PXP")
    );

    // The GitHub code becomes a login of its own; the Fastmail code joins "Mail".
    let links = [
        CodeLink {
            code: 0,
            login_id: None,
        },
        CodeLink {
            code: 1,
            login_id: Some(mail.id.clone()),
        },
    ];
    let summary = device
        .vault
        .finish_import(&review.id, &links)
        .await
        .unwrap();
    assert_eq!(summary.imported, 2);

    let after = items(&device);
    assert_eq!(after.len(), 3);
    let find = |id: &str| after.iter().find(|item| item.id == id).unwrap();
    assert_eq!(find(&github.id).detail("totp"), None);
    assert!(
        find(&mail.id)
            .detail("totp")
            .unwrap()
            .contains("KRSXG5CTMVRXEZLU")
    );
    let own = after
        .iter()
        .find(|item| item.id != github.id && item.id != mail.id)
        .unwrap();
    assert_eq!(own.title(), "GitHub");
    assert!(own.detail("totp").unwrap().contains("JBSWY3DPEHPK3PXP"));

    // A review is finished once.
    let again = device.vault.finish_import(&review.id, &links).await;
    assert_eq!(again.unwrap_err().code, ErrorCode::ImportReviewExpired);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_or_locking_forgets_the_review() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    let vault_id = device.personal_vault();

    let cancelled = review(&device, &vault_id).unwrap();
    device.vault.cancel_import(&cancelled.id);
    let finished = device.vault.finish_import(&cancelled.id, &[]).await;
    assert_eq!(finished.unwrap_err().code, ErrorCode::ImportReviewExpired);
    assert_eq!(
        device
            .vault
            .finish_import("no-such-review", &[])
            .await
            .unwrap_err()
            .code,
        ErrorCode::ImportReviewExpired
    );

    let pending = review(&device, &vault_id).unwrap();
    device.vault.lock();
    assert_eq!(
        device
            .vault
            .finish_import(&pending.id, &[])
            .await
            .unwrap_err()
            .code,
        ErrorCode::Locked
    );
    assert_eq!(
        review(&device, &vault_id).unwrap_err().code,
        ErrorCode::Locked
    );
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    assert_eq!(
        device
            .vault
            .finish_import(&pending.id, &[])
            .await
            .unwrap_err()
            .code,
        ErrorCode::ImportReviewExpired
    );
    assert!(items(&device).is_empty());

    // Without a review, the import saves what the importer matched.
    let summary = device
        .vault
        .finish_import(&review(&device, &vault_id).unwrap().id, &[])
        .await
        .unwrap();
    assert_eq!(summary.imported, 2);
    assert_eq!(items(&device).len(), 2);
}

#[test]
fn qr_codes_are_read_from_images_only() {
    let error = octapass_desktop_vault::tools::read_qr_codes(b"not an image").unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidImage);
    let scan = octapass_desktop_vault::tools::summarize_qr_scans(&[
        "otpauth://totp/GitHub:ada?secret=JBSWY3DPEHPK3PXP&issuer=GitHub".to_owned(),
        "https://example.com".to_owned(),
    ]);
    let scan = serde_json::to_value(scan).unwrap();
    assert_eq!(scan["codes"].as_array().unwrap().len(), 1);
    assert_eq!(scan["other"], 1);
}
