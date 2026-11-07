//! Stay unlocked while logged in to this computer (plan 18), against the real sync server, with
//! the fake device lock and key store.

use crate::common;

use common::*;
use octapass_core::encoding::b64_encode;
use octapass_desktop_vault::model::SessionStatus;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

const NEW_PASSWORD: &str = "a brand new master password 7";

fn confirmed(device: &Device) -> bool {
    device.vault.snapshot().session.confirmed
}

async fn signed_up_and_on(server: &Server) -> Device {
    let device = Device::new(server);
    device.sign_up(server).await;
    let status = device.vault.set_stay_unlocked(true).await.unwrap();
    assert_eq!(status.on, Some(true));
    assert!(status.available && status.enrolled && !status.password_required);
    device
}

#[tokio::test]
async fn it_opens_without_a_prompt_only_while_it_is_on() {
    let server = server().await;
    let device = Device::new(&server);
    device.sign_up(&server).await;
    // Not decided yet: off until the app's migration says otherwise.
    assert_eq!(device.vault.stay_unlocked_status().await.on, None);
    let device = device.restart(&server);
    assert!(!device.vault.unlock_stay_unlocked().await.unwrap());
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    device.vault.set_stay_unlocked(true).await.unwrap();

    let device = device.restart(&server);
    assert_eq!(device.status(), SessionStatus::Locked);
    assert!(device.vault.unlock_stay_unlocked().await.unwrap());
    assert_eq!(device.status(), SessionStatus::Unlocked);
    assert!(device.unlock.prompts().is_empty());

    // Off: every key goes, and the next start asks.
    let status = device.vault.set_stay_unlocked(false).await.unwrap();
    assert!(!status.enrolled);
    let device = device.restart(&server);
    assert!(!device.vault.unlock_stay_unlocked().await.unwrap());
    assert_eq!(device.status(), SessionStatus::Locked);
}

#[tokio::test]
async fn the_first_reveal_asks_and_a_screen_lock_resets_it() {
    let server = server().await;
    let device = signed_up_and_on(&server).await.restart(&server);
    assert!(device.vault.unlock_stay_unlocked().await.unwrap());
    // Opened by itself: the first reveal asks.
    assert!(!confirmed(&device));
    device
        .vault
        .confirm_master_password(secret(PASSWORD))
        .await
        .unwrap();
    // The answer covers the next ones.
    assert!(confirmed(&device));
    device.vault.device_locked();
    assert!(!confirmed(&device));

    // An unlock the user answered is confirmed; with stay unlocked off a screen lock changes
    // nothing (plan 03's once-per-unlock rule).
    device.vault.lock();
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    assert!(confirmed(&device));
    device.vault.set_stay_unlocked(false).await.unwrap();
    device.vault.device_locked();
    assert!(confirmed(&device));
}

#[tokio::test]
async fn filling_and_the_extension_need_no_prompt() {
    let server = server().await;
    let device = signed_up_and_on(&server).await.restart(&server);
    assert!(device.vault.unlock_stay_unlocked().await.unwrap());
    device.vault.confirm_fill("fill").unwrap();
    let extension = StaticSecret::random_from_rng(OsRng);
    let wrap = device
        .vault
        .wrap_session_key(
            &b64_encode(PublicKey::from(&extension).as_bytes()),
            "Chrome",
        )
        .await
        .unwrap();
    assert_eq!(wrap.email, EMAIL);
    assert!(device.vault.bridge_status().await.stay_unlocked);
    assert!(device.unlock.prompts().is_empty());

    // Off, both ask again.
    device.vault.set_stay_unlocked(false).await.unwrap();
    device
        .vault
        .wrap_session_key(
            &b64_encode(PublicKey::from(&extension).as_bytes()),
            "Chrome",
        )
        .await
        .unwrap();
    assert_eq!(device.unlock.prompts(), ["unlock Octa Pass in Chrome"]);
    assert!(!device.vault.bridge_status().await.stay_unlocked);
}

#[tokio::test]
async fn lock_now_holds_until_the_user_unlocks() {
    let server = server().await;
    let device = signed_up_and_on(&server).await;
    device.vault.lock();
    assert!(!device.vault.unlock_stay_unlocked().await.unwrap());
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    device.vault.lock();
    assert!(!device.vault.unlock_stay_unlocked().await.unwrap());
    let device = device.restart(&server);
    assert!(device.vault.unlock_stay_unlocked().await.unwrap());
}

#[tokio::test]
async fn a_master_password_change_deletes_the_key() {
    let server = server().await;
    let device = signed_up_and_on(&server).await;
    let id = format!("{}|{}", server.url, EMAIL);
    assert!(device.unlock.has_unprotected(&id));
    device
        .vault
        .change_master_password(secret(PASSWORD), secret(NEW_PASSWORD))
        .await
        .unwrap();
    assert!(!device.unlock.has_unprotected(&id));
    assert!(!device.vault.stay_unlocked_status().await.enrolled);
    let device = device.restart(&server);
    assert!(!device.vault.unlock_stay_unlocked().await.unwrap());
    // The next unlock with the new password makes a new key.
    device.vault.unlock(secret(NEW_PASSWORD)).await.unwrap();
    assert!(device.unlock.has_unprotected(&id));
}

#[tokio::test]
async fn the_14_day_check_stops_it() {
    let server = server().await;
    let device = signed_up_and_on(&server).await;
    device.vault.lock();
    let Device { unlock, dir, .. } = device;
    // Move the last master password unlock back 15 days.
    let path = dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let old = (time::OffsetDateTime::now_utc() - time::Duration::days(15))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    state["accounts"][0]["lastPasswordUnlockAt"] = old.into();
    std::fs::write(&path, state.to_string()).unwrap();

    let device = Device::reopen(&server, unlock, dir);
    assert!(device.vault.stay_unlocked_status().await.password_required);
    assert!(!device.vault.unlock_stay_unlocked().await.unwrap());
    device.vault.unlock(secret(PASSWORD)).await.unwrap();
    device.vault.lock();
    let device = device.restart(&server);
    assert!(device.vault.unlock_stay_unlocked().await.unwrap());
}

#[tokio::test]
async fn without_a_keyring_it_falls_back() {
    let server = server().await;
    let device = Device::new(&server);
    device.unlock.set_keyring(false);
    device.sign_up(&server).await;
    let status = device.vault.set_stay_unlocked(true).await.unwrap();
    assert!(!status.available && !status.enrolled);
    assert_eq!(status.unavailable, Some("noKeyring"));
    assert!(!device.vault.stays_unlocked());
    let device = device.restart(&server);
    assert!(!device.vault.unlock_stay_unlocked().await.unwrap());
}
