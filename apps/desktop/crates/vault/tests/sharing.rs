//! The desktop's own sharing against the real sync server: shared vaults with fingerprint
//! checks, roles and key rotation on removal, families, one-time share links, emergency access,
//! devices and the security log. `shared_vaults.rs` covers opening vaults another client shared.

use crate::common;

use std::time::Duration;

use common::{Device, PASSWORD, Server, login, secret, server};
use octapass_api::{EmergencyAccessLevel, EmergencyStatus, SecurityEventType, VaultRole};
use octapass_core::sharing::emergency::EmergencyScope;
use octapass_desktop_vault::vault::{AccountLookup, ShareLinkOptions};
use octapass_desktop_vault::{ErrorCode, Event};
use serde_json::json;

async fn sign_up(server: &Server, email: &str) -> Device {
    let device = Device::new(server);
    let started = device
        .vault
        .start_signup(&server.url, email, secret(PASSWORD))
        .await
        .unwrap();
    device
        .vault
        .finish_signup(&started.signup_id, &started.dev_verification_code.unwrap())
        .await
        .unwrap();
    device
}

fn titles(device: &Device, vault_id: &str) -> Vec<String> {
    let mut titles: Vec<String> = device
        .vault
        .list_items()
        .unwrap()
        .into_iter()
        .filter(|item| item.vault_id == vault_id && item.deleted_at.is_none())
        .map(|item| item.title)
        .collect();
    titles.sort();
    titles
}

fn has_vault(device: &Device, vault_id: &str) -> bool {
    device
        .vault
        .list_vaults()
        .unwrap()
        .iter()
        .any(|vault| vault.id == vault_id)
}

async fn save(device: &Device, vault_id: &str, title: &str) -> Result<String, ErrorCode> {
    device
        .vault
        .save_item(login(vault_id, title, &format!("{title}-secret")))
        .await
        .map(|item| item.id)
        .map_err(|error| error.code)
}

fn sharing_events(device: &Device) -> usize {
    device
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| matches!(event, Event::SharingChanged))
        .count()
}

/// Looks `email` up and checks the fingerprint is the one its owner sees, as the user would.
async fn find(owner: &Device, email: &str, person: &Device) -> AccountLookup {
    let account = owner.vault.lookup_account(email).await.unwrap();
    assert_eq!(account.fingerprint, person.vault.my_fingerprint().unwrap());
    account
}

#[tokio::test]
async fn shares_a_vault_changes_roles_and_rotates_the_key_on_removal() {
    let server = server().await;
    let alice = sign_up(&server, "alice@example.com").await;
    let bob = sign_up(&server, "bob@example.com").await;
    let carol = sign_up(&server, "carol@example.com").await;

    let team = alice.vault.create_vault("  Team  ").await.unwrap();
    assert_eq!((team.name.as_str(), team.role), ("Team", VaultRole::Owner));
    let router = save(&alice, &team.id, "Router").await.unwrap();
    assert!(sharing_events(&alice) > 0);

    // Nobody by that email; and a lookup whose keys don't give the fingerprint the user saw.
    assert_eq!(
        alice
            .vault
            .lookup_account("nobody@example.com")
            .await
            .unwrap_err()
            .code,
        ErrorCode::AccountNotFound
    );
    let bob_account = find(&alice, " Bob@Example.com ", &bob).await;
    let mut swapped = bob_account.clone();
    swapped.public_enc_key = carol
        .vault
        .lookup_account("carol@example.com")
        .await
        .unwrap()
        .public_enc_key;
    assert_eq!(
        alice
            .vault
            .add_member(&team.id, &swapped, VaultRole::Write)
            .await
            .unwrap_err()
            .code,
        ErrorCode::UntrustedVault
    );

    alice
        .vault
        .mark_verified(&bob_account.account_id, &bob_account.fingerprint)
        .unwrap();
    alice
        .vault
        .add_member(&team.id, &bob_account, VaultRole::Write)
        .await
        .unwrap();
    let carol_account = find(&alice, "carol@example.com", &carol).await;
    alice
        .vault
        .add_member(&team.id, &carol_account, VaultRole::Read)
        .await
        .unwrap();

    let members = alice.vault.list_members(&team.id).await.unwrap();
    let member = |email: &str| members.iter().find(|m| m.email == email).unwrap().clone();
    assert!(member("alice@example.com").is_you && member("alice@example.com").verified);
    assert_eq!(
        (
            member("bob@example.com").role,
            member("bob@example.com").verified
        ),
        (VaultRole::Write, true)
    );
    assert_eq!(
        (
            member("carol@example.com").role,
            member("carol@example.com").verified
        ),
        (VaultRole::Read, false)
    );
    assert_eq!(
        member("bob@example.com").fingerprint,
        bob_account.fingerprint
    );

    // Bob writes; carol reads and can't share it on.
    bob.vault.sync().await.unwrap();
    assert_eq!(
        bob.vault
            .list_vaults()
            .unwrap()
            .iter()
            .find(|v| v.id == team.id)
            .unwrap()
            .name,
        "Team"
    );
    save(&bob, &team.id, "Printer").await.unwrap();
    carol.vault.sync().await.unwrap();
    assert_eq!(titles(&carol, &team.id), ["Printer", "Router"]);
    assert_eq!(
        save(&carol, &team.id, "Mine").await,
        Err(ErrorCode::ReadOnlyVault)
    );
    let alice_for_carol = carol
        .vault
        .lookup_account("alice@example.com")
        .await
        .unwrap();
    assert_eq!(
        carol
            .vault
            .add_member(&team.id, &alice_for_carol, VaultRole::Read)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotAllowed
    );

    // A new role takes a new grant.
    alice
        .vault
        .change_role(&team.id, &carol_account.account_id, VaultRole::Write)
        .await
        .unwrap();
    carol.vault.sync().await.unwrap();
    save(&carol, &team.id, "Scanner").await.unwrap();

    // Renamed by a member who may write.
    bob.vault.rename_vault(&team.id, "Office").await.unwrap();
    alice.vault.sync().await.unwrap();
    assert_eq!(
        alice
            .vault
            .list_vaults()
            .unwrap()
            .iter()
            .find(|v| v.id == team.id)
            .unwrap()
            .name,
        "Office"
    );

    // Carol is removed: the key rotates, bob keeps working under the new one, carol loses it.
    let before = alice
        .vault
        .with_keys(|_, cache| cache.vault(&team.id).unwrap().key_id.clone())
        .unwrap();
    alice
        .vault
        .remove_member(&team.id, &carol_account.account_id)
        .await
        .unwrap();
    let after = alice
        .vault
        .with_keys(|_, cache| cache.vault(&team.id).unwrap().key_id.clone())
        .unwrap();
    assert_ne!(before, after, "the vault has a new key");
    bob.vault.sync().await.unwrap();
    assert_eq!(
        bob.vault.get_item(&router).unwrap().details["password"],
        "Router-secret"
    );
    save(&bob, &team.id, "Fax").await.unwrap();
    alice.vault.sync().await.unwrap();
    assert_eq!(
        titles(&alice, &team.id),
        ["Fax", "Printer", "Router", "Scanner"]
    );
    carol.vault.sync().await.unwrap();
    assert!(!has_vault(&carol, &team.id));
    assert!(
        sharing_events(&carol) > 0,
        "a sync that loses a vault says sharing changed"
    );

    // Bob leaves on his own.
    bob.vault.leave_vault(&team.id).await.unwrap();
    assert!(!has_vault(&bob, &team.id));
    let members: Vec<String> = alice
        .vault
        .list_members(&team.id)
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.email)
        .collect();
    assert_eq!(members, ["alice@example.com"]);
}

#[tokio::test]
async fn copies_and_moves_items_with_their_files() {
    let server = server().await;
    let alice = sign_up(&server, "alice@example.com").await;
    let personal = alice.personal_vault();
    let team = alice.vault.create_vault("Team").await.unwrap().id;

    let item = save(&alice, &personal, "Router").await.unwrap();
    alice
        .vault
        .add_attachment(&item, "notes.txt", "text/plain", b"port 8080".to_vec())
        .await
        .unwrap();

    let copy = alice.vault.copy_item(&item, &team).await.unwrap();
    assert_eq!(
        (copy.vault_id.as_str(), copy.title()),
        (team.as_str(), "Router")
    );
    let file = &copy.details["attachments"][0];
    assert_eq!(file["name"], "notes.txt");
    let bytes = alice
        .vault
        .get_attachment(&copy.id, file["id"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(bytes, b"port 8080");
    assert!(alice.vault.get_item(&item).unwrap().deleted_at.is_none());

    let moved = alice.vault.move_item(&item, &team).await.unwrap();
    assert_eq!(moved.vault_id, team);
    assert!(
        alice.vault.get_item(&item).unwrap().deleted_at.is_some(),
        "the original is in the trash"
    );
    assert_eq!(titles(&alice, &team), ["Router", "Router"]);
}

#[tokio::test]
async fn runs_a_family_and_rotates_its_key_for_pending_invites() {
    let server = server().await;
    let alice = sign_up(&server, "alice@example.com").await;
    let bob = sign_up(&server, "bob@example.com").await;
    let carol = sign_up(&server, "carol@example.com").await;

    assert!(alice.vault.get_family().await.unwrap().family.is_none());
    alice.vault.create_family().await.unwrap();
    let family = alice.vault.get_family().await.unwrap().family.unwrap();
    assert!(family.is_organiser);
    assert!(has_vault(&alice, &family.vault_id));
    save(&alice, &family.vault_id, "Streaming").await.unwrap();

    let bob_account = find(&alice, "bob@example.com", &bob).await;
    alice.vault.invite_to_family(&bob_account).await.unwrap();
    let invited = bob.vault.get_family().await.unwrap();
    assert_eq!(invited.invitations[0].organiser_email, "alice@example.com");
    bob.vault.accept_family_invite(&family.id).await.unwrap();
    assert_eq!(titles(&bob, &family.vault_id), ["Streaming"]);
    let seen = bob.vault.get_family().await.unwrap().family.unwrap();
    assert!(!seen.is_organiser);
    assert!(
        seen.members
            .iter()
            .any(|m| m.is_you && m.member.email == "bob@example.com")
    );

    // Carol's invite is pending when bob is removed: the new key is sealed to her invite too.
    let carol_account = find(&alice, "carol@example.com", &carol).await;
    alice
        .vault
        .mark_verified(&carol_account.account_id, &carol_account.fingerprint)
        .unwrap();
    alice.vault.invite_to_family(&carol_account).await.unwrap();
    assert_eq!(
        alice
            .vault
            .get_family()
            .await
            .unwrap()
            .family
            .unwrap()
            .invites
            .len(),
        1
    );
    alice
        .vault
        .remove_family_member(&bob_account.account_id)
        .await
        .unwrap();
    bob.vault.sync().await.unwrap();
    assert!(!has_vault(&bob, &family.vault_id));
    carol.vault.accept_family_invite(&family.id).await.unwrap();
    assert_eq!(titles(&carol, &family.vault_id), ["Streaming"]);
    save(&carol, &family.vault_id, "Groceries").await.unwrap();

    // Bob is invited again and declines; carol leaves; then the family goes.
    alice.vault.invite_to_family(&bob_account).await.unwrap();
    bob.vault.decline_family_invite(&family.id).await.unwrap();
    assert!(bob.vault.get_family().await.unwrap().invitations.is_empty());
    alice.vault.invite_to_family(&bob_account).await.unwrap();
    alice
        .vault
        .cancel_family_invite(&bob_account.account_id)
        .await
        .unwrap();
    assert!(bob.vault.get_family().await.unwrap().invitations.is_empty());
    carol.vault.leave_family().await.unwrap();
    assert!(!has_vault(&carol, &family.vault_id));
    assert_eq!(
        bob.vault.delete_family().await.unwrap_err().code,
        ErrorCode::NotFound
    );
    alice.vault.delete_family().await.unwrap();
    assert!(alice.vault.get_family().await.unwrap().family.is_none());
    assert!(!has_vault(&alice, &family.vault_id));
}

#[tokio::test]
async fn share_links_open_once_with_their_passphrase() {
    let server = server().await;
    let alice = sign_up(&server, "alice@example.com").await;
    let personal = alice.personal_vault();
    let mut draft = login(&personal, "Bank", "now");
    draft.overview["favorite"] = json!(true);
    let item = alice.vault.save_item(draft).await.unwrap();
    // A changed password leaves history, which the link doesn't carry.
    let mut edit = login(&personal, "Bank", "newer");
    edit.id = Some(item.id.clone());
    edit.revision = Some(item.revision);
    alice.vault.save_item(edit).await.unwrap();

    let options = |hours, views, passphrase: Option<&str>| ShareLinkOptions {
        expires_in_hours: hours,
        max_views: views,
        passphrase: passphrase.map(Into::into),
    };
    assert_eq!(
        alice
            .vault
            .create_share_link(&item.id, options(0, 1, None))
            .await
            .unwrap_err()
            .code,
        ErrorCode::ServerError
    );
    let link = alice
        .vault
        .create_share_link(&item.id, options(24, 2, Some("blue heron")))
        .await
        .unwrap();
    let listed = alice.vault.list_share_links().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        (
            listed[0].item_title.as_deref(),
            listed[0].max_views,
            listed[0].passphrase_required
        ),
        (Some("Bank"), 2, true)
    );

    // Someone without an account on this device opens it.
    let viewer = Device::new(&server);
    let envelope = viewer
        .vault
        .fetch_share_link(&server.url, &link.id)
        .await
        .unwrap();
    assert_eq!(
        (envelope.views_left, envelope.passphrase_required),
        (1, true)
    );
    assert_eq!(
        viewer
            .vault
            .open_share_link(
                envelope.ciphertext.clone(),
                link.key.clone(),
                Some(secret("wrong"))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::WrongPassphrase
    );
    assert_eq!(
        viewer
            .vault
            .open_share_link(
                envelope.ciphertext.clone(),
                "not-the-key".into(),
                Some(secret("blue heron"))
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidShareLink
    );
    let shared = viewer
        .vault
        .open_share_link(
            envelope.ciphertext,
            link.key.clone(),
            Some(secret("blue heron")),
        )
        .await
        .unwrap();
    assert_eq!(shared.overview["title"], "Bank");
    assert_eq!(shared.details["password"], "newer");
    assert!(shared.overview.get("favorite").is_none());
    assert!(shared.details.get("passwordHistory").is_none());
    assert_eq!(alice.vault.list_share_links().await.unwrap()[0].views, 1);

    alice.vault.revoke_share_link(&link.id).await.unwrap();
    assert!(alice.vault.list_share_links().await.unwrap().is_empty());
    assert_eq!(
        viewer
            .vault
            .fetch_share_link(&server.url, &link.id)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    // Revoking again is fine: it's gone either way.
    alice.vault.revoke_share_link(&link.id).await.unwrap();
}

#[tokio::test]
async fn emergency_contacts_open_the_vaults_after_release() {
    let server = server().await;
    let alice = sign_up(&server, "alice@example.com").await;
    let bob = sign_up(&server, "bob@example.com").await;
    let carol = sign_up(&server, "carol@example.com").await;
    let personal = alice.personal_vault();
    let will = save(&alice, &personal, "Will").await.unwrap();
    let file = alice
        .vault
        .add_attachment(&will, "will.txt", "text/plain", b"to bob".to_vec())
        .await
        .unwrap();
    let file_id = file.details["attachments"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let team = alice.vault.create_vault("Team").await.unwrap().id;
    save(&alice, &team, "Router").await.unwrap();

    // Bob gets the whole account, after alice approves his request.
    let bob_account = find(&alice, "bob@example.com", &bob).await;
    let scope = EmergencyScope::Account;
    assert_eq!(
        alice
            .vault
            .add_emergency_contact(&bob_account, 0, EmergencyAccessLevel::View, scope.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ServerError
    );
    let contact = alice
        .vault
        .add_emergency_contact(&bob_account, 7, EmergencyAccessLevel::View, scope)
        .await
        .unwrap();
    assert_eq!(contact.status, EmergencyStatus::Idle);
    let received = bob.vault.list_emergency_contacts().await.unwrap().received;
    assert_eq!(received[0].grantor_email, "alice@example.com");
    assert_eq!(
        bob.vault
            .open_emergency_access(&contact.id)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotAllowed
    );
    assert_eq!(
        alice
            .vault
            .emergency_action(&contact.id, "request")
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotAllowed
    );
    bob.vault
        .emergency_action(&contact.id, "request")
        .await
        .unwrap();
    alice
        .vault
        .emergency_action(&contact.id, "approve")
        .await
        .unwrap();

    let view = bob.vault.open_emergency_access(&contact.id).await.unwrap();
    let names: Vec<&str> = view.vaults.iter().map(|v| v.name.as_str()).collect();
    assert!(
        names.contains(&"Personal") && names.contains(&"Team"),
        "{names:?}"
    );
    assert!(
        view.vaults
            .iter()
            .all(|v| v.role == VaultRole::Read && !v.untrusted)
    );
    let mut items: Vec<&str> = view.items.iter().map(|item| item.title()).collect();
    items.sort();
    assert_eq!(items, ["Router", "Will"]);
    assert_eq!(
        bob.vault
            .emergency_attachment(&contact.id, &will, &file_id)
            .await
            .unwrap(),
        b"to bob"
    );
    assert!(
        !has_vault(&bob, &personal),
        "nothing of alice's lands in bob's own vaults"
    );

    // Alice ends it: bob can no longer open anything.
    alice
        .vault
        .emergency_action(&contact.id, "deny")
        .await
        .unwrap();
    assert_eq!(
        bob.vault
            .emergency_attachment(&contact.id, &will, &file_id)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotAllowed
    );

    // Carol gets only the shared vault, once the waiting period runs out without a denial.
    let carol_account = find(&alice, "carol@example.com", &carol).await;
    let scope = EmergencyScope::Vault {
        vault_id: team.clone(),
    };
    let contact = alice
        .vault
        .add_emergency_contact(&carol_account, 1, EmergencyAccessLevel::View, scope)
        .await
        .unwrap();
    carol
        .vault
        .emergency_action(&contact.id, "request")
        .await
        .unwrap();
    server.state.clock.advance(Duration::from_secs(86_400 + 60));
    let view = carol
        .vault
        .open_emergency_access(&contact.id)
        .await
        .unwrap();
    assert_eq!(view.vaults.len(), 1);
    assert_eq!(
        (view.vaults[0].id.as_str(), view.vaults[0].name.as_str()),
        (team.as_str(), "Team")
    );
    let items: Vec<&str> = view.items.iter().map(|item| item.title()).collect();
    assert_eq!(items, ["Router"]);
    assert_eq!(
        carol
            .vault
            .emergency_attachment(&contact.id, &will, &file_id)
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );

    // Carol steps down; alice's log has it all.
    carol
        .vault
        .remove_emergency_contact(&contact.id)
        .await
        .unwrap();
    assert!(
        alice
            .vault
            .list_emergency_contacts()
            .await
            .unwrap()
            .granted
            .iter()
            .all(|c| c.id != contact.id)
    );
    let log: Vec<SecurityEventType> = alice
        .vault
        .security_log()
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.event_type)
        .collect();
    for expected in [
        SecurityEventType::EmergencyContactAdded,
        SecurityEventType::EmergencyAccessRequested,
        SecurityEventType::EmergencyAccessApproved,
        SecurityEventType::EmergencyAccessDenied,
        SecurityEventType::EmergencyAccessReleased,
        SecurityEventType::EmergencyContactRemoved,
    ] {
        assert!(log.contains(&expected), "{expected:?} in {log:?}");
    }
}

#[tokio::test]
async fn lists_renames_and_signs_out_devices() {
    let server = server().await;
    let alice = sign_up(&server, "alice@example.com").await;
    let bob = sign_up(&server, "bob@example.com").await;
    let team = alice.vault.create_vault("Team").await.unwrap().id;
    alice
        .vault
        .add_member(
            &team,
            &find(&alice, "bob@example.com", &bob).await,
            VaultRole::Owner,
        )
        .await
        .unwrap();
    alice.vault.create_vault("Mine").await.unwrap();

    let laptop = Device::new(&server);
    laptop
        .vault
        .sign_in(
            &server.url,
            "alice@example.com",
            secret(PASSWORD),
            Some(secret(&alice.vault.secret_key().unwrap())),
        )
        .await
        .unwrap();

    let devices = alice.vault.list_devices().await.unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices.iter().filter(|d| d.current).count(), 1);
    assert_eq!(
        alice
            .vault
            .rename_device(&"x".repeat(65))
            .await
            .unwrap_err()
            .code,
        ErrorCode::ServerError
    );
    alice.vault.rename_device(" Work Mac ").await.unwrap();
    let devices = alice.vault.list_devices().await.unwrap();
    assert_eq!(devices.iter().find(|d| d.current).unwrap().name, "Work Mac");

    // What deleting the account would take: two devices, and the vault only alice owns.
    let summary = alice.vault.account_summary().await.unwrap();
    assert_eq!(summary.device_count, 2);
    assert_eq!(summary.shared_vaults_owned, ["Mine"]);

    let other = devices.iter().find(|d| !d.current).unwrap();
    alice.vault.sign_out_device(&other.id).await.unwrap();
    assert_eq!(alice.vault.list_devices().await.unwrap().len(), 1);
    assert!(
        laptop.vault.sync().await.is_err(),
        "the other device's session is gone"
    );
}

#[tokio::test]
async fn rotates_the_secret_key_and_vault_keys_and_follows_on_another_device() {
    let server = server().await;
    let laptop = sign_up(&server, "kit@example.com").await;
    let vault_id = laptop.vault.list_vaults().unwrap()[0].id.clone();
    save(&laptop, &vault_id, "Bank").await.unwrap();
    let secret_key = laptop.vault.secret_key().unwrap();
    let phone = Device::new(&server);
    phone
        .vault
        .sign_in(
            &server.url,
            "kit@example.com",
            secret(PASSWORD),
            Some(secret(&secret_key)),
        )
        .await
        .unwrap();

    // On demand, with a device still on the old key.
    laptop.vault.rotate_vault_key(&vault_id).await.unwrap();
    assert_eq!(titles(&laptop, &vault_id), ["Bank"]);
    save(&phone, &vault_id, "From the phone").await.unwrap();
    laptop.vault.sync().await.unwrap();
    assert_eq!(titles(&laptop, &vault_id), ["Bank", "From the phone"]);
    let log = laptop.vault.security_log().await.unwrap();
    assert_eq!(log[0].event_type, SecurityEventType::VaultKeyRotated);

    // The Secret Key: a wrong password changes nothing, and the new key is kept here.
    let wrong = laptop.vault.rotate_secret_key(secret("wrong"), false).await;
    assert_eq!(wrong.unwrap_err().code, ErrorCode::InvalidCredentials);
    let kit = laptop
        .vault
        .rotate_secret_key(secret(PASSWORD), false)
        .await
        .unwrap();
    assert_ne!(kit.secret_key, secret_key);
    assert!(kit.recovery_code.is_none());
    assert_eq!(laptop.vault.secret_key().unwrap(), kit.secret_key);
    laptop.vault.lock();
    laptop.vault.unlock(secret(PASSWORD)).await.unwrap();

    // The phone was signed out, and the key it remembers is out of date: the typed one wins.
    let stale = Device::new(&server);
    let refused = stale
        .vault
        .sign_in(
            &server.url,
            "kit@example.com",
            secret(PASSWORD),
            Some(secret(&secret_key)),
        )
        .await;
    assert_eq!(refused.unwrap_err().code, ErrorCode::InvalidCredentials);
    phone
        .vault
        .sign_in(
            &server.url,
            "kit@example.com",
            secret(PASSWORD),
            Some(secret(&kit.secret_key)),
        )
        .await
        .unwrap();
    assert_eq!(titles(&phone, &vault_id), ["Bank", "From the phone"]);
}

#[tokio::test]
async fn takes_over_once_released_and_the_kit_opens_the_account() {
    let server = server().await;
    let grantor = sign_up(&server, "grace@example.com").await;
    let contact = sign_up(&server, "carl@example.com").await;
    let vault_id = grantor.vault.list_vaults().unwrap()[0].id.clone();
    save(&grantor, &vault_id, "Pension").await.unwrap();

    let account = find(&grantor, "carl@example.com", &contact).await;
    let record = grantor
        .vault
        .add_emergency_contact(
            &account,
            1,
            EmergencyAccessLevel::Takeover,
            EmergencyScope::Account,
        )
        .await
        .unwrap();
    let id = record.id.clone();
    let early = contact
        .vault
        .take_over_account(&id, secret(PASSWORD), secret("A new password 12"))
        .await;
    assert_eq!(early.unwrap_err().code, ErrorCode::NotAllowed);

    contact
        .vault
        .emergency_action(&id, "request")
        .await
        .unwrap();
    grantor
        .vault
        .emergency_action(&id, "approve")
        .await
        .unwrap();
    let wrong = contact
        .vault
        .take_over_account(&id, secret("wrong"), secret("A new password 12"))
        .await;
    assert_eq!(wrong.unwrap_err().code, ErrorCode::InvalidCredentials);
    let kit = contact
        .vault
        .take_over_account(&id, secret(PASSWORD), secret("A new password 12"))
        .await
        .unwrap();
    assert_eq!(kit.email, "grace@example.com");
    assert!(kit.recovery_code.is_some());

    // The kit opens the account on a new device, with everything in it.
    let fresh = Device::new(&server);
    fresh
        .vault
        .sign_in(
            &server.url,
            "grace@example.com",
            secret("A new password 12"),
            Some(secret(&kit.secret_key)),
        )
        .await
        .unwrap();
    assert_eq!(titles(&fresh, &vault_id), ["Pension"]);
    let log = fresh.vault.security_log().await.unwrap();
    assert_eq!(log[0].event_type, SecurityEventType::EmergencyTakeover);
}
