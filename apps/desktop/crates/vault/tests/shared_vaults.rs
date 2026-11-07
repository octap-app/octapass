//! Shared and family vaults on the desktop against the real sync server: a member opens the
//! vaults shared with it once their grant verifies, keeps working through a key rotation, loses
//! a vault it was removed from, can't write to a read-only one, and is warned about one whose
//! grant doesn't verify.
//!
//! The owner here shares with its own keys and raw server calls, as the web vault does, so these
//! are vaults another client made; `sharing.rs` covers the desktop's own sharing.

use crate::common;

use common::{Device, PASSWORD, Server, login, secret, server};
use octapass_api::MembersResponse;
use octapass_core::account::new_id;
use octapass_core::encoding::b64_decode_array;
use octapass_core::sharing::Role;
use octapass_core::sharing::grant::{Recipient, SignedGrant};
use octapass_core::sharing::vault::ItemKey;
use octapass_desktop_vault::ErrorCode;
use octapass_desktop_vault::model::{ItemDraft, Vault as VaultView};
use rand_core::OsRng;
use serde_json::{Value, json};

const NOW: u64 = 1_761_177_600_000;

struct Member {
    device: Device,
    email: String,
    server_url: String,
}

async fn sign_up(server: &Server, email: &str) -> Member {
    let device = Device::new(server);
    let started = device
        .vault
        .start_signup(&server.url, email, secret(PASSWORD))
        .await
        .unwrap();
    let code = started.dev_verification_code.unwrap();
    device
        .vault
        .finish_signup(&started.signup_id, &code)
        .await
        .unwrap();
    Member {
        device,
        email: email.into(),
        server_url: server.url.clone(),
    }
}

impl Member {
    fn vaults(&self) -> Vec<VaultView> {
        self.device.vault.list_vaults().unwrap()
    }

    fn vault_named(&self, name: &str) -> VaultView {
        self.vaults()
            .into_iter()
            .find(|vault| vault.name == name)
            .unwrap_or_else(|| panic!("no vault named {name}"))
    }

    fn titles(&self, vault_id: &str) -> Vec<String> {
        let mut titles: Vec<String> = self
            .device
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

    async fn save(&self, vault_id: &str, title: &str) -> Result<String, ErrorCode> {
        self.device
            .vault
            .save_item(login(vault_id, title, &format!("{title}-secret")))
            .await
            .map(|item| item.id)
            .map_err(|error| error.code)
    }

    async fn sync(&self) {
        self.device.vault.sync().await.unwrap();
    }

    fn account_id(&self) -> String {
        self.device
            .vault
            .with_keys(|core, _| core.bundle().account_id.clone().unwrap())
            .unwrap()
    }

    /// An authenticated JSON call to the server, as the account.
    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Value {
        let token = self.device.vault.current_access_token().await.unwrap();
        let mut request = reqwest::Client::new()
            .request(method.clone(), format!("{}/{path}", self.server_url))
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        let text = response.text().await.unwrap();
        assert!(status.is_success(), "{method} {path}: {status} {text}");
        serde_json::from_str(&text).unwrap_or(Value::Null)
    }

    // ---------- Sharing, as the web vault does it ----------

    /// Creates a shared vault named by a `vaultInfo` record inside it, or a family and its vault.
    async fn create_vault(&self, name: &str, family: bool) -> String {
        let created = self
            .device
            .vault
            .with_keys(|core, _| core.create_shared_vault(NOW, &mut OsRng).unwrap())
            .unwrap();
        let vault = json!({
            "id": created.id,
            "keyId": created.key_id,
            "grant": serde_json::to_value(&created.grant).unwrap(),
        });
        if family {
            let id = new_id(NOW, &mut OsRng);
            let body = json!({ "id": id, "vault": vault });
            self.call(reqwest::Method::POST, "v1/families", Some(body))
                .await;
        } else {
            self.call(reqwest::Method::POST, "v1/vaults", Some(vault))
                .await;
        }
        self.sync().await;
        if !family {
            let draft: ItemDraft = serde_json::from_value(json!({
                "vaultId": created.id,
                "overview": { "schemaVersion": 1, "type": "vaultInfo", "title": name },
                "details": { "schemaVersion": 1 },
            }))
            .unwrap();
            self.device.vault.save_item(draft).await.unwrap();
        }
        created.id
    }

    async fn recipient(&self, member: &Member, role: Role) -> Recipient {
        let path = format!(
            "v1/accounts/lookup?email={}",
            member.email.replace('@', "%40")
        );
        let found = self.call(reqwest::Method::GET, &path, None).await;
        Recipient {
            account_id: found["accountId"].as_str().unwrap().into(),
            public_enc_key: b64_decode_array(found["publicEncKey"].as_str().unwrap()).unwrap(),
            public_pq_key: None,
            role,
        }
    }

    async fn grant(&self, vault_id: &str, recipient: &Recipient) -> SignedGrant {
        self.sync().await;
        self.device
            .vault
            .with_keys(|core, _| {
                core.grant_vault(vault_id, recipient, NOW, &mut OsRng)
                    .unwrap()
            })
            .unwrap()
    }

    fn key_id(&self, vault_id: &str) -> Value {
        self.device
            .vault
            .with_keys(|_, cache| json!(cache.vault(vault_id).unwrap().key_id))
            .unwrap()
    }

    async fn add_member(&self, vault_id: &str, member: &Member, role: Role) {
        let grant = self
            .grant(vault_id, &self.recipient(member, role).await)
            .await;
        self.send_grant(vault_id, member, &grant).await;
    }

    async fn send_grant(&self, vault_id: &str, member: &Member, grant: &SignedGrant) {
        let body = json!({ "email": member.email, "grant": grant, "keyId": self.key_id(vault_id) });
        self.call(
            reqwest::Method::POST,
            &format!("v1/vaults/{vault_id}/members"),
            Some(body),
        )
        .await;
    }

    async fn invite_to_family(&self, member: &Member) -> String {
        let families = self.call(reqwest::Method::GET, "v1/families", None).await;
        let family_id = families["family"]["id"].as_str().unwrap().to_owned();
        let vault_id = families["family"]["vaultId"].as_str().unwrap().to_owned();
        let recipient = self.recipient(member, Role::Write).await;
        let grant = self.grant(&vault_id, &recipient).await;
        let body =
            json!({ "email": member.email, "grant": grant, "keyId": self.key_id(&vault_id) });
        self.call(
            reqwest::Method::POST,
            &format!("v1/families/{family_id}/invites"),
            Some(body),
        )
        .await;
        family_id
    }

    /// Removes a member and gives the vault a new key, as the web vault does.
    async fn remove_member(&self, vault_id: &str, member: &Member) {
        let path = format!("v1/vaults/{vault_id}/members/{}", member.account_id());
        self.call(reqwest::Method::DELETE, &path, None).await;
        self.sync().await;
        let path = format!("v1/vaults/{vault_id}/members");
        let members: MembersResponse =
            serde_json::from_value(self.call(reqwest::Method::GET, &path, None).await).unwrap();
        let recipients: Vec<Recipient> = members
            .members
            .iter()
            .map(|member| Recipient {
                account_id: member.account_id.clone(),
                public_enc_key: b64_decode_array(&member.public_enc_key).unwrap(),
                public_pq_key: None,
                role: serde_json::from_value(json!(member.role)).unwrap(),
            })
            .collect();
        let (revision, rotation) = self
            .device
            .vault
            .with_keys(|core, cache| {
                let items: Vec<ItemKey> = cache
                    .items
                    .iter()
                    .filter(|record| record.vault_id == vault_id)
                    .map(|record| ItemKey {
                        item_id: record.id.clone(),
                        encrypted_item_key: record.encrypted_item_key.clone(),
                    })
                    .collect();
                let rotation = core
                    .rotate_vault_key(vault_id, &recipients, &items, NOW, &mut OsRng)
                    .unwrap();
                (cache.vault(vault_id).unwrap().revision, rotation)
            })
            .unwrap();
        let body = json!({
            "revision": revision,
            "keyId": rotation.key_id,
            "grants": rotation.grants,
            "items": rotation.items,
        });
        self.call(
            reqwest::Method::POST,
            &format!("v1/vaults/{vault_id}/rotate"),
            Some(body),
        )
        .await;
        self.sync().await;
    }
}

#[tokio::test]
async fn members_open_shared_and_family_vaults() {
    let server = server().await;
    let alice = sign_up(&server, "alice@example.com").await;
    let bob = sign_up(&server, "bob@example.com").await;
    let carol = sign_up(&server, "carol@example.com").await;

    // Alice shares a vault with a login and a file in it: bob may write, carol only read.
    let team = alice.create_vault("Team", false).await;
    let router = alice.save(&team, "Router").await.unwrap();
    let file = alice
        .device
        .vault
        .add_attachment(&router, "notes.txt", "text/plain", b"port 8080".to_vec())
        .await
        .unwrap();
    let file_id = file.details["attachments"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    alice.add_member(&team, &bob, Role::Write).await;
    alice.add_member(&team, &carol, Role::Read).await;

    // Bob's desktop opens it by its grant: named, listed and readable, with the file.
    bob.sync().await;
    let shared = bob.vault_named("Team");
    assert_eq!(shared.id, team);
    assert!(!shared.untrusted);
    assert_eq!(
        bob.titles(&team),
        ["Router"],
        "the name record isn't an item"
    );
    let item = bob.device.vault.get_item(&router).unwrap();
    assert_eq!(item.details["password"], "Router-secret");
    assert_eq!(
        bob.device
            .vault
            .get_attachment(&router, &file_id)
            .await
            .unwrap(),
        b"port 8080"
    );
    bob.save(&team, "Printer").await.unwrap();
    alice.sync().await;
    assert_eq!(alice.titles(&team), ["Printer", "Router"]);

    // Carol reads but can't write.
    carol.sync().await;
    assert_eq!(carol.titles(&team), ["Printer", "Router"]);
    assert_eq!(
        carol.save(&team, "Mine").await,
        Err(ErrorCode::ReadOnlyVault)
    );

    // A family: bob accepts alice's invite and sees the Family vault.
    alice.create_vault("Family", true).await;
    let family_id = alice.invite_to_family(&bob).await;
    let path = format!("v1/families/{family_id}/invites/accept");
    bob.call(reqwest::Method::POST, &path, Some(json!({})))
        .await;
    let family = alice.vault_named("Family").id;
    alice.save(&family, "Streaming").await.unwrap();
    bob.sync().await;
    assert_eq!(bob.vault_named("Family").id, family);
    assert_eq!(bob.titles(&family), ["Streaming"]);

    // Carol is removed and the key rotated: bob keeps reading and writing under the new key,
    // and carol loses the vault.
    alice.remove_member(&team, &carol).await;
    bob.sync().await;
    assert_eq!(bob.titles(&team), ["Printer", "Router"]);
    assert_eq!(
        bob.device.vault.get_item(&router).unwrap().details["password"],
        "Router-secret"
    );
    bob.save(&team, "Scanner").await.unwrap();
    alice.sync().await;
    assert_eq!(alice.titles(&team), ["Printer", "Router", "Scanner"]);
    carol.sync().await;
    assert!(carol.vaults().iter().all(|vault| vault.id != team));
    assert!(carol.device.vault.get_item(&router).is_err());

    // The vaults survive a restart (they open again from the local copy).
    let Member { device, .. } = bob;
    let bob = device.restart(&server);
    bob.vault
        .unlock(secret(PASSWORD))
        .await
        .expect("unlocks with the password");
    let names: Vec<String> = bob
        .vault
        .list_vaults()
        .unwrap()
        .into_iter()
        .map(|vault| vault.name)
        .collect();
    assert!(names.contains(&"Team".to_owned()), "{names:?}");
    assert!(names.contains(&"Family".to_owned()), "{names:?}");
    assert!(
        bob.vault
            .list_items()
            .unwrap()
            .iter()
            .any(|item| item.title == "Scanner")
    );
}

#[tokio::test]
async fn a_grant_that_does_not_verify_is_flagged() {
    let server = server().await;
    let alice = sign_up(&server, "alice@example.com").await;
    let bob = sign_up(&server, "bob@example.com").await;

    // The grant's role no longer matches what was signed, as if the server had changed it.
    let vault = alice.create_vault("Tampered", false).await;
    alice.save(&vault, "Router").await.unwrap();
    let mut grant = alice
        .grant(&vault, &alice.recipient(&bob, Role::Read).await)
        .await;
    grant.role = Role::Write;
    alice.send_grant(&vault, &bob, &grant).await;

    bob.sync().await;
    let listed: Vec<VaultView> = bob
        .vaults()
        .into_iter()
        .filter(|listed| listed.id == vault)
        .collect();
    assert_eq!(listed.len(), 1, "the vault stays listed, with a warning");
    assert!(listed[0].untrusted);
    assert_eq!(serde_json::to_value(&listed[0]).unwrap()["untrusted"], true);
    assert!(bob.titles(&vault).is_empty(), "its items stay closed");
    assert_eq!(
        bob.save(&vault, "Mine").await,
        Err(ErrorCode::UntrustedVault)
    );

    // A correct grant replaces it, and the vault opens.
    let grant = alice
        .grant(&vault, &alice.recipient(&bob, Role::Read).await)
        .await;
    alice.send_grant(&vault, &bob, &grant).await;
    bob.sync().await;
    assert!(!bob.vault_named("Tampered").untrusted);
    assert_eq!(bob.titles(&vault), ["Router"]);
}
