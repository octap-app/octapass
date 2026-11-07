//! Shared and family vaults on the phone against the real sync server: a member's phone opens
//! the vaults shared with it once their grant verifies, keeps working through a key rotation,
//! loses a vault it was removed from, can't write to a read-only one, and warns about one whose
//! grant doesn't verify. The AutoFill extension (the `octapass-ffi` session over the same store)
//! fills from shared vaults too.
//!
//! The phone app can't share yet (that's the native app's API, `crates/octapass-mobile`), so the
//! owner here shares through its own session and server calls, as the web vault does.

use std::net::SocketAddr;
use std::sync::Arc;

use octapass_api::MembersResponse;
use octapass_core::account::new_id;
use octapass_core::encoding::b64_decode_array;
use octapass_core::sharing::Role;
use octapass_core::sharing::grant::{Recipient, SignedGrant};
use octapass_core::sharing::vault::ItemKey;
use octapass_ffi::DeviceInfo;
use octapass_ffi::{LocalStore, OctaPassError};
use octapass_mobile_vault::accounts::{Accounts, store_path};
use octapass_mobile_vault::model::{ItemDraft, Vault as VaultView};
use octapass_mobile_vault::native::fake::FakeNative;
use octapass_mobile_vault::{Config, ErrorCode, Vault};
use rand_core::OsRng;
use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery staple";
const NOW: u64 = 1_761_177_600_000;

struct Server {
    url: String,
    _data: TempDir,
    _runtime: tokio::runtime::Runtime,
}

fn server() -> Server {
    let data = tempfile::tempdir().unwrap();
    let data_dir = data.path().to_str().unwrap().to_owned();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let url = runtime.block_on(async {
        let config = octapass_server::Config::from_lookup(|name| match name {
            "OCTAPASS_DATA_DIR" => Some(data_dir.clone()),
            "OCTAPASS_DEV_MODE" => Some("true".into()),
            "OCTAPASS_RATE_LIMITS" => Some("off".into()),
            _ => None,
        })
        .unwrap();
        let state = octapass_server::AppState::new(config).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let app =
            octapass_server::router(state).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    });
    Server {
        url,
        _data: data,
        _runtime: runtime,
    }
}

struct Phone {
    vault: Arc<Vault>,
    native: Arc<FakeNative>,
    dir: TempDir,
    email: String,
    server_url: String,
}

impl Phone {
    /// A new account, signed up on its own phone.
    fn sign_up(server: &Server, email: &str) -> Self {
        let native = Arc::new(FakeNative::default());
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::new(
            Config {
                data_dir: dir.path().to_owned(),
                temp_dir: dir.path().join("tmp"),
                device: DeviceInfo {
                    name: "Test iPhone".into(),
                    platform: "ios".into(),
                },
                pwned_passwords_url: server.url.clone(),
            },
            native.clone(),
            Box::new(|_| {}),
        )
        .unwrap();
        let started = vault
            .start_signup(&server.url, email, Zeroizing::new(PASSWORD.into()))
            .unwrap();
        let code = started.dev_verification_code.unwrap();
        vault.finish_signup(&started.signup_id, &code).unwrap();
        Self {
            vault,
            native,
            dir,
            email: email.into(),
            server_url: server.url.clone(),
        }
    }

    fn vaults(&self) -> Vec<VaultView> {
        self.vault.list_vaults().unwrap()
    }

    fn vault_named(&self, name: &str) -> VaultView {
        self.vaults()
            .into_iter()
            .find(|vault| vault.name == name)
            .unwrap_or_else(|| panic!("no vault named {name}"))
    }

    fn personal(&self) -> String {
        self.vault_named("Personal").id
    }

    fn titles(&self, vault_id: &str) -> Vec<String> {
        let mut titles: Vec<String> = self
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

    fn save(&self, vault_id: &str, title: &str) -> Result<String, ErrorCode> {
        self.vault
            .save_item(login(vault_id, title))
            .map(|item| item.id)
            .map_err(|error| error.code)
    }

    fn account_id(&self) -> String {
        self.vault.access().unwrap().store().account_id().unwrap()
    }

    /// An authenticated JSON call to the server, as the account.
    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let access = self.vault.access().unwrap();
        let url = format!("{}/{path}", self.server_url);
        access
            .authorized(|token| {
                let auth = format!("Bearer {token}");
                let agent: ureq::Agent = ureq::Agent::config_builder()
                    .http_status_as_error(false)
                    .build()
                    .into();
                let response = match (method, &body) {
                    ("GET", _) => agent.get(&url).header("authorization", &auth).call(),
                    ("DELETE", _) => agent.delete(&url).header("authorization", &auth).call(),
                    (_, Some(body)) => agent
                        .post(&url)
                        .header("authorization", &auth)
                        .header("content-type", "application/json")
                        .send(serde_json::to_vec(body).unwrap()),
                    (_, None) => agent.post(&url).header("authorization", &auth).send_empty(),
                };
                let mut response = response.map_err(|error| OctaPassError::Network {
                    reason: error.to_string(),
                })?;
                let status = response.status().as_u16();
                let text = response.body_mut().read_to_string().unwrap_or_default();
                if status == 401 {
                    return Err(OctaPassError::Unauthorized);
                }
                assert!(status < 300, "{method} {path}: {status} {text}");
                Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
            })
            .unwrap()
    }

    // ---------- Sharing, as the web vault does it ----------

    /// Creates a shared vault (or, with `family`, a family and its vault) named by a `vaultInfo`
    /// record inside it.
    fn create_vault(&self, name: &str, family: bool) -> String {
        let access = self.vault.access().unwrap();
        let created = access
            .session()
            .with_keys(|core| Ok(core.create_shared_vault(NOW, &mut OsRng).unwrap()))
            .unwrap();
        drop(access);
        let vault = json!({
            "id": created.id,
            "keyId": created.key_id,
            "grant": serde_json::to_value(&created.grant).unwrap(),
        });
        if family {
            let id = new_id(NOW, &mut OsRng);
            self.call(
                "POST",
                "v1/families",
                Some(json!({ "id": id, "vault": vault })),
            );
        } else {
            self.call("POST", "v1/vaults", Some(vault));
        }
        self.vault.sync().unwrap();
        if !family {
            self.vault
                .save_item(ItemDraft {
                    id: None,
                    vault_id: created.id.clone(),
                    revision: None,
                    overview: json!({ "schemaVersion": 1, "type": "vaultInfo", "title": name }),
                    details: json!({ "schemaVersion": 1 }),
                })
                .unwrap();
        }
        created.id
    }

    fn recipient(&self, member: &Phone, role: Role) -> Recipient {
        let found = self.call(
            "GET",
            &format!(
                "v1/accounts/lookup?email={}",
                member.email.replace('@', "%40")
            ),
            None,
        );
        Recipient {
            account_id: found["accountId"].as_str().unwrap().into(),
            public_enc_key: b64_decode_array(found["publicEncKey"].as_str().unwrap()).unwrap(),
            public_pq_key: None,
            role,
        }
    }

    fn grant(&self, vault_id: &str, recipient: &Recipient) -> SignedGrant {
        self.vault.sync().unwrap();
        self.vault
            .access()
            .unwrap()
            .session()
            .with_keys(|core| {
                Ok(core
                    .grant_vault(vault_id, recipient, NOW, &mut OsRng)
                    .unwrap())
            })
            .unwrap()
    }

    fn key_id(&self, vault_id: &str) -> Value {
        let vaults = self.vault.access().unwrap().store().vaults();
        let vault = vaults.iter().find(|vault| vault.id == vault_id).unwrap();
        json!(vault.key_id)
    }

    fn add_member(&self, vault_id: &str, member: &Phone, role: Role) {
        let grant = self.grant(vault_id, &self.recipient(member, role));
        self.send_grant(vault_id, member, &grant);
    }

    fn send_grant(&self, vault_id: &str, member: &Phone, grant: &SignedGrant) {
        self.call(
            "POST",
            &format!("v1/vaults/{vault_id}/members"),
            Some(json!({ "email": member.email, "grant": grant, "keyId": self.key_id(vault_id) })),
        );
    }

    fn invite_to_family(&self, member: &Phone) -> String {
        let family = &self.call("GET", "v1/families", None)["family"];
        let (family_id, vault_id) = (family["id"].as_str().unwrap(), family["vaultId"].as_str());
        let grant = self.grant(vault_id.unwrap(), &self.recipient(member, Role::Write));
        self.call(
            "POST",
            &format!("v1/families/{family_id}/invites"),
            Some(json!({
                "email": member.email,
                "grant": grant,
                "keyId": self.key_id(vault_id.unwrap()),
            })),
        );
        family_id.into()
    }

    /// Removes a member and gives the vault a new key, as the web vault does.
    fn remove_member(&self, vault_id: &str, member: &Phone) {
        self.call(
            "DELETE",
            &format!("v1/vaults/{vault_id}/members/{}", member.account_id()),
            None,
        );
        self.vault.sync().unwrap();
        let members: MembersResponse = serde_json::from_value(self.call(
            "GET",
            &format!("v1/vaults/{vault_id}/members"),
            None,
        ))
        .unwrap();
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
        let access = self.vault.access().unwrap();
        let records: Vec<_> = access
            .store()
            .item_records()
            .into_iter()
            .filter(|record| record.vault_id == vault_id)
            .collect();
        let items: Vec<ItemKey> = records
            .iter()
            .map(|record| ItemKey {
                item_id: record.id.clone(),
                encrypted_item_key: record.encrypted_item_key.clone(),
            })
            .collect();
        let rotation = access
            .session()
            .with_keys(|core| {
                Ok(core
                    .rotate_vault_key(vault_id, &recipients, &items, NOW, &mut OsRng)
                    .unwrap())
            })
            .unwrap();
        let revision = access
            .store()
            .vaults()
            .into_iter()
            .find(|vault| vault.id == vault_id)
            .unwrap()
            .revision;
        drop(access);
        self.call(
            "POST",
            &format!("v1/vaults/{vault_id}/rotate"),
            Some(json!({
                "revision": revision,
                "keyId": rotation.key_id,
                "grants": rotation.grants,
                "items": rotation.items,
            })),
        );
        self.vault.sync().unwrap();
    }
}

fn login(vault_id: &str, title: &str) -> ItemDraft {
    ItemDraft {
        id: None,
        vault_id: vault_id.into(),
        revision: None,
        overview: json!({
            "schemaVersion": 1,
            "type": "login",
            "title": title,
            "urls": ["https://router.example.com"],
        }),
        details: json!({ "username": "admin", "password": format!("{title}-secret") }),
    }
}

#[test]
fn members_open_shared_and_family_vaults() {
    let server = server();
    let alice = Phone::sign_up(&server, "alice@example.com");
    let bob = Phone::sign_up(&server, "bob@example.com");
    let carol = Phone::sign_up(&server, "carol@example.com");

    // Alice shares a vault with a login and a file in it: bob may write, carol only read.
    let team = alice.create_vault("Team", false);
    let router = alice.save(&team, "Router").unwrap();
    let file = alice
        .vault
        .add_attachment(
            &router,
            "notes.txt",
            "text/plain",
            b"admin panel on port 8080",
        )
        .unwrap();
    let file_id = file.details["attachments"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    alice.vault.sync().unwrap();
    alice.add_member(&team, &bob, Role::Write);
    alice.add_member(&team, &carol, Role::Read);

    // Bob's phone opens it by its grant: named, listed and readable, with the file.
    bob.vault.sync().unwrap();
    let shared = bob.vault_named("Team");
    assert_eq!(shared.id, team);
    assert!(!shared.untrusted);
    assert_eq!(
        bob.titles(&team),
        ["Router"],
        "the name record isn't an item"
    );
    let item = bob.vault.get_item(&router).unwrap();
    assert_eq!(item.details["password"], "Router-secret");
    assert_eq!(
        bob.vault.get_attachment(&router, &file_id).unwrap(),
        b"admin panel on port 8080"
    );
    // And writes to it, which alice reads.
    bob.save(&team, "Printer").unwrap();
    alice.vault.sync().unwrap();
    assert_eq!(alice.titles(&team), ["Printer", "Router"]);

    // Carol reads but can't write.
    carol.vault.sync().unwrap();
    assert_eq!(carol.titles(&team), ["Printer", "Router"]);
    assert_eq!(carol.save(&team, "Mine"), Err(ErrorCode::ReadOnlyVault));

    // The AutoFill extension fills from the shared vault, from the same store.
    bob.vault.enable_device_unlock().unwrap();
    let account = Accounts::load(bob.dir.path())
        .unwrap()
        .current()
        .unwrap()
        .clone();
    let device_secret =
        bob.native.device_secrets.lock().unwrap()[&account.device_secret_name()].clone();
    let store = LocalStore::open(
        store_path(bob.dir.path(), &account)
            .to_string_lossy()
            .into_owned(),
    )
    .unwrap();
    let extension = store.unlock_with_device(device_secret).unwrap();
    let matches = extension
        .match_logins(store.clone(), "https://router.example.com/login".into())
        .unwrap();
    assert_eq!(matches.len(), 2, "{matches:?}");
    let filled = extension.get_item(store.clone(), router.clone()).unwrap();
    assert_eq!(
        filled.login.unwrap().password.as_deref(),
        Some("Router-secret")
    );
    extension.lock();

    // A family: bob accepts alice's invite and sees the Family vault.
    alice.create_vault("Family", true);
    let family_id = alice.invite_to_family(&bob);
    bob.call(
        "POST",
        &format!("v1/families/{family_id}/invites/accept"),
        Some(json!({})),
    );
    let family = alice.vault_named("Family").id;
    alice.save(&family, "Streaming").unwrap();
    bob.vault.sync().unwrap();
    assert_eq!(bob.vault_named("Family").id, family);
    assert_eq!(bob.titles(&family), ["Streaming"]);

    // Carol is removed and the key rotated: bob keeps reading and writing under the new key,
    // and carol's phone loses the vault.
    alice.remove_member(&team, &carol);
    bob.vault.sync().unwrap();
    assert_eq!(bob.titles(&team), ["Printer", "Router"]);
    assert_eq!(
        bob.vault.get_attachment(&router, &file_id).unwrap(),
        b"admin panel on port 8080"
    );
    bob.save(&team, "Scanner").unwrap();
    alice.vault.sync().unwrap();
    assert_eq!(alice.titles(&team), ["Printer", "Router", "Scanner"]);
    carol.vault.sync().unwrap();
    assert!(carol.vaults().iter().all(|vault| vault.id != team));
    assert!(carol.vault.get_item(&router).is_err());
    assert_eq!(carol.vaults().len(), 1, "only carol's own vault is left");

    // Bob's personal vault is unaffected by all of it.
    bob.save(&bob.personal(), "Mine").unwrap();
    assert_eq!(bob.titles(&bob.personal()), ["Mine"]);
}

#[test]
fn a_grant_that_does_not_verify_is_flagged() {
    let server = server();
    let alice = Phone::sign_up(&server, "alice@example.com");
    let bob = Phone::sign_up(&server, "bob@example.com");

    // The grant's role no longer matches what was signed, as if the server had changed it.
    let vault = alice.create_vault("Tampered", false);
    alice.save(&vault, "Router").unwrap();
    let mut grant = alice.grant(&vault, &alice.recipient(&bob, Role::Read));
    grant.role = Role::Write;
    alice.send_grant(&vault, &bob, &grant);

    bob.vault.sync().unwrap();
    let listed: Vec<VaultView> = bob
        .vaults()
        .into_iter()
        .filter(|listed| listed.id == vault)
        .collect();
    assert_eq!(listed.len(), 1, "the vault stays listed, with a warning");
    assert!(listed[0].untrusted);
    assert!(
        bob.vault
            .list_items()
            .unwrap()
            .iter()
            .all(|item| item.vault_id != vault),
        "its items stay closed"
    );
    assert_eq!(bob.save(&vault, "Mine"), Err(ErrorCode::UntrustedVault));
    let serialized = serde_json::to_value(&listed[0]).unwrap();
    assert_eq!(serialized["untrusted"], true);
    let personal = serde_json::to_value(bob.vault_named("Personal")).unwrap();
    assert!(personal.get("untrusted").is_none());

    // A correct grant later replaces it, and the vault opens.
    let grant = alice.grant(&vault, &alice.recipient(&bob, Role::Read));
    alice.send_grant(&vault, &bob, &grant);
    bob.vault.sync().unwrap();
    assert!(!bob.vault_named("Tampered").untrusted);
    assert_eq!(bob.titles(&vault), ["Router"]);
}
