//! Accounts with real keys, so sharing tests seal, sign and decrypt with
//! `octapass-core` exactly as clients do, and the sharing calls they make.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{Method, StatusCode};
use ed25519_dalek::SigningKey;
use octapass_core::account::AccountBundle;
use octapass_core::envelope::{Context, seal_b64, wrap_key};
use octapass_core::item::Item;
use octapass_core::keys::SymmetricKey;
use octapass_core::session::{EncryptedItem, Session};
use octapass_core::sharing::Role;
use octapass_core::sharing::grant::{Recipient, SignedGrant};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};

use super::{Response, TestServer, b64, envelope, new_id, random_bytes, unb64};

pub struct Person {
    pub email: String,
    pub account_id: String,
    pub personal_vault: String,
    pub token: String,
    pub session: Session,
}

pub fn now_ms() -> u64 {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    u64::try_from(elapsed.as_millis()).unwrap()
}

impl Person {
    pub fn recipient(&self, role: Role) -> Recipient {
        Recipient {
            account_id: self.account_id.clone(),
            public_enc_key: self.session.key_pairs().public_enc_key(),
            public_pq_key: self.session.pq_keys().map(|keys| keys.public_key().clone()),
            role,
        }
    }

    pub fn public_sign_key(&self) -> [u8; 32] {
        self.session.key_pairs().public_sign_key()
    }

    pub fn grant(&self, vault_id: &str, to: &Person, role: Role) -> Value {
        let grant = self
            .session
            .grant_vault(vault_id, &to.recipient(role), now_ms(), &mut OsRng)
            .unwrap();
        serde_json::to_value(grant).unwrap()
    }

    /// Encrypts a login titled `title` for the vault, as a PUT body.
    pub fn item(&self, vault_id: &str, item_id: &str, title: &str) -> Value {
        let item = Item::from_json(
            &json!({ "overview": { "title": title, "type": "login" }, "details": { "password": "pw" } })
                .to_string(),
        )
        .unwrap();
        let encrypted = self
            .session
            .encrypt_item(vault_id, item_id, &item, None, &mut OsRng)
            .unwrap();
        serde_json::to_value(encrypted).unwrap()
    }

    /// The title of an `ItemRecord` (or anything with its encrypted fields).
    pub fn title(&self, record: &Value) -> String {
        let encrypted: EncryptedItem = serde_json::from_value(record.clone()).unwrap();
        let vault_id = record["vaultId"].as_str().unwrap();
        let item_id = record["id"].as_str().unwrap();
        self.session
            .decrypt_overview(vault_id, item_id, &encrypted)
            .unwrap()
            .title
    }
}

/// A grant for a `VaultRecord` from sync: the record carries every field.
pub fn grant_from_record(record: &Value, recipient_account_id: &str) -> (SignedGrant, [u8; 32]) {
    let grant = SignedGrant {
        vault_id: record["id"].as_str().unwrap().to_owned(),
        recipient_account_id: recipient_account_id.to_owned(),
        role: serde_json::from_value(record["role"].clone()).unwrap(),
        wrapped_vault_key: record["wrappedVaultKey"].as_str().unwrap().to_owned(),
        granted_by: record["grant"]["grantedBy"].as_str().unwrap().to_owned(),
        granted_at: record["grant"]["grantedAt"].as_u64().unwrap(),
        signature: record["grant"]["signature"].as_str().unwrap().to_owned(),
    };
    let granter: [u8; 32] = unb64(&record["grant"]["granterPublicSignKey"])
        .try_into()
        .unwrap();
    (grant, granter)
}

impl TestServer {
    /// Signs up and in with real account keys, and opens the personal vault.
    pub async fn person(&self, email: &str) -> Person {
        let (ask, auk) = (
            SymmetricKey::generate(&mut OsRng),
            SymmetricKey::generate(&mut OsRng),
        );
        let encryption = StaticSecret::random_from_rng(OsRng);
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        // The documented layout of wrappedPrivateKeys: x25519 secret ‖ ed25519 seed.
        let private_keys = [encryption.to_bytes(), seed].concat();
        let vault_id = new_id();
        let wrapped_vault_key = wrap_key(
            &ask,
            &Context::VaultKey {
                vault_id: &vault_id,
            },
            &SymmetricKey::generate(&mut OsRng),
            &mut OsRng,
        )
        .unwrap();
        let account = json!({
            "email": email,
            "kdf": { "algorithm": "argon2id", "memoryKib": 65536, "iterations": 3, "parallelism": 1 },
            "accountSalt": b64(random_bytes(16)),
            "wrappedAsk": wrap_key(&auk, &Context::Ask, &ask, &mut OsRng).unwrap(),
            "publicEncKey": b64(PublicKey::from(&encryption).as_bytes()),
            "publicSignKey": b64(signing.verifying_key().as_bytes()),
            "wrappedPrivateKeys": seal_b64(&ask, &Context::PrivateKeys, &private_keys, &mut OsRng).unwrap(),
            "recoveryWrappedAsk": envelope(48),
        });
        let personal_vault = json!({ "id": vault_id, "wrappedVaultKey": wrapped_vault_key });
        self.register_with(email, |code, upload| {
            json!({
                "email": email,
                "verificationCode": code,
                "registrationUpload": upload,
                "account": account,
                "personalVault": personal_vault,
            })
        })
        .await;

        let device = self.login(email, "Laptop").await;
        let bundle: AccountBundle = serde_json::from_value(device.account.clone()).unwrap();
        let mut session = Session::unlock(bundle, &auk).unwrap();
        session.open_vault(&vault_id, &wrapped_vault_key).unwrap();
        Person {
            email: email.to_owned(),
            account_id: device.account["accountId"].as_str().unwrap().to_owned(),
            personal_vault: vault_id,
            token: device.access_token,
            session,
        }
    }

    pub async fn get_as(&self, person: &Person, path: &str) -> Response {
        self.get(path, &person.token).await
    }

    pub async fn send_as(
        &self,
        person: &Person,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Response {
        self.call(method, path, Some(&person.token), &[], body)
            .await
    }

    /// `POST /v1/vaults` with a vault `owner` just created in their session.
    pub async fn shared_vault(&self, owner: &mut Person) -> String {
        let vault = owner
            .session
            .create_shared_vault(now_ms(), &mut OsRng)
            .unwrap();
        let created = self
            .send_as(
                owner,
                Method::POST,
                "/v1/vaults",
                Some(serde_json::to_value(&vault).unwrap()),
            )
            .await;
        assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
        vault.id
    }

    pub async fn invite(&self, by: &Person, vault_id: &str, to: &Person, role: Role) -> Response {
        let body = json!({ "email": to.email, "grant": by.grant(vault_id, to, role) });
        let path = format!("/v1/vaults/{vault_id}/members");
        self.send_as(by, Method::POST, &path, Some(body)).await
    }

    /// Full sync, as the person.
    pub async fn sync_all(&self, person: &Person) -> Value {
        let synced = self.get_as(person, "/v1/sync").await;
        assert_eq!(synced.status, StatusCode::OK, "{:?}", synced.body);
        synced.body
    }

    /// The person's record of `vault_id` in a full sync, if they can see it.
    pub async fn vault_record(&self, person: &Person, vault_id: &str) -> Option<Value> {
        let synced = self.sync_all(person).await;
        synced["vaults"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vault| vault["id"] == vault_id)
            .cloned()
    }

    /// Syncs and opens the person's grant for `vault_id`, checking its signature.
    pub async fn open_shared_vault(&self, person: &mut Person, vault_id: &str) {
        let record = self.vault_record(person, vault_id).await.expect("a member");
        let (grant, granter) = grant_from_record(&record, &person.account_id);
        person.session.open_shared_vault(&grant, &granter).unwrap();
    }

    pub async fn put_new_item(&self, person: &Person, vault_id: &str, title: &str) -> Response {
        let item_id = new_id();
        let path = format!("/v1/vaults/{vault_id}/items/{item_id}");
        let body = person.item(vault_id, &item_id, title);
        self.call(
            Method::PUT,
            &path,
            Some(&person.token),
            &[("if-none-match", "*")],
            Some(body),
        )
        .await
    }
}
