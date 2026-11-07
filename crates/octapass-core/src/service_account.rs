//! Service accounts: how a CI job or a server reads one shared vault with no person present
//! (plan 03, "Non-human access").
//!
//! A service account is a vault member that isn't a person. Its token holds a random 256-bit root,
//! from which it derives an X25519 and an Ed25519 key. The vault key reaches it as an ordinary
//! [`SignedGrant`] sealed to that X25519 key, so nothing new protects the vault: the token is a
//! member's private key, generated on the creator's device and never sent to the server.
//!
//! ```text
//! encryption key = X25519(HKDF-SHA256(root, salt = id bytes, info = "octapass/v1/service-account/encryption"))
//! signing key    = Ed25519(HKDF-SHA256(root, salt = id bytes, info = "octapass/v1/service-account/signing"))
//! token          = "opsa1_" + base64url(0x01 ‖ id (16) ‖ vault id (16) ‖ root (32) ‖
//!                                       creator's public signing key (32) ‖ url length (u16 BE) ‖
//!                                       server URL ‖ SHA-256(everything before)[0..4])
//! auth message   = "octapass/v1/service-account-auth" ‖ 0x00 ‖
//!                  for each of id, challenge: len (u32 BE) ‖ UTF-8 bytes
//! ```
//!
//! The creator's public signing key is pinned in the token, so a grant is only believed when the
//! creator signed it: the server can't swap the sealed key or raise the role.

use core::fmt;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::CryptoRngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::account::{new_id, parse_id};
use crate::encoding::{b64_decode, b64_encode};
use crate::envelope::{Context, open_b64, seal_b64};
use crate::error::{Error, Result};
use crate::item::{Item, ItemOverview};
use crate::keys::{SymmetricKey, hkdf_key};
use crate::session::{EncryptedItem, Session, open_item, open_overview, seal_item};
use crate::sharing::Role;
use crate::sharing::grant::{Recipient, SignedGrant};

pub const TOKEN_PREFIX: &str = "opsa1_";
const TOKEN_VERSION: u8 = 0x01;
const ENCRYPTION_INFO: &[u8] = b"octapass/v1/service-account/encryption";
const SIGNING_INFO: &[u8] = b"octapass/v1/service-account/signing";
const AUTH_LABEL: &[u8] = b"octapass/v1/service-account-auth\0";
const CHECKSUM_LEN: usize = 4;
const FIXED_LEN: usize = 1 + 16 + 16 + 32 + 32 + 2; // 99
/// The name a person gives one, sealed so the server never sees it.
pub const MAX_NAME_CHARS: usize = 64;
const MAX_URL_LEN: usize = 2048;

/// A service account's token. Whoever holds it can read the vault: it's redacted in `Debug` output
/// and its root is zeroed on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceAccountToken {
    id: String,
    vault_id: String,
    root: [u8; 32],
    creator_public_sign_key: [u8; 32],
    server_url: String,
}

impl Drop for ServiceAccountToken {
    fn drop(&mut self) {
        self.root.zeroize();
    }
}

impl fmt::Debug for ServiceAccountToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountToken")
            .field("id", &self.id)
            .field("vault_id", &self.vault_id)
            .field("root", &"<redacted>")
            .field("server_url", &self.server_url)
            .finish_non_exhaustive()
    }
}

impl ServiceAccountToken {
    pub fn new(
        id: &str,
        vault_id: &str,
        root: [u8; 32],
        creator_public_sign_key: [u8; 32],
        server_url: &str,
    ) -> Result<Self> {
        if server_url.is_empty() || server_url.len() > MAX_URL_LEN {
            return Err(Error::InvalidServiceAccountToken);
        }
        Ok(Self {
            id: parse_id(id)?,
            vault_id: parse_id(vault_id)?,
            root,
            creator_public_sign_key,
            server_url: server_url.to_owned(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn creator_public_sign_key(&self) -> &[u8; 32] {
        &self.creator_public_sign_key
    }

    /// The text to keep in the CI system's secret store.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            FIXED_LEN + self.server_url.len() + CHECKSUM_LEN,
        ));
        bytes.push(TOKEN_VERSION);
        bytes.extend_from_slice(uuid_bytes(&self.id).as_bytes());
        bytes.extend_from_slice(uuid_bytes(&self.vault_id).as_bytes());
        bytes.extend_from_slice(&self.root);
        bytes.extend_from_slice(&self.creator_public_sign_key);
        let url_len = u16::try_from(self.server_url.len()).expect("length checked in new");
        bytes.extend_from_slice(&url_len.to_be_bytes());
        bytes.extend_from_slice(self.server_url.as_bytes());
        let checksum = checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        Zeroizing::new(format!("{TOKEN_PREFIX}{}", b64_encode(&bytes)))
    }

    /// Fails with [`Error::InvalidServiceAccountToken`] for anything but a whole, undamaged token.
    pub fn parse(text: &str) -> Result<Self> {
        let invalid = Error::InvalidServiceAccountToken;
        let body = text.trim().strip_prefix(TOKEN_PREFIX).ok_or(invalid)?;
        let bytes = Zeroizing::new(b64_decode(body).map_err(|_| invalid)?);
        if bytes.len() < FIXED_LEN + CHECKSUM_LEN || bytes[0] != TOKEN_VERSION {
            return Err(invalid);
        }
        let (signed, sum) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
        if checksum(signed) != sum {
            return Err(invalid);
        }
        let url_len = usize::from(u16::from_be_bytes([bytes[97], bytes[98]]));
        if signed.len() != FIXED_LEN + url_len {
            return Err(invalid);
        }
        let id = Uuid::from_slice(&bytes[1..17]).map_err(|_| invalid)?;
        let vault_id = Uuid::from_slice(&bytes[17..33]).map_err(|_| invalid)?;
        let root: [u8; 32] = bytes[33..65].try_into().map_err(|_| invalid)?;
        let creator: [u8; 32] = bytes[65..97].try_into().map_err(|_| invalid)?;
        let url = core::str::from_utf8(&signed[FIXED_LEN..]).map_err(|_| invalid)?;
        Self::new(
            &id.hyphenated().to_string(),
            &vault_id.hyphenated().to_string(),
            root,
            creator,
            url,
        )
    }

    pub fn keys(&self) -> ServiceAccountKeys {
        ServiceAccountKeys::derive(&self.id, &self.root)
    }

    /// Verifies the grant against the creator's key in this token and opens the vault key. Grants
    /// signed by anyone else fail with [`Error::InvalidSignature`]: another manager rotated the
    /// vault's key, and the creator has to issue a new token.
    pub fn open_grant(&self, grant: &SignedGrant) -> Result<ServiceVault> {
        let keys = self.keys();
        let key = grant.open(
            &self.vault_id,
            &self.id,
            &keys.encryption,
            &self.creator_public_sign_key,
        )?;
        Ok(ServiceVault {
            vault_id: self.vault_id.clone(),
            role: grant.role,
            key,
        })
    }
}

fn uuid_bytes(id: &str) -> Uuid {
    Uuid::try_parse(id).expect("ids were parsed in new")
}

fn checksum(bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::digest(bytes);
    let mut out = [0; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

/// The keys a token's root derives.
pub struct ServiceAccountKeys {
    encryption: StaticSecret,
    signing: SigningKey,
}

impl ServiceAccountKeys {
    fn derive(id: &str, root: &[u8; 32]) -> Self {
        let salt = uuid_bytes(id);
        let encryption = hkdf_key(root, salt.as_bytes(), ENCRYPTION_INFO);
        let signing = hkdf_key(root, salt.as_bytes(), SIGNING_INFO);
        Self {
            encryption: StaticSecret::from(*encryption.as_bytes()),
            signing: SigningKey::from_bytes(signing.as_bytes()),
        }
    }

    pub fn public_enc_key(&self) -> [u8; 32] {
        PublicKey::from(&self.encryption).to_bytes()
    }

    pub fn public_sign_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Answers the server's challenge. Returns base64url.
    pub fn sign_challenge(&self, id: &str, challenge: &str) -> Result<String> {
        let message = auth_message(&parse_id(id)?, challenge);
        Ok(b64_encode(&self.signing.sign(&message).to_bytes()))
    }
}

/// The bytes a service account signs to sign in. The server checks the same bytes.
pub fn auth_message(id: &str, challenge: &str) -> Vec<u8> {
    let mut message = AUTH_LABEL.to_vec();
    for field in [id, challenge] {
        let len = u32::try_from(field.len()).expect("auth fields are short");
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(field.as_bytes());
    }
    message
}

/// One shared vault, opened by a service account. It decrypts and encrypts items like a session,
/// with no account behind it.
pub struct ServiceVault {
    vault_id: String,
    role: Role,
    key: SymmetricKey,
}

impl ServiceVault {
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn decrypt_overview(
        &self,
        item_id: &str,
        encrypted: &EncryptedItem,
    ) -> Result<ItemOverview> {
        open_overview(&self.key, &self.vault_id, &parse_id(item_id)?, encrypted)
    }

    pub fn decrypt_item(&self, item_id: &str, encrypted: &EncryptedItem) -> Result<Item> {
        open_item(&self.key, &self.vault_id, &parse_id(item_id)?, encrypted)
    }

    /// Encrypts an item to save it, keeping `existing_item_key` when given. The server refuses it
    /// unless the service account has the `write` role.
    pub fn encrypt_item(
        &self,
        item_id: &str,
        item: &Item,
        existing_item_key: Option<&str>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<EncryptedItem> {
        seal_item(
            &self.key,
            &self.vault_id,
            &parse_id(item_id)?,
            item,
            existing_item_key,
            rng,
        )
    }
}

/// What `POST /v1/vaults/{vaultId}/service-accounts` takes, and the token to show once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewServiceAccount {
    pub id: String,
    pub public_enc_key: String,
    pub public_sign_key: String,
    /// The name, sealed under the creator's ASK.
    pub encrypted_name: String,
    pub grant: SignedGrant,
    /// base64url id of the vault key the grant seals.
    pub key_id: String,
    #[serde(skip)]
    pub token: ServiceAccountToken,
}

impl Session {
    /// Makes a service account for an open vault: its token and keys, and a grant to it.
    pub fn create_service_account(
        &self,
        vault_id: &str,
        role: Role,
        name: &str,
        server_url: &str,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<NewServiceAccount> {
        // A service account can read and at most write: anything more belongs to a person.
        if role > Role::Write {
            return Err(Error::InvalidGrant);
        }
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
            return Err(Error::InvalidServiceAccountName);
        }
        let vault_id = parse_id(vault_id)?;
        let id = new_id(now_ms, rng);
        let mut root = [0u8; 32];
        rng.fill_bytes(&mut root);
        let token = ServiceAccountToken::new(
            &id,
            &vault_id,
            root,
            self.key_pairs().public_sign_key(),
            server_url,
        )?;
        root.zeroize();
        let keys = token.keys();
        let recipient = Recipient {
            account_id: id.clone(),
            public_enc_key: keys.public_enc_key(),
            public_pq_key: None,
            role,
        };
        let grant = self.grant_vault(&vault_id, &recipient, now_ms, rng)?;
        Ok(NewServiceAccount {
            encrypted_name: self.seal_service_account_name(&vault_id, &id, name, rng)?,
            public_enc_key: b64_encode(&keys.public_enc_key()),
            public_sign_key: b64_encode(&keys.public_sign_key()),
            key_id: self.vault_key_id(&vault_id)?,
            grant,
            token,
            id,
        })
    }

    fn seal_service_account_name(
        &self,
        vault_id: &str,
        id: &str,
        name: &str,
        rng: &mut impl CryptoRngCore,
    ) -> Result<String> {
        let context = Context::ServiceAccountName {
            vault_id,
            service_account_id: id,
        };
        seal_b64(self.ask(), &context, name.as_bytes(), rng)
    }

    /// The name of a service account this account created. Others' names fail to open: their
    /// owners sealed them under their own keys.
    pub fn open_service_account_name(
        &self,
        vault_id: &str,
        id: &str,
        encrypted_name: &str,
    ) -> Result<String> {
        let (vault_id, id) = (parse_id(vault_id)?, parse_id(id)?);
        let context = Context::ServiceAccountName {
            vault_id: &vault_id,
            service_account_id: &id,
        };
        let name = open_b64(self.ask(), &context, encrypted_name)?;
        String::from_utf8(name.to_vec()).map_err(|_| Error::DecryptionFailed)
    }

    /// Seals one entry of the account's security log so that only the account can read it.
    pub fn seal_audit_detail(&self, detail: &[u8], rng: &mut impl CryptoRngCore) -> Result<String> {
        let account_id = self.account_id()?;
        seal_b64(
            self.ask(),
            &Context::AuditDetail {
                account_id: &account_id,
            },
            detail,
            rng,
        )
    }

    pub fn open_audit_detail(&self, sealed: &str) -> Result<Zeroizing<Vec<u8>>> {
        let account_id = self.account_id()?;
        open_b64(
            self.ask(),
            &Context::AuditDetail {
                account_id: &account_id,
            },
            sealed,
        )
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, VerifyingKey};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::encoding::b64_decode_array;
    use crate::sharing::test_support::account;

    const NOW: u64 = 1_761_177_600_000;
    const SERVER: &str = "https://octap.app";

    fn item() -> Item {
        Item::from_json(
            r#"{"overview":{"title":"Deploy key","type":"login"},"details":{"password":"p"}}"#,
        )
        .unwrap()
    }

    fn setup() -> (ChaCha20Rng, Session, String) {
        let mut rng = ChaCha20Rng::seed_from_u64(25);
        let mut owner = account(&mut rng);
        let vault = owner.create_shared_vault(NOW, &mut rng).unwrap();
        (rng, owner, vault.id)
    }

    #[test]
    fn a_token_opens_the_vault_it_was_made_for() {
        let (mut rng, owner, vault) = setup();
        let item_id = new_id(NOW, &mut rng);
        let encrypted = owner
            .encrypt_item(&vault, &item_id, &item(), None, &mut rng)
            .unwrap();

        let new = owner
            .create_service_account(&vault, Role::Read, "CI", SERVER, NOW, &mut rng)
            .unwrap();
        let token = ServiceAccountToken::parse(&new.token.encode()).unwrap();
        assert_eq!(token, new.token);
        assert_eq!(token.server_url(), SERVER);

        let opened = token.open_grant(&new.grant).unwrap();
        assert_eq!(opened.role(), Role::Read);
        assert_eq!(opened.decrypt_item(&item_id, &encrypted).unwrap(), item());
        assert_eq!(
            opened.decrypt_overview(&item_id, &encrypted).unwrap().title,
            "Deploy key"
        );

        // A write-role runner's items open for the owner.
        let other_id = new_id(NOW, &mut rng);
        let saved = opened
            .encrypt_item(&other_id, &item(), None, &mut rng)
            .unwrap();
        assert_eq!(
            owner.decrypt_item(&vault, &other_id, &saved).unwrap(),
            item()
        );
    }

    #[test]
    fn the_server_gets_public_keys_and_no_root() {
        let (mut rng, owner, vault) = setup();
        let new = owner
            .create_service_account(&vault, Role::Read, "CI", SERVER, NOW, &mut rng)
            .unwrap();
        let body = serde_json::to_string(&new).unwrap();
        assert!(!body.contains("token"), "{body}");
        let keys = new.token.keys();
        assert_eq!(new.public_enc_key, b64_encode(&keys.public_enc_key()));
        assert_eq!(new.public_sign_key, b64_encode(&keys.public_sign_key()));
        assert!(!body.contains(&b64_encode(&new.token.root)));
    }

    #[test]
    fn the_challenge_signature_verifies() {
        let (mut rng, owner, vault) = setup();
        let new = owner
            .create_service_account(&vault, Role::Read, "CI", SERVER, NOW, &mut rng)
            .unwrap();
        let keys = new.token.keys();
        let signature = keys.sign_challenge(&new.id, "abc").unwrap();
        let signature = Signature::from_bytes(&b64_decode_array(&signature).unwrap());
        let public = VerifyingKey::from_bytes(&keys.public_sign_key()).unwrap();
        public
            .verify_strict(&auth_message(&new.id, "abc"), &signature)
            .unwrap();
        assert!(
            public
                .verify_strict(&auth_message(&new.id, "abd"), &signature)
                .is_err()
        );
    }

    #[test]
    fn roles_above_write_are_refused() {
        let (mut rng, owner, vault) = setup();
        for role in [Role::Manage, Role::Owner] {
            assert_eq!(
                owner
                    .create_service_account(&vault, role, "CI", SERVER, NOW, &mut rng)
                    .unwrap_err(),
                Error::InvalidGrant
            );
        }
    }

    #[test]
    fn names_are_checked_and_sealed() {
        let (mut rng, owner, vault) = setup();
        for name in ["", "   ", &"x".repeat(65)] {
            assert_eq!(
                owner
                    .create_service_account(&vault, Role::Read, name, SERVER, NOW, &mut rng)
                    .unwrap_err(),
                Error::InvalidServiceAccountName
            );
        }
        let new = owner
            .create_service_account(&vault, Role::Read, " deploy ", SERVER, NOW, &mut rng)
            .unwrap();
        assert_eq!(
            owner
                .open_service_account_name(&vault, &new.id, &new.encrypted_name)
                .unwrap(),
            "deploy"
        );
        // Bound to the id: a server can't swap two labels.
        assert!(
            owner
                .open_service_account_name(&vault, &new_id(NOW, &mut rng), &new.encrypted_name)
                .is_err()
        );
        let stranger = account(&mut rng);
        assert!(
            stranger
                .open_service_account_name(&vault, &new.id, &new.encrypted_name)
                .is_err()
        );
    }

    #[test]
    fn a_grant_from_anyone_but_the_creator_is_refused() {
        let (mut rng, owner, vault) = setup();
        let mut stranger = account(&mut rng);
        let their_vault = stranger.create_shared_vault(NOW, &mut rng).unwrap();
        let new = owner
            .create_service_account(&vault, Role::Read, "CI", SERVER, NOW, &mut rng)
            .unwrap();
        let forged = stranger
            .grant_vault(
                &their_vault.id,
                &Recipient {
                    account_id: new.id.clone(),
                    public_enc_key: new.token.keys().public_enc_key(),
                    public_pq_key: None,
                    role: Role::Write,
                },
                NOW,
                &mut rng,
            )
            .unwrap();
        // For another vault, and signed by a key the token doesn't pin.
        assert_eq!(
            new.token.open_grant(&forged).err(),
            Some(Error::InvalidGrant)
        );
        let mut raised = new.grant.clone();
        raised.role = Role::Write;
        assert_eq!(
            new.token.open_grant(&raised).err(),
            Some(Error::InvalidSignature)
        );
    }

    #[test]
    fn a_rotated_key_reaches_the_service_account_when_the_creator_rotates() {
        let (mut rng, mut owner, vault) = setup();
        let new = owner
            .create_service_account(&vault, Role::Read, "CI", SERVER, NOW, &mut rng)
            .unwrap();
        let me = Recipient {
            account_id: owner.bundle().account_id.clone().unwrap(),
            public_enc_key: owner.key_pairs().public_enc_key(),
            public_pq_key: None,
            role: Role::Owner,
        };
        let service = Recipient {
            account_id: new.id.clone(),
            public_enc_key: new.token.keys().public_enc_key(),
            public_pq_key: None,
            role: Role::Read,
        };
        let item_id = new_id(NOW, &mut rng);
        let encrypted = owner
            .encrypt_item(&vault, &item_id, &item(), None, &mut rng)
            .unwrap();
        let rotation = owner
            .rotate_vault_key(
                &vault,
                &[me, service],
                &[crate::sharing::vault::ItemKey {
                    item_id: item_id.clone(),
                    encrypted_item_key: encrypted.encrypted_item_key.clone(),
                }],
                NOW + 1,
                &mut rng,
            )
            .unwrap();
        let [_, grant] = rotation.grants.as_slice() else {
            panic!("two grants");
        };
        let opened = new.token.open_grant(grant).unwrap();
        let rotated = EncryptedItem {
            encrypted_item_key: rotation.items[0].encrypted_item_key.clone(),
            ..encrypted.clone()
        };
        assert_eq!(opened.decrypt_item(&item_id, &rotated).unwrap(), item());
        // The old grant no longer opens the new wrapping.
        let old = new.token.open_grant(&new.grant).unwrap();
        assert!(old.decrypt_item(&item_id, &rotated).is_err());
        owner.close_vault(&vault);
    }

    #[test]
    fn damaged_tokens_are_refused() {
        let (mut rng, owner, vault) = setup();
        let new = owner
            .create_service_account(&vault, Role::Read, "CI", SERVER, NOW, &mut rng)
            .unwrap();
        let good = new.token.encode();
        let mut bad = good.to_string();
        let middle = bad.len() / 2;
        let flipped = if bad.as_bytes()[middle] == b'A' {
            "B"
        } else {
            "A"
        };
        bad.replace_range(middle..=middle, flipped);
        let short = &good[..good.len() - 8];
        let body = good.strip_prefix(TOKEN_PREFIX).unwrap();
        for text in ["", "opsa1_", "nope", bad.as_str(), short, body] {
            assert_eq!(
                ServiceAccountToken::parse(text).err(),
                Some(Error::InvalidServiceAccountToken),
                "{text}"
            );
        }
        assert!(ServiceAccountToken::parse(&format!("  {}\n", good.as_str())).is_ok());
    }

    #[test]
    fn debug_output_hides_the_root() {
        let (mut rng, owner, vault) = setup();
        let new = owner
            .create_service_account(&vault, Role::Read, "CI", SERVER, NOW, &mut rng)
            .unwrap();
        let text = format!("{:?}", new.token);
        assert!(text.contains("<redacted>"));
        assert!(!text.contains(&format!("{:?}", new.token.root)));
    }

    #[test]
    fn audit_details_open_only_for_their_account() {
        let (mut rng, owner, _) = setup();
        let sealed = owner
            .seal_audit_detail(b"{\"client\":\"x\"}", &mut rng)
            .unwrap();
        assert_eq!(
            owner.open_audit_detail(&sealed).unwrap().as_slice(),
            b"{\"client\":\"x\"}"
        );
        let stranger = account(&mut rng);
        assert!(stranger.open_audit_detail(&sealed).is_err());
    }
}
