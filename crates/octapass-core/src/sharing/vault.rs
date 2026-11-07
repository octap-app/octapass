//! Vaults on an unlocked [`Session`]: create a shared one, grant it to others, open the grants
//! sync returns, and rotate a vault's key, when a member leaves or on demand.
//!
//! Rotating gives the vault a new key. Every item key is re-wrapped under it (item bodies stay as
//! they are, encrypted under their unchanged item keys) and every member gets a new grant, or, in
//! a personal vault, the new key wrapped by the account key. Someone who held the old key still
//! knows it, so items they could already read should be treated as known to them.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::account::{new_id, parse_id};
use crate::encoding::{b64_decode_array, b64_encode};
use crate::envelope::{Context, unwrap_key, wrap_key};
use crate::error::{Error, Result};
use crate::keys::SymmetricKey;
use crate::session::Session;
use crate::sharing::Role;
use crate::sharing::grant::{Recipient, SignedGrant};

/// `POST /v1/vaults`: a new shared vault and its owner's own grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewSharedVault {
    pub id: String,
    /// base64url key id of the vault key (see [`SymmetricKey::key_id`]). The server rejects item
    /// keys wrapped under any other key.
    pub key_id: String,
    pub grant: SignedGrant,
}

/// An item's wrapped item key, the only part of an item a key rotation changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemKey {
    pub item_id: String,
    pub encrypted_item_key: String,
}

/// `POST /v1/vaults/{vaultId}/rotate`: the new key's id, a grant per remaining member and every
/// item key re-wrapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultRotation {
    pub key_id: String,
    /// Empty for a personal vault, which has no grants.
    pub grants: Vec<SignedGrant>,
    pub items: Vec<ItemKey>,
    /// A personal vault only: the new key wrapped by the account key (context `vaultkey`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_vault_key: Option<String>,
}

/// A vault as sync lists it (a `VaultRecord`): what opening its key needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncedVault<'a> {
    pub id: &'a str,
    /// Personal vaults are sealed by the account key; shared and family vaults come with a grant.
    pub personal: bool,
    pub role: Role,
    pub wrapped_vault_key: &'a str,
    /// Shared and family vaults: the rest of this account's signed grant.
    pub grant: Option<GrantSignature<'a>>,
}

/// The half of a grant a `VaultRecord` keeps next to the vault id, role and wrapped key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantSignature<'a> {
    pub granted_by: &'a str,
    /// base64url Ed25519 public key of the granter.
    pub granter_public_sign_key: &'a str,
    pub granted_at: u64,
    pub signature: &'a str,
}

impl SyncedVault<'_> {
    /// The member's whole signed grant, with `recipient_account_id` as the recipient.
    pub fn signed_grant(&self, recipient_account_id: &str) -> Option<SignedGrant> {
        let grant = self.grant?;
        Some(SignedGrant {
            vault_id: self.id.to_owned(),
            recipient_account_id: recipient_account_id.to_owned(),
            role: self.role,
            wrapped_vault_key: self.wrapped_vault_key.to_owned(),
            granted_by: grant.granted_by.to_owned(),
            granted_at: grant.granted_at,
            signature: grant.signature.to_owned(),
        })
    }
}

impl Session {
    /// Opens a vault sync returned, as every client must: a personal vault's key with the account
    /// key, a shared or family vault's only once its grant verifies against the granter's signing
    /// key (a server that swapped the wrapped key or the role would otherwise go unnoticed). On
    /// failure the vault is closed, so a key opened earlier (before a rotation) isn't used either.
    pub fn open_synced_vault(&mut self, vault: &SyncedVault) -> Result<()> {
        let opened = if vault.personal {
            self.open_vault(vault.id, vault.wrapped_vault_key)
        } else {
            self.open_granted_vault(vault)
        };
        if opened.is_err() {
            self.close_vault(vault.id);
        }
        opened
    }

    fn open_granted_vault(&mut self, vault: &SyncedVault) -> Result<()> {
        let grant = vault
            .signed_grant(&self.account_id()?)
            .ok_or(Error::InvalidGrant)?;
        let granter = vault
            .grant
            .ok_or(Error::InvalidGrant)?
            .granter_public_sign_key;
        let granter = b64_decode_array(granter).map_err(|_| Error::InvalidKey)?;
        self.open_shared_vault(&grant, &granter)
    }

    /// Creates a shared vault owned by this account and keeps its key open.
    pub fn create_shared_vault(
        &mut self,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<NewSharedVault> {
        let id = new_id(now_ms, rng);
        let key = SymmetricKey::generate(rng);
        let me = Recipient {
            account_id: self.account_id()?,
            public_enc_key: self.key_pairs().public_enc_key(),
            public_pq_key: self.pq_keys().map(|keys| keys.public_key().clone()),
            role: Role::Owner,
        };
        let grant = self.sign_grant(&id, &key, &me, now_ms, rng)?;
        let vault = NewSharedVault {
            key_id: b64_encode(&key.key_id()),
            id: id.clone(),
            grant,
        };
        self.insert_vault_key(id, key);
        Ok(vault)
    }

    /// Grants an open vault to another account, sealed to its public key and signed by this one.
    pub fn grant_vault(
        &self,
        vault_id: &str,
        recipient: &Recipient,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<SignedGrant> {
        let vault_id = parse_id(vault_id)?;
        self.sign_grant(
            &vault_id,
            self.vault_key(&vault_id)?,
            recipient,
            now_ms,
            rng,
        )
    }

    /// Verifies a grant to this account (from a `VaultRecord`) against the granter's signing key
    /// and keeps the vault key open.
    pub fn open_shared_vault(
        &mut self,
        grant: &SignedGrant,
        granter_public_sign_key: &[u8; 32],
    ) -> Result<()> {
        let key = grant.open(
            &grant.vault_id,
            &self.account_id()?,
            self.opener(),
            granter_public_sign_key,
        )?;
        self.insert_vault_key(parse_id(&grant.vault_id)?, key);
        Ok(())
    }

    /// The key id of an open vault's key, base64url.
    pub fn vault_key_id(&self, vault_id: &str) -> Result<String> {
        Ok(b64_encode(&self.vault_key(&parse_id(vault_id)?)?.key_id()))
    }

    /// Prepares a new key for an open vault: grants for `members` (everyone who stays, this
    /// account included) and every item key in the vault re-wrapped. The session keeps the old
    /// key until the server accepts the rotation and the new grant is opened.
    pub fn rotate_vault_key(
        &self,
        vault_id: &str,
        members: &[Recipient],
        items: &[ItemKey],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<VaultRotation> {
        let vault_id = parse_id(vault_id)?;
        let new_key = SymmetricKey::generate(rng);
        let items = self.rewrap_item_keys(&vault_id, &new_key, items, rng)?;
        let grants = members
            .iter()
            .map(|member| self.sign_grant(&vault_id, &new_key, member, now_ms, rng))
            .collect::<Result<_>>()?;
        Ok(VaultRotation {
            key_id: b64_encode(&new_key.key_id()),
            grants,
            items,
            wrapped_vault_key: None,
        })
    }

    /// Prepares a new key for an open personal vault: wrapped by the account key, with every item
    /// key re-wrapped. The session keeps the old key until the server accepts the rotation and
    /// the new wrapped key is opened.
    pub fn rotate_personal_vault_key(
        &self,
        vault_id: &str,
        items: &[ItemKey],
        rng: &mut impl CryptoRngCore,
    ) -> Result<VaultRotation> {
        let vault_id = parse_id(vault_id)?;
        let new_key = SymmetricKey::generate(rng);
        let items = self.rewrap_item_keys(&vault_id, &new_key, items, rng)?;
        let context = Context::VaultKey {
            vault_id: &vault_id,
        };
        Ok(VaultRotation {
            key_id: b64_encode(&new_key.key_id()),
            grants: Vec::new(),
            items,
            wrapped_vault_key: Some(wrap_key(self.ask(), &context, &new_key, rng)?),
        })
    }

    /// Every item key, unwrapped with the vault's open key and wrapped with `new_key`. One that
    /// doesn't open fails the whole rotation, so no item is left behind on the old key.
    fn rewrap_item_keys(
        &self,
        vault_id: &str,
        new_key: &SymmetricKey,
        items: &[ItemKey],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<ItemKey>> {
        let old_key = self.vault_key(vault_id)?;
        items
            .iter()
            .map(|item| {
                let item_id = parse_id(&item.item_id)?;
                let context = Context::ItemKey {
                    vault_id,
                    item_id: &item_id,
                };
                let item_key = unwrap_key(old_key, &context, &item.encrypted_item_key)?;
                Ok(ItemKey {
                    encrypted_item_key: wrap_key(new_key, &context, &item_key, rng)?,
                    item_id,
                })
            })
            .collect()
    }

    /// Opens a synced vault whose key was rotated, and moves `pending` (item keys of changes not
    /// uploaded yet, from before the rotation) from the key that was open to the new one. Their
    /// bodies stay as encrypted, because a rotation leaves item keys as they are. Returns the
    /// moved ones; an item key the old key doesn't open is left out, and left as it is.
    ///
    /// If the vault doesn't open (a grant that doesn't verify), it's closed and nothing moves.
    pub fn rekey_synced_vault(
        &mut self,
        vault: &SyncedVault,
        pending: &[ItemKey],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<ItemKey>> {
        let vault_id = parse_id(vault.id)?;
        let old_key = self.vault_key(&vault_id)?.clone();
        self.open_synced_vault(vault)?;
        let new_key = self.vault_key(&vault_id)?;
        pending
            .iter()
            .filter_map(|item| {
                let item_id = parse_id(&item.item_id).ok()?;
                let context = Context::ItemKey {
                    vault_id: &vault_id,
                    item_id: &item_id,
                };
                let item_key = unwrap_key(&old_key, &context, &item.encrypted_item_key).ok()?;
                let moved = wrap_key(new_key, &context, &item_key, rng);
                Some(moved.map(|encrypted_item_key| ItemKey {
                    item_id,
                    encrypted_item_key,
                }))
            })
            .collect()
    }

    fn sign_grant(
        &self,
        vault_id: &str,
        key: &SymmetricKey,
        recipient: &Recipient,
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<SignedGrant> {
        SignedGrant::create(
            vault_id,
            key,
            recipient,
            &self.account_id()?,
            self.key_pairs().signing_key(),
            now_ms,
            rng,
        )
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::error::Error;
    use crate::item::Item;
    use crate::sharing::test_support::account;

    const NOW: u64 = 1_761_177_600_000;

    fn item() -> Item {
        Item::from_json(
            r#"{"overview":{"title":"Wi-Fi","type":"password"},"details":{"password":"p"}}"#,
        )
        .unwrap()
    }

    fn recipient(session: &Session, role: Role) -> Recipient {
        Recipient {
            account_id: session.account_id().unwrap(),
            public_enc_key: session.key_pairs().public_enc_key(),
            public_pq_key: session.pq_keys().map(|keys| keys.public_key().clone()),
            role,
        }
    }

    fn sign_key(session: &Session) -> [u8; 32] {
        session.key_pairs().public_sign_key()
    }

    #[test]
    fn members_open_the_vault_through_their_grants() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut alice = account(&mut rng);
        let mut bob = account(&mut rng);
        let vault = alice.create_shared_vault(NOW, &mut rng).unwrap();
        assert_eq!(vault.grant.role, Role::Owner);
        assert_eq!(vault.key_id, alice.vault_key_id(&vault.id).unwrap());

        let item_id = new_id(NOW, &mut rng);
        let encrypted = alice
            .encrypt_item(&vault.id, &item_id, &item(), None, &mut rng)
            .unwrap();

        let grant = alice
            .grant_vault(&vault.id, &recipient(&bob, Role::Read), NOW, &mut rng)
            .unwrap();
        assert_eq!(
            bob.open_shared_vault(&grant, &sign_key(&bob)).err(),
            Some(Error::InvalidSignature),
            "signed by alice, not bob"
        );
        bob.open_shared_vault(&grant, &sign_key(&alice)).unwrap();
        assert_eq!(
            bob.decrypt_item(&vault.id, &item_id, &encrypted).unwrap(),
            item()
        );
        // Alice's own grant is sealed to her, so it's no use to bob.
        assert!(
            bob.open_shared_vault(&vault.grant, &sign_key(&alice))
                .is_err()
        );
    }

    #[test]
    fn rotation_rewraps_item_keys_and_leaves_bodies_alone() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut alice = account(&mut rng);
        let mut bob = account(&mut rng);
        let mut carol = account(&mut rng);
        let vault = alice.create_shared_vault(NOW, &mut rng).unwrap();
        for member in [&mut bob, &mut carol] {
            let grant = alice
                .grant_vault(&vault.id, &recipient(member, Role::Write), NOW, &mut rng)
                .unwrap();
            member.open_shared_vault(&grant, &sign_key(&alice)).unwrap();
        }
        let item_id = new_id(NOW, &mut rng);
        let encrypted = bob
            .encrypt_item(&vault.id, &item_id, &item(), None, &mut rng)
            .unwrap();
        let file_id = new_id(NOW, &mut rng);
        let (file_key, encryptor) = bob
            .new_attachment(
                &vault.id,
                &item_id,
                &encrypted.encrypted_item_key,
                &file_id,
                &mut rng,
            )
            .unwrap();
        let file = encryptor.finish().unwrap();

        // Carol leaves: alice rotates for herself and bob.
        let stays = [recipient(&alice, Role::Owner), recipient(&bob, Role::Write)];
        let items = [ItemKey {
            item_id: item_id.clone(),
            encrypted_item_key: encrypted.encrypted_item_key.clone(),
        }];
        let rotation = alice
            .rotate_vault_key(&vault.id, &stays, &items, NOW + 1, &mut rng)
            .unwrap();
        assert_ne!(rotation.key_id, vault.key_id);
        assert_eq!(rotation.grants.len(), 2);
        assert_eq!(rotation.grants[1].role, Role::Write);
        let rotated = crate::session::EncryptedItem {
            encrypted_item_key: rotation.items[0].encrypted_item_key.clone(),
            ..encrypted.clone()
        };

        let alice_key = sign_key(&alice);
        for (member, grant) in [
            (&mut alice, &rotation.grants[0]),
            (&mut bob, &rotation.grants[1]),
        ] {
            assert!(
                member.decrypt_item(&vault.id, &item_id, &rotated).is_err(),
                "still on the old key"
            );
            member.open_shared_vault(grant, &alice_key).unwrap();
            assert_eq!(
                member.decrypt_item(&vault.id, &item_id, &rotated).unwrap(),
                item()
            );
            assert_eq!(member.vault_key_id(&vault.id).unwrap(), rotation.key_id);
            // Attachments hang off the item key, so they open without being touched.
            let mut decryptor = member
                .open_attachment(
                    &vault.id,
                    &item_id,
                    &rotated.encrypted_item_key,
                    &file_id,
                    &file_key,
                )
                .unwrap();
            assert!(decryptor.push(&file).unwrap().is_empty());
            assert!(decryptor.finish().unwrap().is_empty());
        }
        // Carol's old key no longer opens the item key.
        assert_eq!(
            carol.decrypt_item(&vault.id, &item_id, &rotated).err(),
            Some(Error::WrongKey)
        );
    }

    #[test]
    fn a_personal_vault_rotates_under_the_account_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let mut alice = account(&mut rng);
        let vault_id = new_id(NOW, &mut rng);
        let old_key = SymmetricKey::generate(&mut rng);
        let context = Context::VaultKey {
            vault_id: &vault_id,
        };
        let wrapped = wrap_key(alice.ask(), &context, &old_key, &mut rng).unwrap();
        alice.open_vault(&vault_id, &wrapped).unwrap();

        let item_id = new_id(NOW, &mut rng);
        let encrypted = alice
            .encrypt_item(&vault_id, &item_id, &item(), None, &mut rng)
            .unwrap();
        let items = [ItemKey {
            item_id: item_id.clone(),
            encrypted_item_key: encrypted.encrypted_item_key.clone(),
        }];
        let rotation = alice
            .rotate_personal_vault_key(&vault_id, &items, &mut rng)
            .unwrap();
        assert!(rotation.grants.is_empty());
        assert_ne!(rotation.key_id, alice.vault_key_id(&vault_id).unwrap());
        let wrapped = rotation.wrapped_vault_key.as_deref().unwrap();
        let rotated = crate::session::EncryptedItem {
            encrypted_item_key: rotation.items[0].encrypted_item_key.clone(),
            ..encrypted.clone()
        };
        // The old key stays open until the server has the new one.
        assert_eq!(
            alice.decrypt_item(&vault_id, &item_id, &rotated).err(),
            Some(Error::WrongKey)
        );
        alice
            .open_synced_vault(&SyncedVault {
                id: &vault_id,
                personal: true,
                role: Role::Owner,
                wrapped_vault_key: wrapped,
                grant: None,
            })
            .unwrap();
        assert_eq!(alice.vault_key_id(&vault_id).unwrap(), rotation.key_id);
        assert_eq!(
            alice.decrypt_item(&vault_id, &item_id, &rotated).unwrap(),
            item()
        );
        // The item key didn't change, only its wrapping: the old wrapping needs the old key.
        assert_eq!(
            alice.decrypt_item(&vault_id, &item_id, &encrypted).err(),
            Some(Error::WrongKey)
        );
        // The wrapped key is bound to this vault.
        let elsewhere = new_id(NOW, &mut rng);
        assert!(alice.open_vault(&elsewhere, wrapped).is_err());
    }

    #[test]
    fn a_queued_change_moves_to_the_new_key_without_touching_its_body() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let mut alice = account(&mut rng);
        let vault_id = new_id(NOW, &mut rng);
        let old_key = SymmetricKey::generate(&mut rng);
        let context = Context::VaultKey {
            vault_id: &vault_id,
        };
        let wrapped = wrap_key(alice.ask(), &context, &old_key, &mut rng).unwrap();
        alice.open_vault(&vault_id, &wrapped).unwrap();
        let item_id = new_id(NOW, &mut rng);
        let queued = alice
            .encrypt_item(&vault_id, &item_id, &item(), None, &mut rng)
            .unwrap();

        let rotation = alice
            .rotate_personal_vault_key(&vault_id, &[], &mut rng)
            .unwrap();
        let new_wrapped = rotation.wrapped_vault_key.unwrap();
        // One change this key opens, and one from elsewhere that it doesn't.
        let foreign = ItemKey {
            item_id: new_id(NOW, &mut rng),
            encrypted_item_key: queued.encrypted_item_key.clone(),
        };
        let pending = [
            ItemKey {
                item_id: item_id.clone(),
                encrypted_item_key: queued.encrypted_item_key.clone(),
            },
            foreign,
        ];
        let moved = alice
            .rekey_synced_vault(
                &SyncedVault {
                    id: &vault_id,
                    personal: true,
                    role: Role::Owner,
                    wrapped_vault_key: &new_wrapped,
                    grant: None,
                },
                &pending,
                &mut rng,
            )
            .unwrap();
        assert_eq!(moved.len(), 1);
        assert_eq!(alice.vault_key_id(&vault_id).unwrap(), rotation.key_id);
        let moved = crate::session::EncryptedItem {
            encrypted_item_key: moved[0].encrypted_item_key.clone(),
            ..queued
        };
        assert_eq!(
            alice.decrypt_item(&vault_id, &item_id, &moved).unwrap(),
            item()
        );
    }

    #[test]
    fn a_personal_rotation_needs_the_old_key_for_every_item() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let alice = account(&mut rng);
        assert_eq!(
            alice
                .rotate_personal_vault_key(&new_id(NOW, &mut rng), &[], &mut rng)
                .err(),
            Some(Error::VaultNotOpen)
        );
    }

    #[test]
    fn rekeying_a_vault_whose_grant_fails_closes_it() {
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let mut alice = account(&mut rng);
        let vault = alice.create_shared_vault(NOW, &mut rng).unwrap();
        let wrong_signer = b64_encode(&[1; 32]);
        assert!(
            alice
                .rekey_synced_vault(
                    &synced(&vault.id, &vault.grant, &wrong_signer),
                    &[],
                    &mut rng
                )
                .is_err()
        );
        assert!(!alice.is_vault_open(&vault.id));
    }

    fn synced<'a>(id: &'a str, grant: &'a SignedGrant, granter: &'a str) -> SyncedVault<'a> {
        SyncedVault {
            id,
            personal: false,
            role: grant.role,
            wrapped_vault_key: &grant.wrapped_vault_key,
            grant: Some(GrantSignature {
                granted_by: &grant.granted_by,
                granter_public_sign_key: granter,
                granted_at: grant.granted_at,
                signature: &grant.signature,
            }),
        }
    }

    #[test]
    fn synced_vaults_open_only_when_their_grant_verifies() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let mut alice = account(&mut rng);
        let mut bob = account(&mut rng);
        let vault = alice.create_shared_vault(NOW, &mut rng).unwrap();
        let item_id = new_id(NOW, &mut rng);
        let encrypted = alice
            .encrypt_item(&vault.id, &item_id, &item(), None, &mut rng)
            .unwrap();
        let grant = alice
            .grant_vault(&vault.id, &recipient(&bob, Role::Read), NOW, &mut rng)
            .unwrap();
        let alice_key = b64_encode(&sign_key(&alice));

        bob.open_synced_vault(&synced(&vault.id, &grant, &alice_key))
            .unwrap();
        assert_eq!(
            bob.decrypt_item(&vault.id, &item_id, &encrypted).unwrap(),
            item()
        );

        // The server says bob may write: the signature no longer covers the grant, and the key
        // bob had is closed too.
        let mut tampered = synced(&vault.id, &grant, &alice_key);
        tampered.role = Role::Write;
        assert_eq!(
            bob.open_synced_vault(&tampered).err(),
            Some(Error::InvalidSignature)
        );
        assert!(!bob.is_vault_open(&vault.id));

        let bob_key = b64_encode(&sign_key(&bob));
        let mut unsigned = synced(&vault.id, &grant, &bob_key);
        assert_eq!(
            bob.open_synced_vault(&unsigned).err(),
            Some(Error::InvalidSignature)
        );
        unsigned.grant = None;
        assert_eq!(
            bob.open_synced_vault(&unsigned).err(),
            Some(Error::InvalidGrant)
        );
        // Shared keys are sealed to the account, never by its account key.
        unsigned.personal = true;
        assert!(bob.open_synced_vault(&unsigned).is_err());
        assert!(!bob.is_vault_open(&vault.id));
    }

    #[test]
    fn rotation_needs_the_old_key_for_every_item() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut alice = account(&mut rng);
        let vault = alice.create_shared_vault(NOW, &mut rng).unwrap();
        let foreign = ItemKey {
            item_id: new_id(NOW, &mut rng),
            encrypted_item_key: wrap_key(
                &SymmetricKey::generate(&mut rng),
                &Context::Ask,
                &SymmetricKey::generate(&mut rng),
                &mut rng,
            )
            .unwrap(),
        };
        let me = [recipient(&alice, Role::Owner)];
        assert_eq!(
            alice
                .rotate_vault_key(&vault.id, &me, &[foreign], NOW, &mut rng)
                .err(),
            Some(Error::WrongKey)
        );
        let closed = new_id(NOW, &mut rng);
        assert_eq!(
            alice
                .rotate_vault_key(&closed, &me, &[], NOW, &mut rng)
                .err(),
            Some(Error::VaultNotOpen)
        );
    }
}
