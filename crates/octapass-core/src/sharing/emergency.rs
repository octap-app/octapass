//! Emergency access: the grantor seals their account key (ASK), or one vault's key, to a trusted
//! contact's public key. The server holds the sealed key and releases it to the contact only
//! after a waiting period the grantor can cut short by denying the request.
//!
//! The sealed key's context names grantor, contact and scope
//! (`emergency:<grantorId>:<contactId>:ask` or `…:vault:<vaultId>`), so a released key can't be
//! presented as another grantor's, another contact's, or another vault's.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::account::{AccountBundle, parse_id};
use crate::error::{Error, Result};
use crate::session::Session;
use crate::sharing::pq::PqPublicKey;
use crate::sharing::seal::{SealContext, open_key, seal_for};

/// What an emergency contact gets once access is released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum EmergencyScope {
    /// The account key: every vault the grantor can open.
    Account,
    /// One vault's key.
    #[serde(rename_all = "camelCase")]
    Vault { vault_id: String },
}

impl Session {
    /// Seals this account's key, or one open vault's key, to an emergency contact.
    pub fn seal_for_emergency_contact(
        &self,
        contact_account_id: &str,
        contact_public_enc_key: &[u8; 32],
        contact_pq_key: Option<&PqPublicKey>,
        scope: &EmergencyScope,
        rng: &mut impl CryptoRngCore,
    ) -> Result<String> {
        let grantor = self.account_id()?;
        let contact = parse_id(contact_account_id)?;
        match scope {
            EmergencyScope::Account => {
                let context = SealContext::EmergencyAccount {
                    grantor_account_id: &grantor,
                    contact_account_id: &contact,
                };
                seal_for(
                    contact_public_enc_key,
                    contact_pq_key,
                    &context,
                    self.ask(),
                    rng,
                )
            }
            EmergencyScope::Vault { vault_id } => {
                let vault_id = parse_id(vault_id)?;
                let context = SealContext::EmergencyVault {
                    grantor_account_id: &grantor,
                    contact_account_id: &contact,
                    vault_id: &vault_id,
                };
                seal_for(
                    contact_public_enc_key,
                    contact_pq_key,
                    &context,
                    self.vault_key(&vault_id)?,
                    rng,
                )
            }
        }
    }

    /// As the contact, opens a released account key and unlocks the grantor's account with it.
    /// `grantor` is the grantor's account bundle; the key must open its private keys, so a
    /// server can't substitute another account.
    pub fn open_emergency_account(&self, grantor: AccountBundle, sealed: &str) -> Result<Session> {
        let grantor_id = parse_id(
            grantor
                .account_id
                .as_deref()
                .ok_or(Error::InvalidAccountBundle)?,
        )?;
        let contact_id = self.account_id()?;
        let context = SealContext::EmergencyAccount {
            grantor_account_id: &grantor_id,
            contact_account_id: &contact_id,
        };
        let ask = open_key(self.opener(), &context, sealed)?;
        Session::with_ask(grantor, ask)
    }

    /// As the contact, opens a released vault key and keeps it in this session, so the
    /// grantor's items in that vault decrypt like any other.
    pub fn open_emergency_vault(
        &mut self,
        grantor_account_id: &str,
        vault_id: &str,
        sealed: &str,
    ) -> Result<()> {
        let (grantor, vault_id) = (parse_id(grantor_account_id)?, parse_id(vault_id)?);
        let contact = self.account_id()?;
        let context = SealContext::EmergencyVault {
            grantor_account_id: &grantor,
            contact_account_id: &contact,
            vault_id: &vault_id,
        };
        let key = open_key(self.opener(), &context, sealed)?;
        self.insert_vault_key(vault_id, key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::account::new_id;
    use crate::item::Item;
    use crate::sharing::test_support::account;

    const NOW: u64 = 1_761_177_600_000;

    fn item() -> Item {
        Item::from_json(
            r#"{"overview":{"title":"Bank","type":"login"},"details":{"password":"p"}}"#,
        )
        .unwrap()
    }

    #[test]
    fn the_contact_unlocks_the_grantors_account() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut grantor = account(&mut rng);
        let contact = account(&mut rng);
        let vault = grantor.create_shared_vault(NOW, &mut rng).unwrap();
        let item_id = new_id(NOW, &mut rng);
        let encrypted = grantor
            .encrypt_item(&vault.id, &item_id, &item(), None, &mut rng)
            .unwrap();

        let sealed = grantor
            .seal_for_emergency_contact(
                &contact.account_id().unwrap(),
                &contact.key_pairs().public_enc_key(),
                None,
                &EmergencyScope::Account,
                &mut rng,
            )
            .unwrap();
        let mut as_grantor = contact
            .open_emergency_account(grantor.bundle().clone(), &sealed)
            .unwrap();
        // With the grantor's private keys, the grantor's own grants open too.
        as_grantor
            .open_shared_vault(&vault.grant, &grantor.key_pairs().public_sign_key())
            .unwrap();
        assert_eq!(
            as_grantor
                .decrypt_item(&vault.id, &item_id, &encrypted)
                .unwrap(),
            item()
        );

        // The key only unlocks the grantor it was sealed for.
        let other = account(&mut rng);
        assert_eq!(
            contact
                .open_emergency_account(other.bundle().clone(), &sealed)
                .err(),
            Some(Error::DecryptionFailed)
        );
        // And only for the contact it was sealed to.
        assert!(
            other
                .open_emergency_account(grantor.bundle().clone(), &sealed)
                .is_err()
        );
    }

    #[test]
    fn a_vault_scope_releases_only_that_vault() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut grantor = account(&mut rng);
        let mut contact = account(&mut rng);
        let vault = grantor.create_shared_vault(NOW, &mut rng).unwrap();
        let item_id = new_id(NOW, &mut rng);
        let encrypted = grantor
            .encrypt_item(&vault.id, &item_id, &item(), None, &mut rng)
            .unwrap();
        let scope = EmergencyScope::Vault {
            vault_id: vault.id.clone(),
        };
        let sealed = grantor
            .seal_for_emergency_contact(
                &contact.account_id().unwrap(),
                &contact.key_pairs().public_enc_key(),
                None,
                &scope,
                &mut rng,
            )
            .unwrap();
        let grantor_id = grantor.account_id().unwrap();

        let elsewhere = new_id(NOW, &mut rng);
        assert_eq!(
            contact
                .open_emergency_vault(&grantor_id, &elsewhere, &sealed)
                .err(),
            Some(Error::DecryptionFailed)
        );
        assert!(
            contact
                .open_emergency_account(grantor.bundle().clone(), &sealed)
                .is_err()
        );
        contact
            .open_emergency_vault(&grantor_id, &vault.id, &sealed)
            .unwrap();
        assert_eq!(
            contact
                .decrypt_item(&vault.id, &item_id, &encrypted)
                .unwrap(),
            item()
        );
    }

    #[test]
    fn scopes_serialise_with_a_type_tag() {
        assert_eq!(
            serde_json::to_value(EmergencyScope::Account).unwrap(),
            serde_json::json!({ "type": "account" })
        );
        let vault: EmergencyScope =
            serde_json::from_value(serde_json::json!({ "type": "vault", "vaultId": "v" })).unwrap();
        assert_eq!(
            vault,
            EmergencyScope::Vault {
                vault_id: "v".into()
            }
        );
    }
}
