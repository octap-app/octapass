//! Publishing this account's key record from an unlocked session.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::encoding::b64_encode;
use crate::envelope::{Context, open_b64, seal_b64};
use crate::error::{Error, Result};
use crate::session::Session;
use crate::sharing::pq::PqKeyPair;
use crate::transparency::record::{KeyRecord, OfferedKeys};

/// `POST /v1/transparency/publish`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishKeys {
    pub record: KeyRecord,
    /// The ML-KEM seed sealed by the ASK (context `pqprivkey`).
    pub wrapped_pq_private_key: String,
}

impl Session {
    /// A signed record for the log `log_id`, keeping the account's ML-KEM key or generating its
    /// first one. Nothing changes here until the server accepts it and
    /// [`Session::adopt_key_record`] runs.
    pub fn prepare_key_record(
        &self,
        log_id: &str,
        label: &[u8; 32],
        now_ms: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PublishKeys> {
        let generated;
        let pair = match self.pq_keys() {
            Some(pair) => pair,
            None => {
                generated = PqKeyPair::generate(rng);
                &generated
            }
        };
        let bundle = self.bundle();
        let record = KeyRecord {
            log_id: log_id.to_owned(),
            account_id: self.account_id()?,
            label: b64_encode(label),
            public_enc_key: bundle.public_enc_key.clone(),
            public_sign_key: bundle.public_sign_key.clone(),
            public_pq_key: pair.public_key().to_b64(),
            created_at: now_ms,
            signature: String::new(),
        }
        .signed(self.key_pairs().signing_key());
        Ok(PublishKeys {
            record,
            wrapped_pq_private_key: seal_b64(self.ask(), &Context::PqPrivateKey, pair.seed(), rng)?,
        })
    }

    /// Takes a record the server accepted, or one another device of this account published
    /// first, checking that it's this account's and that the sealed key opens and matches it.
    pub fn adopt_key_record(&mut self, keys: PublishKeys) -> Result<()> {
        let bundle = self.bundle();
        keys.record.verify_for(&OfferedKeys {
            account_id: &self.account_id()?,
            public_enc_key: &bundle.public_enc_key,
            public_sign_key: &bundle.public_sign_key,
        })?;
        let seed = open_b64(
            self.ask(),
            &Context::PqPrivateKey,
            &keys.wrapped_pq_private_key,
        )?;
        let pair = PqKeyPair::from_seed(&seed)?;
        if pair.public_key().to_b64() != keys.record.public_pq_key {
            return Err(Error::KeyMismatch);
        }
        let mut bundle = bundle.clone();
        bundle.wrapped_pq_private_key = Some(keys.wrapped_pq_private_key);
        bundle.key_record = Some(keys.record);
        self.set_bundle(bundle);
        self.set_pq_keys(pair);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::sharing::Role;
    use crate::sharing::grant::Recipient;
    use crate::sharing::test_support::account;

    const NOW: u64 = 1_761_177_600_000;

    #[test]
    fn publishing_keeps_old_grants_open_and_new_ones_are_hybrid() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut alice = account(&mut rng);
        let mut bob = account(&mut rng);
        let vault = alice.create_shared_vault(NOW, &mut rng).unwrap();
        let recipient = |bob: &Session| Recipient {
            account_id: bob.account_id().unwrap(),
            public_enc_key: bob.key_pairs().public_enc_key(),
            public_pq_key: bob.pq_keys().map(|keys| keys.public_key().clone()),
            role: Role::Read,
        };
        let classical = alice
            .grant_vault(&vault.id, &recipient(&bob), NOW, &mut rng)
            .unwrap();

        let keys = bob
            .prepare_key_record(&b64_encode(&[1; 32]), &[2; 32], NOW, &mut rng)
            .unwrap();
        assert!(
            bob.pq_keys().is_none(),
            "nothing changes before the server accepts"
        );
        bob.adopt_key_record(keys).unwrap();

        let alice_key = alice.key_pairs().public_sign_key();
        bob.open_shared_vault(&classical, &alice_key).unwrap();
        let hybrid = alice
            .grant_vault(&vault.id, &recipient(&bob), NOW, &mut rng)
            .unwrap();
        assert!(hybrid.wrapped_vault_key.len() > 1500);
        bob.open_shared_vault(&hybrid, &alice_key).unwrap();
    }

    #[test]
    fn the_key_stays_when_a_record_is_made_again() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut bob = account(&mut rng);
        let first = bob
            .prepare_key_record(&b64_encode(&[1; 32]), &[2; 32], NOW, &mut rng)
            .unwrap();
        bob.adopt_key_record(first.clone()).unwrap();
        let second = bob
            .prepare_key_record(&b64_encode(&[3; 32]), &[2; 32], NOW + 1, &mut rng)
            .unwrap();
        assert_eq!(first.record.public_pq_key, second.record.public_pq_key);
        assert_ne!(first.record.log_id, second.record.log_id);
    }

    #[test]
    fn a_session_reopens_its_ml_kem_key_from_the_bundle() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut bob = account(&mut rng);
        let keys = bob
            .prepare_key_record(&b64_encode(&[1; 32]), &[2; 32], NOW, &mut rng)
            .unwrap();
        bob.adopt_key_record(keys).unwrap();
        let reopened = Session::with_ask(bob.bundle().clone(), bob.ask().clone()).unwrap();
        assert_eq!(
            reopened.pq_keys().unwrap().public_key(),
            bob.pq_keys().unwrap().public_key()
        );

        // A server can't pair the sealed key with a record of its own making.
        let mut swapped = bob.bundle().clone();
        let mut record = swapped.key_record.take().unwrap();
        record.public_pq_key = PqKeyPair::generate(&mut rng).public_key().to_b64();
        swapped.key_record = Some(record);
        assert_eq!(
            Session::with_ask(swapped, bob.ask().clone()).err(),
            Some(Error::KeyLogMismatch)
        );
    }

    #[test]
    fn a_record_for_another_account_or_key_is_refused() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let alice = account(&mut rng);
        let mut bob = account(&mut rng);
        let keys = alice
            .prepare_key_record(&b64_encode(&[1; 32]), &[2; 32], NOW, &mut rng)
            .unwrap();
        assert_eq!(
            bob.adopt_key_record(keys).err(),
            Some(Error::KeyLogMismatch)
        );
    }
}
