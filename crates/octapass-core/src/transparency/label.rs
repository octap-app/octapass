//! Log labels: an email as the key log files it.
//!
//! ```text
//! label = SHA-256("octapass/v1/key-log-label" ‖ 0x00 ‖ VOPRF(oprf_key, normalised email))
//! ```
//!
//! RFC 9497's VOPRF, ristretto255-SHA512. The email is blinded on the device and the server proves
//! it used the pinned key, so a label can only be had online (one request, charged to a budget, per
//! email tried) and the server can't give two people different labels for the same email.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use voprf::{BlindedElement, EvaluationElement, Group, Proof, VoprfClient, VoprfServer};

use crate::encoding::{b64_decode, b64_encode};
use crate::error::{Error, Result};
use crate::kdf::normalize_email;

type Suite = voprf::Ristretto255;

const SEED_INFO: &[u8] = b"octapass/v1/key-log-oprf";

/// A blinded email, ready for `POST /v1/transparency/label`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlindedLabel {
    /// Keep this on the device: [`finish`] needs it.
    pub state: String,
    pub blinded: String,
}

/// The server's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluatedLabel {
    pub evaluated: String,
    pub proof: String,
}

fn mismatch<T>(_: T) -> Error {
    Error::KeyLogMismatch
}

fn output_to_label(output: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"octapass/v1/key-log-label\0")
        .chain_update(output)
        .finalize()
        .into()
}

pub fn blind(email: &str, rng: &mut impl CryptoRngCore) -> Result<BlindedLabel> {
    let blinded = VoprfClient::<Suite>::blind(normalize_email(email).as_bytes(), rng)
        .map_err(|_| Error::InvalidKey)?;
    Ok(BlindedLabel {
        state: b64_encode(&blinded.state.serialize()),
        blinded: b64_encode(&blinded.message.serialize()),
    })
}

/// Checks the server's proof against the pinned `oprf_key` and gives the label.
pub fn finish(
    email: &str,
    state: &str,
    evaluated: &EvaluatedLabel,
    oprf_key: &str,
) -> Result<[u8; 32]> {
    let client = VoprfClient::<Suite>::deserialize(&b64_decode(state)?).map_err(mismatch)?;
    let element = EvaluationElement::<Suite>::deserialize(&b64_decode(&evaluated.evaluated)?)
        .map_err(mismatch)?;
    let proof = Proof::<Suite>::deserialize(&b64_decode(&evaluated.proof)?).map_err(mismatch)?;
    let public = <Suite as voprf::CipherSuite>::Group::deserialize_elem(&b64_decode(oprf_key)?)
        .map_err(mismatch)?;
    let output = client
        .finalize(normalize_email(email).as_bytes(), &element, &proof, public)
        .map_err(mismatch)?;
    Ok(output_to_label(&output))
}

/// The server's half.
pub struct LabelKey(VoprfServer<Suite>);

impl LabelKey {
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        VoprfServer::new_from_seed(seed, SEED_INFO)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    /// base64url public key, which clients pin.
    pub fn public_key(&self) -> String {
        b64_encode(&<Suite as voprf::CipherSuite>::Group::serialize_elem(
            self.0.get_public_key(),
        ))
    }

    pub fn evaluate(&self, blinded: &str, rng: &mut impl CryptoRngCore) -> Result<EvaluatedLabel> {
        let blinded = BlindedElement::<Suite>::deserialize(&b64_decode(blinded)?)
            .map_err(|_| Error::InvalidKey)?;
        let result = self.0.blind_evaluate(rng, &blinded);
        Ok(EvaluatedLabel {
            evaluated: b64_encode(&result.message.serialize()),
            proof: b64_encode(&result.proof.serialize()),
        })
    }

    /// An email's label computed directly, to check the one a client publishes under.
    pub fn label(&self, email: &str) -> Result<[u8; 32]> {
        let output = self
            .0
            .evaluate(normalize_email(email).as_bytes())
            .map_err(|_| Error::InvalidKey)?;
        Ok(output_to_label(&output))
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    fn run(key: &LabelKey, email: &str, rng: &mut ChaCha20Rng) -> Result<[u8; 32]> {
        let blinded = blind(email, rng)?;
        let evaluated = key.evaluate(&blinded.blinded, rng)?;
        finish(email, &blinded.state, &evaluated, &key.public_key())
    }

    #[test]
    fn a_blinded_label_equals_the_direct_one() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let key = LabelKey::from_seed(&[1; 32]).unwrap();
        let label = run(&key, "bob@example.com", &mut rng).unwrap();
        assert_eq!(label, key.label("bob@example.com").unwrap());
        assert_eq!(label, run(&key, "bob@example.com", &mut rng).unwrap());
        assert_eq!(label, run(&key, "  BOB@example.com", &mut rng).unwrap());
        assert_ne!(label, run(&key, "carol@example.com", &mut rng).unwrap());
    }

    #[test]
    fn labels_depend_on_the_server_key() {
        let one = LabelKey::from_seed(&[1; 32]).unwrap();
        let two = LabelKey::from_seed(&[2; 32]).unwrap();
        assert_ne!(
            one.label("bob@example.com").unwrap(),
            two.label("bob@example.com").unwrap()
        );
    }

    #[test]
    fn an_answer_under_another_key_is_refused() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let pinned = LabelKey::from_seed(&[1; 32]).unwrap();
        let other = LabelKey::from_seed(&[2; 32]).unwrap();
        let blinded = blind("bob@example.com", &mut rng).unwrap();
        let evaluated = other.evaluate(&blinded.blinded, &mut rng).unwrap();
        assert_eq!(
            finish(
                "bob@example.com",
                &blinded.state,
                &evaluated,
                &pinned.public_key()
            )
            .err(),
            Some(Error::KeyLogMismatch)
        );
    }

    /// The proof covers the blinded element, not the email, so finishing with the wrong email
    /// doesn't fail: it gives that email's input a label nobody else will compute.
    #[test]
    fn finishing_with_another_email_gives_no_one_s_label() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let key = LabelKey::from_seed(&[1; 32]).unwrap();
        let blinded = blind("bob@example.com", &mut rng).unwrap();
        let evaluated = key.evaluate(&blinded.blinded, &mut rng).unwrap();
        let mixed = finish(
            "mallory@example.com",
            &blinded.state,
            &evaluated,
            &key.public_key(),
        )
        .unwrap();
        assert_ne!(mixed, key.label("bob@example.com").unwrap());
        assert_ne!(mixed, key.label("mallory@example.com").unwrap());
    }
}
