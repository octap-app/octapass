//! ML-KEM-768 (FIPS 203) key pairs, the post-quantum half of the hybrid sealed box in
//! [`seal`](super::seal). Never used alone: see plan 03, "Post-quantum sharing".
//!
//! The private key is the 64-byte seed `d ‖ z`, which is the form FIPS 203 recommends keeping.

use core::fmt;

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{B32, Key, Seed};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::encoding::{b64_decode, b64_encode};
use crate::error::{Error, Result};

pub const PUBLIC_KEY_LEN: usize = 1184;
pub const CIPHERTEXT_LEN: usize = 1088;
pub const SEED_LEN: usize = 64;
const SHARED_SECRET_LEN: usize = 32;

/// An ML-KEM-768 encapsulation key, checked as FIPS 203 requires.
#[derive(Clone, PartialEq, Eq)]
pub struct PqPublicKey {
    bytes: Vec<u8>,
    key: EncapsulationKey,
}

impl PqPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = Key::<EncapsulationKey>::try_from(bytes).map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            key: EncapsulationKey::new(&encoded).map_err(|_| Error::InvalidKey)?,
            bytes: bytes.to_vec(),
        })
    }

    pub fn from_b64(text: &str) -> Result<Self> {
        Self::from_bytes(&b64_decode(text)?)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn to_b64(&self) -> String {
        b64_encode(&self.bytes)
    }

    /// `ML-KEM.Encaps`, with the 32 random bytes FIPS 203 calls `m` drawn from `rng`.
    pub(crate) fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> ([u8; CIPHERTEXT_LEN], Zeroizing<[u8; SHARED_SECRET_LEN]>) {
        let mut m = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
        rng.fill_bytes(m.as_mut());
        let (ciphertext, shared) = self.key.encapsulate_deterministic(&B32::from(*m));
        let mut secret = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
        secret.copy_from_slice(&shared);
        let mut out = [0u8; CIPHERTEXT_LEN];
        out.copy_from_slice(&ciphertext);
        (out, secret)
    }
}

impl fmt::Debug for PqPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PqPublicKey({})", b64_encode(&self.bytes[..8]))
    }
}

/// An ML-KEM-768 key pair. Zeroes itself on drop.
pub struct PqKeyPair {
    seed: Zeroizing<[u8; SEED_LEN]>,
    decapsulation: DecapsulationKey,
    public: PqPublicKey,
}

impl PqKeyPair {
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rng.fill_bytes(seed.as_mut());
        Self::expand(seed)
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; SEED_LEN] = seed.try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self::expand(Zeroizing::new(seed)))
    }

    fn expand(seed: Zeroizing<[u8; SEED_LEN]>) -> Self {
        let decapsulation = DecapsulationKey::from_seed(Seed::from(*seed));
        let encoded = decapsulation.encapsulation_key().to_bytes();
        let public = PqPublicKey::from_bytes(&encoded)
            .expect("an encapsulation key derived from a seed is well formed");
        Self {
            seed,
            decapsulation,
            public,
        }
    }

    pub fn public_key(&self) -> &PqPublicKey {
        &self.public
    }

    pub(crate) fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// `ML-KEM.Decaps`. A bad ciphertext gives a different secret, not an error: FIPS 203's
    /// implicit rejection, so the box's tag is what fails.
    pub(crate) fn decapsulate(
        &self,
        ciphertext: &[u8; CIPHERTEXT_LEN],
    ) -> Zeroizing<[u8; SHARED_SECRET_LEN]> {
        let ciphertext = Ciphertext::from(*ciphertext);
        let shared = self.decapsulation.decapsulate(&ciphertext);
        let mut secret = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
        secret.copy_from_slice(&shared);
        secret
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn encapsulates_and_decapsulates() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let pair = PqKeyPair::generate(&mut rng);
        assert_eq!(pair.public_key().as_bytes().len(), PUBLIC_KEY_LEN);
        let (ciphertext, shared) = pair.public_key().encapsulate(&mut rng);
        assert_eq!(pair.decapsulate(&ciphertext), shared);
    }

    #[test]
    fn a_seed_gives_the_same_key_pair() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let pair = PqKeyPair::generate(&mut rng);
        let again = PqKeyPair::from_seed(pair.seed()).unwrap();
        assert_eq!(pair.public_key(), again.public_key());
        assert_eq!(
            PqKeyPair::from_seed(&[0; 63]).err(),
            Some(Error::InvalidKey)
        );
    }

    #[test]
    fn a_tampered_ciphertext_gives_a_different_secret() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let pair = PqKeyPair::generate(&mut rng);
        let (mut ciphertext, shared) = pair.public_key().encapsulate(&mut rng);
        ciphertext[0] ^= 1;
        assert_ne!(pair.decapsulate(&ciphertext), shared);
    }

    #[test]
    fn refuses_malformed_public_keys() {
        assert_eq!(
            PqPublicKey::from_bytes(&[0; 32]).err(),
            Some(Error::InvalidKey)
        );
        // FIPS 203's modulus check: every coefficient must be below q.
        assert_eq!(
            PqPublicKey::from_bytes(&[0xff; PUBLIC_KEY_LEN]).err(),
            Some(Error::InvalidKey)
        );
    }
}
