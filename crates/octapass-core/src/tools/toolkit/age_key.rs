//! age X25519 keys (plan 16 §1): `AGE-SECRET-KEY-1…` identities and `age1…` recipients, the Bech32
//! encodings of an X25519 secret and public key, as `age-keygen` writes them.

use rand_core::CryptoRngCore;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::tools::age_keys;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgeKey {
    /// `AGE-SECRET-KEY-1…`.
    pub identity: Zeroizing<String>,
    /// `age1…`: safe to share.
    pub recipient: String,
}

fn from_secret(secret: &[u8; 32]) -> Result<AgeKey> {
    Ok(AgeKey {
        identity: age_keys::identity_string(secret),
        recipient: age_keys::recipient_of_secret(secret),
    })
}

pub fn generate(rng: &mut impl CryptoRngCore) -> Result<AgeKey> {
    let mut secret = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(secret.as_mut());
    from_secret(&secret)
}

/// The recipient of an `AGE-SECRET-KEY-1…` identity. Lines starting with `#` and other text around
/// it, as in a key file, are skipped.
pub fn read_identity(text: &str) -> Result<AgeKey> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("AGE-SECRET-KEY-1"))
        .ok_or(Error::InvalidKeyFile)?;
    let secret = age_keys::parse_identity(line).map_err(|_| Error::InvalidKeyFile)?;
    from_secret(&secret)
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;

    // The pair from age's own test kit (filippo.io/age/internal/testkit).
    const IDENTITY: &str =
        "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";
    const RECIPIENT: &str = "age1xmwwc06ly3ee5rytxm9mflaz2u56jjj36s0mypdrwsvlul66mv4q47ryef";

    #[test]
    fn reads_the_age_test_kit_identity() {
        let key = read_identity(IDENTITY).unwrap();
        assert_eq!(key.recipient, RECIPIENT);
        assert_eq!(key.identity.as_str(), IDENTITY);
    }

    #[test]
    fn key_files_with_comments() {
        let file =
            format!("# created: 2026-11-02T00:00:00Z\n# public key: {RECIPIENT}\n{IDENTITY}\n");
        assert_eq!(read_identity(&file).unwrap().recipient, RECIPIENT);
    }

    #[test]
    fn generated_keys_read_back() {
        let key = generate(&mut rand_chacha::ChaCha20Rng::from_seed([2; 32])).unwrap();
        assert!(key.identity.starts_with("AGE-SECRET-KEY-1"));
        assert!(key.recipient.starts_with("age1"));
        assert_eq!(
            read_identity(&key.identity).unwrap().recipient,
            key.recipient
        );
    }

    #[test]
    fn a_bad_checksum_is_refused() {
        let broken = IDENTITY.replace("EGTZ", "EGTX");
        assert!(read_identity(&broken).is_err());
        assert!(read_identity(RECIPIENT).is_err());
    }
}
