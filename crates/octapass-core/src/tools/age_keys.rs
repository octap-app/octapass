//! The text forms of age X25519 keys, as `age-keygen` writes them: `AGE-SECRET-KEY-1…` for a private
//! key and `age1…` for a public key, both Bech32. Shared by file encryption (`tools::age`) and the
//! toolkit's key generator (`tools::toolkit::age_key`), so there is one encoding.

use bech32::{FromBase32, ToBase32, Variant};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const SECRET_PREFIX: &str = "age-secret-key-";
const PUBLIC_PREFIX: &str = "age";

fn encode(prefix: &str, key: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(
        bech32::encode(prefix, key.to_base32(), Variant::Bech32)
            .expect("32 bytes and a short lower-case prefix always encode"),
    )
}

/// `age1…` for an X25519 public key.
pub fn recipient_string(public_key: &[u8; 32]) -> String {
    encode(PUBLIC_PREFIX, public_key).to_string()
}

/// `AGE-SECRET-KEY-1…` for an X25519 private key.
pub fn identity_string(private_key: &[u8; 32]) -> Zeroizing<String> {
    Zeroizing::new(encode(SECRET_PREFIX, private_key).to_uppercase())
}

/// `age1…` for the public half of an X25519 private key.
pub fn recipient_of_secret(private_key: &[u8; 32]) -> String {
    recipient_string(PublicKey::from(&StaticSecret::from(*private_key)).as_bytes())
}

/// The private key in an `AGE-SECRET-KEY-1…` string.
pub fn parse_identity(text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let (prefix, data, variant) = bech32::decode(text.trim()).map_err(|_| Error::InvalidKey)?;
    if prefix != SECRET_PREFIX || variant != Variant::Bech32 {
        return Err(Error::InvalidKey);
    }
    let data = Zeroizing::new(Vec::<u8>::from_base32(&data).map_err(|_| Error::InvalidKey)?);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(
        data.as_slice()
            .get(..32)
            .filter(|_| data.len() == 32)
            .ok_or(Error::InvalidKey)?,
    );
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The pair from age's own test kit (filippo.io/age/internal/testkit).
    const IDENTITY: &str =
        "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0";
    const RECIPIENT: &str = "age1xmwwc06ly3ee5rytxm9mflaz2u56jjj36s0mypdrwsvlul66mv4q47ryef";

    #[test]
    fn round_trips_the_test_kit_pair() {
        let key = parse_identity(IDENTITY).unwrap();
        assert_eq!(identity_string(&key).as_str(), IDENTITY);
        assert_eq!(recipient_of_secret(&key), RECIPIENT);
        assert!(
            parse_identity("age1xmwwc06ly3ee5rytxm9mflaz2u56jjj36s0mypdrwsvlul66mv4q47ryef")
                .is_err()
        );
    }
}
