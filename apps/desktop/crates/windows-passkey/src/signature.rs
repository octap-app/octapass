//! The signatures Windows puts on plugin requests and on user verification.
//!
//! Microsoft's `pluginauthenticator.idl` calls them a "Request Hash Signature": a signature over
//! the SHA-256 of the encoded request. Keys are CNG `BCRYPT_PUBLIC_KEY_BLOB`s, whose first field
//! names the algorithm, and which algorithm Windows uses isn't documented: Microsoft's PasskeyManager
//! sample handles RSA-PSS (SHA-256, 32-byte salt) and leaves ECDSA to NCrypt, and Bitwarden's
//! `win_webauthn` reports seeing RSA-PSS, P-256 and P-384. Those are checked here; anything else
//! fails closed. The hash is SHA-256 whatever the curve, and ECDSA signatures are CNG's raw
//! `r ‖ s`.

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use rsa::{BigUint, Pss, RsaPublicKey, pss};
use sha2::{Digest, Sha256};

// bcrypt.h. Also asserted against the `windows` crate in `windows::ffi`.
pub(crate) const ECDSA_P256_MAGIC: u32 = 0x3153_4345; // "ECS1"
pub(crate) const ECDSA_P384_MAGIC: u32 = 0x3353_4345; // "ECS3"
pub(crate) const RSA_MAGIC: u32 = 0x3141_5352; // "RSA1"

const MIN_RSA_BITS: usize = 2048;
const MAX_RSA_BITS: usize = 16384;
const PSS_SALT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("the public key is malformed")]
    MalformedKey,
    #[error("the public key's algorithm isn't supported")]
    UnsupportedKey,
    #[error("the signature doesn't verify")]
    Invalid,
}

#[derive(Debug)]
pub enum PublicKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    Rsa(RsaPublicKey),
}

fn u32_at(blob: &[u8], at: usize) -> Result<u32, SignatureError> {
    blob.get(at..at + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(SignatureError::MalformedKey)
}

fn sec1(x_and_y: &[u8]) -> Vec<u8> {
    let mut point = Vec::with_capacity(x_and_y.len() + 1);
    point.push(0x04);
    point.extend_from_slice(x_and_y);
    point
}

impl PublicKey {
    /// A `BCRYPT_ECCPUBLIC_BLOB` (`Magic, cbKey, X, Y`) or `BCRYPT_RSAPUBLIC_BLOB` (`Magic,
    /// BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2, exponent, modulus`).
    pub fn from_blob(blob: &[u8]) -> Result<Self, SignatureError> {
        match u32_at(blob, 0)? {
            ECDSA_P256_MAGIC => {
                let point = ecc_point(blob, 32)?;
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1(point))
                    .map(Self::P256)
                    .map_err(|_| SignatureError::MalformedKey)
            }
            ECDSA_P384_MAGIC => {
                let point = ecc_point(blob, 48)?;
                p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1(point))
                    .map(Self::P384)
                    .map_err(|_| SignatureError::MalformedKey)
            }
            RSA_MAGIC => rsa_key(blob).map(Self::Rsa),
            _ => Err(SignatureError::UnsupportedKey),
        }
    }

    /// Checks a signature over a SHA-256 hash.
    pub fn verify_hash(&self, hash: &[u8; 32], signature: &[u8]) -> Result<(), SignatureError> {
        let valid = match self {
            Self::P256(key) => p256::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify_prehash(hash, &signature).is_ok()),
            Self::P384(key) => p384::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify_prehash(hash, &signature).is_ok()),
            Self::Rsa(key) => {
                let scheme: Pss = pss::Pss::new_with_salt::<Sha256>(PSS_SALT);
                key.verify(scheme, hash, signature).is_ok()
            }
        };
        valid.then_some(()).ok_or(SignatureError::Invalid)
    }
}

fn ecc_point(blob: &[u8], size: usize) -> Result<&[u8], SignatureError> {
    let declared = u32_at(blob, 4)? as usize;
    if declared != size || blob.len() != 8 + 2 * size {
        return Err(SignatureError::MalformedKey);
    }
    Ok(&blob[8..])
}

fn rsa_key(blob: &[u8]) -> Result<RsaPublicKey, SignatureError> {
    const HEADER: usize = 24;
    let bits = u32_at(blob, 4)? as usize;
    let exponent = u32_at(blob, 8)? as usize;
    let modulus = u32_at(blob, 12)? as usize;
    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits)
        || exponent == 0
        || exponent > 8
        || modulus != bits.div_ceil(8)
        || blob.len() != HEADER + exponent + modulus
    {
        return Err(SignatureError::MalformedKey);
    }
    let (exponent, modulus) = blob[HEADER..].split_at(exponent);
    let modulus = BigUint::from_bytes_be(modulus);
    if modulus.bits() != bits {
        return Err(SignatureError::MalformedKey);
    }
    RsaPublicKey::new_with_max_size(modulus, BigUint::from_bytes_be(exponent), MAX_RSA_BITS)
        .map_err(|_| SignatureError::MalformedKey)
}

/// The SHA-256 of an encoded request, which everything here signs.
pub fn request_hash(encoded: &[u8]) -> [u8; 32] {
    Sha256::digest(encoded).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    // Made with OpenSSL 4.1 (`pkeyutl -sign`, `-pkeyopt rsa_padding_mode:pss -pkeyopt
    // rsa_pss_saltlen:32`), the public keys rewritten as CNG blobs: independent of the code here.
    const MESSAGE: &[u8] = b"openpass windows plugin request vector";
    const HASH: &str = "609f76419f612fb74e86f47bbc6c8f5ebd2188f30189ca9a76f96d5ce7baa53e";
    const P256_BLOB: &str = "4543533120000000fac5200d8b1310f7b6e3dcd56ecdf2ebcab2703c18a9ce4624c3861bf0b2f532f260adacf882350ad81767816367fa427321220bff2168ee6b3d7054c6ce45e3";
    const P256_SIG: &str = "01a834e37ec84d7a34f636e851a0235f0fd0b72baa60b171878eb23b32d41fcc47087ee1710e22d7ff6a4c04fa6b61120799cf1bcfbab56e2201ae190a69ec2b";
    const P384_BLOB: &str = "45435333300000004233f2bc130ad82c59b6960f331313c9e8f736e503f6acb085c6f7ae2ef25a38d852abdbdb60dae2054503035fc5635186e1f1bf1eee1278a8663588f2e4bb12190c79ce9fecd2800071fa20f0aaa80a02ee2eebca3f1fb9f8d277d30e61672b";
    const P384_SIG: &str = "da0f2d7b73beef2e07ff1db251c86f9d6f07b12061568b3f4c35382b82170ca01bad9694ef9475ddc27bbc6aa191c090be5c2891e372d7b531cf27aadd8f1fcd5324baf2857c8ca37c1cd7ee69a6e23773639189057aa09a7524f873efc14a06";
    const RSA_BLOB: &str = "525341310008000003000000000100000000000000000000010001d4a2b26deb5b16fe54ce60aef1dbfcb2468037a0764f2a8ca0ca817e52be4f58852ace13e6f9426bd95a46140496781d9299638fd7e83f60bf445dc7f0f622b59c19cfe823e5cb91759532f76ae696cf97782c1f755a5cc7b92a1b935d2af58940143e9d3729f7d25308863bc869f1337cf5beb69925ee818540595d72a773b8ec64d4cb3e5b75b16af80e71afd08241a59a9686016f7fabd6afe3bf1c976c69e74b9fdb817d7644e29e8d1cf069c13c4c9a382063acbd21bea6a0b16ca59fdfbca5a5463efdbc069a14eef4850fd1d4f8bb75917d07b38c9303620d46014f80ce70cc2712d80ed1d2cfbf19eb0071e667edb6936a0c169756920389dc088c89";
    const RSA_SIG: &str = "707948f983ffcbef166fe45dfb96646cb35cdb7a84905ddbe925e298e50cdc919b6765deea51ca24b9c2b9f8073b3d065af20edbcb40f7a96ca860d42f126d670270eb946fa1f9c326a9ca995881af4b0dd26139cbd402dfa695dbdcbf1e2572a267b4f8b11d92b9802c652b70b3227997a6f0d268c4f4b6acf73e5b591d8c26ac14cb73a77c48601779541d698e7cf81f7ee97c40378aee6ba85e68abe22860eea51e32578f293056e416b313fe47f0789354b916a6cddb80e89adb4e00df690ee0dbb88902e9cf2707f7f473184c80a9c4d856fee2c23379d84bd1db2001df95916dbf77097807117645f127fbc986eeb828f01d7fb56fdf14b546909f8ad5";

    #[test]
    fn hashes_the_request_with_sha256() {
        assert_eq!(request_hash(MESSAGE).to_vec(), hex(HASH));
    }

    #[test]
    fn verifies_openssl_signatures_of_every_kind() {
        let hash = request_hash(MESSAGE);
        for (blob, signature) in [
            (P256_BLOB, P256_SIG),
            (P384_BLOB, P384_SIG),
            (RSA_BLOB, RSA_SIG),
        ] {
            let key = PublicKey::from_blob(&hex(blob)).unwrap();
            let signature = hex(signature);
            assert_eq!(key.verify_hash(&hash, &signature), Ok(()));

            let mut other_hash = hash;
            other_hash[0] ^= 1;
            assert_eq!(
                key.verify_hash(&other_hash, &signature),
                Err(SignatureError::Invalid)
            );
            let mut flipped = signature.clone();
            flipped[0] ^= 1;
            assert_eq!(
                key.verify_hash(&hash, &flipped),
                Err(SignatureError::Invalid)
            );
            assert_eq!(key.verify_hash(&hash, &[]), Err(SignatureError::Invalid));
            assert_eq!(
                key.verify_hash(&hash, &signature[..signature.len() - 1]),
                Err(SignatureError::Invalid)
            );
        }
    }

    #[test]
    fn another_keys_signature_fails() {
        let key = PublicKey::from_blob(&hex(P256_BLOB)).unwrap();
        // A valid signature from P-384 isn't even the right length.
        assert_eq!(
            key.verify_hash(&request_hash(MESSAGE), &hex(P384_SIG)),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn refuses_keys_it_cant_read() {
        assert_eq!(
            PublicKey::from_blob(&[]).unwrap_err(),
            SignatureError::MalformedKey
        );
        // ECS5, P-521: not seen from Windows, so not accepted.
        let p521 = [0x45, 0x43, 0x53, 0x35, 66, 0, 0, 0];
        assert_eq!(
            PublicKey::from_blob(&p521).unwrap_err(),
            SignatureError::UnsupportedKey
        );
        let mut blob = hex(P256_BLOB);
        blob.pop();
        assert_eq!(
            PublicKey::from_blob(&blob).unwrap_err(),
            SignatureError::MalformedKey
        );
        // Off the curve.
        let mut blob = hex(P256_BLOB);
        blob[40] ^= 1;
        assert_eq!(
            PublicKey::from_blob(&blob).unwrap_err(),
            SignatureError::MalformedKey
        );
        // A declared size that doesn't match the magic.
        let mut blob = hex(P256_BLOB);
        blob[4] = 48;
        assert_eq!(
            PublicKey::from_blob(&blob).unwrap_err(),
            SignatureError::MalformedKey
        );
        let mut blob = hex(RSA_BLOB);
        blob[13] = 0; // cbModulus: 0x0100 becomes 0
        assert_eq!(
            PublicKey::from_blob(&blob).unwrap_err(),
            SignatureError::MalformedKey
        );
    }

    #[test]
    fn refuses_short_rsa_keys() {
        let mut blob = RSA_MAGIC.to_le_bytes().to_vec();
        blob.extend_from_slice(&1024u32.to_le_bytes());
        blob.extend_from_slice(&3u32.to_le_bytes());
        blob.extend_from_slice(&128u32.to_le_bytes());
        blob.extend_from_slice(&[0; 8]);
        blob.extend_from_slice(&[1, 0, 1]);
        blob.extend_from_slice(&[0xff; 128]);
        assert_eq!(
            PublicKey::from_blob(&blob).unwrap_err(),
            SignatureError::MalformedKey
        );
    }
}
