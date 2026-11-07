//! Hashes and HMAC (plan 16 §2), for text and for files read in chunks, and comparing a file against
//! a published checksum. MD5 and SHA-1 are for checking old checksums only: [`Algorithm::is_legacy`]
//! labels them everywhere they're shown.

use blake2::{Blake2b512, Blake2s256};
use hmac::{Hmac, Mac};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};

use super::encode::{decode_base64, hex_decode, hex_encode};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "md5")]
    Md5,
    #[serde(rename = "crc32")]
    Crc32,
    #[serde(rename = "sha1")]
    Sha1,
    #[serde(rename = "sha224")]
    Sha224,
    #[serde(rename = "sha256")]
    Sha256,
    #[serde(rename = "sha384")]
    Sha384,
    #[serde(rename = "sha512")]
    Sha512,
    #[serde(rename = "sha3-224")]
    Sha3_224,
    #[serde(rename = "sha3-256")]
    Sha3_256,
    #[serde(rename = "sha3-384")]
    Sha3_384,
    #[serde(rename = "sha3-512")]
    Sha3_512,
    #[serde(rename = "blake2b")]
    Blake2b,
    #[serde(rename = "blake2s")]
    Blake2s,
    #[serde(rename = "blake3")]
    Blake3,
}

impl Algorithm {
    pub const ALL: [Algorithm; 14] = [
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
        Algorithm::Sha224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_224,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Blake3,
        Algorithm::Blake2b,
        Algorithm::Blake2s,
        Algorithm::Sha1,
        Algorithm::Md5,
        Algorithm::Crc32,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Md5 => "md5",
            Algorithm::Crc32 => "crc32",
            Algorithm::Sha1 => "sha1",
            Algorithm::Sha224 => "sha224",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
            Algorithm::Sha3_224 => "sha3-224",
            Algorithm::Sha3_256 => "sha3-256",
            Algorithm::Sha3_384 => "sha3-384",
            Algorithm::Sha3_512 => "sha3-512",
            Algorithm::Blake2b => "blake2b",
            Algorithm::Blake2s => "blake2s",
            Algorithm::Blake3 => "blake3",
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        let name = name.trim().to_ascii_lowercase().replace('_', "-");
        let name = match name.as_str() {
            "sha-1" => "sha1",
            "sha-224" => "sha224",
            "sha-256" => "sha256",
            "sha-384" => "sha384",
            "sha-512" => "sha512",
            "sha3224" => "sha3-224",
            "sha3256" => "sha3-256",
            "sha3384" => "sha3-384",
            "sha3512" => "sha3-512",
            "blake2b512" | "blake2b-512" => "blake2b",
            "blake2s256" | "blake2s-256" => "blake2s",
            other => other,
        };
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.name() == name)
            .ok_or(Error::UnsupportedAlgorithm)
    }

    /// Broken or not cryptographic at all: fine for checking a download against an old checksum,
    /// not for anything an attacker can influence.
    pub fn is_legacy(self) -> bool {
        matches!(self, Algorithm::Md5 | Algorithm::Sha1 | Algorithm::Crc32)
    }

    /// Bytes of output.
    pub fn output_len(self) -> usize {
        match self {
            Algorithm::Crc32 => 4,
            Algorithm::Md5 => 16,
            Algorithm::Sha1 => 20,
            Algorithm::Sha224 | Algorithm::Sha3_224 => 28,
            Algorithm::Sha256 | Algorithm::Sha3_256 | Algorithm::Blake2s | Algorithm::Blake3 => 32,
            Algorithm::Sha384 | Algorithm::Sha3_384 => 48,
            Algorithm::Sha512 | Algorithm::Sha3_512 | Algorithm::Blake2b => 64,
        }
    }
}

/// A hash being fed a file in chunks.
pub enum Hasher {
    Md5(Md5),
    Crc32(crc32fast::Hasher),
    Sha1(Sha1),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
    Sha3_224(Sha3_224),
    Sha3_256(Sha3_256),
    Sha3_384(Sha3_384),
    Sha3_512(Sha3_512),
    Blake2b(Blake2b512),
    Blake2s(Blake2s256),
    // Boxed: its state is almost 2 KB.
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    pub fn new(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Md5 => Hasher::Md5(Md5::new()),
            Algorithm::Crc32 => Hasher::Crc32(crc32fast::Hasher::new()),
            Algorithm::Sha1 => Hasher::Sha1(Sha1::new()),
            Algorithm::Sha224 => Hasher::Sha224(Sha224::new()),
            Algorithm::Sha256 => Hasher::Sha256(Sha256::new()),
            Algorithm::Sha384 => Hasher::Sha384(Sha384::new()),
            Algorithm::Sha512 => Hasher::Sha512(Sha512::new()),
            Algorithm::Sha3_224 => Hasher::Sha3_224(Sha3_224::new()),
            Algorithm::Sha3_256 => Hasher::Sha3_256(Sha3_256::new()),
            Algorithm::Sha3_384 => Hasher::Sha3_384(Sha3_384::new()),
            Algorithm::Sha3_512 => Hasher::Sha3_512(Sha3_512::new()),
            Algorithm::Blake2b => Hasher::Blake2b(Blake2b512::new()),
            Algorithm::Blake2s => Hasher::Blake2s(Blake2s256::new()),
            Algorithm::Blake3 => Hasher::Blake3(Box::default()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Md5(hasher) => Digest::update(hasher, data),
            Hasher::Crc32(hasher) => hasher.update(data),
            Hasher::Sha1(hasher) => Digest::update(hasher, data),
            Hasher::Sha224(hasher) => Digest::update(hasher, data),
            Hasher::Sha256(hasher) => Digest::update(hasher, data),
            Hasher::Sha384(hasher) => Digest::update(hasher, data),
            Hasher::Sha512(hasher) => Digest::update(hasher, data),
            Hasher::Sha3_224(hasher) => Digest::update(hasher, data),
            Hasher::Sha3_256(hasher) => Digest::update(hasher, data),
            Hasher::Sha3_384(hasher) => Digest::update(hasher, data),
            Hasher::Sha3_512(hasher) => Digest::update(hasher, data),
            Hasher::Blake2b(hasher) => Digest::update(hasher, data),
            Hasher::Blake2s(hasher) => Digest::update(hasher, data),
            Hasher::Blake3(hasher) => {
                hasher.update(data);
            }
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Md5(hasher) => hasher.finalize().to_vec(),
            Hasher::Crc32(hasher) => hasher.finalize().to_be_bytes().to_vec(),
            Hasher::Sha1(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha224(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha256(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha384(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha512(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha3_224(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha3_256(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha3_384(hasher) => hasher.finalize().to_vec(),
            Hasher::Sha3_512(hasher) => hasher.finalize().to_vec(),
            Hasher::Blake2b(hasher) => hasher.finalize().to_vec(),
            Hasher::Blake2s(hasher) => hasher.finalize().to_vec(),
            Hasher::Blake3(hasher) => hasher.finalize().as_bytes().to_vec(),
        }
    }
}

pub fn digest(algorithm: Algorithm, data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new(algorithm);
    hasher.update(data);
    hasher.finalize()
}

macro_rules! hmac_with {
    ($hash:ty, $key:expr, $data:expr) => {{
        let mut mac = <Hmac<$hash> as Mac>::new_from_slice($key).map_err(|_| Error::InvalidKey)?;
        Mac::update(&mut mac, $data);
        Ok(mac.finalize().into_bytes().to_vec())
    }};
}

/// HMAC with any of the SHA families. HMAC isn't defined over CRC32, and the BLAKE family has its
/// own keyed modes, so those are refused; so is MD5.
pub fn hmac(algorithm: Algorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Sha1 => hmac_with!(Sha1, key, data),
        Algorithm::Sha224 => hmac_with!(Sha224, key, data),
        Algorithm::Sha256 => hmac_with!(Sha256, key, data),
        Algorithm::Sha384 => hmac_with!(Sha384, key, data),
        Algorithm::Sha512 => hmac_with!(Sha512, key, data),
        Algorithm::Sha3_224 => hmac_with!(Sha3_224, key, data),
        Algorithm::Sha3_256 => hmac_with!(Sha3_256, key, data),
        Algorithm::Sha3_384 => hmac_with!(Sha3_384, key, data),
        Algorithm::Sha3_512 => hmac_with!(Sha3_512, key, data),
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

/// A checksum read from a `sha256sum` line, a BSD `SHA256 (file) = …` line, or on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedChecksum {
    pub bytes: Vec<u8>,
    /// The algorithm the line names, when it does.
    pub algorithm: Option<Algorithm>,
}

pub fn parse_checksum(text: &str) -> Result<PublishedChecksum> {
    let text = text.trim();
    // BSD style: `SHA256 (name) = value`.
    if let Some((left, value)) = text.rsplit_once(" = ")
        && let Some((name, _)) = left.split_once(" (")
        && let Ok(algorithm) = Algorithm::parse(name)
    {
        return Ok(PublishedChecksum {
            bytes: checksum_bytes(value.trim())?,
            algorithm: Some(algorithm),
        });
    }
    // GNU style: `value  name`; or the value alone.
    let value = text
        .split_whitespace()
        .next()
        .ok_or(Error::InvalidEncoding)?;
    // SRI style: `sha256-base64`.
    if let Some((name, value)) = value.split_once('-')
        && let Ok(algorithm) = Algorithm::parse(name)
    {
        return Ok(PublishedChecksum {
            bytes: decode_base64(value)?,
            algorithm: Some(algorithm),
        });
    }
    Ok(PublishedChecksum {
        bytes: checksum_bytes(value)?,
        algorithm: None,
    })
}

fn checksum_bytes(value: &str) -> Result<Vec<u8>> {
    if value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        hex_decode(value)
    } else {
        decode_base64(value)
    }
}

/// The algorithms a checksum of this size can come from: the named one, or every one of that length.
pub fn checksum_candidates(checksum: &PublishedChecksum) -> Vec<Algorithm> {
    match checksum.algorithm {
        Some(algorithm) => vec![algorithm],
        None => Algorithm::ALL
            .into_iter()
            .filter(|algorithm| algorithm.output_len() == checksum.bytes.len())
            .collect(),
    }
}

/// Lower-case hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(algorithm: Algorithm, data: &[u8]) -> String {
        to_hex(&digest(algorithm, data))
    }

    // NIST examples and each function's own published test vector.
    #[test]
    fn known_digests_of_abc() {
        let cases = [
            (Algorithm::Md5, "900150983cd24fb0d6963f7d28e17f72"),
            (Algorithm::Crc32, "352441c2"),
            (Algorithm::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                Algorithm::Sha224,
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            ),
            (
                Algorithm::Sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                Algorithm::Sha384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                Algorithm::Sha3_384,
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
            ),
            (
                Algorithm::Sha3_224,
                "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
            ),
            (
                Algorithm::Sha3_256,
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            ),
            (
                Algorithm::Blake2s,
                "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            ),
            (
                Algorithm::Blake3,
                "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            ),
        ];
        for (algorithm, expected) in cases {
            assert_eq!(hex_of(algorithm, b"abc"), expected, "{}", algorithm.name());
        }
    }

    #[test]
    fn long_digests_of_abc() {
        assert_eq!(
            hex_of(Algorithm::Sha512, b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hex_of(Algorithm::Sha3_512, b"abc"),
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        assert_eq!(
            hex_of(Algorithm::Blake2b, b"abc"),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    #[test]
    fn chunks_give_the_same_digest() {
        for algorithm in Algorithm::ALL {
            let mut hasher = Hasher::new(algorithm);
            hasher.update(b"hello ");
            hasher.update(b"world");
            let chunked = hasher.finalize();
            assert_eq!(
                chunked,
                digest(algorithm, b"hello world"),
                "{}",
                algorithm.name()
            );
            assert_eq!(
                chunked.len(),
                algorithm.output_len(),
                "{}",
                algorithm.name()
            );
        }
    }

    // RFC 4231 test case 2, RFC 2202 test case 2.
    #[test]
    fn hmac_vectors() {
        let data = b"what do ya want for nothing?";
        assert_eq!(
            to_hex(&hmac(Algorithm::Sha256, b"Jefe", data).unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            to_hex(&hmac(Algorithm::Sha512, b"Jefe", data).unwrap()),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
        assert_eq!(
            to_hex(&hmac(Algorithm::Sha1, b"Jefe", data).unwrap()),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hmac(Algorithm::Md5, b"k", b"d"),
            Err(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            hmac(Algorithm::Crc32, b"k", b"d"),
            Err(Error::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn published_checksums() {
        let hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let gnu = parse_checksum(&format!("{hash}  octapass-1.0.tar.gz")).unwrap();
        assert_eq!(gnu.algorithm, None);
        assert_eq!(to_hex(&gnu.bytes), hash);
        assert!(checksum_candidates(&gnu).contains(&Algorithm::Sha256));
        assert!(checksum_candidates(&gnu).contains(&Algorithm::Blake3));
        let bsd = parse_checksum(&format!("SHA256 (octapass.tar.gz) = {hash}")).unwrap();
        assert_eq!(bsd.algorithm, Some(Algorithm::Sha256));
        assert_eq!(checksum_candidates(&bsd), [Algorithm::Sha256]);
        let sri = parse_checksum("sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=").unwrap();
        assert_eq!(sri.algorithm, Some(Algorithm::Sha256));
        assert_eq!(to_hex(&sri.bytes), hash);
    }
}
