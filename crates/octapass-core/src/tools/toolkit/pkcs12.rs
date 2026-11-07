//! PKCS#12 (`.p12`, `.pfx`) files, written the way OpenSSL 3 writes them by default: PBES2 with
//! PBKDF2-HMAC-SHA256 and AES-256-CBC for the contents, HMAC-SHA-256 for the file's MAC.
//!
//! Reading also takes the old PBES1 files that `openssl -legacy`, older Windows and Keychain
//! exports write (3DES and RC2 with SHA-1). Those ciphers are only ever used to read.

use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::encrypted_data::EncryptedData;
use cms::enveloped_data::EncryptedContentInfo;
use der::asn1::{Any, BmpString, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode};
use hmac::{Hmac, Mac};
use pkcs8::pkcs5::{self, pbes2};
use pkcs12::cert_type::CertBag;
use pkcs12::digest_info::DigestInfo;
use pkcs12::kdf::{Pkcs12KeyType, derive_key_utf8};
use pkcs12::mac_data::MacData;
use pkcs12::pbe_params::Pkcs12PbeParams;
use pkcs12::pfx::{Pfx, Version};
use pkcs12::safe_bag::{SafeBag, SafeContents};
use rand_core::CryptoRngCore;
use sha1::Sha1;
use sha2::digest::core_api::BlockSizeUser;
use sha2::digest::{Digest, FixedOutputReset};
use sha2::{Sha256, Sha384, Sha512};
use x509_cert::attr::Attribute;
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier as Oid};
use zeroize::Zeroizing;

use super::keys::PrivateKey;
use crate::error::{Error, Result};

const OID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
const OID_ENCRYPTED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.6");
const OID_FRIENDLY_NAME: Oid = Oid::new_unwrap("1.2.840.113549.1.9.20");
const OID_LOCAL_KEY_ID: Oid = Oid::new_unwrap("1.2.840.113549.1.9.21");
const OID_SHA1: Oid = Oid::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");
const OID_PBES2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.13");

const ITERATIONS: u32 = 600_000;
/// Reading a file can ask for any count: past this it's an attack or a mistake.
const MAX_ITERATIONS: i32 = 10_000_000;

/// A shrouded key bag's value. `pkcs8`'s own type only reads PBES1 and PBES2 identifiers, and old
/// files name the PKCS#12 schemes.
#[derive(der::Sequence)]
struct ShroudedKey {
    algorithm: AlgorithmIdentifierOwned,
    encrypted_data: OctetString,
}

/// What's in a PKCS#12 file.
pub struct Contents {
    pub private_key: Option<PrivateKey>,
    /// DER certificates, as stored.
    pub certificates: Vec<Vec<u8>>,
}

fn der_any(value: &impl Encode) -> Result<Any> {
    let der = value.to_der().map_err(|_| Error::InvalidPkcs12)?;
    Any::from_der(&der).map_err(|_| Error::InvalidPkcs12)
}

fn attributes(local_key_id: &[u8], friendly_name: Option<&str>) -> Result<Vec<Attribute>> {
    let value = der_any(&OctetString::new(local_key_id).map_err(|_| Error::InvalidPkcs12)?)?;
    let mut attributes = vec![Attribute {
        oid: OID_LOCAL_KEY_ID,
        values: SetOfVec::try_from(vec![value]).map_err(|_| Error::InvalidPkcs12)?,
    }];
    if let Some(name) = friendly_name.filter(|name| !name.is_empty()) {
        let name = BmpString::from_utf8(name).map_err(|_| Error::InvalidToolInput)?;
        let value = der_any(&name)?;
        attributes.push(Attribute {
            oid: OID_FRIENDLY_NAME,
            values: SetOfVec::try_from(vec![value]).map_err(|_| Error::InvalidPkcs12)?,
        });
    }
    Ok(attributes)
}

fn attribute_set(attributes: Vec<Attribute>) -> Result<SetOfVec<Attribute>> {
    SetOfVec::try_from(attributes).map_err(|_| Error::InvalidPkcs12)
}

fn pbes2_params<'a>(salt: &'a [u8; 16], iv: &'a [u8; 16]) -> Result<pbes2::Parameters<'a>> {
    pbes2::Parameters::pbkdf2_sha256_aes256cbc(ITERATIONS, salt, iv)
        .map_err(|_| Error::EncryptionFailed)
}

/// Writes `key` and `certificates` (the leaf first) protected by `password`.
pub fn write(
    key: &PrivateKey,
    certificates: &[Vec<u8>],
    password: &str,
    friendly_name: Option<&str>,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    let leaf = certificates.first().ok_or(Error::InvalidToolInput)?;
    super::x509::check_key_matches(leaf, key)?;
    let local_key_id = Sha256::digest(leaf)[..20].to_vec();

    // The private key: PKCS#8, encrypted, in a shrouded key bag.
    let (mut salt, mut iv) = ([0u8; 16], [0u8; 16]);
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);
    let der = key.to_pkcs8_der()?;
    let info = pkcs8::PrivateKeyInfo::try_from(der.as_slice()).map_err(|_| Error::InvalidKey)?;
    let encrypted = info
        .encrypt_with_params(pbes2_params(&salt, &iv)?, password)
        .map_err(|_| Error::EncryptionFailed)?;
    let key_bag = SafeBag {
        bag_id: pkcs12::PKCS_12_PKCS8_KEY_BAG_OID,
        bag_value: encrypted.as_bytes().to_vec(),
        bag_attributes: Some(attribute_set(attributes(&local_key_id, friendly_name)?)?),
    };
    let key_contents: SafeContents = vec![key_bag];
    let key_der = key_contents.to_der().map_err(|_| Error::InvalidPkcs12)?;

    // The certificates: cert bags, in one encrypted container.
    let mut bags: SafeContents = Vec::with_capacity(certificates.len());
    for (index, certificate) in certificates.iter().enumerate() {
        let bag = CertBag {
            cert_id: pkcs12::PKCS_12_X509_CERT_OID,
            cert_value: OctetString::new(certificate.as_slice())
                .map_err(|_| Error::InvalidPkcs12)?,
        };
        bags.push(SafeBag {
            bag_id: pkcs12::PKCS_12_CERT_BAG_OID,
            bag_value: bag.to_der().map_err(|_| Error::InvalidPkcs12)?,
            bag_attributes: if index == 0 {
                Some(attribute_set(attributes(&local_key_id, friendly_name)?)?)
            } else {
                None
            },
        });
    }
    let bags_der = bags.to_der().map_err(|_| Error::InvalidPkcs12)?;
    let (mut salt, mut iv) = ([0u8; 16], [0u8; 16]);
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);
    let scheme = pkcs5::EncryptionScheme::Pbes2(pbes2_params(&salt, &iv)?);
    let ciphertext = scheme
        .encrypt(password, &bags_der)
        .map_err(|_| Error::EncryptionFailed)?;
    let algorithm =
        AlgorithmIdentifierOwned::from_der(&scheme.to_der().map_err(|_| Error::EncryptionFailed)?)
            .map_err(|_| Error::EncryptionFailed)?;
    let encrypted_data = EncryptedData {
        version: CmsVersion::V0,
        enc_content_info: EncryptedContentInfo {
            content_type: OID_DATA,
            content_enc_alg: algorithm,
            encrypted_content: Some(
                OctetString::new(ciphertext).map_err(|_| Error::InvalidPkcs12)?,
            ),
        },
        unprotected_attrs: None,
    };

    let safe = vec![
        ContentInfo {
            content_type: OID_ENCRYPTED_DATA,
            content: der_any(&encrypted_data)?,
        },
        ContentInfo {
            content_type: OID_DATA,
            content: der_any(&OctetString::new(key_der).map_err(|_| Error::InvalidPkcs12)?)?,
        },
    ];
    let safe_der = safe.to_der().map_err(|_| Error::InvalidPkcs12)?;

    let mut mac_salt = [0u8; 16];
    rng.fill_bytes(&mut mac_salt);
    let mac = compute_mac::<Sha256>(password, &mac_salt, ITERATIONS as i32, &safe_der)?;
    let pfx = Pfx {
        version: Version::V3,
        auth_safe: ContentInfo {
            content_type: OID_DATA,
            content: der_any(&OctetString::new(safe_der).map_err(|_| Error::InvalidPkcs12)?)?,
        },
        mac_data: Some(MacData {
            mac: DigestInfo {
                algorithm: AlgorithmIdentifierOwned {
                    oid: OID_SHA256,
                    parameters: Some(Any::null()),
                },
                digest: OctetString::new(mac).map_err(|_| Error::InvalidPkcs12)?,
            },
            mac_salt: OctetString::new(mac_salt.as_slice()).map_err(|_| Error::InvalidPkcs12)?,
            iterations: ITERATIONS as i32,
        }),
    };
    pfx.to_der().map_err(|_| Error::InvalidPkcs12)
}

fn compute_mac<D>(password: &str, salt: &[u8], iterations: i32, data: &[u8]) -> Result<Vec<u8>>
where
    D: Digest + FixedOutputReset + BlockSizeUser + hmac::digest::core_api::CoreProxy,
    D::Core: hmac::digest::core_api::BufferKindUser<BufferKind = hmac::digest::block_buffer::Eager>
        + hmac::digest::HashMarker
        + hmac::digest::core_api::UpdateCore
        + hmac::digest::core_api::FixedOutputCore
        + hmac::digest::Reset
        + Default
        + Clone
        + hmac::digest::core_api::BlockSizeUser,
    <D::Core as hmac::digest::core_api::BlockSizeUser>::BlockSize:
        hmac::digest::typenum::IsLess<hmac::digest::typenum::U256>,
    hmac::digest::typenum::Le<
        <D::Core as hmac::digest::core_api::BlockSizeUser>::BlockSize,
        hmac::digest::typenum::U256,
    >: hmac::digest::typenum::NonZero,
{
    let key = Zeroizing::new(
        derive_key_utf8::<D>(
            password,
            salt,
            Pkcs12KeyType::Mac,
            iterations,
            <D as Digest>::output_size(),
        )
        .map_err(|_| Error::InvalidToolInput)?,
    );
    let mut mac = <Hmac<D> as Mac>::new_from_slice(&key).map_err(|_| Error::InvalidKey)?;
    Mac::update(&mut mac, data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn check_mac(mac_data: &MacData, password: &str, data: &[u8]) -> Result<()> {
    let salt = mac_data.mac_salt.as_bytes();
    let iterations = mac_data.iterations;
    if !(1..=MAX_ITERATIONS).contains(&iterations) {
        return Err(Error::InvalidHashParameters);
    }
    let computed = match mac_data.mac.algorithm.oid {
        OID_SHA1 => compute_mac::<Sha1>(password, salt, iterations, data)?,
        OID_SHA256 => compute_mac::<Sha256>(password, salt, iterations, data)?,
        OID_SHA384 => compute_mac::<Sha384>(password, salt, iterations, data)?,
        OID_SHA512 => compute_mac::<Sha512>(password, salt, iterations, data)?,
        _ => return Err(Error::UnsupportedAlgorithm),
    };
    let expected = mac_data.mac.digest.as_bytes();
    let same = computed.len() == expected.len()
        && computed
            .iter()
            .zip(expected)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0;
    if same {
        Ok(())
    } else {
        Err(Error::InvalidPkcs12)
    }
}

/// Decrypts PBES1 (`pbeWithSHAAnd…`) or PBES2 data.
fn decrypt_data(
    algorithm_oid: ObjectIdentifier,
    algorithm_der: &[u8],
    password: &str,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if algorithm_oid == OID_PBES2 {
        let scheme =
            pkcs5::EncryptionScheme::from_der(algorithm_der).map_err(|_| Error::InvalidPkcs12)?;
        return scheme
            .decrypt(password, ciphertext)
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidPkcs12);
    }
    let parsed =
        AlgorithmIdentifierOwned::from_der(algorithm_der).map_err(|_| Error::InvalidPkcs12)?;
    let parameters = parsed.parameters.as_ref().ok_or(Error::InvalidPkcs12)?;
    let params: Pkcs12PbeParams = parameters.decode_as().map_err(|_| Error::InvalidPkcs12)?;
    let iterations = params.iterations;
    if !(1..=MAX_ITERATIONS).contains(&iterations) {
        return Err(Error::InvalidHashParameters);
    }
    let salt = params.salt.as_bytes();
    let derive = |kind: Pkcs12KeyType, length: usize| {
        derive_key_utf8::<Sha1>(password, salt, kind, iterations, length)
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidToolInput)
    };
    let plaintext = if algorithm_oid == pkcs12::PKCS_12_PBE_WITH_SHAAND3_KEY_TRIPLE_DES_CBC {
        let key = derive(Pkcs12KeyType::EncryptionKey, 24)?;
        let iv = derive(Pkcs12KeyType::Iv, 8)?;
        cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
            .map_err(|_| Error::InvalidKey)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
    } else if algorithm_oid == pkcs12::PKCS_12_PBEWITH_SHAAND40_BIT_RC2_CBC {
        let key = derive(Pkcs12KeyType::EncryptionKey, 5)?;
        let iv = derive(Pkcs12KeyType::Iv, 8)?;
        cbc::Decryptor::<rc2::Rc2>::new_from_slices(&key, &iv)
            .map_err(|_| Error::InvalidKey)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
    } else {
        return Err(Error::UnsupportedAlgorithm);
    };
    plaintext
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidPkcs12)
}

fn read_bags(der: &[u8], password: &str, contents: &mut Contents) -> Result<()> {
    let bags = SafeContents::from_der(der).map_err(|_| Error::InvalidPkcs12)?;
    for bag in bags {
        // `pkcs12` keeps the `[0] EXPLICIT` wrapper around a bag's value when reading.
        let wrapper = Any::from_der(&bag.bag_value).map_err(|_| Error::InvalidPkcs12)?;
        let value = wrapper.value();
        match bag.bag_id {
            pkcs12::PKCS_12_CERT_BAG_OID => {
                let certificate = CertBag::from_der(value).map_err(|_| Error::InvalidPkcs12)?;
                if certificate.cert_id == pkcs12::PKCS_12_X509_CERT_OID {
                    contents
                        .certificates
                        .push(certificate.cert_value.as_bytes().to_vec());
                }
            }
            pkcs12::PKCS_12_PKCS8_KEY_BAG_OID => {
                let info = ShroudedKey::from_der(value).map_err(|_| Error::InvalidPkcs12)?;
                let algorithm = info.algorithm.to_der().map_err(|_| Error::InvalidPkcs12)?;
                let plain = decrypt_data(
                    info.algorithm.oid,
                    &algorithm,
                    password,
                    info.encrypted_data.as_bytes(),
                )?;
                contents.private_key = Some(PrivateKey::from_pkcs8_der(&plain)?);
            }
            pkcs12::PKCS_12_KEY_BAG_OID => {
                contents.private_key = Some(PrivateKey::from_pkcs8_der(value)?);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Reads a PKCS#12 file. A wrong password fails the MAC, so nothing is decrypted with it.
pub fn read(bytes: &[u8], password: &str) -> Result<Contents> {
    let pfx = Pfx::from_der(bytes).map_err(|_| Error::InvalidPkcs12)?;
    if pfx.auth_safe.content_type != OID_DATA {
        return Err(Error::InvalidPkcs12);
    }
    let safe_octets: OctetString = pfx
        .auth_safe
        .content
        .decode_as()
        .map_err(|_| Error::InvalidPkcs12)?;
    let safe_der = safe_octets.as_bytes();
    if let Some(mac_data) = &pfx.mac_data {
        check_mac(mac_data, password, safe_der)?;
    }
    let mut contents = Contents {
        private_key: None,
        certificates: Vec::new(),
    };
    let safe = Vec::<ContentInfo>::from_der(safe_der).map_err(|_| Error::InvalidPkcs12)?;
    for info in safe {
        match info.content_type {
            OID_DATA => {
                let octets: OctetString =
                    info.content.decode_as().map_err(|_| Error::InvalidPkcs12)?;
                read_bags(octets.as_bytes(), password, &mut contents)?;
            }
            OID_ENCRYPTED_DATA => {
                let data: EncryptedData =
                    info.content.decode_as().map_err(|_| Error::InvalidPkcs12)?;
                let enc = data.enc_content_info;
                let ciphertext = enc.encrypted_content.ok_or(Error::InvalidPkcs12)?;
                let algorithm = enc
                    .content_enc_alg
                    .to_der()
                    .map_err(|_| Error::InvalidPkcs12)?;
                let plain = decrypt_data(
                    enc.content_enc_alg.oid,
                    &algorithm,
                    password,
                    ciphertext.as_bytes(),
                )?;
                read_bags(&plain, password, &mut contents)?;
            }
            _ => {}
        }
    }
    if contents.certificates.is_empty() && contents.private_key.is_none() {
        return Err(Error::InvalidPkcs12);
    }
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;
    use crate::tools::toolkit::keys::{KeyKind, generate};
    use crate::tools::toolkit::x509::{self, LeafOptions, Subject};

    const NOW: u64 = 1_793_000_000;

    fn pair() -> (PrivateKey, Vec<u8>) {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([4; 32]);
        let key = generate(KeyKind::P256, &mut rng).unwrap();
        let options = LeafOptions {
            subject: Subject::default(),
            sans: vec!["a.test".into()],
            days: None,
            client_auth: false,
        };
        let certificate = x509::self_signed(&options, &key, NOW, &mut rng).unwrap();
        (key, certificate.to_der().unwrap())
    }

    #[test]
    fn round_trip() {
        let (key, certificate) = pair();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([1; 32]);
        let file = write(
            &key,
            std::slice::from_ref(&certificate),
            "pässword",
            Some("My cert"),
            &mut rng,
        )
        .unwrap();
        let contents = read(&file, "pässword").unwrap();
        assert_eq!(contents.certificates, [certificate]);
        let read_key = contents.private_key.unwrap();
        assert_eq!(read_key.public(), key.public());
    }

    #[test]
    fn wrong_password_and_damage() {
        let (key, certificate) = pair();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([1; 32]);
        let mut file = write(&key, &[certificate], "right", None, &mut rng).unwrap();
        assert_eq!(
            read(&file, "wrong").err().map(|e| e.code()),
            Some("invalid_pkcs12")
        );
        let last = file.len() - 40;
        file[last] ^= 1;
        assert!(read(&file, "right").is_err());
        assert!(read(b"not a file", "right").is_err());
    }

    #[test]
    fn the_key_must_fit_the_certificate() {
        let (_, certificate) = pair();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([2; 32]);
        let other = generate(KeyKind::P256, &mut rng).unwrap();
        assert_eq!(
            write(&other, &[certificate], "p", None, &mut rng).err(),
            Some(Error::CertificateKeyMismatch)
        );
    }
}
