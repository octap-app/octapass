//! The developer toolkit (plan 16 §1–2): generators, inspectors and converters, one implementation
//! for every client.
//!
//! [`run`] is the whole surface other languages see: an operation name and a JSON object go in, a
//! JSON object comes out. The CLI, WebAssembly and the native apps all call it, so a tool behaves
//! the same everywhere, and adding one needs no new binding. Everything here is offline: fetching a
//! JWKS or a live certificate is up to the caller, which shows the user that it's going to the
//! network (plan 16 §6), and passes in what came back.
//!
//! Secrets travel as `Zeroizing` fields, so what this module holds is wiped when it returns. The
//! reply is itself secret when it holds a key, which is why it's `Zeroizing` too.

pub mod acme;
pub mod age_key;
pub mod digest;
pub mod encode;
pub mod items;
pub mod jose;
pub mod keys;
#[cfg(feature = "pgp")]
pub mod openpgp;
pub mod pkcs12;
pub mod pwhash;
pub mod random;
pub mod x509;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::Encode;
use rand_core::CryptoRngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use self::digest::{Algorithm, Hasher};
use self::encode::{Format, hex_encode};
use self::keys::{KeyKind, ParsedKey, PrivateKey, PublicKey};
use self::x509::{CaOptions, CsrOptions, Issued, LeafOptions};
use crate::error::{Error, Result};

/// Runs tool `op` on the JSON object `input`.
pub fn run<R: CryptoRngCore>(
    op: &str,
    input: &str,
    now_ms: u64,
    rng: &mut R,
) -> Result<Zeroizing<String>> {
    let now = now_ms / 1000;
    match op {
        "encoding.encode" => reply(&encoding_encode(parse(input)?)?),
        "encoding.decode" => reply(&encoding_decode(parse(input)?)?),
        "encoding.detect" => reply(&encoding_detect(parse(input)?)),
        "hash.digest" => reply(&hash_digest(parse(input)?)?),
        "hash.hmac" => reply(&hash_hmac(parse(input)?)?),
        "hash.compare" => reply(&hash_compare(parse(input)?)?),
        "random.bytes" => reply(&random_bytes(parse(input)?, rng)?),
        "random.uuid" => reply(&random_uuid(parse(input)?, now_ms, rng)?),
        "random.ulid" => reply(&random_ulid(parse(input)?, now_ms, rng)?),
        "random.token" => reply(&random::token(&parse(input)?, now_ms, rng)?),
        "totp.secret" => reply(&random::totp_secret(&parse(input)?, rng)?),
        "password.hash" => reply(&password_hash(parse(input)?, rng)?),
        "password.verify" => reply(&password_verify(parse(input)?)?),
        "key.generate" => reply(&key_generate(parse(input)?, rng)?),
        "key.inspect" => reply(&key_inspect(parse(input)?)?),
        "key.convert" => reply(&key_convert(parse(input)?, rng)?),
        "key.age" => reply(&age_key::generate(rng)?),
        "key.ageRead" => reply(&age_read(parse(input)?)?),
        #[cfg(feature = "pgp")]
        "key.gpg" => reply(&openpgp::generate(&parse(input)?, now, rng)?),
        #[cfg(feature = "pgp")]
        "key.gpgInspect" => reply(&gpg_inspect(parse(input)?)?),
        #[cfg(not(feature = "pgp"))]
        "key.gpg" | "key.gpgInspect" => Err(Error::PgpUnavailable),
        "jwt.decode" => reply(&jwt_decode(parse(input)?, now)?),
        "jwt.sign" => reply(&jose::sign(&parse(input)?, now, rng)?),
        "jwt.verify" => reply(&jose::verify(&parse(input)?, now)?),
        "jwt.decrypt" => reply(&jose::decrypt(&parse(input)?, now, rng)?),
        "jwt.generateKey" => reply(&jose::generate_jwt_key(&parse(input)?, rng)?),
        "jwt.jwks" => reply(&jwt_jwks(parse(input)?)?),
        "cert.selfSigned" => reply(&cert_self_signed(parse(input)?, now, rng)?),
        "cert.caCreate" => reply(&cert_ca_create(parse(input)?, now, rng)?),
        "cert.issue" => reply(&cert_issue(parse(input)?, now, rng)?),
        "cert.csr" => reply(&cert_csr(parse(input)?, rng)?),
        "cert.signCsr" => reply(&cert_sign_csr(parse(input)?, now, rng)?),
        "cert.read" => reply(&cert_read(parse(input)?, now)?),
        "cert.convert" => reply(&cert_convert(parse(input)?)?),
        "cert.p12Write" => reply(&cert_p12_write(parse(input)?, rng)?),
        "cert.p12Read" => reply(&cert_p12_read(parse(input)?, now)?),
        "cert.renewal" => reply(&cert_renewal(parse(input)?, now)),
        "item.certificate" => reply(&items::certificate(&parse(input)?, now)?),
        "item.key" => reply(&items::key(&parse(input)?)?),
        _ => Err(Error::UnknownTool),
    }
}

fn parse<T: DeserializeOwned>(input: &str) -> Result<T> {
    serde_json::from_str(input).map_err(|_| Error::InvalidToolInput)
}

fn reply<T: Serialize>(value: &T) -> Result<Zeroizing<String>> {
    serde_json::to_string(value)
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidToolInput)
}

/// Data given as text or as base64 of raw bytes.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DataInput {
    #[serde(default)]
    text: Option<Zeroizing<String>>,
    #[serde(default)]
    base64: Option<Zeroizing<String>>,
}

impl DataInput {
    fn bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        match (&self.text, &self.base64) {
            (Some(text), None) => Ok(Zeroizing::new(text.as_bytes().to_vec())),
            (None, Some(data)) => encode::decode_base64(data).map(Zeroizing::new),
            _ => Err(Error::InvalidToolInput),
        }
    }
}

#[derive(Debug, Deserialize)]
struct EncodeInput {
    format: Format,
    #[serde(flatten)]
    data: DataInput,
}

#[derive(Serialize)]
struct EncodeOutput {
    value: Zeroizing<String>,
}

fn encoding_encode(input: EncodeInput) -> Result<EncodeOutput> {
    Ok(EncodeOutput {
        value: Zeroizing::new(encode::encode(input.format, &input.data.bytes()?)?),
    })
}

#[derive(Debug, Deserialize)]
struct DecodeInput {
    format: Format,
    value: Zeroizing<String>,
}

/// Bytes in every form a person or a script may want them.
#[derive(Serialize)]
struct BytesOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<Zeroizing<String>>,
    hex: Zeroizing<String>,
    base64: Zeroizing<String>,
}

fn bytes_output(bytes: &[u8]) -> BytesOutput {
    BytesOutput {
        text: std::str::from_utf8(bytes)
            .ok()
            .map(|text| Zeroizing::new(text.to_owned())),
        hex: Zeroizing::new(hex_encode(bytes)),
        base64: Zeroizing::new(STANDARD.encode(bytes)),
    }
}

fn encoding_decode(input: DecodeInput) -> Result<BytesOutput> {
    let bytes = Zeroizing::new(encode::decode(input.format, &input.value)?);
    Ok(bytes_output(&bytes))
}

#[derive(Debug, Deserialize)]
struct DetectInput {
    value: Zeroizing<String>,
}

#[derive(Serialize)]
struct DetectOutput {
    candidates: Vec<encode::Detected>,
}

fn encoding_detect(input: DetectInput) -> DetectOutput {
    DetectOutput {
        candidates: encode::detect(&input.value),
    }
}

#[derive(Debug, Deserialize)]
struct DigestInput {
    /// Default: every algorithm.
    #[serde(default)]
    algorithms: Option<Vec<String>>,
    #[serde(flatten)]
    data: DataInput,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashResult {
    pub algorithm: String,
    pub hex: String,
    pub base64: String,
    /// MD5, SHA-1 and CRC32: for checking old checksums only.
    pub legacy: bool,
}

/// How a finished digest is shown. The CLI's file hashing ends here too.
pub fn hash_result(algorithm: Algorithm, bytes: &[u8]) -> HashResult {
    HashResult {
        algorithm: algorithm.name().to_owned(),
        hex: hex_encode(bytes),
        base64: STANDARD.encode(bytes),
        legacy: algorithm.is_legacy(),
    }
}

#[derive(Serialize)]
struct DigestOutput {
    hashes: Vec<HashResult>,
}

fn chosen(names: &Option<Vec<String>>) -> Result<Vec<Algorithm>> {
    match names {
        Some(names) => names.iter().map(|name| Algorithm::parse(name)).collect(),
        None => Ok(Algorithm::ALL.to_vec()),
    }
}

fn hash_digest(input: DigestInput) -> Result<DigestOutput> {
    let data = input.data.bytes()?;
    let hashes = chosen(&input.algorithms)?
        .into_iter()
        .map(|algorithm| hash_result(algorithm, &digest::digest(algorithm, &data)))
        .collect();
    Ok(DigestOutput { hashes })
}

#[derive(Debug, Deserialize)]
struct HmacInput {
    algorithm: String,
    key: jose::SecretInput,
    #[serde(flatten)]
    data: DataInput,
}

fn hash_hmac(input: HmacInput) -> Result<HashResult> {
    let algorithm = Algorithm::parse(&input.algorithm)?;
    let key = secret_bytes(&input.key)?;
    let mac = digest::hmac(algorithm, &key, &input.data.bytes()?)?;
    Ok(hash_result(algorithm, &mac))
}

fn secret_bytes(secret: &jose::SecretInput) -> Result<Zeroizing<Vec<u8>>> {
    let value = secret.value.as_str();
    Ok(Zeroizing::new(match secret.encoding.as_deref() {
        None | Some("utf8") => value.as_bytes().to_vec(),
        Some("base64") | Some("base64url") => encode::decode_base64(value)?,
        Some("hex") => encode::hex_decode(value)?,
        _ => return Err(Error::InvalidToolInput),
    }))
}

#[derive(Debug, Deserialize)]
struct CompareInput {
    checksum: String,
    #[serde(flatten)]
    data: DataInput,
}

#[derive(Serialize)]
struct CompareOutput {
    matches: bool,
    /// The algorithm that matched, or the ones tried.
    algorithms: Vec<String>,
}

fn hash_compare(input: CompareInput) -> Result<CompareOutput> {
    let data = input.data.bytes()?;
    let published = digest::parse_checksum(&input.checksum)?;
    let candidates = digest::checksum_candidates(&published);
    if candidates.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    let mut hashers: Vec<(Algorithm, Hasher)> = candidates
        .iter()
        .map(|algorithm| (*algorithm, Hasher::new(*algorithm)))
        .collect();
    hashers
        .iter_mut()
        .for_each(|(_, hasher)| hasher.update(&data));
    Ok(match_checksum(hashers, &published))
}

fn match_checksum(
    hashers: Vec<(Algorithm, Hasher)>,
    published: &digest::PublishedChecksum,
) -> CompareOutput {
    let mut tried = Vec::new();
    for (algorithm, hasher) in hashers {
        if hasher.finalize() == published.bytes {
            return CompareOutput {
                matches: true,
                algorithms: vec![algorithm.name().to_owned()],
            };
        }
        tried.push(algorithm.name().to_owned());
    }
    CompareOutput {
        matches: false,
        algorithms: tried,
    }
}

#[derive(Debug, Deserialize)]
struct RandomBytesInput {
    length: usize,
    /// Default `hex`.
    #[serde(default)]
    format: Option<Format>,
}

fn random_bytes(input: RandomBytesInput, rng: &mut impl CryptoRngCore) -> Result<EncodeOutput> {
    let format = input.format.unwrap_or(Format::Hex);
    if !matches!(
        format,
        Format::Hex | Format::Base64 | Format::Base64url | Format::Base32
    ) {
        return Err(Error::InvalidToolInput);
    }
    let bytes = random::random_bytes(input.length, rng)?;
    Ok(EncodeOutput {
        value: Zeroizing::new(encode::encode(format, &bytes)?),
    })
}

#[derive(Debug, Deserialize)]
struct IdsInput {
    /// `4` or `7`, for UUIDs.
    #[serde(default)]
    version: Option<u8>,
    #[serde(default)]
    count: Option<usize>,
}

#[derive(Serialize)]
struct IdsOutput {
    values: Vec<String>,
}

fn id_count(count: Option<usize>) -> Result<usize> {
    let count = count.unwrap_or(1);
    if (1..=1000).contains(&count) {
        Ok(count)
    } else {
        Err(Error::InvalidToolInput)
    }
}

fn random_uuid(input: IdsInput, now_ms: u64, rng: &mut impl CryptoRngCore) -> Result<IdsOutput> {
    let count = id_count(input.count)?;
    let values = (0..count)
        .map(|_| match input.version.unwrap_or(4) {
            4 => Ok(random::uuid_v4(rng)),
            7 => Ok(random::uuid_v7(now_ms, rng)),
            _ => Err(Error::InvalidToolInput),
        })
        .collect::<Result<_>>()?;
    Ok(IdsOutput { values })
}

fn random_ulid(input: IdsInput, now_ms: u64, rng: &mut impl CryptoRngCore) -> Result<IdsOutput> {
    let count = id_count(input.count)?;
    let values = (0..count)
        .map(|_| random::ulid(now_ms, rng))
        .collect::<Result<_>>()?;
    Ok(IdsOutput { values })
}

#[derive(Debug, Deserialize)]
struct PasswordHashInput {
    scheme: pwhash::Scheme,
    password: Zeroizing<String>,
    #[serde(default)]
    options: pwhash::HashOptions,
}

#[derive(Serialize)]
struct PasswordHashOutput {
    hash: String,
}

fn password_hash(
    input: PasswordHashInput,
    rng: &mut impl CryptoRngCore,
) -> Result<PasswordHashOutput> {
    Ok(PasswordHashOutput {
        hash: pwhash::hash(input.scheme, &input.password, &input.options, rng)?,
    })
}

#[derive(Debug, Deserialize)]
struct PasswordVerifyInput {
    password: Zeroizing<String>,
    hash: String,
}

#[derive(Serialize)]
struct PasswordVerifyOutput {
    matches: bool,
    #[serde(flatten)]
    info: pwhash::HashInfo,
}

fn password_verify(input: PasswordVerifyInput) -> Result<PasswordVerifyOutput> {
    Ok(PasswordVerifyOutput {
        info: pwhash::inspect(&input.hash)?,
        matches: pwhash::verify(&input.password, &input.hash)?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyGenerateInput {
    #[serde(rename = "type")]
    kind: KeyKind,
    /// Protects `privateKey`, as encrypted PKCS#8.
    #[serde(default)]
    passphrase: Option<Zeroizing<String>>,
}

/// The public faces of a key.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicForms {
    #[serde(flatten)]
    pub description: keys::KeyDescription,
    pub public_pem: String,
    pub public_openssh: String,
    pub public_jwk: Value,
    pub fingerprints: keys::Fingerprints,
}

pub fn public_forms(key: &PublicKey) -> Result<PublicForms> {
    Ok(PublicForms {
        description: key.describe(),
        public_pem: key.to_spki_pem()?,
        public_openssh: key.to_openssh()?,
        public_jwk: key.to_jwk(),
        fingerprints: keys::fingerprints(key)?,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyBundle {
    private_key: Zeroizing<String>,
    #[serde(flatten)]
    public: PublicForms,
}

fn key_generate(input: KeyGenerateInput, rng: &mut impl CryptoRngCore) -> Result<KeyBundle> {
    let key = keys::generate(input.kind, rng)?;
    let private_key = match input
        .passphrase
        .as_ref()
        .filter(|passphrase| !passphrase.is_empty())
    {
        Some(passphrase) => key.to_encrypted_pkcs8_pem(passphrase, rng)?,
        None => key.to_pkcs8_pem()?,
    };
    Ok(KeyBundle {
        private_key,
        public: public_forms(&key.public())?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyInput {
    key: Zeroizing<String>,
    #[serde(default)]
    passphrase: Option<Zeroizing<String>>,
}

impl KeyInput {
    fn parsed(&self) -> Result<ParsedKey> {
        keys::parse(&self.key, self.passphrase.as_ref().map(|p| p.as_str()))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyInspection {
    is_private: bool,
    #[serde(flatten)]
    public: PublicForms,
}

fn key_inspect(input: KeyInput) -> Result<KeyInspection> {
    let parsed = input.parsed()?;
    Ok(KeyInspection {
        is_private: matches!(parsed, ParsedKey::Private(_)),
        public: public_forms(&parsed.public())?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyConvertInput {
    #[serde(flatten)]
    key: KeyInput,
    /// See [`key_convert`].
    to: String,
    /// Protects the result, for `pkcs8-pem` and `openssh-private`.
    #[serde(default)]
    to_passphrase: Option<Zeroizing<String>>,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyConverted {
    /// The result as text, or base64 for the DER forms.
    value: Zeroizing<String>,
    /// Whether `value` holds the private key.
    is_private: bool,
    /// Whether `value` is base64 of binary DER.
    binary: bool,
}

fn private_of(parsed: &ParsedKey) -> Result<&PrivateKey> {
    match parsed {
        ParsedKey::Private(key) => Ok(key),
        ParsedKey::Public(_) => Err(Error::PrivateKeyRequired),
    }
}

/// Converts a key to `pkcs8-pem`, `pkcs8-der`, `traditional-pem` (PKCS#1 for RSA, SEC1 for EC),
/// `openssh-private`, `jwk`, `spki-pem`, `spki-der`, `pkcs1-public-pem`, `openssh-public` or
/// `jwk-public`.
fn key_convert(input: KeyConvertInput, rng: &mut impl CryptoRngCore) -> Result<KeyConverted> {
    let parsed = input.key.parsed()?;
    let protection = input
        .to_passphrase
        .as_ref()
        .map(|passphrase| passphrase.as_str())
        .filter(|passphrase| !passphrase.is_empty());
    let text = |value: Zeroizing<String>, is_private| KeyConverted {
        value,
        is_private,
        binary: false,
    };
    let binary = |der: &[u8], is_private| KeyConverted {
        value: Zeroizing::new(STANDARD.encode(der)),
        is_private,
        binary: true,
    };
    let public_text = |value: String| text(Zeroizing::new(value), false);
    Ok(match input.to.as_str() {
        "pkcs8-pem" => {
            let key = private_of(&parsed)?;
            text(
                match protection {
                    Some(passphrase) => key.to_encrypted_pkcs8_pem(passphrase, rng)?,
                    None => key.to_pkcs8_pem()?,
                },
                true,
            )
        }
        "pkcs8-der" => binary(&private_of(&parsed)?.to_pkcs8_der()?, true),
        "traditional-pem" => text(private_of(&parsed)?.to_traditional_pem()?, true),
        "openssh-private" => {
            let comment = input.comment.as_deref().unwrap_or_default();
            text(
                private_of(&parsed)?.to_openssh(comment, protection, rng)?,
                true,
            )
        }
        "jwk" => text(
            Zeroizing::new(private_of(&parsed)?.to_jwk()?.to_string()),
            true,
        ),
        "spki-pem" => public_text(parsed.public().to_spki_pem()?),
        "spki-der" => binary(&parsed.public().to_spki_der()?, false),
        "pkcs1-public-pem" => public_text(parsed.public().to_pkcs1_pem()?),
        "openssh-public" => public_text(parsed.public().to_openssh()?),
        "jwk-public" => public_text(parsed.public().to_jwk().to_string()),
        _ => return Err(Error::UnsupportedAlgorithm),
    })
}

#[derive(Debug, Deserialize)]
struct AgeReadInput {
    identity: Zeroizing<String>,
}

fn age_read(input: AgeReadInput) -> Result<age_key::AgeKey> {
    age_key::read_identity(&input.identity)
}

#[cfg(feature = "pgp")]
#[derive(Debug, Deserialize)]
struct GpgInspectInput {
    key: Zeroizing<String>,
}

#[cfg(feature = "pgp")]
fn gpg_inspect(input: GpgInspectInput) -> Result<openpgp::OpenPgpInfo> {
    openpgp::inspect(&input.key)
}

#[derive(Debug, Deserialize)]
struct TokenInput {
    token: String,
}

fn jwt_decode(input: TokenInput, now: u64) -> Result<jose::Decoded> {
    jose::decode(&input.token, now)
}

#[derive(Debug, Deserialize)]
struct JwksInput {
    keys: Vec<Zeroizing<String>>,
}

fn jwt_jwks(input: JwksInput) -> Result<Value> {
    let jwks = input
        .keys
        .iter()
        .map(|text| {
            let value = match serde_json::from_str::<Value>(text) {
                Ok(value) => value,
                Err(_) => {
                    let parsed = keys::parse(text, None)?;
                    parsed.public().to_jwk()
                }
            };
            Ok(value)
        })
        .collect::<Result<Vec<Value>>>()?;
    jose::public_jwks(&jwks)
}

/// An existing key, or a new one of `key_type`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeySource {
    /// Use this private key instead of making one.
    #[serde(default)]
    key: Option<Zeroizing<String>>,
    #[serde(default)]
    passphrase: Option<Zeroizing<String>>,
    /// Default `p256`.
    #[serde(default)]
    key_type: Option<KeyKind>,
}

impl KeySource {
    fn private_key(&self, rng: &mut impl CryptoRngCore) -> Result<PrivateKey> {
        match &self.key {
            Some(text) => x509::private_key_of(text, self.passphrase.as_ref().map(|p| p.as_str())),
            None => keys::generate(self.key_type.unwrap_or(x509::DEFAULT_KEY), rng),
        }
    }
}

fn issued(
    certificate: &x509_cert::Certificate,
    key: &PrivateKey,
    chain: String,
    now: u64,
) -> Result<Issued> {
    let der = certificate
        .to_der()
        .map_err(|_| Error::InvalidCertificate)?;
    Ok(Issued {
        certificate: x509::der_to_pem(&der)?,
        chain,
        private_key: key.to_pkcs8_pem()?,
        info: x509::inspect(&der, now)?,
    })
}

#[derive(Debug, Deserialize)]
struct SelfSignedInput {
    #[serde(flatten)]
    leaf: LeafOptions,
    #[serde(flatten)]
    source: KeySource,
}

fn cert_self_signed(
    input: SelfSignedInput,
    now: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<Issued> {
    let key = input.source.private_key(rng)?;
    let certificate = x509::self_signed(&input.leaf, &key, now, rng)?;
    issued(&certificate, &key, String::new(), now)
}

#[derive(Debug, Deserialize)]
struct CaCreateInput {
    #[serde(flatten)]
    ca: CaOptions,
    #[serde(flatten)]
    source: KeySource,
}

fn cert_ca_create(input: CaCreateInput, now: u64, rng: &mut impl CryptoRngCore) -> Result<Issued> {
    let key = input.source.private_key(rng)?;
    let certificate = x509::create_ca(&input.ca, &key, now, rng)?;
    issued(&certificate, &key, String::new(), now)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaInput {
    ca_certificate: String,
    ca_key: Zeroizing<String>,
    #[serde(default)]
    ca_passphrase: Option<Zeroizing<String>>,
}

impl CaInput {
    fn certificate(&self) -> Result<x509_cert::Certificate> {
        let ders = x509::parse_certificates(&self.ca_certificate)?;
        x509::parse_certificate(ders.first().ok_or(Error::InvalidCertificate)?)
    }

    fn key(&self) -> Result<PrivateKey> {
        x509::private_key_of(
            &self.ca_key,
            self.ca_passphrase.as_ref().map(|p| p.as_str()),
        )
    }
}

#[derive(Debug, Deserialize)]
struct IssueInput {
    #[serde(flatten)]
    leaf: LeafOptions,
    #[serde(flatten)]
    source: KeySource,
    #[serde(flatten)]
    ca: CaInput,
}

fn cert_issue(input: IssueInput, now: u64, rng: &mut impl CryptoRngCore) -> Result<Issued> {
    let key = input.source.private_key(rng)?;
    let ca_certificate = input.ca.certificate()?;
    let ca_key = input.ca.key()?;
    let certificate = x509::issue(
        &input.leaf,
        &key.public(),
        &ca_certificate,
        &ca_key,
        now,
        rng,
    )?;
    issued(
        &certificate,
        &key,
        x509::certificate_pem(&ca_certificate)?,
        now,
    )
}

#[derive(Debug, Deserialize)]
struct CsrInput {
    #[serde(flatten)]
    csr: CsrOptions,
    #[serde(flatten)]
    source: KeySource,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CsrOutput {
    csr: String,
    private_key: Zeroizing<String>,
    info: x509::CsrInfo,
}

fn cert_csr(input: CsrInput, rng: &mut impl CryptoRngCore) -> Result<CsrOutput> {
    let key = input.source.private_key(rng)?;
    let csr = x509::create_csr(&input.csr, &key, rng)?;
    Ok(CsrOutput {
        csr: x509::csr_pem(&csr)?,
        private_key: key.to_pkcs8_pem()?,
        info: x509::inspect_csr(&csr)?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignCsrInput {
    csr: String,
    #[serde(default)]
    sans: Vec<String>,
    #[serde(default)]
    days: Option<u32>,
    #[serde(flatten)]
    ca: CaInput,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedCsr {
    certificate: String,
    chain: String,
    info: x509::CertificateInfo,
}

fn cert_sign_csr(input: SignCsrInput, now: u64, rng: &mut impl CryptoRngCore) -> Result<SignedCsr> {
    let csr = x509::parse_csr(&input.csr)?;
    let ca_certificate = input.ca.certificate()?;
    let ca_key = input.ca.key()?;
    let certificate = x509::sign_csr(
        &csr,
        &input.sans,
        input.days,
        &ca_certificate,
        &ca_key,
        now,
        rng,
    )?;
    let der = certificate
        .to_der()
        .map_err(|_| Error::InvalidCertificate)?;
    Ok(SignedCsr {
        certificate: x509::der_to_pem(&der)?,
        chain: x509::certificate_pem(&ca_certificate)?,
        info: x509::inspect(&der, now)?,
    })
}

#[derive(Debug, Deserialize)]
struct CertReadInput {
    /// PEM (one or more certificates, or a CSR) or base64 DER.
    text: String,
    /// Check the leaf covers this name.
    #[serde(default)]
    host: Option<String>,
}

/// The chain, or `{ "csr": … }` when the text is a request.
fn cert_read(input: CertReadInput, now: u64) -> Result<Value> {
    if input.text.contains("CERTIFICATE REQUEST-----") {
        let csr = x509::parse_csr(&input.text)?;
        return Ok(json!({ "csr": x509::inspect_csr(&csr)? }));
    }
    let chain = x509::parse_certificates(&input.text)?;
    serde_json::to_value(x509::read_chain(&chain, input.host.as_deref(), now)?)
        .map_err(|_| Error::InvalidCertificate)
}

#[derive(Debug, Deserialize)]
struct CertConvertInput {
    text: String,
    /// `pem` or `der`.
    to: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CertConverted {
    /// PEM text, or base64 of the first certificate's DER.
    value: String,
    binary: bool,
}

fn cert_convert(input: CertConvertInput) -> Result<CertConverted> {
    let ders = x509::parse_certificates(&input.text)?;
    match input.to.as_str() {
        "pem" => Ok(CertConverted {
            value: ders
                .iter()
                .map(|der| x509::der_to_pem(der))
                .collect::<Result<Vec<_>>>()?
                .concat(),
            binary: false,
        }),
        "der" => Ok(CertConverted {
            value: STANDARD.encode(ders.first().ok_or(Error::InvalidCertificate)?),
            binary: true,
        }),
        _ => Err(Error::UnsupportedAlgorithm),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct P12WriteInput {
    certificate: String,
    #[serde(default)]
    chain: Option<String>,
    private_key: Zeroizing<String>,
    #[serde(default)]
    passphrase: Option<Zeroizing<String>>,
    password: Zeroizing<String>,
    #[serde(default)]
    friendly_name: Option<String>,
}

#[derive(Serialize)]
struct P12Output {
    base64: Zeroizing<String>,
}

fn cert_p12_write(input: P12WriteInput, rng: &mut impl CryptoRngCore) -> Result<P12Output> {
    let key = x509::private_key_of(
        &input.private_key,
        input.passphrase.as_ref().map(|p| p.as_str()),
    )?;
    let mut certificates = x509::parse_certificates(&input.certificate)?;
    if let Some(chain) = input
        .chain
        .as_deref()
        .filter(|chain| !chain.trim().is_empty())
    {
        certificates.extend(x509::parse_certificates(chain)?);
    }
    let file = pkcs12::write(
        &key,
        &certificates,
        &input.password,
        input.friendly_name.as_deref(),
        rng,
    )?;
    Ok(P12Output {
        base64: Zeroizing::new(STANDARD.encode(file)),
    })
}

#[derive(Debug, Deserialize)]
struct P12ReadInput {
    base64: Zeroizing<String>,
    password: Zeroizing<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct P12Read {
    certificate: String,
    chain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<Zeroizing<String>>,
    info: x509::CertificateInfo,
}

fn cert_p12_read(input: P12ReadInput, now: u64) -> Result<P12Read> {
    let file = Zeroizing::new(encode::decode_base64(&input.base64)?);
    let contents = pkcs12::read(&file, &input.password)?;
    // The leaf is the certificate of the key; files don't always list it first.
    let mut certificates = contents.certificates;
    if let Some(key) = &contents.private_key
        && let Some(index) = certificates
            .iter()
            .position(|der| x509::check_key_matches(der, key).is_ok())
    {
        certificates.swap(0, index);
    }
    let leaf = certificates.first().ok_or(Error::InvalidPkcs12)?;
    Ok(P12Read {
        certificate: x509::der_to_pem(leaf)?,
        chain: certificates[1..]
            .iter()
            .map(|der| x509::der_to_pem(der))
            .collect::<Result<Vec<_>>>()?
            .concat(),
        private_key: contents
            .private_key
            .as_ref()
            .map(PrivateKey::to_pkcs8_pem)
            .transpose()?,
        info: x509::inspect(leaf, now)?,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenewalInput {
    not_before: u64,
    not_after: u64,
}

fn cert_renewal(input: RenewalInput, now: u64) -> x509::Renewal {
    x509::renewal_state(input.not_before, input.not_after, now)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    const NOW_MS: u64 = 1_793_000_000_000;

    fn call(op: &str, input: Value) -> Value {
        serde_json::from_str(&run(op, &input.to_string(), NOW_MS, &mut OsRng).unwrap()).unwrap()
    }

    #[test]
    fn unknown_tools_and_bad_input_are_errors() {
        assert_eq!(
            run("nope", "{}", 0, &mut OsRng).err(),
            Some(Error::UnknownTool)
        );
        assert_eq!(
            run("hash.digest", "not json", 0, &mut OsRng).err(),
            Some(Error::InvalidToolInput)
        );
        assert_eq!(
            run("encoding.encode", "{\"format\":\"hex\"}", 0, &mut OsRng).err(),
            Some(Error::InvalidToolInput)
        );
    }

    #[test]
    fn encoding_round_trip_through_json() {
        let encoded = call(
            "encoding.encode",
            json!({ "format": "base64", "text": "héllo" }),
        );
        assert_eq!(encoded["value"], "aMOpbGxv");
        let decoded = call(
            "encoding.decode",
            json!({ "format": "base64", "value": "aMOpbGxv" }),
        );
        assert_eq!(decoded["text"], "héllo");
        assert_eq!(decoded["hex"], "68c3a96c6c6f");
        let binary = call(
            "encoding.decode",
            json!({ "format": "hex", "value": "ff00" }),
        );
        assert!(binary.get("text").is_none());
    }

    #[test]
    fn hashes_label_the_legacy_ones() {
        let hashes = call("hash.digest", json!({ "text": "abc" }));
        let list = hashes["hashes"].as_array().unwrap();
        assert_eq!(list.len(), Algorithm::ALL.len());
        let md5 = list.iter().find(|hash| hash["algorithm"] == "md5").unwrap();
        assert_eq!(md5["legacy"], true);
        let sha256 = list
            .iter()
            .find(|hash| hash["algorithm"] == "sha256")
            .unwrap();
        assert_eq!(sha256["legacy"], false);
    }

    #[test]
    fn checksums_are_compared_against_every_algorithm_of_that_length() {
        let sha256 = call(
            "hash.digest",
            json!({ "text": "abc", "algorithms": ["blake3"] }),
        );
        let value = sha256["hashes"][0]["hex"].as_str().unwrap();
        let matched = call("hash.compare", json!({ "text": "abc", "checksum": value }));
        assert_eq!(matched["matches"], true);
        assert_eq!(matched["algorithms"][0], "blake3");
        let missed = call("hash.compare", json!({ "text": "abd", "checksum": value }));
        assert_eq!(missed["matches"], false);
        assert!(missed["algorithms"].as_array().unwrap().len() > 1);
    }

    #[test]
    fn key_conversions_chain() {
        let made = call("key.generate", json!({ "type": "ed25519" }));
        let pem = made["privateKey"].as_str().unwrap();
        let jwk = call("key.convert", json!({ "key": pem, "to": "jwk" }));
        assert_eq!(jwk["isPrivate"], true);
        let openssh = call(
            "key.convert",
            json!({ "key": jwk["value"], "to": "openssh-private", "comment": "me" }),
        );
        let back = call(
            "key.convert",
            json!({ "key": openssh["value"], "to": "openssh-public" }),
        );
        assert_eq!(back["value"], made["publicOpenssh"]);
        assert_eq!(back["isPrivate"], false);
        let der = call("key.convert", json!({ "key": pem, "to": "spki-der" }));
        assert_eq!(der["binary"], true);
        let inspected = call("key.inspect", json!({ "key": der["value"] }));
        assert_eq!(inspected["isPrivate"], false);
        assert_eq!(inspected["fingerprints"], made["fingerprints"]);
    }

    #[test]
    fn a_public_key_cant_be_asked_for_private_forms() {
        let made = call("key.generate", json!({ "type": "p256" }));
        let input = json!({ "key": made["publicPem"], "to": "pkcs8-pem" });
        assert_eq!(
            run("key.convert", &input.to_string(), NOW_MS, &mut OsRng).err(),
            Some(Error::PrivateKeyRequired)
        );
    }

    #[test]
    fn certificates_through_json() {
        let ca = call(
            "cert.caCreate",
            json!({ "subject": { "commonName": "My CA" } }),
        );
        assert_eq!(ca["info"]["isCa"], true);
        let leaf = call(
            "cert.issue",
            json!({
                "sans": ["localhost", "127.0.0.1"],
                "keyType": "ed25519",
                "caCertificate": ca["certificate"],
                "caKey": ca["privateKey"],
            }),
        );
        assert_eq!(leaf["info"]["commonName"], "localhost");
        assert_eq!(leaf["info"]["keyType"], "ed25519");
        let bundle = format!(
            "{}{}",
            leaf["certificate"].as_str().unwrap(),
            leaf["chain"].as_str().unwrap()
        );
        let report = call("cert.read", json!({ "text": bundle, "host": "localhost" }));
        assert_eq!(report["certificates"].as_array().unwrap().len(), 2);
        assert_eq!(report["problems"], json!([]));

        let p12 = call(
            "cert.p12Write",
            json!({
                "certificate": leaf["certificate"],
                "chain": leaf["chain"],
                "privateKey": leaf["privateKey"],
                "password": "pw",
            }),
        );
        let opened = call(
            "cert.p12Read",
            json!({ "base64": p12["base64"], "password": "pw" }),
        );
        assert_eq!(opened["certificate"], leaf["certificate"]);
        assert_eq!(opened["chain"], leaf["chain"]);

        let der = call(
            "cert.convert",
            json!({ "text": leaf["certificate"], "to": "der" }),
        );
        let pem = call("cert.convert", json!({ "text": der["value"], "to": "pem" }));
        assert_eq!(pem["value"], leaf["certificate"]);

        let csr = call("cert.csr", json!({ "sans": ["a.test"] }));
        let read = call("cert.read", json!({ "text": csr["csr"] }));
        assert_eq!(read["csr"]["signatureValid"], true);
        let signed = call(
            "cert.signCsr",
            json!({ "csr": csr["csr"], "caCertificate": ca["certificate"], "caKey": ca["privateKey"] }),
        );
        assert_eq!(signed["info"]["sans"][0]["value"], "a.test");
    }

    #[test]
    fn password_hash_tool() {
        let made = call(
            "password.hash",
            json!({ "scheme": "bcrypt", "password": "hunter2", "options": { "cost": 10 } }),
        );
        let checked = call(
            "password.verify",
            json!({ "password": "hunter2", "hash": made["hash"] }),
        );
        assert_eq!(checked["matches"], true);
        assert_eq!(checked["scheme"], "bcrypt");
    }

    #[test]
    fn jwt_tools_through_json() {
        let key = call("jwt.generateKey", json!({ "algorithm": "ES256" }));
        let signed = call(
            "jwt.sign",
            json!({
                "payload": { "sub": "ada" },
                "algorithm": "ES256",
                "key": key["privateKey"],
                "keyId": key["keyId"],
                "issuedNow": true,
                "expiresInSeconds": 720,
            }),
        );
        let decoded = call("jwt.decode", json!({ "token": signed["token"] }));
        assert_eq!(decoded["keyId"], key["keyId"]);
        let exp = decoded["claims"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "exp")
            .unwrap()
            .clone();
        assert_eq!(exp["secondsFromNow"], 720);
        let verified = call(
            "jwt.verify",
            json!({ "token": signed["token"], "key": key["jwks"] }),
        );
        assert_eq!(verified["valid"], true);
        let jwks = call("jwt.jwks", json!({ "keys": [key["publicKey"]] }));
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn random_tools() {
        let bytes = call("random.bytes", json!({ "length": 16 }));
        assert_eq!(bytes["value"].as_str().unwrap().len(), 32);
        let uuids = call("random.uuid", json!({ "version": 7, "count": 3 }));
        assert_eq!(uuids["values"].as_array().unwrap().len(), 3);
        let ulids = call("random.ulid", json!({}));
        assert_eq!(ulids["values"][0].as_str().unwrap().len(), 26);
        let token = call(
            "random.token",
            json!({ "shape": "base62", "prefix": "sk_live_" }),
        );
        assert!(token["value"].as_str().unwrap().starts_with("sk_live_"));
        let totp = call("totp.secret", json!({ "issuer": "Acme", "account": "ada" }));
        assert!(
            totp["uri"]
                .as_str()
                .unwrap()
                .starts_with("otpauth://totp/Acme")
        );
    }

    #[test]
    fn age_tools() {
        let made = call("key.age", json!({}));
        let read = call("key.ageRead", json!({ "identity": made["identity"] }));
        assert_eq!(read["recipient"], made["recipient"]);
    }

    #[cfg(feature = "pgp")]
    #[test]
    fn gpg_tools() {
        let made = call("key.gpg", json!({ "userId": "Ada <ada@example.test>" }));
        let info = call("key.gpgInspect", json!({ "key": made["publicKey"] }));
        assert_eq!(info["fingerprint"], made["fingerprint"]);
    }
}
