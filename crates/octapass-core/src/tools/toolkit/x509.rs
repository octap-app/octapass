//! X.509 (plan 16 §1–2): self-signed certificates, a private local CA, CSRs, and the certificate
//! reader. Certificates are assembled from `x509-cert`'s types and signed through [`super::keys`],
//! with SHA-256 or stronger only.
//!
//! A local CA is name-constrained unless asked otherwise: it can only issue for names that are
//! private anyway (`localhost`, `*.test`, private IP ranges), so a stolen CA key can't impersonate
//! a public site on the machines that trust it.

use std::net::IpAddr;
use std::time::Duration;

use der::asn1::{
    Any, BitString, GeneralizedTime, Ia5String, ObjectIdentifier, OctetString, SetOfVec, UtcTime,
};
use der::pem::{self, LineEnding};
use der::{DateTime, Decode, Encode, Tag, Tagged};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::attr::{Attribute, AttributeTypeAndValue};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::constraints::name::{GeneralSubtree, NameConstraints};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::request::{CertReq, CertReqInfo};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use zeroize::Zeroizing;

use super::encode::{decode_base64, hex_encode};
use super::keys::{self, KeyKind, ParsedKey, PrivateKey, PublicKey, SignatureAlgorithm};
use crate::error::{Error, Result};

const OID_CN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_C: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
const OID_L: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
const OID_ST: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
const OID_O: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_OU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
const OID_EXTENSION_REQUEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

const OID_SHA1_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
const OID_MD5_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.4");
const OID_RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_ECDSA_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

const OID_SAN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_SKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_AKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

const OID_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
const OID_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const OID_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const OID_EMAIL_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4");
const OID_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const OID_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

/// macOS and iOS refuse TLS leaf certificates valid for longer.
const MAX_TRUSTED_LEAF_DAYS: u32 = 825;
/// Longest validity Octa Pass will write at all.
const MAX_DAYS: u32 = 36_500;
const SECONDS_PER_DAY: u64 = 86_400;
/// The not-before is backdated, so a clock a little behind doesn't reject a brand new certificate.
const CLOCK_SKEW: u64 = 3_600;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    #[serde(default)]
    pub common_name: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub organizational_unit: Option<String>,
    #[serde(default)]
    pub locality: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    /// Two letters.
    #[serde(default)]
    pub country: Option<String>,
}

/// A name the certificate is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum San {
    Dns(String),
    Ip(IpAddr),
    Email(String),
    Uri(String),
}

impl San {
    /// A DNS name (wildcards and non-ASCII allowed), IP address, email address or URI.
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        if let Ok(ip) = text.trim_matches(['[', ']']).parse::<IpAddr>() {
            return Ok(San::Ip(ip));
        }
        if text.contains("://") {
            return ia5(text).map(|_| San::Uri(text.to_owned()));
        }
        if text.contains('@') {
            return ia5(text).map(|_| San::Email(text.to_owned()));
        }
        let (wildcard, host) = match text.strip_prefix("*.") {
            Some(host) => (true, host),
            None => (false, text),
        };
        let ascii = idna::domain_to_ascii_strict(host)
            .or_else(|_| idna::domain_to_ascii(host))
            .map_err(|_| Error::InvalidToolInput)?
            .trim_end_matches('.')
            .to_owned();
        if !is_hostname(&ascii) {
            return Err(Error::InvalidToolInput);
        }
        Ok(San::Dns(if wildcard {
            format!("*.{ascii}")
        } else {
            ascii
        }))
    }

    fn to_general_name(&self) -> Result<GeneralName> {
        Ok(match self {
            San::Dns(name) => GeneralName::DnsName(ia5(name)?),
            San::Ip(ip) => GeneralName::IpAddress(octets(&ip_bytes(ip))?),
            San::Email(address) => GeneralName::Rfc822Name(ia5(address)?),
            San::Uri(uri) => GeneralName::UniformResourceIdentifier(ia5(uri)?),
        })
    }
}

fn is_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

fn ia5(text: &str) -> Result<Ia5String> {
    Ia5String::new(text).map_err(|_| Error::InvalidToolInput)
}

fn octets(bytes: &[u8]) -> Result<OctetString> {
    OctetString::new(bytes).map_err(|_| Error::InvalidCertificate)
}

fn ip_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn attribute(oid: ObjectIdentifier, tag: Tag, value: &str) -> Result<RelativeDistinguishedName> {
    let value = Any::new(tag, value.as_bytes()).map_err(|_| Error::InvalidToolInput)?;
    let set = SetOfVec::try_from(vec![AttributeTypeAndValue { oid, value }])
        .map_err(|_| Error::InvalidToolInput)?;
    Ok(RelativeDistinguishedName(set))
}

fn subject_name(subject: &Subject) -> Result<Name> {
    let mut rdns = Vec::new();
    let text = |value: &Option<String>| {
        value
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    if let Some(country) = text(&subject.country) {
        if country.len() != 2 || !country.is_ascii() {
            return Err(Error::InvalidToolInput);
        }
        rdns.push(attribute(OID_C, Tag::PrintableString, &country)?);
    }
    for (oid, value) in [
        (OID_ST, &subject.state),
        (OID_L, &subject.locality),
        (OID_O, &subject.organization),
        (OID_OU, &subject.organizational_unit),
        (OID_CN, &subject.common_name),
    ] {
        if let Some(value) = text(value) {
            rdns.push(attribute(oid, Tag::Utf8String, &value)?);
        }
    }
    Ok(RdnSequence(rdns))
}

fn time_at(unix_seconds: u64) -> Result<Time> {
    let date = DateTime::from_unix_duration(Duration::from_secs(unix_seconds))
        .map_err(|_| Error::InvalidToolInput)?;
    // RFC 5280 §4.1.2.5: UTCTime until the end of 2049, GeneralizedTime after.
    if date.year() < 2050 {
        UtcTime::from_date_time(date)
            .map(Time::UtcTime)
            .map_err(|_| Error::InvalidToolInput)
    } else {
        Ok(Time::GeneralTime(GeneralizedTime::from_date_time(date)))
    }
}

fn extension(oid: ObjectIdentifier, critical: bool, value: &impl Encode) -> Result<Extension> {
    let der = value.to_der().map_err(|_| Error::InvalidCertificate)?;
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(der).map_err(|_| Error::InvalidCertificate)?,
    })
}

/// RFC 7093 method 1: the leftmost 160 bits of the SHA-256 of the public key bits.
fn key_identifier(spki: &SubjectPublicKeyInfoOwned) -> Result<Vec<u8>> {
    let digest = Sha256::digest(spki.subject_public_key.raw_bytes());
    Ok(digest[..20].to_vec())
}

fn spki_of(key: &PublicKey) -> Result<SubjectPublicKeyInfoOwned> {
    SubjectPublicKeyInfoOwned::from_der(&key.to_spki_der()?).map_err(|_| Error::InvalidKey)
}

fn serial(rng: &mut impl CryptoRngCore) -> Result<SerialNumber> {
    // 128 random bits, positive and without a leading zero byte.
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes[0] = (bytes[0] & 0x7f) | 0x40;
    SerialNumber::new(&bytes).map_err(|_| Error::InvalidCertificate)
}

/// How `key` signs certificates: the algorithm's name in DER, the JOSE algorithm that computes it.
fn signature_algorithm(key: &PrivateKey) -> (ObjectIdentifier, bool, SignatureAlgorithm) {
    match key {
        PrivateKey::Rsa(_) => (OID_SHA256_RSA, true, SignatureAlgorithm::Rs256),
        PrivateKey::P256(_) => (OID_ECDSA_SHA256, false, SignatureAlgorithm::Es256),
        PrivateKey::P384(_) => (OID_ECDSA_SHA384, false, SignatureAlgorithm::Es384),
        PrivateKey::P521(_) => (OID_ECDSA_SHA512, false, SignatureAlgorithm::Es512),
        PrivateKey::Ed25519(_) => (OID_ED25519, false, SignatureAlgorithm::EdDsa),
    }
}

fn algorithm_identifier(oid: ObjectIdentifier, null_parameters: bool) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: null_parameters.then(Any::null),
    }
}

/// `r ‖ s` as the DER SEQUENCE X.509 carries, or the bytes unchanged for RSA and Ed25519.
fn x509_signature(key: &PrivateKey, raw: Vec<u8>) -> Result<Vec<u8>> {
    let invalid = |_| Error::InvalidKey;
    Ok(match key {
        PrivateKey::P256(_) => p256::ecdsa::Signature::from_slice(&raw)
            .map_err(invalid)?
            .to_der()
            .as_bytes()
            .to_vec(),
        PrivateKey::P384(_) => p384::ecdsa::Signature::from_slice(&raw)
            .map_err(invalid)?
            .to_der()
            .as_bytes()
            .to_vec(),
        PrivateKey::P521(_) => p521::ecdsa::Signature::from_slice(&raw)
            .map_err(invalid)?
            .to_der()
            .as_bytes()
            .to_vec(),
        _ => raw,
    })
}

fn sign_der(
    key: &PrivateKey,
    tbs: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(AlgorithmIdentifierOwned, BitString)> {
    let (oid, null_parameters, algorithm) = signature_algorithm(key);
    let raw = key.sign(algorithm, tbs, rng)?;
    let signature = x509_signature(key, raw)?;
    Ok((
        algorithm_identifier(oid, null_parameters),
        BitString::from_bytes(&signature).map_err(|_| Error::InvalidCertificate)?,
    ))
}

/// The parts of a certificate the three kinds below differ in.
struct Template {
    subject: Name,
    public_key: PublicKey,
    issuer: Name,
    issuer_key_id: Option<Vec<u8>>,
    not_before: u64,
    not_after: u64,
    extensions: Vec<Extension>,
}

fn build(
    template: Template,
    signer: &PrivateKey,
    rng: &mut impl CryptoRngCore,
) -> Result<Certificate> {
    let public_key = spki_of(&template.public_key)?;
    let key_id = key_identifier(&public_key)?;
    let mut extensions = template.extensions;
    extensions.push(extension(
        OID_SKI,
        false,
        &SubjectKeyIdentifier(octets(&key_id)?),
    )?);
    extensions.push(extension(
        OID_AKI,
        false,
        &AuthorityKeyIdentifier {
            key_identifier: Some(octets(
                template.issuer_key_id.as_deref().unwrap_or(&key_id),
            )?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        },
    )?);
    let (oid, null_parameters, _) = signature_algorithm(signer);
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial(rng)?,
        signature: algorithm_identifier(oid, null_parameters),
        issuer: template.issuer,
        validity: Validity {
            not_before: time_at(template.not_before)?,
            not_after: time_at(template.not_after)?,
        },
        subject: template.subject,
        subject_public_key_info: public_key,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    let tbs_der = tbs.to_der().map_err(|_| Error::InvalidCertificate)?;
    let (signature_algorithm, signature) = sign_der(signer, &tbs_der, rng)?;
    Ok(Certificate {
        tbs_certificate: tbs,
        signature_algorithm,
        signature,
    })
}

fn leaf_extensions(
    sans: &[San],
    public_key: &PublicKey,
    usages: &[ObjectIdentifier],
) -> Result<Vec<Extension>> {
    let names = sans
        .iter()
        .map(San::to_general_name)
        .collect::<Result<Vec<_>>>()?;
    let mut key_usage = KeyUsages::DigitalSignature.into();
    // TLS with RSA key exchange encrypts to the key; only old clients do this, and only with RSA.
    if matches!(public_key, PublicKey::Rsa(_)) {
        key_usage |= KeyUsages::KeyEncipherment;
    }
    Ok(vec![
        extension(
            OID_BASIC_CONSTRAINTS,
            true,
            &BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
        )?,
        extension(OID_KEY_USAGE, true, &KeyUsage(key_usage))?,
        extension(OID_EKU, false, &ExtendedKeyUsage(usages.to_vec()))?,
        extension(OID_SAN, false, &SubjectAltName(names))?,
    ])
}

fn parse_sans(sans: &[String]) -> Result<Vec<San>> {
    if sans.is_empty() {
        return Err(Error::InvalidToolInput);
    }
    let mut parsed = Vec::with_capacity(sans.len());
    for text in sans {
        let san = San::parse(text)?;
        if !parsed.contains(&san) {
            parsed.push(san);
        }
    }
    Ok(parsed)
}

fn check_days(days: u32) -> Result<u32> {
    if (1..=MAX_DAYS).contains(&days) {
        Ok(days)
    } else {
        Err(Error::InvalidToolInput)
    }
}

/// `subject`, with the first name as the common name when none is given.
fn with_common_name(subject: &Subject, sans: &[San]) -> Subject {
    let mut subject = subject.clone();
    if subject
        .common_name
        .as_deref()
        .is_none_or(|name| name.trim().is_empty())
    {
        subject.common_name = sans.first().map(|san| match san {
            San::Dns(name) | San::Email(name) | San::Uri(name) => name.clone(),
            San::Ip(ip) => ip.to_string(),
        });
    }
    subject
}

/// What to make a certificate for.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeafOptions {
    #[serde(default)]
    pub subject: Subject,
    /// DNS names, IP addresses, email addresses or URIs. At least one.
    pub sans: Vec<String>,
    /// Default 365.
    #[serde(default)]
    pub days: Option<u32>,
    /// Add `clientAuth` to `serverAuth`.
    #[serde(default)]
    pub client_auth: bool,
}

/// A new certificate and the key that goes with it, as PEM.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Issued {
    pub certificate: String,
    /// The certificates between it and the root, without the root: empty for a self-signed one.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub chain: String,
    pub private_key: Zeroizing<String>,
    pub info: CertificateInfo,
}

fn usages_for(options: &LeafOptions) -> Vec<ObjectIdentifier> {
    let mut usages = vec![OID_SERVER_AUTH];
    if options.client_auth {
        usages.push(OID_CLIENT_AUTH);
    }
    usages
}

/// A self-signed certificate for `options`, signed by `key`.
pub fn self_signed(
    options: &LeafOptions,
    key: &PrivateKey,
    now_seconds: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<Certificate> {
    let sans = parse_sans(&options.sans)?;
    let subject = subject_name(&with_common_name(&options.subject, &sans))?;
    let days = check_days(options.days.unwrap_or(365))?;
    build(
        Template {
            issuer: subject.clone(),
            subject,
            public_key: key.public(),
            issuer_key_id: None,
            not_before: now_seconds.saturating_sub(CLOCK_SKEW),
            not_after: now_seconds + u64::from(days) * SECONDS_PER_DAY,
            extensions: leaf_extensions(&sans, &key.public(), &usages_for(options))?,
        },
        key,
        rng,
    )
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaOptions {
    #[serde(default)]
    pub subject: Subject,
    /// Default 3650.
    #[serde(default)]
    pub days: Option<u32>,
    /// Lets this CA issue for any name. Off by default: see the module documentation.
    #[serde(default)]
    pub unconstrained: bool,
    /// Extra names it may issue for: `corp.example.com`, or a CIDR range such as `100.64.0.0/10`.
    #[serde(default)]
    pub permitted: Vec<String>,
}

/// Names that are private by definition: reserved by RFC 2606, 6761, 6762, 8375 and ICANN.
const PRIVATE_DNS: [&str; 5] = ["localhost", "test", "local", "internal", "home.arpa"];
/// Loopback, RFC 1918, link-local, and their IPv6 counterparts.
const PRIVATE_RANGES: [&str; 8] = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

fn cidr_bytes(text: &str) -> Result<Vec<u8>> {
    let (address, prefix) = text.split_once('/').ok_or(Error::InvalidToolInput)?;
    let address: IpAddr = address.parse().map_err(|_| Error::InvalidToolInput)?;
    let prefix: u32 = prefix.parse().map_err(|_| Error::InvalidToolInput)?;
    let mut bytes = ip_bytes(&address);
    let width = bytes.len() as u32 * 8;
    if prefix > width {
        return Err(Error::InvalidToolInput);
    }
    let mask: Vec<u8> = (0..bytes.len() as u32)
        .map(|index| {
            let bits = prefix.saturating_sub(index * 8).min(8);
            if bits == 0 { 0 } else { 0xffu8 << (8 - bits) }
        })
        .collect();
    for (byte, mask) in bytes.iter_mut().zip(&mask) {
        *byte &= mask;
    }
    bytes.extend(mask);
    Ok(bytes)
}

fn subtree(base: GeneralName) -> GeneralSubtree {
    GeneralSubtree {
        base,
        minimum: 0,
        maximum: None,
    }
}

fn constraints(options: &CaOptions) -> Result<NameConstraints> {
    let mut permitted = Vec::new();
    let dns = PRIVATE_DNS.iter().copied();
    let ranges = PRIVATE_RANGES.iter().copied();
    for name in dns.chain(
        options
            .permitted
            .iter()
            .map(String::as_str)
            .filter(|name| !name.contains('/')),
    ) {
        permitted.push(subtree(GeneralName::DnsName(ia5(name.trim())?)));
    }
    for range in ranges.chain(
        options
            .permitted
            .iter()
            .map(String::as_str)
            .filter(|name| name.contains('/')),
    ) {
        permitted.push(subtree(GeneralName::IpAddress(octets(&cidr_bytes(
            range.trim(),
        )?)?)));
    }
    Ok(NameConstraints {
        permitted_subtrees: Some(permitted),
        excluded_subtrees: None,
    })
}

/// A new root for a private CA. Only issues leaf certificates (`pathLen` 0).
pub fn create_ca(
    options: &CaOptions,
    key: &PrivateKey,
    now_seconds: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<Certificate> {
    let mut subject = options.subject.clone();
    if subject
        .common_name
        .as_deref()
        .is_none_or(|name| name.trim().is_empty())
    {
        subject.common_name = Some("Octa Pass Local CA".to_owned());
    }
    let subject = subject_name(&subject)?;
    let days = check_days(options.days.unwrap_or(3650))?;
    let mut extensions = vec![
        extension(
            OID_BASIC_CONSTRAINTS,
            true,
            &BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            },
        )?,
        extension(
            OID_KEY_USAGE,
            true,
            &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        )?,
    ];
    if !options.unconstrained {
        extensions.push(extension(
            OID_NAME_CONSTRAINTS,
            true,
            &constraints(options)?,
        )?);
    }
    build(
        Template {
            issuer: subject.clone(),
            subject,
            public_key: key.public(),
            issuer_key_id: None,
            not_before: now_seconds.saturating_sub(CLOCK_SKEW),
            not_after: now_seconds + u64::from(days) * SECONDS_PER_DAY,
            extensions,
        },
        key,
        rng,
    )
}

fn ca_parts(ca_certificate: &Certificate, ca_key: &PrivateKey, now_seconds: u64) -> Result<u64> {
    let tbs = &ca_certificate.tbs_certificate;
    let spki = tbs
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::InvalidCertificate)?;
    if spki != ca_key.public().to_spki_der()? {
        return Err(Error::CertificateKeyMismatch);
    }
    let details = read_tbs(ca_certificate)?;
    if !details.is_ca {
        return Err(Error::InvalidCertificate);
    }
    let not_after = tbs.validity.not_after.to_unix_duration().as_secs();
    if now_seconds >= not_after {
        return Err(Error::InvalidCertificate);
    }
    Ok(not_after)
}

fn issuer_key_id(ca_certificate: &Certificate) -> Result<Vec<u8>> {
    key_identifier(&ca_certificate.tbs_certificate.subject_public_key_info)
}

/// Whether the CA's name constraints let it issue for `san`.
fn permitted_by(constraints: &NameConstraints, san: &San) -> bool {
    let Some(subtrees) = &constraints.permitted_subtrees else {
        return true;
    };
    let mut relevant = subtrees.iter().filter(|subtree| {
        matches!(
            (&subtree.base, san),
            (GeneralName::DnsName(_), San::Dns(_)) | (GeneralName::IpAddress(_), San::Ip(_))
        )
    });
    match san {
        San::Dns(name) => {
            let name = name.trim_start_matches("*.").to_ascii_lowercase();
            relevant.any(|subtree| match &subtree.base {
                GeneralName::DnsName(base) => {
                    let base = base.as_str().trim_start_matches('.').to_ascii_lowercase();
                    name == base || name.ends_with(&format!(".{base}"))
                }
                _ => false,
            })
        }
        San::Ip(ip) => {
            let bytes = ip_bytes(ip);
            relevant.any(|subtree| match &subtree.base {
                GeneralName::IpAddress(range) => {
                    let range = range.as_bytes();
                    range.len() == bytes.len() * 2
                        && bytes.iter().enumerate().all(|(index, byte)| {
                            let mask = range[bytes.len() + index];
                            byte & mask == range[index] & mask
                        })
                }
                _ => false,
            })
        }
        // Constraints here only cover DNS and IP names.
        San::Email(_) | San::Uri(_) => true,
    }
}

fn check_constraints(ca_certificate: &Certificate, sans: &[San]) -> Result<()> {
    let extensions = ca_certificate
        .tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or_default();
    let Some(extension) = extensions
        .iter()
        .find(|extension| extension.extn_id == OID_NAME_CONSTRAINTS)
    else {
        return Ok(());
    };
    let constraints = NameConstraints::from_der(extension.extn_value.as_bytes())
        .map_err(|_| Error::InvalidCertificate)?;
    if sans.iter().all(|san| permitted_by(&constraints, san)) {
        Ok(())
    } else {
        Err(Error::NameNotPermitted)
    }
}

/// A certificate for `options`, issued by the CA, valid no longer than the CA itself.
pub fn issue(
    options: &LeafOptions,
    public_key: &PublicKey,
    ca_certificate: &Certificate,
    ca_key: &PrivateKey,
    now_seconds: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<Certificate> {
    let ca_not_after = ca_parts(ca_certificate, ca_key, now_seconds)?;
    let sans = parse_sans(&options.sans)?;
    check_constraints(ca_certificate, &sans)?;
    let days = check_days(options.days.unwrap_or(365))?;
    build(
        Template {
            subject: subject_name(&with_common_name(&options.subject, &sans))?,
            public_key: public_key.clone(),
            issuer: ca_certificate.tbs_certificate.subject.clone(),
            issuer_key_id: Some(issuer_key_id(ca_certificate)?),
            not_before: now_seconds.saturating_sub(CLOCK_SKEW),
            not_after: (now_seconds + u64::from(days) * SECONDS_PER_DAY).min(ca_not_after),
            extensions: leaf_extensions(&sans, public_key, &usages_for(options))?,
        },
        ca_key,
        rng,
    )
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsrOptions {
    #[serde(default)]
    pub subject: Subject,
    /// Names to ask for. May be empty when the subject has a common name.
    #[serde(default)]
    pub sans: Vec<String>,
}

/// A PKCS#10 certificate signing request, signed by `key` to prove it holds it.
pub fn create_csr(
    options: &CsrOptions,
    key: &PrivateKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CertReq> {
    let mut sans = Vec::new();
    for text in &options.sans {
        let san = San::parse(text)?;
        if !sans.contains(&san) {
            sans.push(san);
        }
    }
    let subject = subject_name(&with_common_name(&options.subject, &sans))?;
    if subject.0.is_empty() && sans.is_empty() {
        return Err(Error::InvalidToolInput);
    }
    let mut attributes = SetOfVec::new();
    if !sans.is_empty() {
        let names = sans
            .iter()
            .map(San::to_general_name)
            .collect::<Result<Vec<_>>>()?;
        let extensions = vec![extension(OID_SAN, false, &SubjectAltName(names))?];
        let value = Any::encode_from(&extensions).map_err(|_| Error::InvalidCertificate)?;
        attributes
            .insert(Attribute {
                oid: OID_EXTENSION_REQUEST,
                values: SetOfVec::try_from(vec![value]).map_err(|_| Error::InvalidCertificate)?,
            })
            .map_err(|_| Error::InvalidCertificate)?;
    }
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject,
        public_key: spki_of(&key.public())?,
        attributes,
    };
    let info_der = info.to_der().map_err(|_| Error::InvalidCertificate)?;
    let (algorithm, signature) = sign_der(key, &info_der, rng)?;
    Ok(CertReq {
        info,
        algorithm,
        signature,
    })
}

/// Issues a certificate for a CSR, after checking the request's signature: only the names in the
/// request (or `sans`, if given) go in.
pub fn sign_csr(
    csr: &CertReq,
    sans: &[String],
    days: Option<u32>,
    ca_certificate: &Certificate,
    ca_key: &PrivateKey,
    now_seconds: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<Certificate> {
    let info_der = csr.info.to_der().map_err(|_| Error::InvalidCertificate)?;
    let spki = csr
        .info
        .public_key
        .to_der()
        .map_err(|_| Error::InvalidCertificate)?;
    let public_key = PublicKey::from_spki_der(&spki)?;
    if verify_signature(&csr.algorithm, &csr.signature, &info_der, &public_key) != Some(true) {
        return Err(Error::InvalidSignature);
    }
    let requested;
    let sans = if sans.is_empty() {
        requested = csr_sans(csr)?;
        requested.as_slice()
    } else {
        sans
    };
    let options = LeafOptions {
        subject: Subject {
            common_name: name_attribute(&csr.info.subject, OID_CN),
            ..Subject::default()
        },
        sans: sans.to_vec(),
        days,
        client_auth: false,
    };
    issue(
        &options,
        &public_key,
        ca_certificate,
        ca_key,
        now_seconds,
        rng,
    )
}

fn csr_sans(csr: &CertReq) -> Result<Vec<String>> {
    let Some(attribute) = csr
        .info
        .attributes
        .iter()
        .find(|attribute| attribute.oid == OID_EXTENSION_REQUEST)
    else {
        return Ok(Vec::new());
    };
    let Some(value) = attribute.values.iter().next() else {
        return Ok(Vec::new());
    };
    let extensions: Vec<Extension> = value.decode_as().map_err(|_| Error::InvalidCertificate)?;
    Ok(extensions
        .iter()
        .find(|extension| extension.extn_id == OID_SAN)
        .map(|extension| {
            SubjectAltName::from_der(extension.extn_value.as_bytes()).map(|names| {
                names
                    .0
                    .iter()
                    .filter_map(san_text)
                    .map(|san| san.value)
                    .collect()
            })
        })
        .transpose()
        .map_err(|_| Error::InvalidCertificate)?
        .unwrap_or_default())
}

// ---------- Writing ----------

pub fn certificate_pem(certificate: &Certificate) -> Result<String> {
    let der = certificate
        .to_der()
        .map_err(|_| Error::InvalidCertificate)?;
    der_to_pem(&der)
}

pub fn der_to_pem(der: &[u8]) -> Result<String> {
    pem::encode_string("CERTIFICATE", LineEnding::LF, der).map_err(|_| Error::InvalidCertificate)
}

pub fn csr_pem(csr: &CertReq) -> Result<String> {
    let der = csr.to_der().map_err(|_| Error::InvalidCertificate)?;
    pem::encode_string("CERTIFICATE REQUEST", LineEnding::LF, &der)
        .map_err(|_| Error::InvalidCertificate)
}

pub fn parse_certificate(der: &[u8]) -> Result<Certificate> {
    Certificate::from_der(der).map_err(|_| Error::InvalidCertificate)
}

/// Each PEM block of `text` with this label, as DER. Text around the blocks is ignored.
pub fn pem_blocks(text: &str, wanted: &str) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        rest = &rest[start..];
        let Some(label) = keys::pem_label(rest).map(str::to_owned) else {
            break;
        };
        let end_marker = format!("-----END {label}-----");
        let Some(end) = rest.find(&end_marker) else {
            break;
        };
        let block = &rest[..end + end_marker.len()];
        if label == wanted
            && let Ok((_, der)) = pem::decode_vec(block.as_bytes())
        {
            blocks.push(der);
        }
        rest = &rest[end + end_marker.len()..];
    }
    blocks
}

/// The certificates in PEM text, or in base64 of a DER certificate.
pub fn parse_certificates(text: &str) -> Result<Vec<Vec<u8>>> {
    let text = text.trim();
    let blocks = pem_blocks(text, "CERTIFICATE");
    if !blocks.is_empty() {
        return Ok(blocks);
    }
    let der = decode_base64(text).map_err(|_| Error::InvalidCertificate)?;
    parse_certificate(&der)?;
    Ok(vec![der])
}

// ---------- Reading ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanEntry {
    /// `dns`, `ip`, `email` or `uri`.
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

/// A problem the reader found. Apps translate `code`; `severity` is `error`, `warning` or `info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    pub code: String,
    pub severity: String,
}

fn problem(code: &str, severity: &str) -> Problem {
    Problem {
        code: code.to_owned(),
        severity: severity.to_owned(),
    }
}

/// Everything the reader shows for one certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub subject: String,
    pub common_name: Option<String>,
    pub issuer: String,
    pub serial: String,
    pub not_before: u64,
    pub not_after: u64,
    /// Whole days until it expires; negative once it has.
    pub days_left: i64,
    pub sans: Vec<SanEntry>,
    pub key_type: String,
    pub key_bits: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    pub signature_algorithm: String,
    pub is_ca: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_length: Option<u8>,
    pub self_signed: bool,
    pub name_constrained: bool,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    /// SHA-256 of the certificate, colon-separated upper-case hex, as browsers show it.
    pub sha256: String,
    pub sha1: String,
    /// SHA-256 of the public key: stays the same when the certificate is renewed with the same key.
    pub spki_sha256: String,
    pub problems: Vec<Problem>,
}

/// The chain as read, and what's wrong with the whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainReport {
    pub certificates: Vec<CertificateInfo>,
    pub problems: Vec<Problem>,
    /// The host it was checked against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

struct TbsDetails {
    sans: Vec<SanEntry>,
    is_ca: bool,
    path_length: Option<u8>,
    name_constrained: bool,
    key_usage: Vec<String>,
    extended_key_usage: Vec<String>,
}

fn read_tbs(certificate: &Certificate) -> Result<TbsDetails> {
    let mut details = TbsDetails {
        sans: Vec::new(),
        is_ca: false,
        path_length: None,
        name_constrained: false,
        key_usage: Vec::new(),
        extended_key_usage: Vec::new(),
    };
    let invalid = |_| Error::InvalidCertificate;
    let empty = Vec::new();
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .unwrap_or(&empty);
    for extension in extensions {
        let value = extension.extn_value.as_bytes();
        match extension.extn_id {
            OID_SAN => {
                let names = SubjectAltName::from_der(value).map_err(invalid)?;
                details.sans = names.0.iter().filter_map(san_text).collect();
            }
            OID_BASIC_CONSTRAINTS => {
                let constraints = BasicConstraints::from_der(value).map_err(invalid)?;
                details.is_ca = constraints.ca;
                details.path_length = constraints.path_len_constraint;
            }
            OID_NAME_CONSTRAINTS => details.name_constrained = true,
            OID_KEY_USAGE => {
                let usage = KeyUsage::from_der(value).map_err(invalid)?;
                for (flag, name) in [
                    (KeyUsages::DigitalSignature, "digitalSignature"),
                    (KeyUsages::NonRepudiation, "contentCommitment"),
                    (KeyUsages::KeyEncipherment, "keyEncipherment"),
                    (KeyUsages::DataEncipherment, "dataEncipherment"),
                    (KeyUsages::KeyAgreement, "keyAgreement"),
                    (KeyUsages::KeyCertSign, "keyCertSign"),
                    (KeyUsages::CRLSign, "cRLSign"),
                ] {
                    if usage.0.contains(flag) {
                        details.key_usage.push(name.to_owned());
                    }
                }
            }
            OID_EKU => {
                let usages = ExtendedKeyUsage::from_der(value).map_err(invalid)?;
                details.extended_key_usage = usages
                    .0
                    .iter()
                    .map(|oid| match *oid {
                        OID_SERVER_AUTH => "serverAuth".to_owned(),
                        OID_CLIENT_AUTH => "clientAuth".to_owned(),
                        OID_CODE_SIGNING => "codeSigning".to_owned(),
                        OID_EMAIL_PROTECTION => "emailProtection".to_owned(),
                        OID_TIME_STAMPING => "timeStamping".to_owned(),
                        OID_OCSP_SIGNING => "OCSPSigning".to_owned(),
                        other => other.to_string(),
                    })
                    .collect();
            }
            _ => {}
        }
    }
    Ok(details)
}

fn san_text(name: &GeneralName) -> Option<SanEntry> {
    let entry = |kind: &str, value: String| {
        Some(SanEntry {
            kind: kind.to_owned(),
            value,
        })
    };
    match name {
        GeneralName::DnsName(name) => entry("dns", name.to_string()),
        GeneralName::Rfc822Name(name) => entry("email", name.to_string()),
        GeneralName::UniformResourceIdentifier(name) => entry("uri", name.to_string()),
        GeneralName::IpAddress(bytes) => {
            let bytes = bytes.as_bytes();
            let ip = match bytes.len() {
                4 => IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
                16 => IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
                _ => return None,
            };
            entry("ip", ip.to_string())
        }
        _ => None,
    }
}

/// `name`'s value of this attribute, as text.
fn name_attribute(name: &Name, oid: ObjectIdentifier) -> Option<String> {
    name.0.iter().rev().find_map(|rdn| {
        rdn.0
            .iter()
            .find(|attribute| attribute.oid == oid)
            .and_then(|attribute| match attribute.value.tag() {
                Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::TeletexString => {
                    String::from_utf8(attribute.value.value().to_vec()).ok()
                }
                _ => None,
            })
    })
}

fn signature_name(oid: ObjectIdentifier) -> String {
    match oid {
        OID_MD5_RSA => "md5WithRSAEncryption".to_owned(),
        OID_SHA1_RSA => "sha1WithRSAEncryption".to_owned(),
        OID_SHA256_RSA => "sha256WithRSAEncryption".to_owned(),
        OID_SHA384_RSA => "sha384WithRSAEncryption".to_owned(),
        OID_SHA512_RSA => "sha512WithRSAEncryption".to_owned(),
        OID_RSA_PSS => "rsassaPss".to_owned(),
        OID_ECDSA_SHA1 => "ecdsa-with-SHA1".to_owned(),
        OID_ECDSA_SHA256 => "ecdsa-with-SHA256".to_owned(),
        OID_ECDSA_SHA384 => "ecdsa-with-SHA384".to_owned(),
        OID_ECDSA_SHA512 => "ecdsa-with-SHA512".to_owned(),
        OID_ED25519 => "Ed25519".to_owned(),
        other => other.to_string(),
    }
}

fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The public key's type and size, read from the raw structures: the `rsa` crate refuses to load
/// keys above 4096 bits, and this reader only needs their size.
fn describe_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<(String, u32, Option<String>)> {
    let der = spki.to_der().map_err(|_| Error::InvalidCertificate)?;
    if let Ok(key) = PublicKey::from_spki_der(&der) {
        let description = key.describe();
        return Ok((description.key_type, description.bits, description.curve));
    }
    const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    if spki.algorithm.oid == RSA
        && let Ok(key) = rsa::pkcs1::RsaPublicKey::from_der(spki.subject_public_key.raw_bytes())
    {
        let bytes = key.modulus.as_bytes();
        let top = bytes.first().map_or(0, |byte| 8 - byte.leading_zeros());
        let bits = (bytes.len().saturating_sub(1) as u32) * 8 + top;
        return Ok(("rsa".to_owned(), bits, None));
    }
    Ok((spki.algorithm.oid.to_string(), 0, None))
}

/// Reads one certificate. `now_seconds` decides `days_left` and the expiry problems.
pub fn inspect(der: &[u8], now_seconds: u64) -> Result<CertificateInfo> {
    let certificate = parse_certificate(der)?;
    let tbs = &certificate.tbs_certificate;
    let details = read_tbs(&certificate)?;
    let not_before = tbs.validity.not_before.to_unix_duration().as_secs();
    let not_after = tbs.validity.not_after.to_unix_duration().as_secs();
    let days_left = (not_after as i64 - now_seconds as i64).div_euclid(SECONDS_PER_DAY as i64);
    let (key_type, key_bits, curve) = describe_spki(&tbs.subject_public_key_info)?;
    let self_signed = tbs.subject == tbs.issuer;

    let mut problems = Vec::new();
    if now_seconds >= not_after {
        problems.push(problem("expired", "error"));
    } else if now_seconds < not_before {
        problems.push(problem("notYetValid", "error"));
    } else if days_left < 30 {
        problems.push(problem("expiresSoon", "warning"));
    }
    if (key_type == "rsa" && key_bits < 2048) || (key_type == "ec" && key_bits < 256) {
        problems.push(problem("weakKey", "error"));
    }
    let signature_oid = certificate.signature_algorithm.oid;
    if matches!(signature_oid, OID_MD5_RSA | OID_SHA1_RSA | OID_ECDSA_SHA1) && !self_signed {
        problems.push(problem("weakSignature", "error"));
    }
    if !details.is_ca && details.sans.is_empty() {
        problems.push(problem("noSubjectAltName", "warning"));
    }
    if !details.is_ca
        && (not_after.saturating_sub(not_before)) / SECONDS_PER_DAY
            > u64::from(MAX_TRUSTED_LEAF_DAYS)
    {
        problems.push(problem("validityTooLong", "warning"));
    }
    if self_signed {
        problems.push(problem("selfSigned", "info"));
    }

    let spki_der = tbs
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::InvalidCertificate)?;
    Ok(CertificateInfo {
        subject: tbs.subject.to_string(),
        common_name: name_attribute(&tbs.subject, OID_CN),
        issuer: tbs.issuer.to_string(),
        serial: hex_encode(tbs.serial_number.as_bytes()),
        not_before,
        not_after,
        days_left,
        sans: details.sans,
        key_type,
        key_bits,
        curve,
        signature_algorithm: signature_name(signature_oid),
        is_ca: details.is_ca,
        path_length: details.path_length,
        self_signed,
        name_constrained: details.name_constrained,
        key_usage: details.key_usage,
        extended_key_usage: details.extended_key_usage,
        sha256: colon_hex(&Sha256::digest(der)),
        sha1: colon_hex(&Sha1::digest(der)),
        spki_sha256: hex_encode(&Sha256::digest(&spki_der)),
        problems,
    })
}

/// Whether `signature` by `public_key` covers `message`; `None` for algorithms this reader doesn't
/// check (RSA-PSS with odd parameters, anything on SHA-1).
fn verify_signature(
    algorithm: &AlgorithmIdentifierOwned,
    signature: &BitString,
    message: &[u8],
    public_key: &PublicKey,
) -> Option<bool> {
    let signature = signature.as_bytes()?;
    let jose = match algorithm.oid {
        OID_SHA256_RSA => SignatureAlgorithm::Rs256,
        OID_SHA384_RSA => SignatureAlgorithm::Rs384,
        OID_SHA512_RSA => SignatureAlgorithm::Rs512,
        OID_ECDSA_SHA256 | OID_ECDSA_SHA384 | OID_ECDSA_SHA512 => {
            return verify_ecdsa(algorithm.oid, signature, message, public_key);
        }
        OID_ED25519 => SignatureAlgorithm::EdDsa,
        _ => return None,
    };
    public_key.verify(jose, message, signature).ok()
}

/// ECDSA in X.509 can mix curve and hash (a P-384 key over SHA-256 is legal, and some CAs do it).
fn verify_ecdsa(
    oid: ObjectIdentifier,
    signature: &[u8],
    message: &[u8],
    public_key: &PublicKey,
) -> Option<bool> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let prehash: Vec<u8> = match oid {
        OID_ECDSA_SHA256 => Sha256::digest(message).to_vec(),
        OID_ECDSA_SHA384 => sha2::Sha384::digest(message).to_vec(),
        _ => sha2::Sha512::digest(message).to_vec(),
    };
    Some(match public_key {
        PublicKey::P256(key) => {
            let signature = p256::ecdsa::Signature::from_der(signature).ok()?;
            p256::ecdsa::VerifyingKey::from(key)
                .verify_prehash(&prehash, &signature)
                .is_ok()
        }
        PublicKey::P384(key) => {
            let signature = p384::ecdsa::Signature::from_der(signature).ok()?;
            p384::ecdsa::VerifyingKey::from(key)
                .verify_prehash(&prehash, &signature)
                .is_ok()
        }
        _ => return None,
    })
}

fn verified_by(certificate: &Certificate, issuer: &Certificate) -> Option<bool> {
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()?;
    let public_key = PublicKey::from_spki_der(&spki).ok()?;
    let tbs = certificate.tbs_certificate.to_der().ok()?;
    verify_signature(
        &certificate.signature_algorithm,
        &certificate.signature,
        &tbs,
        &public_key,
    )
}

/// Reads a chain, leaf first as servers send it, and checks it fits together and, with `host`, that
/// the leaf covers it.
pub fn read_chain(ders: &[Vec<u8>], host: Option<&str>, now_seconds: u64) -> Result<ChainReport> {
    if ders.is_empty() {
        return Err(Error::InvalidCertificate);
    }
    let certificates = ders
        .iter()
        .map(|der| inspect(der, now_seconds))
        .collect::<Result<Vec<_>>>()?;
    let parsed = ders
        .iter()
        .map(|der| parse_certificate(der))
        .collect::<Result<Vec<_>>>()?;
    let mut problems = Vec::new();
    for pair in parsed.windows(2) {
        if pair[0].tbs_certificate.issuer != pair[1].tbs_certificate.subject {
            problems.push(problem("chainOutOfOrder", "error"));
        } else if verified_by(&pair[0], &pair[1]) == Some(false) {
            problems.push(problem("chainSignatureInvalid", "error"));
        }
    }
    if let Some(last) = parsed.last()
        && last.tbs_certificate.issuer == last.tbs_certificate.subject
        && verified_by(last, last) == Some(false)
    {
        problems.push(problem("chainSignatureInvalid", "error"));
    }
    let host = host.map(str::trim).filter(|host| !host.is_empty());
    if let Some(host) = host
        && !covers_host(&certificates[0], host)
    {
        problems.push(problem("hostMismatch", "error"));
    }
    Ok(ChainReport {
        certificates,
        problems,
        host: host.map(str::to_owned),
    })
}

/// RFC 6125 matching: an exact name, or a wildcard for one whole left-most label.
pub fn covers_host(certificate: &CertificateInfo, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return certificate
            .sans
            .iter()
            .any(|san| san.kind == "ip" && san.value.parse::<IpAddr>() == Ok(ip));
    }
    let host = idna::domain_to_ascii(host).unwrap_or_else(|_| host.to_owned());
    certificate
        .sans
        .iter()
        .filter(|san| san.kind == "dns")
        .any(|san| {
            let name = san.value.to_ascii_lowercase();
            match name.strip_prefix("*.") {
                Some(rest) => host
                    .split_once('.')
                    .is_some_and(|(label, tail)| !label.is_empty() && tail == rest),
                None => name == host,
            }
        })
}

/// What a CSR asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CsrInfo {
    pub subject: String,
    pub common_name: Option<String>,
    pub sans: Vec<String>,
    pub key_type: String,
    pub key_bits: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
    pub signature_algorithm: String,
    /// The requester holds the private key.
    pub signature_valid: bool,
}

pub fn parse_csr(text: &str) -> Result<CertReq> {
    let blocks = pem_blocks(text, "CERTIFICATE REQUEST");
    let blocks = if blocks.is_empty() {
        pem_blocks(text, "NEW CERTIFICATE REQUEST")
    } else {
        blocks
    };
    let der = match blocks.first() {
        Some(der) => der.clone(),
        None => decode_base64(text.trim()).map_err(|_| Error::InvalidCertificate)?,
    };
    CertReq::from_der(&der).map_err(|_| Error::InvalidCertificate)
}

pub fn inspect_csr(csr: &CertReq) -> Result<CsrInfo> {
    let info_der = csr.info.to_der().map_err(|_| Error::InvalidCertificate)?;
    let spki = csr
        .info
        .public_key
        .to_der()
        .map_err(|_| Error::InvalidCertificate)?;
    let signature_valid = PublicKey::from_spki_der(&spki)
        .ok()
        .and_then(|key| verify_signature(&csr.algorithm, &csr.signature, &info_der, &key))
        .unwrap_or(false);
    let (key_type, key_bits, curve) = describe_spki(&csr.info.public_key)?;
    Ok(CsrInfo {
        subject: csr.info.subject.to_string(),
        common_name: name_attribute(&csr.info.subject, OID_CN),
        sans: csr_sans(csr)?,
        key_type,
        key_bits,
        curve,
        signature_algorithm: signature_name(csr.algorithm.oid),
        signature_valid,
    })
}

/// A certificate with its private key, read and checked to belong together.
pub fn check_key_matches(certificate_der: &[u8], key: &PrivateKey) -> Result<()> {
    let certificate = parse_certificate(certificate_der)?;
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| Error::InvalidCertificate)?;
    if spki == key.public().to_spki_der()? {
        Ok(())
    } else {
        Err(Error::CertificateKeyMismatch)
    }
}

/// The private key in PEM text; refuses public keys.
pub fn private_key_of(text: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
    match keys::parse(text, passphrase)? {
        ParsedKey::Private(key) => Ok(key),
        ParsedKey::Public(_) => Err(Error::PrivateKeyRequired),
    }
}

/// Default key type: fast, small and accepted everywhere that matters.
pub const DEFAULT_KEY: KeyKind = KeyKind::P256;

/// How close a certificate is to expiring, for renewal reminders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Renewal {
    /// `ok`, `renewSoon` or `expired`.
    pub state: String,
    pub days_left: i64,
}

/// ACME clients renew with a third of the lifetime left; 30 days is the classic floor for a
/// 90-day certificate, and also what long-lived private certificates get.
pub fn renewal_state(not_before: u64, not_after: u64, now_seconds: u64) -> Renewal {
    let days_left = (not_after as i64 - now_seconds as i64).div_euclid(SECONDS_PER_DAY as i64);
    let window = (not_after.saturating_sub(not_before) / 3).min(30 * SECONDS_PER_DAY);
    let state = if now_seconds >= not_after {
        "expired"
    } else if not_after - now_seconds <= window {
        "renewSoon"
    } else {
        "ok"
    };
    Renewal {
        state: state.to_owned(),
        days_left,
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, SeedableRng};

    use super::*;
    use crate::tools::toolkit::keys::generate;

    const NOW: u64 = 1_793_000_000; // 2026-10-27

    fn seeded() -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed([9; 32])
    }

    fn leaf(names: &[&str]) -> LeafOptions {
        LeafOptions {
            subject: Subject::default(),
            sans: names.iter().map(|name| (*name).to_owned()).collect(),
            days: None,
            client_auth: false,
        }
    }

    fn der_of(certificate: &Certificate) -> Vec<u8> {
        certificate.to_der().unwrap()
    }

    #[test]
    fn san_parsing() {
        assert_eq!(
            San::parse("localhost").unwrap(),
            San::Dns("localhost".into())
        );
        assert_eq!(
            San::parse("*.Example.test").unwrap(),
            San::Dns("*.example.test".into())
        );
        assert_eq!(
            San::parse("bücher.test").unwrap(),
            San::Dns("xn--bcher-kva.test".into())
        );
        assert_eq!(
            San::parse("127.0.0.1").unwrap(),
            San::Ip("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            San::parse("[::1]").unwrap(),
            San::Ip("::1".parse().unwrap())
        );
        assert_eq!(
            San::parse("a@b.test").unwrap(),
            San::Email("a@b.test".into())
        );
        assert_eq!(
            San::parse("spiffe://x/y").unwrap(),
            San::Uri("spiffe://x/y".into())
        );
        for bad in ["", "a b", "-x.test", "*.*.test"] {
            assert!(San::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn self_signed_certificate_for_each_key_type() {
        let mut rng = seeded();
        for kind in [
            KeyKind::P256,
            KeyKind::P384,
            KeyKind::Ed25519,
            KeyKind::Rsa2048,
        ] {
            let key = generate(kind, &mut rng).unwrap();
            let certificate =
                self_signed(&leaf(&["app.test", "127.0.0.1"]), &key, NOW, &mut rng).unwrap();
            let der = der_of(&certificate);
            let report = read_chain(&[der], Some("app.test"), NOW).unwrap();
            let info = &report.certificates[0];
            assert_eq!(info.common_name.as_deref(), Some("app.test"));
            assert_eq!(info.days_left, 365);
            assert_eq!(info.sans.len(), 2);
            assert!(info.self_signed);
            assert!(!info.is_ca);
            assert_eq!(info.extended_key_usage, ["serverAuth"]);
            assert!(report.problems.is_empty(), "{:?}", report.problems);
        }
    }

    #[test]
    fn local_ca_issues_a_chain_that_verifies() {
        let mut rng = seeded();
        let ca_key = generate(KeyKind::P256, &mut rng).unwrap();
        let ca = create_ca(&CaOptions::default(), &ca_key, NOW, &mut rng).unwrap();
        let info = inspect(&der_of(&ca), NOW).unwrap();
        assert!(info.is_ca);
        assert!(info.name_constrained);
        assert_eq!(info.path_length, Some(0));
        assert_eq!(info.common_name.as_deref(), Some("Octa Pass Local CA"));

        let leaf_key = generate(KeyKind::Ed25519, &mut rng).unwrap();
        let certificate = issue(
            &leaf(&["localhost", "*.dev.test", "192.168.1.20", "::1"]),
            &leaf_key.public(),
            &ca,
            &ca_key,
            NOW,
            &mut rng,
        )
        .unwrap();
        let report = read_chain(
            &[der_of(&certificate), der_of(&ca)],
            Some("api.dev.test"),
            NOW,
        )
        .unwrap();
        assert!(report.problems.is_empty(), "{:?}", report.problems);
        assert!(!report.certificates[0].self_signed);
    }

    #[test]
    fn a_constrained_ca_refuses_public_names() {
        let mut rng = seeded();
        let ca_key = generate(KeyKind::P256, &mut rng).unwrap();
        let ca = create_ca(&CaOptions::default(), &ca_key, NOW, &mut rng).unwrap();
        let key = generate(KeyKind::P256, &mut rng).unwrap();
        for name in ["example.com", "8.8.8.8", "testing", "evil-test"] {
            assert_eq!(
                issue(&leaf(&[name]), &key.public(), &ca, &ca_key, NOW, &mut rng).err(),
                Some(Error::NameNotPermitted),
                "{name}"
            );
        }
        let open = CaOptions {
            unconstrained: true,
            ..CaOptions::default()
        };
        let ca = create_ca(&open, &ca_key, NOW, &mut rng).unwrap();
        assert!(
            issue(
                &leaf(&["example.com"]),
                &key.public(),
                &ca,
                &ca_key,
                NOW,
                &mut rng
            )
            .is_ok()
        );
        let extended = CaOptions {
            permitted: vec!["corp.example.com".into(), "100.64.0.0/10".into()],
            ..CaOptions::default()
        };
        let ca = create_ca(&extended, &ca_key, NOW, &mut rng).unwrap();
        assert!(
            issue(
                &leaf(&["a.corp.example.com", "100.100.0.1"]),
                &key.public(),
                &ca,
                &ca_key,
                NOW,
                &mut rng
            )
            .is_ok()
        );
    }

    #[test]
    fn a_ca_needs_its_own_key_and_cant_outlive_itself() {
        let mut rng = seeded();
        let ca_key = generate(KeyKind::P256, &mut rng).unwrap();
        let other = generate(KeyKind::P256, &mut rng).unwrap();
        let ca = create_ca(
            &CaOptions {
                days: Some(10),
                ..CaOptions::default()
            },
            &ca_key,
            NOW,
            &mut rng,
        )
        .unwrap();
        let key = generate(KeyKind::P256, &mut rng).unwrap();
        assert_eq!(
            issue(
                &leaf(&["a.test"]),
                &key.public(),
                &ca,
                &other,
                NOW,
                &mut rng
            )
            .err(),
            Some(Error::CertificateKeyMismatch)
        );
        let certificate = issue(
            &leaf(&["a.test"]),
            &key.public(),
            &ca,
            &ca_key,
            NOW,
            &mut rng,
        )
        .unwrap();
        assert_eq!(inspect(&der_of(&certificate), NOW).unwrap().days_left, 10);
        // A leaf can't be a CA.
        let not_ca = self_signed(&leaf(&["a.test"]), &key, NOW, &mut rng).unwrap();
        assert_eq!(
            issue(
                &leaf(&["b.test"]),
                &key.public(),
                &not_ca,
                &key,
                NOW,
                &mut rng
            )
            .err(),
            Some(Error::InvalidCertificate)
        );
    }

    #[test]
    fn csr_round_trip_and_tampering() {
        let mut rng = seeded();
        let key = generate(KeyKind::P256, &mut rng).unwrap();
        let options = CsrOptions {
            subject: Subject {
                organization: Some("Acme".into()),
                ..Subject::default()
            },
            sans: vec!["a.test".into(), "10.0.0.1".into()],
        };
        let csr = create_csr(&options, &key, &mut rng).unwrap();
        let parsed = parse_csr(&csr_pem(&csr).unwrap()).unwrap();
        let info = inspect_csr(&parsed).unwrap();
        assert!(info.signature_valid);
        assert_eq!(info.common_name.as_deref(), Some("a.test"));
        assert_eq!(info.sans, ["a.test", "10.0.0.1"]);

        let ca_key = generate(KeyKind::Ed25519, &mut rng).unwrap();
        let ca = create_ca(&CaOptions::default(), &ca_key, NOW, &mut rng).unwrap();
        let certificate = sign_csr(&parsed, &[], Some(30), &ca, &ca_key, NOW, &mut rng).unwrap();
        let report = read_chain(&[der_of(&certificate), der_of(&ca)], Some("a.test"), NOW).unwrap();
        assert!(report.problems.is_empty(), "{:?}", report.problems);
        assert_eq!(report.certificates[0].days_left, 30);

        // The same CSR with its subject changed no longer proves anything.
        let mut forged = parsed;
        forged.info.subject = subject_name(&Subject {
            common_name: Some("evil.test".into()),
            ..Subject::default()
        })
        .unwrap();
        assert_eq!(
            sign_csr(&forged, &[], None, &ca, &ca_key, NOW, &mut rng).err(),
            Some(Error::InvalidSignature)
        );
        assert!(!inspect_csr(&forged).unwrap().signature_valid);
    }

    #[test]
    fn reader_flags_problems() {
        let mut rng = seeded();
        let key = generate(KeyKind::P256, &mut rng).unwrap();
        let der = der_of(&self_signed(&leaf(&["a.test"]), &key, NOW, &mut rng).unwrap());
        let codes = |info: &CertificateInfo| -> Vec<String> {
            info.problems.iter().map(|p| p.code.clone()).collect()
        };
        assert_eq!(codes(&inspect(&der, NOW).unwrap()), ["selfSigned"]);
        assert_eq!(
            codes(&inspect(&der, NOW + 400 * 86_400).unwrap()),
            ["expired", "selfSigned"]
        );
        assert_eq!(
            codes(&inspect(&der, NOW - 10 * 86_400).unwrap()),
            ["notYetValid", "selfSigned"]
        );
        assert_eq!(
            codes(&inspect(&der, NOW + 350 * 86_400).unwrap()),
            ["expiresSoon", "selfSigned"]
        );
        let long = LeafOptions {
            days: Some(1000),
            ..leaf(&["a.test"])
        };
        let der = der_of(&self_signed(&long, &key, NOW, &mut rng).unwrap());
        assert!(codes(&inspect(&der, NOW).unwrap()).contains(&"validityTooLong".to_owned()));
        let report = read_chain(&[der], Some("b.test"), NOW).unwrap();
        assert_eq!(report.problems[0].code, "hostMismatch");
    }

    #[test]
    fn broken_chains_are_reported() {
        let mut rng = seeded();
        let ca_key = generate(KeyKind::P256, &mut rng).unwrap();
        let ca = create_ca(&CaOptions::default(), &ca_key, NOW, &mut rng).unwrap();
        let other_key = generate(KeyKind::P256, &mut OsRng).unwrap();
        let impostor = create_ca(&CaOptions::default(), &other_key, NOW, &mut rng).unwrap();
        let key = generate(KeyKind::P256, &mut rng).unwrap();
        let certificate = issue(
            &leaf(&["a.test"]),
            &key.public(),
            &ca,
            &ca_key,
            NOW,
            &mut rng,
        )
        .unwrap();
        // Same name, different key.
        let report = read_chain(&[der_of(&certificate), der_of(&impostor)], None, NOW).unwrap();
        assert_eq!(report.problems[0].code, "chainSignatureInvalid");
        let report = read_chain(&[der_of(&ca), der_of(&certificate)], None, NOW).unwrap();
        assert_eq!(report.problems[0].code, "chainOutOfOrder");
    }

    #[test]
    fn wildcards_cover_one_label() {
        let info = |name: &str| CertificateInfo {
            sans: vec![SanEntry {
                kind: "dns".into(),
                value: name.into(),
            }],
            ..inspect(
                &der_of(
                    &self_signed(
                        &leaf(&["x.test"]),
                        &generate(KeyKind::P256, &mut seeded()).unwrap(),
                        NOW,
                        &mut seeded(),
                    )
                    .unwrap(),
                ),
                NOW,
            )
            .unwrap()
        };
        let wildcard = info("*.example.test");
        assert!(covers_host(&wildcard, "www.example.test"));
        assert!(covers_host(&wildcard, "WWW.Example.Test."));
        assert!(!covers_host(&wildcard, "example.test"));
        assert!(!covers_host(&wildcard, "a.b.example.test"));
    }

    #[test]
    fn renewal_windows() {
        let start = 1_000_000;
        let ninety = start + 90 * 86_400;
        assert_eq!(renewal_state(start, ninety, start).state, "ok");
        assert_eq!(
            renewal_state(start, ninety, ninety - 31 * 86_400).state,
            "ok"
        );
        assert_eq!(
            renewal_state(start, ninety, ninety - 29 * 86_400).state,
            "renewSoon"
        );
        assert_eq!(renewal_state(start, ninety, ninety).state, "expired");
        // Short-lived: a third of the lifetime.
        let six_days = start + 6 * 86_400;
        assert_eq!(renewal_state(start, six_days, start + 86_400).state, "ok");
        assert_eq!(
            renewal_state(start, six_days, start + 5 * 86_400).state,
            "renewSoon"
        );
    }

    #[test]
    fn pem_blocks_skip_other_text() {
        let text = "Bag Attributes\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\nsubject=x\n-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n";
        assert_eq!(
            pem_blocks(text, "CERTIFICATE"),
            [vec![1, 2, 3], vec![4, 5, 6]]
        );
        assert_eq!(pem_blocks(text, "PRIVATE KEY"), [vec![1, 2, 3]]);
    }
}
