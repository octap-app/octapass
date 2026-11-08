//! Single sign-on with SAML 2.0, beside OpenID Connect (plan 03, "SAML"). The server is the
//! service provider: an SP-initiated Web Browser SSO profile, the AuthnRequest over the redirect
//! binding and the Response over the POST binding. Like OIDC, it decides only whether a sign-in
//! that already passed OPAQUE may go on. Nothing here touches a key.
//!
//! XML signature handling is where SAML implementations break, so the rules are narrow:
//!
//! - **No DTD,** a node and depth limit, and every `ID` value unique in the document.
//! - **Exactly one assertion,** a direct child of the Response; encrypted assertions are refused.
//! - **The signature is enveloped** in the element it signs (the Response or the Assertion), its
//!   one reference names that element's `ID`, and its transforms are exactly enveloped-signature
//!   and exclusive canonicalisation. Every signature present must verify, and at least one must
//!   cover the assertion.
//! - **The key is the pinned certificate's,** never one from the message's `KeyInfo`.
//! - **SHA-1 is refused,** for digests and signatures alike.
//! - Claims are read only from the assertion node whose digest was checked.

pub mod c14n;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::signature::{self, UnparsedPublicKey};
use roxmltree::{Document, Node, ParsingOptions};
use sha2::{Digest, Sha256, Sha384, Sha512};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

use crate::crypto::{constant_time_eq, random_token};
use crate::sso::Claims;
use crate::validate;

pub const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const EMAIL_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
/// Attribute names IdPs use for the email address.
const EMAIL_ATTRIBUTES: [&str; 5] = [
    "email",
    "mail",
    "emailaddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
];

/// A Response is a few kilobytes; this is generous.
pub const MAX_RESPONSE: usize = 256 * 1024;
/// Metadata with several certificates and endpoints.
pub const MAX_METADATA: usize = 256 * 1024;
const MAX_NODES: u32 = 20_000;
const MAX_DEPTH: usize = 48;
/// At most this many signing certificates, for an IdP rolling its key over.
pub const MAX_CERTIFICATES: usize = 4;
/// An IdP's clock may be this far from ours.
const CLOCK_SKEW_MS: i64 = 3 * 60 * 1000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SamlError {
    #[error("{0}")]
    Config(&'static str),
    #[error("the SAML response isn't valid: {0}")]
    Invalid(&'static str),
}

use SamlError::{Config, Invalid};

// Keys and certificates.

#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyKind {
    /// A PKCS#1 `RSAPublicKey`, 2048 to 8192 bits.
    Rsa,
    /// An uncompressed P-256 point.
    P256,
    /// An uncompressed P-384 point.
    P384,
}

/// A signing certificate the admin pinned. Only its public key is used: expiry and issuer don't
/// matter for a pinned key, as in every SAML deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// The certificate as DER.
    pub der: Vec<u8>,
    kind: KeyKind,
    key: Vec<u8>,
    /// Unix ms, for display.
    pub not_after: Option<i64>,
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    STANDARD.decode(compact).ok()
}

fn rsa_modulus_bits(pkcs1: &[u8]) -> Option<usize> {
    use x509_cert::der::asn1::UintRef;
    use x509_cert::der::{Decode, Reader, SliceReader};
    let mut reader = SliceReader::new(pkcs1).ok()?;
    let modulus = reader
        .sequence(|nested| {
            let modulus = UintRef::decode(nested)?;
            UintRef::decode(nested)?;
            Ok(modulus)
        })
        .ok()?;
    reader.finish(()).ok()?;
    let bytes = modulus.as_bytes();
    let first = *bytes.first()?;
    Some(bytes.len() * 8 - first.leading_zeros() as usize)
}

impl Certificate {
    /// A certificate as PEM, or as the bare base64 of its DER (what metadata holds).
    pub fn parse(text: &str) -> Result<Self, SamlError> {
        let text = text.trim();
        let body = match text.find("-----BEGIN CERTIFICATE-----") {
            Some(start) => {
                let rest = &text[start + "-----BEGIN CERTIFICATE-----".len()..];
                let end = rest
                    .find("-----END CERTIFICATE-----")
                    .ok_or(Config("the certificate's PEM has no end line"))?;
                &rest[..end]
            }
            None => text,
        };
        let der = decode_base64(body).ok_or(Config("the certificate isn't PEM or base64"))?;
        Self::from_der(der)
    }

    pub fn from_der(der: Vec<u8>) -> Result<Self, SamlError> {
        use x509_cert::der::Decode;
        use x509_cert::der::asn1::ObjectIdentifier;
        const RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        const EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

        let certificate = x509_cert::Certificate::from_der(&der)
            .map_err(|_| Config("that isn't an X.509 certificate"))?;
        let spki = &certificate.tbs_certificate.subject_public_key_info;
        let key = spki.subject_public_key.raw_bytes().to_vec();
        let kind = if spki.algorithm.oid == RSA {
            let bits = rsa_modulus_bits(&key).ok_or(Config("the RSA key can't be read"))?;
            if !(2048..=8192).contains(&bits) {
                return Err(Config("RSA keys must be 2048 to 8192 bits"));
            }
            KeyKind::Rsa
        } else if spki.algorithm.oid == EC {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
            match curve {
                Some(curve) if curve == P256 && key.len() == 65 => KeyKind::P256,
                Some(curve) if curve == P384 && key.len() == 97 => KeyKind::P384,
                _ => return Err(Config("EC keys must be P-256 or P-384")),
            }
        } else {
            return Err(Config("the certificate's key must be RSA or ECDSA"));
        };
        let not_after = i64::try_from(
            certificate
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_millis(),
        )
        .ok();
        Ok(Self {
            der,
            kind,
            key,
            not_after,
        })
    }

    /// SHA-256 of the DER, as colon-separated hex: what IdP admin screens show.
    pub fn fingerprint(&self) -> String {
        Sha256::digest(&self.der)
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.der)
    }

    fn verify(&self, algorithm: &str, message: &[u8], signature: &[u8]) -> Result<(), SamlError> {
        let verifier: &dyn signature::VerificationAlgorithm = match (&self.kind, algorithm) {
            (KeyKind::Rsa, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") => {
                &signature::RSA_PKCS1_2048_8192_SHA256
            }
            (KeyKind::Rsa, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384") => {
                &signature::RSA_PKCS1_2048_8192_SHA384
            }
            (KeyKind::Rsa, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512") => {
                &signature::RSA_PKCS1_2048_8192_SHA512
            }
            (KeyKind::P256, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256") => {
                &signature::ECDSA_P256_SHA256_FIXED
            }
            (KeyKind::P384, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384") => {
                &signature::ECDSA_P384_SHA384_FIXED
            }
            _ => {
                return Err(Invalid(
                    "the signature algorithm isn't one this server accepts",
                ));
            }
        };
        UnparsedPublicKey::new(verifier, &self.key)
            .verify(message, signature)
            .map_err(|_| Invalid("the signature doesn't verify"))
    }
}

/// Certificates as stored: base64 DER, one per line.
pub fn parse_stored_certificates(stored: &str) -> Vec<Certificate> {
    stored
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| Certificate::parse(line).ok())
        .collect()
}

pub fn store_certificates(certificates: &[Certificate]) -> String {
    certificates
        .iter()
        .map(Certificate::to_base64)
        .collect::<Vec<_>>()
        .join("\n")
}

// XML helpers.

fn parse(text: &str) -> Result<Document<'_>, SamlError> {
    let options = ParsingOptions {
        allow_dtd: false,
        nodes_limit: MAX_NODES,
        ..ParsingOptions::default()
    };
    let doc = Document::parse_with_options(text, options)
        .map_err(|_| Invalid("it isn't well-formed XML without a DTD"))?;
    for node in doc.descendants() {
        if node.ancestors().nth(MAX_DEPTH).is_some() {
            return Err(Invalid("it's nested too deeply"));
        }
    }
    Ok(doc)
}

fn is(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}

fn children<'a, 'i>(
    node: Node<'a, 'i>,
    namespace: &'static str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children()
        .filter(move |child| is(*child, namespace, name))
}

/// The one child with this name, if any. Two is an error: which one counts would be a guess.
fn only_child<'a, 'i>(
    node: Node<'a, 'i>,
    namespace: &'static str,
    name: &'static str,
) -> Result<Option<Node<'a, 'i>>, SamlError> {
    let mut found = children(node, namespace, name);
    let first = found.next();
    if found.next().is_some() {
        return Err(Invalid("an element appears twice"));
    }
    Ok(first)
}

fn required_child<'a, 'i>(
    node: Node<'a, 'i>,
    namespace: &'static str,
    name: &'static str,
    missing: &'static str,
) -> Result<Node<'a, 'i>, SamlError> {
    only_child(node, namespace, name)?.ok_or(Invalid(missing))
}

/// All the text directly inside an element, trimmed.
fn text_of(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect::<String>()
        .trim()
        .to_owned()
}

fn time_ms(value: &str) -> Result<i64, SamlError> {
    let parsed = OffsetDateTime::parse(value.trim(), &Rfc3339)
        .map_err(|_| Invalid("a time isn't xs:dateTime"))?;
    i64::try_from(parsed.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| Invalid("a time is out of range"))
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// The identity provider's metadata.

/// What the service provider needs to know about an identity provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdpSettings {
    pub entity_id: String,
    pub sso_url: Url,
    pub certificates: Vec<Certificate>,
}

/// Checks a URL the browser will be sent to: HTTPS (plain HTTP in dev mode only), with no user
/// name, password or fragment. The server never fetches it.
pub fn sso_url(raw: &str, allow_http: bool) -> Result<Url, SamlError> {
    let url = Url::parse(raw.trim()).map_err(|_| Config("the SSO URL isn't a URL"))?;
    let allowed = url.scheme() == "https" || (allow_http && url.scheme() == "http");
    if !allowed {
        return Err(Config("identity providers must use HTTPS"));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(Config(
            "the SSO URL can't hold a user name, password or fragment",
        ));
    }
    if url.host().is_none() {
        return Err(Config("the SSO URL has no host"));
    }
    Ok(url)
}

/// Reads an IdP's metadata (`EntityDescriptor`, or an `EntitiesDescriptor` holding one IdP): its
/// entity id, its redirect-binding SSO URL and its signing certificates. The metadata isn't
/// signature-checked: an admin pasted it, which is the same trust as typing the fields in.
pub fn parse_metadata(xml: &str, allow_http: bool) -> Result<IdpSettings, SamlError> {
    if xml.len() > MAX_METADATA {
        return Err(Config("the metadata is too large"));
    }
    let doc = parse(xml).map_err(|_| Config("the metadata isn't well-formed XML"))?;
    let root = doc.root_element();
    let entities: Vec<Node<'_, '_>> = if is(root, METADATA, "EntityDescriptor") {
        vec![root]
    } else if is(root, METADATA, "EntitiesDescriptor") {
        root.descendants()
            .filter(|node| is(*node, METADATA, "EntityDescriptor"))
            .collect()
    } else {
        return Err(Config("that isn't SAML metadata"));
    };
    let mut idps = entities.into_iter().filter_map(|entity| {
        children(entity, METADATA, "IDPSSODescriptor")
            .next()
            .map(|idp| (entity, idp))
    });
    let (entity, idp) = idps
        .next()
        .ok_or(Config("the metadata describes no identity provider"))?;
    if idps.next().is_some() {
        return Err(Config(
            "the metadata describes more than one identity provider",
        ));
    }
    let entity_id = entity
        .attribute("entityID")
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .ok_or(Config("the metadata has no entityID"))?
        .to_owned();
    let location = children(idp, METADATA, "SingleSignOnService")
        .find(|service| service.attribute("Binding") == Some(REDIRECT_BINDING))
        .and_then(|service| service.attribute("Location"))
        .ok_or(Config(
            "the identity provider has no HTTP-Redirect SingleSignOnService",
        ))?;
    let sso_url = sso_url(location, allow_http)?;
    let mut certificates = Vec::new();
    for key in children(idp, METADATA, "KeyDescriptor") {
        if key.attribute("use").is_some_and(|usage| usage != "signing") {
            continue;
        }
        for node in key
            .descendants()
            .filter(|node| is(*node, DSIG, "X509Certificate"))
        {
            let certificate = Certificate::parse(&text_of(node))?;
            if !certificates.contains(&certificate) {
                certificates.push(certificate);
            }
        }
    }
    if certificates.is_empty() {
        return Err(Config("the metadata has no signing certificate"));
    }
    if certificates.len() > MAX_CERTIFICATES {
        return Err(Config("the metadata has more than 4 signing certificates"));
    }
    Ok(IdpSettings {
        entity_id,
        sso_url,
        certificates,
    })
}

// What this server says as the service provider.

/// The service provider's own endpoints for one organisation.
#[derive(Clone, Debug)]
pub struct ServiceProvider {
    /// Also where its metadata is served, as is usual.
    pub entity_id: String,
    pub acs_url: String,
}

impl ServiceProvider {
    pub fn for_org(public_url: &str, org_id: &str) -> Self {
        let base = public_url.trim_end_matches('/');
        Self {
            entity_id: format!("{base}/v1/sso/saml/{org_id}/metadata"),
            acs_url: format!("{base}/v1/sso/saml/{org_id}/acs"),
        }
    }

    /// The SP metadata to give the identity provider. It wants signed assertions and signs
    /// nothing itself: the AuthnRequest carries no secret, and the Response is what's checked.
    pub fn metadata(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <md:EntityDescriptor xmlns:md=\"{METADATA}\" entityID=\"{entity}\">\
             <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" \
             protocolSupportEnumeration=\"{PROTOCOL}\">\
             <md:NameIDFormat>{EMAIL_FORMAT}</md:NameIDFormat>\
             <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>\
             <md:AssertionConsumerService Binding=\"{POST_BINDING}\" Location=\"{acs}\" index=\"0\" \
             isDefault=\"true\"/></md:SPSSODescriptor></md:EntityDescriptor>\n",
            entity = xml_escape(&self.entity_id),
            acs = xml_escape(&self.acs_url),
        )
    }
}

/// One browser's trip to the identity provider.
#[derive(Clone, Debug)]
pub struct Flow {
    /// The AuthnRequest's ID; the Response must answer it.
    pub request_id: String,
    /// Sent with the request and posted back with the Response: the key the flow waits under.
    pub relay_state: String,
}

impl Flow {
    pub fn new() -> Self {
        Self {
            // An NCName: base64url is letters, digits, '-' and '_', after a leading '_'.
            request_id: format!("_{}", random_token()),
            relay_state: random_token(),
        }
    }

    pub fn authn_request(&self, sp: &ServiceProvider, idp: &IdpSettings, now_ms: i64) -> String {
        let instant = OffsetDateTime::from_unix_timestamp(now_ms.div_euclid(1000))
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
            .format(&Rfc3339)
            .unwrap_or_default();
        format!(
            "<samlp:AuthnRequest xmlns:samlp=\"{PROTOCOL}\" xmlns:saml=\"{ASSERTION}\" \
             ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{instant}\" Destination=\"{destination}\" \
             AssertionConsumerServiceURL=\"{acs}\" ProtocolBinding=\"{POST_BINDING}\">\
             <saml:Issuer>{issuer}</saml:Issuer><samlp:NameIDPolicy AllowCreate=\"true\"/>\
             </samlp:AuthnRequest>",
            id = self.request_id,
            destination = xml_escape(idp.sso_url.as_str()),
            acs = xml_escape(&sp.acs_url),
            issuer = xml_escape(&sp.entity_id),
        )
    }

    /// Where to send the browser: the HTTP-Redirect binding (DEFLATE, base64, URL-encoded).
    pub fn redirect_url(&self, sp: &ServiceProvider, idp: &IdpSettings, now_ms: i64) -> Url {
        use std::io::Write;
        let request = self.authn_request(sp, idp, now_ms);
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(request.as_bytes())
            .expect("writing to memory");
        let deflated = encoder.finish().expect("deflating in memory");
        let mut url = idp.sso_url.clone();
        url.query_pairs_mut()
            .append_pair("SAMLRequest", &STANDARD.encode(deflated))
            .append_pair("RelayState", &self.relay_state);
        url
    }
}

// The Response.

/// What the Response must match.
pub struct Expected<'a> {
    pub idp: &'a IdpSettings,
    pub sp: &'a ServiceProvider,
    pub request_id: &'a str,
    pub now_ms: i64,
}

/// Every `ID` (or `Id`, `id`) value must be unique, so a reference can only mean one element.
fn check_ids(doc: &Document<'_>) -> Result<(), SamlError> {
    let mut seen = std::collections::HashSet::new();
    for node in doc.descendants().filter(Node::is_element) {
        for attribute in node.attributes() {
            if attribute.namespace().is_none()
                && matches!(attribute.name(), "ID" | "Id" | "id")
                && !seen.insert(attribute.value())
            {
                return Err(Invalid("an ID appears twice"));
            }
        }
    }
    Ok(())
}

fn inclusive_prefixes(node: Node<'_, '_>) -> Result<Vec<Option<String>>, SamlError> {
    let mut lists = node
        .children()
        .filter(|child| is(*child, EXC_C14N, "InclusiveNamespaces"));
    let Some(list) = lists.next() else {
        return Ok(Vec::new());
    };
    if lists.next().is_some() {
        return Err(Invalid("InclusiveNamespaces appears twice"));
    }
    Ok(list
        .attribute("PrefixList")
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(|prefix| (prefix != "#default").then(|| prefix.to_owned()))
        .collect())
}

fn digest(algorithm: &str, data: &[u8]) -> Result<Vec<u8>, SamlError> {
    Ok(match algorithm {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Sha256::digest(data).to_vec(),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Sha384::digest(data).to_vec(),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Sha512::digest(data).to_vec(),
        _ => {
            return Err(Invalid(
                "the digest algorithm isn't one this server accepts",
            ));
        }
    })
}

/// Checks the enveloped signature `signature` over its parent `signed`, with one of the pinned
/// certificates.
fn verify_signature(
    signed: Node<'_, '_>,
    signature: Node<'_, '_>,
    certificates: &[Certificate],
) -> Result<(), SamlError> {
    let mut parts = signature.children().filter(Node::is_element);
    let signed_info = parts
        .next()
        .filter(|node| is(*node, DSIG, "SignedInfo"))
        .ok_or(Invalid("the signature has no SignedInfo"))?;
    let value = parts
        .next()
        .filter(|node| is(*node, DSIG, "SignatureValue"))
        .ok_or(Invalid("the signature has no SignatureValue"))?;

    let mut info = signed_info.children().filter(Node::is_element);
    let method = info
        .next()
        .filter(|node| is(*node, DSIG, "CanonicalizationMethod"))
        .ok_or(Invalid("SignedInfo has no CanonicalizationMethod"))?;
    if method.attribute("Algorithm") != Some(EXC_C14N) {
        return Err(Invalid("SignedInfo must use exclusive canonicalisation"));
    }
    let algorithm = info
        .next()
        .filter(|node| is(*node, DSIG, "SignatureMethod"))
        .and_then(|node| node.attribute("Algorithm"))
        .ok_or(Invalid("SignedInfo has no SignatureMethod"))?;
    let reference = info
        .next()
        .filter(|node| is(*node, DSIG, "Reference"))
        .ok_or(Invalid("SignedInfo has no Reference"))?;
    if info.next().is_some() {
        return Err(Invalid("SignedInfo must hold exactly one Reference"));
    }

    // The one reference names the element the signature is enveloped in.
    let id = signed
        .attribute("ID")
        .ok_or(Invalid("the signed element has no ID"))?;
    if reference.attribute("URI") != Some(&format!("#{id}")) {
        return Err(Invalid(
            "the signature doesn't reference the element it's in",
        ));
    }
    let mut reference_parts = reference.children().filter(Node::is_element);
    let transforms = reference_parts
        .next()
        .filter(|node| is(*node, DSIG, "Transforms"))
        .ok_or(Invalid("the reference has no Transforms"))?;
    let transforms: Vec<Node<'_, '_>> = transforms.children().filter(Node::is_element).collect();
    let [enveloped, exclusive] = transforms.as_slice() else {
        return Err(Invalid(
            "the transforms must be enveloped-signature, then exclusive canonicalisation",
        ));
    };
    if !is(*enveloped, DSIG, "Transform")
        || enveloped.attribute("Algorithm") != Some(ENVELOPED)
        || !is(*exclusive, DSIG, "Transform")
        || exclusive.attribute("Algorithm") != Some(EXC_C14N)
    {
        return Err(Invalid(
            "the transforms must be enveloped-signature, then exclusive canonicalisation",
        ));
    }
    let digest_method = reference_parts
        .next()
        .filter(|node| is(*node, DSIG, "DigestMethod"))
        .and_then(|node| node.attribute("Algorithm"))
        .ok_or(Invalid("the reference has no DigestMethod"))?;
    let digest_value = reference_parts
        .next()
        .filter(|node| is(*node, DSIG, "DigestValue"))
        .and_then(|node| decode_base64(&text_of(node)))
        .ok_or(Invalid("the reference has no DigestValue"))?;
    if reference_parts.next().is_some() {
        return Err(Invalid("the reference holds something unexpected"));
    }

    // SignedInfo first: nothing it says is trusted until its signature checks out.
    let canonical_info = c14n::exclusive(signed_info, None, &inclusive_prefixes(method)?)
        .map_err(|_| Invalid("SignedInfo can't be canonicalised"))?;
    let signature_bytes =
        decode_base64(&text_of(value)).ok_or(Invalid("the SignatureValue isn't base64"))?;
    let verified = certificates.iter().any(|certificate| {
        certificate
            .verify(algorithm, &canonical_info, &signature_bytes)
            .is_ok()
    });
    if !verified {
        // Say why when it's the algorithm, which is a setup problem rather than an attack.
        if let Some(certificate) = certificates.first() {
            certificate.verify(algorithm, &canonical_info, &signature_bytes)?;
        }
        return Err(Invalid("the signature doesn't verify"));
    }

    let canonical = c14n::exclusive(
        signed,
        Some(signature.id()),
        &inclusive_prefixes(*exclusive)?,
    )
    .map_err(|_| Invalid("the signed element can't be canonicalised"))?;
    if !constant_time_eq(&digest(digest_method, &canonical)?, &digest_value) {
        return Err(Invalid("the signed element was changed"));
    }
    Ok(())
}

fn check_issuer(node: Node<'_, '_>, expected: &str, required: bool) -> Result<(), SamlError> {
    match only_child(node, ASSERTION, "Issuer")? {
        Some(issuer) if text_of(issuer) == expected => Ok(()),
        Some(_) => Err(Invalid("wrong issuer")),
        None if required => Err(Invalid("no issuer")),
        None => Ok(()),
    }
}

fn check_conditions(assertion: Node<'_, '_>, expected: &Expected<'_>) -> Result<(), SamlError> {
    let conditions = required_child(assertion, ASSERTION, "Conditions", "no Conditions")?;
    if let Some(not_before) = conditions.attribute("NotBefore")
        && time_ms(not_before)? > expected.now_ms + CLOCK_SKEW_MS
    {
        return Err(Invalid("not valid yet"));
    }
    if let Some(not_after) = conditions.attribute("NotOnOrAfter")
        && time_ms(not_after)? + CLOCK_SKEW_MS <= expected.now_ms
    {
        return Err(Invalid("expired"));
    }
    let mut restrictions = children(conditions, ASSERTION, "AudienceRestriction").peekable();
    if restrictions.peek().is_none() {
        return Err(Invalid("no audience"));
    }
    for restriction in restrictions {
        let ours = children(restriction, ASSERTION, "Audience")
            .any(|audience| text_of(audience) == expected.sp.entity_id);
        if !ours {
            return Err(Invalid("wrong audience"));
        }
    }
    Ok(())
}

fn bearer_confirmed(subject: Node<'_, '_>, expected: &Expected<'_>) -> Result<bool, SamlError> {
    for confirmation in children(subject, ASSERTION, "SubjectConfirmation") {
        if confirmation.attribute("Method") != Some(BEARER) {
            continue;
        }
        let Some(data) = only_child(confirmation, ASSERTION, "SubjectConfirmationData")? else {
            continue;
        };
        let recipient = data.attribute("Recipient") == Some(expected.sp.acs_url.as_str());
        let answers = data
            .attribute("InResponseTo")
            .is_none_or(|id| id == expected.request_id);
        let fresh = match data.attribute("NotOnOrAfter") {
            Some(not_after) => time_ms(not_after)? + CLOCK_SKEW_MS > expected.now_ms,
            None => false,
        };
        let started = match data.attribute("NotBefore") {
            Some(not_before) => time_ms(not_before)? <= expected.now_ms + CLOCK_SKEW_MS,
            None => true,
        };
        if recipient && answers && fresh && started {
            return Ok(true);
        }
    }
    Ok(false)
}

fn email_in(assertion: Node<'_, '_>, name_id: Node<'_, '_>) -> Option<String> {
    if name_id.attribute("Format") == Some(EMAIL_FORMAT)
        && let Ok(email) = validate::email(&text_of(name_id))
    {
        return Some(email);
    }
    let statements = children(assertion, ASSERTION, "AttributeStatement");
    for statement in statements {
        for attribute in children(statement, ASSERTION, "Attribute") {
            let name = attribute.attribute("Name").unwrap_or_default();
            if !EMAIL_ATTRIBUTES
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
            {
                continue;
            }
            let value = children(attribute, ASSERTION, "AttributeValue")
                .map(text_of)
                .find_map(|value| validate::email(&value).ok());
            if value.is_some() {
                return value;
            }
        }
    }
    None
}

/// Checks a Response posted to the assertion consumer service, as base64, and returns who it
/// signed in.
pub fn verify_response(encoded: &str, expected: &Expected<'_>) -> Result<Claims, SamlError> {
    if encoded.len() > MAX_RESPONSE * 4 / 3 + 4 {
        return Err(Invalid("it's too large"));
    }
    let bytes = decode_base64(encoded).ok_or(Invalid("it isn't base64"))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Invalid("it isn't UTF-8"))?;
    let doc = parse(text)?;
    check_ids(&doc)?;

    let response = doc.root_element();
    if !is(response, PROTOCOL, "Response") || response.attribute("Version") != Some("2.0") {
        return Err(Invalid("it isn't a SAML 2.0 Response"));
    }
    if response
        .attribute("Destination")
        .is_some_and(|destination| destination != expected.sp.acs_url)
    {
        return Err(Invalid("it was sent to somewhere else"));
    }
    if response.attribute("InResponseTo") != Some(expected.request_id) {
        return Err(Invalid("it doesn't answer this sign-in"));
    }
    check_issuer(response, &expected.idp.entity_id, false)?;
    let status = required_child(response, PROTOCOL, "Status", "no status")?;
    let code = required_child(status, PROTOCOL, "StatusCode", "no status code")?;
    if code.attribute("Value") != Some(SUCCESS) {
        return Err(Invalid("the identity provider refused the sign-in"));
    }

    if doc
        .descendants()
        .any(|node| is(node, ASSERTION, "EncryptedAssertion"))
    {
        return Err(Invalid("encrypted assertions aren't supported"));
    }
    let mut assertions = doc
        .descendants()
        .filter(|node| is(*node, ASSERTION, "Assertion"));
    let assertion = assertions.next().ok_or(Invalid("no assertion"))?;
    if assertions.next().is_some() {
        return Err(Invalid("more than one assertion"));
    }
    if assertion.parent() != Some(response) {
        return Err(Invalid("the assertion isn't where it should be"));
    }

    // Every signature present must verify, and one must cover the assertion. A signed Response
    // covers its assertion as a descendant.
    let response_signature = only_child(response, DSIG, "Signature")?;
    let assertion_signature = only_child(assertion, DSIG, "Signature")?;
    if response_signature.is_none() && assertion_signature.is_none() {
        return Err(Invalid("it isn't signed"));
    }
    let certificates = &expected.idp.certificates;
    if let Some(signature) = response_signature {
        verify_signature(response, signature, certificates)?;
    }
    if let Some(signature) = assertion_signature {
        verify_signature(assertion, signature, certificates)?;
    }
    if doc
        .descendants()
        .filter(|node| is(*node, DSIG, "Signature"))
        .any(|node| Some(node) != response_signature && Some(node) != assertion_signature)
    {
        return Err(Invalid("a signature is somewhere unexpected"));
    }

    // From here on, only the assertion that was checked.
    if assertion.attribute("Version") != Some("2.0") {
        return Err(Invalid("the assertion isn't SAML 2.0"));
    }
    check_issuer(assertion, &expected.idp.entity_id, true)?;
    check_conditions(assertion, expected)?;
    let subject = required_child(assertion, ASSERTION, "Subject", "no subject")?;
    if only_child(subject, ASSERTION, "EncryptedID")?.is_some() {
        return Err(Invalid("encrypted name ids aren't supported"));
    }
    let name_id = required_child(subject, ASSERTION, "NameID", "no NameID")?;
    if name_id.attribute("Format") == Some(TRANSIENT) {
        return Err(Invalid(
            "the NameID is transient; use a persistent or email NameID",
        ));
    }
    let subject_id = text_of(name_id);
    if subject_id.is_empty() || subject_id.len() > 512 {
        return Err(Invalid("no NameID"));
    }
    if !bearer_confirmed(subject, expected)? {
        return Err(Invalid("no valid bearer confirmation for this service"));
    }
    if children(assertion, ASSERTION, "AuthnStatement")
        .next()
        .is_none()
    {
        return Err(Invalid("it doesn't say the person signed in"));
    }
    Ok(Claims {
        email: email_in(assertion, name_id),
        subject: subject_id,
        email_verified: None,
    })
}

#[cfg(test)]
mod tests;
