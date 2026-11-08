//! The SAML checks against responses signed two ways: a fixture signed with libxml2 and openssl
//! (`fixtures/make.sh`), so canonicalisation is checked against another implementation, and
//! responses signed here by a stand-in identity provider with throw-away keys, to try the known
//! attacks on.

use std::sync::OnceLock;

use p256::ecdsa::SigningKey as EcSigningKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::signature::{SignatureEncoding, Signer};
use x509_cert::der::asn1::{BitString, ObjectIdentifier};
use x509_cert::der::{Decode, Encode};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Validity;

use super::*;

const FIXTURE_ORG: &str = "0192f000-0000-7000-8000-000000000001";
const FIXTURE_NOW: i64 = 1_794_132_030_000; // 2026-11-08T10:00:30Z
const IDP: &str = "https://idp.example.com/saml";

fn fixture_idp() -> IdpSettings {
    IdpSettings {
        entity_id: IDP.into(),
        sso_url: Url::parse("https://idp.example.com/sso").unwrap(),
        certificates: vec![Certificate::parse(include_str!("fixtures/idp-cert.pem")).unwrap()],
    }
}

fn sp() -> ServiceProvider {
    ServiceProvider::for_org("https://pass.example.com/", FIXTURE_ORG)
}

fn fixture() -> &'static str {
    include_str!("fixtures/signed-response.xml")
}

fn check(xml: &str, idp: &IdpSettings, request_id: &str, now_ms: i64) -> Result<Claims, SamlError> {
    let sp = sp();
    let expected = Expected {
        idp,
        sp: &sp,
        request_id,
        now_ms,
    };
    verify_response(&STANDARD.encode(xml), &expected)
}

#[test]
fn a_response_signed_by_libxml2_and_openssl_verifies() {
    let claims = check(fixture(), &fixture_idp(), "_fixture-request", FIXTURE_NOW).unwrap();
    assert_eq!(claims.subject, "fixture-subject-42");
    assert_eq!(claims.email.as_deref(), Some("member@example.com"));
}

#[test]
fn the_fixture_fails_once_anything_signed_changes() {
    let idp = fixture_idp();
    for (from, to) in [
        ("fixture-subject-42", "fixture-subject-43"),
        ("Member@Example.com", "Owner@Example.com"),
        ("PasswordProtectedTransport", "Password"),
    ] {
        let changed = fixture().replace(from, to);
        assert_eq!(
            check(&changed, &idp, "_fixture-request", FIXTURE_NOW),
            Err(Invalid("the signed element was changed")),
            "{from}"
        );
    }
}

#[test]
fn the_fixture_is_bound_to_its_request_time_and_place() {
    let idp = fixture_idp();
    assert_eq!(
        check(fixture(), &idp, "_another-request", FIXTURE_NOW),
        Err(Invalid("it doesn't answer this sign-in"))
    );
    assert_eq!(
        check(fixture(), &idp, "_fixture-request", FIXTURE_NOW + 3_600_000),
        Err(Invalid("expired"))
    );
    let elsewhere = IdpSettings {
        entity_id: "https://other-idp.example.com".into(),
        ..idp.clone()
    };
    assert_eq!(
        check(fixture(), &elsewhere, "_fixture-request", FIXTURE_NOW),
        Err(Invalid("wrong issuer"))
    );
    // The key comes from the pinned certificate, never from the response's KeyInfo.
    let other_key = IdpSettings {
        certificates: vec![test_idp().certificate.clone()],
        ..idp
    };
    assert_eq!(
        check(fixture(), &other_key, "_fixture-request", FIXTURE_NOW),
        Err(Invalid("the signature doesn't verify"))
    );
}

// A stand-in identity provider.

struct TestIdp {
    rsa: RsaSigningKey<Sha256>,
    certificate: Certificate,
    ec: EcSigningKey,
    ec_certificate: Certificate,
}

fn certificate_for(spki: SubjectPublicKeyInfoOwned) -> Certificate {
    // Only the key matters to the service provider, so the certificate's own signature is filler.
    let tbs = x509_cert::TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: SerialNumber::new(&[1]).unwrap(),
        signature: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: None,
        },
        issuer: "CN=test-idp".parse::<Name>().unwrap(),
        validity: Validity::from_now(std::time::Duration::from_secs(86_400)).unwrap(),
        subject: "CN=test-idp".parse::<Name>().unwrap(),
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    let certificate = x509_cert::Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
            parameters: None,
        },
        signature: BitString::from_bytes(&[0]).unwrap(),
    };
    Certificate::from_der(certificate.to_der().unwrap()).unwrap()
}

fn test_idp() -> &'static TestIdp {
    static IDP: OnceLock<TestIdp> = OnceLock::new();
    IDP.get_or_init(|| {
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let spki = private.to_public_key().to_public_key_der().unwrap();
        let certificate =
            certificate_for(SubjectPublicKeyInfoOwned::from_der(spki.as_bytes()).unwrap());
        let ec = EcSigningKey::random(&mut rand_core::OsRng);
        let point = ec.verifying_key().to_encoded_point(false);
        let ec_spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
                parameters: Some(
                    x509_cert::der::Any::encode_from(&ObjectIdentifier::new_unwrap(
                        "1.2.840.10045.3.1.7",
                    ))
                    .unwrap(),
                ),
            },
            subject_public_key: BitString::from_bytes(point.as_bytes()).unwrap(),
        };
        TestIdp {
            rsa: RsaSigningKey::<Sha256>::new(private),
            certificate,
            ec,
            ec_certificate: certificate_for(ec_spki),
        }
    })
}

fn test_settings() -> IdpSettings {
    IdpSettings {
        entity_id: IDP.into(),
        sso_url: Url::parse("https://idp.example.com/sso").unwrap(),
        certificates: vec![
            test_idp().certificate.clone(),
            test_idp().ec_certificate.clone(),
        ],
    }
}

const NOW: i64 = FIXTURE_NOW;
const REQUEST: &str = "_request-1";

fn iso(ms: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ms / 1000)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

/// An unsigned assertion, with `{SIG}` where its signature goes.
fn assertion(id: &str, name_id: &str) -> String {
    let sp = sp();
    format!(
        "<saml:Assertion xmlns:saml=\"{ASSERTION}\" ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{now}\">\
         <saml:Issuer>{IDP}</saml:Issuer>{{SIG}}<saml:Subject>\
         <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{name_id}</saml:NameID>\
         <saml:SubjectConfirmation Method=\"{BEARER}\"><saml:SubjectConfirmationData \
         InResponseTo=\"{REQUEST}\" NotOnOrAfter=\"{later}\" Recipient=\"{acs}\"/></saml:SubjectConfirmation>\
         </saml:Subject><saml:Conditions NotBefore=\"{before}\" NotOnOrAfter=\"{later}\">\
         <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>\
         </saml:Conditions><saml:AuthnStatement AuthnInstant=\"{now}\"/>\
         <saml:AttributeStatement><saml:Attribute Name=\"mail\"><saml:AttributeValue>\
         member@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>\
         </saml:Assertion>",
        now = iso(NOW),
        before = iso(NOW - 60_000),
        later = iso(NOW + 300_000),
        acs = sp.acs_url,
        audience = sp.entity_id,
    )
}

fn response(inner: &str) -> String {
    format!(
        "<samlp:Response xmlns:samlp=\"{PROTOCOL}\" xmlns:saml=\"{ASSERTION}\" ID=\"_response-1\" \
         Version=\"2.0\" IssueInstant=\"{now}\" Destination=\"{acs}\" InResponseTo=\"{REQUEST}\">\
         <saml:Issuer>{IDP}</saml:Issuer>{{SIG}}<samlp:Status><samlp:StatusCode Value=\"{SUCCESS}\"/>\
         </samlp:Status>{inner}</samlp:Response>",
        now = iso(NOW),
        acs = sp().acs_url,
    )
}

#[derive(Clone, Copy)]
enum Alg {
    Rsa,
    Ec,
    RsaSha1,
}

/// Signs the element with this ID in `xml`, filling the first `{SIG}` placeholder inside it,
/// and removes any other placeholder.
fn sign(xml: &str, id: &str, alg: Alg) -> String {
    let clean = |text: &str| text.replace("{SIG}", "");
    let (signature_method, digest_method) = match alg {
        Alg::Rsa => (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ),
        Alg::Ec => (
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            "http://www.w3.org/2001/04/xmlenc#sha256",
        ),
        Alg::RsaSha1 => (
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "http://www.w3.org/2000/09/xmldsig#sha1",
        ),
    };
    let start = xml.find(&format!("ID=\"{id}\"")).unwrap();
    let placeholder = start + xml[start..].find("{SIG}").unwrap();
    let unsigned = clean(xml);
    let doc = Document::parse(&unsigned).unwrap();
    let element = doc
        .descendants()
        .find(|node| node.attribute("ID") == Some(id))
        .unwrap();
    let canonical = c14n::exclusive(element, None, &[]).unwrap();
    let digest_value = match alg {
        Alg::RsaSha1 => STANDARD.encode(sha1::Sha1::digest(&canonical)),
        _ => STANDARD.encode(Sha256::digest(&canonical)),
    };
    let signed_info = format!(
        "<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"/>\
         <ds:SignatureMethod Algorithm=\"{signature_method}\"/><ds:Reference URI=\"#{id}\">\
         <ds:Transforms><ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"{EXC_C14N}\"/>\
         </ds:Transforms><ds:DigestMethod Algorithm=\"{digest_method}\"/>\
         <ds:DigestValue>{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    );
    let signature = |value: &str| {
        format!(
            "<ds:Signature xmlns:ds=\"{DSIG}\">{signed_info}<ds:SignatureValue>{value}</ds:SignatureValue>\
             </ds:Signature>"
        )
    };
    let with_empty = format!(
        "{}{}{}",
        clean(&xml[..placeholder]),
        signature(""),
        clean(&xml[placeholder + 5..])
    );
    let doc = Document::parse(&with_empty).unwrap();
    let info = doc
        .descendants()
        .find(|node| is(*node, DSIG, "SignedInfo"))
        .unwrap();
    let canonical_info = c14n::exclusive(info, None, &[]).unwrap();
    let value = match alg {
        Alg::Rsa | Alg::RsaSha1 => STANDARD.encode(test_idp().rsa.sign(&canonical_info).to_bytes()),
        Alg::Ec => {
            let signature: p256::ecdsa::Signature = test_idp().ec.sign(&canonical_info);
            STANDARD.encode(signature.to_bytes())
        }
    };
    with_empty.replacen(
        "<ds:SignatureValue></ds:SignatureValue>",
        &format!("<ds:SignatureValue>{value}</ds:SignatureValue>"),
        1,
    )
}

fn verify(xml: &str) -> Result<Claims, SamlError> {
    check(xml, &test_settings(), REQUEST, NOW)
}

fn signed_assertion_response() -> String {
    sign(&response(&assertion("_a1", "subject-1")), "_a1", Alg::Rsa)
}

#[test]
fn a_signed_assertion_verifies_with_rsa_or_ecdsa() {
    let claims = verify(&signed_assertion_response()).unwrap();
    assert_eq!(claims.subject, "subject-1");
    assert_eq!(claims.email.as_deref(), Some("member@example.com"));
    let ec = sign(&response(&assertion("_a1", "subject-1")), "_a1", Alg::Ec);
    assert_eq!(verify(&ec).unwrap().subject, "subject-1");
}

#[test]
fn a_signed_response_covers_its_assertion() {
    let xml = sign(
        &response(&assertion("_a1", "subject-1")),
        "_response-1",
        Alg::Rsa,
    );
    assert_eq!(verify(&xml).unwrap().subject, "subject-1");
    // Both signed, as some providers do.
    let both = sign(
        &signed_assertion_response().replacen("</saml:Issuer>", "</saml:Issuer>{SIG}", 1),
        "_response-1",
        Alg::Rsa,
    );
    assert_eq!(verify(&both).unwrap().subject, "subject-1");
}

#[test]
fn unsigned_and_sha1_responses_are_refused() {
    let unsigned = response(&assertion("_a1", "subject-1")).replace("{SIG}", "");
    assert_eq!(verify(&unsigned), Err(Invalid("it isn't signed")));
    let sha1 = sign(
        &response(&assertion("_a1", "subject-1")),
        "_a1",
        Alg::RsaSha1,
    );
    assert!(verify(&sha1).is_err());
}

#[test]
fn a_second_assertion_or_a_moved_one_is_refused() {
    let signed = signed_assertion_response();
    // The classic wrapping attack: the signed assertion stays, a forged one is added.
    let forged = assertion("_evil", "admin").replace("{SIG}", "");
    let two = signed.replace("</samlp:Response>", &format!("{forged}</samlp:Response>"));
    assert_eq!(verify(&two), Err(Invalid("more than one assertion")));
    // The signed assertion hidden in an extension, a forged one in its place.
    let start = signed.find("<saml:Assertion").unwrap();
    let end = signed.find("</saml:Assertion>").unwrap() + "</saml:Assertion>".len();
    let original = &signed[start..end];
    let moved = format!(
        "{}<samlp:Extensions>{original}</samlp:Extensions>{}{}",
        &signed[..start],
        forged,
        &signed[end..]
    );
    assert!(verify(&moved).is_err());
    let only_moved = format!(
        "{}<samlp:Extensions>{original}</samlp:Extensions>{}",
        &signed[..start],
        &signed[end..]
    );
    assert_eq!(
        verify(&only_moved),
        Err(Invalid("the assertion isn't where it should be"))
    );
}

#[test]
fn the_signature_must_reference_the_element_it_is_in() {
    // The assertion's signature is valid, but taken out of the assertion and put on the Response
    // it references nothing there.
    let signed = signed_assertion_response();
    let start = signed.find("<ds:Signature").unwrap();
    let end = signed.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    let signature = &signed[start..end];
    let without = format!("{}{}", &signed[..start], &signed[end..]);
    let on_response = without.replacen("</saml:Issuer>", &format!("</saml:Issuer>{signature}"), 1);
    assert_eq!(
        verify(&on_response),
        Err(Invalid(
            "the signature doesn't reference the element it's in"
        ))
    );
}

#[test]
fn duplicate_ids_are_refused() {
    let signed = signed_assertion_response();
    let duplicate = signed.replace(
        "<samlp:Status>",
        "<samlp:Extensions><x ID=\"_a1\"/></samlp:Extensions><samlp:Status>",
    );
    assert_eq!(verify(&duplicate), Err(Invalid("an ID appears twice")));
}

#[test]
fn a_comment_cannot_cut_a_signed_name_short() {
    // Signed as "admin@example.com.evil.test"; a comment inserted after signing doesn't change the
    // digest, and the name is still read whole, not just up to the comment.
    let signed = sign(
        &response(&assertion("_a1", "admin@example.com.evil.test")),
        "_a1",
        Alg::Rsa,
    );
    let commented = signed.replace(
        "admin@example.com.evil.test",
        "admin@example.com<!---->.evil.test",
    );
    assert_eq!(
        verify(&commented).unwrap().subject,
        "admin@example.com.evil.test"
    );
}

#[test]
fn a_dtd_is_refused() {
    let signed = signed_assertion_response();
    let with_dtd = format!("<!DOCTYPE r [<!ENTITY e \"x\">]>{signed}");
    assert_eq!(
        verify(&with_dtd),
        Err(Invalid("it isn't well-formed XML without a DTD"))
    );
}

#[test]
fn every_condition_is_checked() {
    let sp = sp();
    for (from, to, why) in [
        (
            sp.entity_id.as_str(),
            "https://someone-else.example",
            "wrong audience",
        ),
        (
            sp.acs_url.as_str(),
            "https://someone-else.example/acs",
            "it was sent to somewhere else",
        ),
        (REQUEST, "_another", "it doesn't answer this sign-in"),
        (IDP, "https://evil.example", "wrong issuer"),
        (
            SUCCESS,
            "urn:oasis:names:tc:SAML:2.0:status:Requester",
            "the identity provider refused the sign-in",
        ),
        (
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            TRANSIENT,
            "the NameID is transient; use a persistent or email NameID",
        ),
    ] {
        let xml = sign(
            &response(&assertion("_a1", "subject-1")).replace(from, to),
            "_a1",
            Alg::Rsa,
        );
        assert_eq!(verify(&xml), Err(Invalid(why)), "{to}");
    }
    let xml = signed_assertion_response();
    assert_eq!(
        check(&xml, &test_settings(), REQUEST, NOW + 3_600_000),
        Err(Invalid("expired"))
    );
    assert_eq!(
        check(&xml, &test_settings(), REQUEST, NOW - 3_600_000),
        Err(Invalid("not valid yet"))
    );
}

#[test]
fn a_recipient_only_on_the_assertion_must_still_match() {
    // The Response names no Destination; the confirmation's Recipient still has to be ours.
    let sp = sp();
    let base = response(&assertion("_a1", "subject-1"))
        .replace(&format!(" Destination=\"{}\"", sp.acs_url), "");
    assert_eq!(
        verify(&sign(&base, "_a1", Alg::Rsa)).unwrap().subject,
        "subject-1"
    );
    let elsewhere = base.replace(
        &format!("Recipient=\"{}\"", sp.acs_url),
        "Recipient=\"https://x.example/acs\"",
    );
    assert_eq!(
        verify(&sign(&elsewhere, "_a1", Alg::Rsa)),
        Err(Invalid("no valid bearer confirmation for this service"))
    );
}

#[test]
fn metadata_gives_the_entity_redirect_url_and_signing_certificates() {
    let certificate = test_idp().certificate.to_base64();
    let encryption = test_idp().ec_certificate.to_base64();
    let xml = format!(
        "<md:EntityDescriptor xmlns:md=\"{METADATA}\" xmlns:ds=\"{DSIG}\" entityID=\"{IDP}\">\
         <md:IDPSSODescriptor protocolSupportEnumeration=\"{PROTOCOL}\">\
         <md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>\n{certificate}\n\
         </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>\
         <md:KeyDescriptor use=\"encryption\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{encryption}\
         </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>\
         <md:SingleSignOnService Binding=\"{POST_BINDING}\" Location=\"https://idp.example.com/post\"/>\
         <md:SingleSignOnService Binding=\"{REDIRECT_BINDING}\" Location=\"https://idp.example.com/sso\"/>\
         </md:IDPSSODescriptor></md:EntityDescriptor>"
    );
    let settings = parse_metadata(&xml, false).unwrap();
    assert_eq!(settings.entity_id, IDP);
    assert_eq!(settings.sso_url.as_str(), "https://idp.example.com/sso");
    assert_eq!(settings.certificates, vec![test_idp().certificate.clone()]);
    assert!(
        parse_metadata(
            &xml.replace("https://idp.example.com/sso", "http://idp.example.com/sso"),
            false
        )
        .is_err()
    );
    assert!(parse_metadata("<x/>", false).is_err());
}

#[test]
fn certificates_must_carry_a_usable_key() {
    assert!(Certificate::parse(include_str!("fixtures/idp-cert.pem")).is_ok());
    assert!(Certificate::parse(&test_idp().certificate.to_base64()).is_ok());
    assert!(Certificate::parse("not a certificate").is_err());
    let fingerprint = test_idp().certificate.fingerprint();
    assert_eq!(fingerprint.len(), 32 * 3 - 1);
}

#[test]
fn the_redirect_carries_a_deflated_request_naming_this_service() {
    use std::io::Read;
    let flow = Flow::new();
    let url = flow.redirect_url(&sp(), &test_settings(), NOW);
    let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(pairs["RelayState"], flow.relay_state);
    let deflated = STANDARD.decode(&pairs["SAMLRequest"]).unwrap();
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(deflated.as_slice())
        .read_to_string(&mut xml)
        .unwrap();
    let doc = Document::parse(&xml).unwrap();
    let request = doc.root_element();
    assert!(is(request, PROTOCOL, "AuthnRequest"));
    assert_eq!(request.attribute("ID"), Some(flow.request_id.as_str()));
    assert_eq!(
        request.attribute("AssertionConsumerServiceURL"),
        Some(sp().acs_url.as_str())
    );
    assert_eq!(
        text_of(request.first_element_child().unwrap()),
        sp().entity_id
    );
    let metadata = sp().metadata();
    assert!(Document::parse(&metadata).is_ok());
    assert!(metadata.contains(&sp().acs_url));
}
