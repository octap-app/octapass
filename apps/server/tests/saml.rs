//! SAML sign-in, end to end over HTTP: settings, the redirect, the assertion consumer service and
//! the code the browser shows. The identity provider is a stand-in in this process with a key made
//! for the test. It writes its XML already in canonical form and signs it with the `rsa` crate, so
//! the server's own canonicalisation is checked against a second, independent computation.

use crate::common;
use crate::orgs::{create_org, join};

use std::io::Read;
use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::people::Person;
use common::*;
use octapass_server::config::RateLimits;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::signature::{SignatureEncoding, Signer};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_cert::der::asn1::{BitString, ObjectIdentifier};
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const IDP: &str = "https://idp.example.test/saml";
const SSO_URL: &str = "https://idp.example.test/sso";
const SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

struct Idp {
    key: SigningKey<Sha256>,
    /// PEM.
    certificate: String,
}

fn certificate_for(key: &rsa::RsaPrivateKey) -> String {
    // The service provider pins the key; the certificate's own signature is filler.
    let spki = key.to_public_key().to_public_key_der().unwrap();
    let sha256_rsa = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    let algorithm = AlgorithmIdentifierOwned {
        oid: sha256_rsa,
        parameters: None,
    };
    let name: x509_cert::name::Name = "CN=stand-in idp".parse().unwrap();
    let certificate = x509_cert::Certificate {
        tbs_certificate: x509_cert::TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: x509_cert::serial_number::SerialNumber::new(&[7]).unwrap(),
            signature: algorithm.clone(),
            issuer: name.clone(),
            validity: x509_cert::time::Validity::from_now(std::time::Duration::from_secs(3600))
                .unwrap(),
            subject: name,
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(spki.as_bytes()).unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        },
        signature_algorithm: algorithm,
        signature: BitString::from_bytes(&[0]).unwrap(),
    };
    let der = STANDARD.encode(certificate.to_der().unwrap());
    format!("-----BEGIN CERTIFICATE-----\n{der}\n-----END CERTIFICATE-----\n")
}

fn idp() -> &'static Idp {
    static IDP_KEY: OnceLock<Idp> = OnceLock::new();
    IDP_KEY.get_or_init(|| {
        let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        Idp {
            certificate: certificate_for(&key),
            key: SigningKey::new(key),
        }
    })
}

fn iso(offset_secs: i64) -> String {
    (OffsetDateTime::now_utc() + time::Duration::seconds(offset_secs))
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

/// What the stand-in provider says about the next person, and how.
struct Answer<'a> {
    subject: &'a str,
    email: &'a str,
    /// Break the signature after signing.
    tamper: bool,
}

/// A signed Response to `request_id`, base64. Every element is written in exclusive canonical
/// form, so the digest and the signature are over exactly these bytes.
fn signed_response(sp_entity: &str, acs: &str, request_id: &str, answer: &Answer<'_>) -> String {
    let id = format!("_assertion-{}", new_id());
    let (now, before, later) = (iso(0), iso(-60), iso(300));
    let subject = answer.subject;
    let email = answer.email;
    let assertion = |signature: &str| {
        format!(
            "<saml:Assertion xmlns:saml=\"{SAML}\" ID=\"{id}\" IssueInstant=\"{now}\" Version=\"2.0\">\
             <saml:Issuer>{IDP}</saml:Issuer>{signature}<saml:Subject>\
             <saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{subject}</saml:NameID>\
             <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
             <saml:SubjectConfirmationData InResponseTo=\"{request_id}\" NotOnOrAfter=\"{later}\" Recipient=\"{acs}\">\
             </saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject>\
             <saml:Conditions NotBefore=\"{before}\" NotOnOrAfter=\"{later}\"><saml:AudienceRestriction>\
             <saml:Audience>{sp_entity}</saml:Audience></saml:AudienceRestriction></saml:Conditions>\
             <saml:AuthnStatement AuthnInstant=\"{now}\"></saml:AuthnStatement><saml:AttributeStatement>\
             <saml:Attribute Name=\"email\"><saml:AttributeValue>{email}</saml:AttributeValue>\
             </saml:Attribute></saml:AttributeStatement></saml:Assertion>"
        )
    };
    let digest = STANDARD.encode(Sha256::digest(assertion("").as_bytes()));
    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"{DS}\"><ds:CanonicalizationMethod Algorithm=\"{EXC}\">\
         </ds:CanonicalizationMethod><ds:SignatureMethod \
         Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod>\
         <ds:Reference URI=\"#{id}\"><ds:Transforms><ds:Transform \
         Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform>\
         <ds:Transform Algorithm=\"{EXC}\"></ds:Transform></ds:Transforms><ds:DigestMethod \
         Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>\
         <ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"
    );
    let mut value = idp().key.sign(signed_info.as_bytes()).to_bytes().to_vec();
    if answer.tamper {
        value[10] ^= 1;
    }
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{DS}\">{signed_info}<ds:SignatureValue>{}</ds:SignatureValue>\
         </ds:Signature>",
        STANDARD.encode(value)
    );
    let response = format!(
        "<samlp:Response xmlns:samlp=\"{SAMLP}\" xmlns:saml=\"{SAML}\" Destination=\"{acs}\" \
         ID=\"_response-{}\" InResponseTo=\"{request_id}\" IssueInstant=\"{now}\" Version=\"2.0\">\
         <saml:Issuer>{IDP}</saml:Issuer><samlp:Status><samlp:StatusCode \
         Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{}</samlp:Response>",
        new_id(),
        assertion(&signature)
    );
    STANDARD.encode(response)
}

async fn server() -> TestServer {
    TestServer::with_config(|config| config.rate_limits = RateLimits::unlimited()).await
}

fn path_of(url: &str) -> String {
    let url = url::Url::parse(url).unwrap();
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

/// The browser's trip: the start link, the provider, and the post back. Returns the last page,
/// and the form that was posted (to replay).
async fn browser(
    server: &TestServer,
    start: &str,
    answer: &Answer<'_>,
) -> (StatusCode, String, String) {
    let request = Request::builder()
        .uri(path_of(start))
        .body(Body::empty())
        .unwrap();
    let (status, headers, body) = server.send_raw(request).await;
    if status != StatusCode::FOUND {
        return (status, String::from_utf8(body).unwrap(), String::new());
    }
    let location = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
    assert!(location.as_str().starts_with(SSO_URL), "{location}");
    let query: std::collections::HashMap<_, _> = location.query_pairs().into_owned().collect();
    let mut request_xml = String::new();
    flate2::read::DeflateDecoder::new(STANDARD.decode(&query["SAMLRequest"]).unwrap().as_slice())
        .read_to_string(&mut request_xml)
        .unwrap();
    let doc = roxmltree::Document::parse(&request_xml).unwrap();
    let authn = doc.root_element();
    assert_eq!(authn.tag_name().name(), "AuthnRequest");
    let request_id = authn.attribute("ID").unwrap();
    let acs = authn.attribute("AssertionConsumerServiceURL").unwrap();
    let sp_entity = authn.first_element_child().unwrap().text().unwrap();
    let response = signed_response(sp_entity, acs, request_id, answer);
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("SAMLResponse", &response)
        .append_pair("RelayState", &query["RelayState"])
        .finish();
    let (status, page) = post_form(server, acs, &form).await;
    (status, page, form)
}

async fn post_form(server: &TestServer, acs: &str, form: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(path_of(acs))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form.to_owned()))
        .unwrap();
    let (status, _, body) = server.send_raw(request).await;
    (status, String::from_utf8(body).unwrap())
}

fn code_in(page: &str) -> String {
    let start = page.find("class=\"code\">").expect("a code on the page") + 13;
    page[start..start + 6].to_owned()
}

async fn configure(server: &TestServer, owner: &Person, org: &str) -> serde_json::Value {
    let path = format!("/v1/orgs/{org}/sso/saml");
    let body = json!({ "entityId": IDP, "ssoUrl": SSO_URL, "certificates": [idp().certificate] });
    let saved = server.send_as(owner, Method::PUT, &path, Some(body)).await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    saved.body
}

async fn test_sign_in(
    server: &TestServer,
    owner: &Person,
    org: &str,
    answer: &Answer<'_>,
) -> String {
    let path = format!("/v1/orgs/{org}/sso/test");
    let started = server.send_as(owner, Method::POST, &path, None).await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.body);
    let (_, page, _) = browser(server, started.body["url"].as_str().unwrap(), answer).await;
    page
}

async fn require_sso(server: &TestServer, owner: &Person, org: &str) -> Response {
    let path = format!("/v1/orgs/{org}/policies");
    let body = json!({
        "requireTwoStep": false, "requireSso": true, "ssoMaxAgeHours": 168,
        "disableShareLinks": false, "disableEmergencyAccess": false, "disableExport": false,
    });
    server.send_as(owner, Method::PUT, &path, Some(body)).await
}

async fn sso_challenge(server: &TestServer, email: &str) -> serde_json::Value {
    let response = server.login_with(email, PASSWORD, "Laptop").await;
    assert!(response.is_problem("sso-required"), "{:?}", response.body);
    response.body["sso"].clone()
}

#[tokio::test]
async fn saml_is_a_step_after_the_password_with_a_signed_assertion() {
    let server = server().await;
    let owner = server.person("owner@example.com").await;
    let member = server.person("member@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    join(&server, &owner, &org, &member, "member").await;

    let saved = configure(&server, &owner, &org).await;
    assert_eq!(saved["protocol"], "saml");
    assert_eq!(saved["saml"]["entityId"], IDP);
    assert_eq!(
        saved["saml"]["certificates"][0]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        95
    );
    assert!(saved.get("issuer").is_none(), "no OpenID Connect settings");
    let sp = saved["samlServiceProvider"].clone();
    assert!(
        sp["acsUrl"]
            .as_str()
            .unwrap()
            .ends_with(&format!("/v1/sso/saml/{org}/acs"))
    );

    // The metadata to give the provider, with no account and no lookup.
    let request = Request::builder()
        .uri(path_of(sp["metadataUrl"].as_str().unwrap()))
        .body(Body::empty())
        .unwrap();
    let (status, headers, body) = server.send_raw(request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/samlmetadata+xml");
    let metadata = String::from_utf8(body).unwrap();
    assert!(metadata.contains(sp["acsUrl"].as_str().unwrap()));
    assert!(metadata.contains(&format!(
        "entityID=\"{}\"",
        sp["entityId"].as_str().unwrap()
    )));

    // Requiring SSO waits for a test sign-in.
    let early = require_sso(&server, &owner, &org).await;
    assert!(early.is_problem("sso-config"), "{:?}", early.body);
    let owner_answer = Answer {
        subject: "owner-sub",
        email: "owner@example.com",
        tamper: false,
    };
    let page = test_sign_in(&server, &owner, &org, &owner_answer).await;
    assert!(page.contains("It works"), "{page}");
    let required = require_sso(&server, &owner, &org).await;
    assert_eq!(required.status, StatusCode::OK, "{:?}", required.body);

    // The member's sign-in stops after the password, and the browser's code finishes it.
    let sso = sso_challenge(&server, "member@example.com").await;
    let answer = Answer {
        subject: "member-sub",
        email: "Member@Example.com",
        tamper: false,
    };
    let (status, page, form) = browser(&server, sso["url"].as_str().unwrap(), &answer).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert!(page.contains("Laptop"), "the page names the device: {page}");
    let body = json!({ "challengeId": sso["challengeId"], "code": code_in(&page) });
    let finished = server.post("/v1/auth/login/sso", body).await;
    assert_eq!(finished.status, StatusCode::OK, "{:?}", finished.body);
    assert!(
        finished.body["account"]["wrappedAsk"].is_string(),
        "the ASK stays wrapped for the master password"
    );

    // The same Response posted again finds nothing waiting.
    let acs = sp["acsUrl"].as_str().unwrap();
    let (status, page) = post_form(&server, acs, &form).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("expired"), "{page}");

    // The link now decides: another subject with the same email is someone else.
    let sso = sso_challenge(&server, "member@example.com").await;
    let other = Answer {
        subject: "someone-else",
        email: "member@example.com",
        tamper: false,
    };
    let (_, page, _) = browser(&server, sso["url"].as_str().unwrap(), &other).await;
    assert!(page.contains("different account"), "{page}");

    // A broken signature is refused like any provider failure.
    let sso = sso_challenge(&server, "member@example.com").await;
    let forged = Answer {
        subject: "member-sub",
        email: "member@example.com",
        tamper: true,
    };
    let (status, page, _) = browser(&server, sso["url"].as_str().unwrap(), &forged).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(page.contains("didn't finish"), "{page}");
    let members = server
        .get_as(&owner, &format!("/v1/orgs/{org}/members"))
        .await;
    let linked: Vec<bool> = members.body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["ssoLinked"].as_bool().unwrap())
        .collect();
    assert_eq!(
        linked,
        [true, false],
        "the member linked, the owner's test sign-in didn't"
    );
}

#[tokio::test]
async fn saml_settings_are_checked_and_replace_openid_connect() {
    let server = server().await;
    let owner = server.person("owner@example.com").await;
    let org = create_org(&server, &owner, "Acme").await;
    let path = format!("/v1/orgs/{org}/sso/saml");
    for (body, why) in [
        (
            // Plain HTTP is refused too, outside dev mode (the test server's), as for OIDC.
            json!({ "entityId": IDP, "ssoUrl": "https://user:pw@idp.example.test/sso", "certificates": [idp().certificate] }),
            "credentials in the URL",
        ),
        (
            json!({ "entityId": IDP, "ssoUrl": SSO_URL, "certificates": ["not a certificate"] }),
            "a bad certificate",
        ),
        (
            json!({ "entityId": IDP, "ssoUrl": SSO_URL, "certificates": [] }),
            "no certificate",
        ),
        (json!({ "metadataXml": "<x/>" }), "not metadata"),
    ] {
        let refused = server.send_as(&owner, Method::PUT, &path, Some(body)).await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "{why}: {:?}",
            refused.body
        );
    }

    // Metadata, as providers export it.
    let der = idp()
        .certificate
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let metadata = format!(
        "<?xml version=\"1.0\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" \
         xmlns:ds=\"{DS}\" entityID=\"{IDP}\"><md:IDPSSODescriptor \
         protocolSupportEnumeration=\"{SAMLP}\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data>\
         <ds:X509Certificate>{der}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>\
         <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" \
         Location=\"{SSO_URL}\"/></md:IDPSSODescriptor></md:EntityDescriptor>"
    );
    let saved = server
        .send_as(
            &owner,
            Method::PUT,
            &path,
            Some(json!({ "metadataXml": metadata })),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    assert_eq!(saved.body["saml"]["ssoUrl"], SSO_URL);
    let read = server.get_as(&owner, &format!("/v1/orgs/{org}/sso")).await;
    assert_eq!(read.body["protocol"], "saml");

    // Removing works as for OpenID Connect, and so does the SP information without settings.
    let removed = server
        .send_as(&owner, Method::DELETE, &format!("/v1/orgs/{org}/sso"), None)
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT);
    let read = server.get_as(&owner, &format!("/v1/orgs/{org}/sso")).await;
    assert!(read.body.get("protocol").is_none(), "{:?}", read.body);
    assert!(read.body["samlServiceProvider"]["entityId"].is_string());

    // Only owners.
    let admin = server.person("admin@example.com").await;
    join(&server, &owner, &org, &admin, "admin").await;
    let body = json!({ "entityId": IDP, "ssoUrl": SSO_URL, "certificates": [idp().certificate] });
    let refused = server.send_as(&admin, Method::PUT, &path, Some(body)).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
}
