//! The ACME client against a small CA on loopback that does what a real one must: it checks every
//! JWS signature and nonce, fetches HTTP-01 answers from the client's server, checks DNS-01 values
//! and the CSR's signature, and issues from a real CA key. No live CA is involved.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use octapass_core::encoding::{b64_decode, b64_encode};
use octapass_core::tools::toolkit::acme as core_acme;
use octapass_core::tools::toolkit::keys::{
    self, KeyKind, ParsedKey, PublicKey, SignatureAlgorithm,
};
use octapass_core::tools::toolkit::x509;
use octapass_net_tools::acme::{Challenge, ExternalAccount, Request, issue};
use octapass_net_tools::dns::DnsProvider;
use octapass_net_tools::{NetError, Result};
use rand_core::OsRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const TOKEN: &str = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";

#[derive(Default)]
struct State {
    base: String,
    nonces: HashSet<String>,
    next: u64,
    /// One bad nonce is answered with `badNonce` first, as RFC 8555 §6.5 allows.
    rejected_nonce: bool,
    accounts: HashMap<String, PublicKey>,
    identifiers: Vec<String>,
    challenge_kind: String,
    http_port: u16,
    dns_records: Arc<Mutex<HashMap<String, String>>>,
    validated: bool,
    certificate: Option<String>,
    require_eab: bool,
    eab_seen: bool,
    log: Vec<String>,
}

struct Parsed {
    payload: Value,
    empty: bool,
    key: PublicKey,
    kid: Option<String>,
}

fn response(status: u16, headers: &[(&str, String)], body: &str) -> Vec<u8> {
    let mut text = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    text.push_str("\r\n");
    text.push_str(body);
    text.into_bytes()
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next()?.to_owned(), parts.next()?.to_owned());
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).ok()?;
    Some((method, path, body))
}

fn fresh_nonce(state: &mut State) -> String {
    state.next += 1;
    let nonce = format!("nonce-{}", state.next);
    state.nonces.insert(nonce.clone());
    nonce
}

/// Checks a flattened JWS the way a CA does: right URL, unused nonce, valid signature.
fn check_jws(
    state: &mut State,
    path: &str,
    body: &[u8],
) -> std::result::Result<Parsed, (u16, Value)> {
    let jws: Value =
        serde_json::from_slice(body).map_err(|_| (400, json!({ "detail": "not JSON" })))?;
    let protected_text = jws["protected"].as_str().unwrap();
    let payload_text = jws["payload"].as_str().unwrap();
    let protected: Value = serde_json::from_slice(&b64_decode(protected_text).unwrap()).unwrap();
    assert_eq!(
        protected["url"],
        format!("{}{path}", state.base),
        "the JWS must name the URL"
    );
    let nonce = protected["nonce"].as_str().unwrap().to_owned();
    if !state.rejected_nonce {
        state.rejected_nonce = true;
        state.nonces.remove(&nonce);
        return Err((
            400,
            json!({ "type": "urn:ietf:params:acme:error:badNonce", "detail": "try again" }),
        ));
    }
    assert!(
        state.nonces.remove(&nonce),
        "a nonce was used twice or made up"
    );
    let (key, kid) = match protected.get("kid").and_then(Value::as_str) {
        Some(kid) => (
            state.accounts.get(kid).expect("known account").clone(),
            Some(kid.to_owned()),
        ),
        None => match keys::parse_jwk(&protected["jwk"]).unwrap() {
            ParsedKey::Public(key) => (key, None),
            ParsedKey::Private(_) => panic!("a private key must never be sent"),
        },
    };
    let algorithm = SignatureAlgorithm::parse(protected["alg"].as_str().unwrap()).unwrap();
    let signature = b64_decode(jws["signature"].as_str().unwrap()).unwrap();
    assert!(
        key.verify(
            algorithm,
            format!("{protected_text}.{payload_text}").as_bytes(),
            &signature
        )
        .unwrap(),
        "bad signature on {path}"
    );
    let empty = payload_text.is_empty();
    let payload = if empty {
        Value::Null
    } else {
        serde_json::from_slice(&b64_decode(payload_text).unwrap()).unwrap()
    };
    Ok(Parsed {
        payload,
        empty,
        key,
        kid,
    })
}

fn handle(
    state: &Arc<Mutex<State>>,
    ca: &x509_ca::Ca,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut guard = state.lock().unwrap();
    let state = &mut *guard;
    let base = state.base.clone();
    state.log.push(format!("{method} {path}"));
    if method == "GET" && path == "/directory" {
        return response(
            200,
            &[],
            &json!({
                "newNonce": format!("{base}/nonce"),
                "newAccount": format!("{base}/account"),
                "newOrder": format!("{base}/order"),
            })
            .to_string(),
        );
    }
    if method == "HEAD" {
        let nonce = fresh_nonce(state);
        return response(200, &[("Replay-Nonce", nonce)], "");
    }
    let parsed = match check_jws(state, path, body) {
        Ok(parsed) => parsed,
        Err((status, problem)) => {
            let nonce = fresh_nonce(state);
            return response(status, &[("Replay-Nonce", nonce)], &problem.to_string());
        }
    };
    let nonce = fresh_nonce(state);
    let reply = |status: u16, value: Value, location: Option<String>, nonce: String| {
        let mut headers = vec![("Replay-Nonce", nonce)];
        if let Some(location) = location {
            headers.push(("Location", location));
        }
        response(status, &headers, &value.to_string())
    };
    match path {
        "/account" => {
            assert_eq!(parsed.payload["termsOfServiceAgreed"], true);
            if state.require_eab {
                let binding = &parsed.payload["externalAccountBinding"];
                assert!(binding.is_object(), "EAB missing");
                let protected: Value = serde_json::from_slice(
                    &b64_decode(binding["protected"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                assert_eq!(protected["alg"], "HS256");
                assert_eq!(protected["kid"], "eab-kid");
                state.eab_seen = true;
            }
            let url = format!("{base}/acct/1");
            state.accounts.insert(url.clone(), parsed.key);
            reply(201, json!({ "status": "valid" }), Some(url), nonce)
        }
        "/order" => {
            assert!(
                parsed.kid.is_some(),
                "orders are signed with the account's kid"
            );
            state.identifiers = parsed.payload["identifiers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| id["value"].as_str().unwrap().to_owned())
                .collect();
            reply(
                201,
                json!({
                    "status": "pending",
                    "authorizations": [format!("{base}/authz/0")],
                    "finalize": format!("{base}/finalize"),
                }),
                Some(format!("{base}/order/1")),
                nonce,
            )
        }
        "/authz/0" => {
            assert!(parsed.empty, "polling is POST-as-GET");
            let domain = state.identifiers[0].trim_start_matches("*.").to_owned();
            reply(
                200,
                json!({
                    "status": if state.validated { "valid" } else { "pending" },
                    "identifier": { "type": "dns", "value": domain },
                    "wildcard": state.identifiers[0].starts_with("*."),
                    "challenges": [
                        { "type": "http-01", "url": format!("{base}/challenge"), "token": TOKEN },
                        { "type": "dns-01", "url": format!("{base}/challenge"), "token": TOKEN },
                    ],
                }),
                None,
                nonce,
            )
        }
        "/challenge" => {
            let thumbprint = state.accounts.values().next().unwrap().jwk_thumbprint();
            let expected = format!("{TOKEN}.{thumbprint}");
            if state.challenge_kind == "http-01" {
                let mut stream = TcpStream::connect(("127.0.0.1", state.http_port)).unwrap();
                write!(
                    stream,
                    "GET /.well-known/acme-challenge/{TOKEN} HTTP/1.1\r\nHost: a\r\n\r\n"
                )
                .unwrap();
                let mut answer = String::new();
                stream.read_to_string(&mut answer).unwrap();
                assert!(
                    answer.ends_with(&expected),
                    "wrong HTTP-01 answer: {answer}"
                );
            } else {
                let name = core_acme::dns01_name(&state.identifiers[0]);
                let records = state.dns_records.lock().unwrap();
                assert_eq!(records.get(&name), Some(&core_acme::dns01_value(&expected)));
            }
            state.validated = true;
            reply(200, json!({ "status": "valid" }), None, nonce)
        }
        "/finalize" => {
            let csr = x509::parse_csr(parsed.payload["csr"].as_str().unwrap()).unwrap();
            let info = x509::inspect_csr(&csr).unwrap();
            assert!(info.signature_valid);
            assert_eq!(info.sans, state.identifiers);
            state.certificate = Some(ca.sign(&csr));
            reply(200, json!({ "status": "processing" }), None, nonce)
        }
        "/order/1" => reply(
            200,
            json!({ "status": "valid", "certificate": format!("{base}/cert") }),
            None,
            nonce,
        ),
        "/cert" => {
            assert!(parsed.empty, "downloading is POST-as-GET");
            response(
                200,
                &[("Replay-Nonce", nonce)],
                state.certificate.as_deref().unwrap(),
            )
        }
        other => panic!("unexpected {other}"),
    }
}

mod x509_ca {
    use super::*;
    use der::Encode;

    pub struct Ca {
        key: keys::PrivateKey,
        certificate: x509_cert::Certificate,
    }

    impl Ca {
        pub fn new() -> Self {
            let key = keys::generate(KeyKind::P256, &mut OsRng).unwrap();
            let certificate = x509::create_ca(
                &x509::CaOptions {
                    unconstrained: true,
                    ..Default::default()
                },
                &key,
                now(),
                &mut OsRng,
            )
            .unwrap();
            Self { key, certificate }
        }

        pub fn sign(&self, csr: &x509_cert::request::CertReq) -> String {
            let leaf = x509::sign_csr(
                csr,
                &[],
                Some(90),
                &self.certificate,
                &self.key,
                now(),
                &mut OsRng,
            )
            .unwrap();
            format!(
                "{}{}",
                x509::der_to_pem(&leaf.to_der().unwrap()).unwrap(),
                x509::certificate_pem(&self.certificate).unwrap()
            )
        }
    }

    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

/// Starts the CA and returns its directory URL and state.
fn start_ca(challenge: &str, http_port: u16, require_eab: bool) -> (String, Arc<Mutex<State>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let state = Arc::new(Mutex::new(State {
        base: base.clone(),
        challenge_kind: challenge.to_owned(),
        http_port,
        require_eab,
        ..State::default()
    }));
    let served = state.clone();
    std::thread::spawn(move || {
        let ca = x509_ca::Ca::new();
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let Some((method, path, body)) = read_request(&mut stream) else {
                continue;
            };
            let answer = handle(&served, &ca, &method, &path, &body);
            let _ = stream.write_all(&answer);
        }
    });
    (format!("{base}/directory"), state)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn request(directory: String, domains: &[&str]) -> Request {
    Request {
        directory,
        domains: domains.iter().map(|domain| (*domain).to_owned()).collect(),
        email: Some("ada@example.test".into()),
        account_key: None,
        certificate_key: KeyKind::P256,
        external_account: None,
        agreed_to_terms: true,
    }
}

fn check_issued(issued: &octapass_net_tools::acme::Issued, name: &str) {
    let chain = x509::parse_certificates(&issued.certificate_chain).unwrap();
    assert_eq!(chain.len(), 2);
    let report = x509::read_chain(&chain, Some(name), x509_ca::now()).unwrap();
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    let ParsedKey::Private(key) = keys::parse(&issued.private_key, None).unwrap() else {
        panic!("no private key");
    };
    x509::check_key_matches(&chain[0], &key).unwrap();
    // RFC 8555 §11.1: the account key isn't the certificate key.
    let ParsedKey::Private(account) = keys::parse(&issued.account_key, None).unwrap() else {
        panic!("no account key");
    };
    assert_ne!(account.public(), key.public());
}

#[test]
fn http_01_end_to_end() {
    let port = free_port();
    let (directory, state) = start_ca("http-01", port, false);
    let mut steps = Vec::new();
    let issued = issue(
        request(directory, &["a.example.test"]),
        Challenge::Http01Standalone { port },
        |step| steps.push(step.to_owned()),
    )
    .unwrap();
    check_issued(&issued, "a.example.test");
    assert!(state.lock().unwrap().validated);
    assert!(steps.iter().any(|step| step.contains("Asking the CA")));
    // The challenge server is gone: nothing keeps listening after issuing.
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
}

#[test]
fn webroot_writes_the_answer_and_removes_it() {
    let dir = tempfile::tempdir().unwrap();
    // A web server for the fake CA to fetch from.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = dir.path().to_owned();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let Some((_, path, _)) = read_request(&mut stream) else {
                continue;
            };
            let file = root.join(path.trim_start_matches('/'));
            let body = std::fs::read_to_string(file).unwrap_or_default();
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}");
        }
    });
    let (directory, _state) = start_ca("http-01", port, false);
    let issued = issue(
        request(directory, &["b.example.test"]),
        Challenge::Http01Webroot {
            dir: dir.path().to_owned(),
        },
        |_| {},
    )
    .unwrap();
    check_issued(&issued, "b.example.test");
    assert!(
        !dir.path()
            .join(format!(".well-known/acme-challenge/{TOKEN}"))
            .exists()
    );
}

struct FakeDns(Arc<Mutex<HashMap<String, String>>>, Arc<Mutex<Vec<String>>>);

impl DnsProvider for FakeDns {
    fn publish(&self, name: &str, value: &str) -> Result<String> {
        self.0
            .lock()
            .unwrap()
            .insert(name.to_owned(), value.to_owned());
        Ok("handle".to_owned())
    }

    fn remove(&self, name: &str, _value: &str, handle: &str) -> Result<()> {
        assert_eq!(handle, "handle");
        self.0.lock().unwrap().remove(name);
        self.1.lock().unwrap().push(name.to_owned());
        Ok(())
    }
}

#[test]
fn dns_01_wildcard_end_to_end() {
    let (directory, state) = start_ca("dns-01", 0, false);
    let records = state.lock().unwrap().dns_records.clone();
    let removed = Arc::new(Mutex::new(Vec::new()));
    let issued = issue(
        request(directory, &["*.example.test"]),
        Challenge::Dns01 {
            provider: Box::new(FakeDns(records.clone(), removed.clone())),
            propagation: Duration::ZERO,
        },
        |_| {},
    )
    .unwrap();
    check_issued(&issued, "www.example.test");
    assert!(
        records.lock().unwrap().is_empty(),
        "the record is cleaned up"
    );
    assert_eq!(*removed.lock().unwrap(), ["_acme-challenge.example.test"]);
}

#[test]
fn external_account_binding_is_sent() {
    let port = free_port();
    let (directory, state) = start_ca("http-01", port, true);
    let mut ask = request(directory, &["c.example.test"]);
    ask.external_account = Some(ExternalAccount {
        kid: "eab-kid".into(),
        hmac_key: Zeroizing::new(b64_encode(b"a key from the CA's website")),
    });
    issue(ask, Challenge::Http01Standalone { port }, |_| {}).unwrap();
    assert!(state.lock().unwrap().eab_seen);
}

#[test]
fn renewing_reuses_the_account_key() {
    let port = free_port();
    let (directory, _) = start_ca("http-01", port, false);
    let first = issue(
        request(directory.clone(), &["d.example.test"]),
        Challenge::Http01Standalone { port },
        |_| {},
    )
    .unwrap();
    let mut again = request(directory, &["d.example.test"]);
    again.account_key = Some(first.account_key.clone());
    let second = issue(again, Challenge::Http01Standalone { port }, |_| {}).unwrap();
    assert_eq!(first.account_key.as_str(), second.account_key.as_str());
    assert_ne!(first.private_key.as_str(), second.private_key.as_str());
}

#[test]
fn a_ca_that_wont_answer_is_an_error_not_a_hang() {
    let port = free_port();
    let error = issue(
        request(format!("http://127.0.0.1:{port}/directory"), &["a.test"]),
        Challenge::Http01Standalone { port: 0 },
        |_| {},
    )
    .err()
    .unwrap();
    assert!(matches!(error, NetError::Network(_)), "{error}");
}
