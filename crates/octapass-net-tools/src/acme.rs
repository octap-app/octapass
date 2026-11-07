//! An ACME client (RFC 8555): Let's Encrypt, ZeroSSL and any other CA, with HTTP-01 and DNS-01.
//!
//! Keys are made on this device by the core. The CA sees the account's public key, a CSR and
//! signatures, and for DNS-01 the DNS host sees the challenge answer, which is public anyway.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use octapass_core::tools::toolkit::acme::{self, Signer};
use octapass_core::tools::toolkit::keys::{self, KeyKind, ParsedKey, PrivateKey};
use rand_core::OsRng;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::dns::DnsProvider;
use crate::fetch::agent;
use crate::{NetError, Result, check_url};

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const ZEROSSL: &str = "https://acme.zerossl.com/v2/DV90";

const CONTENT_TYPE: &str = "application/jose+json";
const MAX_RESPONSE: u64 = 1 << 20;
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const POLL_LIMIT: Duration = Duration::from_secs(180);

/// How to prove control of a name.
pub enum Challenge {
    /// Serves the answer itself on this port; the CA connects to port 80, so anything else needs a
    /// redirect or port mapping in front.
    Http01Standalone { port: u16 },
    /// Writes the answer in `<dir>/.well-known/acme-challenge/` for a web server already running.
    Http01Webroot { dir: PathBuf },
    Dns01 {
        provider: Box<dyn DnsProvider>,
        /// How long to wait for the record to reach the CA.
        propagation: Duration,
    },
}

/// External account binding: ZeroSSL and some private CAs ask for it.
pub struct ExternalAccount {
    pub kid: String,
    /// Base64url.
    pub hmac_key: Zeroizing<String>,
}

pub struct Request {
    pub directory: String,
    pub domains: Vec<String>,
    /// For the CA's expiry notices.
    pub email: Option<String>,
    /// PKCS#8 PEM, or a new key is made.
    pub account_key: Option<Zeroizing<String>>,
    pub certificate_key: KeyKind,
    pub external_account: Option<ExternalAccount>,
    /// The user accepted the CA's terms. Without it, nothing is sent.
    pub agreed_to_terms: bool,
}

/// What to keep. Renewing uses the same account key.
pub struct Issued {
    /// The leaf and the chain, as the CA sent them.
    pub certificate_chain: String,
    pub private_key: Zeroizing<String>,
    pub account_key: Zeroizing<String>,
    pub account_url: String,
}

struct Client {
    http: ureq::Agent,
    nonce_url: String,
    nonce: Option<String>,
    key: PrivateKey,
    account: Option<String>,
}

/// The parts of a response this client reads.
struct Answer {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body)
            .map_err(|_| NetError::Core(octapass_core::Error::InvalidAcme))
    }

    fn check(self) -> Result<Self> {
        if (200..300).contains(&self.status) {
            return Ok(self);
        }
        Err(NetError::Acme(problem_text(&self.body, self.status)))
    }
}

/// An RFC 7807 problem as one line.
fn problem_text(body: &[u8], status: u16) -> String {
    match serde_json::from_slice::<Value>(body) {
        Ok(problem) => problem["detail"]
            .as_str()
            .or_else(|| problem["type"].as_str())
            .map_or_else(|| format!("error {status}"), str::to_owned),
        Err(_) => format!("error {status}"),
    }
}

impl Client {
    fn new_nonce(&mut self) -> Result<String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }
        let response = self
            .http
            .head(&self.nonce_url)
            .call()
            .map_err(|error| NetError::Network(format!("Can't reach the CA: {error}")))?;
        header(&response, "replay-nonce").ok_or(NetError::Core(octapass_core::Error::InvalidAcme))
    }

    /// One signed POST. A `badNonce` is retried, as RFC 8555 §6.5 expects.
    fn post(&mut self, url: &str, payload: Option<&Value>) -> Result<Answer> {
        for attempt in 0..3 {
            let nonce = self.new_nonce()?;
            let signer = match &self.account {
                Some(kid) => Signer::Kid(kid),
                None => Signer::Jwk,
            };
            let body = acme::signed_request(&self.key, signer, &nonce, url, payload, &mut OsRng)?;
            let mut response = self
                .http
                .post(url)
                .header("Content-Type", CONTENT_TYPE)
                .send(body.to_string().as_bytes())
                .map_err(|error| NetError::Network(format!("Can't reach the CA: {error}")))?;
            self.nonce = header(&response, "replay-nonce");
            let answer = Answer {
                status: response.status().as_u16(),
                location: header(&response, "location"),
                body: response
                    .body_mut()
                    .with_config()
                    .limit(MAX_RESPONSE)
                    .read_to_vec()
                    .map_err(|error| NetError::Network(error.to_string()))?,
            };
            let bad_nonce = answer.status == 400
                && serde_json::from_slice::<Value>(&answer.body)
                    .is_ok_and(|problem| problem["type"] == "urn:ietf:params:acme:error:badNonce");
            if bad_nonce && attempt < 2 {
                continue;
            }
            return Ok(answer);
        }
        unreachable!("the last attempt returns")
    }

    fn post_json(&mut self, url: &str, payload: Option<&Value>) -> Result<(Value, Option<String>)> {
        let answer = self.post(url, payload)?.check()?;
        let location = answer.location.clone();
        Ok((answer.json()?, location))
    }
}

fn header(response: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn read_key(pem: &str) -> Result<PrivateKey> {
    match keys::parse(pem, None)? {
        ParsedKey::Private(key) => Ok(key),
        ParsedKey::Public(_) => Err(octapass_core::Error::PrivateKeyRequired.into()),
    }
}

fn wait_until<T>(what: &str, mut check: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    let started = Instant::now();
    loop {
        if let Some(value) = check()? {
            return Ok(value);
        }
        if started.elapsed() > POLL_LIMIT {
            return Err(NetError::Network(format!("Timed out waiting for {what}.")));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Serves `/.well-known/acme-challenge/<token>` answers until dropped.
struct ChallengeServer {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ChallengeServer {
    fn start(port: u16, answers: HashMap<String, String>) -> Result<Self> {
        let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|error| {
            NetError::System(format!(
                "Can't listen on port {port}: {error}. Port 80 usually needs admin rights: use --webroot, or --http-port behind a redirect."
            ))
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|error| NetError::System(error.to_string()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let mut buffer = [0u8; 2048];
                        let read = stream.read(&mut buffer).unwrap_or(0);
                        let response = answer_request(&buffer[..read], &answers);
                        let _ = stream.write_all(response.as_bytes());
                    }
                    Err(_) => thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for ChallengeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Only exact challenge paths are answered; everything else is a 404.
fn answer_request(request: &[u8], answers: &HashMap<String, String>) -> String {
    let line = request
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let text = String::from_utf8_lossy(line);
    let mut parts = text.split_whitespace();
    let (method, path) = (parts.next(), parts.next());
    let answer = path
        .and_then(|path| path.strip_prefix("/.well-known/acme-challenge/"))
        .filter(|_| method == Some("GET"))
        .and_then(|token| answers.get(token));
    match answer {
        Some(body) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
        None => {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
        }
    }
}

/// What has to be undone once the CA has looked.
enum Cleanup {
    File(PathBuf),
    Record {
        name: String,
        value: String,
        handle: String,
    },
}

/// One name's challenge and its answer.
struct Pending {
    authorization: String,
    challenge: String,
    token: String,
    key_authorization: String,
    domain: String,
    wildcard: bool,
}

fn run_cleanup(cleanups: Vec<Cleanup>, challenge: &Challenge) {
    for cleanup in cleanups {
        match (cleanup, challenge) {
            (Cleanup::File(path), _) => {
                let _ = std::fs::remove_file(path);
            }
            (
                Cleanup::Record {
                    name,
                    value,
                    handle,
                },
                Challenge::Dns01 { provider, .. },
            ) => {
                let _ = provider.remove(&name, &value, &handle);
            }
            _ => {}
        }
    }
}

/// Obtains a certificate. `progress` hears each step, for the person watching.
pub fn issue(
    request: Request,
    challenge: Challenge,
    mut progress: impl FnMut(&str),
) -> Result<Issued> {
    check_url(&request.directory)?;
    if request.domains.is_empty() {
        return Err(NetError::Usage("Name at least one domain.".to_owned()));
    }
    if !request.agreed_to_terms {
        return Err(NetError::Usage(
            "The CA's terms of service must be accepted first.".to_owned(),
        ));
    }
    let wants_wildcard = request
        .domains
        .iter()
        .any(|domain| domain.starts_with("*."));
    if wants_wildcard && !matches!(challenge, Challenge::Dns01 { .. }) {
        return Err(NetError::Usage("Wildcard names need DNS-01.".to_owned()));
    }
    let http = agent();
    let directory: Value = {
        let mut response = http
            .get(&request.directory)
            .call()
            .map_err(|error| NetError::Network(format!("Can't reach the CA: {error}")))?;
        response
            .body_mut()
            .read_json()
            .map_err(|_| NetError::Network("That address isn't an ACME directory.".to_owned()))?
    };
    let url = |name: &str| -> Result<String> {
        directory[name]
            .as_str()
            .map(str::to_owned)
            .ok_or(NetError::Core(octapass_core::Error::InvalidAcme))
    };
    let account_key = match &request.account_key {
        Some(pem) => Zeroizing::new(pem.as_str().to_owned()),
        None => keys::generate(KeyKind::P256, &mut OsRng)?.to_pkcs8_pem()?,
    };
    let key = read_key(&account_key)?;
    let mut client = Client {
        http,
        nonce_url: url("newNonce")?,
        nonce: None,
        key,
        account: None,
    };

    progress("Registering the account key");
    let new_account = url("newAccount")?;
    let mut account = json!({ "termsOfServiceAgreed": true });
    if let Some(email) = &request.email {
        account["contact"] = json!([format!("mailto:{email}")]);
    }
    if let Some(external) = &request.external_account {
        account["externalAccountBinding"] = acme::external_account_binding(
            &client.key,
            &external.kid,
            &external.hmac_key,
            &new_account,
        )?;
    }
    let (_, location) = client.post_json(&new_account, Some(&account))?;
    let account_url = location.ok_or(NetError::Core(octapass_core::Error::InvalidAcme))?;
    client.account = Some(account_url.clone());

    progress("Placing the order");
    let identifiers: Vec<Value> = request
        .domains
        .iter()
        .map(|domain| json!({ "type": "dns", "value": domain }))
        .collect();
    let (order, order_url) = client.post_json(
        &url("newOrder")?,
        Some(&json!({ "identifiers": identifiers })),
    )?;
    let order_url = order_url.ok_or(NetError::Core(octapass_core::Error::InvalidAcme))?;

    let kind = match challenge {
        Challenge::Dns01 { .. } => "dns-01",
        _ => "http-01",
    };
    let mut pending = Vec::new();
    for authorization in order["authorizations"].as_array().into_iter().flatten() {
        let authorization = authorization
            .as_str()
            .ok_or(NetError::Core(octapass_core::Error::InvalidAcme))?
            .to_owned();
        let (details, _) = client.post_json(&authorization, None)?;
        if details["status"] == "valid" {
            continue;
        }
        let found = details["challenges"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|entry| entry["type"] == kind)
            .ok_or_else(|| NetError::Acme(format!("no {kind} challenge offered")))?;
        let token = found["token"].as_str().unwrap_or_default().to_owned();
        pending.push(Pending {
            key_authorization: acme::key_authorization(&client.key, &token)?,
            challenge: found["url"].as_str().unwrap_or_default().to_owned(),
            token,
            domain: details["identifier"]["value"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            wildcard: details["wildcard"].as_bool().unwrap_or(false),
            authorization,
        });
    }

    // Publish every answer first: the CA starts checking as soon as it's told to.
    let mut cleanups = Vec::new();
    let mut server = None;
    let outcome = (|| -> Result<()> {
        match &challenge {
            Challenge::Http01Standalone { port } => {
                let answers = pending
                    .iter()
                    .map(|entry| (entry.token.clone(), entry.key_authorization.clone()))
                    .collect();
                progress("Serving the HTTP-01 answers");
                server = Some(ChallengeServer::start(*port, answers)?);
            }
            Challenge::Http01Webroot { dir } => {
                let folder = dir.join(".well-known/acme-challenge");
                std::fs::create_dir_all(&folder).map_err(|error| {
                    NetError::System(format!("Can't write to {}: {error}", folder.display()))
                })?;
                for entry in &pending {
                    // `key_authorization` already checked the token holds no path characters.
                    let path = folder.join(&entry.token);
                    std::fs::write(&path, &entry.key_authorization).map_err(|error| {
                        NetError::System(format!("Can't write {}: {error}", path.display()))
                    })?;
                    cleanups.push(Cleanup::File(path));
                }
            }
            Challenge::Dns01 {
                provider,
                propagation,
            } => {
                for entry in &pending {
                    let domain = if entry.wildcard {
                        format!("*.{}", entry.domain)
                    } else {
                        entry.domain.clone()
                    };
                    let name = acme::dns01_name(&domain);
                    let value = acme::dns01_value(&entry.key_authorization);
                    progress(&format!("Publishing {name}"));
                    let handle = provider.publish(&name, &value)?;
                    cleanups.push(Cleanup::Record {
                        name,
                        value,
                        handle,
                    });
                }
                if !pending.is_empty() && !propagation.is_zero() {
                    progress("Waiting for DNS");
                    thread::sleep(*propagation);
                }
            }
        }
        for entry in &pending {
            progress(&format!("Asking the CA to check {}", entry.domain));
            client.post_json(&entry.challenge, Some(&json!({})))?;
        }
        for entry in &pending {
            let url = entry.authorization.clone();
            wait_until("the CA to check your domain", || {
                let (details, _) = client.post_json(&url, None)?;
                match details["status"].as_str() {
                    Some("valid") => Ok(Some(())),
                    Some("invalid") => {
                        let reason = details["challenges"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find_map(|entry| entry["error"]["detail"].as_str())
                            .unwrap_or("the challenge failed");
                        Err(NetError::Acme(reason.to_owned()))
                    }
                    _ => Ok(None),
                }
            })?;
        }
        Ok(())
    })();
    drop(server);
    run_cleanup(cleanups, &challenge);
    outcome?;

    progress("Finishing the order");
    let certificate_key = keys::generate(request.certificate_key, &mut OsRng)?;
    let csr = acme::finalize_csr(&request.domains, &certificate_key, &mut OsRng)?;
    let finalize = order["finalize"]
        .as_str()
        .ok_or(NetError::Core(octapass_core::Error::InvalidAcme))?
        .to_owned();
    client.post_json(&finalize, Some(&json!({ "csr": csr })))?;
    let finished = wait_until("the CA to issue the certificate", || {
        let (order, _) = client.post_json(&order_url, None)?;
        match order["status"].as_str() {
            Some("valid") => Ok(Some(order)),
            Some("invalid") => Err(NetError::Acme(problem_text(
                order["error"].to_string().as_bytes(),
                400,
            ))),
            _ => Ok(None),
        }
    })?;
    let certificate_url = finished["certificate"]
        .as_str()
        .ok_or(NetError::Core(octapass_core::Error::InvalidAcme))?
        .to_owned();
    let answer = client.post(&certificate_url, None)?.check()?;
    let certificate_chain = String::from_utf8(answer.body)
        .map_err(|_| NetError::Core(octapass_core::Error::InvalidAcme))?;
    Ok(Issued {
        certificate_chain,
        private_key: certificate_key.to_pkcs8_pem()?,
        account_key,
        account_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_server_only_answers_known_tokens() {
        let answers = HashMap::from([("token".to_owned(), "token.thumb".to_owned())]);
        let ok = answer_request(
            b"GET /.well-known/acme-challenge/token HTTP/1.1\r\n\r\n",
            &answers,
        );
        assert!(ok.starts_with("HTTP/1.1 200"));
        assert!(ok.ends_with("token.thumb"));
        for request in [
            "GET /.well-known/acme-challenge/other HTTP/1.1\r\n",
            "POST /.well-known/acme-challenge/token HTTP/1.1\r\n",
            "GET /etc/passwd HTTP/1.1\r\n",
            "",
        ] {
            assert!(
                answer_request(request.as_bytes(), &answers).starts_with("HTTP/1.1 404"),
                "{request}"
            );
        }
    }

    #[test]
    fn terms_must_be_accepted_before_anything_is_sent() {
        let request = Request {
            directory: "https://ca.invalid/directory".into(),
            domains: vec!["a.test".into()],
            email: None,
            account_key: None,
            certificate_key: KeyKind::P256,
            external_account: None,
            agreed_to_terms: false,
        };
        let error = issue(request, Challenge::Http01Standalone { port: 0 }, |_| {})
            .err()
            .unwrap();
        assert!(error.to_string().contains("terms of service"));
    }

    #[test]
    fn wildcards_need_dns() {
        let request = Request {
            directory: "https://ca.invalid/directory".into(),
            domains: vec!["*.a.test".into()],
            email: None,
            account_key: None,
            certificate_key: KeyKind::P256,
            external_account: None,
            agreed_to_terms: true,
        };
        let error = issue(request, Challenge::Http01Standalone { port: 0 }, |_| {})
            .err()
            .unwrap();
        assert!(error.to_string().contains("DNS-01"));
    }

    #[test]
    fn plain_http_is_only_for_this_machine() {
        assert!(check_url("https://ca.example/dir").is_ok());
        assert!(check_url("http://localhost:14000/dir").is_ok());
        assert!(check_url("http://127.0.0.1:14000/dir").is_ok());
        assert!(check_url("http://[::1]:14000/dir").is_ok());
        assert!(check_url("http://ca.example/dir").is_err());
        assert!(check_url("http://localhost.evil.example/dir").is_err());
        assert!(check_url("ftp://ca.example/dir").is_err());
    }
}
