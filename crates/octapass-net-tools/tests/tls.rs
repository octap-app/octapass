//! Reading a live certificate from a real TLS server on loopback.

use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;

use der::Encode;
use octapass_core::tools::toolkit::keys::{self, KeyKind};
use octapass_core::tools::toolkit::x509;
use octapass_net_tools::tls;
use rand_core::OsRng;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn server(chain: Vec<Vec<u8>>, key: Vec<u8>) -> u16 {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            chain.into_iter().map(CertificateDer::from).collect(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut connection = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::Stream::new(&mut connection, &mut stream);
            // Serving means reading: the handshake runs inside this, and the probe sends no data.
            let mut received = Vec::new();
            let _ = tls.read_to_end(&mut received);
            assert!(
                received.is_empty(),
                "the probe must send nothing after the handshake"
            );
        }
    });
    port
}

#[test]
fn reads_a_private_servers_chain_and_says_it_isnt_publicly_trusted() {
    let ca_key = keys::generate(KeyKind::P256, &mut OsRng).unwrap();
    let ca = x509::create_ca(&x509::CaOptions::default(), &ca_key, now(), &mut OsRng).unwrap();
    let key = keys::generate(KeyKind::P256, &mut OsRng).unwrap();
    let leaf = x509::issue(
        &x509::LeafOptions {
            subject: x509::Subject::default(),
            sans: vec!["localhost".into()],
            days: None,
            client_auth: false,
        },
        &key.public(),
        &ca,
        &ca_key,
        now(),
        &mut OsRng,
    )
    .unwrap();
    let chain = vec![leaf.to_der().unwrap(), ca.to_der().unwrap()];
    let port = server(chain.clone(), key.to_pkcs8_der().unwrap().to_vec());

    let probe = tls::probe("localhost", port).unwrap();
    assert_eq!(probe.chain, chain);
    assert!(!probe.trusted);
    assert!(probe.trust_error.is_some());
    assert!(probe.protocol.contains('1'));
    let report = x509::read_chain(
        &x509::parse_certificates(&probe.pem).unwrap(),
        Some("localhost"),
        now(),
    )
    .unwrap();
    assert!(report.problems.is_empty(), "{:?}", report.problems);
}

#[test]
fn a_closed_port_is_an_error() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert!(tls::probe("127.0.0.1", port).is_err());
}
