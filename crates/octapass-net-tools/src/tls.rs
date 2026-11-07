//! Reads a server's certificate chain with a TLS handshake. Only the handshake happens: no request
//! is sent, and the connection is closed right after.

use std::io::{ErrorKind, Read};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::DigitallySignedStruct;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::Serialize;

use crate::{NetError, Result};

const TIMEOUT: Duration = Duration::from_secs(10);

/// What the handshake gave.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    pub host: String,
    pub port: u16,
    /// Each certificate as the server sent it, DER, the leaf first.
    #[serde(skip)]
    pub chain: Vec<Vec<u8>>,
    /// PEM of the chain, for the certificate reader.
    pub pem: String,
    /// `TLSv1_3`, `TLSv1_2`.
    pub protocol: String,
    pub cipher_suite: String,
    /// Whether the Mozilla root program trusts this chain for this name. A server on a private CA
    /// fails this; the reader still shows what it sent.
    pub trusted: bool,
    /// Why not, when not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_error: Option<String>,
}

/// Accepts every certificate, so a broken server can still be looked at. Only the probe uses it, and
/// nothing is ever sent over the resulting connection.
#[derive(Debug)]
struct Anything(Arc<CryptoProvider>);

impl ServerCertVerifier for Anything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// `example.com`, `example.com:8443`, `https://example.com/x`, `[::1]:443`: the host and port.
pub fn parse_target(target: &str) -> Result<(String, u16)> {
    let invalid = || NetError::Usage(format!("“{target}” isn't a host name."));
    let text = target.trim();
    let text = text.split_once("://").map_or(text, |(_, rest)| rest);
    let text = text.split(['/', '?', '#']).next().unwrap_or_default();
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(invalid)?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().map_err(|_| invalid())?,
            None => 443,
        };
        return Ok((host.to_owned(), port));
    }
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().map_err(|_| invalid())?),
        None => (text, 443),
    };
    if host.is_empty() || host.contains(':') {
        return Err(invalid());
    }
    Ok((host.to_owned(), port))
}

/// Connects to `host:port` and completes a TLS handshake.
pub fn probe(host: &str, port: u16) -> Result<Probe> {
    let provider = Arc::new(ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| NetError::Network(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Anything(provider.clone())))
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned())
        .map_err(|_| NetError::Usage(format!("“{host}” isn't a host name.")))?;
    let mut connection = rustls::ClientConnection::new(Arc::new(config), name.clone())
        .map_err(|error| NetError::Network(error.to_string()))?;

    // Every address in turn: a name can have an IPv6 address that doesn't answer.
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|error| NetError::Network(format!("Can't find {host}: {error}")))?
        .collect();
    let mut last_error = None;
    let mut connected = None;
    for address in &addresses {
        match TcpStream::connect_timeout(address, TIMEOUT) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let mut socket = connected.ok_or_else(|| match last_error {
        Some(error) => NetError::Network(format!("Can't reach {host}:{port}: {error}")),
        None => NetError::Network(format!("Can't find {host}.")),
    })?;
    socket
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| socket.set_write_timeout(Some(TIMEOUT)))
        .map_err(|error| NetError::Network(error.to_string()))?;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket).map_err(|error| {
            NetError::Network(match error.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                    format!("{host}:{port} didn't answer the TLS handshake.")
                }
                _ => format!("TLS with {host}:{port} failed: {error}"),
            })
        })?;
    }
    let chain: Vec<CertificateDer<'static>> = connection
        .peer_certificates()
        .map(<[CertificateDer<'static>]>::to_vec)
        .unwrap_or_default();
    if chain.is_empty() {
        return Err(NetError::Network(format!(
            "{host}:{port} sent no certificate."
        )));
    }
    let protocol = connection
        .protocol_version()
        .map(|version| format!("{version:?}"))
        .unwrap_or_default();
    let cipher_suite = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_default();
    // Nothing to read: this only tells the server we're done.
    connection.send_close_notify();
    let _ = connection.write_tls(&mut socket);
    let _ = socket.read(&mut [0u8; 1]);

    let trust_error = check_trust(&chain, &name, provider).err();
    let der: Vec<Vec<u8>> = chain
        .iter()
        .map(|certificate| certificate.to_vec())
        .collect();
    let pem = der
        .iter()
        .map(|certificate| octapass_core::tools::toolkit::x509::der_to_pem(certificate))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .concat();
    Ok(Probe {
        host: host.to_owned(),
        port,
        chain: der,
        pem,
        protocol,
        cipher_suite,
        trusted: trust_error.is_none(),
        trust_error,
    })
}

fn check_trust(
    chain: &[CertificateDer<'static>],
    name: &ServerName<'_>,
    provider: Arc<CryptoProvider>,
) -> std::result::Result<(), String> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|error| error.to_string())?;
    verifier
        .verify_server_cert(&chain[0], &chain[1..], name, &[], UnixTime::now())
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let parsed = |text| parse_target(text).unwrap();
        assert_eq!(parsed("example.com"), ("example.com".into(), 443));
        assert_eq!(parsed("example.com:8443"), ("example.com".into(), 8443));
        assert_eq!(
            parsed("https://example.com/path?q"),
            ("example.com".into(), 443)
        );
        assert_eq!(parsed("[::1]:9443"), ("::1".into(), 9443));
        assert_eq!(parsed("[::1]"), ("::1".into(), 443));
        assert!(parse_target("").is_err());
        assert!(parse_target("example.com:port").is_err());
    }
}
