//! Starting the relay: the database, the SMTP listener and the internal API.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;

use crate::auth::Verifier;
use crate::config::Config;
use crate::limits::{Limiter, ip_key};
use crate::outbound::{Outbound, SmartHost};
use crate::pipeline::Relay;
use crate::smtp::{self, Outcome};
use crate::{api, db};

pub struct Running {
    pub smtp: SocketAddr,
    pub api: SocketAddr,
    pub relay: Arc<Relay>,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    /// Waits until a listener stops, which only happens on failure.
    pub async fn wait(mut self) {
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn tls_acceptor(config: &Config) -> Result<Option<TlsAcceptor>, String> {
    let Some((chain, key)) = &config.tls else {
        return Ok(None);
    };
    let chain = CertificateDer::pem_slice_iter(chain)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("the TLS certificate: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| format!("the TLS key: {e}"))?;
    let server = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("the TLS certificate and key: {e}"))?;
    Ok(Some(TlsAcceptor::from(Arc::new(server))))
}

async fn connection(stream: TcpStream, relay: Arc<Relay>, ip: IpAddr, tls: Option<TlsAcceptor>) {
    match smtp::session(stream, relay.clone(), ip, tls.is_some(), true).await {
        Outcome::Closed => {}
        Outcome::StartTls(stream) => {
            let Some(acceptor) = tls else { return };
            let handshake = relay.config.limits.command_timeout;
            if let Ok(Ok(stream)) = tokio::time::timeout(handshake, acceptor.accept(stream)).await {
                smtp::session(stream, relay, ip, false, false).await;
            }
        }
    }
}

async fn refuse(mut stream: TcpStream, reply: &'static [u8]) {
    let _ = stream.write_all(reply).await;
}

async fn accept_loop(listener: TcpListener, relay: Arc<Relay>, tls: Option<TlsAcceptor>) {
    let limits = &relay.config.limits;
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let per_ip = Limiter::new(limits.connections_per_ip);
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        if !per_ip.take(&ip_key(peer.ip())) {
            tokio::spawn(refuse(
                stream,
                b"421 4.7.0 Too many connections, try later\r\n",
            ));
            continue;
        }
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            tokio::spawn(refuse(stream, b"421 4.3.2 Busy, try later\r\n"));
            continue;
        };
        let (relay, tls) = (relay.clone(), tls.clone());
        tokio::spawn(async move {
            connection(stream, relay, peer.ip(), tls).await;
            drop(slot);
        });
    }
}

/// Starts everything on the configured addresses.
pub async fn start(config: Config) -> Result<Running, String> {
    let outbound: Arc<dyn Outbound> =
        Arc::new(SmartHost::new(&config.smart_host, &config.hostname)?);
    start_with(config, outbound).await
}

/// `start` with another way out, for tests.
pub async fn start_with(config: Config, outbound: Arc<dyn Outbound>) -> Result<Running, String> {
    let tls = tls_acceptor(&config)?;
    if tls.is_none() {
        tracing::warn!("no TLS certificate: inbound mail will arrive in plaintext");
    }
    if !config.api_bind.ip().is_loopback() {
        tracing::warn!(
            "the internal API isn't on loopback; make sure only the vault server reaches it"
        );
    }
    let db = db::connect(&config.database_url)
        .await
        .map_err(|e| format!("the relay database: {e}"))?;
    let verifier = Verifier::new(&config.hostname, config.dns.clone())?;
    let (smtp_bind, api_bind) = (config.smtp_bind, config.api_bind);
    let relay = Arc::new(Relay::new(config, db, verifier, outbound)?);

    let smtp_listener = TcpListener::bind(smtp_bind)
        .await
        .map_err(|e| format!("listening for SMTP on {smtp_bind}: {e}"))?;
    let api_listener = TcpListener::bind(api_bind)
        .await
        .map_err(|e| format!("listening for the API on {api_bind}: {e}"))?;
    let (smtp, api) = (
        smtp_listener.local_addr().map_err(|e| e.to_string())?,
        api_listener.local_addr().map_err(|e| e.to_string())?,
    );
    let tasks = vec![
        tokio::spawn(accept_loop(smtp_listener, relay.clone(), tls)),
        tokio::spawn({
            let router = api::router(relay.clone());
            async move {
                if let Err(error) = axum::serve(api_listener, router).await {
                    tracing::error!(%error, "the internal API stopped");
                }
            }
        }),
    ];
    Ok(Running {
        smtp,
        api,
        relay,
        tasks,
    })
}
