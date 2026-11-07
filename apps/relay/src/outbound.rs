//! Everything the relay sends goes through the operator's smart host. The call returns only after
//! the smart host has answered, so the SMTP reply to the sender can tell the truth.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use lettre::address::Envelope;
use lettre::transport::smtp::extension::ClientId;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The sender should try again: 451.
    Temporary,
    /// It will never work: 550.
    Permanent,
}

pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SendError>> + Send + 'a>>;

pub trait Outbound: Send + Sync {
    /// Sends `raw`. `from` is the return path, `None` for `<>`.
    fn send<'a>(&'a self, from: Option<&'a str>, to: &'a str, raw: &'a [u8]) -> SendFuture<'a>;
}

/// lettre always ends DATA with `CRLF . CRLF`, so a message that already ends in CRLF would arrive
/// with an extra empty line. Taking that one CRLF off here makes the far side receive the message
/// byte for byte as it was signed.
pub fn wire_form(raw: &[u8]) -> &[u8] {
    raw.strip_suffix(b"\r\n").unwrap_or(raw)
}

pub struct SmartHost {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmartHost {
    pub fn new(url: &str, hostname: &str) -> Result<Self, String> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
            .map_err(|e| format!("OCTAPASS_RELAY_SMART_HOST: {e}"))?
            .hello_name(ClientId::Domain(hostname.to_owned()))
            .timeout(Some(Duration::from_secs(60)))
            .build();
        Ok(Self { transport })
    }
}

impl Outbound for SmartHost {
    fn send<'a>(&'a self, from: Option<&'a str>, to: &'a str, raw: &'a [u8]) -> SendFuture<'a> {
        Box::pin(async move {
            let parse = |text: &str| text.parse::<Address>().map_err(|_| SendError::Permanent);
            let envelope = Envelope::new(from.map(parse).transpose()?, vec![parse(to)?])
                .map_err(|_| SendError::Permanent)?;
            match self.transport.send_raw(&envelope, wire_form(raw)).await {
                Ok(_) => Ok(()),
                Err(error) if error.is_permanent() => Err(SendError::Permanent),
                // A connection failure is ours to fix, not the sender's fault: let it retry.
                Err(error) => {
                    tracing::warn!(
                        transient = error.is_transient(),
                        timeout = error.is_timeout(),
                        "the smart host didn't take a message"
                    );
                    Err(SendError::Temporary)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_terminator_is_not_doubled() {
        assert_eq!(wire_form(b"a\r\nb\r\n"), b"a\r\nb");
        assert_eq!(wire_form(b"a\r\nb\r\n\r\n"), b"a\r\nb\r\n");
        assert_eq!(wire_form(b"a\r\nb"), b"a\r\nb");
        assert_eq!(wire_form(b""), b"");
    }
}
