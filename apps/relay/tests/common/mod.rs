//! A relay on real sockets with a fake smart host, and an SMTP client that says exactly what each
//! test tells it to.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mail_auth::dkim::DomainKey;
use mail_auth::dmarc::DmarcRecord;
use mail_auth::dns::TxtRecordParser;
use mail_auth::spf::SpfRecord;
use octapass_relay::auth::FixedDns;
use octapass_relay::config::Limits;
use octapass_relay::db::Alias;
use octapass_relay::{Config, Running};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

pub const DOMAIN: &str = "relay.example";
pub const ACCOUNT: &str = "account-1";
/// The user's real mailbox.
pub const USER: &str = "real.person@mail.example";
/// Someone who writes to an alias. Its domain passes SPF from this machine.
pub const SENDER: &str = "jane@sender.example";

pub const RELAY_DKIM_KEY: &str = include_str!("../fixtures/dkim.pem");
pub const SENDER_DKIM_KEY: &str = include_str!("../fixtures/sender-dkim.pem");
const RELAY_DKIM_PUB: &str = include_str!("../fixtures/dkim.pub");
const SENDER_DKIM_PUB: &str = include_str!("../fixtures/sender-dkim.pub");

#[derive(Clone, Debug)]
pub struct Sent {
    pub from: String,
    pub to: String,
    pub data: Vec<u8>,
}

impl Sent {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostMode {
    Accept,
    TemporaryFailure,
    PermanentFailure,
}

/// An SMTP server that keeps what it's given.
pub struct SmartHost {
    pub url: String,
    pub sent: Arc<Mutex<Vec<Sent>>>,
    pub mode: Arc<Mutex<HostMode>>,
}

impl SmartHost {
    async fn start() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mode = Arc::new(Mutex::new(HostMode::Accept));
        let (kept, chosen) = (sent.clone(), mode.clone());
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(smart_host_session(stream, kept.clone(), chosen.clone()));
            }
        });
        Self {
            url: format!("smtp://127.0.0.1:{port}"),
            sent,
            mode,
        }
    }
}

async fn smart_host_session(
    stream: TcpStream,
    sent: Arc<Mutex<Vec<Sent>>>,
    mode: Arc<Mutex<HostMode>>,
) {
    let mut stream = BufReader::new(stream);
    stream
        .get_mut()
        .write_all(b"220 smart ESMTP\r\n")
        .await
        .unwrap();
    let (mut from, mut to) = (String::new(), String::new());
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
            return;
        }
        let upper = line.to_ascii_uppercase();
        let reply: &[u8] = if upper.starts_with("EHLO") {
            b"250-smart\r\n250 8BITMIME\r\n"
        } else if upper.starts_with("MAIL FROM:") {
            from = between(&line);
            b"250 OK\r\n"
        } else if upper.starts_with("RCPT TO:") {
            to = between(&line);
            b"250 OK\r\n"
        } else if upper.starts_with("DATA") {
            stream.get_mut().write_all(b"354 go\r\n").await.unwrap();
            let mut data = Vec::new();
            loop {
                let mut piece = Vec::new();
                stream.read_until(b'\n', &mut piece).await.unwrap();
                if piece == b".\r\n" {
                    break;
                }
                data.extend_from_slice(piece.strip_prefix(b".").unwrap_or(&piece));
            }
            let chosen = *mode.lock().unwrap();
            match chosen {
                HostMode::Accept => {
                    sent.lock().unwrap().push(Sent {
                        from: from.clone(),
                        to: to.clone(),
                        data,
                    });
                    b"250 OK\r\n"
                }
                HostMode::TemporaryFailure => b"451 4.3.0 later\r\n",
                HostMode::PermanentFailure => b"550 5.7.1 no\r\n",
            }
        } else if upper.starts_with("QUIT") {
            stream.get_mut().write_all(b"221 bye\r\n").await.unwrap();
            return;
        } else {
            b"250 OK\r\n"
        };
        stream.get_mut().write_all(reply).await.unwrap();
    }
}

fn between(line: &str) -> String {
    let start = line.find('<').unwrap();
    let end = line.find('>').unwrap();
    line[start + 1..end].to_owned()
}

fn fixed_dns() -> FixedDns {
    let spf = |record: &str| SpfRecord::parse(record.as_bytes()).unwrap();
    let dmarc = |record: &str| DmarcRecord::parse(record.as_bytes()).unwrap();
    let key =
        |public: &str| DomainKey::parse(format!("v=DKIM1; k=rsa; p={public}").as_bytes()).unwrap();
    FixedDns::default()
        // Senders with SPF for this machine.
        .with_txt("sender.example", spf("v=spf1 ip4:127.0.0.1 -all"))
        .with_txt("mail.example", spf("v=spf1 ip4:127.0.0.1 -all"))
        .with_txt("_dmarc.sender.example", dmarc("v=DMARC1; p=reject"))
        // A domain that says nothing here may send for it, and to reject what fails.
        .with_txt("strict.example", spf("v=spf1 -all"))
        .with_txt("_dmarc.strict.example", dmarc("v=DMARC1; p=reject"))
        // The same, but only asking to be watched.
        .with_txt("relaxed.example", spf("v=spf1 -all"))
        .with_txt("_dmarc.relaxed.example", dmarc("v=DMARC1; p=none"))
        // A mailbox provider that signs with DKIM and has no SPF for this machine.
        .with_txt("dkim.example", spf("v=spf1 -all"))
        .with_txt("key._domainkey.dkim.example", key(SENDER_DKIM_PUB))
        // The relay's own key, to verify what it signs.
        .with_txt("relay2026._domainkey.relay.example", key(RELAY_DKIM_PUB))
}

pub fn config(url: &str, database: &str, limits: Limits) -> Config {
    Config {
        domain: DOMAIN.into(),
        hostname: "mx.relay.example".into(),
        smtp_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        api_bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        api_token: Zeroizing::new("a-test-api-token-that-is-long-enough".into()),
        secret: Zeroizing::new(vec![9; 32]),
        database_url: database.into(),
        smart_host: url.into(),
        dkim_selector: "relay2026".into(),
        dkim_key_pem: Zeroizing::new(RELAY_DKIM_KEY.into()),
        tls: None,
        operator: None,
        limits,
        dns: Some(Arc::new(fixed_dns())),
    }
}

pub struct Harness {
    pub running: Running,
    pub host: SmartHost,
    pub dir: tempfile::TempDir,
}

/// Generous limits, so only the test about a limit meets one.
pub fn open_limits() -> Limits {
    use octapass_relay::limits::Bucket;
    let wide = Bucket {
        burst: 10_000,
        refill: Duration::from_millis(1),
    };
    Limits {
        connections_per_ip: wide,
        messages_per_alias: wide,
        messages_per_sender: wide,
        messages_per_account: wide,
        replies_per_account: wide,
        ..Limits::default()
    }
}

impl Harness {
    pub async fn start() -> Self {
        Self::with(|_| {}).await
    }

    pub async fn with(change: impl FnOnce(&mut Config)) -> Self {
        let host = SmartHost::start().await;
        let dir = tempfile::tempdir().unwrap();
        let database = format!("sqlite:{}", dir.path().join("relay.db").display());
        let mut config = config(&host.url, &database, open_limits());
        change(&mut config);
        let running = octapass_relay::start(config).await.unwrap();
        Self { running, host, dir }
    }

    pub async fn alias(&self) -> Alias {
        let store = self.running.relay.store();
        store.sync_account(ACCOUNT, USER).await.unwrap();
        store
            .create_alias(ACCOUNT, &self.running.relay.config.limits)
            .await
            .unwrap()
    }

    pub async fn client(&self) -> Client<TcpStream> {
        let stream = TcpStream::connect(self.running.smtp).await.unwrap();
        let mut client = Client::new(stream);
        assert_eq!(client.reply().await.code, 220);
        client.ok("EHLO mx.sender.example").await;
        client
    }

    pub fn sent(&self) -> Vec<Sent> {
        self.host.sent.lock().unwrap().clone()
    }

    pub fn set_host(&self, mode: HostMode) {
        *self.host.mode.lock().unwrap() = mode;
    }

    /// One whole message; the reply to the end of DATA.
    pub async fn send(&self, from: &str, to: &str, message: &str) -> Answer {
        let mut client = self.client().await;
        client.ok(&format!("MAIL FROM:<{from}>")).await;
        let answer = client.command(&format!("RCPT TO:<{to}>")).await;
        if answer.code != 250 {
            return answer;
        }
        client.data(message).await
    }

    /// Mails an alias, and returns the reverse alias the relay made for the sender.
    pub async fn first_contact(&self, alias: &Alias, sender: &str) -> String {
        let to = at(&alias.local);
        let answer = self.send(sender, &to, &plain(sender, &to, "Hello")).await;
        assert_eq!(answer.code, 250, "{answer:?}");
        let store = self.running.relay.store();
        let reverse = store
            .contact(&alias.local, sender, 10)
            .await
            .unwrap()
            .unwrap();
        at(&reverse)
    }
}

pub fn at(local: &str) -> String {
    format!("{local}@{DOMAIN}")
}

pub fn plain(from: &str, to: &str, subject: &str) -> String {
    format!(
        "From: Someone <{from}>\r\nTo: {to}\r\nSubject: {subject}\r\n\
         Date: Mon, 2 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@x.example>\r\n\r\nHello there\r\n"
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub code: u16,
    pub text: String,
}

pub struct Client<S> {
    pub reader: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    pub fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
        }
    }

    pub async fn reply(&mut self) -> Answer {
        let mut text = String::new();
        loop {
            let mut line = String::new();
            let read =
                tokio::time::timeout(Duration::from_secs(20), self.reader.read_line(&mut line))
                    .await
                    .expect("the relay answered in time")
                    .unwrap();
            if read == 0 {
                return Answer {
                    code: 0,
                    text: "closed".into(),
                };
            }
            text.push_str(line.get(4..).unwrap_or(""));
            if line.as_bytes().get(3) != Some(&b'-') {
                return Answer {
                    code: line[..3].parse().unwrap(),
                    text: text.trim().to_owned(),
                };
            }
        }
    }

    pub async fn raw(&mut self, bytes: &[u8]) {
        self.reader.get_mut().write_all(bytes).await.unwrap();
    }

    pub async fn command(&mut self, line: &str) -> Answer {
        self.raw(format!("{line}\r\n").as_bytes()).await;
        self.reply().await
    }

    pub async fn ok(&mut self, line: &str) {
        let answer = self.command(line).await;
        assert_eq!(answer.code, 250, "{line}: {answer:?}");
    }

    /// DATA with dot-stuffing, as a proper client does it.
    pub async fn data(&mut self, message: &str) -> Answer {
        let go = self.command("DATA").await;
        assert_eq!(go.code, 354, "{go:?}");
        let mut body = String::new();
        for line in message.split_inclusive("\r\n") {
            if line.starts_with('.') {
                body.push('.');
            }
            body.push_str(line);
        }
        self.raw(body.as_bytes()).await;
        self.raw(b".\r\n").await;
        self.reply().await
    }

    pub async fn closed(&mut self) -> bool {
        let mut buffer = [0u8; 16];
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.reader.read(&mut buffer)).await,
            Ok(Ok(0) | Err(_))
        )
    }
}

/// A delivery status report for a return path.
pub fn dsn(action: &str, status: &str) -> String {
    format!(
        "From: MAILER-DAEMON@mail.example\r\n\
         Subject: Undelivered Mail Returned to Sender\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status; boundary=\"b\"\r\n\
         \r\n\
         --b\r\n\
         Content-Type: text/plain\r\n\
         \r\n\
         Delivery to {USER} failed.\r\n\
         --b\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         Reporting-MTA: dns; mail.example\r\n\
         \r\n\
         Final-Recipient: rfc822; {USER}\r\n\
         Action: {action}\r\n\
         Status: {status}\r\n\
         \r\n\
         --b--\r\n"
    )
}

pub fn abuse_report(return_path: &str) -> String {
    format!(
        "From: fbl@mail.example\r\n\
         Subject: Abuse report\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=feedback-report; boundary=\"b\"\r\n\
         \r\n\
         --b\r\n\
         Content-Type: text/plain\r\n\
         \r\n\
         This is an abuse report.\r\n\
         --b\r\n\
         Content-Type: message/feedback-report\r\n\
         \r\n\
         Feedback-Type: abuse\r\n\
         User-Agent: Test/1.0\r\n\
         Version: 1\r\n\
         Original-Mail-From: <{return_path}>\r\n\
         \r\n\
         --b--\r\n"
    )
}
