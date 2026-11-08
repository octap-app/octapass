//! What happens to a message: deciding at RCPT whether a recipient exists for this sender, and at
//! the end of DATA doing the one thing that recipient means. Every path answers with a [`Reply`],
//! and 250 is only ever returned after the smart host has taken the message.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mail_auth::AuthenticatedMessage;
use mail_auth::arc::ArcSealer;
use mail_auth::crypto::{RsaKey, Sha256};
use mail_auth::dkim::DkimSigner;
use mail_auth::headers::HeaderWriter;
use mail_auth::signer::Ready;
use mail_parser::MessageParser;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;

use crate::address::{self, Address, Local};
use crate::auth::{Peer, Verifier};
use crate::config::Config;
use crate::db::{Alias, Counter, Db, Paused, Report, Store};
use crate::dsn::{self, Feedback};
use crate::keys::{Keys, base32_lower, random_bytes};
use crate::limits::Limiter;
use crate::notice::{Notice, Pause};
use crate::outbound::{Outbound, SendError};
use crate::rewrite::{self, LOOP_HEADER};
use crate::smtp::command::ReversePath;
use crate::srs::{self, Kind, ReturnPath};

/// An SMTP answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub status: &'static str,
    pub text: &'static str,
}

impl Reply {
    const fn new(code: u16, status: &'static str, text: &'static str) -> Self {
        Self { code, status, text }
    }

    pub fn line(&self) -> String {
        format!("{} {} {}\r\n", self.code, self.status, self.text)
    }

    pub fn is_positive(&self) -> bool {
        self.code < 400
    }
}

pub const OK: Reply = Reply::new(250, "2.0.0", "OK");
/// The same words for unknown, disabled, paused and blocked: nobody learns which it was, or that
/// an address behind it exists.
pub const NO_SUCH_RECIPIENT: Reply = Reply::new(550, "5.1.1", "Recipient address rejected");
pub const NOT_RELAYING: Reply = Reply::new(550, "5.7.1", "Relaying denied");
pub const TRY_LATER: Reply = Reply::new(451, "4.7.1", "Try again later");
pub const UNAVAILABLE: Reply = Reply::new(451, "4.3.0", "Temporary failure, try again later");
pub const REFUSED: Reply = Reply::new(550, "5.7.1", "Message refused");
pub const DMARC_REFUSED: Reply = Reply::new(550, "5.7.1", "Refused by the sender's DMARC policy");
pub const NOT_DELIVERED: Reply = Reply::new(550, "5.0.0", "Message could not be delivered");
pub const LOOP: Reply = Reply::new(550, "5.4.6", "Mail loop detected");
pub const MALFORMED: Reply = Reply::new(550, "5.6.0", "Message headers are malformed");

/// Where one recipient leads. Decided at RCPT, carried out at the end of DATA.
#[derive(Clone, Debug)]
pub enum Route {
    /// An alias: the message goes to its account's mailbox.
    Forward(Alias),
    /// A reverse alias: the owner's message goes out to the contact.
    Reply { alias: Alias, contact: String },
    /// A signed return path: a bounce or complaint to count.
    Feedback(ReturnPath, Alias),
    /// `postmaster@` or `abuse@`.
    Operator(Address),
}

pub struct Limiters {
    per_alias: Limiter,
    per_sender: Limiter,
    per_account: Limiter,
    replies: Limiter,
}

type Key = RsaKey<Sha256>;

pub struct Relay {
    pub config: Config,
    pub db: Db,
    pub keys: Keys,
    pub verifier: Verifier,
    pub outbound: Arc<dyn Outbound>,
    limiters: Limiters,
    dkim: DkimSigner<Key, Ready>,
    arc: ArcSealer<Key, Ready>,
}

/// What DKIM and ARC sign. `From` twice stops a second one being added on the way.
const SIGNED_HEADERS: [&str; 11] = [
    "From",
    "From",
    "Reply-To",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
    "MIME-Version",
    "Content-Type",
];

fn signing_key(pem: &str) -> Result<Key, String> {
    let der = PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| format!("the DKIM key isn't a PEM private key: {e}"))?;
    RsaKey::<Sha256>::from_key_der(der).map_err(|e| format!("the DKIM key: {e}"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after 1970")
        .as_secs()
}

fn message_date() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc2822)
        .expect("the current time formats")
}

fn random_id() -> String {
    base32_lower(&random_bytes::<16>(), 26)
}

impl Relay {
    pub fn new(
        config: Config,
        db: Db,
        verifier: Verifier,
        outbound: Arc<dyn Outbound>,
    ) -> Result<Self, String> {
        let limits = &config.limits;
        let limiters = Limiters {
            per_alias: Limiter::new(limits.messages_per_alias),
            per_sender: Limiter::new(limits.messages_per_sender),
            per_account: Limiter::new(limits.messages_per_account),
            replies: Limiter::new(limits.replies_per_account),
        };
        let dkim = DkimSigner::from_key(signing_key(&config.dkim_key_pem)?)
            .domain(config.domain.clone())
            .selector(config.dkim_selector.clone())
            .headers(SIGNED_HEADERS);
        let arc = ArcSealer::from_key(signing_key(&config.dkim_key_pem)?)
            .domain(config.domain.clone())
            .selector(config.dkim_selector.clone())
            .headers(SIGNED_HEADERS);
        Ok(Self {
            keys: Keys::derive(&config.secret),
            config,
            db,
            verifier,
            outbound,
            limiters,
            dkim,
            arc,
        })
    }

    pub fn store(&self) -> Store<'_> {
        Store {
            db: &self.db,
            keys: &self.keys,
        }
    }

    fn return_path(&self, kind: Kind, alias: &str) -> String {
        let local = srs::encode(&self.keys, kind, alias, now_secs());
        format!("{local}@{}", self.config.domain)
    }

    fn at_domain(&self, local: &str) -> String {
        format!("{local}@{}", self.config.domain)
    }

    /// Decides a `RCPT TO`. The first check is the one that makes this not an open relay: only
    /// addresses on the relay's own domain, in the shapes it issues, go any further.
    pub async fn route(&self, sender: &ReversePath, recipient: &Address) -> Result<Route, Reply> {
        if recipient.domain != self.config.domain {
            return Err(NOT_RELAYING);
        }
        let failed = |error: sqlx::Error| {
            tracing::error!(%error, "database error while routing");
            UNAVAILABLE
        };
        let store = self.store();
        match address::classify(&recipient.local) {
            Local::Unknown => Err(NO_SUCH_RECIPIENT),
            Local::Operator => self
                .config
                .operator
                .clone()
                .map(Route::Operator)
                .ok_or(NO_SUCH_RECIPIENT),
            Local::Srs => {
                let path = srs::decode(
                    &self.keys,
                    &recipient.local,
                    now_secs(),
                    self.config.limits.return_path_days,
                )
                .ok_or(NO_SUCH_RECIPIENT)?;
                let alias = store
                    .alias(&path.alias)
                    .await
                    .map_err(failed)?
                    .ok_or(NO_SUCH_RECIPIENT)?;
                Ok(Route::Feedback(path, alias))
            }
            Local::Alias => {
                // Mail with no return path can't get a reverse alias, and a real delivery
                // failure comes to the signed return path instead.
                let ReversePath::Address(from) = sender else {
                    return Err(NO_SUCH_RECIPIENT);
                };
                let alias = store
                    .alias(&recipient.local)
                    .await
                    .map_err(failed)?
                    .ok_or(NO_SUCH_RECIPIENT)?;
                if !alias.forwards() {
                    return Err(NO_SUCH_RECIPIENT);
                }
                let from = from.to_string();
                if store
                    .is_blocked(&alias.local, &from)
                    .await
                    .map_err(failed)?
                {
                    store
                        .count(&alias.local, Counter::Blocked)
                        .await
                        .map_err(failed)?;
                    return Err(NO_SUCH_RECIPIENT);
                }
                let sender_key = self.keys.lookup("rate", &from);
                let limiters = &self.limiters;
                if !limiters.per_alias.take(&alias.local)
                    || !limiters.per_sender.take(&sender_key)
                    || !limiters.per_account.take(&alias.account_id)
                {
                    return Err(TRY_LATER);
                }
                Ok(Route::Forward(alias))
            }
            Local::Reverse => {
                let ReversePath::Address(from) = sender else {
                    return Err(NO_SUCH_RECIPIENT);
                };
                let (alias_local, contact) = store
                    .reverse(&recipient.local)
                    .await
                    .map_err(failed)?
                    .ok_or(NO_SUCH_RECIPIENT)?;
                let alias = store
                    .alias(&alias_local)
                    .await
                    .map_err(failed)?
                    .ok_or(NO_SUCH_RECIPIENT)?;
                let owner = store
                    .sender_is_destination(&alias.account_id, &from.to_string())
                    .await
                    .map_err(failed)?;
                if !owner || !alias.forwards() {
                    return Err(NO_SUCH_RECIPIENT);
                }
                if !self.limiters.replies.take(&alias.account_id) {
                    return Err(TRY_LATER);
                }
                Ok(Route::Reply { alias, contact })
            }
        }
    }

    /// Carries out a route with the received message.
    pub async fn deliver(
        &self,
        route: Route,
        raw: &[u8],
        ip: IpAddr,
        helo: &str,
        mail_from: &ReversePath,
    ) -> Reply {
        let peer = Peer {
            ip,
            helo,
            mail_from,
        };
        let result = match route {
            Route::Forward(alias) => self.forward(&alias, raw, &peer).await,
            Route::Reply { alias, contact } => self.reply(&alias, &contact, raw, &peer).await,
            Route::Feedback(path, alias) => self.feedback(&path, &alias, raw).await,
            Route::Operator(to) => self.to_operator(&to, raw).await,
        };
        result.unwrap_or_else(|error| {
            tracing::error!(%error, "database error while delivering");
            UNAVAILABLE
        })
    }

    /// Loop checks shared by both directions. `Received` counts every hop, and the marker catches
    /// a mailbox that forwards a message straight back.
    fn check_loop(&self, fields: &[rewrite::Field<'_>]) -> Result<(), Reply> {
        if rewrite::count_field(fields, "received") > self.config.limits.max_hops {
            return Err(LOOP);
        }
        let ours = fields
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case(LOOP_HEADER.as_bytes()))
            .any(|field| field.value().eq_ignore_ascii_case(&self.config.domain));
        if ours { Err(LOOP) } else { Ok(()) }
    }

    /// The single address in the From header. More than one is refused: DMARC exempts such
    /// messages, so allowing them would be a way around the policy check.
    fn sender(&self, parsed: &mail_parser::Message<'_>) -> Option<(Address, Option<String>)> {
        let mut all = parsed.all_from();
        let from = all.next()?;
        if all.next().is_some() {
            return None;
        }
        let mut mailboxes = from.mailboxes();
        let first = mailboxes.next()?;
        if mailboxes.next().is_some() {
            return None;
        }
        let address = Address::parse(first.address()?).ok()?;
        Some((address, first.name().map(str::to_owned)))
    }

    async fn forward(
        &self,
        alias: &Alias,
        raw: &[u8],
        peer: &Peer<'_>,
    ) -> Result<Reply, sqlx::Error> {
        let Ok((fields, body)) = rewrite::split(raw) else {
            return Ok(MALFORMED);
        };
        if let Err(reply) = self.check_loop(&fields) {
            return Ok(reply);
        }
        let Some(message) = AuthenticatedMessage::parse(raw) else {
            return Ok(MALFORMED);
        };
        let Some(parsed) = MessageParser::default().parse_headers(raw) else {
            return Ok(MALFORMED);
        };
        let Some((sender, name)) = self.sender(&parsed) else {
            return Ok(REFUSED);
        };
        let store = self.store();
        let sender_text = sender.to_string();
        if store.is_blocked(&alias.local, &sender_text).await? {
            store.count(&alias.local, Counter::Blocked).await?;
            return Ok(NO_SUCH_RECIPIENT);
        }
        let checked = self.verifier.check(&message, peer).await;
        if checked.dmarc_rejects() {
            store.count(&alias.local, Counter::Blocked).await?;
            return Ok(DMARC_REFUSED);
        }
        let Some(destination) = store.destination(&alias.account_id).await? else {
            return Ok(UNAVAILABLE);
        };
        let Some(reverse) = store
            .contact(
                &alias.local,
                &sender_text,
                self.config.limits.contacts_per_alias,
            )
            .await?
        else {
            return Ok(REFUSED);
        };
        let hostname = &self.config.hostname;
        let results = checked.results(hostname, &sender_text, peer.ip).to_header();
        let rewritten = rewrite::forward(
            &fields,
            body,
            &rewrite::Forward {
                alias: &self.at_domain(&alias.local),
                reverse: &self.at_domain(&reverse),
                sender: &sender_text,
                sender_name: name.as_deref(),
                domain: &self.config.domain,
                results: &results,
            },
        );
        let signed = match self.seal_and_sign(&rewritten, &checked, peer.ip, &sender_text) {
            Ok(signed) => signed,
            Err(error) => {
                tracing::error!(%error, "signing failed");
                return Ok(UNAVAILABLE);
            }
        };
        let return_path = self.return_path(Kind::Forward, &alias.local);
        let sent = self
            .outbound
            .send(Some(&return_path), &destination, &signed)
            .await;
        if sent.is_ok() {
            store.count(&alias.local, Counter::Forwarded).await?;
        }
        Ok(answer(sent))
    }

    /// ARC seal around the DKIM signature, both over the rewritten message.
    fn seal_and_sign(
        &self,
        message: &[u8],
        checked: &crate::auth::Checked<'_>,
        ip: IpAddr,
        sender: &str,
    ) -> Result<Vec<u8>, String> {
        let dkim = self
            .dkim
            .sign(message)
            .map_err(|e| e.to_string())?
            .to_header();
        let mut out = Vec::with_capacity(message.len() + 2048);
        if checked.arc.can_be_sealed() {
            let parsed = AuthenticatedMessage::parse(message).ok_or("rewritten message")?;
            let results = checked.results(&self.config.hostname, sender, ip);
            let set = self
                .arc
                .seal(&parsed, &results, &checked.arc)
                .map_err(|e| e.to_string())?;
            out.extend_from_slice(set.to_header().as_bytes());
        }
        out.extend_from_slice(dkim.as_bytes());
        out.extend_from_slice(message);
        Ok(out)
    }

    async fn reply(
        &self,
        alias: &Alias,
        contact: &str,
        raw: &[u8],
        peer: &Peer<'_>,
    ) -> Result<Reply, sqlx::Error> {
        let Ok((fields, body)) = rewrite::split(raw) else {
            return Ok(MALFORMED);
        };
        if let Err(reply) = self.check_loop(&fields) {
            return Ok(reply);
        }
        // Out-of-office replies and the like would tell a stranger about the mailbox.
        let automatic = rewrite::first_value(&fields, "auto-submitted")
            .is_some_and(|value| !value.eq_ignore_ascii_case("no"));
        let bulk = rewrite::first_value(&fields, "precedence").is_some_and(|value| {
            ["bulk", "junk", "list", "auto_reply"]
                .iter()
                .any(|p| value.eq_ignore_ascii_case(p))
        });
        if automatic || bulk {
            return Ok(REFUSED);
        }
        let Some(message) = AuthenticatedMessage::parse(raw) else {
            return Ok(MALFORMED);
        };
        let Some(parsed) = MessageParser::default().parse_headers(raw) else {
            return Ok(MALFORMED);
        };
        let Some((from, _)) = self.sender(&parsed) else {
            return Ok(REFUSED);
        };
        let store = self.store();
        // The envelope was checked at RCPT; the header must name the same mailbox, and SPF or
        // DKIM must prove it. Anyone can type someone else's address into MAIL FROM.
        if !store
            .sender_is_destination(&alias.account_id, &from.to_string())
            .await?
        {
            return Ok(REFUSED);
        }
        let checked = self.verifier.check(&message, peer).await;
        if !checked.aligned_with(&from.domain) {
            return Ok(REFUSED);
        }
        let rewritten = rewrite::reply(
            &fields,
            body,
            &rewrite::Reply {
                alias: &self.at_domain(&alias.local),
                to: contact,
                domain: &self.config.domain,
                message_id: &random_id(),
                date: &message_date(),
            },
        );
        let Ok(signature) = self.dkim.sign(&rewritten) else {
            return Ok(UNAVAILABLE);
        };
        let mut signed = signature.to_header().into_bytes();
        signed.extend_from_slice(&rewritten);
        let return_path = self.return_path(Kind::Reply, &alias.local);
        let sent = self
            .outbound
            .send(Some(&return_path), contact, &signed)
            .await;
        if sent.is_ok() {
            store.count(&alias.local, Counter::Replied).await?;
        }
        Ok(answer(sent))
    }

    /// Bounces and complaints end here. Accepted and counted, never passed on: a bounce from the
    /// user's mailbox names their real address, so forwarding it would undo the alias. Accepting
    /// it is also why no bounce of our own (backscatter) ever comes of it.
    async fn feedback(
        &self,
        path: &ReturnPath,
        alias: &Alias,
        raw: &[u8],
    ) -> Result<Reply, sqlx::Error> {
        let report = match (dsn::classify(raw), path.kind) {
            (Feedback::Complaint, _) => Some(Report::Complaint),
            // A reply that bounced says the stranger's address is bad, not the user's.
            (Feedback::HardBounce | Feedback::SoftBounce, Kind::Reply) | (Feedback::Other, _) => {
                None
            }
            (Feedback::HardBounce, Kind::Forward) => Some(Report::Hard),
            (Feedback::SoftBounce, Kind::Forward) => Some(Report::Soft),
        };
        if let Some(report) = report {
            let limits = &self.config.limits;
            let paused = self.store().report(alias, report, limits).await?;
            self.notify(alias, paused).await?;
        }
        Ok(OK)
    }

    async fn notify(&self, alias: &Alias, paused: Paused) -> Result<(), sqlx::Error> {
        let pause = match paused {
            Paused { account: true, .. } => Pause::Account,
            Paused { alias: true, .. } => Pause::Alias,
            _ => return Ok(()),
        };
        tracing::info!(?pause, "forwarding paused");
        let Some(to) = self.store().destination(&alias.account_id).await? else {
            return Ok(());
        };
        let notice = Notice {
            to: to.clone(),
            alias: self.at_domain(&alias.local),
            pause,
            date: message_date(),
            message_id: random_id(),
        }
        .render(&self.config.domain);
        let Ok(signature) = self.dkim.sign(&notice) else {
            return Ok(());
        };
        let mut signed = signature.to_header().into_bytes();
        signed.extend_from_slice(&notice);
        if self.outbound.send(None, &to, &signed).await.is_err() {
            // Sent once, whatever happened: this mailbox is already failing.
            tracing::warn!("a pause notice couldn't be sent");
        }
        Ok(())
    }

    /// Abuse reports naming a signed return path count like ones sent to it. The message goes to
    /// the operator as it came, with a null return path, so a failure there bounces to nobody.
    async fn to_operator(&self, to: &Address, raw: &[u8]) -> Result<Reply, sqlx::Error> {
        if dsn::classify(raw) == Feedback::Complaint
            && let Some(local) = dsn::reported_return_path(raw, &self.config.domain)
            && let Some(path) = srs::decode(
                &self.keys,
                &local,
                now_secs(),
                self.config.limits.return_path_days,
            )
            && let Some(alias) = self.store().alias(&path.alias).await?
        {
            let limits = &self.config.limits;
            let paused = self
                .store()
                .report(&alias, Report::Complaint, limits)
                .await?;
            self.notify(&alias, paused).await?;
        }
        Ok(answer(self.outbound.send(None, &to.to_string(), raw).await))
    }
}

fn answer(sent: Result<(), SendError>) -> Reply {
    match sent {
        Ok(()) => OK,
        Err(SendError::Temporary) => UNAVAILABLE,
        Err(SendError::Permanent) => NOT_DELIVERED,
    }
}

/// The internal API's bearer token, in constant time.
pub fn token_matches(given: &str, expected: &str) -> bool {
    given.as_bytes().ct_eq(expected.as_bytes()).into()
}
