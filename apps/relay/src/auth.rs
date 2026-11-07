//! Checking who a message is from: SPF, DKIM, DMARC and ARC, all by `mail-auth`.
//!
//! DNS answers come from the system resolver. The verifiers take a cache, which tests fill with
//! fixed records; in production it's empty and every lookup goes to the resolver, so one code path
//! runs in both.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;

use mail_auth::dmarc::Policy;
use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput,
    DmarcResult, DnsCache, DnsError, Error, MessageAuthenticator, Parameters, ResolverCache,
    SpfOutput, SpfResult, TxtRecord,
};

use crate::smtp::command::ReversePath;

/// Fixed answers. A name that isn't listed has no record, rather than going to the network.
#[derive(Clone, Default)]
pub struct FixedTxt(HashMap<Box<str>, TxtRecord>);

impl ResolverCache<Box<str>, TxtRecord> for FixedTxt {
    fn get<Q>(&self, name: &Q) -> Option<TxtRecord>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        Some(
            self.0
                .get(name)
                .cloned()
                .unwrap_or_else(|| TxtRecord::Error(Error::Dns(DnsError::InvalidRecordType))),
        )
    }

    fn remove<Q>(&self, _: &Q) -> Option<TxtRecord>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        None
    }

    fn insert(&self, _: Box<str>, _: TxtRecord, _: std::time::Instant) {}
}

#[derive(Clone, Default)]
pub struct FixedDns {
    txt: FixedTxt,
}

impl FixedDns {
    /// Adds the TXT record at `name` (without a trailing dot).
    pub fn with_txt(mut self, name: &str, record: impl Into<TxtRecord>) -> Self {
        self.txt.0.insert(
            format!("{}.", name.to_ascii_lowercase()).into(),
            record.into(),
        );
        self
    }
}

/// The relay's DNS "cache": the fixed answers in tests, nothing in production.
pub struct Dns(Option<Arc<FixedDns>>);

impl DnsCache for Dns {
    type Txt = FixedTxt;
    type Mx = mail_auth::NoCache;
    type Ipv4 = mail_auth::NoCache;
    type Ipv6 = mail_auth::NoCache;
    type Ptr = mail_auth::NoCache;

    fn txt(&self) -> Option<&FixedTxt> {
        self.0.as_ref().map(|fixed| &fixed.txt)
    }
    fn mx(&self) -> Option<&Self::Mx> {
        None
    }
    fn ipv4(&self) -> Option<&Self::Ipv4> {
        None
    }
    fn ipv6(&self) -> Option<&Self::Ipv6> {
        None
    }
    fn ptr(&self) -> Option<&Self::Ptr> {
        None
    }
}

pub struct Verifier {
    authenticator: MessageAuthenticator,
    dns: Dns,
    hostname: String,
}

/// Where a message came from on the SMTP side.
pub struct Peer<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    pub mail_from: &'a ReversePath,
}

pub struct Checked<'x> {
    pub dkim: Vec<DkimOutput<'x>>,
    pub arc: ArcOutput<'x>,
    pub spf: SpfOutput,
    pub dmarc: DmarcOutput,
    pub spf_domain: String,
    sender: String,
    helo: String,
}

impl Verifier {
    pub fn new(hostname: &str, fixed: Option<Arc<FixedDns>>) -> Result<Self, String> {
        let authenticator = MessageAuthenticator::new_system_conf().map_err(|e| e.to_string())?;
        Ok(Self {
            authenticator,
            dns: Dns(fixed),
            hostname: hostname.to_owned(),
        })
    }

    pub async fn check<'x>(
        &'x self,
        message: &'x AuthenticatedMessage<'x>,
        peer: &Peer<'_>,
    ) -> Checked<'x> {
        let sender = match peer.mail_from {
            ReversePath::Null => String::new(),
            ReversePath::Address(address) => address.to_string(),
        };
        let spf_domain = match peer.mail_from {
            ReversePath::Null => peer.helo.to_owned(),
            ReversePath::Address(address) => address.domain.clone(),
        };
        let dkim = self
            .authenticator
            .verify_dkim(Parameters::new(message).with_cache(&self.dns))
            .await;
        let arc = self
            .authenticator
            .verify_arc(Parameters::new(message).with_cache(&self.dns))
            .await;
        let spf_parameters = if sender.is_empty() {
            SpfParameters::helo(peer.ip, peer.helo, &self.hostname)
        } else {
            SpfParameters::mail_from(peer.ip, peer.helo, &self.hostname, &sender)
        };
        let spf = self
            .authenticator
            .verify_spf(Parameters::new(spf_parameters).with_cache(&self.dns))
            .await;
        let dmarc = self
            .authenticator
            .verify_dmarc(
                Parameters::new(DmarcParameters::new(message, &dkim, &spf_domain, &spf))
                    .with_cache(&self.dns),
            )
            .await;
        Checked {
            dkim,
            arc,
            spf,
            dmarc,
            spf_domain,
            sender,
            helo: peer.helo.to_owned(),
        }
    }
}

impl Checked<'_> {
    /// The sender's domain asks for mail like this to be refused.
    pub fn dmarc_rejects(&self) -> bool {
        matches!(self.dmarc.result(), DmarcResult::Fail(_)) && self.dmarc.policy() == Policy::Reject
    }

    /// SPF or DKIM passed for the domain in the From header. This is what proves a reply came
    /// from the account's own mailbox and not from someone typing its address.
    pub fn aligned_with(&self, from_domain: &str) -> bool {
        let spf = self.spf.result() == SpfResult::Pass && aligned(&self.spf_domain, from_domain);
        spf || self.dkim.iter().any(|output| {
            output.result() == &DkimResult::Pass
                && output
                    .signature()
                    .is_some_and(|signature| aligned(&signature.d, from_domain))
        })
    }

    /// What was found, for the `Authentication-Results` and ARC headers.
    pub fn results<'a>(
        &'a self,
        hostname: &'a str,
        from: &'a str,
        ip: IpAddr,
    ) -> AuthenticationResults<'a> {
        let parameters = if self.sender.is_empty() {
            SpfParameters::helo(ip, &self.helo, hostname)
        } else {
            SpfParameters::mail_from(ip, &self.helo, hostname, &self.sender)
        };
        AuthenticationResults::new(hostname)
            .with_dkim_results(&self.dkim, from)
            .with_spf_result(&self.spf, &parameters)
            .with_dmarc_result(&self.dmarc)
            .with_arc_result(&self.arc, ip)
    }
}

/// The same domain, or one under the other (DMARC's relaxed alignment without the public suffix
/// list: a parent must still have a dot, so `co.uk` style suffixes of two labels are the worst
/// case, and nobody can sign for those).
fn aligned(identity: &str, from_domain: &str) -> bool {
    let (identity, from_domain) = (
        identity.to_ascii_lowercase(),
        from_domain.to_ascii_lowercase(),
    );
    let under =
        |child: &str, parent: &str| parent.contains('.') && child.ends_with(&format!(".{parent}"));
    identity == from_domain || under(&identity, &from_domain) || under(&from_domain, &identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_is_the_domain_or_its_relatives() {
        assert!(aligned("example.com", "EXAMPLE.com"));
        assert!(aligned("mail.example.com", "example.com"));
        assert!(aligned("example.com", "mail.example.com"));
        assert!(!aligned("example.org", "example.com"));
        assert!(!aligned("badexample.com", "example.com"));
        assert!(!aligned("com", "example.com"));
    }
}
