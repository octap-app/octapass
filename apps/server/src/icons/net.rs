//! The icon fetcher's view of the network: it resolves names itself and only ever connects to
//! public unicast addresses, so a site can't point it at the server's own network.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Whether the fetcher may connect to `ip`: not private, loopback, link-local, multicast, CGNAT,
/// documentation, benchmarking, reserved or IPv6 unique local, nor an IPv4 address hidden in an
/// IPv6 one that is any of those.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        // 100.64.0.0/10, shared address space (CGNAT).
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24, IETF protocol assignments.
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15, benchmarking.
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4, reserved.
        || a >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let segments = ip.segments();
    // Only global unicast, 2000::/3, is ever public.
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }
    match segments[0] {
        // 2001:db8::/32 documentation; 2001::/23 IETF protocol assignments (Teredo among them).
        0x2001 => segments[1] >= 0x0200 && segments[1] != 0x0db8,
        // 2002::/16, 6to4: the IPv4 address inside decides.
        0x2002 => is_public_v4(Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            segments[1] as u8,
            (segments[2] >> 8) as u8,
            segments[2] as u8,
        )),
        // 3fff::/20, documentation.
        0x3fff => segments[1] >= 0x1000,
        _ => true,
    }
}

/// How names are resolved. The real thing asks the system; tests give fixed answers.
#[derive(Clone, Debug, Default)]
pub struct TestNetwork {
    /// Answers for these names, instead of DNS. A non-zero port is the port connected to.
    pub hosts: HashMap<String, Vec<SocketAddr>>,
    /// Addresses the fetcher may connect to although they aren't public: the test sites.
    pub reachable: Vec<SocketAddr>,
}

/// Resolves a name and keeps only the addresses the fetcher may use. Fails when none are left,
/// so a name that resolves only to private addresses is never connected to.
pub struct PublicResolver {
    test: Option<Arc<TestNetwork>>,
}

impl PublicResolver {
    pub fn new(test: Option<Arc<TestNetwork>>) -> Self {
        Self { test }
    }

    pub fn allows(&self, addr: SocketAddr) -> bool {
        is_public(addr.ip())
            || self
                .test
                .as_ref()
                .is_some_and(|test| test.reachable.contains(&addr))
    }

    async fn lookup(&self, name: &str) -> std::io::Result<Vec<SocketAddr>> {
        let found: Vec<SocketAddr> = match &self.test {
            Some(test) => test.hosts.get(name).cloned().unwrap_or_default(),
            None => tokio::net::lookup_host((name, 0)).await?.collect(),
        };
        let allowed: Vec<SocketAddr> = found.into_iter().filter(|a| self.allows(*a)).collect();
        if allowed.is_empty() {
            return Err(std::io::Error::other("no public address"));
        }
        Ok(allowed)
    }
}

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = Self {
            test: self.test.clone(),
        };
        Box::pin(async move {
            let addrs = resolver.lookup(name.as_str()).await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(ip: &str) -> bool {
        is_public(ip.parse().unwrap())
    }

    #[test]
    fn refuses_every_non_public_range() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.8",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "::ffff:169.254.169.254",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "64:ff9b::1",
            "100::1",
            "2001:db8::1",
            "2001::1",
            "2002:7f00:1::",
            "2002:c0a8:101::1",
            "3fff::1",
        ] {
            assert!(!public(ip), "{ip} must be refused");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.215.14",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "192.0.1.1",
            "198.20.0.1",
            "::ffff:8.8.8.8",
            "2606:4700::1111",
            "2a00:1450:4001::200e",
            "2001:4860::8888",
            "2002:0808:0808::1",
        ] {
            assert!(public(ip), "{ip} is public");
        }
    }

    #[tokio::test]
    async fn resolving_keeps_only_allowed_addresses() {
        let site: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let network = TestNetwork {
            hosts: HashMap::from([
                ("site.example".into(), vec![site]),
                (
                    "mixed.example".into(),
                    vec![
                        "10.0.0.1:0".parse().unwrap(),
                        "93.184.215.14:0".parse().unwrap(),
                    ],
                ),
                (
                    "internal.example".into(),
                    vec!["127.0.0.2:4000".parse().unwrap()],
                ),
            ]),
            reachable: vec![site],
        };
        let resolver = PublicResolver::new(Some(Arc::new(network)));
        assert_eq!(resolver.lookup("site.example").await.unwrap(), [site]);
        assert_eq!(
            resolver.lookup("mixed.example").await.unwrap(),
            ["93.184.215.14:0".parse::<SocketAddr>().unwrap()]
        );
        assert!(resolver.lookup("internal.example").await.is_err());
        assert!(resolver.lookup("unknown.example").await.is_err());
    }
}
