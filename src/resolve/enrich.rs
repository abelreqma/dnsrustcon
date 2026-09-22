use crate::model::{normalize_host, IpInfo, RecordType};
use crate::resolve::Resolver;
use crate::sources::asn::{origin_query_name, parse_asname, parse_origin};
use std::collections::HashSet;
use std::net::IpAddr;

pub fn random_label() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("dnsrustcon-{n:x}")
}

/// A source of open-service data for an IP address (e.g. Shodan). Kept as a
/// trait so `enrich_ip` stays decoupled from any specific provider and can be
/// exercised with `None` in tests.
#[async_trait::async_trait]
pub trait ServiceProvider: Send + Sync {
    async fn services(&self, ip: std::net::IpAddr) -> Vec<crate::model::Service>;
}

/// A source of network-registration (org) data for an IP address (RDAP). Kept
/// as a trait, like ServiceProvider, so `enrich_ip` stays decoupled from the
/// HTTP fetch and can be exercised with `None` in tests.
#[async_trait::async_trait]
pub trait OrgProvider: Send + Sync {
    async fn org(&self, ip: std::net::IpAddr) -> Option<String>;
}

pub async fn enrich_ip(
    resolver: &dyn Resolver,
    ip: IpAddr,
    services: Option<&dyn ServiceProvider>,
    org: Option<&dyn OrgProvider>,
) -> IpInfo {
    let ptr = resolver.ptr(ip).await.map(|s| normalize_host(&s));

    let origin_name = origin_query_name(ip);
    let origin = resolver
        .txt(&origin_name)
        .await
        .first()
        .and_then(|t| parse_origin(t));

    let (asn, prefix, country) = match &origin {
        Some(o) => (Some(o.asn), Some(o.prefix.clone()), Some(o.country.clone())),
        None => (None, None, None),
    };

    let rir = origin
        .as_ref()
        .map(|o| o.registry.clone())
        .filter(|r| !r.is_empty());

    let asn_name = match asn {
        Some(n) => {
            let q = format!("AS{n}.asn.cymru.com");
            resolver.txt(&q).await.first().and_then(|t| parse_asname(t))
        }
        None => None,
    };

    let registered_org = match org {
        Some(provider) => provider.org(ip).await,
        None => None,
    };

    let mut info = IpInfo {
        ip,
        ptr,
        asn,
        asn_name,
        rir,
        prefix,
        country,
        org: registered_org,
        services: Vec::new(),
    };
    if let Some(provider) = services {
        info.services = provider.services(ip).await;
    }
    info
}

/// Probe a random name under `base` and collect the catch-all answers a
/// wildcard record returns. The set holds each returned record's value, so it
/// captures wildcard A/AAAA addresses AND wildcard CNAME targets (a wildcard
/// that points every name at a parking or CDN host). Callers suppress any later
/// record whose value lands in this set.
pub async fn detect_wildcard(resolver: &dyn Resolver, base: &str) -> HashSet<String> {
    let probe = format!("{}.{}", random_label(), base);
    resolver
        .resolve(
            &probe,
            &[RecordType::A, RecordType::Aaaa, RecordType::Cname],
        )
        .await
        .into_iter()
        .map(|r| r.value)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsRecord, RecordType};
    use std::net::IpAddr;

    struct StubResolver;

    #[async_trait::async_trait]
    impl crate::resolve::Resolver for StubResolver {
        async fn resolve(&self, name: &str, _t: &[RecordType]) -> Vec<DnsRecord> {
            vec![DnsRecord {
                name: name.into(),
                rtype: RecordType::A,
                value: "1.2.3.4".into(),
            }]
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            Some("host.example.".into())
        }
        async fn txt(&self, name: &str) -> Vec<String> {
            if name.ends_with("origin.asn.cymru.com") {
                vec!["15169 | 8.8.8.0/24 | US | arin | 1992-12-01".into()]
            } else if name.ends_with("asn.cymru.com") {
                vec!["15169 | US | arin | 1992-12-01 | GOOGLE, US".into()]
            } else {
                vec![]
            }
        }
    }

    #[tokio::test]
    async fn enrich_fills_asn_and_ptr() {
        let info = enrich_ip(&StubResolver, "8.8.8.8".parse().unwrap(), None, None).await;
        assert_eq!(info.asn, Some(15169));
        assert_eq!(info.asn_name.as_deref(), Some("GOOGLE, US"));
        assert_eq!(info.rir.as_deref(), Some("arin"));
        assert_eq!(info.ptr.as_deref(), Some("host.example"));
        assert_eq!(info.org, None);
    }

    struct StubOrg;
    #[async_trait::async_trait]
    impl OrgProvider for StubOrg {
        async fn org(&self, _ip: IpAddr) -> Option<String> {
            Some("Google LLC".into())
        }
    }

    #[tokio::test]
    async fn enrich_fills_org_from_provider() {
        let info = enrich_ip(
            &StubResolver,
            "8.8.8.8".parse().unwrap(),
            None,
            Some(&StubOrg),
        )
        .await;
        assert_eq!(info.org.as_deref(), Some("Google LLC"));
    }

    #[tokio::test]
    async fn wildcard_detected() {
        let set = detect_wildcard(&StubResolver, "example.com").await;
        assert!(set.contains("1.2.3.4"));
    }
}
