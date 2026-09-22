use crate::model::{normalize_host, DnsRecord, RecordType};
use futures::StreamExt;
use hickory_client::client::{AsyncClient, ClientHandle};
use hickory_client::proto::iocompat::AsyncIoTokioAsStd;
use hickory_client::proto::rr::Name;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::Mutex;

pub mod enrich;

/// Enforces a minimum interval between DNS queries so the resolver stays under
/// a requested queries-per-second cap. Only constructed when --rate-limit is set.
struct RateGate {
    next: Mutex<Instant>,
    interval: Duration,
}

impl RateGate {
    fn new(per_second: u32) -> Self {
        Self {
            next: Mutex::new(Instant::now()),
            interval: Duration::from_secs(1) / per_second,
        }
    }

    async fn wait(&self) {
        let wait = {
            let mut next = self.next.lock().await;
            let now = Instant::now();
            let wait = next.saturating_duration_since(now);
            *next = now.max(*next) + self.interval;
            wait
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// A stable, always-resolvable name used as the positive control when checking
/// a resolver's health: one.one.one.one is Cloudflare's resolver hostname and
/// resolves to 1.1.1.1 / 1.0.0.1.
const RESOLVER_PROBE_GOOD: &str = "one.one.one.one";

/// Validate candidate resolver IPs, returning only the healthy ones (order not
/// preserved). A healthy resolver answers RESOLVER_PROBE_GOOD with at least one
/// address AND returns no address for a random name under `.invalid`, which can
/// never exist per RFC 2606 - a resolver that answers it is hijacking NXDOMAIN
/// and would poison every negative result the scan relies on. Non-IP strings
/// are dropped. Checks run concurrently.
pub async fn validate_resolvers(candidates: &[String], timeout_secs: u64) -> Vec<String> {
    let checks: Vec<(String, IpAddr)> = candidates
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok().map(|ip| (s.clone(), ip)))
        .collect();
    futures::stream::iter(checks)
        .map(|(label, ip)| async move {
            if resolver_is_healthy(ip, timeout_secs).await {
                Some(label)
            } else {
                None
            }
        })
        .buffer_unordered(16)
        .filter_map(|r| async move { r })
        .collect()
        .await
}

async fn resolver_is_healthy(ip: IpAddr, timeout_secs: u64) -> bool {
    let group = NameServerConfigGroup::from_ips_clear(&[ip], 53, true);
    let cfg = ResolverConfig::from_parts(None, vec![], group);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(timeout_secs.clamp(1, 5));
    let resolver = TokioAsyncResolver::tokio(cfg, opts);

    let good = resolver
        .ipv4_lookup(RESOLVER_PROBE_GOOD)
        .await
        .map(|r| r.iter().next().is_some())
        .unwrap_or(false);
    if !good {
        return false;
    }

    let bogus = format!("{}.invalid", crate::resolve::enrich::random_label());
    let bogus_answered = resolver
        .ipv4_lookup(bogus.as_str())
        .await
        .map(|r| r.iter().next().is_some())
        .unwrap_or(false);
    !bogus_answered
}

#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, name: &str, types: &[RecordType]) -> Vec<DnsRecord>;
    async fn ptr(&self, ip: IpAddr) -> Option<String>;
    async fn txt(&self, name: &str) -> Vec<String>;

    /// Attempt an AXFR zone transfer for `zone` against the authoritative name
    /// server `ns` (a hostname or IP). Returns the dumped records on success,
    /// or an empty vec on any failure (refused transfer, connection error,
    /// timeout) since a rejected AXFR is the common case, not an error. The
    /// default returns empty so stub resolvers in tests never touch the
    /// network; only HickoryResolver performs a real transfer.
    async fn axfr(&self, _ns: &str, _zone: &str) -> Vec<DnsRecord> {
        Vec::new()
    }
}

pub struct HickoryResolver {
    inner: TokioAsyncResolver,
    gate: Option<Arc<RateGate>>,
    timeout: Duration,
}

impl HickoryResolver {
    pub fn new(
        custom: &[String],
        timeout_secs: u64,
        rate_limit: Option<u32>,
    ) -> anyhow::Result<Self> {
        let inner = if custom.is_empty() {
            let (cfg, mut opts) = hickory_resolver::system_conf::read_system_conf()?;
            opts.timeout = Duration::from_secs(timeout_secs);
            // Retry once and fall back to TCP on a UDP error; a single dropped or
            // truncated response on a lossy network otherwise reads as a false negative.
            opts.attempts = 2;
            opts.try_tcp_on_error = true;
            TokioAsyncResolver::tokio(cfg, opts)
        } else {
            let ips: Vec<IpAddr> = custom.iter().filter_map(|s| s.parse().ok()).collect();
            let group = NameServerConfigGroup::from_ips_clear(&ips, 53, true);
            let cfg = ResolverConfig::from_parts(None, vec![], group);
            let mut opts = ResolverOpts::default();
            opts.timeout = Duration::from_secs(timeout_secs);
            // Retry once and fall back to TCP on a UDP error; a single dropped or
            // truncated response on a lossy network otherwise reads as a false negative.
            opts.attempts = 2;
            opts.try_tcp_on_error = true;
            TokioAsyncResolver::tokio(cfg, opts)
        };

        let gate = match rate_limit {
            Some(n) if n > 0 => Some(Arc::new(RateGate::new(n))),
            _ => None,
        };

        Ok(Self {
            inner,
            gate,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    async fn throttle(&self) {
        if let Some(gate) = &self.gate {
            gate.wait().await;
        }
    }
}

#[async_trait::async_trait]
impl Resolver for HickoryResolver {
    async fn resolve(&self, name: &str, types: &[RecordType]) -> Vec<DnsRecord> {
        let mut out = Vec::new();
        for t in types {
            match t {
                RecordType::A => {
                    self.throttle().await;
                    if let Ok(r) = self.inner.ipv4_lookup(name).await {
                        for ip in r.iter() {
                            out.push(DnsRecord {
                                name: name.into(),
                                rtype: *t,
                                value: ip.to_string(),
                            });
                        }
                    }
                }
                RecordType::Aaaa => {
                    self.throttle().await;
                    if let Ok(r) = self.inner.ipv6_lookup(name).await {
                        for ip in r.iter() {
                            out.push(DnsRecord {
                                name: name.into(),
                                rtype: *t,
                                value: ip.to_string(),
                            });
                        }
                    }
                }
                RecordType::Mx => {
                    self.throttle().await;
                    if let Ok(r) = self.inner.mx_lookup(name).await {
                        for mx in r.iter() {
                            out.push(DnsRecord {
                                name: name.into(),
                                rtype: *t,
                                value: format!("{} {}", mx.preference(), mx.exchange()),
                            });
                        }
                    }
                }
                RecordType::Ns => {
                    self.throttle().await;
                    if let Ok(r) = self.inner.ns_lookup(name).await {
                        for ns in r.iter() {
                            out.push(DnsRecord {
                                name: name.into(),
                                rtype: *t,
                                value: ns.to_string(),
                            });
                        }
                    }
                }
                RecordType::Soa => {
                    self.throttle().await;
                    if let Ok(r) = self.inner.soa_lookup(name).await {
                        for soa in r.iter() {
                            out.push(DnsRecord {
                                name: name.into(),
                                rtype: *t,
                                value: soa.mname().to_string(),
                            });
                        }
                    }
                }
                RecordType::Txt => {
                    self.throttle().await;
                    for v in self.txt_inner(name).await {
                        out.push(DnsRecord {
                            name: name.into(),
                            rtype: *t,
                            value: v,
                        });
                    }
                }
                RecordType::Srv => {
                    self.throttle().await;
                    if let Ok(r) = self.inner.srv_lookup(name).await {
                        for srv in r.iter() {
                            out.push(DnsRecord {
                                name: name.into(),
                                rtype: *t,
                                value: srv.to_string(),
                            });
                        }
                    }
                }
                RecordType::Cname => {
                    // Generic lookup: the resolver's typed helpers do not include CNAME
                    // (it is normally chased transparently by A/AAAA lookups), so query
                    // it directly and map every returned record via its Display form.
                    self.throttle().await;
                    if let Ok(r) = self
                        .inner
                        .lookup(name, hickory_proto::rr::RecordType::CNAME)
                        .await
                    {
                        for rdata in r.iter() {
                            out.push(DnsRecord {
                                name: name.into(),
                                rtype: *t,
                                value: rdata.to_string(),
                            });
                        }
                    }
                }
                RecordType::Caa => {
                    self.throttle().await;
                    if let Ok(r) = self
                        .inner
                        .lookup(name, hickory_proto::rr::RecordType::CAA)
                        .await
                    {
                        for rdata in r.iter() {
                            out.push(DnsRecord {
                                name: name.into(),
                                rtype: *t,
                                value: rdata.to_string(),
                            });
                        }
                    }
                }
                RecordType::Ptr => {
                    // PTR is handled separately by the ptr() method against reversed IPs;
                    // it does not apply to a forward name lookup here.
                }
                RecordType::Ds
                | RecordType::Dnskey
                | RecordType::Nsec
                | RecordType::Nsec3
                | RecordType::Hinfo
                | RecordType::Naptr
                | RecordType::Tlsa
                | RecordType::Sshfp => {
                    // These only ever arrive from an AXFR dump; they are not queried in a
                    // forward resolve.
                }
            }
        }
        out
    }

    async fn ptr(&self, ip: IpAddr) -> Option<String> {
        self.throttle().await;
        self.inner
            .reverse_lookup(ip)
            .await
            .ok()
            .and_then(|r| r.iter().next().map(|n| n.to_string()))
    }

    async fn txt(&self, name: &str) -> Vec<String> {
        self.throttle().await;
        self.txt_inner(name).await
    }

    async fn axfr(&self, ns: &str, zone: &str) -> Vec<DnsRecord> {
        self.axfr_inner(ns, zone).await.unwrap_or_default()
    }
}

/// Map a hickory record type to this tool's RecordType set. AXFR can return
/// types beyond the 10 queryable ones (DS, DNSKEY, HINFO, ...); those are kept
/// as output-only variants so a zone dump is not silently thinned out. Types
/// still outside this set fall through to None and are skipped.
fn map_record_type(rt: hickory_client::proto::rr::RecordType) -> Option<RecordType> {
    use hickory_client::proto::rr::RecordType as H;
    Some(match rt {
        H::A => RecordType::A,
        H::AAAA => RecordType::Aaaa,
        H::CNAME => RecordType::Cname,
        H::MX => RecordType::Mx,
        H::NS => RecordType::Ns,
        H::SOA => RecordType::Soa,
        H::TXT => RecordType::Txt,
        H::SRV => RecordType::Srv,
        H::CAA => RecordType::Caa,
        H::PTR => RecordType::Ptr,
        H::DS => RecordType::Ds,
        H::DNSKEY => RecordType::Dnskey,
        H::NSEC => RecordType::Nsec,
        H::NSEC3 => RecordType::Nsec3,
        H::HINFO => RecordType::Hinfo,
        H::NAPTR => RecordType::Naptr,
        H::TLSA => RecordType::Tlsa,
        H::SSHFP => RecordType::Sshfp,
        _ => return None,
    })
}

impl HickoryResolver {
    /// Performs the TXT lookup without throttling. Callers (the public `txt()`
    /// method, and the Txt arm in `resolve()`) are responsible for calling
    /// `throttle()` exactly once before invoking this, so a TXT query is never
    /// throttled twice.
    async fn txt_inner(&self, name: &str) -> Vec<String> {
        match self.inner.txt_lookup(name).await {
            Ok(r) => r.iter().map(|t| t.to_string()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Open a TCP connection to `ns_ip` and stream a full AXFR for `zone_name`.
    /// Returns None on any connection failure so the caller can move on to the
    /// next address. A successful transfer yields one DnsRecord per dumped
    /// record whose type maps to our RecordType set (an empty Vec means the
    /// server answered but refused or had nothing to offer).
    async fn axfr_from_addr(&self, ns_ip: IpAddr, zone_name: Name) -> Option<Vec<DnsRecord>> {
        // Bound the whole attempt (TCP connect plus the transfer stream) with one
        // budget, so a firewalled port or a server that accepts the connection
        // then stalls cannot hang the run. axfr_inner fans these attempts out
        // concurrently, so the total AXFR time is about one budget rather than
        // the sum over every nameserver IP.
        let attempt = async {
            let addr = SocketAddr::new(ns_ip, 53);
            let (stream, sender) =
                TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::with_timeout(
                    addr,
                    self.timeout,
                );
            let (mut client, bg) = AsyncClient::new(stream, sender, None).await.ok()?;
            let bg_handle = tokio::spawn(bg);

            let mut out = Vec::new();
            let mut xfr = client.zone_transfer(zone_name, None);
            while let Some(msg) = xfr.next().await {
                let response = match msg {
                    Ok(r) => r,
                    Err(_) => break,
                };
                for rec in response.answers() {
                    if let Some(rtype) = map_record_type(rec.record_type()) {
                        let value = rec.data().map(|d| d.to_string()).unwrap_or_default();
                        out.push(DnsRecord {
                            name: normalize_host(&rec.name().to_string()),
                            rtype,
                            value,
                        });
                    }
                }
            }

            bg_handle.abort();
            Some(out)
        };

        // A timed-out attempt is treated like any other reachable-but-unhelpful
        // server: None, so the caller moves on.
        tokio::time::timeout(self.timeout, attempt).await.ok()?
    }

    /// Resolve the name server to every address it has, and try an AXFR
    /// against each in turn until one yields records. Returns None on any
    /// failure so the public `axfr` can fall back to an empty result, or
    /// Some(empty vec) if every address was reachable but none offered a
    /// transfer.
    async fn axfr_inner(&self, ns: &str, zone: &str) -> Option<Vec<DnsRecord>> {
        // The NS value from an NS lookup is usually a hostname (often with a
        // trailing dot); it may also already be an address.
        let ns_host = ns.trim_end_matches('.');
        let ips: Vec<IpAddr> = match ns_host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self.inner.lookup_ip(ns_host).await.ok()?.iter().collect(),
        };

        let zone_name = Name::from_ascii(zone).ok()?;
        // Try every nameserver IP concurrently and take the first non-empty dump.
        // Running them in parallel keeps a handful of firewalled IPs from each
        // burning a full timeout back to back.
        let attempts = futures::future::join_all(
            ips.into_iter()
                .map(|ip| self.axfr_from_addr(ip, zone_name.clone())),
        )
        .await;
        for recs in attempts.into_iter().flatten() {
            if !recs.is_empty() {
                return Some(recs);
            }
        }
        Some(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_gate_spaces_out_calls() {
        // At 2/sec, three sequential waits should take at least ~1 second total
        // (the first call is free, the next two each wait ~0.5s). A generous
        // lower bound avoids flakiness from scheduler jitter.
        let gate = RateGate::new(2);
        let start = Instant::now();
        gate.wait().await;
        gate.wait().await;
        gate.wait().await;
        assert!(start.elapsed() >= Duration::from_millis(900));
    }

    #[test]
    fn rate_gate_interval_matches_rate() {
        let gate = RateGate::new(4);
        assert_eq!(gate.interval, Duration::from_millis(250));
    }

    #[test]
    fn map_record_type_keeps_dnskey() {
        use hickory_client::proto::rr::RecordType as H;
        assert_eq!(
            super::map_record_type(H::DNSKEY),
            Some(crate::model::RecordType::Dnskey)
        );
    }
}
