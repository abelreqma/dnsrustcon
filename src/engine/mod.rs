pub mod queue;
use queue::Visited;

use crate::cli::Mode;
use crate::config::Config;
use crate::model::{
    is_valid_hostname, normalize_host, Candidate, CandidateValue, DnsRecord, IpInfo, RecordType,
    Takeover, Target,
};
use crate::resolve::enrich::{detect_wildcard, enrich_ip, OrgProvider, ServiceProvider};
use crate::resolve::Resolver;
use crate::sources::bruteforce::{generate_fqdns, generate_permutations};
use crate::sources::reverse::{containing_24, hosts_of, sweep_host_count, MAX_SWEEP_HOSTS};
use crate::sources::{Source, SourceKind};
use futures::stream::{self, StreamExt};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

pub enum FindingEvent {
    Host(String, String), // host, source
    Record(DnsRecord),
    Ip(IpInfo),
    SourceRun(&'static str),                   // source is about to run
    SourceSkipped(&'static str, &'static str), // source, reason (e.g. "no key")
    SourceError(&'static str, String),         // source, error string
    Takeover(Takeover),                        // potential subdomain takeover
    AxfrSuccess(String, usize),                // ns, record count: a zone transfer succeeded
    Probe(crate::probe::HostProbe),            // HTTP/TLS probe of a discovered host
    DomainInactive(String),                    // domain skipped: no NS or SOA (dead/unregistered)
}

/// Reverse-sweep knobs, grouped so no single struct carries too many bools.
pub struct SweepOpts {
    pub reverse: bool,
    pub sweep_prefix: bool,
    pub allow_large_sweep: bool,
}

/// Opt-in discovery/analysis passes, grouped so no single struct carries too
/// many bools.
pub struct FeatureOpts {
    pub permutations: bool,
    pub takeover: bool,
    pub probe: bool,
}

pub struct EngineOpts {
    pub depth: u8,
    pub concurrency: usize,
    pub record_types: Vec<RecordType>,
    pub words: Vec<String>,
    pub scope: bool,
    pub sweep: SweepOpts,
    pub features: FeatureOpts,
    /// Hosts from a prior run (via --resume) to treat as already seen, so they
    /// are neither re-emitted nor recursed into.
    pub known_hosts: HashSet<String>,
}

/// True if `host` is within one of the scanned `domains`: equal to a domain or a
/// subdomain of it. With no domains (an IP/CIDR-only scan) everything is in
/// scope, since there is no apex to scope against.
fn in_scope(host: &str, domains: &[String]) -> bool {
    domains.is_empty()
        || domains
            .iter()
            .any(|d| host == d || host.ends_with(&format!(".{d}")))
}

/// Decide whether a single host/CNAME pair is a potential takeover. See
/// `detect_takeovers` for the two-signal logic.
async fn check_takeover(
    resolver: &dyn Resolver,
    http: Option<&reqwest::Client>,
    host: &str,
    cname: &str,
    fp: &crate::takeover::Fingerprint,
) -> Option<Takeover> {
    let target = cname.trim_end_matches('.');

    if fp.nxdomain_is_takeover {
        let addrs = resolver
            .resolve(target, &[RecordType::A, RecordType::Aaaa])
            .await;
        // Second signal: when the fingerprint names a base zone, a dangling
        // target alone is not enough. The service's base domain must still
        // resolve; if it does not, we are seeing a network or service-wide
        // failure (a transient resolver hiccup, or the whole service being
        // gone) rather than a specifically reclaimable dangling resource, so we
        // must not flag it. Services with no base_domain keep the single-signal
        // behavior.
        let base_ok = fp.base_domain.is_empty()
            || !resolver
                .resolve(fp.base_domain, &[RecordType::Ns])
                .await
                .is_empty();
        if addrs.is_empty() && base_ok {
            return Some(Takeover {
                host: host.to_string(),
                service: fp.service.to_string(),
                cname: target.to_string(),
                evidence: format!("dangling CNAME: {target} does not resolve"),
            });
        }
    }

    if !fp.body_marker.is_empty() {
        let client = http?;
        // Second verification pass: a single body-marker match is prone to false
        // positives (a transient CDN error page, or a legitimate page that
        // happens to contain the marker). Require the marker in TWO independent
        // fetches, and require the confirming fetch to carry an HTTP error
        // status (>= 400), which is what a genuinely unclaimed resource returns.
        // A live page that merely contains the marker string answers 2xx and is
        // rejected.
        let first = fetch_probe(client, host).await?;
        if !body_indicates_unclaimed(&first.1, fp.body_marker) {
            return None;
        }
        let second = fetch_probe(client, host).await?;
        if body_indicates_unclaimed(&second.1, fp.body_marker) && second.0 >= 400 {
            return Some(Takeover {
                host: host.to_string(),
                service: fp.service.to_string(),
                cname: target.to_string(),
                evidence: format!(
                    "matched {} unclaimed-resource marker on two fetches (HTTP {})",
                    fp.service, second.0
                ),
            });
        }
    }

    None
}

/// True when `body` carries the fingerprint's unclaimed-resource `marker`. Kept
/// separate so the match rule is unit-testable without a live HTTP fetch.
fn body_indicates_unclaimed(body: &str, marker: &str) -> bool {
    !marker.is_empty() && body.contains(marker)
}

/// Fetch the root document of `host`, trying HTTPS then HTTP. Returns the HTTP
/// status code and body text from the first scheme that answers, or None if
/// neither yields a response.
async fn fetch_probe(http: &reqwest::Client, host: &str) -> Option<(u16, String)> {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{host}/");
        if let Ok(resp) = http.get(&url).send().await {
            let status = resp.status().as_u16();
            if let Ok(body) = resp.text().await {
                return Some((status, body));
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct AxfrTransfer {
    pub ns: String,
    pub records: usize,
}

#[derive(Default)]
pub struct Findings {
    pub records: Vec<DnsRecord>,
    pub ips: Vec<IpInfo>,
    pub hosts: BTreeSet<String>,
    pub takeovers: Vec<Takeover>,
    pub axfr: Vec<AxfrTransfer>,
    pub probes: Vec<crate::probe::HostProbe>,
}

/// The single-threaded mutable state every run phase threads through: the
/// visited-set for dedup, the accumulating findings, and the live event sink.
/// Bundled so each phase takes it as one parameter.
struct RunState<'a> {
    visited: &'a mut Visited,
    findings: &'a mut Findings,
    sink: &'a mut dyn FnMut(FindingEvent),
}

pub struct Engine {
    mode: Mode,
    resolver: Arc<dyn Resolver>,
    sources: Vec<Box<dyn Source>>,
    cfg: Config,
    opts: EngineOpts,
    services: Option<Arc<dyn ServiceProvider>>,
    org: Option<Arc<dyn OrgProvider>>,
    progress: Option<indicatif::ProgressBar>,
}

impl Engine {
    pub fn new(
        mode: Mode,
        resolver: Arc<dyn Resolver>,
        sources: Vec<Box<dyn Source>>,
        cfg: Config,
        opts: EngineOpts,
        services: Option<Arc<dyn ServiceProvider>>,
        org: Option<Arc<dyn OrgProvider>>,
    ) -> Self {
        Self {
            mode,
            resolver,
            sources,
            cfg,
            opts,
            services,
            org,
            progress: None,
        }
    }

    /// Attach a progress bar the engine advances as it works. The bar is
    /// updated with a per-phase message and one tick per completed lookup.
    pub fn set_progress(&mut self, pb: indicatif::ProgressBar) {
        self.progress = Some(pb);
    }

    /// Set the progress bar's phase label, if a bar is attached.
    fn progress_phase(&self, msg: String) {
        if let Some(pb) = &self.progress {
            pb.set_message(msg);
        }
    }

    fn source_enabled(&self, kind: SourceKind) -> bool {
        match self.mode {
            Mode::Passive => kind == SourceKind::Passive,
            Mode::Active => kind == SourceKind::Active,
            Mode::Both => true,
        }
    }

    /// Enrich a batch of IP addresses concurrently (bounded by opts.concurrency),
    /// returning their IpInfos in completion order. All mutation of shared state
    /// stays in the callers; this performs only the network-bound lookups.
    async fn enrich_batch(&self, ips: Vec<IpAddr>) -> Vec<IpInfo> {
        self.progress_phase(format!("enriching {} IPs", ips.len()));
        stream::iter(ips)
            .map(|ip| {
                let resolver = self.resolver.clone();
                let services = self.services.clone();
                let org = self.org.clone();
                let pb = self.progress.clone();
                async move {
                    let info =
                        enrich_ip(resolver.as_ref(), ip, services.as_deref(), org.as_deref()).await;
                    if let Some(pb) = &pb {
                        pb.inc(1);
                    }
                    info
                }
            })
            .buffer_unordered(self.opts.concurrency.max(1))
            .collect()
            .await
    }

    /// Dedup, enrich concurrently, and record a batch of IP addresses. When
    /// reverse sweeping is on and a domain is targeted, each IPv4 address also
    /// has its containing /24 (or ASN prefix, see `sweep_net`) enumerated and
    /// its neighbors enriched. IPv6 addresses are never swept.
    async fn seed_and_sweep(
        &self,
        ips: Vec<IpAddr>,
        has_domain_target: bool,
        visited: &mut Visited,
        findings: &mut Findings,
        sink: &mut dyn FnMut(FindingEvent),
    ) {
        let fresh: Vec<IpAddr> = ips
            .into_iter()
            .filter(|ip| visited.insert_new(&CandidateValue::Ip(*ip)))
            .collect();
        if fresh.is_empty() {
            return;
        }

        let mut neighbors: Vec<IpAddr> = Vec::new();
        for info in self.enrich_batch(fresh).await {
            let sweep_net = match info.ip {
                IpAddr::V4(v4) if self.opts.sweep.reverse && has_domain_target => {
                    Some(self.sweep_net(v4, &info))
                }
                _ => None,
            };
            sink(FindingEvent::Ip(info.clone()));
            findings.ips.push(info);

            if let Some(net) = sweep_net {
                for neighbor in hosts_of(&net) {
                    if visited.insert_new(&CandidateValue::Ip(neighbor)) {
                        neighbors.push(neighbor);
                    }
                }
            }
        }

        if !neighbors.is_empty() {
            for ninfo in self.enrich_batch(neighbors).await {
                sink(FindingEvent::Ip(ninfo.clone()));
                findings.ips.push(ninfo);
            }
        }
    }

    /// Choose which network to sweep for a resolved IPv4 address during a
    /// domain reverse sweep. With --sweep-prefix and a usable ASN prefix from
    /// Cymru enrichment, sweep that prefix instead of the containing /24,
    /// unless it exceeds the sweep cap and --allow-large-sweep was not given
    /// (hosts_of caps at MAX_SWEEP_HOSTS regardless, so this only decides
    /// whether to honor the wider prefix or fall back to the /24).
    fn sweep_net(&self, v4: std::net::Ipv4Addr, info: &IpInfo) -> ipnet::IpNet {
        if self.opts.sweep.sweep_prefix {
            if let Some(net) = info
                .prefix
                .as_deref()
                .and_then(|p| p.parse::<ipnet::IpNet>().ok())
            {
                let within_cap = matches!(sweep_host_count(&net), Some(c) if c <= MAX_SWEEP_HOSTS);
                if within_cap || self.opts.sweep.allow_large_sweep {
                    return net;
                }
            }
        }
        ipnet::IpNet::V4(containing_24(v4))
    }

    /// Resolve a flat list of candidate host names concurrently and return the
    /// ones that resolve to at least one address not in `wildcard_ips`. Confirms
    /// brute-force guesses before they are recorded.
    async fn confirm_hosts(
        &self,
        candidates: Vec<String>,
        wildcard_ips: &HashSet<String>,
    ) -> Vec<String> {
        self.progress_phase(format!(
            "confirming {} brute-force candidates",
            candidates.len()
        ));
        let results: Vec<(String, Vec<DnsRecord>)> = stream::iter(candidates)
            .map(|cand| {
                let resolver = self.resolver.clone();
                let pb = self.progress.clone();
                async move {
                    // Query AAAA alongside A so an IPv6-only host is confirmed.
                    let hits = resolver
                        .resolve(&cand, &[RecordType::A, RecordType::Aaaa])
                        .await;
                    if let Some(pb) = &pb {
                        pb.inc(1);
                    }
                    (cand, hits)
                }
            })
            .buffer_unordered(self.opts.concurrency.max(1))
            .collect()
            .await;

        results
            .into_iter()
            .filter(|(_, hits)| hits.iter().any(|r| !wildcard_ips.contains(&r.value)))
            .map(|(cand, _)| cand)
            .collect()
    }

    /// Inspect every discovered CNAME for a dangling pointer to a
    /// takeover-prone service. A finding requires two signals: the CNAME target
    /// matches a known service suffix, and either that target does not resolve
    /// (for services that free the DNS name) or an HTTP fetch of the host
    /// returns the service's unclaimed-resource marker. Checks run concurrently.
    async fn detect_takeovers(&self, records: &[DnsRecord]) -> Vec<Takeover> {
        let mut seen: HashSet<(String, String)> = HashSet::new();
        let mut candidates: Vec<(String, String, &'static crate::takeover::Fingerprint)> =
            Vec::new();
        for r in records.iter().filter(|r| r.rtype == RecordType::Cname) {
            if let Some(fp) = crate::takeover::match_service(&r.value) {
                if seen.insert((r.name.clone(), r.value.clone())) {
                    candidates.push((r.name.clone(), r.value.clone(), fp));
                }
            }
        }
        if candidates.is_empty() {
            return Vec::new();
        }

        self.progress_phase(format!(
            "checking {} CNAME(s) for takeover",
            candidates.len()
        ));
        let http = crate::sources::http_client().ok();

        stream::iter(candidates)
            .map(|(host, cname, fp)| {
                let resolver = self.resolver.clone();
                let http = http.clone();
                let pb = self.progress.clone();
                async move {
                    let result =
                        check_takeover(resolver.as_ref(), http.as_ref(), &host, &cname, fp).await;
                    if let Some(pb) = &pb {
                        pb.inc(1);
                    }
                    result
                }
            })
            .buffer_unordered(self.opts.concurrency.max(1))
            .filter_map(|t| async move { t })
            .collect()
            .await
    }

    /// Active-domain pre-check: a domain that returns neither NS nor SOA is
    /// treated as inactive (likely unregistered or dead), so the run does not
    /// waste OSINT calls, AXFR, and brute force on it. A domain is marked
    /// inactive only when both come back empty, since the resolver already
    /// retries and falls back to TCP. IP/CIDR targets are never checked.
    async fn active_domains(
        &self,
        targets: &[Target],
        sink: &mut dyn FnMut(FindingEvent),
    ) -> HashSet<String> {
        let mut inactive: HashSet<String> = HashSet::new();
        for t in targets {
            if let Target::Domain(d) = t {
                let ns = self.resolver.resolve(d, &[RecordType::Ns]).await;
                let soa = if ns.is_empty() {
                    self.resolver.resolve(d, &[RecordType::Soa]).await
                } else {
                    Vec::new()
                };
                if ns.is_empty() && soa.is_empty() {
                    inactive.insert(d.clone());
                    sink(FindingEvent::DomainInactive(d.clone()));
                }
            }
        }
        inactive
    }

    /// Explicit Ip/Cidr targets name concrete hosts to inspect, not sources to
    /// discover candidates from, so the engine enriches them directly here in
    /// every mode (including the default passive mode), rather than relying on a
    /// Source that only runs when active sources are enabled.
    async fn seed_targets(
        &self,
        targets: &[Target],
        has_domain_target: bool,
        st: &mut RunState<'_>,
    ) {
        let mut seed_ips: Vec<IpAddr> = Vec::new();
        for t in targets {
            match t {
                Target::Ip(ip) => seed_ips.push(*ip),
                Target::Cidr(net) => seed_ips.extend(hosts_of(net)),
                Target::Domain(_) => {}
            }
        }
        if !seed_ips.is_empty() {
            self.seed_and_sweep(
                seed_ips,
                has_domain_target,
                st.visited,
                st.findings,
                st.sink,
            )
            .await;
        }
    }

    /// Run every enabled discovery source, collect the candidates they emit,
    /// enrich candidate IPs, and confirm the initial brute-force pass. Returns
    /// the queue of discovered host names for record resolution and recursion.
    ///
    /// Sources run concurrently. Candidates flow through an unbounded channel so
    /// a high-volume source (crt.sh) can never block on a full buffer; each run
    /// bridges its own bounded Sender into it. The sink is touched only from this
    /// single-threaded caller, never from inside the concurrent futures.
    async fn collect_candidates(
        &self,
        targets: &[Target],
        inactive: &HashSet<String>,
        domains: &[String],
        has_domain_target: bool,
        wildcard_ips: &HashSet<String>,
        st: &mut RunState<'_>,
    ) -> Vec<String> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Candidate>();
        let mut runs = Vec::new();
        // Count the sources that will actually run, for the progress label.
        let runnable = self
            .sources
            .iter()
            .filter(|s| self.source_enabled(s.kind()) && s.available(&self.cfg))
            .count();
        self.progress_phase(format!("querying {runnable} discovery sources"));
        for src in &self.sources {
            if !self.source_enabled(src.kind()) {
                continue;
            }
            if !src.available(&self.cfg) {
                let reason = match src.name() {
                    "securitytrails" | "virustotal" | "shodandns" | "chaos" | "dnsdumpster"
                    | "censys" => "no key",
                    _ => "unavailable",
                };
                (st.sink)(FindingEvent::SourceSkipped(src.name(), reason));
                continue;
            }
            (st.sink)(FindingEvent::SourceRun(src.name()));
            for t in targets {
                // Do not run sources against an inactive domain target.
                if let Target::Domain(d) = t {
                    if inactive.contains(d) {
                        continue;
                    }
                }
                let central = tx.clone();
                let pb = self.progress.clone();
                runs.push(async move {
                    let (btx, mut brx) = tokio::sync::mpsc::channel::<Candidate>(1024);
                    let relay = async move {
                        while let Some(c) = brx.recv().await {
                            let _ = central.send(c);
                        }
                    };
                    let (_, result) = tokio::join!(relay, src.run(t, btx));
                    if let Some(pb) = &pb {
                        pb.inc(1);
                    }
                    (src.name(), result)
                });
            }
        }
        let results = futures::future::join_all(runs).await;
        drop(tx);
        for (name, result) in results {
            if let Err(e) = result {
                (st.sink)(FindingEvent::SourceError(name, e.to_string()));
            }
        }

        // Brute-force candidates are unconfirmed guesses (one per wordlist
        // entry), so they are deferred and confirmed below rather than recorded
        // on arrival. Passive-source hosts are genuine observations and are
        // recorded as they arrive.
        let mut host_queue: Vec<String> = Vec::new();
        let mut bf_candidates: Vec<String> = Vec::new();
        let mut candidate_ips: Vec<IpAddr> = Vec::new();
        while let Some(c) = rx.recv().await {
            match c.value {
                CandidateValue::Host(h) => {
                    let h = normalize_host(&h);
                    // Drop non-host SAN junk (email addresses, descriptive text)
                    // that OSINT sources emit, before it becomes a finding or a
                    // wasted DNS lookup.
                    if !is_valid_hostname(&h) {
                        continue;
                    }
                    // Drop out-of-scope names (unless scoping is disabled): a
                    // co-listed domain from a shared certificate must not be
                    // recorded or recursed into.
                    if self.opts.scope && !in_scope(&h, domains) {
                        continue;
                    }
                    if c.source == "bruteforce" {
                        bf_candidates.push(h);
                    } else if st.visited.insert_new(&CandidateValue::Host(h.clone())) {
                        st.findings.hosts.insert(h.clone());
                        (st.sink)(FindingEvent::Host(h.clone(), c.source));
                        host_queue.push(h);
                    }
                }
                CandidateValue::Ip(ip) => candidate_ips.push(ip),
            }
        }
        self.seed_and_sweep(
            candidate_ips,
            has_domain_target,
            st.visited,
            st.findings,
            st.sink,
        )
        .await;

        // Confirm the deferred brute-force candidates against the apex wildcard
        // set; only non-wildcard hits are recorded and queued.
        for cand in self.confirm_hosts(bf_candidates, wildcard_ips).await {
            let key = CandidateValue::Host(cand.clone());
            if st.visited.insert_new(&key) {
                st.findings.hosts.insert(cand.clone());
                (st.sink)(FindingEvent::Host(cand.clone(), "bruteforce".into()));
                host_queue.push(cand);
            }
        }

        host_queue
    }

    /// AXFR: in active/both mode, attempt a full zone transfer against each
    /// authoritative NS of the apex. Almost always refused, but a misconfigured
    /// server occasionally dumps the entire zone. Every dumped record is
    /// recorded; its owner name is queued as a discovered host and any address
    /// value is enriched.
    async fn attempt_axfr(
        &self,
        apex: &Option<String>,
        has_domain_target: bool,
        host_queue: &mut Vec<String>,
        st: &mut RunState<'_>,
    ) {
        if let (Some(apex_name), true) = (apex, self.source_enabled(SourceKind::Active)) {
            (st.sink)(FindingEvent::SourceRun("axfr"));
            self.progress_phase("attempting AXFR zone transfer".to_string());
            let ns_records = self.resolver.resolve(apex_name, &[RecordType::Ns]).await;
            // Attempt the transfer against every nameserver concurrently (each
            // call also fans out across that nameserver's IPs). The slow network
            // work runs in parallel here; the dumps are then folded into findings
            // sequentially below so all state mutation stays single-threaded.
            let dumps = futures::future::join_all(ns_records.iter().map(|ns| async move {
                (
                    ns.value.clone(),
                    self.resolver.axfr(&ns.value, apex_name).await,
                )
            }))
            .await;
            let mut axfr_ips: Vec<IpAddr> = Vec::new();
            for (ns_value, dump) in dumps {
                if !dump.is_empty() {
                    (st.sink)(FindingEvent::AxfrSuccess(ns_value.clone(), dump.len()));
                    st.findings.axfr.push(AxfrTransfer {
                        ns: ns_value.clone(),
                        records: dump.len(),
                    });
                }
                for rec in dump {
                    (st.sink)(FindingEvent::Record(rec.clone()));
                    st.findings.records.push(rec.clone());
                    if is_valid_hostname(&rec.name)
                        && st
                            .visited
                            .insert_new(&CandidateValue::Host(rec.name.clone()))
                    {
                        st.findings.hosts.insert(rec.name.clone());
                        (st.sink)(FindingEvent::Host(rec.name.clone(), "axfr".into()));
                        host_queue.push(rec.name.clone());
                    }
                    if let Ok(ip) = rec.value.parse::<IpAddr>() {
                        axfr_ips.push(ip);
                    }
                }
            }
            self.seed_and_sweep(
                axfr_ips,
                has_domain_target,
                st.visited,
                st.findings,
                st.sink,
            )
            .await;
        }
    }

    /// Resolve each queued host and recurse brute force up to depth. Resolution
    /// within a round runs concurrently; all mutation of shared state happens
    /// afterward in a sequential loop. Wildcard sets are detected once per base
    /// name and cached, with the apex set seeded here.
    async fn resolve_and_recurse(
        &self,
        host_queue: Vec<String>,
        apex: &Option<String>,
        wildcard_ips: &HashSet<String>,
        has_domain_target: bool,
        st: &mut RunState<'_>,
    ) {
        let mut wildcard_cache: HashMap<String, HashSet<String>> = HashMap::new();
        if let Some(a) = apex {
            wildcard_cache.insert(a.clone(), wildcard_ips.clone());
        }

        let mut depth_hosts = host_queue;
        for round in 0.. {
            if depth_hosts.is_empty() {
                break;
            }

            let hosts_this_round = std::mem::take(&mut depth_hosts);
            self.progress_phase(format!(
                "resolving {} hosts (round {})",
                hosts_this_round.len(),
                round + 1
            ));
            let results: Vec<(String, Vec<DnsRecord>)> = stream::iter(hosts_this_round)
                .map(|h| {
                    let resolver = self.resolver.clone();
                    let types = self.opts.record_types.clone();
                    let pb = self.progress.clone();
                    async move {
                        let recs = resolver.resolve(&h, &types).await;
                        if let Some(pb) = &pb {
                            pb.inc(1);
                        }
                        (h, recs)
                    }
                })
                .buffer_unordered(self.opts.concurrency.max(1))
                .collect()
                .await;

            let mut round_hosts: Vec<String> = Vec::new();
            let mut round_ips: Vec<IpAddr> = Vec::new();
            for (host, recs) in results {
                round_hosts.push(host);
                for r in &recs {
                    // A record whose value is a wildcard answer is not a real
                    // finding, in any mode: drop it rather than record or enrich.
                    // The wildcard set holds both wildcard IPs and wildcard CNAME
                    // targets, so this one check suppresses either kind.
                    if wildcard_ips.contains(&r.value) {
                        continue;
                    }
                    if let Ok(ip) = r.value.parse::<IpAddr>() {
                        round_ips.push(ip);
                    }
                    (st.sink)(FindingEvent::Record(r.clone()));
                    st.findings.records.push(r.clone());
                }
            }
            self.seed_and_sweep(
                round_ips,
                has_domain_target,
                st.visited,
                st.findings,
                st.sink,
            )
            .await;

            // Recurse: brute-force under this round's hosts if active and depth remains.
            let mut next: Vec<String> = Vec::new();
            if self.source_enabled(SourceKind::Active)
                && (round as i64) < i64::from(self.opts.depth.saturating_sub(1))
                && !self.opts.words.is_empty()
            {
                // Detect and cache each base's own wildcard set before brute
                // forcing under it, so a subdomain wildcard does not cause false
                // positives.
                for h in &round_hosts {
                    if !wildcard_cache.contains_key(h) {
                        let wc = detect_wildcard(self.resolver.as_ref(), h).await;
                        wildcard_cache.insert(h.clone(), wc);
                    }
                }

                let all_candidates: Vec<(String, String)> = round_hosts
                    .iter()
                    .flat_map(|h| {
                        let base = h.clone();
                        generate_fqdns(&self.opts.words, h)
                            .into_iter()
                            .map(move |c| (c, base.clone()))
                    })
                    .collect();

                self.progress_phase(format!(
                    "brute-forcing {} candidates (round {})",
                    all_candidates.len(),
                    round + 1
                ));
                let bf_results: Vec<(String, String, Vec<DnsRecord>)> =
                    stream::iter(all_candidates)
                        .map(|(cand, base)| {
                            let resolver = self.resolver.clone();
                            let pb = self.progress.clone();
                            async move {
                                // Query AAAA alongside A so an IPv6-only host is confirmed.
                                let hits = resolver
                                    .resolve(&cand, &[RecordType::A, RecordType::Aaaa])
                                    .await;
                                if let Some(pb) = &pb {
                                    pb.inc(1);
                                }
                                (cand, base, hits)
                            }
                        })
                        .buffer_unordered(self.opts.concurrency.max(1))
                        .collect()
                        .await;

                for (cand, base, hits) in bf_results {
                    let key = CandidateValue::Host(cand.clone());
                    // Filter against the base's own wildcard set unioned with the apex set.
                    let base_wc = wildcard_cache.get(&base);
                    let real = hits.iter().any(|r| {
                        !wildcard_ips.contains(&r.value)
                            && base_wc.is_none_or(|wc| !wc.contains(&r.value))
                    });
                    if real && st.visited.insert_new(&key) {
                        st.findings.hosts.insert(cand.clone());
                        (st.sink)(FindingEvent::Host(cand.clone(), "bruteforce".into()));
                        next.push(cand);
                    }
                }
            }

            depth_hosts = next;
        }
    }

    /// Permutation pass (opt-in, active/both only): altdns-style alterations of
    /// every host discovered above, confirmed against the apex wildcard set. One
    /// non-recursive pass, so a large host set does not explode.
    async fn permutation_pass(
        &self,
        apex: &Option<String>,
        wildcard_ips: &HashSet<String>,
        has_domain_target: bool,
        st: &mut RunState<'_>,
    ) {
        if self.opts.features.permutations
            && self.source_enabled(SourceKind::Active)
            && !self.opts.words.is_empty()
        {
            if let Some(apex_name) = apex {
                let known: Vec<String> = st.findings.hosts.iter().cloned().collect();
                let candidates = generate_permutations(&known, &self.opts.words, apex_name);
                let confirmed = self.confirm_hosts(candidates, wildcard_ips).await;

                let mut perm_hosts: Vec<String> = Vec::new();
                for cand in confirmed {
                    if st.visited.insert_new(&CandidateValue::Host(cand.clone())) {
                        st.findings.hosts.insert(cand.clone());
                        (st.sink)(FindingEvent::Host(cand.clone(), "permutation".into()));
                        perm_hosts.push(cand);
                    }
                }

                if !perm_hosts.is_empty() {
                    self.progress_phase(format!("resolving {} permutation hits", perm_hosts.len()));
                    let results: Vec<(String, Vec<DnsRecord>)> = stream::iter(perm_hosts)
                        .map(|h| {
                            let resolver = self.resolver.clone();
                            let types = self.opts.record_types.clone();
                            let pb = self.progress.clone();
                            async move {
                                let recs = resolver.resolve(&h, &types).await;
                                if let Some(pb) = &pb {
                                    pb.inc(1);
                                }
                                (h, recs)
                            }
                        })
                        .buffer_unordered(self.opts.concurrency.max(1))
                        .collect()
                        .await;

                    let mut perm_ips: Vec<IpAddr> = Vec::new();
                    for (_host, recs) in results {
                        for r in &recs {
                            // Drop any wildcard answer, whether IP or CNAME target.
                            if wildcard_ips.contains(&r.value) {
                                continue;
                            }
                            if let Ok(ip) = r.value.parse::<IpAddr>() {
                                perm_ips.push(ip);
                            }
                            (st.sink)(FindingEvent::Record(r.clone()));
                            st.findings.records.push(r.clone());
                        }
                    }
                    self.seed_and_sweep(
                        perm_ips,
                        has_domain_target,
                        st.visited,
                        st.findings,
                        st.sink,
                    )
                    .await;
                }
            }
        }
    }

    /// Takeover pass (opt-in): inspect discovered CNAMEs for dangling pointers to
    /// unclaimed third-party services. Runs in every mode since it only reads
    /// already-discovered records.
    async fn takeover_pass(&self, st: &mut RunState<'_>) {
        if self.opts.features.takeover {
            for t in self.detect_takeovers(&st.findings.records).await {
                (st.sink)(FindingEvent::Takeover(t.clone()));
                st.findings.takeovers.push(t);
            }
        }
    }

    /// Probe pass (opt-in): over every discovered host, capture the HTTP status,
    /// page title, and final URL after redirects, plus the leaf TLS certificate's
    /// SAN dNSNames. Runs in every mode since it only reads already-discovered
    /// hosts. Fully non-fatal: a per-host failure yields a partial or empty
    /// probe. Bounded by opts.concurrency.
    async fn probe_pass(&self, st: &mut RunState<'_>) {
        if self.opts.features.probe {
            let hosts: Vec<String> = st.findings.hosts.iter().cloned().collect();
            if !hosts.is_empty() {
                self.progress_phase(format!("probing {} hosts", hosts.len()));
                let http = crate::sources::http_client().ok();
                let probes: Vec<crate::probe::HostProbe> = stream::iter(hosts)
                    .map(|host| {
                        let http = http.clone();
                        let pb = self.progress.clone();
                        async move {
                            let mut p = match &http {
                                Some(client) => crate::probe::probe_host(client, &host).await,
                                None => crate::probe::HostProbe {
                                    host: host.clone(),
                                    status: None,
                                    title: None,
                                    final_url: None,
                                    tls_sans: Vec::new(),
                                },
                            };
                            p.tls_sans = crate::probe::tls_san_dns_names(&host).await;
                            if let Some(pb) = &pb {
                                pb.inc(1);
                            }
                            p
                        }
                    })
                    .buffer_unordered(self.opts.concurrency.max(1))
                    .collect()
                    .await;

                for p in probes {
                    (st.sink)(FindingEvent::Probe(p.clone()));
                    st.findings.probes.push(p);
                }
            }
        }
    }

    pub async fn run(&self, targets: &[Target], sink: &mut dyn FnMut(FindingEvent)) -> Findings {
        let mut findings = Findings::default();
        let mut visited = Visited::new();

        // Seed the visited set with hosts carried over from a prior run
        // (--resume) so they are treated as already seen: not re-emitted as
        // findings and not recursed into.
        for h in &self.opts.known_hosts {
            visited.insert_new(&CandidateValue::Host(h.clone()));
        }

        let inactive = self.active_domains(targets, sink).await;

        // The apex and the in-scope suffixes are drawn from the active domain
        // targets only; inactive domains are excluded so nothing keys off a dead
        // target.
        let apex: Option<String> = targets.iter().find_map(|t| match t {
            Target::Domain(d) if !inactive.contains(d) => Some(d.clone()),
            _ => None,
        });
        let domains: Vec<String> = targets
            .iter()
            .filter_map(|t| match t {
                Target::Domain(d) if !inactive.contains(d) => Some(d.clone()),
                _ => None,
            })
            .collect();
        let has_domain_target = !domains.is_empty();

        let mut st = RunState {
            visited: &mut visited,
            findings: &mut findings,
            sink,
        };

        self.seed_targets(targets, has_domain_target, &mut st).await;

        // Wildcard detection runs in EVERY mode (not just active): a domain with
        // a catch-all record makes every name "resolve" to the same address, so
        // without this a passive scan would record wildcard IPs as real findings
        // and enrich them. The set is used to suppress those records below.
        let wildcard_ips: HashSet<String> = match &apex {
            Some(a) => detect_wildcard(self.resolver.as_ref(), a).await,
            None => HashSet::new(),
        };

        let mut host_queue = self
            .collect_candidates(
                targets,
                &inactive,
                &domains,
                has_domain_target,
                &wildcard_ips,
                &mut st,
            )
            .await;

        self.attempt_axfr(&apex, has_domain_target, &mut host_queue, &mut st)
            .await;

        self.resolve_and_recurse(host_queue, &apex, &wildcard_ips, has_domain_target, &mut st)
            .await;

        self.permutation_pass(&apex, &wildcard_ips, has_domain_target, &mut st)
            .await;

        self.takeover_pass(&mut st).await;

        self.probe_pass(&mut st).await;

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::model::{Candidate, CandidateValue, DnsRecord, RecordType, Target};
    use crate::resolve::Resolver;
    use crate::sources::{Source, SourceKind};
    use std::net::IpAddr;
    use std::sync::Arc;

    #[test]
    fn body_marker_predicate_matches_only_on_marker() {
        assert!(body_indicates_unclaimed(
            "... No such app ...",
            "No such app"
        ));
        assert!(!body_indicates_unclaimed(
            "a normal landing page",
            "No such app"
        ));
        // An empty marker never matches, so an nxdomain-only fingerprint cannot
        // be confirmed by the body path.
        assert!(!body_indicates_unclaimed("anything at all", ""));
    }

    struct OneHostSource;
    #[async_trait::async_trait]
    impl Source for OneHostSource {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _c: &Config) -> bool {
            true
        }
        async fn run(
            &self,
            _t: &Target,
            tx: tokio::sync::mpsc::Sender<Candidate>,
        ) -> anyhow::Result<()> {
            tx.send(Candidate {
                value: CandidateValue::Host("dev.example.com".into()),
                source: "mock".into(),
            })
            .await
            .ok();
            Ok(())
        }
    }

    // Emits one real host name and two certificate-SAN shapes that are not
    // host names, exactly as crt.sh does. Only the real host must survive.
    struct JunkAndRealSource;
    #[async_trait::async_trait]
    impl Source for JunkAndRealSource {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _c: &Config) -> bool {
            true
        }
        async fn run(
            &self,
            _t: &Target,
            tx: tokio::sync::mpsc::Sender<Candidate>,
        ) -> anyhow::Result<()> {
            for h in [
                "dev.example.com",
                "user@example.com",
                "a test cert - example.com",
            ] {
                tx.send(Candidate {
                    value: CandidateValue::Host(h.into()),
                    source: "mock".into(),
                })
                .await
                .ok();
            }
            Ok(())
        }
    }

    // Emits an in-scope host and an unrelated domain co-listed on a shared cert.
    struct InAndOutOfScopeSource;
    #[async_trait::async_trait]
    impl Source for InAndOutOfScopeSource {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _c: &Config) -> bool {
            true
        }
        async fn run(
            &self,
            _t: &Target,
            tx: tokio::sync::mpsc::Sender<Candidate>,
        ) -> anyhow::Result<()> {
            for h in ["dev.example.com", "unrelated.twitter.com"] {
                tx.send(Candidate {
                    value: CandidateValue::Host(h.into()),
                    source: "mock".into(),
                })
                .await
                .ok();
            }
            Ok(())
        }
    }

    struct StubResolver;
    #[async_trait::async_trait]
    impl Resolver for StubResolver {
        async fn resolve(&self, name: &str, _t: &[RecordType]) -> Vec<DnsRecord> {
            // Simulate a non-wildcard domain: the random wildcard probe name
            // resolves to nothing, everything else to a fixed address.
            if name.starts_with("dnsrustcon-") {
                return Vec::new();
            }
            vec![DnsRecord {
                name: name.into(),
                rtype: RecordType::A,
                value: "1.2.3.4".into(),
            }]
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            Some("h.example".into())
        }
        async fn txt(&self, name: &str) -> Vec<String> {
            if name.ends_with("origin.asn.cymru.com") {
                vec!["15169 | 1.2.3.0/24 | US | arin | 1992".into()]
            } else if name.ends_with("asn.cymru.com") {
                vec!["15169 | US | arin | 1992 | GOOGLE, US".into()]
            } else {
                vec![]
            }
        }
    }

    #[tokio::test]
    async fn passive_run_collects_host_record_and_ip() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            vec![Box::new(OneHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        assert!(findings.hosts.contains("dev.example.com"));
        assert!(findings.records.iter().any(|r| r.value == "1.2.3.4"));
        assert_eq!(findings.ips.len(), 1);
        assert_eq!(findings.ips[0].asn, Some(15169));
    }

    #[tokio::test]
    async fn discards_non_hostname_candidates() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            vec![Box::new(JunkAndRealSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        assert!(findings.hosts.contains("dev.example.com"));
        assert!(!findings.hosts.contains("user@example.com"));
        assert_eq!(findings.hosts.len(), 1);
    }

    #[tokio::test]
    async fn drops_out_of_scope_hosts() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            vec![Box::new(InAndOutOfScopeSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        assert!(findings.hosts.contains("dev.example.com"));
        assert!(!findings.hosts.contains("unrelated.twitter.com"));
        assert_eq!(findings.hosts.len(), 1);
    }

    #[tokio::test]
    async fn out_of_scope_kept_when_scope_disabled() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: false,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            vec![Box::new(InAndOutOfScopeSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        assert!(findings.hosts.contains("unrelated.twitter.com"));
    }

    // In active/both mode, only brute-force candidates that actually resolve to a
    // non-wildcard address may be recorded; non-resolving wordlist entries must
    // not appear in findings.
    struct SelectiveResolver;
    #[async_trait::async_trait]
    impl Resolver for SelectiveResolver {
        async fn resolve(&self, name: &str, types: &[RecordType]) -> Vec<DnsRecord> {
            // Answer the active-domain pre-check so the apex is not skipped.
            if types.contains(&RecordType::Ns) && name == "example.com" {
                return vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Ns,
                    value: "ns1.example.com.".into(),
                }];
            }
            if name == "www.example.com" {
                vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::A,
                    value: "1.2.3.4".into(),
                }]
            } else {
                Vec::new()
            }
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            None
        }
        async fn txt(&self, _name: &str) -> Vec<String> {
            Vec::new()
        }
    }

    #[tokio::test]
    async fn active_brute_force_records_only_resolving_hosts() {
        let words = vec!["www".to_string(), "nonexistent-zzz".to_string()];
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: words.clone(),
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Active,
            Arc::new(SelectiveResolver),
            vec![Box::new(crate::sources::bruteforce::BruteForce { words })],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        assert!(findings.hosts.contains("www.example.com"));
        assert!(!findings.hosts.contains("nonexistent-zzz.example.com"));
        assert_eq!(findings.hosts.len(), 1);
    }

    // Permutation pass: a discovered host (dev.example.com) plus the word "api"
    // must produce and confirm api-dev.example.com when it resolves, recording
    // both the host and its A record. Only that permutation resolves here.
    struct PermResolver;
    #[async_trait::async_trait]
    impl Resolver for PermResolver {
        async fn resolve(&self, name: &str, types: &[RecordType]) -> Vec<DnsRecord> {
            // Answer the active-domain pre-check so the apex is not skipped.
            if types.contains(&RecordType::Ns) && name == "example.com" {
                return vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Ns,
                    value: "ns1.example.com.".into(),
                }];
            }
            match name {
                "dev.example.com" => vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::A,
                    value: "1.2.3.4".into(),
                }],
                "api-dev.example.com" => vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::A,
                    value: "5.6.7.8".into(),
                }],
                _ => Vec::new(),
            }
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            None
        }
        async fn txt(&self, _name: &str) -> Vec<String> {
            Vec::new()
        }
    }

    #[tokio::test]
    async fn permutation_pass_confirms_altered_hosts() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec!["api".to_string()],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: true,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Both,
            Arc::new(PermResolver),
            vec![Box::new(OneHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        assert!(findings.hosts.contains("dev.example.com"));
        assert!(findings.hosts.contains("api-dev.example.com"));
        assert!(findings.records.iter().any(|r| r.value == "5.6.7.8"));
    }

    // Takeover: a host whose CNAME points at an Azure endpoint whose target does
    // not resolve is flagged (the Azure fingerprint treats a dangling target as
    // sufficient evidence, so no HTTP fetch is needed and the test stays offline).
    struct GoneHostSource;
    #[async_trait::async_trait]
    impl Source for GoneHostSource {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _c: &Config) -> bool {
            true
        }
        async fn run(
            &self,
            _t: &Target,
            tx: tokio::sync::mpsc::Sender<Candidate>,
        ) -> anyhow::Result<()> {
            tx.send(Candidate {
                value: CandidateValue::Host("gone.example.com".into()),
                source: "mock".into(),
            })
            .await
            .ok();
            Ok(())
        }
    }

    struct TakeoverResolver;
    #[async_trait::async_trait]
    impl Resolver for TakeoverResolver {
        async fn resolve(&self, name: &str, types: &[RecordType]) -> Vec<DnsRecord> {
            // Answer the active-domain pre-check so the apex is not skipped.
            if types.contains(&RecordType::Ns) && name == "example.com" {
                return vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Ns,
                    value: "ns1.example.com.".into(),
                }];
            }
            // Second signal: the Azure base zone still resolves, so a dangling
            // trafficmanager.net target is a genuine reclaimable resource.
            if types.contains(&RecordType::Ns) && name == "trafficmanager.net" {
                return vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Ns,
                    value: "ns1-01.azure-dns.com.".into(),
                }];
            }
            if name == "gone.example.com" {
                vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Cname,
                    value: "myapp.trafficmanager.net.".into(),
                }]
            } else {
                // The CNAME target and the wildcard probe both fail to resolve.
                Vec::new()
            }
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            None
        }
        async fn txt(&self, _name: &str) -> Vec<String> {
            Vec::new()
        }
    }

    #[tokio::test]
    async fn flags_dangling_cname_takeover() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::Cname],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: true,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(TakeoverResolver),
            vec![Box::new(GoneHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        assert_eq!(findings.takeovers.len(), 1);
        let t = &findings.takeovers[0];
        assert_eq!(t.host, "gone.example.com");
        assert_eq!(t.service, "Azure");
    }

    // Negative case for the Azure second signal: the CNAME target is still
    // dangling, but the trafficmanager.net base zone itself does not resolve, so
    // this looks like a service-wide or transient failure rather than a
    // reclaimable resource. No takeover may be flagged.
    struct BaseGoneTakeoverResolver;
    #[async_trait::async_trait]
    impl Resolver for BaseGoneTakeoverResolver {
        async fn resolve(&self, name: &str, types: &[RecordType]) -> Vec<DnsRecord> {
            // Answer the active-domain pre-check so the apex is not skipped.
            if types.contains(&RecordType::Ns) && name == "example.com" {
                return vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Ns,
                    value: "ns1.example.com.".into(),
                }];
            }
            if name == "gone.example.com" {
                vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Cname,
                    value: "myapp.trafficmanager.net.".into(),
                }]
            } else {
                // The CNAME target, the trafficmanager.net base zone, and the
                // wildcard probe all fail to resolve.
                Vec::new()
            }
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            None
        }
        async fn txt(&self, _name: &str) -> Vec<String> {
            Vec::new()
        }
    }

    #[tokio::test]
    async fn skips_takeover_when_base_domain_dead() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::Cname],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: true,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(BaseGoneTakeoverResolver),
            vec![Box::new(GoneHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        assert!(findings.takeovers.is_empty());
    }

    #[tokio::test]
    async fn reverse_sweeps_domain_24() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: true,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            vec![Box::new(OneHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        assert!(findings.ips.len() > 1);
        let neighbor: IpAddr = "1.2.3.1".parse().unwrap();
        assert!(findings.ips.iter().any(|i| i.ip == neighbor));
    }

    // The resolved host's Cymru prefix is a /28 (1.2.3.0/28) rather than a /24.
    // With --sweep-prefix set, the sweep must widen to that /28, not stay on the
    // /24.
    struct PrefixStubResolver;
    #[async_trait::async_trait]
    impl Resolver for PrefixStubResolver {
        async fn resolve(&self, name: &str, _t: &[RecordType]) -> Vec<DnsRecord> {
            if name.starts_with("dnsrustcon-") {
                return Vec::new();
            }
            vec![DnsRecord {
                name: name.into(),
                rtype: RecordType::A,
                value: "1.2.3.5".into(),
            }]
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            Some("h.example".into())
        }
        async fn txt(&self, name: &str) -> Vec<String> {
            if name.ends_with("origin.asn.cymru.com") {
                vec!["15169 | 1.2.3.0/28 | US | arin | 1992".into()]
            } else if name.ends_with("asn.cymru.com") {
                vec!["15169 | US | arin | 1992 | GOOGLE, US".into()]
            } else {
                vec![]
            }
        }
    }

    #[tokio::test]
    async fn sweep_prefix_widens_to_asn_prefix_not_24() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: true,
                sweep_prefix: true,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(PrefixStubResolver),
            vec![Box::new(OneHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;
        let in_prefix: IpAddr = "1.2.3.1".parse().unwrap();
        let outside_prefix: IpAddr = "1.2.3.100".parse().unwrap();
        assert!(findings.ips.iter().any(|i| i.ip == in_prefix));
        assert!(!findings.ips.iter().any(|i| i.ip == outside_prefix));
    }

    // An explicit IP target must be enriched even in the default passive mode.
    #[tokio::test]
    async fn passive_mode_enriches_explicit_ip_target() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            Vec::new(),
            Config::default(),
            opts,
            None,
            None,
        );
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut events = Vec::new();
        let findings = engine.run(&[Target::Ip(ip)], &mut |e| events.push(e)).await;
        let info = findings
            .ips
            .iter()
            .find(|i| i.ip == ip)
            .expect("ip target must be enriched");
        assert_eq!(info.asn, Some(15169));
        assert_eq!(info.ptr.as_deref(), Some("h.example"));
    }

    // An explicit CIDR target must also be enriched host by host in passive mode.
    #[tokio::test]
    async fn passive_mode_enriches_explicit_cidr_target() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            Vec::new(),
            Config::default(),
            opts,
            None,
            None,
        );
        let net: ipnet::IpNet = "192.0.2.0/30".parse().unwrap();
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Cidr(net)], &mut |e| events.push(e))
            .await;
        assert_eq!(findings.ips.len(), 2);
    }

    // A source enabled by the mode but unavailable must emit SourceSkipped; an
    // available one must emit SourceRun before it runs.
    struct AvailableMockSource;
    #[async_trait::async_trait]
    impl Source for AvailableMockSource {
        fn name(&self) -> &'static str {
            "avail-mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _c: &Config) -> bool {
            true
        }
        async fn run(
            &self,
            _t: &Target,
            _tx: tokio::sync::mpsc::Sender<Candidate>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct UnavailableMockSource;
    #[async_trait::async_trait]
    impl Source for UnavailableMockSource {
        fn name(&self) -> &'static str {
            "unavail-mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _c: &Config) -> bool {
            false
        }
        async fn run(
            &self,
            _t: &Target,
            _tx: tokio::sync::mpsc::Sender<Candidate>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn emits_source_run_and_skipped_events() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            vec![
                Box::new(AvailableMockSource),
                Box::new(UnavailableMockSource),
            ],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let _ = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;

        assert!(events
            .iter()
            .any(|e| matches!(e, FindingEvent::SourceRun(name) if *name == "avail-mock")));
        assert!(events
            .iter()
            .any(|e| matches!(e, FindingEvent::SourceSkipped(name, reason)
            if *name == "unavail-mock" && *reason == "unavailable")));
    }

    // AXFR: in active mode, a name server that answers the transfer dumps the
    // zone. Every dumped record is recorded, its owner name becomes a
    // discovered host, and address values are enriched. The resolver's default
    // axfr() returns empty, so this stub overrides it to simulate a permissive
    // NS while keeping the suite off the network.
    struct AxfrResolver;
    #[async_trait::async_trait]
    impl Resolver for AxfrResolver {
        async fn resolve(&self, name: &str, types: &[RecordType]) -> Vec<DnsRecord> {
            if types.contains(&RecordType::Ns) && name == "example.com" {
                vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Ns,
                    value: "ns1.example.com.".into(),
                }]
            } else {
                Vec::new()
            }
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            None
        }
        async fn txt(&self, _name: &str) -> Vec<String> {
            Vec::new()
        }
        async fn axfr(&self, ns: &str, zone: &str) -> Vec<DnsRecord> {
            if ns == "ns1.example.com." && zone == "example.com" {
                vec![
                    DnsRecord {
                        name: "internal.example.com".into(),
                        rtype: RecordType::A,
                        value: "10.0.0.5".into(),
                    },
                    DnsRecord {
                        name: "vpn.example.com".into(),
                        rtype: RecordType::Cname,
                        value: "internal.example.com".into(),
                    },
                ]
            } else {
                Vec::new()
            }
        }
    }

    #[tokio::test]
    async fn active_mode_ingests_axfr_zone_dump() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Active,
            Arc::new(AxfrResolver),
            Vec::new(),
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;

        assert!(findings.hosts.contains("internal.example.com"));
        assert!(findings.hosts.contains("vpn.example.com"));
        assert!(findings
            .records
            .iter()
            .any(|r| r.value == "10.0.0.5" && r.rtype == RecordType::A));
        let dumped_ip: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(findings.ips.iter().any(|i| i.ip == dumped_ip));

        assert_eq!(findings.axfr.len(), 1);
        assert!(findings.axfr[0].records >= 1);
        assert!(events
            .iter()
            .any(|e| matches!(e, FindingEvent::AxfrSuccess(_, n) if *n >= 1)));
    }

    // In passive mode AXFR must not run: no NS lookup, no transfer, no records.
    #[tokio::test]
    async fn passive_mode_skips_axfr() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(AxfrResolver),
            Vec::new(),
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;

        assert!(findings.hosts.is_empty());
        assert!(findings.records.is_empty());
    }

    // --resume: a host seeded into known_hosts is treated as already seen, so it
    // must not reappear in findings, while a fresh host from the same source
    // still does.
    struct TwoHostSource;
    #[async_trait::async_trait]
    impl Source for TwoHostSource {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _c: &Config) -> bool {
            true
        }
        async fn run(
            &self,
            _t: &Target,
            tx: tokio::sync::mpsc::Sender<Candidate>,
        ) -> anyhow::Result<()> {
            for h in ["old.example.com", "new.example.com"] {
                tx.send(Candidate {
                    value: CandidateValue::Host(h.into()),
                    source: "mock".into(),
                })
                .await
                .ok();
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn resume_skips_known_hosts() {
        let mut known = HashSet::new();
        known.insert("old.example.com".to_string());
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: known,
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            vec![Box::new(TwoHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;

        assert!(!findings.hosts.contains("old.example.com"));
        assert!(findings.hosts.contains("new.example.com"));
    }

    // Probe pass: with probe enabled, every discovered host yields one
    // HostProbe. The suite runs offline so the HTTP and TLS probes just fail,
    // producing empty probes; the pass must still complete without panicking
    // and emit one probe per host.
    #[tokio::test]
    async fn probe_pass_yields_one_probe_per_host() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: true,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            vec![Box::new(OneHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;

        assert_eq!(findings.probes.len(), findings.hosts.len());
        assert!(findings.probes.iter().any(|p| p.host == "dev.example.com"));
        assert!(events.iter().any(|e| matches!(e, FindingEvent::Probe(_))));
    }

    // Wildcard CNAME: the random wildcard probe returns a parking CNAME, and a
    // discovered host inherits that same CNAME. That record must be suppressed
    // (it is a catch-all answer, not a real finding), while a host with a
    // distinct real record survives.
    struct WildCnameSource;
    #[async_trait::async_trait]
    impl Source for WildCnameSource {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _c: &Config) -> bool {
            true
        }
        async fn run(
            &self,
            _t: &Target,
            tx: tokio::sync::mpsc::Sender<Candidate>,
        ) -> anyhow::Result<()> {
            for h in ["wild.example.com", "real.example.com"] {
                tx.send(Candidate {
                    value: CandidateValue::Host(h.into()),
                    source: "mock".into(),
                })
                .await
                .ok();
            }
            Ok(())
        }
    }

    struct WildcardCnameResolver;
    #[async_trait::async_trait]
    impl Resolver for WildcardCnameResolver {
        async fn resolve(&self, name: &str, types: &[RecordType]) -> Vec<DnsRecord> {
            if types.contains(&RecordType::Ns) && name == "example.com" {
                return vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Ns,
                    value: "ns1.example.com.".into(),
                }];
            }
            // The wildcard probe and any wildcard-inheriting host both answer with
            // the same parking CNAME target.
            if name.starts_with("dnsrustcon-") || name == "wild.example.com" {
                return vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::Cname,
                    value: "parking.example-cdn.net.".into(),
                }];
            }
            if name == "real.example.com" {
                return vec![DnsRecord {
                    name: name.into(),
                    rtype: RecordType::A,
                    value: "9.9.9.9".into(),
                }];
            }
            Vec::new()
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            None
        }
        async fn txt(&self, _name: &str) -> Vec<String> {
            Vec::new()
        }
    }

    #[tokio::test]
    async fn wildcard_cname_is_suppressed() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A, RecordType::Cname],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(WildcardCnameResolver),
            vec![Box::new(WildCnameSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;

        // The wildcard CNAME must not survive as a record.
        assert!(!findings
            .records
            .iter()
            .any(|r| r.value == "parking.example-cdn.net."));
        // A host with a distinct real record still survives.
        assert!(findings.records.iter().any(|r| r.value == "9.9.9.9"));
    }

    // Active-domain pre-check: a domain that returns neither NS nor SOA is
    // inactive and skipped, so a source that would emit a host never runs and
    // findings stay empty. A DomainInactive event is emitted.
    struct DeadDomainResolver;
    #[async_trait::async_trait]
    impl Resolver for DeadDomainResolver {
        async fn resolve(&self, _name: &str, _t: &[RecordType]) -> Vec<DnsRecord> {
            Vec::new()
        }
        async fn ptr(&self, _ip: IpAddr) -> Option<String> {
            None
        }
        async fn txt(&self, _name: &str) -> Vec<String> {
            Vec::new()
        }
    }

    #[tokio::test]
    async fn inactive_domain_is_skipped() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(DeadDomainResolver),
            vec![Box::new(OneHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("dead.example".into())], &mut |e| {
                events.push(e)
            })
            .await;

        assert!(findings.hosts.is_empty());
        assert!(events
            .iter()
            .any(|e| matches!(e, FindingEvent::DomainInactive(d) if d == "dead.example")));
    }

    // The complement: an active domain (StubResolver answers the NS pre-check)
    // still yields its host and emits no DomainInactive event.
    #[tokio::test]
    async fn active_domain_still_yields_host() {
        let opts = EngineOpts {
            depth: 1,
            concurrency: 4,
            record_types: vec![RecordType::A],
            words: vec![],
            scope: true,
            sweep: SweepOpts {
                reverse: false,
                sweep_prefix: false,
                allow_large_sweep: false,
            },
            features: FeatureOpts {
                permutations: false,
                takeover: false,
                probe: false,
            },
            known_hosts: HashSet::new(),
        };
        let engine = Engine::new(
            crate::cli::Mode::Passive,
            Arc::new(StubResolver),
            vec![Box::new(OneHostSource)],
            Config::default(),
            opts,
            None,
            None,
        );
        let mut events = Vec::new();
        let findings = engine
            .run(&[Target::Domain("example.com".into())], &mut |e| {
                events.push(e)
            })
            .await;

        assert!(findings.hosts.contains("dev.example.com"));
        assert!(!events
            .iter()
            .any(|e| matches!(e, FindingEvent::DomainInactive(_))));
    }
}
