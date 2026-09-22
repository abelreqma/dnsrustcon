use crate::config::Config;
use crate::model::{Candidate, Target};
use tokio::sync::mpsc::Sender;

pub mod anubis;
pub mod asn;
pub mod bruteforce;
pub mod censys;
pub mod certspotter;
pub mod chaos;
pub mod crtsh;
pub mod dnsdumpster;
pub mod hackertarget;
pub mod otx;
pub mod passivedns;
pub mod rapiddns;
pub mod rdap;
pub mod reverse;
pub mod shodan;
pub mod shodandns;
pub mod subdomaincenter;
pub mod urlscan;
pub mod virustotal;
pub mod wayback;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Passive,
    Active,
}

/// Seconds an HTTP source will wait on a request before giving up. The keyless
/// endpoints (crt.sh, HackerTarget) can be slow, so this is generous rather
/// than tied to --timeout (which governs the far shorter DNS query budget).
const HTTP_TIMEOUT_SECS: u64 = 20;

/// Build once and return a shared HTTP client with a request timeout, so a
/// source can never hang the run on a stalled endpoint. `reqwest::Client` is an
/// Arc over a connection pool, so returning a clone lets every source reuse
/// pooled connections. The `reqwest::Result` signature is kept so existing
/// callers compile unchanged, and a first-build failure is not cached.
pub fn http_client() -> reqwest::Result<reqwest::Client> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
        .user_agent("dnsrustcon")
        .build()?;
    Ok(CLIENT.get_or_init(|| client).clone())
}

/// Process-wide gate that enforces a minimum interval between HTTP requests so
/// the OSINT sources honor the same --rate-limit cap the resolver does. It
/// mirrors the resolver's RateGate.
struct HttpGate {
    next: tokio::sync::Mutex<std::time::Instant>,
    interval: std::time::Duration,
}

impl HttpGate {
    fn new(per_second: u32) -> Self {
        Self {
            next: tokio::sync::Mutex::new(std::time::Instant::now()),
            interval: std::time::Duration::from_secs(1) / per_second,
        }
    }

    async fn wait(&self) {
        // Compute the sleep while briefly holding the lock, then release it
        // before awaiting so the mutex is never held across the await point.
        let wait = {
            let mut next = self.next.lock().await;
            let now = std::time::Instant::now();
            let wait = next.saturating_duration_since(now);
            *next = now.max(*next) + self.interval;
            wait
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// The one HTTP rate gate for the whole run, set at startup from --rate-limit.
/// A stored `None` (flag absent or zero) means no throttling. A OnceLock so all
/// sources' requests share a single gate.
static HTTP_GATE: std::sync::OnceLock<Option<HttpGate>> = std::sync::OnceLock::new();

/// Install the process-wide HTTP rate limiter from the --rate-limit value.
/// `None` or `0` installs no gate, leaving the HTTP sources unthrottled. Called
/// once from main; a later call is ignored since OnceLock keeps the first value.
pub fn init_http_rate_limit(per_second: Option<u32>) {
    let gate = match per_second {
        Some(n) if n > 0 => Some(HttpGate::new(n)),
        _ => None,
    };
    let _ = HTTP_GATE.set(gate);
}

/// Await the shared HTTP gate before a request, if one was installed. A no-op
/// when init_http_rate_limit was never called or installed no gate.
async fn http_throttle() {
    if let Some(Some(gate)) = HTTP_GATE.get() {
        gate.wait().await;
    }
}

/// Number of times a keyless GET is attempted before giving up. The public
/// OSINT endpoints (crt.sh especially) intermittently time out or drop a
/// connection, so one transient failure should not lose a source's whole
/// contribution.
const HTTP_ATTEMPTS: u32 = 3;

/// GET `url` and return the body text, retrying transient transport failures
/// (timeouts, dropped connections) with a short exponential backoff. A non-2xx
/// response is returned to the caller rather than retried, since it is a real
/// answer (e.g. rate limited or not found), not a transport hiccup.
pub async fn get_text(client: &reqwest::Client, url: &str) -> anyhow::Result<String> {
    let mut last_err: Option<reqwest::Error> = None;
    for attempt in 0..HTTP_ATTEMPTS {
        if attempt > 0 {
            let backoff = std::time::Duration::from_millis(250 * (1 << (attempt - 1)));
            tokio::time::sleep(backoff).await;
        }
        http_throttle().await;
        match client.get(url).send().await {
            Ok(resp) => match resp.text().await {
                Ok(body) => return Ok(body),
                Err(e) => last_err = Some(e),
            },
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("at least one attempt was made").into())
}

/// GET `url` with the given request headers, retrying transient transport
/// failures on the same schedule as `get_text`, and hand the whole `Response`
/// back to the caller. Keyed sources need this because they send their API key
/// in a header and must inspect the HTTP status themselves (a bad key or a rate
/// limit is a real error to surface, not a transport hiccup), which `get_text`
/// hides.
pub async fn get_with_headers(
    client: &reqwest::Client,
    url: &str,
    headers: &[(&str, &str)],
) -> anyhow::Result<reqwest::Response> {
    let mut last_err: Option<reqwest::Error> = None;
    for attempt in 0..HTTP_ATTEMPTS {
        if attempt > 0 {
            let backoff = std::time::Duration::from_millis(250 * (1 << (attempt - 1)));
            tokio::time::sleep(backoff).await;
        }
        http_throttle().await;
        let mut req = client.get(url);
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        match req.send().await {
            Ok(resp) => return Ok(resp),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("at least one attempt was made").into())
}

#[async_trait::async_trait]
pub trait Source: Send + Sync {
    fn name(&self) -> &'static str;
    fn kind(&self) -> SourceKind;
    fn available(&self, cfg: &Config) -> bool;
    async fn run(&self, target: &Target, tx: Sender<Candidate>) -> anyhow::Result<()>;
}

/// The discovery source names a user may pass to --sources / --exclude-sources.
/// These are the Source::name() values registered in main.rs; the Shodan and
/// RDAP IP-enrichment providers are not discovery sources and are not listed.
pub const KNOWN_SOURCES: &[&str] = &[
    "crt.sh",
    "hackertarget",
    "otx",
    "anubis",
    "certspotter",
    "wayback",
    "bruteforce",
    "securitytrails",
    "virustotal",
    "shodandns",
    "chaos",
    "dnsdumpster",
    "censys",
    "rapiddns",
    "subdomaincenter",
    "urlscan",
];

/// Which discovery sources to run, derived from --sources / --exclude-sources.
pub enum SourceFilter {
    /// Run only the named sources.
    Only(Vec<String>),
    /// Run every source except the named ones.
    Exclude(Vec<String>),
    /// Run every source (neither flag given).
    All,
}

/// Parse a comma-separated source list, lowercasing and trimming each name and
/// dropping empties. Every remaining name must be a KNOWN_SOURCES value;
/// otherwise this errors listing the unknown name(s) and the valid set.
pub fn parse_source_list(list: &str) -> anyhow::Result<Vec<String>> {
    let names: Vec<String> = list
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let unknown: Vec<String> = names
        .iter()
        .filter(|n| !KNOWN_SOURCES.contains(&n.as_str()))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        anyhow::bail!(
            "unknown source name(s): {}. valid sources: {}",
            unknown.join(", "),
            KNOWN_SOURCES.join(", ")
        );
    }
    Ok(names)
}

/// Retain only the discovery sources selected by `filter`, matching on
/// Source::name() case-insensitively. Names in `filter` are already normalized
/// by parse_source_list.
pub fn apply_source_filter(sources: &mut Vec<Box<dyn Source>>, filter: &SourceFilter) {
    match filter {
        SourceFilter::Only(names) => {
            sources.retain(|s| names.iter().any(|n| n.eq_ignore_ascii_case(s.name())));
        }
        SourceFilter::Exclude(names) => {
            sources.retain(|s| !names.iter().any(|n| n.eq_ignore_ascii_case(s.name())));
        }
        SourceFilter::All => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CandidateValue, Target};

    struct MockSource;

    #[async_trait::async_trait]
    impl Source for MockSource {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _cfg: &crate::config::Config) -> bool {
            true
        }
        async fn run(
            &self,
            _t: &Target,
            tx: tokio::sync::mpsc::Sender<crate::model::Candidate>,
        ) -> anyhow::Result<()> {
            tx.send(crate::model::Candidate {
                value: CandidateValue::Host("dev.example.com".into()),
                source: "mock".into(),
            })
            .await
            .ok();
            Ok(())
        }
    }

    #[tokio::test]
    async fn mock_source_emits_candidate() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let src = MockSource;
        src.run(&Target::Domain("example.com".into()), tx)
            .await
            .unwrap();
        let c = rx.recv().await.unwrap();
        assert_eq!(c.value, CandidateValue::Host("dev.example.com".into()));
    }

    // A source whose name is fixed at construction, so a filter test can build a
    // list with several distinct names.
    struct NamedSource(&'static str);

    #[async_trait::async_trait]
    impl Source for NamedSource {
        fn name(&self) -> &'static str {
            self.0
        }
        fn kind(&self) -> SourceKind {
            SourceKind::Passive
        }
        fn available(&self, _cfg: &crate::config::Config) -> bool {
            true
        }
        async fn run(
            &self,
            _t: &Target,
            _tx: tokio::sync::mpsc::Sender<crate::model::Candidate>,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn names(sources: &[Box<dyn Source>]) -> Vec<&'static str> {
        sources.iter().map(|s| s.name()).collect()
    }

    #[test]
    fn include_list_keeps_only_named() {
        let mut sources: Vec<Box<dyn Source>> = vec![
            Box::new(NamedSource("crt.sh")),
            Box::new(NamedSource("otx")),
            Box::new(NamedSource("bruteforce")),
        ];
        let filter = SourceFilter::Only(parse_source_list("crt.sh,otx").unwrap());
        apply_source_filter(&mut sources, &filter);
        assert_eq!(names(&sources), vec!["crt.sh", "otx"]);
    }

    #[test]
    fn exclude_list_drops_named() {
        let mut sources: Vec<Box<dyn Source>> = vec![
            Box::new(NamedSource("crt.sh")),
            Box::new(NamedSource("otx")),
            Box::new(NamedSource("bruteforce")),
        ];
        let filter = SourceFilter::Exclude(parse_source_list("bruteforce").unwrap());
        apply_source_filter(&mut sources, &filter);
        assert_eq!(names(&sources), vec!["crt.sh", "otx"]);
    }

    #[test]
    fn unknown_source_name_is_rejected() {
        let err = parse_source_list("crt.sh,bogus").unwrap_err().to_string();
        assert!(err.contains("bogus"));
    }

    #[tokio::test]
    async fn http_gate_spaces_out_calls() {
        // At 2/sec, three sequential waits should take at least ~1 second total
        // (the first call is free, the next two each wait ~0.5s). A generous
        // lower bound avoids flakiness from scheduler jitter.
        let gate = HttpGate::new(2);
        let start = std::time::Instant::now();
        gate.wait().await;
        gate.wait().await;
        gate.wait().await;
        assert!(start.elapsed() >= std::time::Duration::from_millis(900));
    }

    #[test]
    fn http_gate_interval_matches_rate() {
        let gate = HttpGate::new(4);
        assert_eq!(gate.interval, std::time::Duration::from_millis(250));
    }

    #[test]
    fn source_list_matching_is_case_insensitive() {
        let mut sources: Vec<Box<dyn Source>> = vec![
            Box::new(NamedSource("crt.sh")),
            Box::new(NamedSource("otx")),
        ];
        let filter = SourceFilter::Only(parse_source_list("CRT.SH").unwrap());
        apply_source_filter(&mut sources, &filter);
        assert_eq!(names(&sources), vec!["crt.sh"]);
    }
}
