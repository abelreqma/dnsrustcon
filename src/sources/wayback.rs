use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{Source, SourceKind};
use std::collections::BTreeSet;
use tokio::sync::mpsc::Sender;

/// Extract the host portion of a URL line from the Wayback CDX output. Lines are
/// full URLs (`http://sub.example.com:8080/path?x=1`); this returns the bare
/// host (`sub.example.com`), dropping scheme, userinfo, port, and path. Returns
/// None when no host can be isolated.
fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = host_port.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Parse the Wayback CDX text response (one archived URL per line) into a
/// deduplicated set of host names.
pub fn parse_wayback(body: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(host) = host_from_url(line) {
            let h = normalize_host(&host);
            if !h.is_empty() {
                out.insert(h);
            }
        }
    }
    out.into_iter().collect()
}

pub struct Wayback;

#[async_trait::async_trait]
impl Source for Wayback {
    fn name(&self) -> &'static str {
        "wayback"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn available(&self, _cfg: &Config) -> bool {
        true
    }

    async fn run(&self, target: &Target, tx: Sender<Candidate>) -> anyhow::Result<()> {
        let domain = match target {
            Target::Domain(d) => d.clone(),
            _ => return Ok(()),
        };
        let url = format!(
            "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
        );
        let body = crate::sources::get_text(&crate::sources::http_client()?, &url).await?;
        for host in parse_wayback(&body) {
            tx.send(Candidate {
                value: CandidateValue::Host(host),
                source: "wayback".into(),
            })
            .await
            .ok();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_hosts_from_urls() {
        let body = "http://dev.example.com/index.html\n\
                    https://api.example.com:8443/v1?x=1\n\
                    http://user@shop.example.com/cart\n";
        assert_eq!(
            parse_wayback(body),
            vec!["api.example.com", "dev.example.com", "shop.example.com"]
        );
    }

    #[test]
    fn empty_on_blank() {
        assert!(parse_wayback("").is_empty());
        assert!(parse_wayback("\n  \n").is_empty());
    }
}
