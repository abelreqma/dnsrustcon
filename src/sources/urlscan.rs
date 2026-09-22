use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{get_text, http_client, Source, SourceKind};
use std::collections::BTreeSet;
use tokio::sync::mpsc::Sender;

/// Parse the urlscan.io search response. The relevant shape is
/// `{"results":[{"page":{"domain":"sub.example.com"},"task":{"domain":"..."}}]}`.
/// Both the page and task domains are collected; unrelated hosts (urlscan
/// surfaces every domain seen on a scanned page) are dropped later by the
/// engine's scope filter. Malformed bodies yield an empty list.
pub fn parse_urlscan(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let mut out = BTreeSet::new();
    if let Some(results) = v.get("results").and_then(|r| r.as_array()) {
        for item in results {
            for section in ["page", "task"] {
                if let Some(d) = item
                    .get(section)
                    .and_then(|p| p.get("domain"))
                    .and_then(|d| d.as_str())
                {
                    let h = normalize_host(d);
                    if !h.is_empty() {
                        out.insert(h);
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

pub struct UrlScan;

#[async_trait::async_trait]
impl Source for UrlScan {
    fn name(&self) -> &'static str {
        "urlscan"
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
        let url = format!("https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100");
        let body = get_text(&http_client()?, &url).await?;
        for host in parse_urlscan(&body) {
            tx.send(Candidate {
                value: CandidateValue::Host(host),
                source: self.name().into(),
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
    fn collects_page_and_task_domains() {
        let body = r#"{"results":[
            {"page":{"domain":"dev.example.com"},"task":{"domain":"api.example.com"}},
            {"page":{"domain":"unrelated.other.com"}}
        ]}"#;
        let mut got = parse_urlscan(body);
        got.sort();
        assert_eq!(
            got,
            vec!["api.example.com", "dev.example.com", "unrelated.other.com"]
        );
    }

    #[test]
    fn empty_on_garbage() {
        assert!(parse_urlscan("not json").is_empty());
        assert!(parse_urlscan(r#"{"results":[]}"#).is_empty());
    }
}
