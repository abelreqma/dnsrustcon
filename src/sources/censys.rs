use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{http_client, Source, SourceKind};
use std::collections::BTreeSet;
use tokio::sync::mpsc::Sender;

/// Collect every name from result.hits[].names, stripping a leading "*."
/// wildcard label so `*.example.com` becomes `example.com`. Deduplicated.
pub fn parse_censys(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let mut out: BTreeSet<String> = BTreeSet::new();
    if let Some(hits) = v
        .get("result")
        .and_then(|r| r.get("hits"))
        .and_then(|h| h.as_array())
    {
        for hit in hits {
            if let Some(names) = hit.get("names").and_then(|n| n.as_array()) {
                for name in names.iter().filter_map(|n| n.as_str()) {
                    let host = normalize_host(name.trim_start_matches("*."));
                    if !host.is_empty() {
                        out.insert(host);
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

pub struct Censys {
    pub api_id: String,
    pub api_secret: String,
}

#[async_trait::async_trait]
impl Source for Censys {
    fn name(&self) -> &'static str {
        "censys"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn available(&self, _cfg: &Config) -> bool {
        !self.api_id.is_empty() && !self.api_secret.is_empty()
    }

    async fn run(&self, target: &Target, tx: Sender<Candidate>) -> anyhow::Result<()> {
        let domain = match target {
            Target::Domain(d) => d.clone(),
            _ => return Ok(()),
        };

        let client = match http_client() {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };

        // Censys authenticates with HTTP basic auth, which get_with_headers
        // cannot set. Send the request through the shared client (keeping its
        // pooling and User-Agent) with an inline .basic_auth() builder. Both
        // transport and status errors are non-fatal so the run continues on
        // whatever the other sources return.
        let url = format!("https://search.censys.io/api/v2/certificates/search?q=names:{domain}");
        let resp = match client
            .get(&url)
            .basic_auth(&self.api_id, Some(&self.api_secret))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        if !resp.status().is_success() {
            return Ok(());
        }
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };

        for host in parse_censys(&body) {
            let _ = tx
                .send(Candidate {
                    value: CandidateValue::Host(host),
                    source: self.name().into(),
                })
                .await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_names_and_strips_wildcard() {
        let body = r#"{"result":{"hits":[{"names":["a.example.com","*.example.com"]}]}}"#;
        let mut got = parse_censys(body);
        got.sort();
        assert_eq!(got, vec!["a.example.com", "example.com"]);
    }

    #[test]
    fn garbage_returns_empty() {
        assert!(parse_censys("not json").is_empty());
        assert!(parse_censys(r#"{"result":{}}"#).is_empty());
    }
}
