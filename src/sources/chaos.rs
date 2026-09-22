use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{get_with_headers, http_client, Source, SourceKind};
use tokio::sync::mpsc::Sender;

/// Join each entry in the ProjectDiscovery Chaos `subdomains` array with the
/// apex. Chaos returns bare leftmost labels, so the domain is appended here.
pub fn parse_chaos(body: &str, apex: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    v.get("subdomains")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str())
                .filter(|s| !s.is_empty())
                .map(|sub| normalize_host(&format!("{sub}.{apex}")))
                .collect()
        })
        .unwrap_or_default()
}

pub struct Chaos {
    pub key: String,
}

#[async_trait::async_trait]
impl Source for Chaos {
    fn name(&self) -> &'static str {
        "chaos"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Passive
    }
    fn available(&self, _cfg: &Config) -> bool {
        !self.key.is_empty()
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

        let url = format!("https://dns.projectdiscovery.io/dns/{domain}/subdomains");
        let resp =
            match get_with_headers(&client, &url, &[("Authorization", self.key.as_str())]).await {
                Ok(r) => r,
                Err(_) => return Ok(()),
            };
        if !resp.status().is_success() {
            anyhow::bail!("chaos: HTTP {}", resp.status());
        }
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };

        for host in parse_chaos(&body, &domain) {
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
    fn joins_subdomains_with_apex() {
        let body = r#"{"domain":"example.com","subdomains":["www","dev"]}"#;
        let mut got = parse_chaos(body, "example.com");
        got.sort();
        assert_eq!(got, vec!["dev.example.com", "www.example.com"]);
    }

    #[test]
    fn garbage_returns_empty() {
        assert!(parse_chaos("<<not json>>", "example.com").is_empty());
        assert!(parse_chaos("{}", "example.com").is_empty());
    }
}
