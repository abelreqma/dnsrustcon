use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{Source, SourceKind};
use std::collections::BTreeSet;
use tokio::sync::mpsc::Sender;

/// Parse the CertSpotter issuances response, a JSON array of certificate
/// objects each carrying a `dns_names` array of covered names (some wildcards).
/// Wildcard prefixes are stripped and results deduped; malformed bodies yield
/// an empty list.
pub fn parse_certspotter(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let mut out = BTreeSet::new();
    if let Some(certs) = v.as_array() {
        for cert in certs {
            if let Some(names) = cert.get("dns_names").and_then(|d| d.as_array()) {
                for name in names.iter().filter_map(|n| n.as_str()) {
                    let h = normalize_host(name.trim_start_matches("*."));
                    if !h.is_empty() {
                        out.insert(h);
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

pub struct CertSpotter;

#[async_trait::async_trait]
impl Source for CertSpotter {
    fn name(&self) -> &'static str {
        "certspotter"
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
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        );
        let body = crate::sources::get_text(&crate::sources::http_client()?, &url).await?;
        for host in parse_certspotter(&body) {
            tx.send(Candidate {
                value: CandidateValue::Host(host),
                source: "certspotter".into(),
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
    fn parses_dns_names_and_strips_wildcards() {
        let body = r#"[
            {"dns_names":["example.com","*.example.com"]},
            {"dns_names":["dev.example.com"]}
        ]"#;
        assert_eq!(
            parse_certspotter(body),
            vec!["dev.example.com", "example.com"]
        );
    }

    #[test]
    fn empty_on_garbage() {
        assert!(parse_certspotter("not json").is_empty());
        assert!(parse_certspotter("{}").is_empty());
    }
}
