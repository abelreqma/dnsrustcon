use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{Source, SourceKind};
use std::collections::BTreeSet;
use tokio::sync::mpsc::Sender;

/// Parse the AlienVault OTX passive-DNS response, whose relevant shape is
/// `{"passive_dns":[{"hostname":"sub.example.com", ...}, ...]}`. Malformed or
/// unexpected bodies yield an empty list rather than an error.
pub fn parse_otx(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let mut out = BTreeSet::new();
    if let Some(arr) = v.get("passive_dns").and_then(|p| p.as_array()) {
        for entry in arr {
            if let Some(h) = entry.get("hostname").and_then(|h| h.as_str()) {
                let h = normalize_host(h);
                if !h.is_empty() {
                    out.insert(h);
                }
            }
        }
    }
    out.into_iter().collect()
}

pub struct Otx;

#[async_trait::async_trait]
impl Source for Otx {
    fn name(&self) -> &'static str {
        "otx"
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
        let url =
            format!("https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns");
        let body = crate::sources::get_text(&crate::sources::http_client()?, &url).await?;
        for host in parse_otx(&body) {
            tx.send(Candidate {
                value: CandidateValue::Host(host),
                source: "otx".into(),
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
    fn parses_hostnames_and_dedups() {
        let body = r#"{"passive_dns":[
            {"hostname":"dev.example.com"},
            {"hostname":"API.Example.COM."},
            {"hostname":"dev.example.com"}
        ]}"#;
        assert_eq!(parse_otx(body), vec!["api.example.com", "dev.example.com"]);
    }

    #[test]
    fn empty_on_garbage() {
        assert!(parse_otx("not json").is_empty());
        assert!(parse_otx("{}").is_empty());
    }
}
