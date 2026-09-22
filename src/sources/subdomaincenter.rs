use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{get_text, http_client, Source, SourceKind};
use std::collections::BTreeSet;
use tokio::sync::mpsc::Sender;

/// Parse the subdomain.center response, a flat JSON array of full host names:
/// `["a.example.com", "b.example.com"]`. Malformed bodies yield an empty list.
pub fn parse_subdomaincenter(body: &str) -> Vec<String> {
    let names: Vec<String> = serde_json::from_str(body).unwrap_or_default();
    let mut out = BTreeSet::new();
    for name in names {
        let h = normalize_host(&name);
        if !h.is_empty() {
            out.insert(h);
        }
    }
    out.into_iter().collect()
}

pub struct SubdomainCenter;

#[async_trait::async_trait]
impl Source for SubdomainCenter {
    fn name(&self) -> &'static str {
        "subdomaincenter"
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
        let url = format!("https://api.subdomain.center/?domain={domain}");
        let body = get_text(&http_client()?, &url).await?;
        for host in parse_subdomaincenter(&body) {
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
    fn parses_array_and_normalizes() {
        let body = r#"["dev.example.com","API.Example.COM."]"#;
        assert_eq!(
            parse_subdomaincenter(body),
            vec!["api.example.com", "dev.example.com"]
        );
    }

    #[test]
    fn empty_on_garbage() {
        assert!(parse_subdomaincenter("not json").is_empty());
        assert!(parse_subdomaincenter("{}").is_empty());
    }
}
