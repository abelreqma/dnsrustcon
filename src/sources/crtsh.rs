use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{Source, SourceKind};
use std::collections::BTreeSet;
use tokio::sync::mpsc::Sender;

pub fn parse_crtsh(body: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    let entries: Vec<serde_json::Value> = serde_json::from_str(body).unwrap_or_default();
    for e in entries {
        if let Some(nv) = e.get("name_value").and_then(|v| v.as_str()) {
            for line in nv.split('\n') {
                let name = normalize_host(line.trim_start_matches("*."));
                if !name.is_empty() {
                    out.insert(name);
                }
            }
        }
    }
    out.into_iter().collect()
}

pub struct CrtSh;

#[async_trait::async_trait]
impl Source for CrtSh {
    fn name(&self) -> &'static str {
        "crt.sh"
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
        let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
        let body = crate::sources::get_text(&crate::sources::http_client()?, &url).await?;
        for host in parse_crtsh(&body) {
            tx.send(Candidate {
                value: CandidateValue::Host(host),
                source: "crt.sh".into(),
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
    fn parses_names_and_strips_wildcards() {
        let body = r#"[
            {"name_value": "dev.example.com\n*.example.com"},
            {"name_value": "example.com"}
        ]"#;
        let mut got = parse_crtsh(body);
        got.sort();
        assert_eq!(got, vec!["dev.example.com", "example.com"]);
    }
}
