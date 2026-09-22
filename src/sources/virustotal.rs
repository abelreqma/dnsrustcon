use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{get_with_headers, http_client, Source, SourceKind};
use tokio::sync::mpsc::Sender;

pub fn parse_virustotal(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    v.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("id").and_then(|i| i.as_str()))
                .map(normalize_host)
                .collect()
        })
        .unwrap_or_default()
}

/// The cursor URL for the next page of results, if the response carries one.
/// VirusTotal's v3 API paginates via `links.next`; its absence marks the last
/// page.
pub fn next_page_url(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("links")
        .and_then(|l| l.get("next"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string())
}

/// Cap on the number of subdomain pages fetched for a single domain, so a
/// target with an enormous history cannot spin indefinitely. At 40 results per
/// page this is up to 400 subdomains.
const MAX_PAGES: usize = 10;

pub struct VirusTotal {
    pub key: String,
}

#[async_trait::async_trait]
impl Source for VirusTotal {
    fn name(&self) -> &'static str {
        "virustotal"
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

        // Walk the pages via the `links.next` cursor rather than taking only
        // the first 40 results. Bounded by MAX_PAGES so a large history cannot
        // loop forever.
        let mut url =
            format!("https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40");
        for _ in 0..MAX_PAGES {
            let resp =
                match get_with_headers(&client, &url, &[("x-apikey", self.key.as_str())]).await {
                    Ok(r) => r,
                    Err(_) => return Ok(()),
                };
            if !resp.status().is_success() {
                anyhow::bail!("virustotal: HTTP {}", resp.status());
            }
            let body = match resp.text().await {
                Ok(b) => b,
                Err(_) => return Ok(()),
            };

            for host in parse_virustotal(&body) {
                let _ = tx
                    .send(Candidate {
                        value: CandidateValue::Host(host),
                        source: self.name().into(),
                    })
                    .await;
            }

            match next_page_url(&body) {
                Some(next) => url = next,
                None => break,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_virustotal_subdomains() {
        let body = r#"{"data":[{"id":"dev.example.com"},{"id":"API.Example.COM."}]}"#;
        let mut got = parse_virustotal(body);
        got.sort();
        assert_eq!(got, vec!["api.example.com", "dev.example.com"]);
    }

    #[test]
    fn extracts_next_page_cursor() {
        let body = r#"{"data":[],"links":{"next":"https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=abc"}}"#;
        assert_eq!(
            next_page_url(body).as_deref(),
            Some("https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=abc")
        );
    }

    #[test]
    fn no_next_page_on_last() {
        let body = r#"{"data":[{"id":"dev.example.com"}]}"#;
        assert_eq!(next_page_url(body), None);
    }
}
