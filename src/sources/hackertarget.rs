use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{Source, SourceKind};
use tokio::sync::mpsc::Sender;

pub fn parse_hostsearch(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter_map(|line| {
            let (host, ip) = line.split_once(',')?;
            if ip.parse::<std::net::IpAddr>().is_err() {
                return None;
            }
            Some((normalize_host(host), ip.trim().to_string()))
        })
        .collect()
}

pub struct HackerTarget;

#[async_trait::async_trait]
impl Source for HackerTarget {
    fn name(&self) -> &'static str {
        "hackertarget"
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
        let url = format!("https://api.hackertarget.com/hostsearch/?q={domain}");
        let body = crate::sources::get_text(&crate::sources::http_client()?, &url).await?;
        for (host, ip) in parse_hostsearch(&body) {
            tx.send(Candidate {
                value: CandidateValue::Host(host),
                source: "hackertarget".into(),
            })
            .await
            .ok();
            if let Ok(addr) = ip.parse() {
                tx.send(Candidate {
                    value: CandidateValue::Ip(addr),
                    source: "hackertarget".into(),
                })
                .await
                .ok();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_ip_lines() {
        let body = "dev.example.com,192.0.2.125\napi.example.com,192.0.2.10\n";
        assert_eq!(
            parse_hostsearch(body),
            vec![
                ("dev.example.com".to_string(), "192.0.2.125".to_string()),
                ("api.example.com".to_string(), "192.0.2.10".to_string()),
            ]
        );
    }

    #[test]
    fn skips_error_body() {
        assert!(parse_hostsearch("error check your api query").is_empty());
    }
}
