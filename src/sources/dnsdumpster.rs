use crate::config::Config;
use crate::model::{normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{get_with_headers, http_client, Source, SourceKind};
use std::collections::BTreeSet;
use std::net::IpAddr;
use tokio::sync::mpsc::Sender;

/// The host names and IP addresses pulled from a DnsDumpster domain response.
#[derive(Debug, Default)]
pub struct DnsDumpsterParsed {
    pub hosts: Vec<String>,
    pub ips: Vec<IpAddr>,
}

/// Collect every `host` field from the a/cname/mx/ns record arrays, and every
/// address under a[].ips[].ip. Parsing is defensive: missing sections, missing
/// fields, and unparseable addresses are skipped rather than fatal.
pub fn parse_dnsdumpster(body: &str) -> DnsDumpsterParsed {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    let mut ips: BTreeSet<IpAddr> = BTreeSet::new();

    for section in ["a", "cname", "mx", "ns"] {
        if let Some(arr) = v.get(section).and_then(|s| s.as_array()) {
            for entry in arr {
                if let Some(h) = entry.get("host").and_then(|h| h.as_str()) {
                    let name = normalize_host(h);
                    if !name.is_empty() {
                        hosts.insert(name);
                    }
                }
            }
        }
    }

    // Only the a records carry resolved addresses.
    if let Some(arr) = v.get("a").and_then(|s| s.as_array()) {
        for entry in arr {
            if let Some(ip_arr) = entry.get("ips").and_then(|i| i.as_array()) {
                for ip_entry in ip_arr {
                    if let Some(ip_str) = ip_entry.get("ip").and_then(|i| i.as_str()) {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            ips.insert(ip);
                        }
                    }
                }
            }
        }
    }

    DnsDumpsterParsed {
        hosts: hosts.into_iter().collect(),
        ips: ips.into_iter().collect(),
    }
}

pub struct DnsDumpster {
    pub key: String,
}

#[async_trait::async_trait]
impl Source for DnsDumpster {
    fn name(&self) -> &'static str {
        "dnsdumpster"
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

        let url = format!("https://api.dnsdumpster.com/domain/{domain}");
        let resp = match get_with_headers(&client, &url, &[("X-API-Key", self.key.as_str())]).await
        {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        if !resp.status().is_success() {
            anyhow::bail!("dnsdumpster: HTTP {}", resp.status());
        }
        let body = match resp.text().await {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };

        let parsed = parse_dnsdumpster(&body);
        for host in parsed.hosts {
            let _ = tx
                .send(Candidate {
                    value: CandidateValue::Host(host),
                    source: self.name().into(),
                })
                .await;
        }
        for ip in parsed.ips {
            let _ = tx
                .send(Candidate {
                    value: CandidateValue::Ip(ip),
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
    fn collects_hosts_and_ips() {
        let body = r#"{
            "a":[{"host":"www.example.com","ips":[{"ip":"1.2.3.4"}]}],
            "cname":[{"host":"x.example.com"}],
            "mx":[{"host":"mail.example.com"}],
            "ns":[{"host":"ns1.example.com"}]
        }"#;
        let parsed = parse_dnsdumpster(body);
        let mut hosts = parsed.hosts;
        hosts.sort();
        assert_eq!(
            hosts,
            vec![
                "mail.example.com",
                "ns1.example.com",
                "www.example.com",
                "x.example.com",
            ]
        );
        assert_eq!(parsed.ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn garbage_returns_empty() {
        let parsed = parse_dnsdumpster("not json");
        assert!(parsed.hosts.is_empty());
        assert!(parsed.ips.is_empty());
        let empty = parse_dnsdumpster("{}");
        assert!(empty.hosts.is_empty());
        assert!(empty.ips.is_empty());
    }
}
