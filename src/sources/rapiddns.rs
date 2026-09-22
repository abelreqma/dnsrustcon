use crate::config::Config;
use crate::model::{is_valid_hostname, normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{get_text, http_client, Source, SourceKind};
use std::collections::BTreeSet;
use tokio::sync::mpsc::Sender;

/// Scrape host names out of RapidDNS's HTML page without an HTML parser. The
/// body is split on any character that cannot appear in a host name, and each
/// remaining token is kept only when it is a valid host name that falls under
/// the target domain. Deduplicated.
pub fn parse_rapiddns(body: &str, domain: &str) -> Vec<String> {
    let suffix = format!(".{domain}");
    let mut out: BTreeSet<String> = BTreeSet::new();
    for token in
        body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'))
    {
        let name = normalize_host(token);
        if is_valid_hostname(&name) && (name == domain || name.ends_with(&suffix)) {
            out.insert(name);
        }
    }
    out.into_iter().collect()
}

pub struct RapidDns;

#[async_trait::async_trait]
impl Source for RapidDns {
    fn name(&self) -> &'static str {
        "rapiddns"
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
        let url = format!("https://rapiddns.io/subdomain/{domain}?full=1");
        let body = get_text(&http_client()?, &url).await?;
        for host in parse_rapiddns(&body, &domain) {
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
    fn scrapes_hosts_from_html() {
        let body = r#"<html><body><table>
            <tr><td>www.example.com</td><td>1.2.3.4</td></tr>
            <tr><td>dev.example.com</td><td>5.6.7.8</td></tr>
            <tr><td>unrelated.other.com</td><td>9.9.9.9</td></tr>
            </table></body></html>"#;
        let mut got = parse_rapiddns(body, "example.com");
        got.sort();
        assert_eq!(got, vec!["dev.example.com", "www.example.com"]);
    }

    #[test]
    fn garbage_returns_empty() {
        assert!(parse_rapiddns("no hosts here just words", "example.com").is_empty());
        assert!(parse_rapiddns("", "example.com").is_empty());
    }
}
