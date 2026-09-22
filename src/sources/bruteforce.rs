use crate::config::Config;
use crate::model::{is_valid_hostname, normalize_host, Candidate, CandidateValue, Target};
use crate::sources::{Source, SourceKind};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use tokio::sync::mpsc::Sender;

/// The wordlist bundled into the binary, used for active/both mode when the user
/// gives no --wordlist. It is the 5,000 most common subdomain labels from
/// SecLists (Discovery/DNS/subdomains-top1million-5000.txt, MIT licensed); see
/// wordlists/README.md. Comment/blank lines are filtered by the same
/// generate_fqdns path a file wordlist goes through.
pub const DEFAULT_WORDLIST: &str = include_str!("../../wordlists/subdomains-top1million-5000.txt");

/// The bundled wordlist split into owned lines, ready to merge like a file
/// wordlist. Blank lines are dropped here; comment handling stays in
/// generate_fqdns so both sources behave identically.
pub fn default_words() -> Vec<String> {
    DEFAULT_WORDLIST
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

pub fn generate_fqdns(words: &[String], base: &str) -> Vec<String> {
    words
        .iter()
        .map(|w| w.trim())
        .filter(|w| !w.is_empty() && !w.starts_with('#'))
        .map(|w| normalize_host(&format!("{w}.{base}")))
        .collect()
}

/// Upper bound on generated permutations, so a large discovered-host set crossed
/// with a large wordlist cannot allocate an unbounded candidate list.
const MAX_PERMUTATIONS: usize = 200_000;

/// Numeric mutations of a single DNS label: if it ends in a digit run, emit the
/// run incremented by one and two (both bare and zero-padded to the original
/// width) and decremented by one; otherwise append small indices. Deterministic.
fn number_mutations(label: &str) -> Vec<String> {
    let mut out = Vec::new();
    let stem_len = label.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    if stem_len < label.len() {
        let (prefix, digits) = label.split_at(stem_len);
        if let Ok(n) = digits.parse::<u32>() {
            let width = digits.len();
            for delta in [1u32, 2] {
                out.push(format!("{prefix}{}", n + delta));
                out.push(format!(
                    "{prefix}{val:0width$}",
                    val = n + delta,
                    width = width
                ));
            }
            if n > 0 {
                out.push(format!("{prefix}{}", n - 1));
            }
        }
    } else {
        for i in 1..=3 {
            out.push(format!("{label}{i}"));
            out.push(format!("{label}-{i}"));
            out.push(format!("{label}0{i}"));
        }
    }
    out
}

/// Generate altdns-style permutations of already-discovered host names. Only
/// strict subdomains of `apex` are permuted, and the apex suffix is always held
/// fixed - the apex itself is skipped so we never fabricate unrelated sibling
/// registered domains (example.com -> example2.com). For each in-scope host and
/// each word, the word is inserted as a new leftmost label and dash-joined to
/// the subdomain's leftmost label in both orders; that label is also numerically
/// mutated. Results are validated, deduplicated, never include an input host,
/// and capped at MAX_PERMUTATIONS.
pub fn generate_permutations(hosts: &[String], words: &[String], apex: &str) -> Vec<String> {
    let clean: Vec<&str> = words
        .iter()
        .map(|w| w.trim())
        .filter(|w| !w.is_empty() && !w.starts_with('#'))
        .collect();
    let inputs: HashSet<&str> = hosts.iter().map(|h| h.as_str()).collect();
    let apex_suffix = format!(".{apex}");

    let mut out: BTreeSet<String> = BTreeSet::new();
    let push = |cand: String, out: &mut BTreeSet<String>| {
        let h = normalize_host(&cand);
        if is_valid_hostname(&h) && !inputs.contains(h.as_str()) {
            out.insert(h);
        }
    };

    for host in hosts {
        // The subdomain portion, with the apex suffix stripped; an empty result
        // (the bare apex) or an out-of-scope host is skipped.
        let sub = match host.strip_suffix(&apex_suffix) {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };
        let (first, subrest) = match sub.split_once('.') {
            Some((f, r)) => (f, Some(r)),
            None => (sub, None),
        };
        // Rebuild a full host name from a mutated leftmost label, preserving the
        // rest of the subdomain and the apex suffix.
        let with_first = |mutated: String| match subrest {
            Some(rest) => format!("{mutated}.{rest}.{apex}"),
            None => format!("{mutated}.{apex}"),
        };

        for w in &clean {
            push(format!("{w}.{host}"), &mut out);
            push(with_first(format!("{first}-{w}")), &mut out);
            push(with_first(format!("{w}-{first}")), &mut out);
        }
        for variant in number_mutations(first) {
            push(with_first(variant), &mut out);
        }
        if out.len() >= MAX_PERMUTATIONS {
            break;
        }
    }

    out.into_iter().take(MAX_PERMUTATIONS).collect()
}

pub fn load_wordlist(path: &Path) -> anyhow::Result<Vec<String>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .map(|l| l.to_string())
        .collect())
}

pub struct BruteForce {
    pub words: Vec<String>,
}

#[async_trait::async_trait]
impl Source for BruteForce {
    fn name(&self) -> &'static str {
        "bruteforce"
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Active
    }
    fn available(&self, _cfg: &Config) -> bool {
        !self.words.is_empty()
    }

    async fn run(&self, target: &Target, tx: Sender<Candidate>) -> anyhow::Result<()> {
        let base = match target {
            Target::Domain(d) => d.clone(),
            _ => return Ok(()),
        };
        for host in generate_fqdns(&self.words, &base) {
            tx.send(Candidate {
                value: CandidateValue::Host(host),
                source: "bruteforce".into(),
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
    fn generates_fqdns() {
        let words = vec!["dev".to_string(), "api".to_string()];
        assert_eq!(
            generate_fqdns(&words, "example.com"),
            vec!["dev.example.com", "api.example.com"]
        );
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        let words = vec!["".to_string(), "# comment".to_string(), "www".to_string()];
        assert_eq!(
            generate_fqdns(&words, "example.com"),
            vec!["www.example.com"]
        );
    }

    #[test]
    fn permutes_labels_both_orders() {
        let hosts = vec!["dev.example.com".to_string()];
        let words = vec!["api".to_string()];
        let got = generate_permutations(&hosts, &words, "example.com");
        assert!(got.contains(&"api.dev.example.com".to_string()));
        assert!(got.contains(&"dev-api.example.com".to_string()));
        assert!(got.contains(&"api-dev.example.com".to_string()));
        // never re-emit an input host
        assert!(!got.contains(&"dev.example.com".to_string()));
    }

    #[test]
    fn permutes_trailing_numbers() {
        let hosts = vec!["web01.example.com".to_string()];
        let got = generate_permutations(&hosts, &[], "example.com");
        assert!(got.contains(&"web02.example.com".to_string()));
        assert!(got.contains(&"web2.example.com".to_string()));
    }

    #[test]
    fn skips_hosts_outside_apex() {
        let hosts = vec!["dev.other.org".to_string()];
        let words = vec!["api".to_string()];
        assert!(generate_permutations(&hosts, &words, "example.com").is_empty());
    }

    #[test]
    fn does_not_permute_bare_apex_into_siblings() {
        // Permuting the apex itself would fabricate unrelated registered domains
        // (example2.com, api-example.com); it must be skipped, apex held fixed.
        let hosts = vec!["example.com".to_string()];
        let words = vec!["api".to_string()];
        let got = generate_permutations(&hosts, &words, "example.com");
        assert!(got.is_empty());
        assert!(!got.iter().any(|h| !h.ends_with(".example.com")));
    }

    #[test]
    fn keeps_apex_fixed_for_multilevel_subdomain() {
        let hosts = vec!["a.b.example.com".to_string()];
        let words = vec!["api".to_string()];
        let got = generate_permutations(&hosts, &words, "example.com");
        assert!(got.contains(&"api.a.b.example.com".to_string()));
        assert!(got.contains(&"a-api.b.example.com".to_string()));
        // every result stays within the apex
        assert!(got.iter().all(|h| h.ends_with(".example.com")));
    }
}
