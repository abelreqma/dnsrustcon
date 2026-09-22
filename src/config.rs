use crate::cli::Cli;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    shodan_key: Option<String>,
    securitytrails_key: Option<String>,
    virustotal_key: Option<String>,
    chaos_key: Option<String>,
    dnsdumpster_key: Option<String>,
    censys_api_id: Option<String>,
    censys_api_secret: Option<String>,
    #[serde(default)]
    resolvers: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Config {
    pub shodan_key: Option<String>,
    pub securitytrails_key: Option<String>,
    pub virustotal_key: Option<String>,
    pub chaos_key: Option<String>,
    pub dnsdumpster_key: Option<String>,
    pub censys_api_id: Option<String>,
    pub censys_api_secret: Option<String>,
    pub resolvers: Vec<String>,
}

pub fn resolve_key(env_name: &str, file_val: Option<String>) -> Option<String> {
    match std::env::var(env_name) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => file_val,
    }
}

fn default_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("dnsrustcon").join("config.toml"))
}

impl Config {
    pub fn load(cli: &Cli) -> anyhow::Result<Config> {
        let path = cli.config.clone().or_else(default_config_path);
        let file: FileConfig = match path {
            Some(p) if p.exists() => toml::from_str(&std::fs::read_to_string(&p)?)?,
            _ => FileConfig::default(),
        };

        let mut resolvers = file.resolvers.clone();
        if let Some(list) = &cli.resolvers {
            // Inline comma list or a file path.
            let p = std::path::Path::new(list);
            if p.exists() {
                resolvers = std::fs::read_to_string(p)?
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect();
            } else {
                resolvers = list
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        Ok(Config {
            shodan_key: resolve_key("DNSRUSTCON_SHODAN_KEY", file.shodan_key),
            securitytrails_key: resolve_key(
                "DNSRUSTCON_SECURITYTRAILS_KEY",
                file.securitytrails_key,
            ),
            virustotal_key: resolve_key("DNSRUSTCON_VIRUSTOTAL_KEY", file.virustotal_key),
            chaos_key: resolve_key("DNSRUSTCON_CHAOS_KEY", file.chaos_key),
            dnsdumpster_key: resolve_key("DNSRUSTCON_DNSDUMPSTER_KEY", file.dnsdumpster_key),
            censys_api_id: resolve_key("DNSRUSTCON_CENSYS_API_ID", file.censys_api_id),
            censys_api_secret: resolve_key("DNSRUSTCON_CENSYS_API_SECRET", file.censys_api_secret),
            resolvers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_overrides_file() {
        std::env::set_var("DNSRUSTCON_TEST_KEY", "from-env");
        let got = resolve_key("DNSRUSTCON_TEST_KEY", Some("from-file".into()));
        std::env::remove_var("DNSRUSTCON_TEST_KEY");
        assert_eq!(got, Some("from-env".to_string()));
    }

    #[test]
    fn file_used_when_env_absent() {
        let got = resolve_key("DNSRUSTCON_DEFINITELY_UNSET", Some("from-file".into()));
        assert_eq!(got, Some("from-file".to_string()));
    }

    #[test]
    fn none_when_both_absent() {
        let got = resolve_key("DNSRUSTCON_DEFINITELY_UNSET", None);
        assert_eq!(got, None);
    }
}
