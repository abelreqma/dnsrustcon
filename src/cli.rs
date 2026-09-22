use clap::builder::styling::{AnsiColor, Styles};
use std::path::PathBuf;

/// Banner shown at the top of the help menu.
const LOGO: &str = r"
 /$$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$$                        /$$
| $$__  $$| $$$ | $$ /$$__  $$| $$__  $$                      | $$
| $$  \ $$| $$$$| $$| $$  \__/| $$  \ $$ /$$   /$$  /$$$$$$$ /$$$$$$    /$$$$$$$  /$$$$$$  /$$$$$$$
| $$  | $$| $$ $$ $$|  $$$$$$ | $$$$$$$/| $$  | $$ /$$_____/|_  $$_/   /$$_____/ /$$__  $$| $$__  $$
| $$  | $$| $$  $$$$ \____  $$| $$__  $$| $$  | $$|  $$$$$$   | $$    | $$      | $$  \ $$| $$  \ $$
| $$  | $$| $$\  $$$ /$$  \ $$| $$  \ $$| $$  | $$ \____  $$  | $$ /$$| $$      | $$  | $$| $$  | $$
| $$$$$$$/| $$ \  $$|  $$$$$$/| $$  | $$|  $$$$$$/ /$$$$$$$/  |  $$$$/|  $$$$$$$|  $$$$$$/| $$  | $$
|_______/ |__/  \__/ \______/ |__/  |__/ \______/ |_______/    \___/   \_______/ \______/ |__/  |__/
";

/// Help colors: bold green for section headings and usage, cyan for flag names,
/// dim for value placeholders.
const HELP_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::BrightBlack.on_default());

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Passive,
    Active,
    Both,
}

#[derive(clap::Parser, Debug)]
#[command(
    name = "dnsrustcon",
    version,
    about = "DNS and subdomain reconnaissance",
    before_help = LOGO,
    styles = HELP_STYLES,
)]
pub struct Cli {
    /// One or more domains, IPs, or CIDR blocks
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Scan mode: passive OSINT only, active brute force plus AXFR, or both
    #[arg(long, value_enum, default_value_t = Mode::Passive, help_heading = "Scan")]
    pub mode: Mode,

    /// Path to a wordlist file; repeat -w to merge several. Optional: with none
    /// given, active/both modes use the bundled 5,000-label list.
    #[arg(short, long, help_heading = "Scan")]
    pub wordlist: Vec<PathBuf>,

    /// In active/both mode, run an altdns-style permutation pass over every
    /// discovered host using the wordlist(s), confirming non-wildcard hits.
    #[arg(long, help_heading = "Scan")]
    pub permutations: bool,

    /// Recursive brute-force depth (active/both modes)
    #[arg(short, long, default_value_t = 2, help_heading = "Scan")]
    pub depth: u8,

    /// Comma-separated record types to query, e.g. A,AAAA,MX (default: all)
    #[arg(long, help_heading = "Scan")]
    pub record_types: Option<String>,

    /// Keep hosts discovered outside the target domain(s). By default a
    /// discovered name must fall under a scanned domain; unrelated names (e.g. a
    /// co-listed domain on a shared certificate) are dropped.
    #[arg(long, help_heading = "Scan")]
    pub out_of_scope: bool,

    /// Check discovered hosts with a CNAME to a takeover-prone service (GitHub
    /// Pages, S3, Heroku, Azure, ...) for a dangling/unclaimed target. The
    /// report states the result whether or not anything is found.
    #[arg(long, help_heading = "Scan")]
    pub takeover: bool,

    /// Probe each discovered host over HTTP(S) for status code, page title,
    /// final URL, and TLS certificate SAN names.
    #[arg(long, help_heading = "Probing")]
    pub probe: bool,

    /// Run only these discovery sources (comma-separated, case-insensitive):
    /// crt.sh, hackertarget, otx, anubis, certspotter, wayback, bruteforce,
    /// securitytrails, virustotal, shodandns, chaos, dnsdumpster, censys,
    /// rapiddns, subdomaincenter, urlscan. Mutually exclusive with
    /// --exclude-sources
    #[arg(long, help_heading = "Discovery sources")]
    pub sources: Option<String>,

    /// Run every discovery source except these (comma-separated,
    /// case-insensitive; same names as --sources). Mutually exclusive with
    /// --sources
    #[arg(long, help_heading = "Discovery sources")]
    pub exclude_sources: Option<String>,

    /// For a domain target, also sweep the containing /24 of each resolved
    /// IPv4. PTR/ASN enrichment already runs for every IP regardless of this
    /// flag; this only adds the neighbor sweep
    #[arg(long, help_heading = "Reverse DNS")]
    pub reverse: bool,

    /// With --reverse, widen the neighbor sweep from the /24 to the IP's
    /// ASN-announced prefix (Team Cymru), falling back to the /24 if missing
    #[arg(long, help_heading = "Reverse DNS")]
    pub sweep_prefix: bool,

    /// Allow a CIDR target or ASN prefix larger than 65536 hosts to be swept;
    /// without it such a target is rejected up front
    #[arg(long, help_heading = "Reverse DNS")]
    pub allow_large_sweep: bool,

    /// Custom resolvers: an inline comma-separated list or a path to a file
    /// with one per line. Replaces the config-file resolver list
    #[arg(long, help_heading = "Network")]
    pub resolvers: Option<String>,

    /// Maximum concurrent lookups
    #[arg(short = 't', long, default_value_t = 50, help_heading = "Network")]
    pub concurrency: usize,

    /// DNS query timeout in seconds
    #[arg(long, default_value_t = 5, help_heading = "Network")]
    pub timeout: u64,

    /// Throttle DNS queries to at most this many per second
    #[arg(long, help_heading = "Network")]
    pub rate_limit: Option<u32>,

    /// Write the full result to this path as JSON
    #[arg(long, help_heading = "Output")]
    pub json: Option<PathBuf>,

    /// Write the full result to this path as CSV
    #[arg(long, help_heading = "Output")]
    pub csv: Option<PathBuf>,

    /// Write all three output formats into this directory after the run:
    /// dnsrustcon.json, dnsrustcon.csv, and dnsrustcon.txt. Additive to
    /// --json/--csv
    #[arg(long, help_heading = "Output")]
    pub output_dir: Option<PathBuf>,

    /// Stream findings to this file as newline-delimited JSON (one compact
    /// object per finding) as they are discovered, so it can be tailed live
    #[arg(long, help_heading = "Output")]
    pub jsonl: Option<PathBuf>,

    /// Read a prior --json export and skip hosts already listed in it, so the
    /// run only surfaces new findings. Resumed hosts are skipped entirely: they
    /// are not re-resolved, enriched, or recursed into
    #[arg(long, help_heading = "Output")]
    pub resume: Option<PathBuf>,

    /// Print only the end-of-run summary: suppress the live finding stream and
    /// the progress spinner
    #[arg(short, long, help_heading = "Output")]
    pub quiet: bool,

    /// Verbose output: stream each finding live as it is discovered, show the
    /// scan-parameter header, and print source diagnostics to stderr
    #[arg(short, long, help_heading = "Output")]
    pub verbose: bool,

    /// Disable colored output
    #[arg(long, help_heading = "Output")]
    pub no_color: bool,

    /// Path to a config file (defaults to the OS config directory)
    #[arg(long, help_heading = "Config")]
    pub config: Option<PathBuf>,
}

impl Cli {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.timeout == 0 {
            anyhow::bail!("--timeout must be at least 1 second");
        }
        if self.rate_limit == Some(0) {
            anyhow::bail!("--rate-limit must be at least 1 query per second");
        }
        if self.sources.is_some() && self.exclude_sources.is_some() {
            anyhow::bail!("--sources and --exclude-sources are mutually exclusive");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn defaults_are_passive_depth_two() {
        let cli = Cli::try_parse_from(["dnsrustcon", "example.com"]).unwrap();
        assert_eq!(cli.mode, Mode::Passive);
        assert_eq!(cli.depth, 2);
        assert_eq!(cli.concurrency, 50);
    }

    #[test]
    fn active_without_wordlist_is_ok_uses_bundled_default() {
        // A wordlist is no longer required: active/both fall back to the
        // wordlist bundled into the binary when no -w is given.
        let cli = Cli::try_parse_from(["dnsrustcon", "--mode", "active", "example.com"]).unwrap();
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn both_with_wordlist_ok() {
        let cli = Cli::try_parse_from([
            "dnsrustcon",
            "--mode",
            "both",
            "-w",
            "/tmp/w.txt",
            "example.com",
        ])
        .unwrap();
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn rejects_zero_timeout() {
        let cli = Cli::try_parse_from(["dnsrustcon", "--timeout", "0", "example.com"]).unwrap();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn rejects_zero_rate_limit() {
        let cli = Cli::try_parse_from(["dnsrustcon", "--rate-limit", "0", "example.com"]).unwrap();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn rejects_sources_and_exclude_sources_together() {
        let cli = Cli::try_parse_from([
            "dnsrustcon",
            "--sources",
            "crt.sh",
            "--exclude-sources",
            "otx",
            "example.com",
        ])
        .unwrap();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn sources_alone_is_ok() {
        let cli =
            Cli::try_parse_from(["dnsrustcon", "--sources", "crt.sh", "example.com"]).unwrap();
        assert!(cli.validate().is_ok());
    }
}
