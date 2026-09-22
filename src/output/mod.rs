pub mod export;

use crate::engine::{FindingEvent, Findings};
use crate::model::DnsRecord;
use comfy_table::{Attribute, Cell, Table};
use owo_colors::OwoColorize;
use std::collections::BTreeMap;

pub fn group_by_type(records: &[DnsRecord]) -> BTreeMap<String, Vec<&DnsRecord>> {
    let mut map: BTreeMap<String, Vec<&DnsRecord>> = BTreeMap::new();
    for r in records {
        map.entry(r.rtype.to_string()).or_default().push(r);
    }
    map
}

/// Stable color per record type, grouped by what the type is for: address
/// types are green, mail amber/yellow, name servers red, aliases blue, zone
/// authority magenta, DNSSEC records bright magenta, and the remaining
/// security/service-discovery types each get their own distinct color.
pub fn record_type_color(rt: &crate::model::RecordType) -> owo_colors::AnsiColors {
    use crate::model::RecordType::*;
    use owo_colors::AnsiColors;
    match rt {
        A | Aaaa => AnsiColors::Green,
        Ptr => AnsiColors::BrightGreen,
        Cname => AnsiColors::Blue,
        Mx => AnsiColors::Yellow,
        Ns => AnsiColors::Red,
        Soa => AnsiColors::Magenta,
        Txt => AnsiColors::White,
        Srv => AnsiColors::Cyan,
        Caa => AnsiColors::BrightRed,
        Ds | Dnskey | Nsec | Nsec3 => AnsiColors::BrightMagenta,
        Hinfo => AnsiColors::BrightBlack,
        Naptr => AnsiColors::BrightBlue,
        Tlsa => AnsiColors::BrightCyan,
        Sshfp => AnsiColors::BrightYellow,
    }
}

/// Builds the IP-intelligence table shared by both report paths, so the column
/// set and row construction live in one place and cannot drift. The colored
/// terminal path passes `bold_header` true to bold the header cells; the plain
/// path passes false so no ANSI attributes are emitted.
fn ip_table(ips: &[crate::model::IpInfo], bold_header: bool) -> Table {
    let headers = [
        "IP", "ASN", "ASN Name", "RIR", "Org", "PTR", "Prefix", "Country", "Services",
    ];
    let mut table = Table::new();
    table.set_header(
        headers
            .iter()
            .map(|h| {
                let cell = Cell::new(h);
                if bold_header {
                    cell.add_attribute(Attribute::Bold)
                } else {
                    cell
                }
            })
            .collect::<Vec<_>>(),
    );
    for ip in ips {
        let services = ip
            .services
            .iter()
            .map(|s| format!("{}/{}", s.port, s.name))
            .collect::<Vec<_>>()
            .join(", ");
        table.add_row(vec![
            ip.ip.to_string(),
            ip.asn.map(|a| format!("AS{a}")).unwrap_or_default(),
            ip.asn_name.clone().unwrap_or_default(),
            ip.rir.clone().unwrap_or_default(),
            ip.org.clone().unwrap_or_default(),
            ip.ptr.clone().unwrap_or_default(),
            ip.prefix.clone().unwrap_or_default(),
            ip.country.clone().unwrap_or_default(),
            services,
        ]);
    }
    table
}

/// Builds the full end-of-run report as plain text (no ANSI codes). This is
/// the pure, testable core of the report; the colored terminal path reuses
/// the same section structure.
///
/// `show_header` gates the scan-parameter line (target/mode/depth) that opens
/// the report; it is only shown under verbose so the default output starts
/// straight at the SUBDOMAINS section. `takeover` reports the takeover result
/// explicitly: when the check ran, the section always appears, stating either
/// the findings or that nothing vulnerable was found.
pub fn render_report_plain(
    f: &Findings,
    target: &str,
    mode: &str,
    depth: u8,
    elapsed_secs: f64,
    show_header: bool,
    takeover: bool,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    if show_header {
        writeln!(
            out,
            "dnsrustcon  target {target}  mode {mode}  depth {depth}\n"
        )
        .unwrap();
    }

    writeln!(out, "SUBDOMAINS ({})", f.hosts.len()).unwrap();
    // Hosts start at column 0 with no marker so the list can be copied verbatim.
    for h in &f.hosts {
        writeln!(out, "{h}").unwrap();
    }

    writeln!(out, "\nDNS RECORDS ({})", f.records.len()).unwrap();
    for (rtype, recs) in group_by_type(&f.records) {
        writeln!(out, "\n  {} ({})", rtype, recs.len()).unwrap();
        let name_width = recs.iter().map(|r| r.name.len()).max().unwrap_or(0);
        for r in recs {
            writeln!(out, "    {:name_width$}   {}", r.name, r.value).unwrap();
        }
    }

    writeln!(out, "\nIP INTELLIGENCE ({})", f.ips.len()).unwrap();
    writeln!(out, "{}", ip_table(&f.ips, false)).unwrap();

    if !f.axfr.is_empty() {
        writeln!(out, "\nZONE TRANSFER ({})", f.axfr.len()).unwrap();
        for a in &f.axfr {
            writeln!(out, "  {}  {} records", a.ns, a.records).unwrap();
        }
    }

    if takeover {
        if f.takeovers.is_empty() {
            writeln!(out, "\nSUBDOMAIN TAKEOVER").unwrap();
            writeln!(out, "  No hosts vulnerable to takeover were found.").unwrap();
        } else {
            writeln!(out, "\nSUBDOMAIN TAKEOVER ({})", f.takeovers.len()).unwrap();
            for t in &f.takeovers {
                writeln!(
                    out,
                    "  [!] {}  CNAME {}  [{}]  {}",
                    t.host, t.cname, t.service, t.evidence
                )
                .unwrap();
            }
        }
    }

    if !f.probes.is_empty() {
        writeln!(out, "\nHTTP/TLS PROBES ({})", f.probes.len()).unwrap();
        for p in &f.probes {
            let status = p
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            let title = p.title.clone().unwrap_or_default();
            writeln!(
                out,
                "  {}  {}  {}  {} SANs",
                p.host,
                status,
                title,
                p.tls_sans.len()
            )
            .unwrap();
        }
    }

    writeln!(
        out,
        "\n{} hosts   {} records   {} IPs   {} zone transfers   {:.1}s",
        f.hosts.len(),
        f.records.len(),
        f.ips.len(),
        f.axfr.len(),
        elapsed_secs
    )
    .unwrap();

    out
}

pub struct Printer {
    pub color: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub progress: Option<indicatif::ProgressBar>,
}

impl Printer {
    /// Run `f` (which prints a finding line) with the progress bar temporarily
    /// hidden, so the live-updating bar and the finding stream never overwrite
    /// each other. Without a bar attached, `f` just runs directly.
    fn suspended(&self, f: impl FnOnce()) {
        match &self.progress {
            Some(pb) => pb.suspend(f),
            None => f(),
        }
    }

    pub fn event(&self, e: &FindingEvent) {
        match e {
            FindingEvent::Host(h, src) => {
                if !self.verbose || self.quiet {
                    return;
                }
                self.suspended(|| {
                    if self.color {
                        println!("{} {} [{}]", "HOST".green(), h, src.dimmed());
                    } else {
                        println!("HOST {h} [{src}]");
                    }
                });
            }
            FindingEvent::Record(r) => {
                if !self.verbose || self.quiet {
                    return;
                }
                self.suspended(|| {
                    if self.color {
                        let color = record_type_color(&r.rtype);
                        println!(
                            "{} {} {}",
                            r.rtype.to_string().color(color),
                            r.name,
                            r.value
                        );
                    } else {
                        println!("{} {} {}", r.rtype, r.name, r.value);
                    }
                });
            }
            FindingEvent::Ip(info) => {
                if !self.verbose || self.quiet {
                    return;
                }
                let asn = info.asn.map(|a| format!("AS{a}")).unwrap_or_default();
                let name = info.asn_name.clone().unwrap_or_default();
                self.suspended(|| {
                    if self.color {
                        println!("{} {} {} {}", "IP".yellow(), info.ip, asn.magenta(), name);
                    } else {
                        println!("IP {} {} {}", info.ip, asn, name);
                    }
                });
            }
            FindingEvent::SourceRun(name) => {
                if !self.verbose {
                    return;
                }
                self.suspended(|| {
                    if self.color {
                        eprintln!("{}", format!("[verbose] running source: {name}").dimmed());
                    } else {
                        eprintln!("[verbose] running source: {name}");
                    }
                });
            }
            FindingEvent::SourceSkipped(name, reason) => {
                if !self.verbose {
                    return;
                }
                self.suspended(|| {
                    if self.color {
                        eprintln!(
                            "{}",
                            format!("[verbose] skipped source: {name} ({reason})").dimmed()
                        );
                    } else {
                        eprintln!("[verbose] skipped source: {name} ({reason})");
                    }
                });
            }
            FindingEvent::SourceError(name, err) => {
                if !self.verbose {
                    return;
                }
                self.suspended(|| {
                    if self.color {
                        eprintln!(
                            "{}",
                            format!("[verbose] source error: {name}: {err}").dimmed()
                        );
                    } else {
                        eprintln!("[verbose] source error: {name}: {err}");
                    }
                });
            }
            FindingEvent::Takeover(t) => {
                // A potential takeover is high-signal and rare, so it is printed
                // even under -q, which only silences the routine finding stream.
                self.suspended(|| {
                    if self.color {
                        println!(
                            "{} {} -> {} [{}] {}",
                            "TAKEOVER".red().bold(),
                            t.host,
                            t.cname,
                            t.service.yellow(),
                            t.evidence
                        );
                    } else {
                        println!(
                            "TAKEOVER {} -> {} [{}] {}",
                            t.host, t.cname, t.service, t.evidence
                        );
                    }
                });
            }
            FindingEvent::Probe(p) => {
                if !self.verbose || self.quiet {
                    return;
                }
                let status = p
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let title = p.title.clone().unwrap_or_default();
                self.suspended(|| {
                    if self.color {
                        println!(
                            "{} {} {} {}",
                            "PROBE".cyan(),
                            p.host,
                            status.magenta(),
                            title
                        );
                    } else {
                        println!("PROBE {} {} {}", p.host, status, title);
                    }
                });
            }
            FindingEvent::DomainInactive(domain) => {
                // A skipped inactive domain explains why a target produced
                // nothing, so it is high-signal and printed even without -v.
                self.suspended(|| {
                    if self.color {
                        println!(
                            "{} {} inactive (no NS or SOA)",
                            "SKIP".yellow().bold(),
                            domain
                        );
                    } else {
                        println!("SKIP {domain} inactive (no NS or SOA)");
                    }
                });
            }
            FindingEvent::AxfrSuccess(ns, count) => {
                // A successful zone transfer is high-signal and rare, so it is
                // printed even under -q, like a takeover.
                self.suspended(|| {
                    if self.color {
                        println!(
                            "{} zone transfer from {} ({} records)",
                            "AXFR".red().bold(),
                            ns.yellow(),
                            count
                        );
                    } else {
                        println!("AXFR zone transfer from {ns} ({count} records)");
                    }
                });
            }
        }
    }

    /// Prints the end-of-run report. With `color` false this is exactly
    /// `render_report_plain`, guaranteeing --no-color emits no ANSI codes.
    /// With `color` true, the same sections are rendered in the same order
    /// (header, SUBDOMAINS, DNS RECORDS, IP INTELLIGENCE, ZONE TRANSFER,
    /// SUBDOMAIN TAKEOVER, HTTP/TLS PROBES, footer) so the two paths cannot
    /// drift. The scan-parameter header is shown only under verbose; `takeover`
    /// forces the takeover section to state its result either way.
    pub fn summary(
        &self,
        f: &Findings,
        target: &str,
        mode: &str,
        depth: u8,
        elapsed_secs: f64,
        takeover: bool,
    ) {
        if !self.color {
            print!(
                "{}",
                render_report_plain(f, target, mode, depth, elapsed_secs, self.verbose, takeover)
            );
            return;
        }

        if self.verbose {
            println!(
                "{}\n",
                format!("dnsrustcon  target {target}  mode {mode}  depth {depth}").bold()
            );
        }

        println!(
            "{} {}",
            "SUBDOMAINS".bold().cyan(),
            format!("({})", f.hosts.len()).dimmed()
        );
        // Hosts start at column 0 with no marker so the list can be copied verbatim.
        for h in &f.hosts {
            println!("{h}");
        }

        println!(
            "\n{} {}",
            "DNS RECORDS".bold().cyan(),
            format!("({})", f.records.len()).dimmed()
        );
        for (rtype, recs) in group_by_type(&f.records) {
            let color = record_type_color(&recs[0].rtype);
            println!("\n  {} ({})", rtype.color(color), recs.len());
            let name_width = recs.iter().map(|r| r.name.len()).max().unwrap_or(0);
            for r in recs {
                println!("    {:name_width$}   {}", r.name, r.value);
            }
        }

        println!(
            "\n{} {}",
            "IP INTELLIGENCE".bold().cyan(),
            format!("({})", f.ips.len()).dimmed()
        );
        println!("{}", ip_table(&f.ips, true));

        if !f.axfr.is_empty() {
            println!(
                "\n{} {}",
                "ZONE TRANSFER".bold().red(),
                format!("({})", f.axfr.len()).dimmed()
            );
            for a in &f.axfr {
                println!("  {}  {} records", a.ns.yellow(), a.records);
            }
        }

        if takeover {
            if f.takeovers.is_empty() {
                println!("\n{}", "SUBDOMAIN TAKEOVER".bold().green());
                println!(
                    "  {}",
                    "No hosts vulnerable to takeover were found.".green()
                );
            } else {
                println!(
                    "\n{} {}",
                    "SUBDOMAIN TAKEOVER".bold().red(),
                    format!("({})", f.takeovers.len()).dimmed()
                );
                for t in &f.takeovers {
                    println!(
                        "  {} {}  CNAME {}  [{}]  {}",
                        "[!]".red().bold(),
                        t.host,
                        t.cname,
                        t.service.yellow(),
                        t.evidence
                    );
                }
            }
        }

        if !f.probes.is_empty() {
            println!(
                "\n{} {}",
                "HTTP/TLS PROBES".bold().cyan(),
                format!("({})", f.probes.len()).dimmed()
            );
            for p in &f.probes {
                let status = p
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let title = p.title.clone().unwrap_or_default();
                println!(
                    "  {}  {}  {}  {} SANs",
                    p.host,
                    status.magenta(),
                    title,
                    p.tls_sans.len()
                );
            }
        }

        println!(
            "\n{} hosts   {} records   {} IPs   {} zone transfers   {:.1}s",
            f.hosts.len().to_string().bold(),
            f.records.len().to_string().bold(),
            f.ips.len().to_string().bold(),
            f.axfr.len().to_string().bold(),
            elapsed_secs
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsRecord, RecordType};

    #[test]
    fn groups_records_by_type() {
        let recs = vec![
            DnsRecord {
                name: "a".into(),
                rtype: RecordType::A,
                value: "1.1.1.1".into(),
            },
            DnsRecord {
                name: "b".into(),
                rtype: RecordType::Mx,
                value: "10 mail".into(),
            },
            DnsRecord {
                name: "c".into(),
                rtype: RecordType::A,
                value: "2.2.2.2".into(),
            },
        ];
        let g = group_by_type(&recs);
        assert_eq!(g.get("A").unwrap().len(), 2);
        assert_eq!(g.get("MX").unwrap().len(), 1);
    }

    #[test]
    fn plain_report_has_all_sections_and_counts() {
        let mut f = Findings::default();
        f.hosts.insert("dev.example.com".into());
        f.records.push(DnsRecord {
            name: "dev.example.com".into(),
            rtype: RecordType::A,
            value: "1.2.3.4".into(),
        });
        f.axfr.push(crate::engine::AxfrTransfer {
            ns: "ns2.example.com".into(),
            records: 42,
        });
        let out = render_report_plain(&f, "example.com", "both", 2, 4.1, true, false);
        assert!(out.contains("example.com"));
        assert!(out.contains("SUBDOMAINS"));
        assert!(out.contains("dev.example.com"));
        assert!(out.contains("A")); // record type label
        assert!(out.contains("zone transfer") || out.contains("ZONE TRANSFER"));
        assert!(out.contains("ns2.example.com"));
        assert!(out.contains("1 hosts") || out.contains("1 host"));
    }

    #[test]
    fn header_line_is_gated_by_show_header() {
        let f = Findings::default();
        let with = render_report_plain(&f, "example.com", "passive", 2, 1.0, true, false);
        let without = render_report_plain(&f, "example.com", "passive", 2, 1.0, false, false);
        assert!(with.contains("mode passive"));
        assert!(!without.contains("mode passive"));
        // Either way the report body starts at the SUBDOMAINS section.
        assert!(without.starts_with("SUBDOMAINS"));
    }

    #[test]
    fn takeover_section_states_result_both_ways() {
        // Requested but nothing found: an explicit "none" message appears.
        let f = Findings::default();
        let none = render_report_plain(&f, "example.com", "passive", 2, 1.0, false, true);
        assert!(none.contains("SUBDOMAIN TAKEOVER"));
        assert!(none.contains("No hosts vulnerable to takeover were found."));

        // Requested and found: the finding is listed.
        let mut f2 = Findings::default();
        f2.takeovers.push(crate::model::Takeover {
            host: "gone.example.com".into(),
            service: "Azure".into(),
            cname: "x.trafficmanager.net".into(),
            evidence: "dangling CNAME".into(),
        });
        let found = render_report_plain(&f2, "example.com", "passive", 2, 1.0, false, true);
        assert!(found.contains("SUBDOMAIN TAKEOVER (1)"));
        assert!(found.contains("gone.example.com"));

        // Not requested: no takeover section at all.
        let off = render_report_plain(&f, "example.com", "passive", 2, 1.0, false, false);
        assert!(!off.contains("SUBDOMAIN TAKEOVER"));
    }
}
