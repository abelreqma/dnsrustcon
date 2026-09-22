use crate::engine::Findings;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct AxfrView<'a> {
    ns: &'a str,
    records: usize,
}

#[derive(Serialize)]
struct FindingsView<'a> {
    hosts: Vec<&'a String>,
    records: &'a [crate::model::DnsRecord],
    ips: &'a [crate::model::IpInfo],
    takeovers: &'a [crate::model::Takeover],
    zone_transfers: Vec<AxfrView<'a>>,
    probes: &'a [crate::probe::HostProbe],
}

pub fn to_json(f: &Findings) -> anyhow::Result<String> {
    let view = FindingsView {
        hosts: f.hosts.iter().collect(),
        records: &f.records,
        ips: &f.ips,
        takeovers: &f.takeovers,
        zone_transfers: f
            .axfr
            .iter()
            .map(|a| AxfrView {
                ns: &a.ns,
                records: a.records,
            })
            .collect(),
        probes: &f.probes,
    };
    Ok(serde_json::to_string_pretty(&view)?)
}

/// Pack an IpInfo's enrichment fields into a single human-readable value for
/// the CSV IP row, e.g. "asn=AS15169; name=GOOGLE, US; org=Google LLC;
/// ptr=dns.google; prefix=8.8.8.0/24; country=US; services=443/nginx,
/// 22/OpenSSH". Fields that are None/empty are omitted entirely.
fn format_ip_value(info: &crate::model::IpInfo) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(asn) = info.asn {
        parts.push(format!("asn=AS{asn}"));
    }
    if let Some(name) = &info.asn_name {
        parts.push(format!("name={name}"));
    }
    if let Some(rir) = &info.rir {
        parts.push(format!("rir={rir}"));
    }
    if let Some(org) = &info.org {
        parts.push(format!("org={org}"));
    }
    if let Some(ptr) = &info.ptr {
        parts.push(format!("ptr={ptr}"));
    }
    if let Some(prefix) = &info.prefix {
        parts.push(format!("prefix={prefix}"));
    }
    if let Some(country) = &info.country {
        parts.push(format!("country={country}"));
    }
    if !info.services.is_empty() {
        let services = info
            .services
            .iter()
            .map(|s| format!("{}/{}", s.port, s.name))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("services={services}"));
    }
    parts.join("; ")
}

/// Pack a HostProbe's fields into a single human-readable value for the CSV
/// PROBE row, e.g. "status=200; title=Home; final_url=https://x/; sans=a.x,
/// b.x". Absent/empty fields are omitted entirely.
fn format_probe_value(p: &crate::probe::HostProbe) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(status) = p.status {
        parts.push(format!("status={status}"));
    }
    if let Some(title) = &p.title {
        parts.push(format!("title={title}"));
    }
    if let Some(url) = &p.final_url {
        parts.push(format!("final_url={url}"));
    }
    if !p.tls_sans.is_empty() {
        parts.push(format!("sans={}", p.tls_sans.join(", ")));
    }
    parts.join("; ")
}

/// Map a finding-bearing event to one compact JSON line for --jsonl streaming.
/// The lifecycle events (SourceRun, SourceSkipped, SourceError) carry no
/// finding and return None. Each line gets a `kind` tag so a consumer can
/// dispatch on it. IpInfo and Takeover reuse their serde derives; the simpler
/// events are built inline to match the documented shapes.
pub fn event_to_jsonl(e: &crate::engine::FindingEvent) -> Option<String> {
    use crate::engine::FindingEvent::*;
    let value = match e {
        Host(host, source) => {
            serde_json::json!({ "kind": "host", "host": host, "source": source })
        }
        Record(r) => serde_json::json!({
            "kind": "record",
            "name": r.name,
            "type": r.rtype.to_string(),
            "value": r.value,
        }),
        Ip(info) => {
            let mut v = serde_json::to_value(info).ok()?;
            if let serde_json::Value::Object(map) = &mut v {
                map.insert("kind".into(), serde_json::Value::String("ip".into()));
            }
            v
        }
        Takeover(t) => {
            let mut v = serde_json::to_value(t).ok()?;
            if let serde_json::Value::Object(map) = &mut v {
                map.insert("kind".into(), serde_json::Value::String("takeover".into()));
            }
            v
        }
        AxfrSuccess(ns, records) => serde_json::json!({
            "kind": "zone_transfer",
            "ns": ns,
            "records": records,
        }),
        Probe(p) => {
            let mut v = serde_json::to_value(p).ok()?;
            if let serde_json::Value::Object(map) = &mut v {
                map.insert("kind".into(), serde_json::Value::String("probe".into()));
            }
            v
        }
        SourceRun(_) | SourceSkipped(_, _) | SourceError(_, _) | DomainInactive(_) => return None,
    };
    serde_json::to_string(&value).ok()
}

pub fn write_csv(f: &Findings, path: &Path) -> anyhow::Result<()> {
    let mut w = csv::Writer::from_path(path)?;
    w.write_record(["name", "type", "value"])?;
    for host in &f.hosts {
        w.write_record([host.as_str(), "HOST", ""])?;
    }
    for r in &f.records {
        w.write_record([&r.name, &r.rtype.to_string(), &r.value])?;
    }
    for ip in &f.ips {
        w.write_record([
            ip.ip.to_string().as_str(),
            "IP",
            format_ip_value(ip).as_str(),
        ])?;
    }
    for t in &f.takeovers {
        let value = format!("service={}; cname={}; {}", t.service, t.cname, t.evidence);
        w.write_record([t.host.as_str(), "TAKEOVER", value.as_str()])?;
    }
    for a in &f.axfr {
        let value = format!("records={}", a.records);
        w.write_record([a.ns.as_str(), "AXFR", value.as_str()])?;
    }
    for p in &f.probes {
        w.write_record([p.host.as_str(), "PROBE", format_probe_value(p).as_str()])?;
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Findings;
    use crate::model::{DnsRecord, IpInfo, RecordType, Service};

    #[test]
    fn json_contains_record() {
        let mut f = Findings::default();
        f.records.push(DnsRecord {
            name: "dev.example.com".into(),
            rtype: RecordType::A,
            value: "1.2.3.4".into(),
        });
        let json = to_json(&f).unwrap();
        assert!(json.contains("dev.example.com"));
        assert!(json.contains("1.2.3.4"));
    }

    #[test]
    fn exports_include_zone_transfers() {
        let mut f = Findings::default();
        f.axfr.push(crate::engine::AxfrTransfer {
            ns: "ns1.example.com".into(),
            records: 42,
        });

        let json = to_json(&f).unwrap();
        assert!(json.contains("zone_transfers"));
        assert!(json.contains("ns1.example.com"));
        assert!(json.contains("42"));

        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_csv(&f, tmp.path()).unwrap();
        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        let axfr_row = contents
            .lines()
            .find(|l| l.starts_with("ns1.example.com,AXFR,"));
        assert!(
            axfr_row.is_some(),
            "expected an AXFR row for ns1.example.com"
        );
        assert!(axfr_row.unwrap().contains("records=42"));
    }

    #[test]
    fn exports_include_probes() {
        let mut f = Findings::default();
        f.probes.push(crate::probe::HostProbe {
            host: "dev.example.com".into(),
            status: Some(200),
            title: Some("Home".into()),
            final_url: Some("https://dev.example.com/".into()),
            tls_sans: vec!["dev.example.com".into(), "www.example.com".into()],
        });

        let json = to_json(&f).unwrap();
        assert!(json.contains("probes"));
        assert!(json.contains("dev.example.com"));
        assert!(json.contains("www.example.com"));

        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_csv(&f, tmp.path()).unwrap();
        let contents = std::fs::read_to_string(tmp.path()).unwrap();
        let probe_row = contents
            .lines()
            .find(|l| l.starts_with("dev.example.com,PROBE,"));
        let probe_row = probe_row.expect("expected a PROBE row for dev.example.com");
        assert!(probe_row.contains("status=200"));
        assert!(probe_row.contains("title=Home"));

        let line = event_to_jsonl(&crate::engine::FindingEvent::Probe(f.probes[0].clone()))
            .expect("a probe event maps to a line");
        assert!(line.contains("\"kind\":\"probe\""));
        assert!(line.contains("dev.example.com"));
    }

    #[test]
    fn event_to_jsonl_maps_findings_and_skips_lifecycle() {
        use crate::engine::FindingEvent;

        let record = FindingEvent::Record(DnsRecord {
            name: "dev.example.com".into(),
            rtype: RecordType::A,
            value: "1.2.3.4".into(),
        });
        let line = event_to_jsonl(&record).expect("a record event maps to a line");
        assert!(line.contains("\"kind\":\"record\""));
        assert!(line.contains("\"type\":\"A\""));
        assert!(line.contains("dev.example.com"));
        assert!(line.contains("1.2.3.4"));

        // A lifecycle event carries no finding and must not produce a line.
        assert!(event_to_jsonl(&FindingEvent::SourceRun("crt.sh")).is_none());
    }

    #[test]
    fn write_csv_exports_hosts_records_and_ips() {
        let mut f = Findings::default();
        f.hosts.insert("dev.example.com".into());
        f.records.push(DnsRecord {
            name: "dev.example.com".into(),
            rtype: RecordType::A,
            value: "1.2.3.4".into(),
        });
        f.ips.push(IpInfo {
            ip: "1.2.3.4".parse().unwrap(),
            ptr: Some("dns.google".into()),
            asn: Some(15169),
            asn_name: Some("GOOGLE, US".into()),
            rir: Some("arin".into()),
            prefix: None,
            country: None,
            org: None,
            services: vec![Service {
                port: 443,
                name: "nginx".into(),
            }],
        });

        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_csv(&f, tmp.path()).unwrap();
        let contents = std::fs::read_to_string(tmp.path()).unwrap();

        assert!(contents.contains("name,type,value"));

        let host_row = contents
            .lines()
            .find(|l| l.contains("dev.example.com") && l.contains("HOST"));
        assert!(
            host_row.is_some(),
            "expected a HOST row for dev.example.com"
        );

        let record_row = contents
            .lines()
            .find(|l| l.contains("dev.example.com") && l.contains("A") && l.contains("1.2.3.4"));
        assert!(record_row.is_some(), "expected the A record row");

        let ip_row = contents.lines().find(|l| l.starts_with("1.2.3.4,IP,"));
        let ip_row = ip_row.expect("expected an IP row for 1.2.3.4");
        assert!(ip_row.contains("AS15169"));
        assert!(ip_row.contains("443/nginx"));
    }
}
