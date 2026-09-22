use ipnet::IpNet;
use serde::Serialize;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Domain(String),
    Ip(IpAddr),
    Cidr(IpNet),
}

#[derive(Debug, thiserror::Error)]
pub enum TargetParseError {
    #[error("'{0}' is not a valid domain, IP, or CIDR")]
    Invalid(String),
}

impl Target {
    pub fn parse(input: &str) -> Result<Target, TargetParseError> {
        let s = input.trim();
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Target::Ip(ip));
        }
        if let Ok(net) = s.parse::<IpNet>() {
            return Ok(Target::Cidr(net));
        }
        let domain_to_check = s.strip_suffix('.').unwrap_or(s);
        if is_domain(domain_to_check) {
            return Ok(Target::Domain(normalize_host(s)));
        }
        Err(TargetParseError::Invalid(input.to_string()))
    }
}

fn is_domain(s: &str) -> bool {
    if !s.contains('.') || s.contains(' ') {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

pub fn normalize_host(name: &str) -> String {
    let trimmed = name.trim();
    trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

/// True if `name` (already normalized) is a syntactically valid DNS host name we
/// should attempt to resolve. OSINT sources such as crt.sh return certificate
/// SAN entries that are not host names at all - email addresses (`user@host`),
/// descriptive text with spaces, or empty labels - and those must not be
/// recorded as discovered hosts or wasted on doomed DNS lookups. Underscore is
/// permitted since it appears in legitimate DNS names (`_dmarc`, `_domainkey`).
pub fn is_valid_hostname(name: &str) -> bool {
    if !name.contains('.') || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(into = "String")]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Soa,
    Txt,
    Srv,
    Caa,
    Ptr,
    // Output-only: these arrive from AXFR zone dumps only and are never
    // queried or accepted as input (see FromStr and all() below).
    Ds,
    Dnskey,
    Nsec,
    Nsec3,
    Hinfo,
    Naptr,
    Tlsa,
    Sshfp,
}

impl RecordType {
    pub fn all() -> Vec<RecordType> {
        use RecordType::*;
        vec![A, Aaaa, Cname, Mx, Ns, Soa, Txt, Srv, Caa, Ptr]
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RecordType::*;
        let s = match self {
            A => "A",
            Aaaa => "AAAA",
            Cname => "CNAME",
            Mx => "MX",
            Ns => "NS",
            Soa => "SOA",
            Txt => "TXT",
            Srv => "SRV",
            Caa => "CAA",
            Ptr => "PTR",
            Ds => "DS",
            Dnskey => "DNSKEY",
            Nsec => "NSEC",
            Nsec3 => "NSEC3",
            Hinfo => "HINFO",
            Naptr => "NAPTR",
            Tlsa => "TLSA",
            Sshfp => "SSHFP",
        };
        f.write_str(s)
    }
}

impl FromStr for RecordType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use RecordType::*;
        match s.to_ascii_uppercase().as_str() {
            "A" => Ok(A),
            "AAAA" => Ok(Aaaa),
            "CNAME" => Ok(Cname),
            "MX" => Ok(Mx),
            "NS" => Ok(Ns),
            "SOA" => Ok(Soa),
            "TXT" => Ok(Txt),
            "SRV" => Ok(Srv),
            "CAA" => Ok(Caa),
            "PTR" => Ok(Ptr),
            other => Err(format!("unknown record type: {other}")),
        }
    }
}

impl From<RecordType> for String {
    fn from(rt: RecordType) -> Self {
        rt.to_string()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: RecordType,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CandidateValue {
    Host(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub value: CandidateValue,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Service {
    pub port: u16,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpInfo {
    pub ip: IpAddr,
    pub ptr: Option<String>,
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub rir: Option<String>,
    pub prefix: Option<String>,
    pub country: Option<String>,
    pub org: Option<String>,
    pub services: Vec<Service>,
}

/// A potential subdomain takeover: a host whose CNAME points at a
/// takeover-prone third-party service that appears to be unclaimed.
#[derive(Debug, Clone, Serialize)]
pub struct Takeover {
    pub host: String,
    pub service: String,
    pub cname: String,
    pub evidence: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn parses_ipv4_as_ip() {
        assert_eq!(
            Target::parse("192.0.2.125").unwrap(),
            Target::Ip("192.0.2.125".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn parses_cidr_as_cidr() {
        assert_eq!(
            Target::parse("192.0.2.0/24").unwrap(),
            Target::Cidr("192.0.2.0/24".parse().unwrap())
        );
    }

    #[test]
    fn parses_domain_as_domain() {
        assert_eq!(
            Target::parse("example.com").unwrap(),
            Target::Domain("example.com".to_string())
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(Target::parse("not a domain").is_err());
    }

    #[test]
    fn normalizes_host() {
        assert_eq!(normalize_host("DEV.Example.COM."), "dev.example.com");
    }

    #[test]
    fn parses_trailing_dot_domain() {
        assert_eq!(
            Target::parse("example.com.").unwrap(),
            Target::Domain("example.com".to_string())
        );
    }

    #[test]
    fn rejects_domain_with_space() {
        assert!(Target::parse("foo bar.com").is_err());
    }

    #[test]
    fn rejects_empty_label() {
        assert!(Target::parse("foo..com").is_err());
    }

    #[test]
    fn rejects_oversized_label() {
        let oversized = format!("{}label.com", "a".repeat(64));
        assert!(Target::parse(&oversized).is_err());
    }

    #[test]
    fn accepts_valid_hostnames() {
        assert!(is_valid_hostname("dev.example.com"));
        assert!(is_valid_hostname("_dmarc.example.com"));
    }

    #[test]
    fn rejects_certificate_san_junk() {
        // The exact shapes crt.sh emits alongside real host names.
        assert!(!is_valid_hostname("user@example.com"));
        assert!(!is_valid_hostname("subjectname@example.com"));
        assert!(!is_valid_hostname(
            "as207960 test intermediate - example.com"
        ));
        assert!(!is_valid_hostname("no-dot-here"));
        assert!(!is_valid_hostname("foo..com"));
    }

    #[test]
    fn record_type_roundtrip() {
        assert_eq!("AAAA".parse::<RecordType>().unwrap(), RecordType::Aaaa);
        assert_eq!(RecordType::Mx.to_string(), "MX");
    }

    #[test]
    fn record_type_all_has_ten() {
        assert_eq!(RecordType::all().len(), 10);
    }

    #[test]
    fn displays_extra_axfr_types() {
        assert_eq!(RecordType::Dnskey.to_string(), "DNSKEY");
        assert_eq!(RecordType::Nsec3.to_string(), "NSEC3");
        assert_eq!(RecordType::Sshfp.to_string(), "SSHFP");
    }

    #[test]
    fn fromstr_rejects_non_queryable_extra_types() {
        assert!("DNSKEY".parse::<RecordType>().is_err());
    }

    #[test]
    fn all_still_has_ten() {
        assert_eq!(RecordType::all().len(), 10);
    }
}
