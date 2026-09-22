use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginInfo {
    pub asn: u32,
    pub prefix: String,
    pub country: String,
    pub registry: String,
}

pub fn origin_query_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut nibbles = String::new();
            for byte in v6.octets().iter().rev() {
                nibbles.push_str(&format!("{:x}.{:x}.", byte & 0xf, byte >> 4));
            }
            format!("{nibbles}origin6.asn.cymru.com")
        }
    }
}

fn fields(txt: &str) -> Vec<String> {
    txt.trim_matches('"')
        .split('|')
        .map(|s| s.trim().to_string())
        .collect()
}

pub fn parse_origin(txt: &str) -> Option<OriginInfo> {
    let f = fields(txt);
    if f.len() < 4 {
        return None;
    }
    Some(OriginInfo {
        asn: f[0].split_whitespace().next()?.parse().ok()?,
        prefix: f[1].clone(),
        country: f[2].clone(),
        registry: f[3].clone(),
    })
}

pub fn parse_asname(txt: &str) -> Option<String> {
    let f = fields(txt);
    f.last().filter(|s| !s.is_empty()).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn builds_reversed_origin_name() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(origin_query_name(ip), "8.8.8.8.origin.asn.cymru.com");
    }

    #[test]
    fn parses_origin_txt() {
        let txt = "15169 | 8.8.8.0/24 | US | arin | 1992-12-01";
        let o = parse_origin(txt).unwrap();
        assert_eq!(o.asn, 15169);
        assert_eq!(o.prefix, "8.8.8.0/24");
        assert_eq!(o.country, "US");
        assert_eq!(o.registry, "arin");
    }

    #[test]
    fn parses_asname_txt() {
        let txt = "15169 | US | arin | 1992-12-01 | GOOGLE, US";
        assert_eq!(parse_asname(txt).unwrap(), "GOOGLE, US");
    }
}
