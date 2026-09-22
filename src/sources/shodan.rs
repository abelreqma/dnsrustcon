use crate::model::Service;
use crate::resolve::enrich::ServiceProvider;
use crate::sources::{get_with_headers, http_client};
use std::net::IpAddr;

pub fn parse_shodan_services(body: &str) -> Vec<Service> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    v.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let port = u16::try_from(item.get("port")?.as_u64()?).ok()?;
                    let name = item
                        .get("product")
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(Service { port, name })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub struct ShodanClient {
    pub key: String,
}

#[async_trait::async_trait]
impl ServiceProvider for ShodanClient {
    async fn services(&self, ip: IpAddr) -> Vec<Service> {
        let client = match http_client() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let url = format!("https://api.shodan.io/shodan/host/{ip}?key={}", self.key);
        let resp = match get_with_headers(&client, &url, &[]).await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        match resp.text().await {
            Ok(body) => parse_shodan_services(&body),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_services() {
        let body = r#"{"data":[{"port":443,"product":"nginx"},{"port":22,"product":"OpenSSH"}]}"#;
        let s = parse_shodan_services(body);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].port, 443);
        assert_eq!(s[0].name, "nginx");
    }

    #[test]
    fn skips_out_of_range_port() {
        let body = r#"{"data":[{"port":70000,"product":"x"},{"port":443,"product":"nginx"}]}"#;
        let s = parse_shodan_services(body);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].port, 443);
    }
}
