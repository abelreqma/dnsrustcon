use crate::resolve::enrich::OrgProvider;
use std::net::IpAddr;

/// Extract the registered network's organization name from an RDAP IP-network
/// JSON response. RDAP records the org in one of two places: an entity's vCard
/// `fn` (full name) property, or, lacking that, the network object's own
/// `name`. The first entity carrying a vCard full name wins, since that is the
/// registrant/org; the network `name` (netname) is the fallback.
pub fn parse_rdap(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;

    if let Some(entities) = v.get("entities").and_then(|e| e.as_array()) {
        for entity in entities {
            if let Some(name) = vcard_fn(entity) {
                return Some(name);
            }
        }
    }

    v.get("name")
        .and_then(|n| n.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Pull the vCard `fn` (full name) value out of an RDAP entity. The vcardArray
/// is `["vcard", [ [prop, {}, type, value], ... ]]`; the `fn` property carries
/// the value at index 3.
fn vcard_fn(entity: &serde_json::Value) -> Option<String> {
    let props = entity.get("vcardArray")?.as_array()?.get(1)?.as_array()?;
    for prop in props {
        if let Some(p) = prop.as_array() {
            if p.first().and_then(|n| n.as_str()) == Some("fn") {
                if let Some(val) = p.get(3).and_then(|v| v.as_str()) {
                    if !val.is_empty() {
                        return Some(val.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Keyless RDAP lookup provider. Queries rdap.org, which redirects to the
/// authoritative RIR for the address; reqwest follows the redirect.
pub struct RdapClient {
    client: reqwest::Client,
}

impl RdapClient {
    pub fn new() -> reqwest::Result<Self> {
        Ok(Self {
            client: crate::sources::http_client()?,
        })
    }
}

#[async_trait::async_trait]
impl OrgProvider for RdapClient {
    async fn org(&self, ip: IpAddr) -> Option<String> {
        let url = format!("https://rdap.org/ip/{ip}");
        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/rdap+json")
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = resp.text().await.ok()?;
        parse_rdap(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_org_from_entity_vcard() {
        let body = r#"{
            "name": "GOOGLE",
            "entities": [
                {"vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Google LLC"]
                ]]}
            ]
        }"#;
        assert_eq!(parse_rdap(body).as_deref(), Some("Google LLC"));
    }

    #[test]
    fn falls_back_to_network_name() {
        let body = r#"{"name": "GOOGLE", "entities": []}"#;
        assert_eq!(parse_rdap(body).as_deref(), Some("GOOGLE"));
    }

    #[test]
    fn none_on_empty_response() {
        assert_eq!(parse_rdap("{}"), None);
    }
}
