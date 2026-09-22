//! Opt-in HTTP/TLS probing of discovered hosts. Every function here is
//! non-fatal: a per-host failure yields a partial or empty probe rather than
//! aborting the run, so the engine can fan this out across all hosts without
//! any one of them being able to take the pass down.

use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

/// What a single host probe captured. Any field may be absent when the host did
/// not answer, redirected without a title, or refused a TLS handshake.
#[derive(Debug, Clone, Serialize)]
pub struct HostProbe {
    pub host: String,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub final_url: Option<String>,
    pub tls_sans: Vec<String>,
}

/// How long to wait on the TCP connect plus TLS handshake before giving up. The
/// HTTP side is already bounded by the shared http_client() request timeout.
const TLS_TIMEOUT_SECS: u64 = 10;

/// Probe a single host over HTTP(S). Tries HTTPS first, then HTTP, and records
/// the status code, the final URL after redirects, and the page title from the
/// first scheme that answers. On total failure every field is None/empty; this
/// never panics. TLS SANs are collected separately by `tls_san_dns_names`.
pub async fn probe_host(http: &reqwest::Client, host: &str) -> HostProbe {
    let mut probe = HostProbe {
        host: host.to_string(),
        status: None,
        title: None,
        final_url: None,
        tls_sans: Vec::new(),
    };

    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{host}/");
        if let Ok(resp) = http.get(&url).send().await {
            probe.status = Some(resp.status().as_u16());
            probe.final_url = Some(resp.url().to_string());
            if let Ok(body) = resp.text().await {
                probe.title = parse_title(&body);
            }
            break;
        }
    }

    probe
}

/// Extract the page title from an HTML body. Scans case-insensitively for a
/// `<title ...>...</title>` pair, tolerating attributes on the opening tag and
/// any casing, then trims and collapses internal whitespace. Returns None when
/// there is no title element or it is empty. Uses no HTML parsing crate.
pub fn parse_title(html: &str) -> Option<String> {
    // ASCII-lowercasing preserves byte length, so offsets found here index the
    // original `html` correctly, and every offset lands on an ASCII boundary.
    let lower = html.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let content_start = open + lower[open..].find('>')? + 1;
    let content_len = lower[content_start..].find("</title>")?;
    let raw = &html[content_start..content_start + content_len];
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed)
    }
}

/// Open a TLS connection to `{host}:443` and return the leaf certificate's SAN
/// dNSName entries. Empty on any failure (DNS, connect, handshake, no peer
/// certificate), so the caller can treat it as best-effort.
pub async fn tls_san_dns_names(host: &str) -> Vec<String> {
    use tokio::net::TcpStream;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Pin the ring provider explicitly rather than relying on a process-wide
    // default provider being installed, which would panic if it were not.
    let config = match ClientConfig::builder_with_provider(
        tokio_rustls::rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    {
        Ok(b) => b.with_root_certificates(roots).with_no_client_auth(),
        Err(_) => return Vec::new(),
    };

    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    let connector = TlsConnector::from(Arc::new(config));
    let timeout = Duration::from_secs(TLS_TIMEOUT_SECS);

    let handshake = async {
        let stream = TcpStream::connect((host, 443)).await.ok()?;
        let tls = connector.connect(server_name, stream).await.ok()?;
        let (_, conn) = tls.get_ref();
        let leaf = conn.peer_certificates()?.first()?.clone();
        Some(leaf)
    };

    match tokio::time::timeout(timeout, handshake).await {
        Ok(Some(leaf)) => parse_san_dns_names(leaf.as_ref()),
        _ => Vec::new(),
    }
}

/// Extract the dNSName SAN entries from a DER-encoded certificate. Returns an
/// empty vector when the certificate cannot be parsed or carries no SAN
/// extension, so it never fails loudly.
pub fn parse_san_dns_names(der: &[u8]) -> Vec<String> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::*;

    let cert = match X509Certificate::from_der(der) {
        Ok((_, c)) => c,
        Err(_) => return Vec::new(),
    };
    let san = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext.value,
        _ => return Vec::new(),
    };
    san.general_names
        .iter()
        .filter_map(|gn| match gn {
            GeneralName::DNSName(name) => Some((*name).to_string()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_normal_title() {
        assert_eq!(
            parse_title("<html><head><title>Hello World</title></head></html>"),
            Some("Hello World".to_string())
        );
    }

    #[test]
    fn parses_uppercase_title_tag() {
        assert_eq!(
            parse_title("<HTML><TITLE>Login</TITLE></HTML>"),
            Some("Login".to_string())
        );
    }

    #[test]
    fn parses_title_with_attributes_and_collapses_whitespace() {
        assert_eq!(
            parse_title("<title id=\"pg\" data-x='1'>  Home\n\t  Page  </title>"),
            Some("Home Page".to_string())
        );
    }

    #[test]
    fn missing_title_is_none() {
        assert_eq!(parse_title("<html><body>no title here</body></html>"), None);
    }

    #[test]
    fn empty_title_is_none() {
        assert_eq!(parse_title("<title>   </title>"), None);
    }

    // The fixture is a throwaway self-signed cert generated with:
    //   openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null \
    //     -outform DER -out tests/fixtures/san_cert.der -days 1 \
    //     -subj "/CN=example.com" \
    //     -addext "subjectAltName=DNS:a.example.com,DNS:b.example.com"
    #[test]
    fn extracts_san_dns_names_from_fixture() {
        let der = include_bytes!("../tests/fixtures/san_cert.der");
        let sans = parse_san_dns_names(der);
        assert_eq!(sans, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn garbage_der_yields_no_sans() {
        assert!(parse_san_dns_names(b"not a certificate").is_empty());
    }
}
