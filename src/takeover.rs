//! Subdomain-takeover fingerprints and matching.
//!
//! A takeover is possible when a host has a dangling CNAME to a third-party
//! service whose resource (bucket, page, app) no longer exists but whose DNS
//! target the attacker can register. Each fingerprint pairs the service's CNAME
//! suffixes with the tell-tale response body of an unclaimed resource; some
//! services (e.g. Azure) can be judged from a non-resolving CNAME target alone.
//!
//! The list is intentionally curated to well-documented, high-confidence
//! services rather than exhaustive: every finding is reported as *potential* and
//! backed by concrete evidence (a dangling target or a matched body marker).

/// One service's takeover signature.
pub struct Fingerprint {
    /// Human-readable service name.
    pub service: &'static str,
    /// CNAME target suffixes that route to this service (lowercase, no trailing dot).
    pub cname_suffixes: &'static [&'static str],
    /// A substring found in the HTTP response of an unclaimed resource. Empty
    /// when the service cannot be confirmed by body content.
    pub body_marker: &'static str,
    /// True when a CNAME target that fails to resolve is itself sufficient
    /// evidence of takeover (the service frees the DNS name when unclaimed).
    pub nxdomain_is_takeover: bool,
    /// The service's registrable base zone, used as a second signal for
    /// nxdomain services: a dangling target is only trusted when this zone
    /// still resolves (see `check_takeover`). Empty for services that do not
    /// need it.
    pub base_domain: &'static str,
}

/// Curated fingerprint table. Markers are taken from the services' documented
/// unclaimed-resource responses.
pub const FINGERPRINTS: &[Fingerprint] = &[
    Fingerprint {
        service: "GitHub Pages",
        cname_suffixes: &["github.io"],
        body_marker: "There isn't a GitHub Pages site here.",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "AWS S3",
        cname_suffixes: &["s3.amazonaws.com", "s3-website"],
        body_marker: "The specified bucket does not exist",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Heroku",
        cname_suffixes: &["herokudns.com", "herokuapp.com", "herokussl.com"],
        body_marker: "No such app",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Shopify",
        cname_suffixes: &["myshopify.com"],
        body_marker: "Sorry, this shop is currently unavailable",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Fastly",
        cname_suffixes: &["fastly.net"],
        body_marker: "Fastly error: unknown domain",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Surge.sh",
        cname_suffixes: &["surge.sh"],
        body_marker: "project not found",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Bitbucket",
        cname_suffixes: &["bitbucket.io"],
        body_marker: "Repository not found",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Ghost",
        cname_suffixes: &["ghost.io"],
        body_marker: "The thing you were looking for is no longer here",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Pantheon",
        cname_suffixes: &["pantheonsite.io"],
        body_marker: "The gods are wise, but do not know of the site which you seek.",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Read the Docs",
        cname_suffixes: &["readthedocs.io"],
        body_marker: "unknown to Read the Docs",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Azure",
        cname_suffixes: &[
            "azurewebsites.net",
            "cloudapp.net",
            "cloudapp.azure.com",
            "trafficmanager.net",
            "blob.core.windows.net",
            "azureedge.net",
        ],
        body_marker: "",
        nxdomain_is_takeover: true,
        base_domain: "trafficmanager.net",
    },
    Fingerprint {
        service: "Vercel",
        cname_suffixes: &["vercel-dns.com", "vercel.app"],
        body_marker: "The deployment could not be found on Vercel",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Netlify",
        cname_suffixes: &["netlify.app", "netlify.com"],
        body_marker: "Not Found - Request ID",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "WordPress.com",
        cname_suffixes: &["wordpress.com"],
        body_marker: "Do you want to register",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Cargo",
        cname_suffixes: &["cargocollective.com"],
        body_marker: "If you're moving your domain away from Cargo",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Tumblr",
        cname_suffixes: &["domains.tumblr.com"],
        body_marker: "Whatever you were looking for doesn't currently exist at this address",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Zendesk",
        cname_suffixes: &["zendesk.com"],
        body_marker: "Help Center Closed",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
    Fingerprint {
        service: "Cloudfront",
        cname_suffixes: &["cloudfront.net"],
        body_marker: "ERROR: The request could not be satisfied",
        nxdomain_is_takeover: false,
        base_domain: "",
    },
];

/// The fingerprint whose CNAME suffix matches `cname`, if any. `cname` may carry
/// a trailing dot and any case.
pub fn match_service(cname: &str) -> Option<&'static Fingerprint> {
    let c = cname.trim_end_matches('.').to_ascii_lowercase();
    FINGERPRINTS
        .iter()
        .find(|fp| fp.cname_suffixes.iter().any(|s| c.ends_with(s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_services() {
        assert_eq!(
            match_service("myblog.github.io.").unwrap().service,
            "GitHub Pages"
        );
        assert_eq!(
            match_service("app.herokuapp.com").unwrap().service,
            "Heroku"
        );
        let azure = match_service("x.trafficmanager.net").unwrap();
        assert_eq!(azure.service, "Azure");
        assert!(azure.nxdomain_is_takeover);
        assert_eq!(match_service("x.vercel-dns.com").unwrap().service, "Vercel");
        assert_eq!(match_service("y.netlify.app").unwrap().service, "Netlify");
        assert_eq!(
            match_service("z.cloudfront.net").unwrap().service,
            "Cloudfront"
        );
    }

    #[test]
    fn ignores_unrelated_cnames() {
        assert!(match_service("cdn.cloudflare.net").is_none());
        assert!(match_service("mail.google.com").is_none());
    }
}
