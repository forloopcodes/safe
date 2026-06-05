// Domain reputation matches installer hosts against curated trust databases.
// Unknown or uncategorized hosts produce advisory findings without blocking.

use crate::analyzer::{Finding, Severity};

const TRUSTED: &[&str] = &[
    "github.com",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "npmjs.org",
    "nodejs.org",
    "deno.land",
    "bun.sh",
    "rust-lang.org",
    "crates.io",
    "python.org",
    "pypi.org",
    "golang.org",
    "go.dev",
    "curl.se",
    "brew.sh",
    "code.visualstudio.com",
    "get.docker.com",
    "docs.docker.com",
    "tailscale.com",
    "fly.io",
    "netlify.com",
    "vercel.com",
    "sh.rustup.rs",
    "static.rust-lang.org",
    "dl.google.com",
    "gitlab.com",
    "bitbucket.org",
    "mirrors.edge.kernel.org",
    "deb.debian.org",
    "archive.ubuntu.com",
    "dl.fedoraproject.org",
    "pkgs.alpinelinux.org",
];

pub fn check(host: &str) -> Option<Finding> {
    let trimmed = host.trim_start_matches("www.");
    if TRUSTED.contains(&trimmed)
        || TRUSTED.iter().any(|t| {
            trimmed.len() > t.len()
                && trimmed.as_bytes()[trimmed.len() - t.len() - 1] == b'.'
                && trimmed.ends_with(t)
        })
    {
        return None;
    }
    if trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Some(Finding {
            source: "Reputation",
            title: "Raw IP installation source",
            detail: "Installer originates from an IP address instead of a named domain",
            severity: Severity::Medium,
            score: 12,
            evidence: host.to_string(),
        });
    }
    if trimmed.ends_with(".cloudfront.net")
        || trimmed.ends_with(".s3.amazonaws.com")
        || trimmed.ends_with(".storage.googleapis.com")
    {
        return Some(Finding {
            source: "Reputation",
            title: "Cloud storage download host",
            detail: "Content originates from cloud storage which may have weak publisher verification",
            severity: Severity::Low,
            score: 5,
            evidence: host.to_string(),
        });
    }
    Some(Finding {
        source: "Reputation",
        title: "Uncommon download host",
        detail: "Host is not in the trusted installer publisher database",
        severity: Severity::Medium,
        score: 10,
        evidence: host.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_host_is_clean() {
        assert!(check("github.com").is_none());
        assert!(check("bun.sh").is_none());
        assert!(check("raw.githubusercontent.com").is_none());
    }

    #[test]
    fn subdomain_of_trusted_host_is_clean() {
        assert!(check("pages.github.com").is_none());
    }

    #[test]
    fn unknown_host_produces_finding() {
        let result = check("evil-downloads.xyz");
        assert!(result.is_some());
        assert_eq!(result.unwrap().score, 10);
    }

    #[test]
    fn ip_address_source_is_flagged() {
        let result = check("94.23.45.67");
        assert!(result.is_some());
        assert_eq!(result.unwrap().score, 12);
    }

    #[test]
    fn cloudfront_source_is_low_risk() {
        let result = check("d3pcsg2wjq9izr.cloudfront.net");
        assert!(result.is_some());
        assert_eq!(result.unwrap().score, 5);
    }
}
