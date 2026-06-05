// OSV.dev vulnerability database lookup for packages identified from installer URLs.
// Falls back silently when no package name can be extracted or network fails.

use crate::analyzer::{Finding, Severity};
use url::Url;

struct PackageHint {
    name: &'static str,
    ecosystems: &'static [&'static str],
}

const HINTS: &[(&str, PackageHint)] = &[
    (
        "bun.sh",
        PackageHint {
            name: "bun",
            ecosystems: &["npm"],
        },
    ),
    (
        "deno.land",
        PackageHint {
            name: "deno",
            ecosystems: &["npm"],
        },
    ),
    (
        "sh.rustup.rs",
        PackageHint {
            name: "rustup",
            ecosystems: &["crates.io"],
        },
    ),
    (
        "rustup.rs",
        PackageHint {
            name: "rustup",
            ecosystems: &["crates.io"],
        },
    ),
    (
        "get.docker.com",
        PackageHint {
            name: "docker",
            ecosystems: &["npm"],
        },
    ),
    (
        "brew.sh",
        PackageHint {
            name: "homebrew",
            ecosystems: &["RubyGems"],
        },
    ),
    (
        "go.dev",
        PackageHint {
            name: "go",
            ecosystems: &["Go"],
        },
    ),
    (
        "nodejs.org",
        PackageHint {
            name: "node",
            ecosystems: &["npm"],
        },
    ),
    (
        "curl.se",
        PackageHint {
            name: "curl",
            ecosystems: &["crates.io"],
        },
    ),
    (
        "code.visualstudio.com",
        PackageHint {
            name: "vscode",
            ecosystems: &["npm"],
        },
    ),
    (
        "tailscale.com",
        PackageHint {
            name: "tailscale",
            ecosystems: &["Go"],
        },
    ),
    (
        "fly.io",
        PackageHint {
            name: "flyctl",
            ecosystems: &["npm"],
        },
    ),
    (
        "netlify.com",
        PackageHint {
            name: "netlify-cli",
            ecosystems: &["npm"],
        },
    ),
    (
        "vercel.com",
        PackageHint {
            name: "vercel",
            ecosystems: &["npm"],
        },
    ),
    (
        "crates.io",
        PackageHint {
            name: "",
            ecosystems: &["crates.io"],
        },
    ),
    (
        "pypi.org",
        PackageHint {
            name: "",
            ecosystems: &["PyPI"],
        },
    ),
    (
        "npmjs.org",
        PackageHint {
            name: "",
            ecosystems: &["npm"],
        },
    ),
];

const FALLBACK_ECOSYSTEMS: &[&str] = &["npm", "crates.io", "PyPI", "Go", "RubyGems"];

pub async fn check(url: &Url) -> Vec<Finding> {
    let host = url.host_str().unwrap_or("");
    let hints = resolve(host, url.path());
    let mut findings = Vec::new();
    for (ecosystem, name) in hints {
        findings.extend(check_package(ecosystem, &name).await);
    }
    findings
}

pub async fn check_package(ecosystem: &str, package: &str) -> Vec<Finding> {
    query(ecosystem, package).await.into_iter().collect()
}

fn resolve(host: &str, path: &str) -> Vec<(&'static str, String)> {
    let trimmed = host.trim_start_matches("www.");
    for (domain, hint) in HINTS {
        if *domain == trimmed {
            if hint.name.is_empty() {
                let seg = path
                    .trim_start_matches('/')
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_owned();
                return vec![(hint.ecosystems[0], seg)];
            }
            return hint
                .ecosystems
                .iter()
                .map(|e| (*e, hint.name.to_owned()))
                .collect();
        }
    }
    if trimmed.ends_with(".github.io") || trimmed == "github.com" {
        let segs: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
        if segs.len() >= 2 {
            return FALLBACK_ECOSYSTEMS
                .iter()
                .map(|e| (*e, segs[1].to_owned()))
                .collect();
        }
    }
    Vec::new()
}

fn score_from_cvss_vector(vector: &str) -> Option<f64> {
    if !vector.starts_with("CVSS:") {
        return None;
    }
    let metrics: std::collections::HashMap<&str, &str> = vector
        .split('/')
        .filter_map(|m| {
            let mut parts = m.splitn(2, ':');
            Some((parts.next()?, parts.next()?))
        })
        .collect();

    let av = match metrics.get("AV") {
        Some(&"N") => 0.85,
        Some(&"A") => 0.62,
        Some(&"L") => 0.55,
        Some(&"P") => 0.20,
        _ => return None,
    };
    let ac = match metrics.get("AC") {
        Some(&"L") => 0.77,
        Some(&"H") => 0.44,
        _ => return None,
    };
    let scope_changed = metrics.get("S").is_none_or(|s| *s != "U");
    let pr = if !scope_changed {
        match metrics.get("PR") {
            Some(&"N") => 0.85,
            Some(&"L") => 0.62,
            Some(&"H") => 0.27,
            _ => return None,
        }
    } else {
        match metrics.get("PR") {
            Some(&"N") => 0.85,
            Some(&"L") => 0.68,
            Some(&"H") => 0.50,
            _ => return None,
        }
    };
    let ui = match metrics.get("UI") {
        Some(&"N") => 0.85,
        Some(&"R") => 0.62,
        _ => return None,
    };
    let c = match metrics.get("C") {
        Some(&"H") => 0.56,
        Some(&"L") => 0.22,
        Some(&"N") => 0.00,
        _ => return None,
    };
    let i = match metrics.get("I") {
        Some(&"H") => 0.56,
        Some(&"L") => 0.22,
        Some(&"N") => 0.00,
        _ => return None,
    };
    let a = match metrics.get("A") {
        Some(&"H") => 0.56,
        Some(&"L") => 0.22,
        Some(&"N") => 0.00,
        _ => return None,
    };

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let iss = 6.42 * iss;
    let exploitability = 8.22 * av * ac * pr * ui;

    if iss <= 0.0 {
        return Some(0.0);
    }
    let base: f64 = if scope_changed {
        (iss + exploitability) * 1.08
    } else {
        iss + exploitability
    };
    let base = base.min(10.0);
    Some((base * 10.0).round() / 10.0)
}

struct VulnEntry {
    id: String,
    cve: Option<String>,
    cvss: f64,
    summary: String,
    date: Option<String>,
}

fn approximate_days_old(date: &Option<String>, now_secs: f64) -> f64 {
    let d = match date {
        Some(s) if s.len() >= 10 => s,
        _ => return 365.0,
    };
    let y: f64 = d[..4].parse().unwrap_or(2020.0);
    let m: f64 = d[5..7].parse().unwrap_or(6.0);
    let dd: f64 = d[8..10].parse().unwrap_or(15.0);
    let epoch_days = (y - 1970.0) * 365.25 + (m - 1.0) * 30.44 + dd;
    (now_secs / 86400.0 - epoch_days).max(0.0)
}

fn recency_weight(days: f64) -> f64 {
    (-0.08 * days / 365.0).exp()
}

async fn query(ecosystem: &str, package: &str) -> Option<Finding> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("safeinstall/0.1.0")
        .build()
        .ok()?;

    let body = serde_json::json!({"package": {"name": package, "ecosystem": ecosystem}});
    let resp = client
        .post("https://api.osv.dev/v1/query")
        .json(&body)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let vulns = json["vulns"].as_array()?;
    if vulns.is_empty() {
        return None;
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    let mut entries: Vec<VulnEntry> = vulns
        .iter()
        .filter_map(|v| {
            let id = v["id"].as_str()?.to_owned();
            let cve = v["aliases"]
                .as_array()
                .and_then(|a| a.iter().filter_map(|a| a.as_str()).find(|s| s.starts_with("CVE-")))
                .map(|s| s.to_owned());
            let summary = v["summary"].as_str().unwrap_or("").to_owned();
            let date = v["published"].as_str().map(|s| if s.len() >= 10 { s[..10].to_owned() } else { s.to_owned() });
            let cvss = if let Some(score) = v["database_specific"]["cvss"]["score"].as_f64()
                && score > 0.0
            {
                score
            } else if let Some(arr) = v["severity"].as_array() {
                let mut found = 3.0_f64;
                for entry in arr {
                    let stype = entry["type"].as_str().unwrap_or("");
                    if stype.contains("CVSS")
                        && let Some(parsed) = score_from_cvss_vector(entry["score"].as_str().unwrap_or(""))
                    {
                        found = parsed;
                        break;
                    }
                }
                found
            } else {
                match v["database_specific"]["severity"].as_str() {
                    Some(s) if s.eq_ignore_ascii_case("critical") => 9.5,
                    Some(s) if s.eq_ignore_ascii_case("high") => 8.0,
                    Some(s) if s.eq_ignore_ascii_case("moderate") || s.eq_ignore_ascii_case("medium") => 5.5,
                    _ => 3.0,
                }
            };
            Some(VulnEntry { id, cve, cvss, summary, date })
        })
        .collect();
    entries.sort_by(|a, b| {
        let ka = a.cvss * recency_weight(approximate_days_old(&a.date, now_secs));
        let kb = b.cvss * recency_weight(approximate_days_old(&b.date, now_secs));
        kb.partial_cmp(&ka).unwrap_or(std::cmp::Ordering::Equal)
    });

    let count = entries.len();
    let energy: f64 = entries
        .iter()
        .map(|e| {
            let days = approximate_days_old(&e.date, now_secs);
            recency_weight(days) * (e.cvss / 10.0_f64).powi(3)
        })
        .sum();
    let raw = 100.0 * (1.0 - (-0.5 * energy).exp());
    let score = (raw.round() as u8).min(100);
    let severity = match score {
        0..=25 => Severity::Low,
        26..=50 => Severity::Medium,
        51..=75 => Severity::High,
        _ => Severity::Critical,
    };

    let crit: Vec<&VulnEntry> = entries.iter().filter(|e| e.cvss >= 9.0).collect();
    let high: Vec<&VulnEntry> = entries.iter().filter(|e| e.cvss >= 7.0 && e.cvss < 9.0).collect();
    let mod_low = entries.len() - crit.len() - high.len();
    let trimmed = |s: &str| if s.len() > 55 { format!("{}…", &s[..52]) } else { s.to_owned() };

    let mut evidence = format!(
        "{} ({}) - {} known advisories\n  Critical: {}  High: {}  Moderate/Low: {}",
        ecosystem, package, count, crit.len(), high.len(), mod_low,
    );

    if !crit.is_empty() {
        let showing = crit.len().min(5);
        evidence.push_str(&format!("\n\n  Critical ({}):", if showing < crit.len() { format!("top {} of {}", showing, crit.len()) } else { crit.len().to_string() }));
        for entry in crit.iter().take(showing) {
            let display_id = entry.cve.as_deref().unwrap_or(&entry.id);
            evidence.push_str(&format!(
                "\n    {} {:4.1}  {:10}  {}",
                format_args!("{:<24}", display_id),
                entry.cvss,
                entry.date.as_deref().unwrap_or("--"),
                trimmed(&entry.summary),
            ));
        }
    }

    if !high.is_empty() {
        let showing = high.len().min(5);
        evidence.push_str(&format!("\n\n  High ({}):", if showing < high.len() { format!("top {} of {}", showing, high.len()) } else { high.len().to_string() }));
        for entry in high.iter().take(showing) {
            let display_id = entry.cve.as_deref().unwrap_or(&entry.id);
            evidence.push_str(&format!(
                "\n    {} {:4.1}  {:10}  {}",
                format_args!("{:<24}", display_id),
                entry.cvss,
                entry.date.as_deref().unwrap_or("--"),
                trimmed(&entry.summary),
            ));
        }
    }

    if mod_low > 0 {
        evidence.push_str(&format!("\n  + {} more moderate/low severity advisories", mod_low));
    }

    Some(Finding {
        source: if ecosystem == "GitHub" { "OSV (GitHub)" } else { "OSV" },
        title: "Known vulnerabilities in package",
        detail: "The software being installed has publicly known security vulnerabilities",
        severity,
        score,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_npm_package() {
        let url = Url::parse("https://bun.sh/install").unwrap();
        let hints = resolve("bun.sh", url.path());
        assert!(hints.contains(&("npm", "bun".to_owned())));
    }

    #[test]
    fn extracts_github_repo() {
        let url = Url::parse("https://github.com/ovrtaylor/some-tool/releases").unwrap();
        let hints = resolve("github.com", url.path());
        assert!(hints.iter().any(|(_, n)| n == "some-tool"));
    }

    #[test]
    fn unknown_domain_returns_empty() {
        let url = Url::parse("https://some-random-site.xyz/install").unwrap();
        let hints = resolve("some-random-site.xyz", url.path());
        assert!(hints.is_empty());
    }

    #[test]
    fn parses_cvss_high() {
        let v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let score = score_from_cvss_vector(v).unwrap();
        assert!((score - 9.8).abs() < 0.1, "expected ~9.8, got {score}");
    }

    #[test]
    fn parses_cvss_medium() {
        let v = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N";
        let score = score_from_cvss_vector(v).unwrap();
        assert!((score - 4.6).abs() < 0.2, "expected ~4.6, got {score}");
    }

    #[test]
    fn parses_cvss_low() {
        let v = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N";
        let score = score_from_cvss_vector(v).unwrap();
        assert!((score - 1.7).abs() < 0.2, "expected ~1.7, got {score}");
    }
}
