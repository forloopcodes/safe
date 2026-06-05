// GitHub Advisory Database lookup for package-specific security advisories.
// Queries the public API without authentication for open-source packages.

use crate::analyzer::{Finding, Severity};

struct Entry {
    id: String,
    cve: Option<String>,
    cvss: f64,
    summary: String,
    date: Option<String>,
}

fn days_old(date: &Option<String>, now: f64) -> f64 {
    let d = match date {
        Some(s) if s.len() >= 10 => s,
        _ => return 365.0,
    };
    let y: f64 = d[..4].parse().unwrap_or(2020.0);
    let m: f64 = d[5..7].parse().unwrap_or(6.0);
    let dd: f64 = d[8..10].parse().unwrap_or(15.0);
    let epoch = (y - 1970.0) * 365.25 + (m - 1.0) * 30.44 + dd;
    (now / 86400.0 - epoch).max(0.0)
}

fn recency(days: f64) -> f64 {
    (-0.08 * days / 365.0).exp()
}

fn advisory_cvss(adv: &serde_json::Value) -> f64 {
    if let Some(s) = adv["cvss"]["score"].as_f64()
        && s > 0.0
    {
        return s;
    }
    if let Some(s) = adv["cvss_severities"]["cvss_v4"]["score"].as_f64()
        && s > 0.0
    {
        return s;
    }
    if let Some(s) = adv["cvss_severities"]["cvss_v3"]["score"].as_f64()
        && s > 0.0
    {
        return s;
    }
    match adv["severity"].as_str() {
        Some(s) if s.eq_ignore_ascii_case("critical") => 9.5,
        Some(s) if s.eq_ignore_ascii_case("high") => 8.0,
        Some(s) if s.eq_ignore_ascii_case("medium") => 5.5,
        Some(s) if s.eq_ignore_ascii_case("low") => 3.0,
        _ => 3.0,
    }
}

pub async fn check(ecosystem: &str, package: &str) -> Option<Finding> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("safeinstall/0.1.0")
        .build()
        .ok()?;

    let url = format!(
        "https://api.github.com/advisories?ecosystem={}&affects={}&per_page=100&sort=published&direction=desc",
        ecosystem, package
    );
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2026-03-10")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let advisories: Vec<serde_json::Value> = serde_json::from_str(&text).ok()?;
    if advisories.is_empty() {
        return None;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    let mut entries: Vec<Entry> = advisories
        .into_iter()
        .filter(|a| {
            a["vulnerabilities"]
                .as_array()
                .map(|arr| {
                    arr.iter().any(|v| {
                        v["package"]["ecosystem"]
                            .as_str()
                            .is_some_and(|e| e.eq_ignore_ascii_case(ecosystem))
                            && v["package"]["name"].as_str() == Some(package)
                    })
                })
                .unwrap_or(false)
        })
        .map(|a| {
            let id = a["ghsa_id"].as_str().unwrap_or("").to_owned();
            let cve = a["cve_id"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_owned());
            let summary = a["summary"].as_str().unwrap_or("").to_owned();
            let date = a["published_at"].as_str().map(|s| {
                if s.len() >= 10 { s[..10].to_owned() } else { s.to_owned() }
            });
            Entry { id, cve, cvss: advisory_cvss(&a), summary, date }
        })
        .collect();

    if entries.is_empty() {
        return None;
    }

    entries.sort_by(|a, b| {
        let ka = a.cvss * recency(days_old(&a.date, now));
        let kb = b.cvss * recency(days_old(&b.date, now));
        kb.partial_cmp(&ka).unwrap_or(std::cmp::Ordering::Equal)
    });

    let count = entries.len();
    let energy: f64 = entries
        .iter()
        .map(|e| recency(days_old(&e.date, now)) * (e.cvss / 10.0).powi(3))
        .sum();
    let raw = 100.0 * (1.0 - (-0.5 * energy).exp());
    let score = (raw.round() as u8).min(100);
    let severity = match score {
        0..=25 => Severity::Low,
        26..=50 => Severity::Medium,
        51..=75 => Severity::High,
        _ => Severity::Critical,
    };

    let crit: Vec<&Entry> = entries.iter().filter(|e| e.cvss >= 9.0).collect();
    let high: Vec<&Entry> = entries.iter().filter(|e| e.cvss >= 7.0 && e.cvss < 9.0).collect();
    let mod_low = entries.len() - crit.len() - high.len();
    let trimmed = |s: &str| {
        if s.len() > 55 {
            format!("{}…", &s[..52])
        } else {
            s.to_owned()
        }
    };

    let mut evidence = format!(
        "{} ({}) - {} known advisories\n  Critical: {}  High: {}  Moderate/Low: {}",
        ecosystem, package, count, crit.len(), high.len(), mod_low,
    );

    if !crit.is_empty() {
        let showing = crit.len().min(5);
        evidence.push_str(&format!(
            "\n\n  Critical ({}):",
            if showing < crit.len() { format!("top {} of {}", showing, crit.len()) } else { crit.len().to_string() }
        ));
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
        evidence.push_str(&format!(
            "\n\n  High ({}):",
            if showing < high.len() { format!("top {} of {}", showing, high.len()) } else { high.len().to_string() }
        ));
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
        source: "GitHub Advisories",
        title: "Known vulnerabilities in package",
        detail: "GitHub Advisory Database reports known security advisories for this package",
        severity,
        score,
        evidence,
    })
}
