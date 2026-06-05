// VirusTotal hash lookup checks downloaded content against known malware databases.
// Requires VIRUSTOTAL_API_KEY environment variable and degrades gracefully when absent.

use crate::analyzer::{Finding, Severity};

pub async fn check(sha256: &str, api_key: &str) -> Option<Finding> {
    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("safeinstall/0.1.0")
        .build()
        .ok()?;
    let response = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await
        .ok()?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return None;
    }
    if !response.status().is_success() {
        return None;
    }

    let text = response.text().await.ok()?;
    let body: serde_json::Value = serde_json::from_str(&text).ok()?;
    let stats = &body["data"]["attributes"]["last_analysis_stats"];

    let malicious = stats["malicious"].as_u64().unwrap_or(0);
    let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
    let total = malicious
        + suspicious
        + stats["undetected"].as_u64().unwrap_or(0)
        + stats["harmless"].as_u64().unwrap_or(0)
        + stats["timeout"].as_u64().unwrap_or(0);

    if malicious > 0 {
        let score = ((malicious as f64 / total.max(1) as f64) * 100.0).min(100.0) as u8;
        Some(Finding {
            source: "VirusTotal",
            title: "Known malware signature",
            detail: "The downloaded content matches known malware in VirusTotal",
            severity: if score >= 50 {
                Severity::Critical
            } else {
                Severity::High
            },
            score: score.max(50),
            evidence: format!(
                "{malicious}/{total} security vendors flagged this file as malicious"
            ),
        })
    } else if suspicious > 0 {
        Some(Finding {
            source: "VirusTotal",
            title: "Suspicious file detection",
            detail: "Some engines found suspicious behavior in this downloaded file",
            severity: Severity::Medium,
            score: 15,
            evidence: format!("{suspicious}/{total} engines reported suspicious behavior"),
        })
    } else {
        None
    }
}
