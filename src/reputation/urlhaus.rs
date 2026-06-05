// URLHaus domain malware blocklist lookup checks if the download host is known
// for distributing malware. Free public API with no authentication required.

use crate::analyzer::{Finding, Severity};

pub async fn check(host: &str) -> Option<Finding> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("safeinstall/0.1.0")
        .build()
        .ok()?;

    let url = format!("https://urlhaus-api.abuse.ch/v1/host/{host}");
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let text = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;

    let status = json["query_status"].as_str()?;
    if status != "ok" {
        return None;
    }

    let urls = json["urls"].as_array()?;
    if urls.is_empty() {
        return None;
    }

    let count = urls.len();
    let threats: Vec<&str> = urls.iter().filter_map(|u| u["threat"].as_str()).collect();
    let unique: Vec<&str> = {
        let mut v: Vec<&str> = threats.clone();
        v.sort();
        v.dedup();
        v
    };

    let has_payload_download = threats
        .iter()
        .any(|t| t.contains("payload") || t.contains("downloader") || t.contains("malware"));

    Some(Finding {
        source: "URLHaus",
        title: "Domain listed on URLHaus blocklist",
        detail: "This download host is known for distributing malware or threats",
        severity: if has_payload_download {
            Severity::Critical
        } else {
            Severity::High
        },
        score: if has_payload_download { 55 } else { 35 },
        evidence: format!(
            "{} threats reported ({}): {}",
            count,
            unique.join(", "),
            urls.iter()
                .take(3)
                .filter_map(|u| u["url"].as_str())
                .collect::<Vec<_>>()
                .join("; ")
        ),
    })
}

#[cfg(test)]
mod tests {}
