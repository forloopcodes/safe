// Cloudflare Radar domain ranking provides popularity and category signals for
// download host trust assessment. Optional provider requiring CLOUDFLARE_API_TOKEN.

use crate::analyzer::{Finding, Severity};

const SAFE_CATEGORIES: &[&str] = &[
    "software",
    "developer_tools",
    "technology",
    "business",
    "hosting",
    "cdn",
    "saas",
    "cloud_computing",
    "open_source",
];

pub async fn check(host: &str, token: &str) -> Option<Finding> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("safeinstall/0.1.0")
        .build()
        .ok()?;

    let url = format!(
        "https://api.cloudflare.com/client/v4/radar/ranking/domain/{}",
        host
    );
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let text = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    if json["success"].as_bool().unwrap_or(false) {
        return None;
    }

    let result = &json["result"];
    let rank = result["rank"].as_u64();

    let categories: Vec<&str> = result["categories"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|c| c.as_str()).collect())
        .unwrap_or_default();

    let in_safe_category = categories.iter().any(|c| SAFE_CATEGORIES.contains(c));

    match rank {
        Some(r) if r > 0 && r < 100_000 && !in_safe_category => {
            let evidence = format!("Radar rank {} (categories: {})", r, categories.join(", "));
            Some(Finding {
                source: "Cloudflare",
                title: "Low popularity download host",
                detail: "Cloudflare Radar ranks this domain well below typical installer hosts",
                severity: Severity::Low,
                score: 5,
                evidence,
            })
        }
        Some(r) if r > 0 && r < 1_000_000 => {
            let evidence = format!("Radar rank {} (categories: {})", r, categories.join(", "));
            Some(Finding {
                source: "Cloudflare",
                title: "Uncommon download host",
                detail: "Domain has moderate Cloudflare Radar ranking",
                severity: Severity::Low,
                score: 3,
                evidence,
            })
        }
        _ => None,
    }
}
