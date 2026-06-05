// Reputation providers augment static analysis with external threat intelligence.
// Each optional provider degrades gracefully when its data source is unavailable.

pub mod cloudflare;
pub mod domain;
pub mod github_advisory;
pub mod osv;
pub mod urlhaus;
pub mod virustotal;

pub struct ReputationConfig {
    pub virustotal_api_key: Option<String>,
    pub cloudflare_api_token: Option<String>,
}
