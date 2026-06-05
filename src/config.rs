// Persistent global storage for API keys and user preferences across sessions.
// Config is stored as JSON in the platform-appropriate config directory.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub virustotal_api_key: Option<String>,
    pub cloudflare_api_token: Option<String>,
}

impl AppConfig {
    pub fn load() -> Self {
        let path = config_path();
        if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Self::default()
        }
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "VIRUSTOTAL_API_KEY" => self.virustotal_api_key = Some(value.into()),
            "CLOUDFLARE_API_TOKEN" => self.cloudflare_api_token = Some(value.into()),
            _ => return Err(format!("unknown config key: {key}")),
        }
        Ok(())
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)
    }
}

fn config_path() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var("APPDATA").unwrap_or_else(|_| ".".into())
    } else {
        std::env::var("XDG_CONFIG_HOME")
            .or_else(|_| std::env::var("HOME").map(|h| format!("{h}/.config")))
            .unwrap_or_else(|_| ".".into())
    };
    PathBuf::from(base).join("safeinstall").join("config.json")
}
