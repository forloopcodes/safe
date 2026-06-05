// Installer acquisition downloads artifacts once and preserves exact analyzed bytes.
// Source parsing recognizes common remote installer commands without executing anything.

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Serialize;
use url::Url;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallerKind {
    Bash,
    PowerShell,
    Python,
    Executable,
    Text,
}

#[derive(Debug)]
pub struct Artifact {
    pub bytes: Vec<u8>,
    pub kind: InstallerKind,
    pub url: Url,
}

pub async fn acquire(input: &str) -> Result<Artifact> {
    let url = extract_url(input)?;
    let mut response = reqwest::get(url.clone())
        .await
        .with_context(|| format!("failed to download {url}"))?;
    if !response.status().is_success() {
        bail!("download failed with HTTP {}", response.status());
    }
    if response
        .content_length()
        .is_some_and(|size| size > 20_000_000)
    {
        bail!("installer exceeds the 20 MB analysis limit");
    }
    let url = response.url().clone();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > 20_000_000 {
            bail!("installer exceeds the 20 MB analysis limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        bail!("downloaded installer is empty");
    }
    Ok(Artifact {
        kind: detect_kind(&url, &content_type, &bytes),
        bytes,
        url,
    })
}

fn extract_url(input: &str) -> Result<Url> {
    if let Ok(url) = Url::parse(input) {
        return validate_url(url);
    }
    Regex::new(r#"https?://[^\s"'|;)]+"#)?
        .find(input)
        .context("no HTTP or HTTPS installer URL found")
        .and_then(|value| validate_url(Url::parse(value.as_str())?))
}

fn validate_url(url: Url) -> Result<Url> {
    if matches!(url.scheme(), "http" | "https") {
        Ok(url)
    } else {
        bail!("only HTTP and HTTPS installer sources are supported")
    }
}

fn detect_kind(url: &Url, content_type: &str, bytes: &[u8]) -> InstallerKind {
    let path = url.path().to_ascii_lowercase();
    let start = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]).to_ascii_lowercase();
    let first_line = start.lines().next().unwrap_or_default();
    if path.ends_with(".ps1") {
        InstallerKind::PowerShell
    } else if path.ends_with(".py") {
        InstallerKind::Python
    } else if path.ends_with(".sh")
        || first_line.starts_with("#!")
            && (first_line.contains("bash") || first_line.contains("/sh"))
    {
        InstallerKind::Bash
    } else if first_line.starts_with("#!")
        && (first_line.contains("powershell") || first_line.contains("pwsh"))
    {
        InstallerKind::PowerShell
    } else if first_line.starts_with("#!") && first_line.contains("python") {
        InstallerKind::Python
    } else if content_type.contains("octet-stream")
        || bytes.iter().take(1024).any(|byte| *byte == 0)
    {
        InstallerKind::Executable
    } else {
        InstallerKind::Text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_url_from_piped_command() {
        assert_eq!(
            extract_url("curl -fsSL https://example.com/install.sh | bash")
                .unwrap()
                .as_str(),
            "https://example.com/install.sh"
        );
    }

    #[test]
    fn detects_powershell_extension() {
        assert!(matches!(
            detect_kind(
                &Url::parse("https://example.com/install.ps1").unwrap(),
                "text/plain",
                b"Write-Host test"
            ),
            InstallerKind::PowerShell
        ));
    }

    #[test]
    fn prioritizes_bash_shebang_over_powershell_mentions() {
        assert!(matches!(
            detect_kind(
                &Url::parse("https://example.com/install").unwrap(),
                "text/plain",
                b"#!/usr/bin/env bash\nprintf 'Use PowerShell on Windows'"
            ),
            InstallerKind::Bash
        ));
    }
}
