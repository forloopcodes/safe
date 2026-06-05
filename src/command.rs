// Command parsing classifies user input into installer types for targeted analysis.
// Package manager patterns are matched before falling back to generic execution.

use regex::Regex;
use url::Url;

#[derive(Debug)]
pub enum InstallCommand {
    Url { #[allow(dead_code)] url: Url },
    CurlPipe { #[allow(dead_code)] url: Url, #[allow(dead_code)] raw: String },
    PmInstall { registry: &'static str, package: String, #[allow(dead_code)] global: bool, #[allow(dead_code)] raw: String },
    Generic { #[allow(dead_code)] raw: String },
}

pub fn parse(input: &str) -> InstallCommand {
    let trimmed = input.trim();

    if let Ok(url) = Url::parse(trimmed)
        && matches!(url.scheme(), "http" | "https")
    {
        return InstallCommand::Url { url };
    }

    if let Ok(re) = Regex::new(r"https?://[^\s'|;)]+")
        && let Some(m) = re.find(trimmed)
    {
        let has_pipe = trimmed[m.end()..].contains('|');
        let has_shell = trimmed[m.end()..].contains("bash")
            || trimmed[m.end()..].contains("sh")
            || trimmed[m.end()..].contains("iex");
        if has_pipe && has_shell
            && let Ok(url) = Url::parse(m.as_str())
        {
            return InstallCommand::CurlPipe {
                url,
                raw: trimmed.to_owned(),
            };
        }
    }

    if let Ok(re) = Regex::new(r"(?i)^(?:npm|pnpm|yarn)\s+(?:global\s+)?(?:add|install|i)\s+(-g\s+|--global\s+)?(.+)$")
        && let Some(caps) = re.captures(trimmed)
        && let Some(rest) = caps.get(2)
    {
        let global = caps.get(1).is_some_and(|m| !m.as_str().trim().is_empty())
            || trimmed.contains(" -g ");
        if let Some(pkg) = rest.as_str().split_whitespace().find(|s| !s.starts_with('-')) {
            return InstallCommand::PmInstall {
                registry: "npm",
                package: pkg.to_owned(),
                global,
                raw: trimmed.to_owned(),
            };
        }
    }

    if let Ok(re) = Regex::new(r"(?i)^pip3?\s+install\s+(-g\s+|--user\s+)?(.+)$")
        && let Some(caps) = re.captures(trimmed)
        && let Some(rest) = caps.get(2)
        && let Some(pkg) = rest.as_str().split_whitespace().find(|s| !s.starts_with('-'))
    {
        return InstallCommand::PmInstall {
            registry: "PyPI",
            package: pkg.to_owned(),
            global: false,
            raw: trimmed.to_owned(),
        };
    }

    if let Ok(re) = Regex::new(r"(?i)^cargo\s+install\s+(.+)$")
        && let Some(caps) = re.captures(trimmed)
        && let Some(rest) = caps.get(1)
        && let Some(pkg) = rest.as_str().split_whitespace().find(|s| !s.starts_with('-'))
    {
        return InstallCommand::PmInstall {
            registry: "crates.io",
            package: pkg.to_owned(),
            global: true,
            raw: trimmed.to_owned(),
        };
    }

    InstallCommand::Generic {
        raw: trimmed.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_npm_install() {
        let cmd = parse("npm install -g bun");
        assert!(matches!(&cmd, InstallCommand::PmInstall { registry, package, .. }
            if *registry == "npm" && package == "bun"));
    }

    #[test]
    fn parses_npm_i_short() {
        let cmd = parse("npm i -g bun");
        assert!(matches!(&cmd, InstallCommand::PmInstall { package, .. }
            if package == "bun"));
    }

    #[test]
    fn parses_pip_install() {
        let cmd = parse("pip install requests");
        assert!(matches!(&cmd, InstallCommand::PmInstall { registry, package, .. }
            if *registry == "PyPI" && package == "requests"));
    }

    #[test]
    fn parses_cargo_install() {
        let cmd = parse("cargo install ripgrep");
        assert!(matches!(&cmd, InstallCommand::PmInstall { registry, package, .. }
            if *registry == "crates.io" && package == "ripgrep"));
    }

    #[test]
    fn parses_curl_pipe() {
        let cmd = parse("curl -fsSL https://bun.sh/install | bash");
        assert!(matches!(&cmd, InstallCommand::CurlPipe { .. }));
    }

    #[test]
    fn parses_direct_url() {
        let cmd = parse("https://bun.sh/install");
        assert!(matches!(&cmd, InstallCommand::Url { .. }));
    }

    #[test]
    fn generic_fallback() {
        let cmd = parse("some-random-command --flag");
        assert!(matches!(&cmd, InstallCommand::Generic { .. }));
    }
}
