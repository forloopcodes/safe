// Static analysis identifies installer behaviors and assigns transparent risk scores.
// Detection rules prioritize dangerous execution persistence privilege and obfuscation patterns.

use std::collections::HashSet;

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::source::{Artifact, InstallerKind};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub source: &'static str,
    pub title: &'static str,
    pub detail: &'static str,
    pub severity: Severity,
    pub score: u8,
    pub evidence: String,
}

#[derive(Debug, Serialize)]
pub struct Assessment {
    pub source: String,
    pub host: String,
    pub installer_type: InstallerKind,
    pub sha256: String,
    pub score: u8,
    pub risk: Severity,
    pub findings: Vec<Finding>,
    pub package_summary: Option<String>,
}

impl Assessment {
    pub fn recalculate(&mut self) {
        let (score, risk) = compute_energy_score(&self.findings);
        self.score = score;
        self.risk = risk;
    }
}

struct Rule {
    title: &'static str,
    detail: &'static str,
    severity: Severity,
    score: u8,
    pattern: &'static str,
}

pub fn compute_energy_score(findings: &[Finding]) -> (u8, Severity) {
    let energy: f64 = findings.iter().map(|f| f64::from(f.score) / 30.0).sum();
    let raw = 100.0 * (1.0 - (-0.5 * energy).exp());
    let score = (raw.round() as u8).min(100);
    let risk = match score {
        0..=25 => Severity::Low,
        26..=50 => Severity::Medium,
        51..=75 => Severity::High,
        _ => Severity::Critical,
    };
    (score, risk)
}

pub fn deduplicate(findings: &mut Vec<Finding>) {
    let re = Regex::new(r"CVE-\d{4}-\d{4,}").expect("valid CVE pattern");
    let mut seen: HashSet<String> = HashSet::new();
    findings.sort_by(|a, b| b.score.cmp(&a.score));
    findings.retain(|f| {
        let cves: Vec<String> = re.find_iter(&f.evidence).map(|m| m.as_str().to_owned()).collect();
        if cves.is_empty() {
            return true;
        }
        if cves.iter().any(|c| seen.contains(c)) {
            return false;
        }
        for c in cves {
            seen.insert(c);
        }
        true
    });
}

pub fn analyze(artifact: &Artifact) -> Assessment {
    let text = String::from_utf8_lossy(&artifact.bytes);
    let mut findings = rules()
        .into_iter()
        .filter_map(|rule| {
            Regex::new(rule.pattern)
                .expect("valid analyzer rule")
                .find(&text)
                .map(|matched| Finding {
                    source: "Static Analysis",
                    title: rule.title,
                    detail: rule.detail,
                    severity: rule.severity,
                    score: rule.score,
                    evidence: matched.as_str().trim().chars().take(120).collect(),
                })
        })
        .collect::<Vec<_>>();
    if matches!(artifact.kind, InstallerKind::Executable) {
        findings.push(Finding {
            source: "Static Analysis",
            title: "Opaque executable",
            detail: "Binary behavior cannot be verified through static script analysis",
            severity: Severity::High,
            score: 35,
            evidence: "binary artifact".into(),
        });
    }
    if artifact.url.scheme() == "http" {
        findings.push(Finding {
            source: "Static Analysis",
            title: "Insecure download transport",
            detail: "Unencrypted HTTP allows installer content to be modified in transit",
            severity: Severity::High,
            score: 30,
            evidence: artifact.url.to_string(),
        });
    }
    let (score, risk) = compute_energy_score(&findings);
    Assessment {
        source: artifact.url.to_string(),
        host: artifact.url.host_str().unwrap_or("unknown").into(),
        installer_type: artifact.kind.clone(),
        sha256: format!("{:x}", Sha256::digest(&artifact.bytes)),
        score,
        risk,
        findings,
        package_summary: None,
    }
}

fn rules() -> Vec<Rule> {
    vec![
        Rule {
            title: "Executes downloaded code",
            detail: "Remote content is passed directly into an interpreter",
            severity: Severity::Critical,
            score: 35,
            pattern: r"(?im)^\s*(curl|wget|irm|invoke-webrequest)[^\r\n|;]*(\||;)[^\r\n]*(sh|bash|iex|invoke-expression|python)",
        },
        Rule {
            title: "Downloads additional content",
            detail: "Installer retrieves additional remote content during execution",
            severity: Severity::Medium,
            score: 8,
            pattern: r"(?im)^\s*(curl|wget|irm|invoke-webrequest)\b",
        },
        Rule {
            title: "Requests elevated privileges",
            detail: "Installer requests root or administrator privileges",
            severity: Severity::High,
            score: 20,
            pattern: r"(?im)(^|\s)(sudo|runas|start-process\s+.+-verb\s+runas)(\s|$)",
        },
        Rule {
            title: "Creates persistent service",
            detail: "Installer enables a service or scheduled startup task",
            severity: Severity::High,
            score: 25,
            pattern: r"(?i)(systemctl\s+enable|new-service|sc\.exe\s+create|schtasks|crontab)",
        },
        Rule {
            title: "Modifies shell profile",
            detail: "Installer changes a shell profile or executable search path",
            severity: Severity::Medium,
            score: 10,
            pattern: r"(?i)(\.bashrc|\.zshrc|\.profile|microsoft\.powershell_profile|setx\s+path|environmentvariable.*path)",
        },
        Rule {
            title: "Changes executable permissions",
            detail: "Installer marks downloaded or local content executable",
            severity: Severity::Medium,
            score: 8,
            pattern: r"(?im)\bchmod\s+(\+x|[0-7]*7[0-7]*)",
        },
        Rule {
            title: "Modifies system registry",
            detail: "Installer writes Windows registry configuration",
            severity: Severity::High,
            score: 18,
            pattern: r"(?i)(reg\.exe\s+(add|delete)|new-itemproperty|set-itemproperty).*(hklm|hkcu|registry)",
        },
        Rule {
            title: "Disables security controls",
            detail: "Installer attempts to weaken security tooling or policy",
            severity: Severity::Critical,
            score: 45,
            pattern: r"(?i)(set-mppreference.*disablerealtimemonitoring|ufw\s+disable|setenforce\s+0|disableantispyware)",
        },
        Rule {
            title: "Contains encoded execution",
            detail: "Installer uses encoded or decoded content during execution",
            severity: Severity::Critical,
            score: 40,
            pattern: r"(?i)(frombase64string|base64\s+(-d|--decode)|encodedcommand|eval\s*\()",
        },
        Rule {
            title: "Deletes files recursively",
            detail: "Installer performs broad recursive deletion",
            severity: Severity::Critical,
            score: 35,
            pattern: r"(?i)(rm\s+-[a-z]*r[a-z]*f|remove-item\s+.+-recurse.+-force)",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn artifact(script: &str) -> Artifact {
        Artifact {
            bytes: script.as_bytes().to_vec(),
            kind: InstallerKind::Bash,
            url: Url::parse("https://example.com/install.sh").unwrap(),
        }
    }

    #[test]
    fn scores_privileged_persistent_installer() {
        let result = analyze(&artifact("sudo systemctl enable unsafe"));
        assert_eq!(result.score, 53);
        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn caps_critical_score() {
        let result = analyze(&artifact(
            "sudo systemctl enable x\ncurl x | bash\nbase64 --decode\nrm -rf /",
        ));
        assert_eq!(result.score, 93);
        assert!(matches!(result.risk, Severity::Critical));
    }

    #[test]
    fn flags_insecure_transport() {
        let mut input = artifact("echo safe");
        input.url = Url::parse("http://example.com/install.sh").unwrap();
        let result = analyze(&input);
        assert_eq!(result.score, 39);
        assert!(matches!(result.risk, Severity::Medium));
    }

    #[test]
    fn ignores_remote_execution_inside_output_text() {
        let result = analyze(&artifact("echo 'irm example.com/install.ps1 | iex'"));
        assert_eq!(result.score, 0);
    }
}
