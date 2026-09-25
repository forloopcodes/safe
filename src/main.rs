// SafeInstall command line entrypoint coordinates inspection approval and execution workflows.
// Runtime setup delegates security decisions to focused reusable application modules.

mod analyzer;
mod cli;
mod command;
mod config;
mod executor;
mod features;
mod ml;
mod ml_model;
mod registry;
mod report;
mod reputation;
mod source;

use std::io::{self, Write};
use std::process;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};

const RED: &str = "\x1b[38;2;249;76;114m";
const RST: &str = "\x1b[0m";

#[tokio::main]
async fn main() -> Result<()> {
    tokio::spawn(async {
        let _ = tokio::signal::ctrl_c().await;
        println!();
        println!("{RED}Exiting.{RST}");
        process::exit(0);
    });

    let cli = Cli::parse();

    let config = {
        let c = config::AppConfig::load();
        reputation::ReputationConfig {
            virustotal_api_key: c.virustotal_api_key,
            cloudflare_api_token: c.cloudflare_api_token,
        }
    };

    match cli.command {
        Command::Set { key, value } => {
            let mut cfg = config::AppConfig::load();
            match cfg.set(&key, &value) {
                Ok(()) => {
                    cfg.save().ok();
                    println!("  set {key}");
                }
                Err(msg) => eprintln!("{msg}"),
            }
        }
        Command::Features { paths, json } => print_features(&paths, json)?,
        Command::Inspect { source, json, no_ml } => {
            let cmd = command::parse(&source);
            if !json {
                report::print_header();
            }
            match cmd {
                command::InstallCommand::PmInstall {
                    registry, package, raw, ..
                } => {
                    let assessment = stream_pm(registry, &package, &raw, json).await?;
                    if json {
                        report::print_json(&assessment)?;
                    }
                }
                _ => {
                    let (_, assessment) = stream_url(&source, &config, json, !no_ml).await?;
                    if json {
                        report::print_json(&assessment)?;
                    }
                }
            }
        }
        Command::Run {
            command,
            yes,
            json,
            no_ml,
        } => {
            let cmd = command::parse(&command);
            if !json {
                report::print_header();
            }
            match cmd {
                command::InstallCommand::PmInstall {
                    registry,
                    package,
                    raw,
                    ..
                } => {
                    let assessment = stream_pm(registry, &package, &raw, json).await?;
                    if json {
                        report::print_json(&assessment)?;
                    }
                    executor::run_shell(raw, &assessment, yes).await?;
                }
                _ => {
                    let (artifact, assessment) = stream_url(&command, &config, json, !no_ml).await?;
                    if json {
                        report::print_json(&assessment)?;
                    }
                    executor::run(artifact, &assessment, yes).await?;
                }
            }
        }
    }
    Ok(())
}

async fn stream_url(
    source: &str,
    config: &reputation::ReputationConfig,
    json: bool,
    use_ml: bool,
) -> Result<(source::Artifact, analyzer::Assessment)> {
    if !json {
        print!("  Downloading... ");
        io::stdout().flush()?;
    }
    let artifact = source::acquire(source).await?;
    if !json {
        println!("{} bytes", artifact.bytes.len());
    }

    let mut assessment = analyzer::analyze(&artifact);
    if !json {
        println!("Source: {}", &assessment.source);
        println!("Host: {}", &assessment.host);
        println!("Downloaded: {} bytes", artifact.bytes.len());
        println!("Type: {:?}", &assessment.installer_type);
        println!("SHA-256: {}", &assessment.sha256);
        io::stdout().flush().ok();
        println!();
        if assessment.findings.is_empty() {
            println!("  No risky static behaviors detected.");
        } else {
            let mut prev_source = None;
            for finding in &assessment.findings {
                report::print_finding(finding, &mut prev_source);
            }
        }
    }

    let mut prev_source: Option<&'static str> = None;

    if use_ml && let Some(prediction) = ml::predict(&artifact) {
        assessment.ml_probability = Some(prediction.probability);
        match ml::finding(&prediction) {
            Some(finding) => {
                if !json {
                    report::print_finding(&finding, &mut prev_source);
                }
                assessment.findings.push(finding);
            }
            None if !json => {
                println!();
                println!("  ML Model: {:.0}% malicious probability, below threshold", prediction.probability * 100.0);
            }
            None => {}
        }
    }

    // Local files have no host, so network reputation sources do not apply.
    if artifact.url.scheme() == "file" {
        return Ok(finish(artifact, assessment, json));
    }

    let host = artifact.url.host_str().unwrap_or("unknown");

    if let Some(finding) = reputation::domain::check(host) {
        if !json {
            report::print_finding(&finding, &mut prev_source);
        }
        assessment.findings.push(finding);
    }
    if let Some(finding) = reputation::urlhaus::check(host).await {
        if !json {
            report::print_finding(&finding, &mut prev_source);
        }
        assessment.findings.push(finding);
    }
    for finding in reputation::osv::check(&artifact.url).await {
        if !json {
            report::print_finding(&finding, &mut prev_source);
        }
        assessment.findings.push(finding);
    }
    if let Some(ref key) = config.virustotal_api_key
        && let Some(finding) = reputation::virustotal::check(&assessment.sha256, key).await
    {
        if !json {
            report::print_finding(&finding, &mut prev_source);
        }
        assessment.findings.push(finding);
    }
    if let Some(ref token) = config.cloudflare_api_token
        && let Some(finding) = reputation::cloudflare::check(host, token).await
    {
        if !json {
            report::print_finding(&finding, &mut prev_source);
        }
        assessment.findings.push(finding);
    }

    Ok(finish(artifact, assessment, json))
}

fn finish(
    artifact: source::Artifact,
    mut assessment: analyzer::Assessment,
    json: bool,
) -> (source::Artifact, analyzer::Assessment) {
    assessment.recalculate();
    if !json {
        let sources = report::source_breakdown(&assessment.findings);
        report::print_score(assessment.score, &assessment.risk, &sources);
    }
    (artifact, assessment)
}

fn print_features(paths: &[std::path::PathBuf], json: bool) -> Result<()> {
    let names = features::names();
    for path in paths {
        let artifact = source::read_local(path)?;
        let values = features::extract(&artifact);
        let probability = ml::probability(&values);
        if json {
            let map: serde_json::Map<String, serde_json::Value> = names
                .iter()
                .zip(&values)
                .map(|(n, v)| ((*n).to_owned(), serde_json::json!(v)))
                .collect();
            let record = serde_json::json!({
                "path": path.display().to_string(),
                "installer_type": artifact.kind,
                "ml_probability": probability,
                "features": map,
            });
            if paths.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else {
                println!("{record}");
            }
        } else {
            println!("{} ({:?})", path.display(), artifact.kind);
            for (n, v) in names.iter().zip(&values) {
                println!("  {n:<24} {v:.4}");
            }
            println!("  {:<24} {probability:.4}", "ml_probability");
        }
    }
    Ok(())
}

async fn stream_pm(registry: &str, package: &str, raw: &str, json: bool) -> Result<analyzer::Assessment> {
    if !json {
        println!("{RED}$ {raw}{RST}");
        println!();
        io::stdout().flush().ok();
    }
    let mut findings = Vec::new();
    let mut summary = None;

    let pkg_info = match registry {
        "npm" => registry::lookup_npm(package).await,
        _ => None,
    };

    let gh_info = match &pkg_info {
        Some(p) => match (&p.repo_owner, &p.repo_name) {
            (Some(o), Some(r)) => registry::lookup_github(o, r).await,
            _ => None,
        },
        None => None,
    };

    let sc_info = match &pkg_info {
        Some(p) if gh_info.is_some() => match (&p.repo_owner, &p.repo_name) {
            (Some(o), Some(r)) => registry::lookup_scorecard(o, r).await,
            _ => None,
        },
        _ => None,
    };

    if let Some(ref p) = pkg_info {
        let s = registry::format_summary(p, gh_info.as_ref(), sc_info.as_ref());
        if !json {
            print!("{s}");
            io::stdout().flush().ok();
            println!();
        }
        summary = Some(s);
    }

    let mut prev_source: Option<&'static str> = None;

    if let Some(gh) = &gh_info {
        if gh.archived {
            let finding = analyzer::Finding {
                source: "GitHub",
                title: "Archived repository",
                detail: "The linked GitHub repository has been archived and is no longer maintained",
                severity: analyzer::Severity::Medium,
                score: 10,
                evidence: format!(
                    "github.com/{}/{}",
                    pkg_info
                        .as_ref()
                        .and_then(|p| p.repo_owner.as_ref())
                        .unwrap_or(&"?".into()),
                    pkg_info
                        .as_ref()
                        .and_then(|p| p.repo_name.as_ref())
                        .unwrap_or(&"?".into())
                ),
            };
            if !json {
                report::print_finding(&finding, &mut prev_source);
            }
            findings.push(finding);
        }
        if !gh.has_security_policy {
            let finding = analyzer::Finding {
                source: "GitHub",
                title: "No security policy",
                detail: "Repository lacks a SECURITY.md for coordinated disclosure and patch timelines",
                severity: analyzer::Severity::Low,
                score: 4,
                evidence: "SECURITY.md not found".into(),
            };
            if !json {
                report::print_finding(&finding, &mut prev_source);
            }
            findings.push(finding);
        }
    }

    let (osv_npm, gh_adv) = tokio::join!(
        reputation::osv::check_package("npm", package),
        reputation::github_advisory::check("npm", package),
    );

    for finding in osv_npm {
        if !json {
            report::print_finding(&finding, &mut prev_source);
        }
        findings.push(finding);
    }
    if let Some(finding) = gh_adv {
        if !json {
            report::print_finding(&finding, &mut prev_source);
        }
        findings.push(finding);
    }

    if let Some((o, r)) = pkg_info
        .as_ref()
        .and_then(|p| Some((p.repo_owner.as_ref()?, p.repo_name.as_ref()?)))
    {
        for finding in reputation::osv::check_package("GitHub", &format!("{o}/{r}")).await {
            if !json {
                report::print_finding(&finding, &mut prev_source);
            }
            findings.push(finding);
        }
    }

    if let Some(sc) = &sc_info
        && sc.overall < 7.5
    {
        let finding = analyzer::Finding {
            source: "Scorecard",
            title: "Moderate OpenSSF Scorecard",
            detail: "Security practices score below recommended thresholds for trusted software",
            severity: analyzer::Severity::Low,
            score: 5,
            evidence: format!("{:.1}/10 from {} checks", sc.overall, sc.checks.len()),
        };
        if !json {
            report::print_finding(&finding, &mut prev_source);
        }
        findings.push(finding);
    }

    let sources = report::source_breakdown(&findings);
    analyzer::deduplicate(&mut findings);
    let host = format!("registry.{}s.org", registry);
    let (score, risk) = analyzer::compute_energy_score(&findings);

    let assessment = analyzer::Assessment {
        source: format!("{} install {}", registry, package),
        host,
        installer_type: source::InstallerKind::Text,
        sha256: "package manager analysis (no download)".into(),
        score,
        risk,
        findings,
        package_summary: summary,
        ml_probability: None,
    };
    if !json {
        report::print_score(assessment.score, &assessment.risk, &sources);
    }
    Ok(assessment)
}
