// Reports present actionable installer findings for humans and automated consumers.
// Risk summaries keep evidence visible while enforcing consistent decision thresholds.

use std::io::{self, Write};

use anyhow::Result;

use crate::analyzer::{Assessment, Finding, Severity};

const GRN: &str = "\x1b[38;2;146;190;30m";
const RED: &str = "\x1b[38;2;249;76;114m";
const RST: &str = "\x1b[0m";

const HEADER: &str = concat!(
    "   .-'''-.    ____     ________     .-''-.  .-./`) ,---.   .--.   .-'''-. ,---------.    ____      .---.     .---.    \n",
    "  / _     \\ .'  __ `. |        |  .'_ _   \\ \\ .-.')|    \\  |  |  / _     \\\\          \\ .'  __ `.   | ,_|     | ,_|    \n",
    " (`' )/`--'/   '  \\  \\|   .----' / ( ` )   '/ `-' \\|  ,  \\ |  | (`' )/`--' `--.  ,---'/   '  \\  \\,-./  )   ,-./  )    \n",
    "(_ o _).   |___|  /  ||  _|____ . (_ o _)  | `-'`\"`|  |\\_\\|  |(_ o _).       |   \\   |___|  /  |\\  '_ '`) \\  '_ '`)   \n",
    " (_,_). '.    _.-`   ||_( )_   ||  (_,_)___| .---. |  _( )_\\  | (_,_). '.     :_ _:      _.-`   | > (_)  )  > (_)  )   \n",
    ".---.  \\  :.'   _    |(_ o._)__|'  \\   .---. |   | | (_ o _)  |.---.  \\  :    (_I_)   .'   _    |(  .  .-' (  .  .-'   \n",
    "\\    `-'  ||  _( )_  ||(_,_)     \\  `-'    / |   | |  (_,_)\\  |\\    `-'  |   (_(=)_)  |  _( )_  | `-'`-'|___`-'`-'|___ \n",
    " \\       / \\ (_ o _) /|   |       \\       /  |   | |  |    |  | \\       /     (_I_)   \\ (_ o _) /  |        \\|        \\\n",
    "  `-...-'   '.(_,_).' '---'        `'-..-'   '---' '--'    '--'  `-...-'      '---'    '.(_,_).'   `--------``--------`",
);

const HEADER_COMPACT: &str = concat!(
    "   .-'''-.    ____     ________     .-''-.   \n",
    "  / _     \\ .'  __ `. |        |  .'_ _   \\  \n",
    " (`' )/`--'/   '  \\  \\|   .----' / ( ` )   ' \n",
    "(_ o _).   |___|  /  ||  _|____ . (_ o _)  | \n",
    " (_,_). '.    _.-`   ||_( )_   ||  (_,_)___| \n",
    ".---.  \\  :.'   _    |(_ o._)__|'  \\   .---. \n",
    "\\    `-'  ||  _( )_  ||(_,_)     \\  `-'    / \n",
    " \\       / \\ (_ o _) /|   |       \\       /  \n",
    "  `-...-'   '.(_,_).' '---'        `'-..-'   ",
);

fn header() -> String {
    let raw = {
        let narrow = std::env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .is_some_and(|w| w < 95);
        if narrow { HEADER_COMPACT } else { HEADER }
    };
    let mut out = String::with_capacity(raw.len() * 3);
    out.push_str(GRN);
    for c in raw.chars() {
        if c == '(' || c == ')' {
            out.push_str(RED);
            out.push(c);
            out.push_str(GRN);
        } else {
            out.push(c);
        }
    }
    out.push_str(RST);
    out
}

pub fn print_header() {
    println!();
    println!("{}", header());
    println!();
    io::stdout().flush().ok();
}

pub fn print_finding(finding: &Finding, prev_source: &mut Option<&'static str>) {
    if *prev_source != Some(finding.source) {
        if prev_source.is_some() {
            println!();
        }
        println!("  {RED}{}{RST}", finding.source);
        *prev_source = Some(finding.source);
    }
    println!(
        "  [{}] {} (+{}): {}",
        severity_name(&finding.severity),
        finding.title,
        finding.score,
        finding.detail
    );
    println!("  Evidence: {}", finding.evidence);
    io::stdout().flush().ok();
}

pub fn source_breakdown(findings: &[Finding]) -> String {
    let mut groups: Vec<(&str, u16)> = Vec::new();
    for f in findings {
        if let Some((_, sum)) = groups.iter_mut().find(|(s, _)| *s == f.source) {
            *sum += f.score as u16;
        } else {
            groups.push((f.source, f.score as u16));
        }
    }
    let max_w = groups.iter().map(|(s, _)| s.len()).max().unwrap_or(0);
    groups
        .iter()
        .map(|(s, n)| {
            let e = f64::from(*n) / 30.0;
            let sc = (100.0 * (1.0 - (-0.5 * e).exp())).round() as u8;
            format!("{s:<max_w$}  {sc:>3}")
        })
        .collect::<Vec<_>>()
        .join("\n    ")
}

pub fn print_score(score: u8, risk: &Severity, sources: &str) {
    println!();
    println!("  {RED}Risk score: {score}/100 ({}){RST}", severity_name(risk));
    if !sources.is_empty() {
        println!("    {sources}");
    }
    io::stdout().flush().ok();
}

pub fn print_json(assessment: &Assessment) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(assessment)?);
    Ok(())
}

pub fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Low => "Low",
        Severity::Medium => "Moderate",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}
