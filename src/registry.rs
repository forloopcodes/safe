// Registry metadata lookups fetch package info from npm, PyPI, crates.io and
// linked GitHub repositories to surface publisher trust and security signals.

    use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PackageInfo {
    pub registry: String,
    pub package: String,
    pub version: String,
    pub description: String,
    pub maintainers: usize,
    pub downloads: String,
    pub license: String,
    pub repo_owner: Option<String>,
    pub repo_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GitHubInfo {
    pub stars: u32,
    pub forks: u32,
    pub language: Option<String>,
    pub archived: bool,
    pub has_security_policy: bool,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct ScorecardInfo {
    pub overall: f64,
    pub checks: Vec<ScorecardCheck>,
}

#[derive(Debug, Serialize)]
pub struct ScorecardCheck {
    pub name: String,
    pub score: i8,
}

pub async fn lookup_npm(package: &str) -> Option<PackageInfo> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("safeinstall/0.1.0")
        .build()
        .ok()?;

    let url = format!("https://registry.npmjs.org/{package}");
    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;

    let name = json["name"].as_str().unwrap_or(package).to_owned();
    let version = json["dist-tags"]["latest"]
        .as_str()
        .unwrap_or("unknown")
        .to_owned();
    let description = json["description"].as_str().unwrap_or("").to_owned();
    let maintainers = json["maintainers"].as_array().map(|a| a.len()).unwrap_or(0);
    let license = json["license"]
        .as_str()
        .or_else(|| json["license"]["type"].as_str())
        .unwrap_or("unknown")
        .to_owned();

    let downloads = async {
        let url = format!("https://api.npmjs.org/downloads/point/last-week/{package}");
        let resp = reqwest::get(&url).await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let text = resp.text().await.ok()?;
        let json: serde_json::Value = serde_json::from_str(&text).ok()?;
        let n = json["downloads"].as_u64()?;
        Some(if n >= 1_000_000 {
            format!("{:.1}M/week", n as f64 / 1_000_000.0)
        } else if n >= 1_000 {
            format!("{:.1}K/week", n as f64 / 1_000.0)
        } else {
            format!("{n}/week")
        })
    }
    .await
    .unwrap_or_else(|| "unknown".to_owned());

    let repo_url = json["repository"]["url"].as_str().unwrap_or("");
    let (repo_owner, repo_name) = match url::Url::parse(repo_url.trim_start_matches("git+").trim_end_matches(".git")) {
        Ok(parsed) if parsed.host_str() == Some("github.com") => {
            let mut segs = parsed.path().trim_start_matches('/').splitn(3, '/');
            (segs.next().map(|o| o.to_owned()), segs.next().map(|r| r.trim_end_matches(".git").to_owned()))
        }
        _ => (None, None),
    };

    Some(PackageInfo {
        registry: "npm".to_owned(),
        package: name,
        version,
        description,
        maintainers,
        downloads,
        license,
        repo_owner,
        repo_name,
    })
}

pub async fn lookup_github(owner: &str, repo: &str) -> Option<GitHubInfo> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("safeinstall/0.1.0")
        .build()
        .ok()?;

    let url = format!("https://api.github.com/repos/{owner}/{repo}");
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;

    let stars = json["stargazers_count"].as_u64().unwrap_or(0) as u32;
    let forks = json["forks_count"].as_u64().unwrap_or(0) as u32;
    let language = json["language"].as_str().map(|s| s.to_owned());
    let archived = json["archived"].as_bool().unwrap_or(false);
    let updated_at = json["pushed_at"].as_str().unwrap_or("unknown").to_owned();
    let has_security_policy = {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .user_agent("safeinstall/0.1.0")
            .build()
            .ok()?;
        let url = format!(
            "https://api.github.com/repos/{owner}/{repo}/contents/SECURITY.md"
        );
        let resp = client.get(&url).send().await.ok()?;
        resp.status().is_success()
    };

    Some(GitHubInfo {
        stars,
        forks,
        language,
        archived,
        has_security_policy,
        updated_at,
    })
}

pub async fn lookup_scorecard(owner: &str, repo: &str) -> Option<ScorecardInfo> {
    let url = format!(
        "https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}"
    );
    let resp = reqwest::get(&url).await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let overall = json["score"].as_f64()?;
    let checks = json["checks"].as_array()?;

    let parsed: Vec<ScorecardCheck> = checks
        .iter()
        .filter_map(|c| {
            let name = c["name"].as_str()?.to_owned();
            let score = c["score"].as_i64().unwrap_or(0) as i8;
            Some(ScorecardCheck { name, score })
        })
        .collect();

    Some(ScorecardInfo {
        overall,
        checks: parsed,
    })
}

fn label_val(label: &str, val: impl std::fmt::Display) -> String {
    format!("  {label:<14} {val}\n")
}

fn num_with_commas(n: u32) -> String {
    let s = n.to_string();
    let mut r = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            r.push(',');
        }
        r.push(c);
    }
    r
}

pub fn format_summary(
    pkg: &PackageInfo,
    gh: Option<&GitHubInfo>,
    sc: Option<&ScorecardInfo>,
) -> String {
    let mut out = format!(
        "  Registry:      {}\n  Package:       {}  (v{})\n",
        pkg.registry, pkg.package, pkg.version,
    );
    if pkg.license != "unknown" {
        out.push_str(&label_val("License:", &pkg.license));
    }
    if !pkg.description.is_empty() {
        let desc = if pkg.description.len() > 72 {
            format!("{}…", &pkg.description[..69])
        } else {
            pkg.description.clone()
        };
        out.push_str(&label_val("Description:", desc));
    }
    out.push_str(&label_val("Maintainers:", pkg.maintainers));
    out.push_str(&label_val("Downloads:", &pkg.downloads));

    if let (Some(owner), Some(repo)) = (&pkg.repo_owner, &pkg.repo_name) {
        out.push_str(&format!("\n  Repository:    github.com/{owner}/{repo}\n"));
        if let Some(gh) = gh {
            out.push_str(&label_val("Stars:", num_with_commas(gh.stars)));
            if gh.forks > 0 {
                out.push_str(&label_val("Forks:", num_with_commas(gh.forks)));
            }
            if let Some(ref lang) = gh.language {
                out.push_str(&label_val("Language:", lang));
            }
            let updated = gh
                .updated_at
                .split('T')
                .next()
                .unwrap_or(&gh.updated_at);
            out.push_str(&label_val("Updated:", updated));
            out.push_str(&label_val("Security:",
                if gh.has_security_policy { "present" } else { "absent" }));
            out.push_str(&label_val("Archived:",
                if gh.archived { "yes" } else { "no" }));
        }
        if let Some(sc) = sc {
            let rating = if sc.overall >= 7.5 {
                "Good"
            } else if sc.overall >= 5.0 {
                "Moderate"
            } else {
                "Low"
            };
            out.push_str(&format!(
                "  Scorecard:     {:.1}/10 ({rating})\n",
                sc.overall
            ));
            for check in &sc.checks {
                let icon = if check.score < 0 { "-" } else if check.score >= 7 { "v" } else if check.score >= 4 { "!" } else { "x" };
                let label = if check.score < 0 { "N/A".into() } else { format!("{}/10", check.score) };
                out.push_str(&format!("    {icon} {} ({label})\n", check.name));
            }
        }
    }
    out
}
