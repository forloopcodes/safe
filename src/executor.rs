// Execution launches only previously analyzed artifacts through their detected interpreter.
// Approval policy blocks critical findings unless callers explicitly override protection.

use std::io::{self, Write};
use std::process::{self, Stdio};

use anyhow::{Context, Result, bail};
use tokio::process::Command;

use crate::analyzer::{Assessment, Severity};
use crate::source::{Artifact, InstallerKind};

const GRN: &str = "\x1b[38;2;146;190;30m";
const RED: &str = "\x1b[38;2;249;76;114m";
const RST: &str = "\x1b[0m";

pub async fn run(
    artifact: Artifact,
    assessment: &Assessment,
    yes: bool,
) -> Result<()> {
    println!();
    if !yes {
        let default_yes = !matches!(assessment.risk, Severity::High | Severity::Critical);
        print!("{GRN}Proceed with this analyzed installer? {} {RST}", if default_yes { "[Y/n]" } else { "[y/N]" });
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if if default_yes {
            matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no")
        } else {
            !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
        } {
            println!("{RED}Cancelled.{RST}");
            process::exit(0);
        }
    }
    if matches!(assessment.risk, Severity::High | Severity::Critical) {
        println!("{RED}Installing from {}{RST}", assessment.source);
    } else {
        println!("{GRN}Installing from {}{RST}", assessment.source);
    }
    let suffix = match artifact.kind {
        InstallerKind::Bash => ".sh",
        InstallerKind::PowerShell => ".ps1",
        InstallerKind::Python => ".py",
        InstallerKind::Executable if cfg!(windows) => ".exe",
        InstallerKind::Executable => ".bin",
        InstallerKind::Text => bail!("unknown text installer type cannot be executed safely"),
    };
    let file = tempfile::Builder::new().suffix(suffix).tempfile()?;
    std::fs::write(file.path(), artifact.bytes)?;
    #[cfg(unix)]
    if matches!(artifact.kind, InstallerKind::Executable) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let mut command = interpreter(&artifact.kind, file.path())?;
    let status = command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .context("failed to launch analyzed installer")?;
    if !status.success() {
        bail!("installer exited with status {status}");
    }
    Ok(())
}

pub async fn run_shell(
    raw: String,
    assessment: &Assessment,
    yes: bool,
) -> Result<()> {
    println!();
    if !yes {
        let default_yes = !matches!(assessment.risk, Severity::High | Severity::Critical);
        print!("{GRN}Execute this command? {} {RST}", if default_yes { "[Y/n]" } else { "[y/N]" });
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if if default_yes {
            matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no")
        } else {
            !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
        } {
            println!("{RED}Cancelled.{RST}");
            process::exit(0);
        }
    }
    if matches!(assessment.risk, Severity::High | Severity::Critical) {
        println!("{RED}Running {raw}{RST}");
    } else {
        println!("{GRN}Running {raw}{RST}");
    }
    let status = if cfg!(windows) {
        let mut cmd = Command::new("cmd");
        cmd.args(["/C", &raw]);
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("failed to launch command")?
    } else {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", &raw]);
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("failed to launch command")?
    };
    if !status.success() {
        bail!("command exited with status {status}");
    }
    Ok(())
}

fn interpreter(kind: &InstallerKind, path: &std::path::Path) -> Result<Command> {
    let path = path.as_os_str();
    Ok(match kind {
        InstallerKind::Bash => {
            let mut command = Command::new("bash");
            command.arg(path);
            command
        }
        InstallerKind::PowerShell => {
            let mut command = Command::new(if cfg!(windows) { "powershell" } else { "pwsh" });
            command.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]);
            command.arg(path);
            command
        }
        InstallerKind::Python => {
            let mut command = Command::new(if cfg!(windows) { "python" } else { "python3" });
            command.arg(path);
            command
        }
        InstallerKind::Executable => Command::new(path),
        InstallerKind::Text => bail!("unknown text installer type cannot be executed safely"),
    })
}
