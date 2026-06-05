// Command definitions expose focused inspection and guarded installer execution workflows.
// Arguments preserve concise automation support alongside clear interactive safety controls.

use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub enum Command {
    Inspect {
        source: String,
        #[arg(long)]
        json: bool,
    },
    Run {
        command: String,
        #[arg(short = 'y', long, help = "Skip confirmation prompt")]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
    Set {
        key: String,
        value: String,
    },
}

#[derive(Parser)]
#[command(
    name = "safe",
    version,
    about = "Inspect remote installers before execution",
    long_about = "Analyzes installer scripts for risk before executing them.\n\nOptional environment variables:\n  VIRUSTOTAL_API_KEY    VirusTotal file hash reputation lookups\n  CLOUDFLARE_API_TOKEN  Cloudflare Radar domain ranking checks"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
