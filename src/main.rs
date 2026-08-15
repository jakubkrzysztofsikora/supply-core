use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};
use supply_core::{
    adapters::{config::load_policy, github::FsWorkflowReader, http::app},
    application::GitHubActionsScanner,
};

#[derive(Parser)]
#[command(
    name = "supply",
    about = "Local-first supply-chain dependency firewall MVP"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "127.0.0.1:4873")]
        addr: SocketAddr,
    },
    ScanActions {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { addr } => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app()).await?;
        }
        Command::ScanActions { root, policy, json } => {
            let p = load_policy(policy.as_deref())?;
            let scanner = GitHubActionsScanner {
                policy: &p,
                reader: &FsWorkflowReader,
            };
            let report = scanner.scan(&root)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for f in &report.findings {
                    println!("BLOCK: {}", f.reasons.join("; "));
                }
                println!("scanned {} action references", report.references.len());
            }
            if report.is_blocking() {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}
