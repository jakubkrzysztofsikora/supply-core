use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};
use supply_core::{
    adapters::{
        config::load_policy, github::FsWorkflowReader, http::app, npm::HttpNpmRegistry,
        osv::NoopVulnerabilitySource, storage::MemoryMetadataStore,
    },
    application::{GitHubActionsScanner, PackageEvaluator},
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
    /// Snapshot every dependency of a package.json against the live
    /// registry: latest satisfying version, publish age, policy decision.
    SnapshotNpm {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
}
struct SystemClock;
impl supply_core::ports::Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
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
        Command::SnapshotNpm { root, policy } => {
            let p = load_policy(policy.as_deref())?;
            tokio::task::spawn_blocking(move || snapshot_npm(&root, &p))
                .await
                .map_err(|e| anyhow::anyhow!("snapshot task failed: {e}"))??;
        }
    }
    Ok(())
}

fn snapshot_npm(root: &std::path::Path, policy: &supply_core::domain::Policy) -> Result<()> {
    use supply_core::adapters::npm::package_version_from_metadata;
    use supply_core::domain::PackageVersion;
    use supply_core::ports::UpstreamNpmRegistry;

    let manifest = std::fs::read_to_string(root.join("package.json"))?;
    let deps: Vec<(String, String)> = serde_json::from_str::<serde_json::Value>(&manifest)?
        .get("dependencies")
        .and_then(|d| d.as_object())
        .map(|o| {
            o.iter()
                .filter(|(_, v)| v.is_string())
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default();

    let registry = HttpNpmRegistry::new()?;
    let store = MemoryMetadataStore::default();
    let now = chrono::Utc::now();
    let mut entries = vec![];
    let mut errors = vec![];

    for (name, range) in &deps {
        let req = semver::VersionReq::parse(range);
        let Ok(req) = req else {
            errors.push(
                serde_json::json!({"package": name, "error": format!("unparseable range {range}")}),
            );
            continue;
        };
        let meta = match registry.metadata(name) {
            Ok(m) => m,
            Err(e) => {
                errors.push(serde_json::json!({"package": name, "error": e.to_string()}));
                continue;
            }
        };
        let versions: Vec<semver::Version> = meta
            .get("versions")
            .and_then(|v| v.as_object())
            .map(|o| {
                o.keys()
                    .filter_map(|k| semver::Version::parse(k).ok())
                    .collect()
            })
            .unwrap_or_default();
        let Some(latest_satisfying) = versions.iter().filter(|v| req.matches(v)).max() else {
            errors.push(serde_json::json!({"package": name, "error": format!("no version satisfies {range}")}));
            continue;
        };
        let pv: PackageVersion = match package_version_from_metadata(&meta, name, latest_satisfying)
        {
            Ok(pv) => pv,
            Err(e) => {
                errors.push(serde_json::json!({"package": name, "error": e.to_string()}));
                continue;
            }
        };
        let age_days = pv
            .published_at
            .map(|t| now.signed_duration_since(t).num_days())
            .unwrap_or(-1);
        let decision = PackageEvaluator {
            policy,
            clock: &SystemClock,
            vulns: &NoopVulnerabilitySource,
            metadata: &store,
        }
        .evaluate(&pv, Some(&req));
        let decision = match decision {
            Ok(d) => d,
            Err(e) => {
                errors.push(serde_json::json!({"package": name, "error": e.to_string()}));
                continue;
            }
        };
        entries.push(serde_json::json!({
            "package": name,
            "range": range,
            "resolved": latest_satisfying.to_string(),
            "age_days": age_days,
            "status": format!("{:?}", decision.status),
            "reasons": decision.reasons,
            "warnings": decision.warnings,
        }));
    }
    let out = serde_json::json!({
        "captured_at": now.to_rfc3339(),
        "repository": root.display().to_string(),
        "policy": { "quarantine_days": policy.quarantine.minimum_age_days },
        "dependencies": entries,
        "errors": errors,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
