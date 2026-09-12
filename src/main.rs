use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::Path, path::PathBuf};
use supply_core::{
    adapters::{
        azure_devops::{pipeline_annotations, FsAzurePipelineReader},
        config::load_policy,
        github::{workflow_annotations, FsWorkflowReader},
        http::app_with_config,
        npm::HttpNpmRegistry,
        nuget::{package_version_from_nuget, parse_packages_lock, HttpNuGetRegistry},
        osv::{NoopVulnerabilitySource, OsvVulnerabilitySource, ReqwestOsvTransport},
        pypi::{package_version_from_pypi, parse_requirements, HttpPyPiRegistry},
        storage::MemoryMetadataStore,
    },
    application::{AzurePipelinesScanner, DockerScanner, GitHubActionsScanner, PackageEvaluator},
    ports::{ContentScanner, MetadataStore, UpstreamNuGetRegistry, UpstreamPyPiRegistry},
};

#[derive(Parser)]
#[command(
    name = "supply",
    version,
    about = "Local-first supply-chain dependency firewall MVP"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long, default_value = "0.0.0.0:4873")]
        addr: SocketAddr,
        #[arg(
            long,
            env = "SUPPLY_SERVICE_NAME",
            default_value = "supply-core-official"
        )]
        service_name: String,
        #[arg(long, env = "SUPPLY_ARTIFACTS_DIR")]
        artifacts_dir: Option<PathBuf>,
        #[arg(long, env = "SUPPLY_STATUS_FILE")]
        status_file: Option<PathBuf>,
        #[arg(long, env = "SUPPLY_AUTH_TOKEN")]
        auth_token: Option<String>,
    },
    ScanActions {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Emit GitHub Actions workflow error annotations for blocking findings.
        #[arg(long, conflicts_with = "json")]
        annotations: bool,
    },
    #[command(alias = "scan-azure-pipelines")]
    ScanPipelines {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Emit Azure DevOps pipeline error logging commands (##vso[task.logissue...]) for blocking findings.
        #[arg(long, conflicts_with = "json")]
        annotations: bool,
    },
    /// Snapshot every dependency of a package.json against the live
    /// registry: latest satisfying version, publish age, policy decision.
    SnapshotNpm {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Query the real OSV.dev API for known vulnerabilities.
        /// Off by default to keep tests deterministic; the daily cron
        /// sets this to populate the field report.
        #[arg(long)]
        osv: bool,
        /// Directory to cache OSV responses in. Defaults to
        /// `$HOME/.local/share/supply-core/osv-cache`.
        #[arg(long)]
        osv_cache: Option<PathBuf>,
        /// JSONL file of content findings to enforce while evaluating.
        #[arg(long)]
        findings: Option<PathBuf>,
    },
    /// Snapshot exact pins from requirements.txt against PyPI: publish
    /// age, sha256, policy decision.
    SnapshotPip {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Query the real OSV.dev API for known vulnerabilities.
        #[arg(long)]
        osv: bool,
        /// Directory to cache OSV responses in. Defaults to
        /// `$HOME/.local/share/supply-core/osv-cache`.
        #[arg(long)]
        osv_cache: Option<PathBuf>,
        /// JSONL file of content findings to enforce while evaluating.
        #[arg(long)]
        findings: Option<PathBuf>,
    },
    /// Snapshot resolved packages from packages.lock.json against
    /// nuget.org: publish age, package hash, policy decision.
    #[command(name = "snapshot-nuget")]
    SnapshotNuGet {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Query the real OSV.dev API for known vulnerabilities.
        #[arg(long)]
        osv: bool,
        /// Directory to cache OSV responses in. Defaults to
        /// `$HOME/.local/share/supply-core/osv-cache`.
        #[arg(long)]
        osv_cache: Option<PathBuf>,
        /// JSONL file of content findings to enforce while evaluating.
        #[arg(long)]
        findings: Option<PathBuf>,
    },
    /// Record content findings for a package archive so later evaluations
    /// can block it.
    ScanPackage {
        /// Ecosystem: npm or pypi.
        ecosystem: String,
        archive: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: String,
        /// Optional external scanner command that prints a normalized
        /// `{"score","rules","summary"}` JSON report.
        #[arg(long)]
        external: Option<PathBuf>,
        /// Also run GuardDog (`$GUARDDOG_BIN` or `guarddog` on PATH).
        #[arg(long)]
        guarddog: bool,
        /// The registry reports a verified build attestation for this
        /// version; lower the static score accordingly.
        #[arg(long)]
        provenance: bool,
        /// Append the finding as JSONL to this file for later evaluation.
        #[arg(long)]
        findings_out: Option<PathBuf>,
    },
    /// Emit OSV records for stored content findings (dry run by default).
    Report {
        /// JSON file containing an array of content findings.
        findings: PathBuf,
        /// Print the manual submission checklist for public disclosure.
        #[arg(long)]
        submit: bool,
    },
    /// Scan Dockerfiles and compose files for container images that are
    /// not pinned to a sha256 digest.
    ScanDocker {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        json: bool,
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
        Command::Serve {
            addr,
            service_name,
            artifacts_dir,
            status_file,
            auth_token,
        } => {
            let config = supply_core::adapters::http::ServerConfig {
                service_name,
                artifacts_dir,
                status_file,
                auth_token,
                tailnet_domain: supply_core::adapters::http::configured_domain(),
            };
            eprintln!(
                "Starting supply-core server '{}' listening on {}",
                config.service_name, addr
            );
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app_with_config(config)).await?;
        }
        Command::ScanActions {
            root,
            policy,
            json,
            annotations,
        } => {
            let p = load_policy(policy.as_deref())?;
            let scanner = GitHubActionsScanner {
                policy: &p,
                reader: &FsWorkflowReader,
            };
            let report = scanner.scan(&root)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if annotations {
                for annotation in workflow_annotations(&report) {
                    println!("{annotation}");
                }
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
        Command::ScanPipelines {
            root,
            policy,
            json,
            annotations,
        } => {
            let p = load_policy(policy.as_deref())?;
            let scanner = AzurePipelinesScanner {
                policy: &p,
                reader: &FsAzurePipelineReader,
            };
            let report = scanner.scan(&root)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if annotations {
                for annotation in pipeline_annotations(&report) {
                    println!("{annotation}");
                }
            } else {
                for f in &report.findings {
                    println!("BLOCK: {}", f.reasons.join("; "));
                }
                println!("scanned {} pipeline references", report.references.len());
            }
            if report.is_blocking() {
                std::process::exit(2);
            }
        }
        Command::SnapshotNpm {
            root,
            policy,
            osv,
            osv_cache,
            findings,
        } => {
            let p = load_policy(policy.as_deref())?;
            tokio::task::spawn_blocking(move || {
                snapshot_npm(&root, &p, osv, osv_cache.as_deref(), findings.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("snapshot task failed: {e}"))??;
        }
        Command::SnapshotPip {
            root,
            policy,
            osv,
            osv_cache,
            findings,
        } => {
            let p = load_policy(policy.as_deref())?;
            tokio::task::spawn_blocking(move || {
                snapshot_pip(&root, &p, osv, osv_cache.as_deref(), findings.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("snapshot task failed: {e}"))??;
        }
        Command::SnapshotNuGet {
            root,
            policy,
            osv,
            osv_cache,
            findings,
        } => {
            let p = load_policy(policy.as_deref())?;
            tokio::task::spawn_blocking(move || {
                snapshot_nuget(&root, &p, osv, osv_cache.as_deref(), findings.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("snapshot task failed: {e}"))??;
        }
        Command::ScanDocker { root, policy, json } => {
            let p = load_policy(policy.as_deref())?;
            let report = DockerScanner { policy: &p }.scan(&root)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for finding in &report.findings {
                    println!("BLOCK: {}", finding.reasons.join("; "));
                }
                println!("scanned {} image references", report.references.len());
            }
            if report.is_blocking() {
                std::process::exit(2);
            }
        }
        Command::ScanPackage {
            ecosystem,
            archive,
            name,
            version,
            external,
            guarddog,
            provenance,
            findings_out,
        } => {
            let ecosystem = match ecosystem.as_str() {
                "npm" => supply_core::domain::Ecosystem::Npm,
                "pypi" | "pip" => supply_core::domain::Ecosystem::PyPi,
                other => anyhow::bail!("unsupported ecosystem: {other}"),
            };
            let parsed = semver::Version::parse(&version)?;
            let bytes = std::fs::read(&archive)?;
            let store = MemoryMetadataStore::default();
            let static_finding =
                supply_core::application::scanner::scan_archive_bytes_with_provenance(
                    &store, &ecosystem, &name, &parsed, &bytes, provenance,
                )?;
            let mut all_findings: Vec<supply_core::domain::ContentFinding> = Vec::new();
            if let Some(finding) = static_finding {
                all_findings.push(finding);
            }
            let mut external_scanners = Vec::new();
            if let Some(command) = external {
                external_scanners.push(
                    supply_core::adapters::command_scanner::CommandScanner::new(
                        command,
                        "external-scan",
                    ),
                );
            }
            if guarddog {
                let command =
                    std::env::var("GUARDDOG_BIN").unwrap_or_else(|_| "guarddog".to_string());
                external_scanners.push(
                    supply_core::adapters::command_scanner::CommandScanner::guarddog(command),
                );
            }
            for scanner in external_scanners {
                if let Some(external_finding) =
                    scanner.scan_archive(&ecosystem, &archive, &name, &parsed)?
                {
                    store.save_content_finding(&external_finding)?;
                    all_findings.push(external_finding);
                }
            }
            if all_findings.is_empty() {
                println!("no content finding for {name}@{version}");
            } else {
                println!("{}", serde_json::to_string_pretty(&all_findings)?);
                if let Some(path) = findings_out {
                    let file = supply_core::adapters::storage::FindingFile::new(path);
                    for finding in &all_findings {
                        file.append(finding)?;
                    }
                }
            }
        }
        Command::Report { findings, submit } => {
            let content = std::fs::read_to_string(&findings)?;
            let stored = supply_core::adapters::storage::parse_findings(&content)?;
            let records: Vec<serde_json::Value> =
                stored.iter().map(|finding| finding.to_osv()).collect();
            println!("{}", serde_json::to_string_pretty(&records)?);
            if submit {
                eprintln!("Public disclosure remains a manual, reviewed step:");
                eprintln!("  1. malicious npm package: use 'Report malware' on the package page");
                eprintln!(
                    "  2. malicious PyPI project: use 'Report project as malware' (cite inspector.pypi.io lines)"
                );
                eprintln!("  3. open a PR against ossf/malicious-packages with these OSV records");
                eprintln!(
                    "  4. non-malicious vulnerability: maintainers privately, then GitHub Advisory Database"
                );
            }
        }
    }
    Ok(())
}

fn snapshot_npm(
    root: &std::path::Path,
    policy: &supply_core::domain::Policy,
    use_osv: bool,
    osv_cache: Option<&std::path::Path>,
    findings: Option<&std::path::Path>,
) -> Result<()> {
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
    if let Some(path) = findings {
        supply_core::adapters::storage::FindingFile::new(path).load_into(&store)?;
    }
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
        let noop: Box<dyn supply_core::ports::VulnerabilitySource> =
            Box::new(NoopVulnerabilitySource);
        let cached: Box<dyn supply_core::ports::VulnerabilitySource> = if use_osv {
            let cache = osv_cache.map(|p| p.to_path_buf()).unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(std::env::temp_dir)
                    .join(".local/share/supply-core/osv-cache")
            });
            Box::new(
                OsvVulnerabilitySource::new(Box::new(ReqwestOsvTransport::new()?))
                    .with_cache(cache),
            )
        } else {
            noop
        };
        let decision = PackageEvaluator {
            policy,
            clock: &SystemClock,
            vulns: cached.as_ref(),
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

fn vulnerability_source(
    use_osv: bool,
    osv_cache: Option<&Path>,
) -> Result<Box<dyn supply_core::ports::VulnerabilitySource>> {
    if !use_osv {
        return Ok(Box::new(NoopVulnerabilitySource));
    }
    let cache = osv_cache.map(Path::to_path_buf).unwrap_or_else(|| {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(".local/share/supply-core/osv-cache")
    });
    Ok(Box::new(
        OsvVulnerabilitySource::new(Box::new(ReqwestOsvTransport::new()?)).with_cache(cache),
    ))
}

fn snapshot_pip(
    root: &Path,
    policy: &supply_core::domain::Policy,
    use_osv: bool,
    osv_cache: Option<&Path>,
    findings: Option<&Path>,
) -> Result<()> {
    let content = std::fs::read_to_string(root.join("requirements.txt"))?;
    let (pins, gaps) = parse_requirements(&content);
    let registry = HttpPyPiRegistry::new()?;
    let store = MemoryMetadataStore::default();
    if let Some(path) = findings {
        supply_core::adapters::storage::FindingFile::new(path).load_into(&store)?;
    }
    let vulns = vulnerability_source(use_osv, osv_cache)?;
    let now = chrono::Utc::now();
    let mut entries = vec![];
    let mut errors: Vec<serde_json::Value> = gaps
        .into_iter()
        .map(|gap| serde_json::json!({ "input": gap }))
        .collect();
    for pin in &pins {
        let name = &pin.name;
        let pinned = &pin.version;
        let Ok(version) = semver::Version::parse(pinned) else {
            errors.push(serde_json::json!({
                "package": name,
                "error": format!("non-semver version {pinned}; not evaluated"),
            }));
            continue;
        };
        let payload = match registry.release(name, pinned) {
            Ok(payload) => payload,
            Err(error) => {
                errors.push(serde_json::json!({ "package": name, "error": error.to_string() }));
                continue;
            }
        };
        let pv = match package_version_from_pypi(&payload, name, &version, &pin.hashes) {
            Ok(pv) => pv,
            Err(error) => {
                errors.push(serde_json::json!({ "package": name, "error": error.to_string() }));
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
            vulns: vulns.as_ref(),
            metadata: &store,
        }
        .evaluate(&pv, None)?;
        entries.push(serde_json::json!({
            "package": name,
            "pinned": pinned,
            "age_days": age_days,
            "status": format!("{:?}", decision.status),
            "reasons": decision.reasons,
            "warnings": decision.warnings,
        }));
    }
    let out = serde_json::json!({
        "captured_at": now.to_rfc3339(),
        "repository": root.display().to_string(),
        "ecosystem": "pypi",
        "dependencies": entries,
        "errors": errors,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn snapshot_nuget(
    root: &Path,
    policy: &supply_core::domain::Policy,
    use_osv: bool,
    osv_cache: Option<&Path>,
    findings: Option<&Path>,
) -> Result<()> {
    let content = std::fs::read_to_string(root.join("packages.lock.json"))?;
    let (pins, gaps) = parse_packages_lock(&content)?;
    let registry = HttpNuGetRegistry::new()?;
    let store = MemoryMetadataStore::default();
    if let Some(path) = findings {
        supply_core::adapters::storage::FindingFile::new(path).load_into(&store)?;
    }
    let vulns = vulnerability_source(use_osv, osv_cache)?;
    let now = chrono::Utc::now();
    let mut entries = vec![];
    let mut errors: Vec<serde_json::Value> = gaps
        .into_iter()
        .map(|gap| serde_json::json!({ "input": gap }))
        .collect();
    for pin in &pins {
        let name = &pin.name;
        let pinned = &pin.version;
        let Ok(version) = semver::Version::parse(pinned) else {
            errors.push(serde_json::json!({
                "package": name,
                "error": format!("non-semver version {pinned}; not evaluated"),
            }));
            continue;
        };
        let payload = match registry.release(name, pinned) {
            Ok(payload) => payload,
            Err(error) => {
                errors.push(serde_json::json!({ "package": name, "error": error.to_string() }));
                continue;
            }
        };
        let pv =
            match package_version_from_nuget(&payload, name, &version, pin.content_hash.as_deref())
            {
                Ok(pv) => pv,
                Err(error) => {
                    errors.push(serde_json::json!({ "package": name, "error": error.to_string() }));
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
            vulns: vulns.as_ref(),
            metadata: &store,
        }
        .evaluate(&pv, None)?;
        entries.push(serde_json::json!({
            "package": name,
            "pinned": pinned,
            "age_days": age_days,
            "status": format!("{:?}", decision.status),
            "reasons": decision.reasons,
            "warnings": decision.warnings,
        }));
    }
    let out = serde_json::json!({
        "captured_at": now.to_rfc3339(),
        "repository": root.display().to_string(),
        "ecosystem": "nuget",
        "dependencies": entries,
        "errors": errors,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn version_flag_is_supported() {
        match Cli::try_parse_from(["supply", "--version"]) {
            Ok(_) => panic!("--version must not parse as a subcommand"),
            Err(error) => assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion),
        }
    }
    #[test]
    fn ecosystem_subcommands_parse() -> Result<()> {
        let cli = Cli::try_parse_from(["supply", "snapshot-pip"])?;
        assert!(matches!(cli.command, Command::SnapshotPip { .. }));
        let cli = Cli::try_parse_from(["supply", "snapshot-nuget", "dir"])?;
        assert!(matches!(cli.command, Command::SnapshotNuGet { .. }));
        let cli = Cli::try_parse_from(["supply", "scan-docker", "--json"])?;
        assert!(matches!(
            cli.command,
            Command::ScanDocker { json: true, .. }
        ));
        let cli = Cli::try_parse_from(["supply", "report", "findings.json", "--submit"])?;
        assert!(matches!(cli.command, Command::Report { submit: true, .. }));
        let cli = Cli::try_parse_from([
            "supply",
            "scan-package",
            "npm",
            "evil.tgz",
            "--name",
            "evil",
            "--version",
            "1.2.3",
            "--guarddog",
            "--provenance",
        ])?;
        assert!(matches!(
            cli.command,
            Command::ScanPackage {
                guarddog: true,
                provenance: true,
                ..
            }
        ));
        let cli = Cli::try_parse_from([
            "supply",
            "snapshot-pip",
            "dir",
            "--findings",
            "findings.jsonl",
        ])?;
        assert!(matches!(cli.command, Command::SnapshotPip { .. }));
        let cli = Cli::try_parse_from([
            "supply",
            "snapshot-nuget",
            "dir",
            "--findings",
            "findings.jsonl",
        ])?;
        assert!(matches!(cli.command, Command::SnapshotNuGet { .. }));
        Ok(())
    }
    #[test]
    fn annotations_flag_is_accepted() -> Result<()> {
        let cli = Cli::try_parse_from(["supply", "scan-actions", "--annotations"])?;
        assert!(matches!(
            cli.command,
            Command::ScanActions {
                annotations: true,
                json: false,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn annotations_and_json_are_mutually_exclusive() {
        let error = Cli::try_parse_from(["supply", "scan-actions", "--annotations", "--json"])
            .err()
            .map(|error| error.kind());
        assert_eq!(error, Some(clap::error::ErrorKind::ArgumentConflict));
    }

    #[test]
    fn scan_pipelines_flags_accepted() -> Result<()> {
        let cli = Cli::try_parse_from(["supply", "scan-pipelines", "--annotations"])?;
        assert!(matches!(
            cli.command,
            Command::ScanPipelines {
                annotations: true,
                json: false,
                ..
            }
        ));
        let cli_alias = Cli::try_parse_from(["supply", "scan-azure-pipelines", "--json"])?;
        assert!(matches!(
            cli_alias.command,
            Command::ScanPipelines {
                annotations: false,
                json: true,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn scan_pipelines_annotations_and_json_conflict() {
        let error = Cli::try_parse_from(["supply", "scan-pipelines", "--annotations", "--json"])
            .err()
            .map(|error| error.kind());
        assert_eq!(error, Some(clap::error::ErrorKind::ArgumentConflict));
    }
}
