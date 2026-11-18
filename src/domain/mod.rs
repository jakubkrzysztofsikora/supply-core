use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    PyPi,
    NuGet,
    DockerImage,
    GitHubActions,
    AzurePipelines,
}

#[derive(Debug, Clone)]
enum ParsedPackageVersion {
    Npm(node_semver::Version),
    PyPi(pep440_rs::Version),
    NuGet(NuGetVersion),
    Opaque,
}

#[derive(Debug, Clone)]
struct NuGetVersion {
    numbers: [i32; 4],
    prerelease: Option<semver::Prerelease>,
}

#[derive(Debug, Clone)]
pub struct PackageVersionId {
    ecosystem: Ecosystem,
    upstream: String,
    canonical: String,
    parsed: ParsedPackageVersion,
}

impl PackageVersionId {
    pub fn parse(ecosystem: &Ecosystem, raw: &str) -> anyhow::Result<Self> {
        let (canonical, parsed) = match ecosystem {
            Ecosystem::Npm => {
                let version = node_semver::Version::parse(raw)
                    .map_err(|error| anyhow::anyhow!("invalid npm version {raw:?}: {error}"))?;
                (version.to_string(), ParsedPackageVersion::Npm(version))
            }
            Ecosystem::PyPi => {
                let version: pep440_rs::Version = raw
                    .parse()
                    .map_err(|error| anyhow::anyhow!("invalid PEP 440 version {raw:?}: {error}"))?;
                let mut release = version.release().to_vec();
                while release.len() > 1 && release.last() == Some(&0) {
                    release.pop();
                }
                let version = version.with_release(release);
                (version.to_string(), ParsedPackageVersion::PyPi(version))
            }
            Ecosystem::NuGet => {
                let (version, canonical) = NuGetVersion::parse(raw)?;
                (canonical, ParsedPackageVersion::NuGet(version))
            }
            _ => {
                if raw.is_empty() {
                    anyhow::bail!("package version cannot be empty");
                }
                (raw.to_string(), ParsedPackageVersion::Opaque)
            }
        };

        Ok(Self {
            ecosystem: ecosystem.clone(),
            upstream: raw.to_string(),
            canonical,
            parsed,
        })
    }

    pub fn ecosystem(&self) -> &Ecosystem {
        &self.ecosystem
    }

    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn satisfies_npm_range(&self, range: &node_semver::Range) -> bool {
        match &self.parsed {
            ParsedPackageVersion::Npm(version) => version.satisfies(range),
            _ => false,
        }
    }

    pub fn precedence_cmp(&self, other: &Self) -> anyhow::Result<Ordering> {
        if self.ecosystem != other.ecosystem {
            anyhow::bail!("cannot compare versions from different ecosystems");
        }

        match (&self.parsed, &other.parsed) {
            (ParsedPackageVersion::Npm(left), ParsedPackageVersion::Npm(right)) => {
                Ok(left.cmp(right))
            }
            (ParsedPackageVersion::PyPi(left), ParsedPackageVersion::PyPi(right)) => {
                Ok(left.cmp(right))
            }
            (ParsedPackageVersion::NuGet(left), ParsedPackageVersion::NuGet(right)) => {
                Ok(left.precedence_cmp(right))
            }
            _ => anyhow::bail!("version parser does not match ecosystem"),
        }
    }
}

impl PartialEq for PackageVersionId {
    fn eq(&self, other: &Self) -> bool {
        self.ecosystem == other.ecosystem && self.canonical == other.canonical
    }
}

impl Eq for PackageVersionId {}

impl Hash for PackageVersionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ecosystem.hash(state);
        self.canonical.hash(state);
    }
}

impl Display for PackageVersionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.canonical)
    }
}

impl Serialize for PackageVersionId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            ecosystem: &'a Ecosystem,
            upstream: &'a str,
            canonical: &'a str,
        }

        Wire {
            ecosystem: &self.ecosystem,
            upstream: &self.upstream,
            canonical: &self.canonical,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PackageVersionId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            ecosystem: Ecosystem,
            upstream: String,
            canonical: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        let parsed = Self::parse(&wire.ecosystem, &wire.upstream)
            .map_err(<D::Error as serde::de::Error>::custom)?;
        if parsed.canonical != wire.canonical {
            return Err(serde::de::Error::custom(
                "canonical package version does not match upstream version",
            ));
        }
        Ok(parsed)
    }
}

impl NuGetVersion {
    fn parse(raw: &str) -> anyhow::Result<(Self, String)> {
        let input = raw.trim();
        if input.is_empty() {
            anyhow::bail!("NuGet version cannot be empty");
        }

        let (without_metadata, metadata) = match input.split_once('+') {
            Some((version, metadata)) => {
                Self::validate_identifiers(metadata, "build metadata")?;
                (version, Some(metadata))
            }
            None => (input, None),
        };
        if metadata.is_some_and(|_| without_metadata.contains('+')) {
            anyhow::bail!("NuGet version contains multiple build separators");
        }

        let (numeric, prerelease) = match without_metadata.split_once('-') {
            Some((numeric, prerelease)) => {
                if prerelease.is_empty() {
                    anyhow::bail!("NuGet prerelease label cannot be empty");
                }
                (numeric, Some(prerelease))
            }
            None => (without_metadata, None),
        };

        let components: Vec<&str> = numeric.split('.').collect();
        if !(1..=4).contains(&components.len()) {
            anyhow::bail!("NuGet version needs 1 to 4 numeric components");
        }

        let mut numbers = [0; 4];
        for (index, component) in components.iter().enumerate() {
            if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
                anyhow::bail!("invalid NuGet numeric component {component:?}");
            }
            numbers[index] = component
                .parse::<i32>()
                .map_err(|_| anyhow::anyhow!("NuGet numeric component overflows: {component:?}"))?;
        }

        let prerelease = prerelease
            .map(|value| {
                Self::validate_identifiers(value, "prerelease")?;
                let normalized = value.to_ascii_lowercase();
                for identifier in normalized.split('.') {
                    if identifier.len() > 1
                        && identifier.starts_with('0')
                        && identifier.bytes().all(|byte| byte.is_ascii_digit())
                    {
                        anyhow::bail!(
                            "NuGet numeric prerelease identifiers cannot have leading zeroes"
                        );
                    }
                }
                semver::Prerelease::new(&normalized)
                    .map_err(|error| anyhow::anyhow!("invalid NuGet prerelease: {error}"))
            })
            .transpose()?;

        let version = Self {
            numbers,
            prerelease,
        };
        let canonical = version.canonical();
        Ok((version, canonical))
    }

    fn validate_identifiers(value: &str, part: &str) -> anyhow::Result<()> {
        if value.is_empty()
            || value.split('.').any(|identifier| {
                identifier.is_empty()
                    || !identifier
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            anyhow::bail!("invalid NuGet {part} {value:?}");
        }
        Ok(())
    }

    fn canonical(&self) -> String {
        use std::fmt::Write as _;

        let mut canonical = format!(
            "{}.{}.{}",
            self.numbers[0], self.numbers[1], self.numbers[2]
        );
        if self.numbers[3] != 0 {
            let _ = write!(&mut canonical, ".{}", self.numbers[3]);
        }
        if let Some(prerelease) = &self.prerelease {
            canonical.push('-');
            canonical.push_str(&prerelease.to_string());
        }
        canonical
    }

    fn precedence_cmp(&self, other: &Self) -> Ordering {
        self.numbers
            .cmp(&other.numbers)
            .then_with(|| match (&self.prerelease, &other.prerelease) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(left), Some(right)) => left.cmp(right),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageCoordinate {
    pub ecosystem: Ecosystem,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageVersion {
    pub package: PackageCoordinate,
    pub version: PackageVersionId,
    pub published_at: Option<DateTime<Utc>>,
    pub integrity: Option<String>,
    pub tarball_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactKey {
    pub source: String,
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: PackageVersionId,
    pub filename: String,
}

impl ArtifactKey {
    pub fn from_tarball_url(
        tarball_url: &str,
        ecosystem: &Ecosystem,
        name: &str,
        version: &PackageVersionId,
    ) -> anyhow::Result<Self> {
        let (source, filename) = artifact_url_identity(tarball_url)?;
        let key = Self {
            source,
            ecosystem: ecosystem.clone(),
            name: name.to_string(),
            version: version.clone(),
            filename,
        };
        key.validate()?;
        Ok(key)
    }

    pub fn source_from_tarball_url(tarball_url: &str) -> anyhow::Result<String> {
        artifact_url_identity(tarball_url).map(|(source, _)| source)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.source != normalized_source(&self.source)? {
            anyhow::bail!("artifact source must be a normalized HTTP(S) origin");
        }
        if self.version.ecosystem() != &self.ecosystem {
            anyhow::bail!("artifact version ecosystem does not match artifact ecosystem");
        }
        if self.name.is_empty()
            || self.name.contains('\\')
            || self.name.chars().any(char::is_control)
            || self
                .name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            anyhow::bail!("invalid artifact package name: {:?}", self.name);
        }
        if self.filename.is_empty()
            || self.filename == "."
            || self.filename == ".."
            || self.filename.contains('/')
            || self.filename.contains('\\')
            || self.filename.chars().any(char::is_control)
        {
            anyhow::bail!("invalid artifact filename: {:?}", self.filename);
        }
        Ok(())
    }
}

fn artifact_url_identity(tarball_url: &str) -> anyhow::Result<(String, String)> {
    let uri = tarball_url
        .parse::<http::Uri>()
        .map_err(|error| anyhow::anyhow!("invalid tarball URL: {error}"))?;
    let source = normalized_source_uri(&uri)?;
    let filename = uri
        .path()
        .rsplit('/')
        .next()
        .filter(|filename| !filename.is_empty())
        .ok_or_else(|| anyhow::anyhow!("tarball URL has no filename"))?
        .to_string();
    if filename == "."
        || filename == ".."
        || filename.contains('/')
        || filename.contains('\\')
        || filename.chars().any(char::is_control)
    {
        anyhow::bail!("invalid tarball URL filename: {filename:?}");
    }
    Ok((source, filename))
}

fn normalized_source(source: &str) -> anyhow::Result<String> {
    let uri = source
        .parse::<http::Uri>()
        .map_err(|error| anyhow::anyhow!("invalid artifact source: {error}"))?;
    normalized_source_uri(&uri)
}

fn normalized_source_uri(uri: &http::Uri) -> anyhow::Result<String> {
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow::anyhow!("tarball URL must be absolute"))?
        .to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("tarball URL must use HTTP or HTTPS");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("tarball URL must include a host"))?;
    if authority.as_str().contains('@') {
        anyhow::bail!("tarball URL must not include credentials");
    }
    let mut host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        anyhow::bail!("tarball URL must include a host");
    }
    if host.contains(':') && !host.starts_with('[') {
        host = format!("[{host}]");
    }
    let port = authority.port_u16();
    let default_port = matches!(
        (scheme.as_str(), port),
        ("http", Some(80)) | ("https", Some(443))
    );
    let port = if default_port { None } else { port };
    Ok(match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrozenArtifact {
    pub key: ArtifactKey,
    pub package: PackageCoordinate,
    pub version: PackageVersionId,
    pub sha256: String,
    pub integrity: Option<String>,
    pub path: String,
    pub frozen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    pub fn rank(&self) -> u8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub source: String,
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub summary: String,
    #[serde(default)]
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub withdrawn: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pending,
    Held,
    ScanIncomplete,
    Review,
    Blocked,
    Released,
    Withdrawn,
}

impl Verdict {
    pub fn combine(self, other: Self) -> Self {
        if self.precedence() >= other.precedence() {
            self
        } else {
            other
        }
    }

    fn precedence(self) -> u8 {
        match self {
            Self::Released => 0,
            Self::Held => 1,
            Self::Review => 2,
            Self::Pending => 3,
            Self::ScanIncomplete => 4,
            Self::Blocked => 5,
            Self::Withdrawn => 6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionStatus {
    Allow,
    Warn,
    Block,
    Quarantine,
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub status: DecisionStatus,
    pub package: String,
    pub requested_version: Option<String>,
    pub served_version: Option<String>,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
}
impl Decision {
    pub fn allow(package: impl Into<String>, version: impl Into<String>) -> Self {
        let version = version.into();
        Self {
            status: DecisionStatus::Allow,
            package: package.into(),
            requested_version: Some(version.clone()),
            served_version: Some(version),
            reasons: vec![],
            warnings: vec![],
        }
    }
    pub fn fallback(
        package: impl Into<String>,
        requested: impl Into<String>,
        served: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            status: DecisionStatus::Fallback,
            package: package.into(),
            requested_version: Some(requested.into()),
            served_version: Some(served.into()),
            reasons: vec![],
            warnings: vec![reason.into()],
        }
    }
    pub fn block(
        package: impl Into<String>,
        requested: Option<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            status: DecisionStatus::Block,
            package: package.into(),
            requested_version: requested,
            served_version: None,
            reasons: vec![reason.into()],
            warnings: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QuarantinePolicy {
    pub enabled: bool,
    pub minimum_age_days: i64,
    pub cve_keeps_quarantined: bool,
}
impl Default for QuarantinePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            minimum_age_days: 7,
            cve_keeps_quarantined: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VulnerabilityPolicy {
    pub block_severities: Vec<Severity>,
}
impl Default for VulnerabilityPolicy {
    fn default() -> Self {
        Self {
            block_severities: vec![Severity::High, Severity::Critical],
        }
    }
}
impl VulnerabilityPolicy {
    pub fn blocks_severity(&self, severity: &Severity) -> bool {
        self.block_severities
            .iter()
            .map(Severity::rank)
            .min()
            .is_some_and(|minimum| severity.rank() >= minimum)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImagePinKind {
    Digest,
    InvalidDigest,
    Tag,
    Latest,
    MissingTag,
    Unresolved,
}

pub fn classify_image_ref(raw: &str) -> ImagePinKind {
    let trimmed = raw.trim().trim_matches(['"', '\'']);
    if trimmed.is_empty() || trimmed.contains('$') {
        return ImagePinKind::Unresolved;
    }
    if let Some((_, digest)) = trimmed.split_once('@') {
        let valid = digest
            .strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
        return if valid {
            ImagePinKind::Digest
        } else {
            ImagePinKind::InvalidDigest
        };
    }
    let last_slash = trimmed.rfind('/');
    let last_colon = trimmed.rfind(':');
    match last_colon {
        Some(colon) if last_slash.is_none_or(|slash| colon > slash) => {
            match &trimmed[colon + 1..] {
                "" => ImagePinKind::MissingTag,
                "latest" => ImagePinKind::Latest,
                _ => ImagePinKind::Tag,
            }
        }
        _ => ImagePinKind::MissingTag,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PipPolicy {
    pub require_integrity: bool,
    pub fallback_to_frozen: bool,
}
impl Default for PipPolicy {
    fn default() -> Self {
        Self {
            require_integrity: true,
            fallback_to_frozen: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NuGetPolicy {
    pub require_integrity: bool,
    pub fallback_to_frozen: bool,
}
impl Default for NuGetPolicy {
    fn default() -> Self {
        Self {
            require_integrity: true,
            fallback_to_frozen: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerPolicy {
    pub require_digest_pin: bool,
}
impl Default for DockerPolicy {
    fn default() -> Self {
        Self {
            require_digest_pin: true,
        }
    }
}

fn default_detected_at() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}
fn default_scan_incomplete() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentFinding {
    pub ecosystem: Ecosystem,
    pub package: String,
    pub version: PackageVersionId,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<Decimal>,
    #[serde(default = "default_scan_incomplete")]
    pub scan_incomplete: bool,
    pub rules: Vec<String>,
    pub summary: String,
    #[serde(default = "default_detected_at")]
    pub detected_at: chrono::DateTime<chrono::Utc>,
}
impl ContentFinding {
    /// OSV-shaped record, ready to attach to an `ossf/malicious-packages`
    /// contribution or a GitHub advisory.
    pub fn to_osv(&self) -> serde_json::Value {
        let ecosystem = match self.ecosystem {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "PyPI",
            Ecosystem::NuGet => "NuGet",
            _ => "unknown",
        };
        let sanitized = |raw: &str| -> String {
            raw.chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character.to_ascii_uppercase()
                    } else {
                        '-'
                    }
                })
                .collect()
        };
        serde_json::json!({
            "schema_version": "1.7.0",
            "id": format!(
                "SUPPLY-{}-{}",
                sanitized(&self.package),
                sanitized(&self.version.to_string())
            ),
            "modified": self.detected_at.to_rfc3339(),
            "summary": self.summary,
            "details": format!(
                "rules: {}; source: {}",
                self.rules.join(", "),
                self.source
            ),
            "affected": [{
                "package": { "ecosystem": ecosystem, "name": self.package },
                "versions": [self.version.to_string()]
            }],
            "references": []
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct QuarantineScannerPolicy {
    pub enabled: bool,
    pub review_score: u8,
    pub block_score: u8,
}
impl Default for QuarantineScannerPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            review_score: 4,
            block_score: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NpmPolicy {
    pub require_integrity: bool,
    pub fallback_to_frozen: bool,
    pub deny_packages: Vec<String>,
}
impl Default for NpmPolicy {
    fn default() -> Self {
        Self {
            require_integrity: true,
            fallback_to_frozen: true,
            deny_packages: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitHubActionsPolicy {
    pub require_full_sha_pin: bool,
    pub allow_local_actions: bool,
}
impl Default for GitHubActionsPolicy {
    fn default() -> Self {
        Self {
            require_full_sha_pin: true,
            allow_local_actions: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzurePipelinesPolicy {
    pub require_task_version: bool,
    pub require_full_sha_pin: bool,
    pub allow_local_templates: bool,
    pub allowed_unpinned_checkouts: Vec<String>,
    pub allowed_unpinned_tasks: Vec<String>,
    pub allowed_unpinned_repositories: Vec<String>,
}
impl Default for AzurePipelinesPolicy {
    fn default() -> Self {
        Self {
            require_task_version: true,
            require_full_sha_pin: true,
            allow_local_templates: true,
            allowed_unpinned_checkouts: vec![],
            allowed_unpinned_tasks: vec![],
            allowed_unpinned_repositories: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ServerPolicy {
    pub service_url: String,
    pub allow_fallback: bool,
    pub force_official: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub server: ServerPolicy,
    #[serde(default)]
    pub quarantine: QuarantinePolicy,
    #[serde(default)]
    pub vulnerabilities: VulnerabilityPolicy,
    #[serde(default)]
    pub npm: NpmPolicy,
    #[serde(default)]
    pub pip: PipPolicy,
    #[serde(default)]
    pub nuget: NuGetPolicy,
    #[serde(default)]
    pub docker: DockerPolicy,
    #[serde(default)]
    pub quarantine_scanner: QuarantineScannerPolicy,
    #[serde(default)]
    pub github_actions: GitHubActionsPolicy,
    #[serde(default)]
    pub azure_pipelines: AzurePipelinesPolicy,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionPinKind {
    FullSha,
    TagOrBranch,
    Local,
    Docker,
    TaskVersion,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubActionReference {
    pub raw: String,
    pub file: String,
    pub line: usize,
    pub pin_kind: ActionPinKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineRefKind {
    Action,
    Task,
    Checkout,
    Template,
    Repository,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineReference {
    pub raw: String,
    pub file: String,
    pub line: usize,
    pub kind: PipelineRefKind,
    pub pin_kind: ActionPinKind,
}

pub fn classify_action_ref(raw: &str) -> ActionPinKind {
    if raw.starts_with("./") {
        return ActionPinKind::Local;
    }
    if raw.starts_with("docker://") {
        return ActionPinKind::Docker;
    }
    let Some((_, reference)) = raw.rsplit_once('@') else {
        return ActionPinKind::Unknown;
    };
    if reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()) {
        ActionPinKind::FullSha
    } else {
        ActionPinKind::TagOrBranch
    }
}

pub fn classify_pipeline_ref(raw: &str, kind: &PipelineRefKind) -> ActionPinKind {
    match kind {
        PipelineRefKind::Task => {
            if let Some((_, version)) = raw.rsplit_once('@') {
                if !version.is_empty() {
                    if version.len() == 40 && version.chars().all(|c| c.is_ascii_hexdigit()) {
                        ActionPinKind::FullSha
                    } else {
                        ActionPinKind::TaskVersion
                    }
                } else {
                    ActionPinKind::Unknown
                }
            } else {
                ActionPinKind::Unknown
            }
        }
        PipelineRefKind::Checkout => {
            if raw == "self" || raw == "none" {
                ActionPinKind::Local
            } else if let Some((_, reference)) = raw.rsplit_once('@') {
                if reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit()) {
                    ActionPinKind::FullSha
                } else {
                    ActionPinKind::TagOrBranch
                }
            } else {
                ActionPinKind::TagOrBranch
            }
        }
        PipelineRefKind::Template => {
            if let Some((_, suffix)) = raw.rsplit_once('@') {
                if suffix.len() == 40 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
                    ActionPinKind::FullSha
                } else {
                    ActionPinKind::TagOrBranch
                }
            } else {
                ActionPinKind::Local
            }
        }
        PipelineRefKind::Repository => {
            let reference = raw.rsplit_once('@').map_or(raw, |(_, reference)| reference);
            let trimmed = reference
                .strip_prefix("refs/heads/")
                .or_else(|| reference.strip_prefix("refs/tags/"))
                .unwrap_or(reference);
            if trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                ActionPinKind::FullSha
            } else if !trimmed.is_empty() {
                ActionPinKind::TagOrBranch
            } else {
                ActionPinKind::Unknown
            }
        }
        PipelineRefKind::Action => classify_action_ref(raw),
    }
}

pub fn is_version_quarantined(
    published_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    policy: &QuarantinePolicy,
) -> bool {
    policy.enabled
        && match published_at {
            Some(p) => now.signed_duration_since(p).num_days() < policy.minimum_age_days,
            None => true,
        }
}

fn severity_word(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

pub fn strongest_vulnerability(findings: &[VulnerabilityFinding]) -> Option<String> {
    strongest_vulnerability_matching(findings, |_| true)
}

pub fn strongest_osv_vulnerability(findings: &[VulnerabilityFinding]) -> Option<String> {
    strongest_vulnerability_matching(findings, |finding| finding.source == "OSV")
}

fn strongest_vulnerability_matching(
    findings: &[VulnerabilityFinding],
    matches: impl Fn(&VulnerabilityFinding) -> bool,
) -> Option<String> {
    findings
        .iter()
        .filter(|finding| finding.withdrawn.is_none() && matches(finding))
        .max_by_key(|finding| (finding.severity.rank(), finding.id.as_str()))
        .map(|finding| {
            format!(
                "{} vulnerability {} from {}",
                severity_word(&finding.severity),
                finding.id,
                finding.source
            )
        })
}

pub fn blocks_vulnerability(
    findings: &[VulnerabilityFinding],
    policy: &VulnerabilityPolicy,
) -> Option<String> {
    findings
        .iter()
        .filter(|finding| finding.withdrawn.is_none() && policy.blocks_severity(&finding.severity))
        .max_by_key(|f| (f.severity.rank(), f.id.as_str()))
        .map(|f| {
            format!(
                "{} vulnerability {} from {}",
                severity_word(&f.severity),
                f.id,
                f.source
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    #[test]
    fn classifies_actions() {
        assert_eq!(
            classify_action_ref("actions/checkout@v4"),
            ActionPinKind::TagOrBranch
        );
        assert_eq!(
            classify_action_ref("./.github/actions/x"),
            ActionPinKind::Local
        );
        assert_eq!(
            classify_action_ref("docker://node:20"),
            ActionPinKind::Docker
        );
        assert_eq!(
            classify_action_ref("a/b@0123456789abcdef0123456789abcdef01234567"),
            ActionPinKind::FullSha
        );
    }
    #[test]
    fn quarantine_by_age() {
        let now = Utc::now();
        assert!(is_version_quarantined(
            Some(now - Duration::days(2)),
            now,
            &QuarantinePolicy {
                enabled: true,
                minimum_age_days: 7,
                cve_keeps_quarantined: true
            }
        ));
        assert!(!is_version_quarantined(
            Some(now - Duration::days(8)),
            now,
            &QuarantinePolicy {
                enabled: true,
                minimum_age_days: 7,
                cve_keeps_quarantined: true
            }
        ));
    }
    #[test]
    fn package_version_accepts_pep440_release_versions() {
        let encoded = serde_json::json!({
            "package": {"ecosystem": "PyPi", "name": "demo"},
            "version": {
                "ecosystem": "PyPi",
                "upstream": "1.0.post1",
                "canonical": "1.post1"
            },
            "published_at": null,
            "integrity": null,
            "tarball_url": null
        });

        let package = match serde_json::from_value::<PackageVersion>(encoded) {
            Ok(package) => package,
            Err(error) => panic!("PEP 440 release version rejected: {error}"),
        };

        assert_eq!(package.version.to_string(), "1.post1");
    }

    #[test]
    fn npm_build_metadata_changes_identity_but_not_precedence() -> anyhow::Result<()> {
        let first = PackageVersionId::parse(&Ecosystem::Npm, "1.2.3+build.1")?;
        let second = PackageVersionId::parse(&Ecosystem::Npm, "1.2.3+build.2")?;

        assert_ne!(first, second);
        assert_eq!(first.precedence_cmp(&second)?, std::cmp::Ordering::Equal);
        assert_eq!(first.canonical(), "1.2.3+build.1");
        assert_eq!(first.upstream(), "1.2.3+build.1");
        Ok(())
    }

    #[test]
    fn pypi_package_identity_uses_pep440_equality_and_preserves_local_segments(
    ) -> anyhow::Result<()> {
        let short = PackageVersionId::parse(&Ecosystem::PyPi, "1.0")?;
        let long = PackageVersionId::parse(&Ecosystem::PyPi, "1.0.0")?;
        assert_eq!(short, long);
        assert_eq!(short.canonical(), "1");

        let alias = PackageVersionId::parse(&Ecosystem::PyPi, "1.0RC1")?;
        let normalized = PackageVersionId::parse(&Ecosystem::PyPi, "1.0-rc1")?;
        assert_eq!(alias, normalized);

        let local = PackageVersionId::parse(&Ecosystem::PyPi, "1.0+ABC.01")?;
        let other_local = PackageVersionId::parse(&Ecosystem::PyPi, "1.0+abc.2")?;
        assert_ne!(local, other_local);
        assert_eq!(local.canonical(), "1+abc.1");
        assert_eq!(local.upstream(), "1.0+ABC.01");
        Ok(())
    }

    #[test]
    fn nuget_package_versions_match_microsoft_normalization_cases() -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct Case {
            input: String,
            canonical: String,
        }

        let fixture: Vec<Case> =
            serde_json::from_str(include_str!("../../tests/fixtures/nuget_versions.json"))?;

        for case in fixture {
            let parsed = PackageVersionId::parse(&Ecosystem::NuGet, &case.input)?;
            assert_eq!(parsed.canonical(), case.canonical, "input {}", case.input);
        }

        assert_eq!(
            PackageVersionId::parse(&Ecosystem::NuGet, "1.6.2-BeTa")?,
            PackageVersionId::parse(&Ecosystem::NuGet, "1.6.02-beta")?
        );
        assert_eq!(
            PackageVersionId::parse(&Ecosystem::NuGet, "1.0.0+beta.2")?,
            PackageVersionId::parse(&Ecosystem::NuGet, "1.0.0+beta.1")?
        );
        assert_eq!(
            PackageVersionId::parse(&Ecosystem::NuGet, "1.0.0-alpha.2")?.precedence_cmp(
                &PackageVersionId::parse(&Ecosystem::NuGet, "1.0.0-alpha.10")?
            )?,
            std::cmp::Ordering::Less
        );
        Ok(())
    }

    #[test]
    fn nuget_package_version_parser_rejects_invalid_and_overflowing_values() {
        for raw in [
            "1.2.3.4.5",
            "1.2147483648",
            "1.2.3.2147483648",
            "1.4.7-",
            "1.4.7+*",
            "1.2Av^c",
        ] {
            assert!(
                PackageVersionId::parse(&Ecosystem::NuGet, raw).is_err(),
                "accepted {raw}"
            );
        }
    }

    #[test]
    fn package_version_id_round_trips_with_canonical_and_upstream_values() -> anyhow::Result<()> {
        let parsed = PackageVersionId::parse(&Ecosystem::PyPi, "1.0.post1")?;
        let encoded = serde_json::to_string(&parsed)?;
        let decoded: PackageVersionId = serde_json::from_str(&encoded)?;

        assert_eq!(decoded, parsed);
        assert_eq!(decoded.upstream(), "1.0.post1");
        assert_eq!(decoded.canonical(), "1.post1");
        Ok(())
    }

    #[test]
    fn content_finding_serializes_to_osv_record() {
        let finding = ContentFinding {
            ecosystem: Ecosystem::Npm,
            package: "evil-pkg".into(),
            version: PackageVersionId::parse(&Ecosystem::Npm, "1.2.3")
                .unwrap_or_else(|_| panic!("valid npm version")),
            source: "static-heuristics".into(),
            score: Some(Decimal::from(9)),
            scan_incomplete: false,
            rules: vec!["install-script-network".into()],
            summary: "postinstall beacon".into(),
            detected_at: chrono::Utc::now(),
        };
        let record = finding.to_osv();
        assert_eq!(record["id"], "SUPPLY-EVIL-PKG-1-2-3");
        assert!(
            record["modified"]
                .as_str()
                .is_some_and(|modified| modified.contains('T')),
            "OSV records need an RFC3339 modified timestamp"
        );
        assert_eq!(record["affected"][0]["package"]["ecosystem"], "npm");
        assert_eq!(record["affected"][0]["package"]["name"], "evil-pkg");
        assert_eq!(record["affected"][0]["versions"][0], "1.2.3");
        assert_eq!(record["summary"], "postinstall beacon");
        assert!(record["details"]
            .as_str()
            .is_some_and(|details| details.contains("install-script-network")));
    }
    #[test]
    fn scanner_policy_defaults_are_disabled() {
        let p = Policy::default();
        assert!(!p.quarantine_scanner.enabled);
        assert_eq!(p.quarantine_scanner.review_score, 4);
        assert_eq!(p.quarantine_scanner.block_score, 8);
    }
    #[test]
    fn classifies_image_references() {
        let pinned = format!("nginx@sha256:{}", "a".repeat(64));
        assert_eq!(classify_image_ref(&pinned), ImagePinKind::Digest);
        assert_eq!(
            classify_image_ref("nginx@sha256:deadbeef"),
            ImagePinKind::InvalidDigest
        );
        assert_eq!(classify_image_ref("nginx:1.27-alpine"), ImagePinKind::Tag);
        assert_eq!(classify_image_ref("nginx:latest"), ImagePinKind::Latest);
        assert_eq!(classify_image_ref("nginx"), ImagePinKind::MissingTag);
        assert_eq!(
            classify_image_ref("ghcr.io/org/app@sha256:abc123"),
            ImagePinKind::InvalidDigest
        );
        assert_eq!(
            classify_image_ref("localhost:5000/app:1.2"),
            ImagePinKind::Tag
        );
        assert_eq!(classify_image_ref("$BASE_IMAGE"), ImagePinKind::Unresolved);
        assert_eq!(
            classify_image_ref("${BASE_IMAGE}:1"),
            ImagePinKind::Unresolved
        );
    }
    #[test]
    fn ecosystem_policies_have_secure_defaults() {
        let p = Policy::default();
        assert!(p.pip.require_integrity);
        assert!(p.pip.fallback_to_frozen);
        assert!(p.nuget.require_integrity);
        assert!(p.nuget.fallback_to_frozen);
        assert!(p.docker.require_digest_pin);
    }
    #[test]
    fn verdict_combination_uses_safety_precedence() {
        let order = [
            Verdict::Withdrawn,
            Verdict::Blocked,
            Verdict::ScanIncomplete,
            Verdict::Pending,
            Verdict::Review,
            Verdict::Held,
            Verdict::Released,
        ];

        for (index, stronger) in order.iter().copied().enumerate() {
            for weaker in order.iter().copied().skip(index) {
                assert_eq!(stronger.combine(weaker), stronger);
                assert_eq!(weaker.combine(stronger), stronger);
            }
        }
    }
    #[test]
    fn strongest_vulnerability_is_order_independent() {
        let finding = |id: &str| VulnerabilityFinding {
            source: "OSV".into(),
            id: id.into(),
            severity: Severity::Medium,
            summary: "x".into(),
            aliases: vec![],
            modified: None,
            withdrawn: None,
        };
        let forward = vec![finding("GHSA-a"), finding("GHSA-b")];
        let reverse = vec![finding("GHSA-b"), finding("GHSA-a")];
        assert_eq!(
            strongest_vulnerability(&forward),
            strongest_vulnerability(&reverse)
        );
    }
    #[test]
    fn vuln_threshold() {
        let f = vec![VulnerabilityFinding {
            source: "OSV".into(),
            id: "GHSA-x".into(),
            severity: Severity::High,
            summary: "x".into(),
            aliases: vec![],
            modified: None,
            withdrawn: None,
        }];
        assert!(blocks_vulnerability(&f, &VulnerabilityPolicy::default()).is_some());
    }
    #[test]
    fn classifies_pipeline_refs() {
        assert_eq!(
            classify_pipeline_ref("AzureCLI@2", &PipelineRefKind::Task),
            ActionPinKind::TaskVersion
        );
        assert_eq!(
            classify_pipeline_ref("UseNode@1.2.3", &PipelineRefKind::Task),
            ActionPinKind::TaskVersion
        );
        assert_eq!(
            classify_pipeline_ref("AzureCLI", &PipelineRefKind::Task),
            ActionPinKind::Unknown
        );
        assert_eq!(
            classify_pipeline_ref("self", &PipelineRefKind::Checkout),
            ActionPinKind::Local
        );
        assert_eq!(
            classify_pipeline_ref("none", &PipelineRefKind::Checkout),
            ActionPinKind::Local
        );
        assert_eq!(
            classify_pipeline_ref(
                "git://Circit/release-notes-generator",
                &PipelineRefKind::Checkout
            ),
            ActionPinKind::TagOrBranch
        );
        assert_eq!(
            classify_pipeline_ref(
                "git://Circit/repo@0123456789abcdef0123456789abcdef01234567",
                &PipelineRefKind::Checkout
            ),
            ActionPinKind::FullSha
        );
        assert_eq!(
            classify_pipeline_ref("../templates/bicep.yml", &PipelineRefKind::Template),
            ActionPinKind::Local
        );
        assert_eq!(
            classify_pipeline_ref("template.yml@common-templates", &PipelineRefKind::Template),
            ActionPinKind::TagOrBranch
        );
        assert_eq!(
            classify_pipeline_ref(
                "template.yml@common@0123456789abcdef0123456789abcdef01234567",
                &PipelineRefKind::Template
            ),
            ActionPinKind::FullSha
        );
        assert_eq!(
            classify_pipeline_ref(
                "0123456789abcdef0123456789abcdef01234567",
                &PipelineRefKind::Repository
            ),
            ActionPinKind::FullSha
        );
        assert_eq!(
            classify_pipeline_ref("refs/heads/main", &PipelineRefKind::Repository),
            ActionPinKind::TagOrBranch
        );
    }
}
