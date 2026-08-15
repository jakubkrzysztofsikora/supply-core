use crate::{domain::*, ports::VulnerabilitySource};
use anyhow::Result;
use semver::Version;
pub struct NoopVulnerabilitySource;
impl VulnerabilitySource for NoopVulnerabilitySource {
    fn query(&self, _: Ecosystem, _: &str, _: &Version) -> Result<Vec<VulnerabilityFinding>> {
        Ok(vec![])
    }
}
