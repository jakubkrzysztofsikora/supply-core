use crate::domain::Policy;
use anyhow::Result;
use std::{fs, path::Path};

pub fn load_policy(path: Option<&Path>) -> Result<Policy> {
    match path {
        Some(p) if p.exists() => Ok(serde_norway::from_str(&fs::read_to_string(p)?)?),
        Some(p) => anyhow::bail!("policy file not found: {}", p.display()),
        None => Ok(Policy::default()),
    }
}

pub fn parse_policy_str(content: &str) -> Result<Policy> {
    Ok(serde_norway::from_str(content)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::OFFICIAL_SERVICE_URL;

    #[test]
    fn explicit_missing_policy_errors() {
        assert!(load_policy(Some(Path::new("/nonexistent/policy.yml"))).is_err());
    }

    #[test]
    fn no_policy_uses_defaults() -> Result<()> {
        assert_eq!(load_policy(None)?, Policy::default());
        Ok(())
    }

    #[test]
    fn server_defaults_to_official_service() -> Result<()> {
        let policy = parse_policy_str("quarantine:\n  enabled: false\n")?;

        assert_eq!(policy.server.service_url, OFFICIAL_SERVICE_URL);
        assert!(!policy.server.allow_fallback);
        assert!(policy.server.force_official);
        Ok(())
    }

    #[test]
    fn server_settings_require_explicit_overrides() -> Result<()> {
        let policy = parse_policy_str(
            "server:\n  service_url: http://localhost:4873\n  allow_fallback: true\n  force_official: false\n",
        )?;

        assert_eq!(policy.server.service_url, "http://localhost:4873");
        assert!(policy.server.allow_fallback);
        assert!(!policy.server.force_official);
        Ok(())
    }
}
