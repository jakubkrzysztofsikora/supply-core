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

    #[test]
    fn explicit_missing_policy_errors() {
        assert!(load_policy(Some(Path::new("/nonexistent/policy.yml"))).is_err());
    }

    #[test]
    fn no_policy_uses_defaults() -> Result<()> {
        assert_eq!(load_policy(None)?, Policy::default());
        Ok(())
    }
}
