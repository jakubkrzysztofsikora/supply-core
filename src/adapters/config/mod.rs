use crate::domain::Policy;
use anyhow::Result;
use std::{fs, path::Path};
pub fn load_policy(path: Option<&Path>) -> Result<Policy> {
    match path {
        Some(p) if p.exists() => Ok(serde_yaml::from_str(&fs::read_to_string(p)?)?),
        _ => Ok(Policy::default()),
    }
}
