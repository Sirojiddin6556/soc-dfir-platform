#![forbid(unsafe_code)]

use core_domain::scenario::ScenarioManifest;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScenarioError {
    #[error("Invalid bundle signature")]
    InvalidSignature,

    #[error("Manifest parse error: {0}")]
    ParseError(#[from] serde_json::Error),
}

pub struct ScenarioEngine;

impl ScenarioEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn load_manifest(&self, raw_json: &str) -> Result<ScenarioManifest, ScenarioError> {
        let manifest: ScenarioManifest = serde_json::from_str(raw_json)?;
        if manifest.signature.is_empty() {
            return Err(ScenarioError::InvalidSignature);
        }
        Ok(manifest)
    }
}

impl Default for ScenarioEngine {
    fn default() -> Self {
        Self::new()
    }
}
