use serde::{Deserialize, Serialize};

/// Distinguishes between direct observations/facts and analytical reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssertionType {
    /// Directly observed from normalized telemetry or artifacts.
    Fact,
    /// Derived logically through deterministic correlation rules.
    Inference,
    /// Speculative analytical path awaiting corroborating evidence.
    Hypothesis,
}

/// The current epistemic verification status of an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationState {
    /// Newly proposed assertion awaiting verification.
    Candidate,
    /// Supported by at least one independent observation or rule.
    Corroborated,
    /// Definitively confirmed and validated by conclusive forensic evidence.
    Confirmed,
    /// Disproved by contradictory facts or telemetry.
    Disproved,
}

/// Standardized security severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// David Bianco's Pyramid of Pain indicator classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PainLevel {
    HashValues,
    IpAddresses,
    DomainNames,
    NetworkArtifacts,
    HostArtifacts,
    Tools,
    TTPs,
}

/// Normalized confidence bounded between 0.0 and 1.0
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(f32);

impl Confidence {
    pub fn new(val: f32) -> Self {
        Self(val.clamp(0.0, 1.0))
    }

    pub fn value(&self) -> f32 {
        self.0
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self(1.0)
    }
}
