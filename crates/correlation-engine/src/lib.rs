#![forbid(unsafe_code)]

use core_domain::epistemic::{AssertionType, Confidence, PainLevel, Severity, VerificationState};
use core_domain::fact::{EntityType, Fact};
use core_domain::id::EntityId;
use core_domain::observation::Observation;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CorrelationError {
    #[error("Rule evaluation failed: {0}")]
    EvaluationError(String),
}

pub struct DeterministicCorrelationEngine;

impl DeterministicCorrelationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates observations and derives verified security facts
    pub fn correlate(&self, observations: &[Observation]) -> Result<Vec<Fact>, CorrelationError> {
        let mut facts = Vec::new();

        for obs in observations {
            // 1. Process execution correlation
            if let Some(cmd) = obs.data.get("command_line").and_then(|c| c.as_str()) {
                let cmd_lower = cmd.to_lowercase();

                // Credential access heuristic
                if cmd_lower.contains("mimikatz")
                    || cmd_lower.contains("procdump")
                    || cmd_lower.contains("comsvcs.dll")
                {
                    facts.push(Fact {
                        id: EntityId::new_v7(),
                        case_id: obs.case_id,
                        observation_id: Some(obs.id),
                        assertion_type: AssertionType::Fact,
                        verification_state: VerificationState::Confirmed,
                        entity_type: EntityType::Process,
                        entity_key: format!("proc:cred_dump:{}", obs.id),
                        fact_type: "CredentialAccessAttempt".to_string(),
                        confidence: Confidence::new(0.98),
                        severity: Severity::Critical,
                        risk_score: 95.0,
                        evidence_strength: 0.95,
                        pain_level: Some(PainLevel::Tools),
                        data: obs.data.clone(),
                        created_at: obs.source_timestamp,
                    });
                }
                // Persistence via Scheduled Tasks / Cron
                else if cmd_lower.contains("schtasks") && cmd_lower.contains("/create") {
                    facts.push(Fact {
                        id: EntityId::new_v7(),
                        case_id: obs.case_id,
                        observation_id: Some(obs.id),
                        assertion_type: AssertionType::Fact,
                        verification_state: VerificationState::Confirmed,
                        entity_type: EntityType::Process,
                        entity_key: format!("proc:persist:{}", obs.id),
                        fact_type: "ScheduledTaskPersistence".to_string(),
                        confidence: Confidence::new(0.95),
                        severity: Severity::High,
                        risk_score: 85.0,
                        evidence_strength: 0.9,
                        pain_level: Some(PainLevel::TTPs),
                        data: obs.data.clone(),
                        created_at: obs.source_timestamp,
                    });
                }
                // Reconnaissance / Discovery
                else if cmd_lower.contains("whoami")
                    || cmd_lower.contains("net user")
                    || cmd_lower.contains("nltest")
                {
                    facts.push(Fact {
                        id: EntityId::new_v7(),
                        case_id: obs.case_id,
                        observation_id: Some(obs.id),
                        assertion_type: AssertionType::Fact,
                        verification_state: VerificationState::Corroborated,
                        entity_type: EntityType::Process,
                        entity_key: format!("proc:recon:{}", obs.id),
                        fact_type: "DiscoveryReconnaissance".to_string(),
                        confidence: Confidence::new(0.90),
                        severity: Severity::Medium,
                        risk_score: 60.0,
                        evidence_strength: 0.85,
                        pain_level: Some(PainLevel::TTPs),
                        data: obs.data.clone(),
                        created_at: obs.source_timestamp,
                    });
                }
                // Suspicious obfuscated execution
                else if cmd_lower.contains("-enc") || cmd_lower.contains("-encodedcommand") {
                    facts.push(Fact {
                        id: EntityId::new_v7(),
                        case_id: obs.case_id,
                        observation_id: Some(obs.id),
                        assertion_type: AssertionType::Fact,
                        verification_state: VerificationState::Corroborated,
                        entity_type: EntityType::Process,
                        entity_key: format!("proc:obfuscated:{}", obs.id),
                        fact_type: "ObfuscatedExecution".to_string(),
                        confidence: Confidence::new(0.92),
                        severity: Severity::High,
                        risk_score: 80.0,
                        evidence_strength: 0.9,
                        pain_level: Some(PainLevel::Tools),
                        data: obs.data.clone(),
                        created_at: obs.source_timestamp,
                    });
                }
                // Standard process spawn
                else {
                    facts.push(Fact {
                        id: EntityId::new_v7(),
                        case_id: obs.case_id,
                        observation_id: Some(obs.id),
                        assertion_type: AssertionType::Fact,
                        verification_state: VerificationState::Candidate,
                        entity_type: EntityType::Process,
                        entity_key: format!("proc:generic:{}", obs.id),
                        fact_type: "ProcessExecution".to_string(),
                        confidence: Confidence::new(1.0),
                        severity: Severity::Info,
                        risk_score: 10.0,
                        evidence_strength: 1.0,
                        pain_level: Some(PainLevel::HostArtifacts),
                        data: obs.data.clone(),
                        created_at: obs.source_timestamp,
                    });
                }
            }

            // 2. Network socket correlation
            if let Some(dest_ip) = obs.data.get("destination_ip").and_then(|ip| ip.as_str()) {
                let port = obs
                    .data
                    .get("destination_port")
                    .and_then(|p| p.as_u64())
                    .unwrap_or(0);
                facts.push(Fact {
                    id: EntityId::new_v7(),
                    case_id: obs.case_id,
                    observation_id: Some(obs.id),
                    assertion_type: AssertionType::Fact,
                    verification_state: VerificationState::Confirmed,
                    entity_type: EntityType::NetworkSocket,
                    entity_key: format!("{}:{}", dest_ip, port),
                    fact_type: "NetworkConnection".to_string(),
                    confidence: Confidence::new(1.0),
                    severity: if port == 4444 || port == 1337 {
                        Severity::High
                    } else {
                        Severity::Low
                    },
                    risk_score: if port == 4444 { 85.0 } else { 15.0 },
                    evidence_strength: 1.0,
                    pain_level: Some(PainLevel::IpAddresses),
                    data: obs.data.clone(),
                    created_at: obs.source_timestamp,
                });
            }
        }

        Ok(facts)
    }
}

impl Default for DeterministicCorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_dumping_correlation() {
        let engine = DeterministicCorrelationEngine::new();
        let obs = Observation {
            id: EntityId::new_v7(),
            case_id: EntityId::new_v7(),
            artifact_id: None,
            tool_run_id: None,
            source_tool: "evtx_parser".to_string(),
            raw_event_type: "process_create".to_string(),
            source_timestamp: chrono::Utc::now(),
            ingest_timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
                "host_ip": "10.0.0.5"
            }),
        };

        let facts = engine.correlate(&[obs]).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].fact_type, "CredentialAccessAttempt");
        assert_eq!(facts[0].severity, Severity::Critical);
        assert_eq!(facts[0].verification_state, VerificationState::Confirmed);
    }
}
