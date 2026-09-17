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
        use std::collections::HashMap;

        let mut facts: Vec<Fact> = Vec::new();
        let mut fact_indices: HashMap<(EntityId, EntityType, String, String), usize> =
            HashMap::new();

        for obs in observations {
            let mut candidate_facts = Vec::new();

            // 1. Process execution correlation
            if let Some(cmd) = obs.data.get("command_line").and_then(|c| c.as_str()) {
                let cmd_lower = cmd.to_lowercase();
                let host = obs
                    .data
                    .get("host_ip")
                    .or_else(|| obs.data.get("host"))
                    .and_then(|h| h.as_str())
                    .unwrap_or("localhost");

                if cmd_lower.contains("mimikatz")
                    || cmd_lower.contains("procdump")
                    || cmd_lower.contains("comsvcs.dll")
                {
                    candidate_facts.push((
                        EntityType::Process,
                        format!("{}:proc:cred_dump", host),
                        "CredentialAccessAttempt".to_string(),
                        Confidence::new(0.90),
                        Severity::Critical,
                        95.0,
                        Some(PainLevel::Tools),
                    ));
                } else if cmd_lower.contains("schtasks") && cmd_lower.contains("/create") {
                    candidate_facts.push((
                        EntityType::Process,
                        format!("{}:proc:persist:schtasks", host),
                        "ScheduledTaskPersistence".to_string(),
                        Confidence::new(0.85),
                        Severity::High,
                        85.0,
                        Some(PainLevel::TTPs),
                    ));
                } else if cmd_lower.contains("whoami")
                    || cmd_lower.contains("net user")
                    || cmd_lower.contains("nltest")
                {
                    candidate_facts.push((
                        EntityType::Process,
                        format!("{}:proc:recon", host),
                        "DiscoveryReconnaissance".to_string(),
                        Confidence::new(0.75),
                        Severity::Medium,
                        60.0,
                        Some(PainLevel::TTPs),
                    ));
                } else if cmd_lower.contains("-enc") || cmd_lower.contains("-encodedcommand") {
                    candidate_facts.push((
                        EntityType::Process,
                        format!("{}:proc:obfuscated", host),
                        "ObfuscatedExecution".to_string(),
                        Confidence::new(0.80),
                        Severity::High,
                        80.0,
                        Some(PainLevel::Tools),
                    ));
                } else {
                    let proc_name = obs
                        .data
                        .get("process_name")
                        .and_then(|p| p.as_str())
                        .unwrap_or("process");
                    candidate_facts.push((
                        EntityType::Process,
                        format!("{}:proc:{}", host, proc_name),
                        "ProcessExecution".to_string(),
                        Confidence::new(0.70),
                        Severity::Info,
                        10.0,
                        Some(PainLevel::HostArtifacts),
                    ));
                }
            }

            // 2. Network socket correlation
            if let Some(dest_ip) = obs.data.get("destination_ip").and_then(|ip| ip.as_str()) {
                let port = obs
                    .data
                    .get("destination_port")
                    .and_then(|p| p.as_u64())
                    .unwrap_or(0);
                let (sev, risk) = if port == 4444 || port == 1337 {
                    (Severity::High, 85.0)
                } else {
                    (Severity::Low, 15.0)
                };
                candidate_facts.push((
                    EntityType::NetworkSocket,
                    format!("{}:{}", dest_ip, port),
                    "NetworkConnection".to_string(),
                    Confidence::new(0.80),
                    sev,
                    risk,
                    Some(PainLevel::IpAddresses),
                ));
            }

            // Aggregate candidate facts into facts vector
            for (ent_type, ent_key, fact_type, conf, sev, risk, pain) in candidate_facts {
                let lookup_key = (obs.case_id, ent_type, ent_key.clone(), fact_type.clone());

                if let Some(&idx) = fact_indices.get(&lookup_key) {
                    let fact = &mut facts[idx];
                    if !fact.evidence_ids.contains(&obs.id) {
                        fact.evidence_ids.push(obs.id);
                    }
                    if fact.evidence_ids.len() >= 3 {
                        fact.verification_state = VerificationState::Confirmed;
                        fact.confidence = Confidence::new((fact.confidence.value() + 0.1).min(1.0));
                        fact.evidence_strength = (fact.evidence_strength + 0.2).min(1.0);
                    } else if fact.evidence_ids.len() >= 2 {
                        fact.verification_state = VerificationState::Corroborated;
                        fact.confidence =
                            Confidence::new((fact.confidence.value() + 0.08).min(1.0));
                        fact.evidence_strength = (fact.evidence_strength + 0.15).min(1.0);
                    }
                    if obs.source_timestamp < fact.created_at {
                        fact.created_at = obs.source_timestamp;
                    }
                } else {
                    let idx = facts.len();
                    fact_indices.insert(lookup_key, idx);
                    facts.push(Fact {
                        id: EntityId::new_v7(),
                        case_id: obs.case_id,
                        evidence_ids: vec![obs.id],
                        assertion_type: AssertionType::Fact,
                        verification_state: VerificationState::Candidate,
                        entity_type: ent_type,
                        entity_key: ent_key,
                        fact_type,
                        confidence: conf,
                        severity: sev,
                        risk_score: risk,
                        evidence_strength: 0.5,
                        pain_level: pain,
                        data: obs.data.clone(),
                        created_at: obs.source_timestamp,
                    });
                }
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
        let case_id = EntityId::new_v7();
        let obs1 = Observation {
            id: EntityId::new_v7(),
            case_id,
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

        // Single observation -> Candidate state
        let facts1 = engine.correlate(std::slice::from_ref(&obs1)).unwrap();
        assert_eq!(facts1.len(), 1);
        assert_eq!(facts1[0].fact_type, "CredentialAccessAttempt");
        assert_eq!(facts1[0].severity, Severity::Critical);
        assert_eq!(facts1[0].evidence_ids.len(), 1);
        assert_eq!(facts1[0].verification_state, VerificationState::Candidate);

        // Second observation of the same credential dumping -> Corroborated state
        let obs2 = Observation {
            id: EntityId::new_v7(),
            case_id,
            artifact_id: None,
            tool_run_id: None,
            source_tool: "sysmon_parser".to_string(),
            raw_event_type: "process_create".to_string(),
            source_timestamp: chrono::Utc::now(),
            ingest_timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
                "host_ip": "10.0.0.5"
            }),
        };

        let facts2 = engine.correlate(&[obs1, obs2]).unwrap();
        assert_eq!(facts2.len(), 1);
        assert_eq!(facts2[0].evidence_ids.len(), 2);
        assert_eq!(
            facts2[0].verification_state,
            VerificationState::Corroborated
        );
        assert!(facts2[0].is_corroborated());
    }
}
