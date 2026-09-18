#![forbid(unsafe_code)]

pub mod artifact;
pub mod audit;
pub mod broker;
pub mod case;
pub mod collaboration;
pub mod epistemic;
pub mod error;
pub mod evidence;
pub mod fact;
pub mod graph;
pub mod id;
pub mod observation;
pub mod scenario;
pub mod taxonomy;
pub mod workflow;

// Re-exports of foundational domain types
pub use artifact::{Artifact, CustodyEvent, CustodyEventType};
pub use audit::AuditEvent;
pub use broker::{BrokerCapability, PrivilegedOperation};
pub use case::Case;
pub use collaboration::{
    Channel, ChannelType, ChatMessage, CollabNotification, EntityRef, Permission, ReferenceType,
    Role, Team, TeamMember, User, UserPresence, UserSession, Workspace,
};
pub use epistemic::{AssertionType, Confidence, PainLevel, Severity, VerificationState};
pub use error::DomainError;
pub use evidence::{Evidence, EvidenceMember};
pub use fact::{EntityType, Fact};
pub use graph::{AttackEdge, AttackGraph, AttackNode, GraphDelta};
pub use id::EntityId;
pub use observation::{Observation, RawToolResult, ToolRun};
pub use scenario::{GroundTruth, ScenarioManifest, VerificationReport};
pub use taxonomy::{TaxonomyCandidate, TaxonomyMapping, TaxonomyNamespace, TaxonomyVersion};
pub use workflow::{
    ConditionalEdge, ResourceBudget, TaskStatus, WorkflowProfileType, WorkflowTask,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entity_id_ordering_v7() {
        let id1 = EntityId::new_v7();
        let id2 = EntityId::new_v7();
        assert!(id1 <= id2);
    }

    #[test]
    fn test_epistemic_invariants() {
        let fact = Fact {
            id: EntityId::new_v7(),
            case_id: EntityId::new_v7(),
            evidence_ids: vec![EntityId::new_v7(), EntityId::new_v7()],
            assertion_type: AssertionType::Fact,
            verification_state: VerificationState::Confirmed,
            entity_type: EntityType::Process,
            entity_key: "host1:1234".to_string(),
            fact_type: "ProcessSpawn".to_string(),
            confidence: Confidence::new(0.95),
            severity: Severity::High,
            risk_score: 75.0,
            evidence_strength: 0.9,
            pain_level: Some(PainLevel::Tools),
            data: serde_json::json!({"cmd": "powershell.exe -enc ..."}),
            created_at: chrono::Utc::now(),
        };

        assert_eq!(fact.assertion_type, AssertionType::Fact);
        assert_eq!(fact.verification_state, VerificationState::Confirmed);
    }
}
