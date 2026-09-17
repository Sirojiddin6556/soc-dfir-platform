use crate::id::EntityId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: EntityId,
    pub case_id: EntityId,
    pub hash_blake3: String, // 64 hex characters (internal CAS locator)
    pub hash_sha256: String, // 64 hex characters (forensic/IOC standard)
    pub original_name: String,
    pub file_size: u64,
    pub mime_type: String,
    pub acquisition_method: String,
    pub acquired_at: DateTime<Utc>,
    pub ingested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CustodyEventType {
    ArtifactAcquired,
    ArtifactStored,
    ArtifactHashed,
    ArtifactParsed,
    ArtifactAccessed,
    ArtifactExported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEvent {
    pub id: EntityId,
    pub case_id: EntityId,
    pub actor_id: String,
    pub event_type: CustodyEventType,
    pub artifact_hash: Option<String>,
    pub details_json: String,
    pub previous_state_hash: String, // Merkle chain backlink
    pub timestamp: DateTime<Utc>,
}
