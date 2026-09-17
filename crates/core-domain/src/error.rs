use thiserror::Error;

#[derive(Error, Debug)]
pub enum DomainError {
    #[error("Entity not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Integrity error: hash mismatch for artifact {0}")]
    HashMismatch(String),

    #[error("Privilege violation: capability {0:?} is required")]
    PrivilegeViolation(crate::broker::BrokerCapability),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    InternalError(String),
}
