use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("Entity not found: {entity} with id {id}")]
    NotFound { entity: &'static str, id: String },

    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("Storage failure: {0}")]
    Storage(String),

    #[error("Execution failed: {0}")]
    Execution(String),

    #[error("Conflict: {0}")]
    Conflict(String),
}

impl DomainError {
    pub fn not_found(entity: &'static str, id: impl Into<String>) -> Self {
        Self::NotFound {
            entity,
            id: id.into(),
        }
    }

    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    pub fn security(msg: impl Into<String>) -> Self {
        Self::SecurityViolation(msg.into())
    }

    pub fn resource_limit(msg: impl Into<String>) -> Self {
        Self::ResourceLimit(msg.into())
    }

    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }

    pub fn execution(msg: impl Into<String>) -> Self {
        Self::Execution(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }
}

impl From<serde_json::Error> for DomainError {
    fn from(err: serde_json::Error) -> Self {
        DomainError::Storage(format!("JSON serialization error: {}", err))
    }
}

impl From<std::io::Error> for DomainError {
    fn from(err: std::io::Error) -> Self {
        DomainError::Storage(format!("IO error: {}", err))
    }
}
