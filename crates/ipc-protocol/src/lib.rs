#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use serde::{Deserialize, Serialize};

pub const IPC_API_VERSION: u32 = 1;

/// RFC 7807 Compliant Problem Details for API Errors
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub instance: Option<String>,
    pub invalid_params: Vec<String>,
}

impl ProblemDetails {
    pub fn bad_request(detail: &str, invalid_params: Vec<String>) -> Self {
        Self {
            type_uri: "https://soc-dfir.local/errors/bad-request".to_string(),
            title: "Bad Request".to_string(),
            status: 400,
            detail: detail.to_string(),
            instance: None,
            invalid_params,
        }
    }

    pub fn not_found(detail: &str) -> Self {
        Self {
            type_uri: "https://soc-dfir.local/errors/not-found".to_string(),
            title: "Not Found".to_string(),
            status: 404,
            detail: detail.to_string(),
            instance: None,
            invalid_params: Vec::new(),
        }
    }

    pub fn forbidden(detail: &str) -> Self {
        Self {
            type_uri: "https://soc-dfir.local/errors/forbidden".to_string(),
            title: "Forbidden".to_string(),
            status: 403,
            detail: detail.to_string(),
            instance: None,
            invalid_params: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub live: bool,
    pub ready: bool,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest<T> {
    pub api_version: u32,
    pub request_id: String,
    pub case_id: Option<EntityId>,
    pub method: String,
    pub params: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse<T> {
    pub api_version: u32,
    pub request_id: String,
    pub result: Option<T>,
    pub error: Option<ProblemDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaseParams {
    pub title: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestArtifactParams {
    pub file_path: String,
    pub original_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryGraphParams {
    pub lod_level: u8,
    pub cursor: Option<String>,
    pub limit: usize,
}

pub struct ApiDispatcher;

impl ApiDispatcher {
    pub fn handle_health() -> HealthStatus {
        HealthStatus {
            live: true,
            ready: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn validate_version(api_version: u32) -> Result<(), ProblemDetails> {
        if api_version != IPC_API_VERSION {
            return Err(ProblemDetails::bad_request(
                &format!(
                    "Unsupported API version: expected {}, got {}",
                    IPC_API_VERSION, api_version
                ),
                vec!["api_version".to_string()],
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc7807_problem_details_formatting() {
        let err =
            ProblemDetails::bad_request("Invalid file path format", vec!["file_path".to_string()]);
        assert_eq!(err.status, 400);
        assert_eq!(err.title, "Bad Request");
        assert_eq!(err.invalid_params, vec!["file_path"]);

        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("type"));
        assert!(json.contains("invalid_params"));
    }

    #[test]
    fn test_api_version_validation() {
        assert!(ApiDispatcher::validate_version(1).is_ok());
        let err = ApiDispatcher::validate_version(2).unwrap_err();
        assert_eq!(err.status, 400);
    }
}
