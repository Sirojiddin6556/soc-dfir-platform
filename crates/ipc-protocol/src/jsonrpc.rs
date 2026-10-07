#![forbid(unsafe_code)]

use core_domain::error::DomainError;
use serde::{Deserialize, Serialize};

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

pub const SECURITY_VIOLATION: i32 = -32001;
pub const RESOURCE_EXHAUSTED: i32 = -32002;
pub const EXECUTION_FAILED: i32 = -32003;
pub const ENTITY_NOT_FOUND: i32 = -32004;
pub const CONFLICT_STATE: i32 = -32005;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcRequest<T> {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    pub params: T,
}

impl<T> JsonRpcRequest<T> {
    pub fn new(id: serde_json::Value, method: impl Into<String>, params: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcNotification<T> {
    pub jsonrpc: String,
    pub method: String,
    pub params: T,
}

impl<T> JsonRpcNotification<T> {
    pub fn new(method: impl Into<String>, params: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(code: i32, message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self::new(PARSE_ERROR, msg)
    }

    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(INVALID_REQUEST, msg)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("Method not found: {method}"))
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, msg)
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, msg)
    }

    pub fn security_violation(msg: impl Into<String>) -> Self {
        Self::new(SECURITY_VIOLATION, msg)
    }

    pub fn resource_exhausted(msg: impl Into<String>) -> Self {
        Self::new(RESOURCE_EXHAUSTED, msg)
    }

    pub fn entity_not_found(msg: impl Into<String>) -> Self {
        Self::new(ENTITY_NOT_FOUND, msg)
    }

    pub fn conflict_state(msg: impl Into<String>) -> Self {
        Self::new(CONFLICT_STATE, msg)
    }
}

impl From<DomainError> for JsonRpcError {
    fn from(err: DomainError) -> Self {
        match err {
            DomainError::NotFound {
                entity: "Method",
                id,
            } => Self::new(METHOD_NOT_FOUND, format!("Method not found: {id}")),
            DomainError::NotFound { entity, id } => Self::new(
                ENTITY_NOT_FOUND,
                format!("Entity not found: {entity} with id {id}"),
            ),
            DomainError::Validation(msg) => Self::new(INVALID_PARAMS, msg),
            DomainError::SecurityViolation(msg) => Self::new(SECURITY_VIOLATION, msg),
            DomainError::ResourceLimit(msg) => Self::new(RESOURCE_EXHAUSTED, msg),
            DomainError::Execution(msg) => Self::new(EXECUTION_FAILED, msg),
            DomainError::Conflict(msg) => Self::new(CONFLICT_STATE, msg),
            DomainError::Storage(msg) => {
                Self::new(INTERNAL_ERROR, format!("Storage failure: {msg}"))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcResponse<T> {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl<T> JsonRpcResponse<T> {
    pub fn ok(id: serde_json::Value, result: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: serde_json::Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

pub fn domain_error_to_problem_details(err: &DomainError) -> crate::ProblemDetails {
    match err {
        DomainError::NotFound { entity, id } => {
            crate::ProblemDetails::not_found(&format!("Entity not found: {entity} with id {id}"))
        }
        DomainError::Validation(msg) => crate::ProblemDetails::bad_request(msg, vec![]),
        DomainError::SecurityViolation(msg) => crate::ProblemDetails::forbidden(msg),
        DomainError::ResourceLimit(msg) => crate::ProblemDetails {
            type_uri: "https://soc-dfir.local/errors/resource-exhausted".to_string(),
            title: "Resource Limit Exceeded".to_string(),
            status: 429,
            detail: msg.clone(),
            instance: None,
            invalid_params: vec![],
        },
        DomainError::Conflict(msg) => crate::ProblemDetails::conflict(msg),
        DomainError::Execution(msg) | DomainError::Storage(msg) => {
            crate::ProblemDetails::internal_error(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jsonrpc_success_roundtrip() {
        let req = JsonRpcRequest::new(
            serde_json::json!(1),
            "competitions.get",
            serde_json::json!({ "id": "comp-123" }),
        );
        let req_json = serde_json::to_string(&req).unwrap();
        let parsed: JsonRpcRequest<serde_json::Value> = serde_json::from_str(&req_json).unwrap();
        assert_eq!(parsed.jsonrpc, "2.0");
        assert_eq!(parsed.method, "competitions.get");

        let resp = JsonRpcResponse::ok(parsed.id, serde_json::json!({ "name": "CTF 2026" }));
        let resp_json = serde_json::to_string(&resp).unwrap();
        assert!(resp_json.contains("\"result\":{\"name\":\"CTF 2026\"}"));
        assert!(!resp_json.contains("\"error\""));
    }

    #[test]
    fn test_domain_error_mapping() {
        let not_found = DomainError::not_found("Challenge", "chal-01");
        let rpc_err: JsonRpcError = not_found.into();
        assert_eq!(rpc_err.code, ENTITY_NOT_FOUND);

        let sec = DomainError::security("Shell injection attempt");
        let rpc_err: JsonRpcError = sec.into();
        assert_eq!(rpc_err.code, SECURITY_VIOLATION);

        let limit = DomainError::ResourceLimit("Zip bomb limit exceeded".into());
        let rpc_err: JsonRpcError = limit.into();
        assert_eq!(rpc_err.code, RESOURCE_EXHAUSTED);

        let conflict = DomainError::conflict("Cannot transition from Solved");
        let rpc_err: JsonRpcError = conflict.into();
        assert_eq!(rpc_err.code, CONFLICT_STATE);

        let val = DomainError::Validation("Name is required".into());
        let rpc_err: JsonRpcError = val.into();
        assert_eq!(rpc_err.code, INVALID_PARAMS);
    }
}
