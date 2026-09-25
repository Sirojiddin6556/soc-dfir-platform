#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use serde::{Deserialize, Serialize};

pub mod ctf_dto;
pub mod events;
pub mod jsonrpc;

pub use ctf_dto::*;
pub use events::*;
pub use jsonrpc::*;

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

    pub fn unauthorized(detail: &str) -> Self {
        Self {
            type_uri: "https://soc-dfir.local/errors/unauthorized".to_string(),
            title: "Unauthorized".to_string(),
            status: 401,
            detail: detail.to_string(),
            instance: None,
            invalid_params: Vec::new(),
        }
    }

    pub fn conflict(detail: &str) -> Self {
        Self {
            type_uri: "https://soc-dfir.local/errors/conflict".to_string(),
            title: "Conflict".to_string(),
            status: 409,
            detail: detail.to_string(),
            instance: None,
            invalid_params: Vec::new(),
        }
    }

    pub fn internal_error(detail: &str) -> Self {
        Self {
            type_uri: "https://soc-dfir.local/errors/internal-error".to_string(),
            title: "Internal Server Error".to_string(),
            status: 500,
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

pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB max frame safety limit

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum FrameError {
    #[error("Frame size ({0} bytes) exceeds maximum limit of {MAX_FRAME_SIZE} bytes")]
    FrameTooLarge(usize),

    #[error("Malformed frame: {0}")]
    Malformed(String),
}

/// Length-prefixed binary frame codec: [u32 big-endian payload_length (4 bytes)] [payload bytes]
pub struct FrameCodec;

impl FrameCodec {
    /// Encodes a raw byte payload into a length-prefixed frame
    pub fn encode(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        let len = payload.len();
        if len > MAX_FRAME_SIZE {
            return Err(FrameError::FrameTooLarge(len));
        }

        let mut frame = Vec::with_capacity(4 + len);
        frame.extend_from_slice(&(len as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        Ok(frame)
    }

    /// Attempts to extract the next frame from an incoming byte buffer.
    /// Returns Ok(Some(payload)) if a full frame is present, Ok(None) if partial.
    pub fn decode(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, FrameError> {
        if buffer.len() < 4 {
            return Ok(None);
        }

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&buffer[..4]);
        let payload_len = u32::from_be_bytes(len_bytes) as usize;

        if payload_len > MAX_FRAME_SIZE {
            return Err(FrameError::FrameTooLarge(payload_len));
        }

        let total_frame_len = 4 + payload_len;
        if buffer.len() < total_frame_len {
            return Ok(None);
        }

        let payload = buffer[4..total_frame_len].to_vec();
        buffer.drain(..total_frame_len);
        Ok(Some(payload))
    }

    /// Encodes a typed value to JSON within a length-prefixed frame
    pub fn encode_json<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
        let json_bytes =
            serde_json::to_vec(value).map_err(|e| FrameError::Malformed(e.to_string()))?;
        Self::encode(&json_bytes)
    }

    /// Decodes a typed value from JSON if a complete frame is available in the buffer
    pub fn decode_json<T: for<'de> Deserialize<'de>>(
        buffer: &mut Vec<u8>,
    ) -> Result<Option<T>, FrameError> {
        match Self::decode(buffer)? {
            Some(bytes) => {
                let value = serde_json::from_slice(&bytes)
                    .map_err(|e| FrameError::Malformed(e.to_string()))?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
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

    #[test]
    fn test_frame_codec_roundtrip() {
        let message = b"HELLO_SOC_DFIR_IPC";
        let frame = FrameCodec::encode(message).unwrap();
        assert_eq!(frame.len(), 4 + message.len());

        let mut buffer = frame;
        let decoded = FrameCodec::decode(&mut buffer).unwrap().unwrap();
        assert_eq!(decoded, message);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_frame_codec_partial_buffer() {
        let message = b"PARTIAL_FRAME_TEST";
        let frame = FrameCodec::encode(message).unwrap();

        // Feed only first 5 bytes (4 length bytes + 1 data byte)
        let mut buffer = frame[..5].to_vec();
        assert_eq!(FrameCodec::decode(&mut buffer).unwrap(), None);

        // Append the rest of the frame
        buffer.extend_from_slice(&frame[5..]);
        let decoded = FrameCodec::decode(&mut buffer).unwrap().unwrap();
        assert_eq!(decoded, message);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_frame_codec_json_typed() {
        let req = IpcRequest {
            api_version: 1,
            request_id: "req-123".to_string(),
            case_id: None,
            method: "case.create".to_string(),
            params: CreateCaseParams {
                title: "Incident Beta".to_string(),
                description: Some("Description".to_string()),
            },
        };

        let mut buffer = FrameCodec::encode_json(&req).unwrap();
        let decoded: IpcRequest<CreateCaseParams> =
            FrameCodec::decode_json(&mut buffer).unwrap().unwrap();

        assert_eq!(decoded.request_id, "req-123");
        assert_eq!(decoded.params.title, "Incident Beta");
        assert!(buffer.is_empty());
    }
}
