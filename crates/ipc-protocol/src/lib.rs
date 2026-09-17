#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use serde::{Deserialize, Serialize};

pub const IPC_API_VERSION: u32 = 1;

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
    pub error: Option<IpcErrorPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcErrorPayload {
    pub code: i32,
    pub message: String,
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
