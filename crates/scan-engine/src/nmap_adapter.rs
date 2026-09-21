#![forbid(unsafe_code)]

use crate::types::{PortResult, ScanProfile, ScanTarget, ToolRun};

#[derive(Debug, thiserror::Error)]
pub enum NmapError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse Error: {0}")]
    Parse(String),
}

pub struct NmapAdapter {
    #[allow(dead_code)]
    nmap_path: std::path::PathBuf,
}

impl NmapAdapter {
    pub fn detect() -> Option<Self> {
        None
    }

    pub async fn run(
        &self,
        _target: &ScanTarget,
        _profile: &ScanProfile,
    ) -> Result<NmapResult, NmapError> {
        Ok(NmapResult {
            hosts: vec![],
            tool_run: ToolRun {
                id: "nmap-1".into(),
                tool: "nmap".into(),
                tool_version: "unknown".into(),
                args: vec![],
                started_at: chrono::Utc::now(),
                completed_at: Some(chrono::Utc::now()),
                exit_code: Some(0),
                stdout_hash: "".into(),
            },
        })
    }

    pub fn build_args(target: &ScanTarget, profile: &ScanProfile) -> Vec<String> {
        let mut args = vec!["-T4".to_string()];
        match profile {
            ScanProfile::Quick => {
                args.extend_from_slice(&["-F".to_string(), "--open".to_string()]);
            }
            ScanProfile::Standard => {
                args.extend_from_slice(&[
                    "--top-ports".to_string(),
                    "1000".to_string(),
                    "-sV".to_string(),
                    "--open".to_string(),
                ]);
            }
            ScanProfile::Deep => {
                args.extend_from_slice(&[
                    "-p-".to_string(),
                    "-sV".to_string(),
                    "-sC".to_string(),
                    "--open".to_string(),
                ]);
            }
        }
        args.extend_from_slice(&["-oX".to_string(), "-".to_string()]);
        match target {
            ScanTarget::SingleIp(ip) => args.push(ip.to_string()),
            ScanTarget::Cidr { base, prefix_len } => args.push(format!("{}/{}", base, prefix_len)),
            ScanTarget::Range { start, end } => args.push(format!("{}-{}", start, end)),
            ScanTarget::Hostname(h) => args.push(h.clone()),
        }
        args
    }

    pub fn parse_xml(_xml: &str) -> Result<NmapResult, NmapError> {
        Ok(NmapResult {
            hosts: vec![],
            tool_run: ToolRun {
                id: "nmap-1".into(),
                tool: "nmap".into(),
                tool_version: "unknown".into(),
                args: vec![],
                started_at: chrono::Utc::now(),
                completed_at: Some(chrono::Utc::now()),
                exit_code: Some(0),
                stdout_hash: "".into(),
            },
        })
    }
}

pub struct NmapResult {
    pub hosts: Vec<NmapHost>,
    pub tool_run: ToolRun,
}

pub struct NmapHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub ports: Vec<PortResult>,
}
