#![forbid(unsafe_code)]

use crate::types::{
    PortResult, PortState, ScanProfile, ScanTarget, ServiceInfo, ToolRun, TransportProto,
};

#[derive(Debug, thiserror::Error)]
pub enum NmapError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse Error: {0}")]
    Parse(String),
    #[error("Execution failed with code {0}: {1}")]
    ExecutionFailed(i32, String),
}

pub struct NmapAdapter {
    pub nmap_path: std::path::PathBuf,
}

impl NmapAdapter {
    pub fn detect() -> Option<Self> {
        // Look up nmap in PATH or standard Windows locations
        #[cfg(target_os = "windows")]
        let candidates = [
            "nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ];
        #[cfg(not(target_os = "windows"))]
        let candidates = ["nmap", "/usr/bin/nmap", "/usr/local/bin/nmap"];

        for candidate in candidates {
            if let Ok(output) = std::process::Command::new(candidate)
                .arg("--version")
                .output()
            {
                if output.status.success() {
                    return Some(NmapAdapter {
                        nmap_path: std::path::PathBuf::from(candidate),
                    });
                }
            }
        }
        None
    }

    pub async fn run(
        &self,
        target: &ScanTarget,
        profile: &ScanProfile,
    ) -> Result<NmapResult, NmapError> {
        let args = Self::build_args(target, profile);
        let started_at = chrono::Utc::now();

        let output = tokio::process::Command::new(&self.nmap_path)
            .args(&args)
            .output()
            .await?;

        let completed_at = chrono::Utc::now();
        let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
        let stdout_hash = blake3::hash(output.stdout.as_slice()).to_hex().to_string();

        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(NmapError::ExecutionFailed(
                output.status.code().unwrap_or(-1),
                stderr_str,
            ));
        }

        let mut nmap_res = Self::parse_xml(&stdout_str)?;
        nmap_res.tool_run = ToolRun {
            id: uuid::Uuid::now_v7().to_string(),
            tool: "nmap".into(),
            tool_version: "7.x".into(),
            args,
            started_at,
            completed_at: Some(completed_at),
            exit_code: output.status.code(),
            stdout_hash,
        };

        Ok(nmap_res)
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

    pub fn parse_xml(xml: &str) -> Result<NmapResult, NmapError> {
        let mut hosts = Vec::new();

        // Robust token-based XML parser for <host ...> entries
        for host_block in xml.split("<host ").skip(1) {
            let end_idx = host_block.find("</host>").unwrap_or(host_block.len());
            let block = &host_block[..end_idx];

            // Extract IP: <address addr="10.10.20.11" ...
            let ip = if let Some(addr_idx) = block.find("<address ") {
                let rest = &block[addr_idx + 9..];
                let tag_end = rest.find('>').unwrap_or(rest.len());
                match extract_attr(&rest[..tag_end], "addr=") {
                    Some(a) => a,
                    None => continue,
                }
            } else {
                continue;
            };

            // Extract Hostname: <hostname name="DC-LAB.corp.local" ...
            let hostname = if let Some(hn_idx) = block.find("<hostname ") {
                let rest = &block[hn_idx + 10..];
                let tag_end = rest.find('>').unwrap_or(rest.len());
                extract_attr(&rest[..tag_end], "name=")
            } else {
                None
            };

            // Extract Ports: <port protocol="tcp" portid="445">
            let mut ports = Vec::new();
            for port_block in block.split("<port ").skip(1) {
                let p_end = port_block.find("</port>").unwrap_or(port_block.len());
                let pb = &port_block[..p_end];

                let port_id = if let Some(pid_idx) = pb.find("portid=\"") {
                    let rest = &pb[pid_idx + 8..];
                    let q_idx = rest.find('"').unwrap_or(0);
                    rest[..q_idx].parse::<u16>().unwrap_or(0)
                } else {
                    0
                };

                if port_id == 0 {
                    continue;
                }

                let state = if pb.contains("state=\"open\"") {
                    PortState::Open
                } else if pb.contains("state=\"closed\"") {
                    PortState::Closed
                } else if pb.contains("state=\"filtered\"") {
                    PortState::Filtered
                } else {
                    PortState::Unknown
                };

                // Service info
                let service = if let Some(svc_idx) = pb.find("<service ") {
                    let rest = &pb[svc_idx + 9..];
                    let s_end = rest.find('>').unwrap_or(rest.len());
                    let sb = &rest[..s_end];

                    let s_name = extract_attr(sb, "name=").unwrap_or_else(|| "unknown".to_string());
                    let s_prod = extract_attr(sb, "product=");
                    let s_ver = extract_attr(sb, "version=");

                    let version = match (s_prod, s_ver) {
                        (Some(p), Some(v)) => Some(format!("{} {}", p, v)),
                        (Some(p), None) => Some(p),
                        (None, Some(v)) => Some(v),
                        (None, None) => None,
                    };

                    Some(ServiceInfo {
                        name: s_name,
                        version,
                        banner: None,
                        extra: serde_json::Value::Null,
                        confidence: 0.95,
                        method: "nmap-sV".into(),
                    })
                } else {
                    None
                };

                ports.push(PortResult {
                    port: port_id,
                    protocol: TransportProto::Tcp,
                    state,
                    service,
                });
            }

            hosts.push(NmapHost {
                ip,
                hostname,
                ports,
            });
        }

        Ok(NmapResult {
            hosts,
            tool_run: ToolRun {
                id: "nmap-xml".into(),
                tool: "nmap".into(),
                tool_version: "7.x".into(),
                args: vec![],
                started_at: chrono::Utc::now(),
                completed_at: Some(chrono::Utc::now()),
                exit_code: Some(0),
                stdout_hash: "".into(),
            },
        })
    }
}

fn extract_attr(text: &str, attr: &str) -> Option<String> {
    let idx = text.find(attr)?;
    let rest = &text[idx + attr.len()..];
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let after_q = &rest[1..];
    let end_q = after_q.find(quote)?;
    Some(after_q[..end_q].to_string())
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
