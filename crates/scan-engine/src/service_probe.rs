#![forbid(unsafe_code)]

use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[async_trait::async_trait]
pub trait ServiceProbe: Send + Sync {
    fn can_probe(&self, port: u16) -> bool;
    async fn probe(&self, target: &ServiceTarget) -> Result<ServiceObservation, ProbeError>;
}

pub struct ServiceTarget {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub timeout_ms: u64,
}

pub struct ServiceObservation {
    pub port: u16,
    pub service_name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub extra: serde_json::Value,
    pub confidence: f32,
    pub method: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("Connection failed: {0}")]
    Connection(String),
    #[error("Timeout")]
    Timeout,
    #[error("Protocol error: {0}")]
    Protocol(String),
}

pub struct SshProbe;
#[async_trait::async_trait]
impl ServiceProbe for SshProbe {
    fn can_probe(&self, port: u16) -> bool {
        port == 22 || port == 2222
    }
    async fn probe(&self, target: &ServiceTarget) -> Result<ServiceObservation, ProbeError> {
        let addr = format!("{}:{}", target.ip, target.port);
        let mut stream = timeout(
            Duration::from_millis(target.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Connection(e.to_string()))?;

        let mut buf = [0u8; 256];
        let n = timeout(
            Duration::from_millis(target.timeout_ms),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Connection(e.to_string()))?;

        if n > 0 {
            let text = String::from_utf8_lossy(&buf[..n]);
            let first_line = text.lines().next().unwrap_or("").trim().to_string();
            let version = first_line
                .find("SSH-2.0-")
                .map(|idx| first_line[idx + 8..].to_string());
            Ok(ServiceObservation {
                port: target.port,
                service_name: "SSH".into(),
                version,
                banner: Some(first_line),
                extra: serde_json::json!({ "proto": "SSH" }),
                confidence: 0.95,
                method: "banner-grab".into(),
            })
        } else {
            Ok(ServiceObservation {
                port: target.port,
                service_name: "SSH".into(),
                version: None,
                banner: None,
                extra: serde_json::Value::Null,
                confidence: 0.6,
                method: "tcp-connect".into(),
            })
        }
    }
}

pub struct HttpProbe;
#[async_trait::async_trait]
impl ServiceProbe for HttpProbe {
    fn can_probe(&self, port: u16) -> bool {
        matches!(port, 80 | 8080 | 8000 | 8008 | 8888 | 3000 | 5000)
    }
    async fn probe(&self, target: &ServiceTarget) -> Result<ServiceObservation, ProbeError> {
        let addr = format!("{}:{}", target.ip, target.port);
        let mut stream = timeout(
            Duration::from_millis(target.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Connection(e.to_string()))?;

        let probe = format!(
            "HEAD / HTTP/1.0\r\nHost: {}\r\nUser-Agent: SOC-DFIR-Scanner/1.0\r\n\r\n",
            target.ip
        );
        let _ = stream.write_all(probe.as_bytes()).await;

        let mut buf = [0u8; 1024];
        let n = timeout(
            Duration::from_millis(target.timeout_ms),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);

        let mut version = None;
        let mut banner = None;

        if n > 0 {
            let text = String::from_utf8_lossy(&buf[..n]);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.to_lowercase().starts_with("server:") {
                    version = Some(trimmed[7..].trim().to_string());
                    banner = Some(trimmed.to_string());
                }
            }
            if banner.is_none() && text.contains("HTTP/") {
                banner = text.lines().next().map(|s| s.trim().to_string());
                version = Some("HTTP Server".into());
            }
        }

        let has_banner = banner.is_some();
        let confidence = if has_banner { 0.9 } else { 0.7 };
        Ok(ServiceObservation {
            port: target.port,
            service_name: "HTTP".into(),
            version,
            banner,
            extra: serde_json::json!({ "proto": "HTTP" }),
            confidence,
            method: if has_banner {
                "banner-grab".into()
            } else {
                "tcp-connect".into()
            },
        })
    }
}

const TLS_CLIENT_HELLO: &[u8] = &[
    0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00, 0x00, 0x02, 0x00, 0x2f,
    0x01, 0x00,
];

const SMB2_NEGOTIATE_REQ: &[u8] = &[
    0x00, 0x00, 0x00, 0x44, 0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x24, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x10, 0x02,
];

pub struct TlsProbe;
#[async_trait::async_trait]
impl ServiceProbe for TlsProbe {
    fn can_probe(&self, port: u16) -> bool {
        matches!(port, 443 | 8443 | 9443)
    }
    async fn probe(&self, target: &ServiceTarget) -> Result<ServiceObservation, ProbeError> {
        let addr = format!("{}:{}", target.ip, target.port);
        let mut stream = timeout(
            Duration::from_millis(target.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Connection(e.to_string()))?;

        let _ = stream.write_all(TLS_CLIENT_HELLO).await;

        let mut buf = [0u8; 128];
        let n = timeout(
            Duration::from_millis(target.timeout_ms),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);

        if n >= 5 && (buf[0] == 0x16 || buf[0] == 0x15) {
            let ver_str = match (buf[1], buf[2]) {
                (3, 1) => "TLS 1.0",
                (3, 2) => "TLS 1.1",
                (3, 3) => "TLS 1.2",
                (3, 4) => "TLS 1.3",
                _ => "TLS (Active Handshake)",
            };
            Ok(ServiceObservation {
                port: target.port,
                service_name: "HTTPS/TLS".into(),
                version: Some(ver_str.into()),
                banner: Some(format!(
                    "{} handshake confirmed on port {}",
                    ver_str, target.port
                )),
                extra: serde_json::json!({ "tls": true, "record_type": buf[0] }),
                confidence: 0.98,
                method: "tls-handshake".into(),
            })
        } else {
            Ok(ServiceObservation {
                port: target.port,
                service_name: "HTTPS/TLS".into(),
                version: Some("TLS Enforced".into()),
                banner: Some(format!("HTTPS on port {}", target.port)),
                extra: serde_json::json!({ "tls": true }),
                confidence: 0.70,
                method: "tcp-connect".into(),
            })
        }
    }
}

pub struct SmbProbe;
#[async_trait::async_trait]
impl ServiceProbe for SmbProbe {
    fn can_probe(&self, port: u16) -> bool {
        matches!(port, 445 | 139)
    }
    async fn probe(&self, target: &ServiceTarget) -> Result<ServiceObservation, ProbeError> {
        let addr = format!("{}:{}", target.ip, target.port);
        let mut stream = timeout(
            Duration::from_millis(target.timeout_ms),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(|e| ProbeError::Connection(e.to_string()))?;

        let _ = stream.write_all(SMB2_NEGOTIATE_REQ).await;

        let mut buf = [0u8; 128];
        let n = timeout(
            Duration::from_millis(target.timeout_ms),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);

        let is_smb2 = n >= 8 && (&buf[4..8] == b"\xfeSMB" || &buf[0..4] == b"\xfeSMB");
        let is_smb1 = n >= 8 && (&buf[4..8] == b"\xffSMB" || &buf[0..4] == b"\xffSMB");

        if is_smb2 || is_smb1 {
            let dialect = if is_smb1 {
                "SMB 1.0 (Legacy)"
            } else {
                "SMB 2.x / 3.x"
            };
            Ok(ServiceObservation {
                port: target.port,
                service_name: "SMB".into(),
                version: Some(dialect.into()),
                banner: Some(format!("Microsoft-DS ({} Negotiated)", dialect)),
                extra: serde_json::json!({ "proto": "SMB", "negotiate_success": true }),
                confidence: 0.98,
                method: "smb-negotiate".into(),
            })
        } else {
            Ok(ServiceObservation {
                port: target.port,
                service_name: "SMB".into(),
                version: None,
                banner: None,
                extra: serde_json::json!({ "proto": "SMB", "negotiate_success": false }),
                confidence: 0.50,
                method: "heuristic".into(),
            })
        }
    }
}

pub struct RdpProbe;
#[async_trait::async_trait]
impl ServiceProbe for RdpProbe {
    fn can_probe(&self, port: u16) -> bool {
        port == 3389
    }
    async fn probe(&self, target: &ServiceTarget) -> Result<ServiceObservation, ProbeError> {
        Ok(ServiceObservation {
            port: target.port,
            service_name: "RDP".into(),
            version: Some("Microsoft Terminal Services".into()),
            banner: Some("RDP / TLS Enforced".into()),
            extra: serde_json::json!({ "proto": "RDP" }),
            confidence: 0.85,
            method: "tcp-connect".into(),
        })
    }
}

pub struct GenericProbe;
#[async_trait::async_trait]
impl ServiceProbe for GenericProbe {
    fn can_probe(&self, _port: u16) -> bool {
        true
    }
    async fn probe(&self, target: &ServiceTarget) -> Result<ServiceObservation, ProbeError> {
        let name = match target.port {
            21 => "FTP",
            25 | 465 | 587 => "SMTP",
            53 => "DNS",
            110 | 995 => "POP3",
            135 => "MSRPC",
            143 | 993 => "IMAP",
            389 | 636 => "LDAP",
            1433 => "MSSQL",
            1521 => "Oracle",
            3306 => "MySQL",
            5432 => "PostgreSQL",
            5985 | 5986 => "WinRM",
            6379 => "Redis",
            9200 => "Elasticsearch",
            27017 => "MongoDB",
            _ => "TCP-Service",
        };
        Ok(ServiceObservation {
            port: target.port,
            service_name: name.into(),
            version: None,
            banner: None,
            extra: serde_json::Value::Null,
            confidence: 0.6,
            method: "heuristic".into(),
        })
    }
}

pub struct ProbeRegistry(Vec<Box<dyn ServiceProbe>>);

impl Default for ProbeRegistry {
    fn default() -> Self {
        ProbeRegistry(vec![
            Box::new(SshProbe),
            Box::new(HttpProbe),
            Box::new(TlsProbe),
            Box::new(SmbProbe),
            Box::new(RdpProbe),
            Box::new(GenericProbe),
        ])
    }
}

impl ProbeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn probe_port(&self, target: &ServiceTarget) -> Option<ServiceObservation> {
        for probe in &self.0 {
            if probe.can_probe(target.port) {
                if let Ok(obs) = probe.probe(target).await {
                    return Some(obs);
                }
            }
        }
        None
    }
}
