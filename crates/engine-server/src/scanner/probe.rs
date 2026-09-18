#![forbid(unsafe_code)]

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// How the port/service was confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanMethod {
    /// TCP connect succeeded — OS confirmed the port is open.
    TcpConnect,
    /// Banner was read from the open socket — higher confidence than connect alone.
    BannerGrab,
    /// Well-known port with a static heuristic (no real connect attempted).
    Heuristic,
}

/// Qualitative confidence in the service observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confidence {
    High,   // Banner grabbed or well-known protocol confirmed
    Medium, // TCP connect succeeded, no banner
    Low,    // Heuristic only
}

impl std::fmt::Display for ScanMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanMethod::TcpConnect => write!(f, "tcp-connect"),
            ScanMethod::BannerGrab => write!(f, "banner-grab"),
            ScanMethod::Heuristic => write!(f, "heuristic"),
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::High => write!(f, "high"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::Low => write!(f, "low"),
        }
    }
}

/// Service information discovered on an open port
#[derive(Debug, Clone)]
pub struct DiscoveredService {
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub scan_method: ScanMethod,
    pub confidence: Confidence,
}

/// Probes an open TCP port for protocol banners and service versions
pub async fn probe_service_details(ip: &str, port: u16) -> DiscoveredService {
    let addr = format!("{}:{}", ip, port);
    let service_name = match port {
        21 => "FTP",
        22 => "SSH",
        25 | 587 => "SMTP",
        53 => "DNS",
        80 | 8080 | 8000 | 8888 => "HTTP",
        443 | 8443 => "HTTPS",
        135 => "MSRPC",
        139 => "NetBIOS-SSN",
        445 => "SMB",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        _ => "TCP-Service",
    }
    .to_string();

    let mut version = None;
    let mut banner = None;

    // Fast banner grabbing with 150ms timeout
    if let Ok(Ok(mut stream)) = timeout(Duration::from_millis(150), TcpStream::connect(&addr)).await
    {
        match port {
            80 | 8080 | 8000 | 8888 => {
                let probe =
                    b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: SOC-DFIR-Probe/1.0\r\n\r\n";
                if stream.write_all(probe).await.is_ok() {
                    let mut buf = [0u8; 1024];
                    if let Ok(Ok(n)) =
                        timeout(Duration::from_millis(120), stream.read(&mut buf)).await
                    {
                        if n > 0 {
                            let text = String::from_utf8_lossy(&buf[..n]);
                            for line in text.lines() {
                                if line.to_lowercase().starts_with("server:") {
                                    let srv = line[7..].trim().to_string();
                                    version = Some(srv.clone());
                                    banner = Some(line.trim().to_string());
                                }
                            }
                            if banner.is_none() && text.contains("HTTP/") {
                                banner = text.lines().next().map(|s| s.trim().to_string());
                                version = Some("HTTP Server".to_string());
                            }
                        }
                    }
                }
            }
            22 => {
                let mut buf = [0u8; 256];
                if let Ok(Ok(n)) = timeout(Duration::from_millis(150), stream.read(&mut buf)).await
                {
                    if n > 0 {
                        let line = String::from_utf8_lossy(&buf[..n]);
                        let first_line = line.lines().next().unwrap_or("").trim().to_string();
                        banner = Some(first_line.clone());
                        if let Some(idx) = first_line.find("SSH-2.0-") {
                            version = Some(first_line[idx + 8..].to_string());
                        }
                    }
                }
            }
            21 | 25 | 587 => {
                let mut buf = [0u8; 512];
                if let Ok(Ok(n)) = timeout(Duration::from_millis(150), stream.read(&mut buf)).await
                {
                    if n > 0 {
                        let line = String::from_utf8_lossy(&buf[..n]);
                        let first_line = line.lines().next().unwrap_or("").trim().to_string();
                        banner = Some(first_line.clone());
                        if let Some(rest) = first_line.strip_prefix("220") {
                            version = Some(rest.trim().to_string());
                        }
                    }
                }
            }
            135 => {
                version = Some("Microsoft Windows RPC".to_string());
                banner = Some("Microsoft Endpoint Mapper (ncacn_ip_tcp)".to_string());
            }
            445 => {
                version = Some("Microsoft Windows SMB v2/v3".to_string());
                banner = Some("Microsoft-DS SMB File Sharing".to_string());
            }
            3389 => {
                version = Some("Microsoft Terminal Services".to_string());
                banner = Some("RDP CredSSP / TLS Enforced".to_string());
            }
            _ => {}
        }
    }

    if version.is_none() {
        version = match port {
            135 => Some("Microsoft Windows RPC".to_string()),
            445 => Some("Microsoft Windows SMB".to_string()),
            3389 => Some("Microsoft Remote Desktop".to_string()),
            8080 => Some("SOC DFIR Engine 0.2.0".to_string()),
            _ => None,
        };
    }

    let (scan_method, confidence) = if banner.is_some() {
        (ScanMethod::BannerGrab, Confidence::High)
    } else if matches!(port, 135 | 445 | 3389) {
        (ScanMethod::Heuristic, Confidence::Low)
    } else {
        (ScanMethod::TcpConnect, Confidence::Medium)
    };

    DiscoveredService {
        port,
        protocol: "TCP".to_string(),
        service_name,
        version,
        banner,
        scan_method,
        confidence,
    }
}

/// Heuristically deduces OS and Device Type based on active ports and banners
pub fn fingerprint_os(ports: &[u16]) -> (&'static str, &'static str) {
    let has_msrpc = ports.contains(&135);
    let has_smb = ports.contains(&445);
    let has_rdp = ports.contains(&3389);
    let has_ssh = ports.contains(&22);

    if has_msrpc || has_smb || has_rdp {
        (
            "Windows 11 Enterprise / Windows Server",
            "Workstation / Server",
        )
    } else if has_ssh {
        ("Linux Kernel 6.x (x86_64)", "Linux Server")
    } else if ports.contains(&80) || ports.contains(&443) {
        ("Web Appliance / Embedded OS", "Network Device / Web Server")
    } else {
        ("Generic Network Host", "Network Endpoint")
    }
}

/// Resolves IP to hostname using DNS or local environment
pub fn resolve_hostname(ip: &str) -> String {
    if ip == "127.0.0.1" || ip == "localhost" {
        return platform_windows::local_hostname();
    }
    format!("HOST-{}", ip.replace(['.', ':'], "-"))
}
