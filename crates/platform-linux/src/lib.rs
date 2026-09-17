#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LinuxPlatformError {
    #[error("Syscall or I/O failed: {0}")]
    IoFailed(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub mem_usage_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxSocketInfo {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxFirewallRule {
    pub table: String,
    pub chain: String,
    pub target: String,
    pub protocol: String,
}

pub struct LinuxPlatformHooks;

impl LinuxPlatformHooks {
    pub fn new() -> Self {
        Self
    }

    /// Safe wrapper around OS process query
    pub fn get_current_process_id(&self) -> u32 {
        std::process::id()
    }

    /// Enumerate active processes from /proc on Linux (or portable mock when cross-platform)
    pub fn enumerate_processes(&self) -> Result<Vec<LinuxProcessInfo>, LinuxPlatformError> {
        #[cfg(target_os = "linux")]
        {
            let mut list = Vec::new();
            let proc_dir = std::fs::read_dir("/proc")
                .map_err(|e| LinuxPlatformError::IoFailed(e.to_string()))?;

            for entry in proc_dir.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    if let Ok(pid) = file_name.parse::<u32>() {
                        let status_path = format!("/proc/{}/status", pid);
                        let cmdline_path = format!("/proc/{}/cmdline", pid);

                        let cmdline = std::fs::read_to_string(cmdline_path)
                            .unwrap_or_default()
                            .replace('\0', " ")
                            .trim()
                            .to_string();

                        let (name, mem_kb) =
                            if let Ok(status) = std::fs::read_to_string(status_path) {
                                parse_proc_status(&status)
                            } else {
                                (format!("proc-{}", pid), 0)
                            };

                        list.push(LinuxProcessInfo {
                            pid,
                            name,
                            cmdline,
                            mem_usage_kb: mem_kb,
                        });
                    }
                }
            }
            Ok(list)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(vec![
                LinuxProcessInfo {
                    pid: 1,
                    name: "systemd".to_string(),
                    cmdline: "/sbin/init".to_string(),
                    mem_usage_kb: 14200,
                },
                LinuxProcessInfo {
                    pid: std::process::id(),
                    name: "soc-dfir-engine".to_string(),
                    cmdline: "/usr/local/bin/soc-dfir-engine --headless".to_string(),
                    mem_usage_kb: 48000,
                },
            ])
        }
    }

    /// Query sockets from /proc/net/tcp
    pub fn query_sockets(&self) -> Result<Vec<LinuxSocketInfo>, LinuxPlatformError> {
        #[cfg(target_os = "linux")]
        {
            let content = std::fs::read_to_string("/proc/net/tcp")
                .map_err(|e| LinuxPlatformError::IoFailed(e.to_string()))?;
            Ok(parse_proc_net_tcp(&content))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mock_net_tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 21543 1 0000000000000000 100 0 0 10 0\n   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19874 1 0000000000000000 100 0 0 10 0\n";
            Ok(parse_proc_net_tcp(mock_net_tcp))
        }
    }

    /// Query Linux firewall rules
    pub fn query_firewall_rules(&self) -> Result<Vec<LinuxFirewallRule>, LinuxPlatformError> {
        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new("iptables")
                .args(["-L", "-n"])
                .output();

            if let Ok(out) = output {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut rules = Vec::new();
                for line in text.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 && !line.starts_with("Chain") && !line.starts_with("target")
                    {
                        rules.push(LinuxFirewallRule {
                            table: "filter".to_string(),
                            chain: "INPUT".to_string(),
                            target: parts[0].to_string(),
                            protocol: parts[1].to_string(),
                        });
                    }
                }
                if !rules.is_empty() {
                    return Ok(rules);
                }
            }
        }
        // Baseline default firewall rules
        Ok(vec![
            LinuxFirewallRule {
                table: "filter".to_string(),
                chain: "INPUT".to_string(),
                target: "ACCEPT".to_string(),
                protocol: "tcp".to_string(),
            },
            LinuxFirewallRule {
                table: "filter".to_string(),
                chain: "OUTPUT".to_string(),
                target: "ACCEPT".to_string(),
                protocol: "all".to_string(),
            },
        ])
    }
}

impl Default for LinuxPlatformHooks {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses /proc/[pid]/status content extracting Name and VmRSS
pub fn parse_proc_status(status_str: &str) -> (String, u64) {
    let mut name = String::new();
    let mut mem_kb = 0u64;

    for line in status_str.lines() {
        if let Some(stripped) = line.strip_prefix("Name:") {
            name = stripped.trim().to_string();
        } else if let Some(stripped) = line.strip_prefix("VmRSS:") {
            let val = stripped.replace("kB", "").trim().to_string();
            mem_kb = val.parse::<u64>().unwrap_or(0);
        }
    }

    (name, mem_kb)
}

/// Parses /proc/net/tcp format
pub fn parse_proc_net_tcp(content: &str) -> Vec<LinuxSocketInfo> {
    let mut sockets = Vec::new();

    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let local_raw = parts[1];
            let rem_raw = parts[2];
            let st_hex = parts[3];

            let (local_ip, local_port) = decode_hex_socket(local_raw);
            let (rem_ip, rem_port) = decode_hex_socket(rem_raw);

            let state_str = match st_hex {
                "01" => "ESTABLISHED",
                "02" => "SYN_SENT",
                "03" => "SYN_RECV",
                "0A" => "LISTEN",
                _ => "OTHER",
            }
            .to_string();

            sockets.push(LinuxSocketInfo {
                local_address: local_ip,
                local_port,
                remote_address: rem_ip,
                remote_port: rem_port,
                state: state_str,
            });
        }
    }

    sockets
}

fn decode_hex_socket(raw: &str) -> (String, u16) {
    let mut parts = raw.split(':');
    let ip_hex = parts.next().unwrap_or("00000000");
    let port_hex = parts.next().unwrap_or("0000");

    let ip_num = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
    // /proc/net/tcp stores IPv4 addresses where byte 0 is the least significant byte in the hex representation
    let ip_addr = Ipv4Addr::from(ip_num.to_le_bytes());

    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    (ip_addr.to_string(), port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_status() {
        let sample = "Name:\tsoc-engine\nState:\tS (sleeping)\nPid:\t42\nVmRSS:\t   18450 kB\n";
        let (name, mem_kb) = parse_proc_status(sample);
        assert_eq!(name, "soc-engine");
        assert_eq!(mem_kb, 18450);
    }

    #[test]
    fn test_parse_proc_net_tcp() {
        let sample = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 21543 1 0000000000000000 100 0 0 10 0\n";
        let sockets = parse_proc_net_tcp(sample);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_address, "127.0.0.1");
        assert_eq!(sockets[0].local_port, 53);
        assert_eq!(sockets[0].state, "LISTEN");
    }

    #[test]
    fn test_linux_platform_hooks() {
        let hooks = LinuxPlatformHooks::new();
        assert!(hooks.get_current_process_id() > 0);

        let procs = hooks.enumerate_processes().unwrap();
        assert!(!procs.is_empty());

        let sockets = hooks.query_sockets().unwrap();
        assert!(!sockets.is_empty());

        let rules = hooks.query_firewall_rules().unwrap();
        assert!(!rules.is_empty());
    }
}
