#![forbid(unsafe_code)]

use crate::ps::{get_str, get_u64};
use host_snapshot::json_items;
pub use host_snapshot::SocketObservation;

/// All TCP connections and UDP endpoints with owning process ids.
pub const SOCKET_SCRIPT: &str = r#"
$tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{ Protocol='TCP'; LocalAddress=[string]$_.LocalAddress; LocalPort=[int]$_.LocalPort; RemoteAddress=[string]$_.RemoteAddress; RemotePort=[int]$_.RemotePort; State=[int]$_.State; OwningProcess=[int]$_.OwningProcess }
})
$udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{ Protocol='UDP'; LocalAddress=[string]$_.LocalAddress; LocalPort=[int]$_.LocalPort; RemoteAddress=''; RemotePort=0; State=100; OwningProcess=[int]$_.OwningProcess }
})
ConvertTo-Json -InputObject @($tcp + $udp) -Compress
"#;

/// `MSFT_NetTCPConnection.State` values.
pub fn map_tcp_state(code: i64) -> &'static str {
    match code {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTCB",
        100 => "Bound",
        _ => "Unknown",
    }
}

pub fn parse_sockets_json(json: &str, collected_at: &str) -> Vec<SocketObservation> {
    json_items(json)
        .iter()
        .filter_map(|item| {
            let protocol = get_str(item, "Protocol").unwrap_or_else(|| "TCP".to_string());
            let state = match item.get("State") {
                Some(serde_json::Value::Number(n)) => {
                    map_tcp_state(n.as_i64().unwrap_or(0)).to_string()
                }
                Some(serde_json::Value::String(s)) => s.clone(),
                _ => "Unknown".to_string(),
            };
            Some(SocketObservation {
                protocol,
                local_address: get_str(item, "LocalAddress")?,
                local_port: get_u64(item, "LocalPort").unwrap_or(0) as u16,
                remote_address: get_str(item, "RemoteAddress").unwrap_or_default(),
                remote_port: get_u64(item, "RemotePort").unwrap_or(0) as u16,
                state,
                pid: get_u64(item, "OwningProcess").unwrap_or(0) as u32,
                process_name: None,
                first_seen: collected_at.to_string(),
                last_seen: collected_at.to_string(),
                collected_at: collected_at.to_string(),
                inode: None,
                uid: None,
            })
        })
        .collect()
}

/// Enumerates live TCP connections and UDP endpoints with owning PIDs.
#[cfg(target_os = "windows")]
pub fn enumerate_sockets_deep() -> Result<Vec<SocketObservation>, String> {
    let now = chrono::Utc::now().to_rfc3339();
    let json = crate::ps::run(SOCKET_SCRIPT)?;
    Ok(parse_sockets_json(&json, &now))
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_sockets_deep() -> Result<Vec<SocketObservation>, String> {
    Err(crate::ps::unsupported("Get-NetTCPConnection"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[{"Protocol":"TCP","LocalAddress":"0.0.0.0","LocalPort":135,"RemoteAddress":"0.0.0.0","RemotePort":0,"State":2,"OwningProcess":1188},{"Protocol":"TCP","LocalAddress":"192.168.1.105","LocalPort":49823,"RemoteAddress":"198.51.100.42","RemotePort":4444,"State":5,"OwningProcess":7344},{"Protocol":"TCP","LocalAddress":"::","LocalPort":445,"RemoteAddress":"::","RemotePort":0,"State":2,"OwningProcess":4},{"Protocol":"UDP","LocalAddress":"0.0.0.0","LocalPort":5353,"RemoteAddress":"","RemotePort":0,"State":100,"OwningProcess":2456}]"#;

    #[test]
    fn parses_tcp_and_udp_endpoints() {
        let socks = parse_sockets_json(SAMPLE, "2026-10-07T08:00:00Z");
        assert_eq!(socks.len(), 4);
        assert_eq!(socks[0].state, "Listen");
        assert_eq!(socks[0].pid, 1188);
        assert_eq!(socks[1].remote_address, "198.51.100.42");
        assert_eq!(socks[1].remote_port, 4444);
        assert_eq!(socks[1].state, "Established");
        assert_eq!(socks[2].local_address, "::");
        assert_eq!(socks[3].protocol, "UDP");
        assert_eq!(socks[3].state, "Bound");
        assert_eq!(socks[3].remote_address, "");
    }

    #[test]
    fn accepts_string_states() {
        let socks = parse_sockets_json(
            r#"{"LocalAddress":"127.0.0.1","LocalPort":5000,"State":"Listen","OwningProcess":9}"#,
            "t",
        );
        assert_eq!(socks[0].state, "Listen");
        assert_eq!(socks[0].protocol, "TCP");
    }
}
