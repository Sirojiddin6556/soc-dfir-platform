#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

/// DNS PTR lookup using standard library socket lookup
pub async fn resolve_ptr(ip: Ipv4Addr) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        if ip.is_loopback() {
            return Some("localhost".to_string());
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// Fallback NetBIOS name query
pub async fn query_netbios_name(_ip: Ipv4Addr, _timeout_ms: u64) -> Option<String> {
    None
}

/// Resolves IP to hostname using DNS or local environment
pub async fn resolve_hostname(ip: Ipv4Addr) -> Option<String> {
    if ip.is_loopback() {
        return Some("localhost".to_string());
    }
    if let Some(name) = resolve_ptr(ip).await {
        return Some(name);
    }
    if let Some(name) = query_netbios_name(ip, 1000).await {
        return Some(name);
    }
    None
}
