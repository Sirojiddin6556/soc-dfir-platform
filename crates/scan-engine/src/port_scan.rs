#![forbid(unsafe_code)]

use crate::types::{PortResult, PortState, ScanProfile, TransportProto};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

pub const TOP_QUICK_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995,
    1433, 1521, 2049, 3306, 3389, 4444, 5432, 5900, 5985, 5986, 6379, 7001, 8080, 8443, 8888, 9090,
    9200, 9300, 10250, 27017,
];

pub const TOP_STANDARD_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
    162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 631, 636, 873, 902, 989, 990, 993, 995,
    1080, 1194, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375, 2376, 2483,
    2484, 3000, 3128, 3268, 3269, 3306, 3389, 4000, 4444, 5000, 5432, 5672, 5900, 5984, 5985, 5986,
    6000, 6379, 6667, 7000, 7001, 7077, 8000, 8008, 8080, 8081, 8443, 8500, 8888, 9000, 9042, 9090,
    9092, 9100, 9200, 9300, 9418, 9999, 10000, 10250, 11211, 27017, 50000, 50051, 51820,
];

pub fn ports_for_profile(profile: &ScanProfile) -> Vec<u16> {
    match profile {
        ScanProfile::Quick => TOP_QUICK_PORTS.to_vec(),
        ScanProfile::Standard => {
            let mut set: std::collections::BTreeSet<u16> =
                TOP_STANDARD_PORTS.iter().copied().collect();
            let mut p = 1u16;
            while set.len() < 1000 && p <= 1024 {
                set.insert(p);
                p += 1;
            }
            set.into_iter().collect()
        }
        ScanProfile::Deep => (1u16..=65535).collect(),
    }
}

pub async fn scan_tcp_ports(ip: Ipv4Addr, ports: &[u16], timeout_ms: u64) -> Vec<PortResult> {
    let concurrency = if ports.len() > 1000 { 256 } else { 64 };
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for &port in ports {
        let sem_clone = Arc::clone(&sem);
        handles.push(tokio::spawn(async move {
            let _permit = sem_clone.acquire_owned().await.ok()?;
            let addr = format!("{}:{}", ip, port);
            let connect_timeout = Duration::from_millis(timeout_ms);

            let state = match timeout(connect_timeout, TcpStream::connect(&addr)).await {
                Ok(Ok(_stream)) => PortState::Open,
                Ok(Err(e)) => classify_error(&e),
                Err(_) => PortState::Timeout,
            };

            Some(PortResult {
                port,
                protocol: TransportProto::Tcp,
                state,
                service: None,
            })
        }));
    }

    let mut results = Vec::with_capacity(ports.len());
    for h in handles {
        if let Ok(Some(res)) = h.await {
            results.push(res);
        }
    }
    results.sort_by_key(|r| r.port);
    results
}

pub fn classify_error(e: &std::io::Error) -> PortState {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => PortState::Closed,
        std::io::ErrorKind::TimedOut => PortState::Timeout,
        std::io::ErrorKind::ConnectionReset => PortState::Closed,
        _ => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("refused") {
                PortState::Closed
            } else if msg.contains("timed out") || msg.contains("timeout") {
                PortState::Timeout
            } else if msg.contains("unreachable") {
                PortState::Unreachable
            } else {
                PortState::Filtered
            }
        }
    }
}
