#![forbid(unsafe_code)]

use super::probe::{fingerprint_os, probe_service_details, resolve_hostname};
use serde_json::json;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Executes an infrastructure network scan (Quick, Standard, Deep) with banner grabbing
pub async fn execute_network_scan(subnet: &str, mode: &str) -> serde_json::Value {
    let is_local = subnet.starts_with("127.") || subnet == "localhost";
    let start_instant = std::time::Instant::now();

    if is_local {
        let common_ports: Vec<u16> = match mode {
            "deep" => vec![
                21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 8888, 9090, 9200,
                27017,
            ],
            "standard" => vec![
                22, 25, 53, 80, 110, 135, 143, 443, 445, 1433, 3306, 3389, 5432, 5985, 8080, 8443,
            ],
            _ => vec![22, 80, 135, 443, 445, 3389, 8080], // quick
        };

        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let sem = Arc::new(Semaphore::new(64)); // max 64 concurrent probes
        let mut handles = Vec::new();

        for &port in &common_ports {
            let sem = Arc::clone(&sem);
            let ip_str = "127.0.0.1".to_string(); // use "127.0.0.1" for local branch
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                let addr = format!("{}:{}", ip_str, port);
                if timeout(Duration::from_millis(80), TcpStream::connect(&addr))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
                {
                    Some(port)
                } else {
                    None
                }
            }));
        }

        let mut open_ports: Vec<u16> = Vec::new();
        for h in handles {
            if let Ok(Some(p)) = h.await {
                open_ports.push(p);
            }
        }
        open_ports.sort_unstable();

        let mut services_json = Vec::new();
        for &port in &open_ports {
            let s = probe_service_details("127.0.0.1", port).await;
            services_json.push(json!({
                "port": s.port,
                "protocol": s.protocol,
                "service": s.service_name,
                "version": s.version.unwrap_or_else(|| "Detected".to_string()),
                "banner": s.banner.unwrap_or_else(|| format!("{}/{}", s.service_name, s.port)),
            }));
        }

        let (os_str, dev_type) = fingerprint_os(&open_ports);
        let hostname = resolve_hostname("127.0.0.1");
        let duration = start_instant.elapsed().as_millis();

        return json!({
            "subnet": subnet,
            "mode": mode,
            "hosts_scanned": 1,
            "hosts_up": 1,
            "duration_ms": duration,
            "scan_rate_pps": 350,
            "discovered_hosts": [
                {
                    "id": "h_local",
                    "hostname": hostname,
                    "ip": "127.0.0.1",
                    "mac": "00:00:00:00:00:00",
                    "os": os_str,
                    "device_type": dev_type,
                    "criticality": "Tier-1 (Рабочая станция аналитика)",
                    "status": "Активен / Боевой режим",
                    "risk": "НИЗКИЙ (1.0)",
                    "subnet": "127.0.0.1/32",
                    "ports": open_ports,
                    "services": services_json,
                    "persistence": [],
                    "software": [{ "name": "SOC DFIR Engine", "ver": "0.2.0", "cpe": "cpe:2.3:a:soc:dfir_engine:0.2.0" }],
                    "vulnerabilities": []
                }
            ]
        });
    }

    if mode == "remote" {
        let target = if subnet.contains('/') {
            subnet.split('/').next().unwrap_or(subnet)
        } else {
            subnet
        };
        let common_ports: Vec<u16> = match mode {
            "deep" => vec![
                21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 8888, 9090, 9200,
                27017,
            ],
            "standard" => vec![
                22, 25, 53, 80, 110, 135, 143, 443, 445, 1433, 3306, 3389, 5432, 5985, 8080, 8443,
            ],
            _ => vec![22, 80, 135, 443, 445, 3389, 8080], // quick
        };

        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let sem = Arc::new(Semaphore::new(64)); // max 64 concurrent probes
        let mut handles = Vec::new();

        for &port in &common_ports {
            let sem = Arc::clone(&sem);
            let ip_str = target.to_string(); // use target for remote branch
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                let addr = format!("{}:{}", ip_str, port);
                if timeout(Duration::from_millis(80), TcpStream::connect(&addr))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
                {
                    Some(port)
                } else {
                    None
                }
            }));
        }

        let mut open_ports: Vec<u16> = Vec::new();
        for h in handles {
            if let Ok(Some(p)) = h.await {
                open_ports.push(p);
            }
        }
        open_ports.sort_unstable();

        let mut discovered = Vec::new();
        if !open_ports.is_empty() {
            let mut services_json = Vec::new();
            for &port in &open_ports {
                let s = probe_service_details(target, port).await;
                services_json.push(json!({
                    "port": s.port,
                    "protocol": s.protocol,
                    "service": s.service_name,
                    "version": s.version.unwrap_or_else(|| "Detected".to_string()),
                    "banner": s.banner.unwrap_or_else(|| format!("{}/{}", s.service_name, s.port)),
                }));
            }

            let (os_str, dev_type) = fingerprint_os(&open_ports);
            let hostname = resolve_hostname(target);

            discovered.push(json!({
                "id": format!("remote_{}", target.replace(['.', ':'], "_")),
                "hostname": hostname,
                "ip": target,
                "mac": "02:42:AC:11:00:02",
                "os": os_str,
                "device_type": dev_type,
                "criticality": "Tier-1 (Внешний периметр)",
                "status": "В сети / Сканирован",
                "risk": "НИЗКИЙ (1.0)",
                "subnet": format!("{}/32", target),
                "ports": open_ports,
                "services": services_json,
                "persistence": [],
                "software": [],
                "vulnerabilities": []
            }));
        }

        let hosts_up = discovered.len();
        let duration = start_instant.elapsed().as_millis();
        return json!({
            "subnet": target,
            "mode": "remote",
            "hosts_scanned": 1,
            "hosts_up": hosts_up,
            "duration_ms": duration,
            "scan_rate_pps": 350,
            "discovered_hosts": discovered
        });
    }

    // Live Subnet Discovery (e.g. 192.168.56.0/24, 172.16.121.0/24, 172.20.32.0/20)
    let prefix = if let Some(slash_idx) = subnet.find('/') {
        let base_ip = &subnet[..slash_idx];
        if let Some(last_dot) = base_ip.rfind('.') {
            &base_ip[..=last_dot]
        } else {
            "127.0.0."
        }
    } else {
        "127.0.0."
    };

    let probe_hosts = vec![1, 2, 10, 32, 50, 100, 254];
    let probe_ports = vec![80, 443, 445, 135, 22, 3389, 8080];
    let mut discovered = Vec::new();

    for &host_suffix in &probe_hosts {
        let ip = format!("{}{}", prefix, host_suffix);
        let mut host_open_ports = Vec::new();

        for &port in &probe_ports {
            let addr = format!("{}:{}", ip, port);
            if let Ok(Ok(_)) = timeout(Duration::from_millis(30), TcpStream::connect(&addr)).await {
                host_open_ports.push(port);
            }
        }

        if !host_open_ports.is_empty() {
            let mut services_json = Vec::new();
            for &port in &host_open_ports {
                let s = probe_service_details(&ip, port).await;
                services_json.push(json!({
                    "port": s.port,
                    "protocol": s.protocol,
                    "service": s.service_name,
                    "version": s.version.unwrap_or_else(|| "Detected".to_string()),
                    "banner": s.banner.unwrap_or_else(|| format!("{}/{}", s.service_name, s.port)),
                }));
            }

            let (os_str, dev_type) = fingerprint_os(&host_open_ports);
            let hostname = resolve_hostname(&ip);

            discovered.push(json!({
                "id": format!("h_{}", host_suffix),
                "hostname": hostname,
                "ip": ip.clone(),
                "mac": "00:50:56:C0:00:08",
                "os": os_str,
                "device_type": dev_type,
                "criticality": "Tier-2 (Сетевой узел)",
                "status": "В сети / Обнаружен",
                "risk": "НИЗКИЙ (1.0)",
                "subnet": subnet,
                "ports": host_open_ports,
                "services": services_json,
                "persistence": [],
                "software": [],
                "vulnerabilities": []
            }));
        }
    }

    let hosts_up = discovered.len();
    let duration = start_instant.elapsed().as_millis();
    json!({
        "subnet": subnet,
        "mode": mode,
        "hosts_scanned": probe_hosts.len(),
        "hosts_up": hosts_up,
        "duration_ms": duration,
        "scan_rate_pps": 500,
        "discovered_hosts": discovered
    })
}

/// Correlates asset software stack against CVE vulnerability knowledge base with CPE 2.3 normalization
pub fn execute_cve_scan(host_id: &str) -> serde_json::Value {
    let hostname = if host_id == "h_local" {
        crate::default_host_id()
    } else {
        host_id
    };
    let snap = crate::host_inspector::get_or_collect_snapshot(hostname);
    let vuln_db = normalization_engine::VulnerabilityDatabase::new();

    let mut scanned_software = Vec::new();
    let mut vulnerabilities = Vec::new();

    for sw in &snap.software {
        let norm =
            normalization_engine::resolve_cpe_and_purl(&sw.product, &sw.publisher, &sw.version);
        let matches = vuln_db.match_vulnerabilities(&sw.product, &sw.version);

        for m in &matches {
            vulnerabilities.push(json!({
                "cve": m.cve_id,
                "name": format!("{} - {}", sw.product, m.description),
                "cvss": m.cvss_v3,
                "severity": m.severity,
                "epss": m.epss_score,
                "cisa_kev": m.cisa_kev,
                "cpe": norm.cpe23,
                "purl": norm.purl
            }));
        }

        scanned_software.push(json!({
            "name": sw.product,
            "ver": sw.version,
            "publisher": sw.publisher,
            "cpe": norm.cpe23,
            "purl": norm.purl,
            "status": if matches.is_empty() { "SECURE (CVE-FREE)" } else { "AFFECTED" }
        }));
    }

    let calculated_risk = if vulnerabilities.is_empty() {
        1.0
    } else {
        vulnerabilities
            .iter()
            .map(|v| v.get("cvss").and_then(|c| c.as_f64()).unwrap_or(5.0) as f32)
            .fold(1.0f32, f32::max)
    };

    json!({
        "host_id": host_id,
        "hostname": hostname,
        "software_scanned": scanned_software.len(),
        "calculated_risk": calculated_risk,
        "scanned_software": scanned_software,
        "vulnerabilities": vulnerabilities
    })
}
