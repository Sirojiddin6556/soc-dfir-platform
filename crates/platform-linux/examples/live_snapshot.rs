//! Prints a summary of the live snapshot of the machine this runs on.
//!
//! cargo run -p platform-linux --example live_snapshot [--json]

fn main() {
    let started = std::time::Instant::now();
    let snap = platform_linux::collect_host_snapshot();
    let elapsed = started.elapsed();

    if std::env::args().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&snap).unwrap());
        return;
    }

    println!("snapshot     {}", snap.snapshot_id);
    println!("host         {} ({})", snap.host, snap.host_ip);
    println!("addresses    {}", snap.ip_addresses.join(", "));
    println!("os           {}", snap.os);
    println!(
        "platform     {} / family={} version={} codename={}",
        snap.platform,
        snap.os_family,
        snap.os_version,
        snap.os_codename.as_deref().unwrap_or("-")
    );
    println!("kernel       {}  arch={}", snap.kernel, snap.architecture);
    println!("collected in {:.2?}", elapsed);
    println!();
    println!(
        "counts: processes={} sockets={} services={} scheduled_tasks={} autoruns={} software={} users={} firewall_rules={}",
        snap.processes.len(),
        snap.sockets.len(),
        snap.services.len(),
        snap.scheduled_tasks.len(),
        snap.autoruns.len(),
        snap.software.len(),
        snap.users.len(),
        snap.firewall_rules.len()
    );

    println!("\nprocesses (user-space sample):");
    for p in snap
        .processes
        .iter()
        .filter(|p| p.executable_path.is_some())
        .take(8)
    {
        println!(
            "  pid={:<6} ppid={:<6} user={:<8} {:<16} exe={}{} sha256={}",
            p.pid,
            p.ppid,
            p.username.as_deref().unwrap_or("?"),
            p.name,
            p.executable_path.as_deref().unwrap_or("-"),
            if p.exe_deleted { " (DELETED)" } else { "" },
            p.sha256.as_deref().map(|h| &h[..16]).unwrap_or("-")
        );
    }
    let me = std::process::id();
    if let Some(p) = snap.processes.iter().find(|p| p.pid == me) {
        println!(
            "  [self] pid={} exe={} started={}",
            p.pid,
            p.executable_path.as_deref().unwrap_or("-"),
            p.started_at.as_deref().unwrap_or("-")
        );
    }

    println!("\nsockets:");
    for s in snap.sockets.iter().take(8) {
        println!(
            "  {:<4} {}:{} -> {}:{} {:<12} pid={} ({})",
            s.protocol,
            s.local_address,
            s.local_port,
            s.remote_address,
            s.remote_port,
            s.state,
            s.pid,
            s.process_name.as_deref().unwrap_or("?")
        );
    }

    println!("\nservices (sample):");
    for s in snap.services.iter().take(6) {
        println!(
            "  {:<32} {:<10} {:<10} {}",
            s.service_name, s.state, s.start_type, s.binary_path
        );
    }

    println!("\nscheduled tasks:");
    for t in snap.scheduled_tasks.iter().take(6) {
        println!(
            "  [{}] {:<28} {:<14} user={} {}",
            t.mechanism,
            t.task_name,
            t.schedule.as_deref().unwrap_or("-"),
            t.user.as_deref().unwrap_or("-"),
            t.action.as_deref().unwrap_or("-")
        );
    }

    println!("\nautoruns:");
    for a in snap.autoruns.iter().take(8) {
        println!("  [{}] {:<28} {}", a.mechanism, a.value_name, a.value_data);
    }

    println!("\nsoftware (sample):");
    for s in snap.software.iter().take(4) {
        println!(
            "  {} {} [{}] {}",
            s.product,
            s.version,
            s.ecosystem.as_deref().unwrap_or("-"),
            s.purl.as_deref().unwrap_or("-")
        );
    }
    if let Some(ssl) = snap
        .software
        .iter()
        .find(|s| s.source_package.as_deref() == Some("openssl"))
    {
        println!(
            "  {} {} {}",
            ssl.product,
            ssl.version,
            ssl.purl.as_deref().unwrap_or("-")
        );
    }

    println!("\nusers: {}", snap.users.join(", "));
    println!(
        "interactive/admin accounts: {}",
        snap.user_accounts
            .iter()
            .filter(|u| u.interactive)
            .map(|u| format!("{}{}", u.name, if u.admin { "*" } else { "" }))
            .collect::<Vec<_>>()
            .join(", ")
    );

    println!("\nfirewall:");
    for r in &snap.firewall_rules {
        println!("  {:<10} {:<8} {}", r.direction, r.action, r.name);
    }

    println!("\ncollection_errors:");
    for e in &snap.collection_errors {
        println!("  - {}", e);
    }
}
