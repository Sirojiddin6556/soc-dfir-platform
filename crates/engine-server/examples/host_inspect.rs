//! Live host inspection + correlation of the machine this runs on, exactly as
//! the `host.overview` / `host.correlate` RPCs compute it.
//!
//! cargo run -p engine-server --example host_inspect

use core_domain::id::EntityId;
use correlation_engine::DeterministicCorrelationEngine;
use engine_server::host_inspector;
use storage_sqlite::SqliteStorage;

fn main() {
    let host = engine_server::default_host_id();
    let overview = host_inspector::handle_host_overview(host);
    println!("{}", serde_json::to_string_pretty(&overview).unwrap());

    let storage = SqliteStorage::open_in_memory().expect("in-memory db");
    let case = EntityId::new_v7();
    storage
        .insert_case(case, "host_inspect example", None)
        .expect("case");
    let corr = host_inspector::handle_host_correlation(
        host,
        case,
        &storage,
        &DeterministicCorrelationEngine::new(),
    );
    println!(
        "\ncorrelation: status={} observations={} findings={} risk={} ({})",
        corr["status"],
        corr["observations_evaluated"],
        corr["findings_count"],
        corr["risk_score"],
        corr["risk_level"]
    );
    for f in corr["findings"].as_array().into_iter().flatten() {
        println!(
            "  [{}] {} {} {}  {}",
            f["rule_id"].as_str().unwrap_or(""),
            f["severity"].as_str().unwrap_or(""),
            f["mitre_technique"].as_str().unwrap_or("-"),
            f["entity_key"].as_str().unwrap_or(""),
            f["title"].as_str().unwrap_or("")
        );
    }
}
