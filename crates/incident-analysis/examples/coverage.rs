//! Coverage report over a labelled `.evtx` corpus (e.g. EVTX-ATTACK-SAMPLES),
//! where each top-level folder names a MITRE tactic. For every sample file it
//! runs the same investigation pipeline the app uses and reports, per tactic,
//! how many files produced at least one finding — a ground-truth coverage
//! check that is not tuned to file names (only the folder decides the tactic
//! bucket; detections come entirely from event content).
//!
//! Usage:
//!   cargo run -p incident-analysis --example coverage -- <path-to-corpus>

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use incident_analysis::{analyze_path, Options};

/// Collect every `.evtx` under `dir`, recursively.
fn evtx_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            evtx_files(&p, out);
        } else if p
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("evtx"))
        {
            out.push(p);
        }
    }
}

fn main() {
    let root = match std::env::args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: coverage <path-to-corpus>");
            std::process::exit(2);
        }
    };
    let opts = Options::default();
    // tactic -> (files, files with >=1 finding)
    let mut per_tactic: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut total_files = 0usize;
    let mut total_hit = 0usize;

    let Ok(top) = std::fs::read_dir(&root) else {
        eprintln!("cannot read {}", root.display());
        std::process::exit(1);
    };
    for entry in top.flatten() {
        let tp = entry.path();
        if !tp.is_dir() {
            continue;
        }
        let tactic = tp
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let mut files = Vec::new();
        evtx_files(&tp, &mut files);
        for f in &files {
            total_files += 1;
            let hit = matches!(analyze_path(f, &opts), Ok(t) if !t.findings.is_empty());
            let e = per_tactic.entry(tactic.clone()).or_insert((0, 0));
            e.0 += 1;
            if hit {
                e.1 += 1;
                total_hit += 1;
            }
        }
    }

    println!(
        "{:<30} {:>7} {:>11} {:>6}",
        "Tactic", "files", "w/finding", "%"
    );
    println!("{}", "-".repeat(56));
    for (tactic, (files, hit)) in &per_tactic {
        let pct = if *files > 0 {
            100.0 * *hit as f64 / *files as f64
        } else {
            0.0
        };
        println!("{tactic:<30} {files:>7} {hit:>11} {pct:>5.0}%");
    }
    println!("{}", "-".repeat(56));
    let pct = if total_files > 0 {
        100.0 * total_hit as f64 / total_files as f64
    } else {
        0.0
    };
    println!(
        "{:<30} {total_files:>7} {total_hit:>11} {pct:>5.0}%",
        "TOTAL"
    );
}
