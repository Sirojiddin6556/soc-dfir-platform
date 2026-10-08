//! Scores the analyzer on an OWASP Benchmark checkout the way the official
//! scorecard does: a test counts as flagged when a finding with the test's
//! CWE points into the test file; per category the score is TPR - FPR.
//!
//! cargo run --release -p code-analysis --example owasp_benchmark -- DIR [--misses CATEGORY] [--show TEST]

use std::collections::BTreeMap;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = Path::new(args.first().expect("benchmark directory"));
    let misses = args
        .iter()
        .position(|a| a == "--misses")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let show = args
        .iter()
        .position(|a| a == "--show")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let csv = std::fs::read_dir(root)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("expectedresults"))
                .unwrap_or(false)
        })
        .expect("expectedresults csv");
    let expected: Vec<(String, String, bool, u32)> = std::fs::read_to_string(&csv)
        .expect("csv")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(',').collect();
            (
                f[0].to_string(),
                f[1].to_string(),
                f[2] == "true",
                f[3].trim().parse().unwrap_or(0),
            )
        })
        .collect();

    let report = code_analysis::analyze_dir(root).expect("analyze");

    // test name -> set of CWEs reported in it
    let mut flagged: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for f in &report.findings {
        let mut files: Vec<&str> = vec![f.file.as_str()];
        files.extend(f.trace.iter().map(|l| l.file.as_str()));
        for file in files {
            let stem = Path::new(file)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if stem.starts_with("BenchmarkTest") {
                flagged.entry(stem.to_string()).or_default().push(f.cwe);
            }
        }
    }
    if let Some(name) = &show {
        for f in report.findings.iter().filter(|f| {
            f.file.contains(name.as_str()) || f.trace.iter().any(|l| l.file.contains(name.as_str()))
        }) {
            println!(
                "{}:{} [{} CWE-{}] {}",
                f.file, f.line, f.rule, f.cwe, f.message
            );
            for t in &f.trace {
                println!("    {}:{} {}", t.file, t.line, t.note);
            }
        }
    }

    #[derive(Default)]
    struct Score {
        tp: u32,
        fn_: u32,
        tn: u32,
        fp: u32,
    }
    let mut by_cat: BTreeMap<String, Score> = BTreeMap::new();
    for (name, cat, real, cwe) in &expected {
        let hit = flagged.get(name).map(|c| c.contains(cwe)).unwrap_or(false);
        let s = by_cat.entry(cat.clone()).or_default();
        match (real, hit) {
            (true, true) => s.tp += 1,
            (true, false) => {
                s.fn_ += 1;
                if misses.as_deref() == Some(cat) || misses.as_deref() == Some("all") {
                    println!("FN {name} {cat}");
                }
            }
            (false, false) => s.tn += 1,
            (false, true) => {
                s.fp += 1;
                if misses.as_deref() == Some(cat) || misses.as_deref() == Some("all") {
                    println!("FP {name} {cat}");
                }
            }
        }
    }
    println!(
        "{} files, {} lines, {} findings; load {} ms, analysis {} ms",
        report.files,
        report.lines,
        report.findings.len(),
        report.load_ms,
        report.analysis_ms
    );
    println!(
        "{:<16} {:>4} {:>4} {:>4} {:>4} {:>7} {:>7} {:>7}",
        "category", "TP", "FN", "TN", "FP", "TPR", "FPR", "score"
    );
    let mut total = 0.0;
    let (mut tp, mut fn_, mut tn, mut fp) = (0, 0, 0, 0);
    for (cat, s) in &by_cat {
        let tpr = s.tp as f64 / ((s.tp + s.fn_).max(1)) as f64;
        let fpr = s.fp as f64 / ((s.fp + s.tn).max(1)) as f64;
        total += tpr - fpr;
        tp += s.tp;
        fn_ += s.fn_;
        tn += s.tn;
        fp += s.fp;
        println!(
            "{:<16} {:>4} {:>4} {:>4} {:>4} {:>6.1}% {:>6.1}% {:>6.1}%",
            cat,
            s.tp,
            s.fn_,
            s.tn,
            s.fp,
            tpr * 100.0,
            fpr * 100.0,
            (tpr - fpr) * 100.0
        );
    }
    let n = by_cat.len().max(1) as f64;
    println!(
        "{:<16} {:>4} {:>4} {:>4} {:>4} {:>7} {:>7} {:>6.1}%",
        "average",
        tp,
        fn_,
        tn,
        fp,
        "",
        "",
        total / n * 100.0
    );
}
