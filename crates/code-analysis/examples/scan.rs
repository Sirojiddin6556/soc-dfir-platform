//! Prints the findings for a directory.
//!
//! cargo run --release -p code-analysis --example scan -- DIR [--json]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = std::path::Path::new(args.first().expect("directory"));
    let started = std::time::Instant::now();
    let report = code_analysis::analyze_dir(root).expect("analyze");
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&report).expect("json"));
        return;
    }
    for f in &report.findings {
        let src = f
            .source
            .as_ref()
            .map(|s| format!(" <- {}:{} {}", s.file, s.line, s.note))
            .unwrap_or_default();
        println!(
            "{:?} {}:{} [{} CWE-{}] {}{}",
            f.severity, f.file, f.line, f.rule, f.cwe, f.snippet, src
        );
    }
    eprintln!(
        "{} files, {} lines, {} findings, {} parse errors, {:.1?} (load {} ms, analysis {} ms)",
        report.files,
        report.lines,
        report.findings.len(),
        report.parse_errors.len(),
        started.elapsed(),
        report.load_ms,
        report.analysis_ms
    );
}
