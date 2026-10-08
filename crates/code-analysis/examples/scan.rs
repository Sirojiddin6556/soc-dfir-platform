//! Prints the findings for a directory.
//!
//! cargo run --release -p code-analysis --example scan -- DIR [--json] [--tests]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = std::path::Path::new(args.first().expect("directory"));
    let started = std::time::Instant::now();
    let options = code_analysis::Options {
        include_tests: args.iter().any(|a| a == "--tests"),
        external_sources: args.iter().any(|a| a == "--external"),
    };
    let report = code_analysis::analyze_dir_with(root, options).expect("analyze");
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
        let more = match f.other_sources.len() {
            0 => String::new(),
            n => format!(" (+{n} other sources)"),
        };
        println!(
            "{:?} {}:{} [{} CWE-{}] {}{}{}",
            f.severity, f.file, f.line, f.rule, f.cwe, f.snippet, src, more
        );
    }
    eprintln!(
        "{} files ({} test files not analyzed), {} lines, {} findings, {} parse errors, {:.1?} (load {} ms, analysis {} ms)",
        report.files,
        report.test_files,
        report.lines,
        report.findings.len(),
        report.parse_errors.len(),
        started.elapsed(),
        report.load_ms,
        report.analysis_ms
    );
}
