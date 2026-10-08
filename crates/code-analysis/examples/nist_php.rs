//! Scores the analyzer on the NIST SARD PHP Vulnerability Test Suite
//! (`CATEGORY/CWE_N/{safe,unsafe}/*.php`, one flaw or fix per file). Each
//! file is analyzed on its own; a file counts as flagged when a finding of
//! the rule matching its CWE points into it. Per CWE the score is
//! TPR - FPR, also split by the kind of input the file reads. Files whose
//! template is broken (see `broken_template`) are left out and counted.
//!
//! cargo run --release -p code-analysis --example nist_php -- DIR [--external]
//!     [--misses CWE_N] [--fps CWE_N] [--show FILE]

use code_analysis::project::Project;
use code_analysis::Options;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// The rule that answers each CWE directory of the suite.
fn rule_for(cwe: &str) -> Option<&'static str> {
    Some(match cwe {
        "CWE_78" => "command-injection",
        "CWE_89" => "sql-injection",
        "CWE_90" => "ldap-injection",
        "CWE_91" => "xpath-injection",
        "CWE_95" => "code-injection",
        "CWE_98" => "file-inclusion",
        "CWE_601" => "open-redirect",
        "CWE_79" => "xss",
        _ => return None,
    })
}

/// Inputs from the request, as opposed to files, commands and the session.
fn request_source(src: &str) -> bool {
    matches!(
        src,
        "GET"
            | "POST"
            | "array-GET"
            | "object-Array"
            | "object-classicGet"
            | "object-directGet"
            | "object-indexArray"
            | "unserialize"
    )
}

struct Case {
    path: PathBuf,
    cwe: String,
    unsafe_: bool,
    source: String,
    sanitizer: String,
    sink: String,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = PathBuf::from(args.first().expect("suite directory"));
    let opt = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let external = args.iter().any(|a| a == "--external");
    let misses = opt("--misses");
    let fps = opt("--fps");
    let show = opt("--show");
    let mut not_tests: BTreeMap<&str, usize> = BTreeMap::new();

    let mut cases = Vec::new();
    let mut unsupported: BTreeMap<String, usize> = BTreeMap::new();
    for cat in read_dir(&root) {
        for cwe_dir in read_dir(&cat) {
            let cwe = name_of(&cwe_dir);
            for (kind, unsafe_) in [("safe", false), ("unsafe", true)] {
                for f in read_dir(&cwe_dir.join(kind)) {
                    if f.extension().and_then(|e| e.to_str()) != Some("php") {
                        continue;
                    }
                    if rule_for(&cwe).is_none() {
                        *unsupported.entry(cwe.clone()).or_default() += 1;
                        continue;
                    }
                    let src = std::fs::read_to_string(&f).unwrap_or_default();
                    if let Some(why) = broken_template(&src) {
                        *not_tests.entry(why).or_default() += 1;
                        continue;
                    }
                    let stem = f
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();
                    let parts: Vec<&str> = stem.split("__").collect();
                    cases.push(Case {
                        path: f.clone(),
                        cwe: cwe.clone(),
                        unsafe_,
                        source: parts.get(1).unwrap_or(&"").to_string(),
                        sanitizer: parts.get(2).unwrap_or(&"").to_string(),
                        sink: parts.get(3).unwrap_or(&"").to_string(),
                    });
                }
            }
        }
    }
    if let Some(s) = &show {
        cases.retain(|c| c.path.to_string_lossy().contains(s.as_str()));
    }

    let options = Options {
        external_sources: external,
        ..Options::default()
    };
    let started = std::time::Instant::now();
    let results: Mutex<Vec<(usize, bool, Vec<String>)>> = Mutex::new(Vec::new());
    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    std::thread::scope(|s| {
        for _ in 0..workers {
            std::thread::Builder::new()
                .stack_size(256 << 20)
                .spawn_scoped(s, || loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(c) = cases.get(i) else {
                        break;
                    };
                    let src = std::fs::read_to_string(&c.path).unwrap_or_default();
                    let name = name_of(&c.path);
                    let project = Project::from_sources(vec![(name, src)]);
                    let report = code_analysis::analyze_with(&project, options);
                    let rule = rule_for(&c.cwe).unwrap_or("");
                    let hit = report.findings.iter().any(|f| f.rule == rule);
                    let lines = if show.is_some() {
                        report
                            .findings
                            .iter()
                            .map(|f| format!("  {}:{} [{}] {}", f.file, f.line, f.rule, f.message))
                            .collect()
                    } else {
                        Vec::new()
                    };
                    results.lock().unwrap().push((i, hit, lines));
                })
                .expect("thread");
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|r| r.0);

    #[derive(Default, Clone, Copy)]
    struct Counts {
        tp: usize,
        fn_: usize,
        tn: usize,
        fp: usize,
    }
    impl Counts {
        fn add(&mut self, unsafe_: bool, hit: bool) {
            match (unsafe_, hit) {
                (true, true) => self.tp += 1,
                (true, false) => self.fn_ += 1,
                (false, false) => self.tn += 1,
                (false, true) => self.fp += 1,
            }
        }
        fn line(&self, label: &str) -> String {
            let tpr = self.tp as f64 / (self.tp + self.fn_).max(1) as f64;
            let fpr = self.fp as f64 / (self.fp + self.tn).max(1) as f64;
            format!(
                "{label:<26} TP {:>5} FN {:>5} TN {:>5} FP {:>5}  TPR {:>5.1}% FPR {:>5.1}%  score {:>5.1}%",
                self.tp,
                self.fn_,
                self.tn,
                self.fp,
                tpr * 100.0,
                fpr * 100.0,
                (tpr - fpr) * 100.0
            )
        }
    }
    let mut by_cwe: BTreeMap<(String, &str), Counts> = BTreeMap::new();
    let mut total: BTreeMap<&str, Counts> = BTreeMap::new();
    // (CWE, input kind, sanitizer, sink, unsafe) -> (files, first file)
    type Group = (String, &'static str, String, String, bool);
    let mut groups: BTreeMap<Group, (usize, usize)> = BTreeMap::new();
    for (i, hit, lines) in &results {
        let c = &cases[*i];
        let kind = if request_source(&c.source) {
            "request"
        } else {
            "external"
        };
        by_cwe
            .entry((c.cwe.clone(), "all"))
            .or_default()
            .add(c.unsafe_, *hit);
        by_cwe
            .entry((c.cwe.clone(), kind))
            .or_default()
            .add(c.unsafe_, *hit);
        total.entry("all").or_default().add(c.unsafe_, *hit);
        total.entry(kind).or_default().add(c.unsafe_, *hit);
        let wrong = c.unsafe_ != *hit;
        let wanted = |sel: &Option<String>, want_unsafe: bool| {
            sel.as_deref()
                .map(|s| (s == "all" || s == c.cwe) && c.unsafe_ == want_unsafe)
                .unwrap_or(false)
        };
        if wrong && (wanted(&misses, true) || wanted(&fps, false)) {
            let g = groups
                .entry((
                    c.cwe.clone(),
                    kind,
                    c.sanitizer.clone(),
                    c.sink.clone(),
                    c.unsafe_,
                ))
                .or_default();
            g.0 += 1;
            if g.0 == 1 {
                g.1 = *i;
            }
        }
        if show.is_some() {
            println!(
                "{} {} -> {}",
                if c.unsafe_ { "UNSAFE" } else { "safe  " },
                c.path.display(),
                if *hit { "flagged" } else { "not flagged" }
            );
            for l in lines {
                println!("{l}");
            }
        }
    }
    for ((cwe, kind), counts) in &by_cwe {
        println!("{}", counts.line(&format!("{cwe} {kind}")));
    }
    for (kind, counts) in &total {
        println!("{}", counts.line(&format!("TOTAL {kind}")));
    }
    for (cwe, n) in &unsupported {
        println!("{cwe}: {n} files not scored (not a data-flow flaw this tool reports)");
    }
    for (why, n) in &not_tests {
        println!("{n} files not scored: {why}");
    }
    for ((cwe, kind, san, sink, unsafe_), (n, first)) in &groups {
        println!(
            "{} {cwe} {kind} {san} / {sink}: {n} (e.g. {})",
            if *unsafe_ { "MISS" } else { "FP  " },
            cases[*first].path.display()
        );
    }
    eprintln!(
        "{} files in {:.1} s{}",
        results.len(),
        started.elapsed().as_secs_f64(),
        if external {
            " (external sources on)"
        } else {
            ""
        }
    );
}

/// Generator bugs that leave a file testing nothing: the flaw it is
/// labelled with cannot happen, whatever the input. Each was checked with
/// PHP 8.3 (`php -l`, and running the fixed part of the code).
fn broken_template(src: &str) -> Option<&'static str> {
    if src.contains("= >") {
        return Some("syntax error (`= >`), PHP refuses to run the file");
    }
    if src.contains("filter_var($sanitized") && !src.contains("$sanitized =") {
        return Some("the filter reads an unset `$sanitized`, so the input never reaches the sink");
    }
    if src.contains(". checked_data .") {
        return Some(
            "undefined constant `checked_data` stops the script before the input is printed",
        );
    }
    if src.contains("\"echo $'") || src.contains("(\"$temp = ") || src.contains("= \"$temp = ") {
        return Some("the code given to eval() is a parse error before the input (`echo $'...'`, ` = '...'`)");
    }
    if redirect_stays_on_site(src) {
        return Some("the redirect target starts with a fixed `'` or `pages/`, so the browser stays on the site");
    }
    if src.contains("$tained = escapeshellarg($tained)") {
        return Some(
            "escapeshellarg() is applied to a misspelt `$tained`, so the command is unescaped",
        );
    }
    None
}

/// Every CWE_601 template puts a fixed `'` or `pages/` before the input
/// (or a `'` before `Location`, which then is not a Location header), so
/// the target resolves to a path on the same site: with `php -S`, the
/// response to `?u=https://example.org/x` is `location: 'https://example.org/x'`,
/// which a browser resolves to `http://site/app/'https://example.org/x'`.
fn redirect_stays_on_site(src: &str) -> bool {
    let Some(start) = src.find("header(").or_else(|| src.find("http_redirect(")) else {
        return false;
    };
    let call = &src[start..];
    let Some(q) = call.find('"') else {
        return false;
    };
    let lit = &call[q + 1..];
    let target = if call.starts_with("header(") {
        if lit.starts_with('\'') {
            return true;
        }
        match lit.get(..9) {
            Some(l) if l.eq_ignore_ascii_case("location:") => lit[9..].trim_start(),
            _ => return false,
        }
    } else {
        lit
    };
    target.starts_with('\'') || target.starts_with("pages/")
}

fn read_dir(p: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(p)
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn name_of(p: &Path) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}
