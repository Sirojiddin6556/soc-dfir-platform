//! Scores the analyzer on the NIST Juliet C/C++ test suite 1.3
//! (`testcases/CWE*/[s01/]*.c|cpp`). Each test case (the files of one
//! flow variant: `_51a.c` and `_51b.c`, or `_81_bad.cpp` and
//! `_81_goodG2B.cpp`) is analyzed with the suite's support files. A finding
//! of the rule matching the CWE counts as a true positive when it points
//! into a function whose name says it is the flawed one (`bad`,
//! `badSink`, `CWE..._81_bad::action`) and as a false positive when it
//! points into a fixed one (`goodG2B`, `goodB2GSink`). Per CWE the score is
//! TPR - FPR over test cases, also split by input and by flow variant.
//!
//! cargo run --release -p code-analysis --example juliet -- DIR [--cwe CWE78]
//!     [--no-external] [--misses] [--fps] [--show NAME] [--limit N] [--other]
//!
//! `--other` lists findings of other rules, which in a test case written
//! for one flaw are false positives unless they point into a `bad` function.

use code_analysis::ir::{Function, Stmt};
use code_analysis::project::Project;
use code_analysis::Options;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// The rule that answers each CWE of the suite.
fn rule_for(cwe: &str) -> Option<&'static str> {
    Some(match cwe {
        "CWE78" => "command-injection",
        "CWE134" => "format-string",
        "CWE23" | "CWE36" => "path-traversal",
        "CWE90" => "ldap-injection",
        "CWE121" | "CWE122" | "CWE124" => "buffer-overflow",
        "CWE126" | "CWE127" => "buffer-overread",
        "CWE476" => "null-dereference",
        "CWE690" => "unchecked-null",
        _ => return None,
    })
}

struct Case {
    cwe: String,
    /// `char_connect_socket_execl`
    variant: String,
    /// `01` .. `84`
    flow: String,
    files: Vec<PathBuf>,
}

#[derive(Default)]
struct Outcome {
    bad_hit: bool,
    good_hit: bool,
    lines: Vec<String>,
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
    let flag = |name: &str| args.iter().any(|a| a == name);
    let only_cwe = opt("--cwe");
    let show = opt("--show");
    let limit: usize = opt("--limit")
        .and_then(|n| n.parse().ok())
        .unwrap_or(usize::MAX);
    let misses = flag("--misses");
    let fps = flag("--fps");
    let other = flag("--other");

    let support: Vec<(String, String)> = ["io.c", "std_testcase.h", "std_testcase_io.h"]
        .iter()
        .filter_map(|n| {
            let p = root.join("testcasesupport").join(n);
            std::fs::read_to_string(&p)
                .ok()
                .map(|s| (format!("testcasesupport/{n}"), s))
        })
        .collect();

    let mut cases: Vec<Case> = Vec::new();
    for cwe_dir in read_dir(&root.join("testcases")) {
        let dir_name = name_of(&cwe_dir);
        let cwe = dir_name.split('_').next().unwrap_or("").to_string();
        if rule_for(&cwe).is_none() || only_cwe.as_ref().is_some_and(|c| *c != cwe) {
            continue;
        }
        let mut dirs = vec![cwe_dir.clone()];
        dirs.extend(read_dir(&cwe_dir).into_iter().filter(|p| p.is_dir()));
        for d in dirs {
            let mut groups: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
            for f in read_dir(&d) {
                let name = name_of(&f);
                if !(name.ends_with(".c") || name.ends_with(".cpp") || name.ends_with(".h")) {
                    continue;
                }
                if let Some(id) = case_id(&name) {
                    groups.entry(id).or_default().push(f);
                }
            }
            for (id, files) in groups {
                if !files.iter().any(|f| !name_of(f).ends_with(".h")) {
                    continue;
                }
                let (head, flow) = id.rsplit_once('_').unwrap_or((&id, ""));
                let variant = head.split_once("__").map(|x| x.1).unwrap_or(head);
                cases.push(Case {
                    cwe: cwe.clone(),
                    variant: variant.to_string(),
                    flow: flow.to_string(),
                    files,
                });
            }
        }
    }
    if let Some(s) = &show {
        cases.retain(|c| c.files.iter().any(|f| name_of(f).contains(s.as_str())));
    }
    cases.truncate(limit);

    let options = Options {
        external_sources: !flag("--no-external"),
        ..Options::default()
    };
    let started = std::time::Instant::now();
    let results: Mutex<Vec<(usize, Outcome)>> = Mutex::new(Vec::new());
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
                    let mut sources = support.clone();
                    for f in &c.files {
                        let text = std::fs::read(f)
                            .map(|b| String::from_utf8_lossy(&b).into_owned())
                            .unwrap_or_default();
                        sources.push((name_of(f), text));
                    }
                    let project = Project::from_sources(sources);
                    let report = code_analysis::analyze_with(&project, options);
                    let rule = rule_for(&c.cwe).unwrap_or("");
                    let mut out = Outcome::default();
                    for f in &report.findings {
                        let func = enclosing_function(&project, &f.file, f.line);
                        let side = side_of(&func, &f.file);
                        if other && f.rule != rule {
                            out.lines.push(format!(
                                "OTHER {:?} {} {}:{} {}",
                                side, f.rule, f.file, f.line, f.message
                            ));
                        }
                        if f.rule == rule {
                            match side {
                                Side::Bad => out.bad_hit = true,
                                Side::Good => out.good_hit = true,
                                Side::Other => {}
                            }
                        }
                        if show.is_some() {
                            out.lines.push(format!(
                                "  {:?} {}:{} in {} [{}] {}",
                                side, f.file, f.line, func, f.rule, f.message
                            ));
                        }
                    }
                    results.lock().unwrap().push((i, out));
                })
                .expect("thread");
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|r| r.0);

    #[derive(Default, Clone, Copy)]
    struct Counts {
        cases: usize,
        tp: usize,
        fp: usize,
    }
    impl Counts {
        fn add(&mut self, o: &Outcome) {
            self.cases += 1;
            self.tp += usize::from(o.bad_hit);
            self.fp += usize::from(o.good_hit);
        }
        fn line(&self, label: &str) -> String {
            let n = self.cases.max(1) as f64;
            let tpr = self.tp as f64 / n;
            let fpr = self.fp as f64 / n;
            format!(
                "{label:<44} cases {:>5} TP {:>5} FP {:>4}  TPR {:>5.1}% FPR {:>5.1}%  score {:>5.1}%",
                self.cases,
                self.tp,
                self.fp,
                tpr * 100.0,
                fpr * 100.0,
                (tpr - fpr) * 100.0
            )
        }
    }
    let mut by_cwe: BTreeMap<String, Counts> = BTreeMap::new();
    let mut by_variant: BTreeMap<(String, String), Counts> = BTreeMap::new();
    let mut by_flow: BTreeMap<(String, String), Counts> = BTreeMap::new();
    let mut total = Counts::default();
    for (i, o) in &results {
        let c = &cases[*i];
        by_cwe.entry(c.cwe.clone()).or_default().add(o);
        by_variant
            .entry((c.cwe.clone(), source_of(&c.variant)))
            .or_default()
            .add(o);
        by_flow
            .entry((c.cwe.clone(), c.flow.clone()))
            .or_default()
            .add(o);
        total.add(o);
        let first = c.files.first().map(|f| name_of(f)).unwrap_or_default();
        if misses && !o.bad_hit {
            println!("MISS {}/{first}", c.cwe);
        }
        if fps && o.good_hit {
            println!("FP   {}/{first}", c.cwe);
        }
        if other && show.is_none() {
            for l in o.lines.iter().filter(|l| l.starts_with("OTHER")) {
                println!("{l}");
            }
        }
        if show.is_some() {
            println!(
                "{} {} bad:{} good:{}",
                c.cwe,
                c.files
                    .iter()
                    .map(|f| name_of(f))
                    .collect::<Vec<_>>()
                    .join(" "),
                o.bad_hit,
                o.good_hit
            );
            for l in &o.lines {
                println!("{l}");
            }
        }
    }
    for ((cwe, src), counts) in &by_variant {
        println!("{}", counts.line(&format!("{cwe} input {src}")));
    }
    for ((cwe, flow), counts) in &by_flow {
        if counts.tp < counts.cases || counts.fp > 0 {
            println!("{}", counts.line(&format!("{cwe} flow {flow}")));
        }
    }
    for (cwe, counts) in &by_cwe {
        println!("{}", counts.line(cwe));
    }
    println!("{}", total.line("TOTAL"));
    eprintln!(
        "{} test cases in {:.1} s{}",
        results.len(),
        started.elapsed().as_secs_f64(),
        if options.external_sources {
            " (external sources on)"
        } else {
            ""
        }
    );
}

/// `CWE78_..__char_connect_socket_execl_51` for `..._51a.c`,
/// `..._81_goodG2B.cpp` and `..._81.h`.
fn case_id(file: &str) -> Option<String> {
    let stem = file.rsplit_once('.')?.0;
    let parts: Vec<&str> = stem.split('_').collect();
    let k = parts.iter().rposition(|p| {
        p.len() >= 2 && p.as_bytes()[0].is_ascii_digit() && p.as_bytes()[1].is_ascii_digit()
    })?;
    if k < 2 {
        return None;
    }
    Some(format!("{}_{}", parts[..k].join("_"), &parts[k][..2]))
}

/// The kind of input of a functional variant: `connect_socket`, `console`.
fn source_of(variant: &str) -> String {
    for s in [
        "connect_socket",
        "listen_socket",
        "console",
        "environment",
        "file",
        "fgets",
        "fscanf",
        "rand",
        "large",
        "fixed",
        "zero",
    ] {
        if variant.contains(s) {
            return s.to_string();
        }
    }
    variant.to_string()
}

#[derive(Debug, Clone, Copy)]
enum Side {
    Bad,
    Good,
    Other,
}

fn side_of(func: &str, file: &str) -> Side {
    let f = func.to_ascii_lowercase();
    // A method of `CWE.._81_bad` or a function named `..._bad`.
    let last = f.rsplit("::").nth(1).unwrap_or("");
    for name in [last, f.rsplit("::").next().unwrap_or(&f)] {
        if name.contains("good") {
            return Side::Good;
        }
        if name.contains("bad") {
            return Side::Bad;
        }
    }
    let file = file.to_ascii_lowercase();
    if file.contains("_good") {
        Side::Good
    } else if file.contains("_bad") {
        Side::Bad
    } else {
        Side::Other
    }
}

/// The innermost function or method of `file` holding `line`.
fn enclosing_function(project: &Project, file: &str, line: u32) -> String {
    let Some(m) = project.modules.iter().find(|m| m.path == file) else {
        return String::new();
    };
    let mut best: Option<(u32, String)> = None;
    let mut visit = |f: &Function, class: Option<&str>| {
        if f.span.line <= line && line <= f.span.end_line {
            let name = match class {
                Some(c) => format!("{c}::{}", f.name),
                None => f.name.clone(),
            };
            if best.as_ref().map(|b| f.span.line >= b.0).unwrap_or(true) {
                best = Some((f.span.line, name));
            }
        }
    };
    for s in &m.ir.body {
        match s {
            Stmt::FuncDef(f) => visit(f, None),
            Stmt::ClassDef(c) => {
                for f in &c.methods {
                    visit(f, Some(&c.name));
                }
            }
            _ => {}
        }
    }
    best.map(|b| b.1).unwrap_or_default()
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
