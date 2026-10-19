//! Source code analysis of a project directory on the engine's machine.
//!
//! `code.scan` starts `code_analysis` on a directory in the background: it
//! looks for flaws in Python, Java, PHP, C/C++ and JavaScript/TypeScript
//! where user input reaches
//! a dangerous call (SQL, command, path, template, LDAP ...). `code.status`
//! reports whether it is running and, once done, the findings with the path
//! the data took from its source to the sink.
//!
//! The third-party packages the project names (manifests, lock files,
//! copied JavaScript libraries, CDN links) are checked against the OSV
//! advisories of their ecosystems in the vulnerability database; each
//! vulnerable or malicious package is a finding where its version is set.
//! `code.deps` checks them again after the database was loaded or updated.

use crate::vulndb::VulnDbService;
use chrono::Utc;
use code_analysis::deps::{DepKind, Dependency, ImportedModule};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use vulnerability_engine::cvss::Severity as CvssSeverity;
use vulnerability_engine::deps::{self as vdeps, Advisory, PackageQuery};

/// Packages and unpinned entries listed in the report, at most.
const MAX_LISTED_PACKAGES: usize = 5000;
const MAX_LISTED_UNPINNED: usize = 500;
/// Places other than the main one listed for a package, at most.
const MAX_OTHER_PLACES: usize = 50;

/// Rough size of each ecosystem's OSV export, for the download button.
fn download_mb(ecosystem: &str) -> u32 {
    match ecosystem {
        "npm" => 210,
        "PyPI" => 35,
        "Go" => 12,
        "Packagist" => 11,
        "Maven" => 10,
        "RubyGems" => 5,
        "crates.io" => 4,
        "NuGet" => 3,
        "Hex" => 1,
        "Pub" => 1,
        "SwiftURL" => 1,
        "GitHub Actions" => 1,
        _ => 10,
    }
}

#[derive(Default)]
struct ScanJob {
    running: bool,
    /// Counts runs, so a dependency check of an older run is not stored
    /// over a newer one.
    generation: u64,
    path: Option<String>,
    root: Option<PathBuf>,
    external_sources: bool,
    include_tests: bool,
    started_at: Option<String>,
    finished_at: Option<String>,
    /// The code analysis report without dependency findings.
    base: Option<Value>,
    dependencies: Vec<Dependency>,
    imports: Vec<ImportedModule>,
    report: Option<Value>,
    error: Option<String>,
}

pub struct CodeScanService {
    job: Mutex<ScanJob>,
    vulndb: Arc<VulnDbService>,
    /// Read versions of undeclared Python imports from the host's installed
    /// environment (a read-only `importlib.metadata` query). On by default;
    /// turned off in hermetic tests so the result does not depend on what
    /// happens to be installed on the test machine.
    probe_python_env: bool,
}

impl CodeScanService {
    pub fn new(vulndb: Arc<VulnDbService>) -> Self {
        Self {
            job: Mutex::new(ScanJob::default()),
            vulndb,
            probe_python_env: true,
        }
    }

    /// Like `new`, but without reading the host Python environment — for
    /// tests that must not depend on the machine's installed packages.
    #[cfg(test)]
    fn new_without_env_probe(vulndb: Arc<VulnDbService>) -> Self {
        Self {
            job: Mutex::new(ScanJob::default()),
            vulndb,
            probe_python_env: false,
        }
    }

    /// Starts analyzing the directory `path`; one analysis runs at a time.
    pub fn start(
        self: &Arc<Self>,
        path: &str,
        external_sources: bool,
        include_tests: bool,
    ) -> Result<Value, String> {
        let path = path.trim();
        if path.is_empty() {
            return Err("Укажите папку с исходным кодом".to_string());
        }
        let root =
            std::fs::canonicalize(path).map_err(|e| format!("Папка {path} недоступна: {e}"))?;
        if !root.is_dir() {
            return Err(format!("{path} не папка"));
        }
        let generation = {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.running {
                return Err("Анализ кода уже выполняется".to_string());
            }
            let generation = job.generation + 1;
            *job = ScanJob {
                running: true,
                generation,
                path: Some(shown_path(&root)),
                root: Some(root.clone()),
                external_sources,
                include_tests,
                started_at: Some(Utc::now().to_rfc3339()),
                ..ScanJob::default()
            };
            generation
        };
        let service = Arc::clone(self);
        let options = code_analysis::Options {
            external_sources,
            include_tests,
        };
        let spawned = std::thread::Builder::new()
            .name("code-scan".into())
            .spawn(move || service.run(root, options, generation));
        if let Err(e) = spawned {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            job.running = false;
            job.error = Some(format!("Не удалось запустить анализ: {e}"));
        }
        Ok(self.status())
    }

    fn run(&self, root: PathBuf, options: code_analysis::Options, generation: u64) {
        let Analyzed {
            base,
            dependencies,
            imports,
        } = match analyze(&root, options) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("code analysis of {} failed: {e}", root.display());
                let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
                job.running = false;
                job.finished_at = Some(Utc::now().to_rfc3339());
                job.error = Some(format!("Анализ не выполнен: {e}"));
                return;
            }
        };
        let report = self.compose(&root, &base, &dependencies, &imports, options.include_tests);
        let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        if job.generation != generation {
            return;
        }
        job.running = false;
        job.finished_at = Some(Utc::now().to_rfc3339());
        job.base = Some(base);
        job.dependencies = dependencies;
        job.imports = imports;
        job.report = Some(report);
    }

    /// Checks the last analysis' dependencies against the database again,
    /// after its advisories were loaded or updated.
    pub fn recheck_dependencies(&self) -> Result<Value, String> {
        let (generation, root, base, dependencies, imports, include_tests) = {
            let job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.running {
                return Err("Анализ кода ещё выполняется".to_string());
            }
            let (Some(root), Some(base)) = (job.root.clone(), job.base.clone()) else {
                return Err("Сначала проверьте проект".to_string());
            };
            (
                job.generation,
                root,
                base,
                job.dependencies.clone(),
                job.imports.clone(),
                job.include_tests,
            )
        };
        let report = self.compose(&root, &base, &dependencies, &imports, include_tests);
        {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.generation == generation && !job.running {
                job.report = Some(report);
            }
        }
        Ok(self.status())
    }

    /// The analysis report with the dependency check: vulnerable packages
    /// join the findings and `dependency_check` says what was checked.
    fn compose(
        &self,
        root: &Path,
        base: &Value,
        dependencies: &[Dependency],
        imports: &[ImportedModule],
        include_tests: bool,
    ) -> Value {
        compose_report(
            &self.vulndb,
            self.probe_python_env,
            root,
            base,
            dependencies,
            imports,
            include_tests,
        )
    }

    /// The current or last analysis; the report once it finished.
    pub fn status(&self) -> Value {
        let job = self.job.lock().unwrap_or_else(|p| p.into_inner());
        json!({
            "languages": ["python", "java", "php", "c", "cpp", "javascript", "typescript"],
            "running": job.running,
            "path": job.path,
            "external_sources": job.external_sources,
            "include_tests": job.include_tests,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "error": job.error,
            "report": job.report,
        })
    }
}

/// A project analysed into its base report (without dependency findings) and
/// the raw dependency/import lists the dependency check consumes. Shared by the
/// local code scan and the remote (SFTP-fetched) one.
pub(crate) struct Analyzed {
    pub base: Value,
    pub dependencies: Vec<Dependency>,
    pub imports: Vec<ImportedModule>,
}

/// Runs `code_analysis` on `root` and splits the dependency/import lists out of
/// the report, leaving a base report the dependency check folds its findings
/// into. The analyser produces project-relative file paths, so the result is
/// identical whether the files sit in a local folder or a temporary SFTP copy.
pub(crate) fn analyze(root: &Path, options: code_analysis::Options) -> Result<Analyzed, String> {
    code_analysis::analyze_dir_with(root, options)
        .map_err(|e| e.to_string())
        .and_then(|mut report| {
            let dependencies = std::mem::take(&mut report.dependencies);
            let imports = std::mem::take(&mut report.imports);
            let mut base = serde_json::to_value(report).map_err(|e| e.to_string())?;
            if let Some(map) = base.as_object_mut() {
                map.remove("dependencies");
                map.remove("imports");
            }
            Ok(Analyzed {
                base,
                dependencies,
                imports,
            })
        })
}

/// Folds the dependency check into the base report: vulnerable packages join
/// the findings (sorted by severity, then location) and `dependency_check`
/// records what was checked. `probe_python_env` reads the host's installed
/// Python versions — left off for a remote project, whose packages must come
/// only from the fetched source, never from the engine machine's environment.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compose_report(
    vulndb: &VulnDbService,
    probe_python_env: bool,
    root: &Path,
    base: &Value,
    dependencies: &[Dependency],
    imports: &[ImportedModule],
    include_tests: bool,
) -> Value {
    let (check, mut found) = check_dependencies(
        vulndb,
        root,
        dependencies,
        imports,
        include_tests,
        probe_python_env,
    );
    let mut report = base.clone();
    if let Some(map) = report.as_object_mut() {
        let mut findings = match map.remove("findings") {
            Some(Value::Array(list)) => list,
            _ => Vec::new(),
        };
        findings.append(&mut found);
        findings.sort_by(|a, b| {
            severity_rank(&b["severity"])
                .cmp(&severity_rank(&a["severity"]))
                .then_with(|| a["file"].as_str().cmp(&b["file"].as_str()))
                .then_with(|| a["line"].as_u64().cmp(&b["line"].as_u64()))
                .then_with(|| a["rule"].as_str().cmp(&b["rule"].as_str()))
        });
        map.insert("findings".into(), Value::Array(findings));
        map.insert("dependency_check".into(), check);
    }
    report
}

fn severity_rank(v: &Value) -> u8 {
    match v.as_str() {
        Some("critical") => 4,
        Some("high") => 3,
        Some("medium") => 2,
        _ => 1,
    }
}

/// How the project names a package, for the reader.
fn kind_label(kind: DepKind) -> &'static str {
    match kind {
        DepKind::Manifest => "файл зависимостей",
        DepKind::Lockfile => "lock-файл",
        DepKind::Bundled => "копия библиотеки в проекте",
        DepKind::Cdn => "загрузка с CDN",
        DepKind::Installed => "установлен в окружении проекта",
    }
}

fn kind_rank(kind: DepKind) -> u8 {
    match kind {
        DepKind::Manifest => 0,
        DepKind::Lockfile => 1,
        DepKind::Bundled => 2,
        DepKind::Cdn => 3,
        DepKind::Installed => 4,
    }
}

fn severity_label(severity: CvssSeverity) -> &'static str {
    match severity {
        CvssSeverity::Critical => "критическая",
        CvssSeverity::High => "высокая",
        CvssSeverity::Medium => "средняя",
        CvssSeverity::Low | CvssSeverity::None => "низкая",
        CvssSeverity::Unknown => "без оценки",
    }
}

/// Lines of the files findings point at, read once each.
struct Lines<'a> {
    root: &'a Path,
    files: HashMap<String, Vec<String>>,
}

impl Lines<'_> {
    fn line(&mut self, file: &str, line: u32) -> String {
        let root = self.root;
        let lines = self.files.entry(file.to_string()).or_insert_with(|| {
            std::fs::read(root.join(file))
                .map(|b| {
                    String::from_utf8_lossy(&b)
                        .lines()
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        });
        let text = lines
            .get(line.saturating_sub(1) as usize)
            .map(|l| l.trim())
            .unwrap_or("");
        if text.chars().count() > 240 {
            let cut: String = text.chars().take(240).collect();
            format!("{cut}…")
        } else {
            text.to_string()
        }
    }
}

/// The versions of the given top-level Python import names as installed in the
/// host's environment. It runs the host interpreter on a fixed one-line script
/// that only reads `importlib.metadata` — the project's own code is never
/// imported or executed. Returns a map `import name -> (distribution, version)`
/// and the interpreter that answered, or an empty map when none is found.
fn resolve_installed_python(
    modules: &[&str],
) -> (HashMap<String, (String, String)>, Option<String>) {
    let mut out = HashMap::new();
    if modules.is_empty() {
        return (out, None);
    }
    // Reads installed distributions (name -> version) and the authoritative
    // import -> distribution map, and prints them as JSON. Imports nothing from
    // the project.
    const SCRIPT: &str = r#"
import json, sys
try:
    import importlib.metadata as md
except Exception:
    try:
        import importlib_metadata as md
    except Exception:
        json.dump({"dists": {}, "top": {}}, sys.stdout); sys.exit(0)
dists = {}
for d in md.distributions():
    try:
        name = d.metadata["Name"]; ver = d.version
    except Exception:
        continue
    if name and ver:
        dists[name.strip().lower().replace("_", "-").replace(".", "-")] = ver
top = {}
try:
    for k, v in md.packages_distributions().items():
        top[k] = list(v)
except Exception:
    pass
json.dump({"dists": dists, "top": top}, sys.stdout)
"#;
    // Interpreters to try, in order: an explicit override, then the usual
    // names and the Windows `py` launcher.
    let mut candidates: Vec<(String, Vec<&str>)> = Vec::new();
    if let Ok(p) = std::env::var("SOC_PYTHON") {
        if !p.trim().is_empty() {
            candidates.push((p.trim().to_string(), vec![]));
        }
    }
    // On Windows the bare `python3`/`python` names are often the Microsoft
    // Store app-execution alias, which stalls when run non-interactively, so
    // try the real `py` launcher first and keep each probe short. On other
    // systems `python3` is the canonical name.
    if cfg!(windows) {
        candidates.push(("py".to_string(), vec!["-3"]));
        candidates.push(("python".to_string(), vec![]));
        candidates.push(("python3".to_string(), vec![]));
    } else {
        candidates.push(("python3".to_string(), vec![]));
        candidates.push(("python".to_string(), vec![]));
        candidates.push(("py".to_string(), vec!["-3"]));
    }

    let norm = |s: &str| s.trim().to_ascii_lowercase().replace(['_', '.'], "-");
    for (prog, pre) in &candidates {
        let Some(stdout) = run_capture(prog, pre, SCRIPT, std::time::Duration::from_secs(8)) else {
            continue;
        };
        let Ok(parsed) = serde_json::from_slice::<Value>(&stdout) else {
            continue;
        };
        let Some(dists) = parsed.get("dists").and_then(Value::as_object) else {
            continue;
        };
        let top = parsed.get("top").and_then(Value::as_object);
        for &m in modules {
            // Candidate distributions, best first: the environment's own
            // import map, then the fallback table, then the import name.
            let mut cand: Vec<String> = Vec::new();
            if let Some(list) = top.and_then(|t| t.get(m)).and_then(Value::as_array) {
                cand.extend(list.iter().filter_map(|v| v.as_str()).map(String::from));
            }
            if let Some(dist) = code_analysis::deps::python_dist_name(m) {
                cand.push(dist.to_string());
            }
            cand.push(m.to_string());
            for c in cand {
                if let Some(ver) = dists.get(&norm(&c)).and_then(Value::as_str) {
                    out.insert(m.to_string(), (c, ver.to_string()));
                    break;
                }
            }
        }
        return (out, Some(prog.clone()));
    }
    (out, None)
}

/// Runs `prog pre... -c script` with no stdin, capturing stdout, and gives up
/// after `timeout` so a stuck interpreter cannot stall the scan. `None` on any
/// failure (program missing, non-zero exit, timeout).
fn run_capture(
    prog: &str,
    pre: &[&str],
    script: &str,
    timeout: std::time::Duration,
) -> Option<Vec<u8>> {
    let mut cmd = std::process::Command::new(prog);
    cmd.args(pre)
        .arg("-c")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let (tx, rx) = std::sync::mpsc::channel();
    // `output()` drains the pipe, so a large listing cannot deadlock; the
    // thread is detached on timeout and ends when the child exits.
    std::thread::Builder::new()
        .name("python-probe".into())
        .spawn(move || {
            let _ = tx.send(cmd.output());
        })
        .ok()?;
    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) if output.status.success() => Some(output.stdout),
        _ => None,
    }
}

/// Checks the pinned packages against the database; returns the summary
/// for the report and a finding per vulnerable or malicious package.
fn check_dependencies(
    vulndb: &VulnDbService,
    root: &Path,
    dependencies: &[Dependency],
    imports: &[ImportedModule],
    include_tests: bool,
    probe_python_env: bool,
) -> (Value, Vec<Value>) {
    let is_used = |file: &str| include_tests || !code_analysis::project::is_test_path(file);
    // A project that already lists its Python packages (a manifest, a lock
    // file or a virtualenv) is taken at its word; otherwise its bare imports
    // are the only clue to its packages.
    let has_python_list = dependencies
        .iter()
        .any(|d| d.ecosystem == "PyPI" && is_used(&d.file));
    let py_imports: Vec<&ImportedModule> = imports.iter().filter(|m| is_used(&m.file)).collect();
    // Read the versions of those imports from the host's installed Python
    // environment, so a project with no manifest is still CVE-checked.
    let (resolved, interpreter) = if probe_python_env && !has_python_list && !py_imports.is_empty()
    {
        let mods: Vec<&str> = py_imports.iter().map(|m| m.module.as_str()).collect();
        resolve_installed_python(&mods)
    } else {
        (HashMap::new(), None)
    };
    check_dependencies_inner(
        vulndb,
        root,
        dependencies,
        imports,
        include_tests,
        &resolved,
        interpreter,
    )
}

/// The pure part of the dependency check: the host environment has already
/// been read into `resolved` (import name -> distribution, version). Kept
/// separate so it can be tested without depending on what is installed.
#[allow(clippy::too_many_arguments)]
fn check_dependencies_inner(
    vulndb: &VulnDbService,
    root: &Path,
    dependencies: &[Dependency],
    imports: &[ImportedModule],
    include_tests: bool,
    resolved: &HashMap<String, (String, String)>,
    interpreter: Option<String>,
) -> (Value, Vec<Value>) {
    let is_used = |file: &str| include_tests || !code_analysis::project::is_test_path(file);
    let has_python_list = dependencies
        .iter()
        .any(|d| d.ecosystem == "PyPI" && is_used(&d.file));
    let py_imports: Vec<&ImportedModule> = imports.iter().filter(|m| is_used(&m.file)).collect();
    // Each resolved import becomes a package pinned at its installed version,
    // placed where the project first imports it.
    let synthetic: Vec<Dependency> = py_imports
        .iter()
        .filter_map(|m| {
            resolved.get(&m.module).map(|(dist, ver)| Dependency {
                ecosystem: "PyPI".to_string(),
                name: dist.clone(),
                version: Some(ver.clone()),
                requirement: String::new(),
                file: m.file.clone(),
                line: m.line,
                kind: DepKind::Installed,
                dev: false,
            })
        })
        .collect();
    let all_deps: Vec<Dependency> = dependencies.iter().cloned().chain(synthetic).collect();
    let used: Vec<&Dependency> = all_deps.iter().filter(|d| is_used(&d.file)).collect();
    // One package version, wherever the project names it.
    let mut groups: BTreeMap<PackageQuery, Vec<&Dependency>> = BTreeMap::new();
    for d in &used {
        if let Some(version) = &d.version {
            groups
                .entry(PackageQuery {
                    ecosystem: d.ecosystem.clone(),
                    name: vdeps::normalize_package_name(&d.ecosystem, &d.name),
                    version: version.clone(),
                })
                .or_default()
                .push(d);
        }
    }
    for places in groups.values_mut() {
        places.sort_by(|a, b| {
            (kind_rank(a.kind), a.file.as_str(), a.line).cmp(&(
                kind_rank(b.kind),
                b.file.as_str(),
                b.line,
            ))
        });
    }
    let queries: Vec<PackageQuery> = groups.keys().cloned().collect();
    let (states, advisories, error) = if queries.is_empty() {
        (Vec::new(), Vec::new(), None)
    } else {
        match vulndb.check_dependencies(&queries) {
            Ok(check) => (check.ecosystems, check.advisories, None),
            Err(e) => (Vec::new(), Vec::new(), Some(e)),
        }
    };
    let checked_at = vulndb.osv_checked_at();

    let mut lines = Lines {
        root,
        files: HashMap::new(),
    };
    let mut findings = Vec::new();
    let mut packages = Vec::new();
    let mut vulnerable = 0usize;
    let mut advisory_total = 0usize;
    for (i, (query, places)) in groups.iter().enumerate() {
        let found: &[Advisory] = advisories.get(i).map(Vec::as_slice).unwrap_or(&[]);
        let main = places[0];
        if packages.len() < MAX_LISTED_PACKAGES {
            packages.push(json!({
                "ecosystem": query.ecosystem,
                "name": main.name,
                "version": query.version,
                "file": main.file,
                "line": main.line,
                "kind": main.kind,
                "places": places.len(),
                "advisories": found.len(),
                "malicious": found.iter().any(|a| a.malicious),
            }));
        }
        if found.is_empty() {
            continue;
        }
        vulnerable += 1;
        advisory_total += found.len();
        findings.push(dependency_finding(query, places, found, &mut lines));
    }

    // Constraints without an exact version, unless another file pins it.
    let pinned: std::collections::HashSet<(String, String)> = groups
        .keys()
        .map(|q| (q.ecosystem.clone(), q.name.clone()))
        .collect();
    let unpinned: Vec<&&Dependency> = used
        .iter()
        .filter(|d| d.version.is_none())
        .filter(|d| {
            !pinned.contains(&(
                d.ecosystem.clone(),
                vdeps::normalize_package_name(&d.ecosystem, &d.name),
            ))
        })
        .collect();

    let mut per_ecosystem: BTreeMap<&str, usize> = BTreeMap::new();
    for q in groups.keys() {
        *per_ecosystem.entry(q.ecosystem.as_str()).or_default() += 1;
    }
    let ecosystems: Vec<Value> = per_ecosystem
        .iter()
        .map(|(eco, n)| {
            let loaded = states
                .iter()
                .find(|s| s.ecosystem == *eco)
                .map(|s| s.loaded)
                .unwrap_or(false);
            json!({
                "ecosystem": eco,
                "packages": n,
                "loaded": loaded,
                "checked_at": checked_at.get(*eco),
                "download_mb": download_mb(eco),
            })
        })
        .collect();
    let missing: Vec<&str> = ecosystems
        .iter()
        .filter(|e| e["loaded"] == false)
        .filter_map(|e| e["ecosystem"].as_str())
        .collect();
    // Imports the installed environment could not resolve: still unchecked,
    // shown with the PyPI name and how to make them checkable.
    let undeclared: Vec<&ImportedModule> = if has_python_list {
        Vec::new()
    } else {
        py_imports
            .iter()
            .copied()
            .filter(|m| !resolved.contains_key(&m.module))
            .collect()
    };
    let undeclared_json: Vec<Value> = undeclared
        .iter()
        .map(|m| {
            let dist =
                code_analysis::deps::python_dist_name(&m.module).unwrap_or(m.module.as_str());
            json!({
                "module": m.module,
                "dist": dist,
                "file": m.file,
                "line": m.line,
                "files": m.files,
            })
        })
        .collect();
    // What was read from the environment, and what the user can do for the rest.
    let advice = if has_python_list || py_imports.is_empty() {
        Value::Null
    } else {
        let mut parts: Vec<String> = Vec::new();
        if !resolved.is_empty() {
            parts.push(format!(
                "Версии {} пакетов взяты из установленного окружения{} и проверены на уязвимости.",
                resolved.len(),
                interpreter
                    .as_deref()
                    .map(|i| format!(" ({i})"))
                    .unwrap_or_default()
            ));
        }
        if !undeclared.is_empty() {
            parts.push(
                "Для остальных версия не задана (нет requirements.txt). Выполните в папке проекта `pip freeze > requirements.txt` (или `pipreqs .`) и пересканируйте — тогда они тоже будут проверены."
                    .to_string(),
            );
        }
        if parts.is_empty() {
            Value::Null
        } else {
            Value::String(parts.join(" "))
        }
    };
    let summary = json!({
        "total": used.len(),
        "packages": groups.len(),
        "vulnerable": vulnerable,
        "advisories": advisory_total,
        "ecosystems": ecosystems,
        "missing": missing,
        "list": packages,
        "unpinned_total": unpinned.len(),
        "unpinned": unpinned.iter().take(MAX_LISTED_UNPINNED).map(|d| json!({
            "ecosystem": d.ecosystem,
            "name": d.name,
            "requirement": d.requirement,
            "file": d.file,
            "line": d.line,
            "kind": d.kind,
        })).collect::<Vec<_>>(),
        "undeclared_python": undeclared_json,
        "python_env": {
            "interpreter": interpreter,
            "resolved": resolved.len(),
        },
        "python_advice": advice,
        "checked_at": Utc::now().to_rfc3339(),
        "error": error,
    });
    (summary, findings)
}

/// A finding for one vulnerable or malicious package version, placed where
/// the project sets that version.
fn dependency_finding(
    query: &PackageQuery,
    places: &[&Dependency],
    advisories: &[Advisory],
    lines: &mut Lines,
) -> Value {
    let main = places[0];
    let who = format!("{} {} ({})", main.name, query.version, query.ecosystem);
    let malware: Vec<&Advisory> = advisories.iter().filter(|a| a.malicious).collect();
    let flaws: Vec<&Advisory> = advisories.iter().filter(|a| !a.malicious).collect();
    // Every place this package is listed is a dev/build dependency.
    let dev_only = places.iter().all(|d| d.dev);
    let upgrade = vdeps::upgrade_target(&query.ecosystem, advisories);
    let (rule, cwe, title, severity, message) = if let Some(m) = malware.first() {
        let mut message = format!(
            "Пакет {who} опубликован злоумышленниками ({}){}. Удалите его из проекта и проверьте машины, где он устанавливался: такой пакет мог выполнить свой код при установке.",
            m.id,
            if m.summary.is_empty() {
                String::new()
            } else {
                format!(": {}", m.summary.trim_end_matches('.'))
            }
        );
        if !flaws.is_empty() {
            message.push_str(&format!(
                " Кроме того, известных уязвимостей: {}.",
                flaws.len()
            ));
        }
        (
            "malicious-dependency",
            506,
            "Вредоносный пакет",
            "critical",
            message,
        )
    } else {
        let worst = flaws
            .iter()
            .map(|a| a.severity)
            .max()
            .unwrap_or(CvssSeverity::Unknown);
        // A flaw reachable only through dev/build tooling (every place is a
        // dev dependency) does not ship, so it sits one step below a runtime
        // flaw of the same rating.
        let severity = match (worst, dev_only) {
            (CvssSeverity::Critical, false) => "critical",
            (CvssSeverity::High, false) | (CvssSeverity::Critical, true) => "high",
            (CvssSeverity::Medium | CvssSeverity::Unknown, false) | (CvssSeverity::High, true) => {
                "medium"
            }
            (CvssSeverity::Low | CvssSeverity::None, false)
            | (
                CvssSeverity::Medium
                | CvssSeverity::Unknown
                | CvssSeverity::Low
                | CvssSeverity::None,
                true,
            ) => "low",
        };
        let listed: Vec<String> = flaws
            .iter()
            .take(5)
            .map(|a| format!("{} ({})", a.id, severity_label(a.severity)))
            .collect();
        let mut message = format!(
            "{who}: известных уязвимостей {}: {}{}.",
            flaws.len(),
            listed.join(", "),
            if flaws.len() > listed.len() {
                format!(" и ещё {}", flaws.len() - listed.len())
            } else {
                String::new()
            }
        );
        let exploited: Vec<&str> = flaws
            .iter()
            .filter(|a| a.kev.is_some())
            .map(|a| a.id.as_str())
            .collect();
        if !exploited.is_empty() {
            message.push_str(&format!(
                " Используются в реальных атаках (CISA KEV): {}.",
                exploited.join(", ")
            ));
        }
        match &upgrade {
            Some(v) => message.push_str(&format!(" Обновите до {v} или новее.")),
            None => message.push_str(
                " Исправленной версии нет хотя бы для одной из них: замените библиотеку или закройте уязвимость по её описанию.",
            ),
        }
        if dev_only {
            message.push_str(
                " Только dev-зависимость (не попадает в сборку) — риск ниже; важно для CI и машин разработчиков.",
            );
        }
        (
            "vulnerable-dependency",
            1395,
            "Уязвимая зависимость",
            severity,
            message,
        )
    };
    // The line that sets the version; lock files and `pom.xml` often put
    // the name and the version on different lines.
    let snippet = match main.kind {
        DepKind::Manifest | DepKind::Lockfile | DepKind::Cdn => {
            Some(lines.line(&main.file, main.line)).filter(|t| t.contains(query.version.as_str()))
        }
        DepKind::Bundled | DepKind::Installed => None,
    }
    .unwrap_or_else(|| format!("{} {}", main.name, query.version));
    let other_sources: Vec<Value> = places[1..]
        .iter()
        .take(MAX_OTHER_PLACES)
        .map(|d| {
            json!({
                "file": d.file,
                "line": d.line,
                "column": 1,
                "note": kind_label(d.kind),
            })
        })
        .collect();
    json!({
        "rule": rule,
        "cwe": cwe,
        "severity": severity,
        "title": title,
        "message": message,
        "file": main.file,
        "line": main.line,
        "column": 1,
        "snippet": snippet,
        "source": null,
        "trace": [],
        "other_sources": other_sources,
        "package": {
            "ecosystem": query.ecosystem,
            "name": main.name,
            "version": query.version,
            "kind": main.kind,
            "where": kind_label(main.kind),
            "requirement": main.requirement,
            "fixed_version": upgrade,
            "dev": dev_only,
        },
        "advisories": advisories,
    })
}

/// The folder as the user would write it: canonical paths on Windows carry
/// the `\\?\` prefix, which is noise for a drive path.
fn shown_path(root: &std::path::Path) -> String {
    let path = root.display().to_string();
    match path.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_string(),
        _ => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(service: &CodeScanService) -> Value {
        for _ in 0..600 {
            let s = service.status();
            if s["running"] == false {
                return s;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("analysis did not finish");
    }

    fn vulndb() -> Arc<VulnDbService> {
        Arc::new(VulnDbService::new(
            std::env::temp_dir().join(format!("code_scan_db_{}", uuid::Uuid::now_v7())),
            None,
        ))
    }

    fn project(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("code_scan_{name}_{}", uuid::Uuid::now_v7()));
        for (path, text) in files {
            let p = dir.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    #[test]
    fn reports_flaws_of_a_project_with_their_path() {
        let dir = project(
            "flask",
            &[(
                "app/views.py",
                "from flask import request\nimport os\n\n\ndef run():\n    os.system('ping ' + request.args['host'])\n",
            )],
        );
        // A SAST finding test, not a dependency test: no host-environment
        // probe, so it does not depend on (or wait on) the machine's Python.
        let service = Arc::new(CodeScanService::new_without_env_probe(vulndb()));
        let started = service.start(dir.to_str().unwrap(), false, false).unwrap();
        assert_eq!(started["running"], true);
        let s = wait(&service);
        assert_eq!(s["error"], Value::Null, "{s}");
        let findings = s["report"]["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1, "{s}");
        assert_eq!(findings[0]["rule"], "command-injection");
        assert_eq!(findings[0]["file"], "app/views.py");
        assert_eq!(findings[0]["line"], 6);
        assert!(!findings[0]["trace"].as_array().unwrap().is_empty());
        assert_eq!(s["report"]["files"], 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn shows_windows_drive_paths_without_the_verbatim_prefix() {
        assert_eq!(
            shown_path(std::path::Path::new(r"\\?\C:\src\shop")),
            r"C:\src\shop"
        );
        assert_eq!(
            shown_path(std::path::Path::new(r"\\?\UNC\server\share")),
            r"\\?\UNC\server\share"
        );
        assert_eq!(shown_path(std::path::Path::new("/srv/shop")), "/srv/shop");
    }

    #[test]
    fn refuses_missing_folders_and_a_second_run() {
        let service = Arc::new(CodeScanService::new(vulndb()));
        assert!(service.start("  ", false, false).is_err());
        let missing = std::env::temp_dir().join(format!("code_scan_none_{}", uuid::Uuid::now_v7()));
        let err = service
            .start(missing.to_str().unwrap(), false, false)
            .unwrap_err();
        assert!(err.contains("недоступна"), "{err}");

        let dir = project("busy", &[("a.py", "x = 1\n")]);
        // Hold the job as running to see the second start refused.
        service.job.lock().unwrap().running = true;
        let err = service
            .start(dir.to_str().unwrap(), false, false)
            .unwrap_err();
        assert!(err.contains("уже выполняется"), "{err}");
        service.job.lock().unwrap().running = false;
        service.start(dir.to_str().unwrap(), false, false).unwrap();
        let s = wait(&service);
        assert_eq!(s["report"]["findings"].as_array().unwrap().len(), 0, "{s}");
        std::fs::remove_dir_all(dir).ok();
    }

    fn zip_of(files: &[(&str, &str)]) -> Vec<u8> {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in files {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(body.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    const JINJA_ADVISORY: &str = r#"{
        "id": "GHSA-462w-v97r-4m45",
        "summary": "Jinja2 sandbox escape via string formatting",
        "aliases": ["CVE-2019-10906"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"}],
        "database_specific": {"severity": "HIGH"},
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "Jinja2"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]
        }]
    }"#;

    const MALWARE: &str = r#"{
        "id": "MAL-2025-1234",
        "summary": "Malicious code in left-padder (npm)",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "left-padder"},
            "versions": ["1.0.3"]
        }]
    }"#;

    #[test]
    fn dependencies_are_checked_once_their_advisories_are_loaded() {
        let dir = project(
            "deps",
            &[
                ("requirements.txt", "Jinja2==2.10\nflask>=2.0\n"),
                (
                    "package.json",
                    "{\n  \"name\": \"shop\",\n  \"dependencies\": {\n    \"left-padder\": \"1.0.3\",\n    \"lodash\": \"^4.17.0\"\n  }\n}\n",
                ),
                ("venv/pyvenv.cfg", "home = /usr/bin\n"),
                (
                    "venv/lib/python3.12/site-packages/jinja2-2.10.dist-info/METADATA",
                    "Metadata-Version: 2.1\nName: Jinja2\nVersion: 2.10\n",
                ),
                ("tests/requirements.txt", "jinja2==2.9\n"),
                ("app/main.py", "import jinja2\n"),
            ],
        );
        let offline =
            std::env::temp_dir().join(format!("code_scan_feeds_{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&offline).unwrap();
        std::fs::write(
            offline.join("PyPI.zip"),
            zip_of(&[("GHSA-462w-v97r-4m45.json", JINJA_ADVISORY)]),
        )
        .unwrap();
        std::fs::write(
            offline.join("npm.zip"),
            zip_of(&[("MAL-2025-1234.json", MALWARE)]),
        )
        .unwrap();
        let db = Arc::new(VulnDbService::new(
            std::env::temp_dir().join(format!("code_scan_db_{}", uuid::Uuid::now_v7())),
            Some(offline.clone()),
        ));
        let service = Arc::new(CodeScanService::new(db.clone()));

        service.start(dir.to_str().unwrap(), false, false).unwrap();
        let s = wait(&service);
        let check = &s["report"]["dependency_check"];
        assert_eq!(check["packages"], 2, "{check}");
        assert_eq!(check["missing"], json!(["PyPI", "npm"]), "{check}");
        assert_eq!(check["ecosystems"][0]["loaded"], false);
        assert_eq!(check["ecosystems"][0]["packages"], 1);
        assert_eq!(check["unpinned_total"], 2, "{check}");
        assert_eq!(check["unpinned"][0]["name"], "lodash");
        assert_eq!(check["unpinned"][1]["name"], "flask");
        assert_eq!(check["undeclared_python"], json!([]));
        let rules = |s: &Value| -> Vec<String> {
            s["report"]["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    format!(
                        "{} {}:{}",
                        f["rule"].as_str().unwrap(),
                        f["file"].as_str().unwrap(),
                        f["line"]
                    )
                })
                .collect()
        };
        assert!(rules(&s).iter().all(|r| !r.contains("dependency")), "{s}");
        assert!(service.recheck_dependencies().is_ok());

        db.start_update(vec!["PyPI".into(), "npm".into()], None)
            .unwrap();
        for _ in 0..600 {
            if !db.updating() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let s = service.recheck_dependencies().unwrap();
        let check = &s["report"]["dependency_check"];
        assert_eq!(check["missing"], json!([]), "{check}");
        assert_eq!(check["vulnerable"], 2);
        assert!(check["ecosystems"][0]["checked_at"].is_string());
        assert_eq!(
            rules(&s),
            vec![
                "malicious-dependency package.json:4",
                "vulnerable-dependency requirements.txt:1"
            ]
        );
        let findings = s["report"]["findings"].as_array().unwrap();
        let malware = &findings[0];
        assert_eq!(malware["severity"], "critical");
        assert_eq!(malware["cwe"], 506);
        assert_eq!(malware["snippet"], "\"left-padder\": \"1.0.3\",");
        assert!(malware["message"]
            .as_str()
            .unwrap()
            .contains("MAL-2025-1234"));
        let jinja = &findings[1];
        assert_eq!(jinja["severity"], "high");
        assert_eq!(jinja["snippet"], "Jinja2==2.10");
        assert_eq!(jinja["package"]["fixed_version"], "2.10.1");
        assert_eq!(jinja["advisories"][0]["id"], "CVE-2019-10906");
        assert_eq!(
            jinja["advisories"][0]["aliases"],
            json!(["GHSA-462w-v97r-4m45"])
        );
        let message = jinja["message"].as_str().unwrap();
        assert!(message.contains("CVE-2019-10906 (высокая)"), "{message}");
        assert!(message.contains("Обновите до 2.10.1"), "{message}");
        // The same version installed in the project's virtualenv is the
        // same finding, shown as another place; the test list is not read.
        let others = jinja["other_sources"].as_array().unwrap();
        assert_eq!(others.len(), 1, "{jinja}");
        assert_eq!(others[0]["note"], "установлен в окружении проекта");
        assert!(!s.to_string().contains("jinja2==2.9"));

        std::fs::remove_dir_all(dir).ok();
        std::fs::remove_dir_all(offline).ok();
    }

    #[test]
    fn python_code_without_a_package_list_names_its_imports() {
        let dir = project(
            "imports",
            &[
                ("main.py", "from fastapi import FastAPI\nimport os\nfrom models import User\n"),
                ("models.py", "from sqlalchemy import Column\n"),
                ("templates/base.html", "<link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">\n"),
            ],
        );
        // No host probe here, so the result does not depend on what Python
        // packages this machine happens to have installed.
        let service = Arc::new(CodeScanService::new_without_env_probe(vulndb()));
        service.start(dir.to_str().unwrap(), false, false).unwrap();
        let s = wait(&service);
        let check = &s["report"]["dependency_check"];
        let imports: Vec<&str> = check["undeclared_python"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["module"].as_str().unwrap())
            .collect();
        assert_eq!(imports, vec!["fastapi", "sqlalchemy"], "{check}");
        assert_eq!(check["list"][0]["name"], "bootstrap");
        assert_eq!(check["list"][0]["kind"], "cdn");
        assert_eq!(check["missing"], json!(["npm"]));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn installed_python_versions_are_resolved_and_the_rest_get_advice() {
        // A project with no requirements.txt that imports `cv2` and `numpy`.
        // The host environment resolved only `cv2` (to opencv-python 4.5.0);
        // `numpy` stays undeclared, named by its PyPI distribution, with a
        // how-to.
        let imports = vec![
            ImportedModule {
                module: "cv2".into(),
                file: "app/vision.py".into(),
                line: 3,
                files: 1,
            },
            ImportedModule {
                module: "numpy".into(),
                file: "app/vision.py".into(),
                line: 4,
                files: 2,
            },
        ];
        let mut resolved = HashMap::new();
        resolved.insert(
            "cv2".to_string(),
            ("opencv-python".to_string(), "4.5.0".to_string()),
        );
        let (check, _findings) = check_dependencies_inner(
            &vulndb(),
            Path::new("/tmp/does-not-matter"),
            &[],
            &imports,
            false,
            &resolved,
            Some("python3".to_string()),
        );
        // The resolved import is a pinned package, placed at its import site.
        assert_eq!(check["packages"], 1, "{check}");
        assert_eq!(check["list"][0]["name"], "opencv-python", "{check}");
        assert_eq!(check["list"][0]["version"], "4.5.0");
        assert_eq!(check["list"][0]["kind"], "installed");
        assert_eq!(check["list"][0]["file"], "app/vision.py");
        assert_eq!(check["python_env"]["resolved"], 1);
        assert_eq!(check["python_env"]["interpreter"], "python3");
        // The unresolved one keeps its import name and gains its PyPI name.
        let undeclared = check["undeclared_python"].as_array().unwrap();
        assert_eq!(undeclared.len(), 1, "{check}");
        assert_eq!(undeclared[0]["module"], "numpy");
        assert_eq!(undeclared[0]["dist"], "numpy");
        assert!(check["python_advice"]
            .as_str()
            .unwrap()
            .contains("pip freeze"));
    }
}
