//! Third-party packages a project uses, read from the files that name them:
//! manifests (`requirements.txt`, `package.json`, `pom.xml` ...), lock
//! files, packages installed next to the code (a virtualenv, a
//! `node_modules/.package-lock.json`, Composer's `vendor`), JavaScript
//! libraries copied into the project and libraries loaded from a CDN.
//! Each entry keeps the file and line that names it, so a vulnerable
//! version can be shown where it is set. Ecosystem names are OSV's.

use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

/// How the project names the package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepKind {
    /// A manifest the developer edits: `requirements.txt`, `package.json`.
    Manifest,
    /// A lock file with the resolved versions.
    Lockfile,
    /// A library file copied into the project (`static/js/jquery.min.js`).
    Bundled,
    /// A library a page loads from a CDN by URL.
    Cdn,
    /// Installed next to the code: a virtualenv, `node_modules`, `vendor`.
    Installed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dependency {
    /// OSV ecosystem: PyPI, npm, Packagist, Maven, Go, crates.io,
    /// RubyGems, NuGet.
    pub ecosystem: String,
    pub name: String,
    /// The exact version, when the file fixes one.
    pub version: Option<String>,
    /// The constraint as written (`==2.10`, `^4.17.1`), empty when none.
    pub requirement: String,
    /// Path relative to the project root, with `/` separators.
    pub file: String,
    pub line: u32,
    pub kind: DepKind,
    /// Only used while building or testing, not shipped to users: a
    /// `devDependencies`/`optionalDependencies` entry, or a lock-file entry
    /// marked `dev`. A flaw in one of these is less exposed than in a
    /// runtime dependency. Known for npm today; `false` where a manifest
    /// draws no dev/runtime line.
    #[serde(default)]
    pub dev: bool,
}

/// Lock files of big projects run to tens of megabytes.
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
/// Bundles larger than this are not searched for library banners.
const MAX_SCRIPT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TEXT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DEPENDENCIES: usize = 100_000;
const MAX_DEPTH: usize = 48;

/// Directories that never hold the project's own dependency lists.
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".tox",
    ".nox",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".pytest_cache",
    ".gradle",
    "target",
];

struct Collector<'a> {
    root: &'a Path,
    out: Vec<Dependency>,
    seen: HashSet<(String, String, Option<String>, String, u32)>,
    /// One-shot flag for the next `add`: set it right before a dev-scoped
    /// `add`, and it clears itself so the following `add` is runtime again.
    dev: bool,
}

impl Collector<'_> {
    fn rel(&self, path: &Path) -> String {
        path.strip_prefix(self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }

    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        ecosystem: &str,
        name: &str,
        version: Option<String>,
        requirement: &str,
        file: &str,
        line: u32,
        kind: DepKind,
    ) {
        let name = name.trim();
        if name.is_empty() || self.out.len() >= MAX_DEPENDENCIES {
            return;
        }
        let version = version
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let key = (
            ecosystem.to_string(),
            name.to_string(),
            version.clone(),
            file.to_string(),
            line,
        );
        let dev = std::mem::take(&mut self.dev);
        if !self.seen.insert(key) {
            return;
        }
        self.out.push(Dependency {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version,
            requirement: requirement.trim().to_string(),
            file: file.to_string(),
            line,
            kind,
            dev,
        });
    }
}

/// Finds the dependencies of the project under `root`.
pub fn collect(root: &Path) -> Vec<Dependency> {
    let mut c = Collector {
        root,
        out: Vec::new(),
        seen: HashSet::new(),
        dev: false,
    };
    walk(&mut c, root, 0);
    let mut out = c.out;
    out.sort_by(|a, b| {
        (a.file.as_str(), a.line, a.name.as_str()).cmp(&(b.file.as_str(), b.line, b.name.as_str()))
    });
    out
}

fn read_limited(path: &Path, max: u64) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > max {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn walk(c: &mut Collector, dir: &Path, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = read.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    let names: HashSet<String> = entries
        .iter()
        .map(|e| e.file_name().to_string_lossy().to_ascii_lowercase())
        .collect();
    for entry in entries {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if ft.is_dir() {
            if path.join("pyvenv.cfg").is_file() {
                python_environment(c, &path);
                continue;
            }
            match name.as_str() {
                "node_modules" => {
                    // A lock file next to it already says what is installed.
                    if ![
                        "package-lock.json",
                        "npm-shrinkwrap.json",
                        "yarn.lock",
                        "pnpm-lock.yaml",
                    ]
                    .iter()
                    .any(|l| names.contains(*l))
                    {
                        node_modules(c, &path);
                    }
                    continue;
                }
                "vendor" if path.join("composer").join("installed.json").is_file() => {
                    if !names.contains("composer.lock") {
                        composer_installed(c, &path.join("composer").join("installed.json"));
                    }
                    continue;
                }
                "site-packages" | "dist-packages" => {
                    site_packages(c, &path);
                    continue;
                }
                _ => {}
            }
            if SKIP_DIRS.contains(&name.as_str()) || (name.starts_with('.') && name.len() > 1) {
                continue;
            }
            walk(c, &path, depth + 1);
            continue;
        }
        if ft.is_file() {
            file(c, &path, &name);
        }
    }
}

fn file(c: &mut Collector, path: &Path, name: &str) {
    let lower = name.to_ascii_lowercase();
    let ext = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    let in_requirements_dir = path
        .parent()
        .and_then(|p| p.file_name())
        .is_some_and(|d| d.to_string_lossy().eq_ignore_ascii_case("requirements"));
    let manifest = |c: &mut Collector, parse: fn(&mut Collector, &str, &str)| {
        if let Some(text) = read_limited(path, MAX_MANIFEST_BYTES) {
            let rel = c.rel(path);
            parse(c, &rel, &text);
        }
    };
    let requirements = (lower.contains("requirements") || lower.starts_with("constraints"))
        && matches!(ext, "txt" | "in" | "pip")
        || in_requirements_dir && matches!(ext, "txt" | "in");
    match lower.as_str() {
        _ if requirements => manifest(c, requirements_txt),
        "pipfile" => manifest(c, pipfile),
        "pipfile.lock" => manifest(c, pipfile_lock),
        "poetry.lock" | "uv.lock" | "pdm.lock" => manifest(c, python_lock),
        "pyproject.toml" => manifest(c, pyproject),
        "package.json" => manifest(c, package_json),
        "package-lock.json" | "npm-shrinkwrap.json" => manifest(c, package_lock),
        "yarn.lock" => manifest(c, yarn_lock),
        "pnpm-lock.yaml" => manifest(c, pnpm_lock),
        "composer.json" => manifest(c, composer_json),
        "composer.lock" => manifest(c, composer_lock),
        "pom.xml" => manifest(c, pom_xml),
        "build.gradle" | "build.gradle.kts" => manifest(c, gradle),
        "gradle.lockfile" => manifest(c, gradle_lock),
        "go.mod" => manifest(c, go_mod),
        "cargo.lock" => manifest(c, cargo_lock),
        "gemfile.lock" => manifest(c, gemfile_lock),
        "packages.config" => manifest(c, packages_config),
        "packages.lock.json" => manifest(c, nuget_lock),
        "directory.packages.props" => manifest(c, msbuild),
        _ if matches!(ext, "csproj" | "fsproj" | "vbproj") => manifest(c, msbuild),
        _ if ext == "js" || ext == "mjs" || ext == "cjs" => {
            if let Some(text) = read_limited(path, MAX_SCRIPT_BYTES) {
                let rel = c.rel(path);
                bundled_script(c, &rel, name, &text);
                cdn_links(c, &rel, &text);
            }
        }
        _ if is_page(ext) => {
            if let Some(text) = read_limited(path, MAX_TEXT_BYTES) {
                let rel = c.rel(path);
                cdn_links(c, &rel, &text);
            }
        }
        _ => {}
    }
}

/// Files that may hold `<script src>` or `<link href>` tags.
fn is_page(ext: &str) -> bool {
    matches!(
        ext,
        "html"
            | "htm"
            | "xhtml"
            | "jinja"
            | "jinja2"
            | "j2"
            | "twig"
            | "tpl"
            | "mustache"
            | "hbs"
            | "handlebars"
            | "ejs"
            | "erb"
            | "jsp"
            | "jspx"
            | "vue"
            | "svelte"
            | "njk"
            | "liquid"
            | "cshtml"
            | "razor"
            | "php"
            | "phtml"
            | "py"
            | "ts"
            | "tsx"
            | "jsx"
    )
}

fn line_at(text: &str, offset: usize) -> u32 {
    let offset = offset.min(text.len());
    text.as_bytes()[..offset]
        .iter()
        .filter(|b| **b == b'\n')
        .count() as u32
        + 1
}

/// Line of the first occurrence of `needle`, or 1.
fn line_of(text: &str, needle: &str) -> u32 {
    text.find(needle).map(|o| line_at(text, o)).unwrap_or(1)
}

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("dependency pattern"))
}

// ---------------------------------------------------------------- Python

/// A PEP 508 requirement: name, extras, version specifiers, markers.
/// Returns the name, the specifier as written and the pinned version.
fn pep508(text: &str) -> Option<(String, String, Option<String>)> {
    static NAME: OnceLock<Regex> = OnceLock::new();
    let text = text.split(';').next().unwrap_or(text).trim();
    let caps = re(
        &NAME,
        r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$",
    )
    .captures(text)?;
    let name = caps.get(1)?.as_str().to_string();
    let spec = caps.get(3).map_or("", |m| m.as_str()).trim();
    // Prose is not a requirement: after the name comes an operator or nothing.
    if !spec.is_empty() && !spec.starts_with(['<', '>', '=', '!', '~', '@', '(', ',']) {
        return None;
    }
    if spec.starts_with('@') {
        // `name @ https://...`: a URL, not a version from the index.
        return Some((name, spec.to_string(), None));
    }
    let spec = spec.trim_start_matches('(').trim_end_matches(')').trim();
    let pinned = spec.split(',').find_map(|clause| {
        let clause = clause.trim();
        let v = clause
            .strip_prefix("===")
            .or_else(|| clause.strip_prefix("=="))?
            .trim();
        (!v.is_empty() && !v.contains('*') && !v.contains(' ')).then(|| v.to_string())
    });
    Some((name, spec.to_string(), pinned))
}

fn requirements_txt(c: &mut Collector, file: &str, text: &str) {
    // A text file named like a requirements file but holding prose (a
    // document about constraints) names no packages.
    let mut found = Vec::new();
    let mut prose = 0usize;
    let mut pending = String::new();
    let mut start = 0u32;
    for (i, raw) in text.lines().enumerate() {
        if pending.is_empty() {
            start = i as u32 + 1;
        }
        let line = match raw.find(" #").or_else(|| raw.find("\t#")) {
            Some(at) => &raw[..at],
            None if raw.trim_start().starts_with('#') => "",
            None => raw,
        };
        if let Some(cont) = line.trim_end().strip_suffix('\\') {
            pending.push_str(cont);
            pending.push(' ');
            continue;
        }
        pending.push_str(line);
        let full = std::mem::take(&mut pending);
        let full = full.trim();
        if full.is_empty() || full.starts_with('-') || full.contains("://") && !full.contains('@') {
            continue;
        }
        // Per-requirement options: `pkg==1.0 --hash=sha256:...`.
        let full = full.split(" --").next().unwrap_or(full);
        match pep508(full) {
            Some(found_one) => found.push((found_one, start)),
            None => prose += 1,
        }
    }
    if prose > found.len() {
        return;
    }
    for ((name, spec, pinned), line) in found {
        c.add("PyPI", &name, pinned, &spec, file, line, DepKind::Manifest);
    }
}

/// `[section]` headers of a TOML file with the lines under each.
fn toml_sections(text: &str) -> Vec<(String, Vec<(u32, &str)>)> {
    let mut out: Vec<(String, Vec<(u32, &str)>)> = vec![(String::new(), Vec::new())];
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.starts_with('[') && !t.starts_with("[[") && t.ends_with(']') && !t.contains('=') {
            let name = t.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            out.push((name, Vec::new()));
        } else if t.starts_with("[[") {
            out.push((t.to_string(), Vec::new()));
        } else if let Some(last) = out.last_mut() {
            last.1.push((i as u32 + 1, line));
        }
    }
    out
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches(|c| c == '"' || c == '\'')
}

/// `name = "spec"` or `name = { version = "spec", ... }` of a TOML table.
fn toml_key_spec(line: &str) -> Option<(String, String)> {
    let (key, value) = line.split_once('=')?;
    let key = unquote(key).to_string();
    let value = value.trim();
    let spec = if value.starts_with('{') {
        static VERSION: OnceLock<Regex> = OnceLock::new();
        let caps = re(&VERSION, r#"version\s*=\s*["']([^"']*)["']"#).captures(value)?;
        caps.get(1)?.as_str().to_string()
    } else if value.starts_with('"') || value.starts_with('\'') {
        unquote(value).to_string()
    } else {
        return None;
    };
    Some((key, spec))
}

fn pipfile(c: &mut Collector, file: &str, text: &str) {
    for (section, lines) in toml_sections(text) {
        if section != "packages" && section != "dev-packages" {
            continue;
        }
        for (n, line) in lines {
            let Some((name, spec)) = toml_key_spec(line) else {
                continue;
            };
            let pinned = spec
                .strip_prefix("==")
                .filter(|v| !v.contains('*'))
                .map(str::to_string);
            c.add("PyPI", &name, pinned, &spec, file, n, DepKind::Manifest);
        }
    }
}

fn pipfile_lock(c: &mut Collector, file: &str, text: &str) {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return;
    };
    for section in ["default", "develop"] {
        let Some(map) = json.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, info) in map {
            let Some(spec) = info.get("version").and_then(Value::as_str) else {
                continue;
            };
            let pinned = spec.strip_prefix("==").map(str::to_string);
            let line = line_of(text, &format!("\"{name}\": {{"));
            c.add("PyPI", name, pinned, spec, file, line, DepKind::Lockfile);
        }
    }
}

/// `[[package]]` tables of poetry.lock, uv.lock and pdm.lock.
fn python_lock(c: &mut Collector, file: &str, text: &str) {
    let mut name: Option<(String, u32)> = None;
    let mut version: Option<String> = None;
    let mut local = false;
    let mut flush =
        |name: &mut Option<(String, u32)>, version: &mut Option<String>, local: bool| {
            if let (Some((n, line)), Some(v)) = (name.take(), version.take()) {
                if !local {
                    c.add(
                        "PyPI",
                        &n,
                        Some(v.clone()),
                        &v,
                        file,
                        line,
                        DepKind::Lockfile,
                    );
                }
            }
        };
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t == "[[package]]" {
            flush(&mut name, &mut version, local);
            local = false;
            continue;
        }
        if t.starts_with("[[") || (t.starts_with('[') && !t.starts_with("[package")) {
            continue;
        }
        if let Some(v) = t.strip_prefix("name =") {
            if name.is_none() {
                name = Some((unquote(v).to_string(), i as u32 + 1));
            }
        } else if let Some(v) = t.strip_prefix("version =") {
            if version.is_none() {
                version = Some(unquote(v).to_string());
            }
        } else if t.starts_with("source =") || t.starts_with("type =") {
            // uv: `source = { editable = "." }`; poetry: `[package.source] type = "git"`.
            local |= [
                "editable",
                "virtual",
                "directory",
                "\"git\"",
                "git =",
                "path",
                "\"file\"",
                "\"url\"",
            ]
            .iter()
            .any(|k| t.contains(k));
        }
    }
    flush(&mut name, &mut version, local);
}

/// Quoted strings of a TOML array that starts on `lines[from]`.
fn toml_array_items<'a>(lines: &[(u32, &'a str)], from: usize) -> Vec<(u32, &'a str)> {
    static ITEM: OnceLock<Regex> = OnceLock::new();
    let item = re(&ITEM, r#""([^"]*)"|'([^']*)'"#);
    let mut out = Vec::new();
    for (n, line) in &lines[from..] {
        let body = if out.is_empty() && line.contains('[') {
            &line[line.find('[').map_or(0, |i| i + 1)..]
        } else {
            line
        };
        let body = body.split('#').next().unwrap_or(body);
        for caps in item.captures_iter(body) {
            if let Some(m) = caps.get(1).or_else(|| caps.get(2)) {
                out.push((*n, m.as_str()));
            }
        }
        if body.contains(']') {
            break;
        }
    }
    out
}

fn pyproject(c: &mut Collector, file: &str, text: &str) {
    for (section, lines) in toml_sections(text) {
        if section == "project" || section == "project.optional-dependencies" {
            for (i, (_, line)) in lines.iter().enumerate() {
                let t = line.trim_start();
                let array = if section == "project" {
                    t.starts_with("dependencies") && t.contains('=')
                } else {
                    t.contains('=') && t.contains('[')
                };
                if !array {
                    continue;
                }
                for (n, req) in toml_array_items(&lines, i) {
                    if let Some((name, spec, pinned)) = pep508(req) {
                        c.add("PyPI", &name, pinned, &spec, file, n, DepKind::Manifest);
                    }
                }
            }
        } else if section == "tool.poetry.dependencies"
            || section == "tool.poetry.dev-dependencies"
            || (section.starts_with("tool.poetry.group.") && section.ends_with(".dependencies"))
        {
            for (n, line) in lines {
                let Some((name, spec)) = toml_key_spec(line) else {
                    continue;
                };
                if name == "python" {
                    continue;
                }
                // Poetry reads a bare `1.2.3` as `^1.2.3`; only `==` pins.
                let pinned = spec
                    .strip_prefix("==")
                    .filter(|v| !v.contains('*'))
                    .map(|v| v.trim().to_string());
                c.add("PyPI", &name, pinned, &spec, file, n, DepKind::Manifest);
            }
        }
    }
}

/// Packages installed in a virtualenv next to the code.
fn python_environment(c: &mut Collector, venv: &Path) {
    for lib in ["lib", "Lib", "lib64"] {
        let dir = venv.join(lib);
        if lib == "Lib" {
            site_packages(c, &dir.join("site-packages"));
            continue;
        }
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut pythons: Vec<_> = read.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        pythons.sort();
        for python in pythons {
            site_packages(c, &python.join("site-packages"));
        }
    }
}

/// `*.dist-info/METADATA` and `*.egg-info/PKG-INFO` of a site-packages
/// directory: what pip installed.
fn site_packages(c: &mut Collector, dir: &Path) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = read.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for entry in entries {
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let meta = if name.ends_with(".dist-info") {
            entry.join("METADATA")
        } else if name.ends_with(".egg-info") {
            if entry.is_dir() {
                entry.join("PKG-INFO")
            } else {
                entry.clone()
            }
        } else {
            continue;
        };
        let Some(text) = read_limited(&meta, 4 * 1024 * 1024) else {
            continue;
        };
        let mut pkg = None;
        let mut version = None;
        for (i, line) in text.lines().enumerate() {
            if line.is_empty() {
                break;
            }
            if let Some(v) = line.strip_prefix("Name:") {
                pkg = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Version:") {
                version = Some((v.trim().to_string(), i as u32 + 1));
            }
        }
        if let (Some(pkg), Some((version, line))) = (pkg, version) {
            let rel = c.rel(&meta);
            c.add(
                "PyPI",
                &pkg,
                Some(version.clone()),
                &version,
                &rel,
                line,
                DepKind::Installed,
            );
        }
    }
}

// -------------------------------------------------------------- JavaScript

/// A version npm installs exactly: `1.2.3`, `=1.2.3`, `v1.2.3-beta.1`.
fn exact_semver(spec: &str) -> Option<String> {
    static EXACT: OnceLock<Regex> = OnceLock::new();
    let s = spec.trim();
    let caps = re(
        &EXACT,
        r"^=?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$",
    )
    .captures(s)?;
    Some(caps.get(1)?.as_str().to_string())
}

fn package_json(c: &mut Collector, file: &str, text: &str) {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return;
    };
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(map) = json.get(section).and_then(Value::as_object) else {
            continue;
        };
        let section_at = text.find(&format!("\"{section}\"")).unwrap_or(0);
        for (name, spec) in map {
            let Some(spec) = spec.as_str() else { continue };
            // `"alias": "npm:real-name@1.2.3"`
            let (pkg, version_spec) = match spec.strip_prefix("npm:") {
                Some(alias) => match alias.rfind('@').filter(|i| *i > 0) {
                    Some(at) => (&alias[..at], &alias[at + 1..]),
                    None => (alias, ""),
                },
                None => (name.as_str(), spec),
            };
            if [
                "file:",
                "link:",
                "git",
                "github:",
                "http:",
                "https:",
                "workspace:",
                "portal:",
            ]
            .iter()
            .any(|p| version_spec.starts_with(p))
            {
                continue;
            }
            let line = text[section_at..]
                .find(&format!("\"{name}\""))
                .map(|o| line_at(text, section_at + o))
                .unwrap_or(1);
            c.dev = section != "dependencies";
            c.add(
                "npm",
                pkg,
                exact_semver(version_spec),
                spec,
                file,
                line,
                DepKind::Manifest,
            );
        }
    }
}

/// `"node_modules/a/node_modules/b"` -> `b` (scoped names keep their scope).
fn npm_name_from_path(key: &str) -> Option<&str> {
    let at = key.rfind("node_modules/")?;
    let name = &key[at + "node_modules/".len()..];
    (!name.is_empty()).then_some(name)
}

/// Lines of `"node_modules/...": {` keys of a lock file, found in one pass.
fn npm_key_lines(text: &str) -> std::collections::HashMap<&str, u32> {
    let mut out = std::collections::HashMap::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix('"') {
            if let Some(end) = rest.find('"') {
                out.entry(&rest[..end]).or_insert(i as u32 + 1);
            }
        }
    }
    out
}

fn package_lock_with(c: &mut Collector, file: &str, text: &str, kind: DepKind) {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let lines = npm_key_lines(text);
    if let Some(packages) = json.get("packages").and_then(Value::as_object) {
        for (key, info) in packages {
            let Some(name) = npm_name_from_path(key) else {
                continue;
            };
            if info.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            // An alias installs another package under this name.
            let name = info.get("name").and_then(Value::as_str).unwrap_or(name);
            let Some(version) = info.get("version").and_then(Value::as_str) else {
                continue;
            };
            let Some(exact) = exact_semver(version) else {
                continue;
            };
            let line = lines.get(key.as_str()).copied().unwrap_or(1);
            c.dev = info.get("dev").and_then(Value::as_bool) == Some(true)
                || info.get("devOptional").and_then(Value::as_bool) == Some(true);
            c.add("npm", name, Some(exact), version, file, line, kind);
        }
        return;
    }
    // Lock file version 1: nested `dependencies`.
    fn nested(
        c: &mut Collector,
        file: &str,
        lines: &std::collections::HashMap<&str, u32>,
        deps: &serde_json::Map<String, Value>,
        kind: DepKind,
        depth: usize,
    ) {
        if depth > 64 {
            return;
        }
        for (name, info) in deps {
            if let Some(version) = info.get("version").and_then(Value::as_str) {
                if let Some(exact) = exact_semver(version) {
                    let line = lines.get(name.as_str()).copied().unwrap_or(1);
                    c.dev = info.get("dev").and_then(Value::as_bool) == Some(true);
                    c.add("npm", name, Some(exact), version, file, line, kind);
                }
            }
            if let Some(inner) = info.get("dependencies").and_then(Value::as_object) {
                nested(c, file, lines, inner, kind, depth + 1);
            }
        }
    }
    if let Some(deps) = json.get("dependencies").and_then(Value::as_object) {
        nested(c, file, &lines, deps, kind, 0);
    }
}

fn package_lock(c: &mut Collector, file: &str, text: &str) {
    package_lock_with(c, file, text, DepKind::Lockfile);
}

/// npm name and version from a yarn/pnpm spec: `@scope/name@1.2.3`.
fn split_at_version(spec: &str) -> Option<(&str, &str)> {
    let at = spec[1..].rfind('@')? + 1;
    Some((&spec[..at], &spec[at + 1..]))
}

fn yarn_lock(c: &mut Collector, file: &str, text: &str) {
    let mut current: Option<(String, u32)> = None;
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            current = None;
            let header = line.trim_end().trim_end_matches(':');
            let first = header.split(", ").next().unwrap_or(header);
            let first = unquote(first);
            if first == "__metadata" {
                continue;
            }
            if let Some((name, _)) = split_at_version(first) {
                current = Some((name.to_string(), i as u32 + 1));
            }
            continue;
        }
        let t = line.trim();
        let version = t
            .strip_prefix("version:")
            .or_else(|| t.strip_prefix("version "))
            .map(unquote);
        if let (Some(v), Some((name, line))) = (version, current.as_ref()) {
            if let Some(exact) = exact_semver(v) {
                if !exact.ends_with("use.local") {
                    c.add("npm", name, Some(exact), v, file, *line, DepKind::Lockfile);
                }
            }
        }
    }
}

fn pnpm_lock(c: &mut Collector, file: &str, text: &str) {
    let mut in_packages = false;
    for (i, line) in text.lines().enumerate() {
        if !line.starts_with(' ') && !line.is_empty() {
            in_packages = line.trim_end() == "packages:" || line.trim_end() == "snapshots:";
            continue;
        }
        if !in_packages || !line.starts_with("  ") || line.starts_with("   ") {
            continue;
        }
        let key = unquote(line.trim().trim_end_matches(':'));
        let key = key.strip_prefix('/').unwrap_or(key);
        // Peer dependency suffixes: `react-dom@18.2.0(react@18.2.0)`, `_react@18`.
        let key = key.split('(').next().unwrap_or(key);
        let (name, version) = match split_at_version(key) {
            Some(pair) => pair,
            // pnpm 5: `/name/1.2.3`
            None => match key.rfind('/') {
                Some(at) => (&key[..at], &key[at + 1..]),
                None => continue,
            },
        };
        let version = version.split('_').next().unwrap_or(version);
        if let Some(exact) = exact_semver(version) {
            c.add(
                "npm",
                name,
                Some(exact),
                version,
                file,
                i as u32 + 1,
                DepKind::Lockfile,
            );
        }
    }
}

/// `node_modules` without a lock file beside it: npm's hidden lock file,
/// else the packages' own `package.json`.
fn node_modules(c: &mut Collector, dir: &Path) {
    let hidden = dir.join(".package-lock.json");
    if let Some(text) = read_limited(&hidden, MAX_MANIFEST_BYTES) {
        let rel = c.rel(&hidden);
        package_lock_with(c, &rel, &text, DepKind::Installed);
        return;
    }
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut dirs: Vec<_> = read.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    dirs.sort();
    let mut packages = Vec::new();
    for d in dirs {
        let name = d.file_name().map(|n| n.to_string_lossy().into_owned());
        match name {
            Some(n) if n.starts_with('@') => {
                if let Ok(scoped) = std::fs::read_dir(&d) {
                    let mut inner: Vec<_> =
                        scoped.filter_map(|e| e.ok()).map(|e| e.path()).collect();
                    inner.sort();
                    packages.extend(inner);
                }
            }
            Some(n) if !n.starts_with('.') => packages.push(d),
            _ => {}
        }
    }
    for pkg in packages.into_iter().take(20_000) {
        let manifest = pkg.join("package.json");
        let Some(text) = read_limited(&manifest, 4 * 1024 * 1024) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let (Some(name), Some(version)) = (
            json.get("name").and_then(Value::as_str),
            json.get("version").and_then(Value::as_str),
        ) else {
            continue;
        };
        if let Some(exact) = exact_semver(version) {
            let rel = c.rel(&manifest);
            let line = line_of(&text, "\"version\"");
            c.add(
                "npm",
                name,
                Some(exact),
                version,
                &rel,
                line,
                DepKind::Installed,
            );
        }
    }
}

/// A library recognized by its file name or the banner it carries.
struct Library {
    npm: &'static str,
    /// File name stem before the version: `jquery` for `jquery-3.4.1.min.js`.
    file: &'static [&'static str],
    /// Patterns with the version as the first group.
    banners: &'static [&'static str],
    /// The banners only count in files whose name contains one of these.
    only_in: &'static [&'static str],
}

const V: &str = r"(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z][0-9A-Za-z.]*)?)";

const LIBRARIES: &[Library] = &[
    Library {
        npm: "jquery",
        file: &["jquery"],
        banners: &[
            r"/\*!?\s*jQuery v{V}",
            r"\*\s*jQuery JavaScript Library v{V}",
        ],
        only_in: &[],
    },
    Library {
        npm: "jquery-ui",
        file: &["jquery-ui", "jquery.ui"],
        banners: &[r"/\*!\s*jQuery UI - v{V}", r"\*\s*jQuery UI (?:Core )?{V}"],
        only_in: &[],
    },
    Library {
        npm: "jquery-migrate",
        file: &["jquery-migrate"],
        banners: &[r"jQuery Migrate - v{V}", r"jQuery Migrate v{V}"],
        only_in: &[],
    },
    Library {
        npm: "jquery-validation",
        file: &["jquery.validate", "jquery-validate"],
        banners: &[r"jQuery Validation Plugin (?:- )?v{V}"],
        only_in: &[],
    },
    Library {
        npm: "bootstrap",
        file: &["bootstrap"],
        banners: &[
            r"\*\s*Bootstrap v{V} \(https?://getbootstrap\.com",
            r"\*\s*bootstrap\.js v{V}",
            r"\*\s*Bootstrap: [\w.-]+\.js v{V}",
        ],
        only_in: &[],
    },
    Library {
        npm: "angular",
        file: &["angular"],
        banners: &[r"@license AngularJS v{V}", r"\*\s*AngularJS v{V}"],
        only_in: &[],
    },
    Library {
        npm: "vue",
        file: &["vue"],
        banners: &[r"\*\s*Vue\.js v{V}"],
        only_in: &[],
    },
    Library {
        npm: "react",
        file: &[],
        banners: &[r"@license React v{V}\s*\*\s*react\.(?:production|development)"],
        only_in: &[],
    },
    Library {
        npm: "react-dom",
        file: &[],
        banners: &[r"@license React v{V}\s*\*\s*react-dom\.(?:production|development)"],
        only_in: &[],
    },
    Library {
        npm: "lodash",
        file: &["lodash"],
        banners: &[
            r"@license\s*\*?\s*(?:lodash|Lodash|Lo-Dash) v?{V}",
            r#"@license\s*\*\s*(?:lodash|Lodash|Lo-Dash)\b[\s\S]{0,1500}?var VERSION\s*=\s*['"]{V}['"]"#,
            r#"[A-Za-z$_]{1,2}="{V}",[A-Za-z$_]{1,2}=200,"#,
            r#"\.VERSION="{V}",[A-Za-z$_]{1,3}\("bind bindKey curry"#,
        ],
        only_in: &[],
    },
    Library {
        npm: "underscore",
        file: &["underscore"],
        banners: &[r"(?m)^\s*//\s*Underscore\.js {V}"],
        only_in: &[],
    },
    Library {
        npm: "moment",
        file: &["moment"],
        banners: &[r"//! moment\.js\s*\n\s*//! version : {V}"],
        only_in: &[],
    },
    Library {
        npm: "handlebars",
        file: &["handlebars"],
        banners: &[r"@license\s*\n?\s*handlebars v{V}", r"\*\s*handlebars v{V}"],
        only_in: &[],
    },
    Library {
        npm: "dompurify",
        file: &["purify", "dompurify"],
        banners: &[
            r"@license DOMPurify {V}",
            r"DOMPurify {V} \|",
            r#"\.version\s*=\s*['"]{V}['"],\s*[A-Za-z$_]{1,3}\.removed\s*=\s*\[\]"#,
        ],
        only_in: &[],
    },
    Library {
        npm: "axios",
        file: &["axios"],
        banners: &[r"/\*!?\s*Axios v{V}", r"\*\s*axios v{V}"],
        only_in: &[],
    },
    Library {
        npm: "chart.js",
        file: &["chart"],
        banners: &[r"\*\s*Chart\.js v{V}"],
        only_in: &[],
    },
    Library {
        npm: "knockout",
        file: &["knockout"],
        banners: &[r"Knockout JavaScript library v{V}"],
        only_in: &[],
    },
    Library {
        npm: "backbone",
        file: &["backbone"],
        banners: &[
            r"(?m)^\s*//\s*Backbone\.js {V}",
            r#"Backbone\.VERSION\s*=\s*['"]{V}['"]"#,
            r#"[A-Za-z$_]{1,2}\.VERSION="{V}";[A-Za-z$_]{1,2}\.\$=[A-Za-z$_]{1,2};[A-Za-z$_]{1,2}\.noConflict"#,
        ],
        only_in: &[],
    },
    Library {
        npm: "tinymce",
        file: &[],
        banners: &[r"\*\s*TinyMCE version {V}"],
        only_in: &[],
    },
    Library {
        npm: "tinymce",
        file: &[],
        banners: &[r"\A\s*// {V} \(\d{4}-\d\d-\d\d\)"],
        only_in: &["tinymce"],
    },
    Library {
        npm: "highcharts",
        file: &["highcharts"],
        banners: &[r"Highcharts JS v{V}"],
        only_in: &[],
    },
    Library {
        npm: "marked",
        file: &["marked"],
        banners: &[r"\*\s*marked v{V} - a markdown parser"],
        only_in: &[],
    },
    Library {
        npm: "select2",
        file: &["select2"],
        banners: &[r"\*!?\s*Select2 {V}"],
        only_in: &[],
    },
    Library {
        npm: "datatables.net",
        file: &["jquery.datatables", "datatables"],
        banners: &[r"/\*! DataTables {V}", r"(?m)^\s*\*?\s*DataTables {V}\s*$"],
        only_in: &[],
    },
];

struct CompiledLibrary {
    npm: &'static str,
    banners: Vec<Regex>,
    only_in: &'static [&'static str],
}

fn libraries() -> &'static [CompiledLibrary] {
    static LIBS: OnceLock<Vec<CompiledLibrary>> = OnceLock::new();
    LIBS.get_or_init(|| {
        LIBRARIES
            .iter()
            .map(|l| CompiledLibrary {
                npm: l.npm,
                banners: l
                    .banners
                    .iter()
                    .map(|b| Regex::new(&b.replace("{V}", V)).expect("library banner"))
                    .collect(),
                only_in: l.only_in,
            })
            .collect()
    })
}

/// `jquery-3.4.1.min.js` -> (`jquery`, `3.4.1`).
fn library_from_file_name(name: &str) -> Option<(&'static str, String)> {
    static FILE: OnceLock<Regex> = OnceLock::new();
    let caps = re(
        &FILE,
        r"(?i)^([a-z][a-z.-]*?)[-.@]v?(\d+\.\d+\.\d+(?:-[0-9a-z.]+?)?)(?:\.slim)?(?:\.min)?(?:\.js)$",
    )
    .captures(name)?;
    let stem = caps.get(1)?.as_str().to_ascii_lowercase();
    let lib = LIBRARIES.iter().find(|l| l.file.contains(&stem.as_str()))?;
    Some((lib.npm, caps.get(2)?.as_str().to_string()))
}

fn bundled_script(c: &mut Collector, file: &str, name: &str, text: &str) {
    let mut found: Vec<&'static str> = Vec::new();
    let lower = name.to_ascii_lowercase();
    for lib in libraries() {
        if found.contains(&lib.npm)
            || !lib.only_in.is_empty() && !lib.only_in.iter().any(|h| lower.contains(h))
        {
            continue;
        }
        for banner in &lib.banners {
            if let Some(caps) = banner.captures(text) {
                let m = caps.get(1).expect("version group");
                let line = line_at(text, m.start());
                c.add(
                    "npm",
                    lib.npm,
                    Some(m.as_str().to_string()),
                    m.as_str(),
                    file,
                    line,
                    DepKind::Bundled,
                );
                found.push(lib.npm);
                break;
            }
        }
    }
    if let Some((npm, version)) = library_from_file_name(name) {
        if !found.contains(&npm) {
            c.add(
                "npm",
                npm,
                Some(version.clone()),
                &version,
                file,
                1,
                DepKind::Bundled,
            );
        }
    }
}

/// npm names of libraries as CDNs spell them.
fn cdn_package(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mapped = match lower.as_str() {
        "twitter-bootstrap" => "bootstrap",
        "jqueryui" | "jquery.ui" => "jquery-ui",
        "angularjs" | "angular.js" => "angular",
        "lodash.js" => "lodash",
        "moment.js" => "moment",
        "underscore.js" => "underscore",
        "handlebars.js" => "handlebars",
        "backbone.js" => "backbone",
        "jquery-validate" | "jquery.validate" => "jquery-validation",
        "datatables" => "datatables.net",
        "vue.js" => "vue",
        "knockout.js" => "knockout",
        other => other.strip_suffix(".js").unwrap_or(other),
    };
    mapped.to_string()
}

/// Libraries a page loads from a CDN with the version in the URL.
fn cdn_links(c: &mut Collector, file: &str, text: &str) {
    static CDN: OnceLock<Regex> = OnceLock::new();
    let cdn = CDN.get_or_init(|| {
        let alternatives = [
            r#"//(?:cdn\.jsdelivr\.net/npm|unpkg\.com)/(?P<npm>(?:@[\w.-]+/)?[\w.-]+)@(?P<npmv>\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)(?:[/"'\s?#]|$)"#,
            r"//cdnjs\.cloudflare\.com/ajax/libs/(?P<cdnjs>[\w.-]+)/(?P<cdnjsv>\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)/",
            r"//ajax\.googleapis\.com/ajax/libs/(?P<google>[\w.-]+)/(?P<googlev>\d+\.\d+(?:\.\d+)?)/",
            r"//code\.jquery\.com/(?:ui/(?P<jqui>\d+\.\d+\.\d+)/|jquery-(?P<jq>\d+\.\d+\.\d+)(?:\.slim)?(?:\.min)?\.js|jquery-migrate-(?P<jqm>\d+\.\d+\.\d+)(?:\.min)?\.js)",
            r"//(?:stackpath|maxcdn|netdna)\.bootstrapcdn\.com/(?P<bscdn>bootstrap|twitter-bootstrap)/(?P<bscdnv>\d+\.\d+\.\d+)/",
            r"//ajax\.aspnetcdn\.com/ajax/(?:jquery/jquery-(?P<msjq>\d+\.\d+\.\d+)(?:\.min)?\.js|jquery\.ui/(?P<msjqui>\d+\.\d+\.\d+)/|bootstrap/(?P<msbs>\d+\.\d+\.\d+)/)",
        ];
        Regex::new(&alternatives.join("|")).expect("CDN pattern")
    });
    for caps in cdn.captures_iter(text) {
        let pick = |n: &str| caps.name(n).map(|m| (m.as_str(), m.start()));
        let found = if let (Some((name, _)), Some((v, at))) = (pick("npm"), pick("npmv")) {
            Some((name.to_string(), v, at))
        } else if let (Some((name, _)), Some((v, at))) = (pick("cdnjs"), pick("cdnjsv")) {
            Some((cdn_package(name), v, at))
        } else if let (Some((name, _)), Some((v, at))) = (pick("google"), pick("googlev")) {
            Some((cdn_package(name), v, at))
        } else if let (Some((name, _)), Some((v, at))) = (pick("bscdn"), pick("bscdnv")) {
            Some((cdn_package(name), v, at))
        } else if let Some((v, at)) = pick("jqui").or_else(|| pick("msjqui")) {
            Some(("jquery-ui".to_string(), v, at))
        } else if let Some((v, at)) = pick("jq").or_else(|| pick("msjq")) {
            Some(("jquery".to_string(), v, at))
        } else if let Some((v, at)) = pick("jqm") {
            Some(("jquery-migrate".to_string(), v, at))
        } else if let Some((v, at)) = pick("msbs") {
            Some(("bootstrap".to_string(), v, at))
        } else {
            None
        };
        if let Some((name, version, at)) = found {
            let line = line_at(text, at);
            c.add(
                "npm",
                &name,
                Some(version.to_string()),
                version,
                file,
                line,
                DepKind::Cdn,
            );
        }
    }
}

// --------------------------------------------------------------------- PHP

fn composer_exact(spec: &str) -> Option<String> {
    static EXACT: OnceLock<Regex> = OnceLock::new();
    let caps = re(&EXACT, r"^=?v?(\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.]+)?)$").captures(spec.trim())?;
    Some(caps.get(1)?.as_str().to_string())
}

fn composer_platform(name: &str) -> bool {
    !name.contains('/')
}

fn composer_json(c: &mut Collector, file: &str, text: &str) {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return;
    };
    for section in ["require", "require-dev"] {
        let Some(map) = json.get(section).and_then(Value::as_object) else {
            continue;
        };
        let section_at = text.find(&format!("\"{section}\"")).unwrap_or(0);
        for (name, spec) in map {
            let Some(spec) = spec.as_str() else { continue };
            if composer_platform(name) {
                continue;
            }
            let line = text[section_at..]
                .find(&format!("\"{name}\""))
                .map(|o| line_at(text, section_at + o))
                .unwrap_or(1);
            c.add(
                "Packagist",
                name,
                composer_exact(spec),
                spec,
                file,
                line,
                DepKind::Manifest,
            );
        }
    }
}

fn composer_packages(c: &mut Collector, file: &str, text: &str, packages: &[Value], kind: DepKind) {
    for p in packages {
        let (Some(name), Some(version)) = (
            p.get("name").and_then(Value::as_str),
            p.get("version").and_then(Value::as_str),
        ) else {
            continue;
        };
        if version.starts_with("dev-") || version.ends_with("-dev") {
            continue;
        }
        let line = line_of(text, &format!("\"name\": \"{name}\""));
        let exact = version.strip_prefix('v').unwrap_or(version).to_string();
        c.add("Packagist", name, Some(exact), version, file, line, kind);
    }
}

fn composer_lock(c: &mut Collector, file: &str, text: &str) {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return;
    };
    for section in ["packages", "packages-dev"] {
        if let Some(list) = json.get(section).and_then(Value::as_array) {
            composer_packages(c, file, text, list, DepKind::Lockfile);
        }
    }
}

fn composer_installed(c: &mut Collector, path: &Path) {
    let Some(text) = read_limited(path, MAX_MANIFEST_BYTES) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    let rel = c.rel(path);
    let list = json
        .as_array()
        .or_else(|| json.get("packages").and_then(Value::as_array));
    if let Some(list) = list {
        composer_packages(c, &rel, &text, list, DepKind::Installed);
    }
}

// -------------------------------------------------------------------- Java

/// `<tag>value</tag>` children of an XML fragment, in order.
fn xml_children(xml: &str) -> Vec<(String, String, usize)> {
    static TAG: OnceLock<Regex> = OnceLock::new();
    let tag = re(
        &TAG,
        r"<([A-Za-z_][\w.\-]*)>\s*([^<]*?)\s*</([A-Za-z_][\w.\-]*)>",
    );
    tag.captures_iter(xml)
        .filter(|c| c[1] == c[3])
        .map(|c| {
            (
                c[1].to_string(),
                c[2].to_string(),
                c.get(0).unwrap().start(),
            )
        })
        .collect()
}

fn maven_exact(version: &str) -> Option<String> {
    let v = version.trim();
    // `[1.2.3]` pins; other ranges and properties do not.
    let v = v
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .filter(|r| !r.contains(','))
        .unwrap_or(v);
    (!v.is_empty() && !v.contains(['$', '[', '(', ',', ')', ']'])).then(|| v.to_string())
}

fn pom_xml(c: &mut Collector, file: &str, text: &str) {
    static COMMENT: OnceLock<Regex> = OnceLock::new();
    static PROPS: OnceLock<Regex> = OnceLock::new();
    static DEP: OnceLock<Regex> = OnceLock::new();
    static EXCL: OnceLock<Regex> = OnceLock::new();
    static PROP_REF: OnceLock<Regex> = OnceLock::new();
    // Comments keep their length so offsets still give the right lines.
    let clean = re(&COMMENT, r"(?s)<!--.*?-->").replace_all(text, |m: &regex::Captures| {
        m[0].chars()
            .map(|ch| if ch == '\n' { '\n' } else { ' ' })
            .collect::<String>()
    });
    let mut props: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for caps in re(&PROPS, r"(?s)<properties>(.*?)</properties>").captures_iter(&clean) {
        for (k, v, _) in xml_children(&caps[1]) {
            props.insert(k, v);
        }
    }
    let prop_ref = re(&PROP_REF, r"\$\{([^}]+)\}");
    let excl = re(&EXCL, r"(?s)<exclusions>.*?</exclusions>");
    for m in re(&DEP, r"(?s)<dependency>(.*?)</dependency>").find_iter(&clean) {
        let body = excl.replace_all(m.as_str(), "");
        let children = xml_children(&body);
        let get = |name: &str| {
            children
                .iter()
                .find(|(k, _, _)| k == name)
                .map(|(_, v, _)| v.clone())
        };
        let (Some(group), Some(artifact)) = (get("groupId"), get("artifactId")) else {
            continue;
        };
        if group.contains("${") || artifact.contains("${") {
            continue;
        }
        let written = get("version").unwrap_or_default();
        let resolved = prop_ref
            .replace_all(&written, |caps: &regex::Captures| {
                props
                    .get(&caps[1])
                    .cloned()
                    .unwrap_or_else(|| caps[0].to_string())
            })
            .into_owned();
        let at = m.start() + m.as_str().find("<artifactId>").unwrap_or(0);
        c.add(
            "Maven",
            &format!("{group}:{artifact}"),
            maven_exact(&resolved),
            &written,
            file,
            line_at(&clean, at),
            DepKind::Manifest,
        );
    }
}

fn gradle(c: &mut Collector, file: &str, text: &str) {
    static VAR: OnceLock<Regex> = OnceLock::new();
    static COORD: OnceLock<Regex> = OnceLock::new();
    static MAP: OnceLock<Regex> = OnceLock::new();
    let mut vars: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for caps in re(
        &VAR,
        r#"(?m)^\s*(?:def|val|var|ext\.|set\(\s*)?\s*["']?([A-Za-z_][\w.]*)["']?\s*[=,]\s*["']([^"'$]+)["']"#,
    )
    .captures_iter(text)
    {
        vars.insert(caps[1].to_string(), caps[2].to_string());
    }
    let resolve = |v: &str| -> String {
        let name = v
            .trim_start_matches('$')
            .trim_start_matches('{')
            .trim_end_matches('}');
        if v.starts_with('$') {
            vars.get(name)
                .or_else(|| vars.get(name.rsplit('.').next().unwrap_or(name)))
                .cloned()
                .unwrap_or_else(|| v.to_string())
        } else {
            v.to_string()
        }
    };
    let configs = r"(?:implementation|api|compile|compileOnly|runtimeOnly|runtime|testImplementation|testCompile|testRuntimeOnly|annotationProcessor|kapt|classpath|providedCompile|providedRuntime)";
    let coord = re(
        &COORD,
        &format!(
            r#"{configs}\s*\(?\s*(?:platform\()?\s*["']([\w.\-]+):([\w.\-]+):([^"'@:]+)(?:[:@][^"']*)?["']"#
        ),
    );
    for caps in coord.captures_iter(text) {
        let written = caps[3].to_string();
        let resolved = resolve(&written);
        let at = caps.get(1).unwrap().start();
        c.add(
            "Maven",
            &format!("{}:{}", &caps[1], &caps[2]),
            maven_exact(&resolved),
            &written,
            file,
            line_at(text, at),
            DepKind::Manifest,
        );
    }
    let map = re(
        &MAP,
        &format!(
            r#"{configs}\s*\(?\s*group\s*[:=]\s*["']([\w.\-]+)["']\s*,\s*name\s*[:=]\s*["']([\w.\-]+)["']\s*,\s*version\s*[:=]\s*["']([^"']+)["']"#
        ),
    );
    for caps in map.captures_iter(text) {
        let written = caps[3].to_string();
        let resolved = resolve(&written);
        let at = caps.get(1).unwrap().start();
        c.add(
            "Maven",
            &format!("{}:{}", &caps[1], &caps[2]),
            maven_exact(&resolved),
            &written,
            file,
            line_at(text, at),
            DepKind::Manifest,
        );
    }
}

fn gradle_lock(c: &mut Collector, file: &str, text: &str) {
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.starts_with('#') || t.starts_with("empty=") {
            continue;
        }
        let coords = t.split('=').next().unwrap_or(t);
        let parts: Vec<&str> = coords.split(':').collect();
        if parts.len() == 3 {
            c.add(
                "Maven",
                &format!("{}:{}", parts[0], parts[1]),
                Some(parts[2].to_string()),
                parts[2],
                file,
                i as u32 + 1,
                DepKind::Lockfile,
            );
        }
    }
}

// ---------------------------------------------------------- Go, Rust, Ruby

fn go_mod(c: &mut Collector, file: &str, text: &str) {
    let mut in_block = false;
    for (i, line) in text.lines().enumerate() {
        let t = line.split("//").next().unwrap_or(line).trim();
        let entry = if in_block {
            if t == ")" {
                in_block = false;
                continue;
            }
            t
        } else if let Some(rest) = t.strip_prefix("require") {
            let rest = rest.trim();
            if rest == "(" {
                in_block = true;
                continue;
            }
            rest
        } else {
            continue;
        };
        let mut parts = entry.split_whitespace();
        if let (Some(module), Some(version)) = (parts.next(), parts.next()) {
            let exact = version
                .strip_suffix("+incompatible")
                .unwrap_or(version)
                .to_string();
            c.add(
                "Go",
                module,
                Some(exact),
                version,
                file,
                i as u32 + 1,
                DepKind::Manifest,
            );
        }
    }
}

fn cargo_lock(c: &mut Collector, file: &str, text: &str) {
    let mut current: Option<(String, u32, Option<String>, bool)> = None;
    let flush = |c: &mut Collector, cur: Option<(String, u32, Option<String>, bool)>| {
        if let Some((name, line, Some(version), true)) = cur {
            c.add(
                "crates.io",
                &name,
                Some(version.clone()),
                &version,
                file,
                line,
                DepKind::Lockfile,
            );
        }
    };
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t == "[[package]]" {
            flush(c, current.take());
            current = Some((String::new(), i as u32 + 1, None, false));
            continue;
        }
        let Some(cur) = current.as_mut() else {
            continue;
        };
        if let Some(v) = t.strip_prefix("name =") {
            cur.0 = unquote(v).to_string();
            cur.1 = i as u32 + 1;
        } else if let Some(v) = t.strip_prefix("version =") {
            cur.2 = Some(unquote(v).to_string());
        } else if let Some(v) = t.strip_prefix("source =") {
            // Only packages from crates.io; workspace members have no source.
            cur.3 = unquote(v).starts_with("registry+");
        }
    }
    flush(c, current.take());
}

fn gemfile_lock(c: &mut Collector, file: &str, text: &str) {
    let mut in_specs = false;
    let mut in_gem = false;
    for (i, line) in text.lines().enumerate() {
        if !line.starts_with(' ') {
            in_gem = line.trim() == "GEM";
            in_specs = false;
            continue;
        }
        if in_gem && line.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        // Gems are indented by four spaces, their own requirements by six.
        if !in_specs || !line.starts_with("    ") || line.starts_with("     ") {
            continue;
        }
        let t = line.trim();
        let Some((name, rest)) = t.split_once(" (") else {
            continue;
        };
        let version = rest.trim_end_matches(')');
        // `1.13.10-x86_64-linux`: the platform follows the dash.
        let exact = version.split('-').next().unwrap_or(version).to_string();
        c.add(
            "RubyGems",
            name,
            Some(exact),
            version,
            file,
            i as u32 + 1,
            DepKind::Lockfile,
        );
    }
}

// -------------------------------------------------------------------- .NET

fn nuget_exact(version: &str) -> Option<String> {
    let v = version.trim();
    let v = v
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .filter(|r| !r.contains(','))
        .unwrap_or(v);
    (!v.is_empty() && !v.contains(['*', '[', '(', ',', ')', ']', '$'])).then(|| v.to_string())
}

fn msbuild(c: &mut Collector, file: &str, text: &str) {
    static TAG: OnceLock<Regex> = OnceLock::new();
    static ATTR: OnceLock<Regex> = OnceLock::new();
    static CHILD: OnceLock<Regex> = OnceLock::new();
    let tag = re(
        &TAG,
        r"(?s)<(PackageReference|PackageVersion)\b([^>]*?)(/>|>(.*?)</(?:PackageReference|PackageVersion)>)",
    );
    let attr = re(&ATTR, r#"(\w+)\s*=\s*"([^"]*)""#);
    let child = re(&CHILD, r"<Version>\s*([^<]*?)\s*</Version>");
    for caps in tag.captures_iter(text) {
        let attrs: Vec<(String, String)> = attr
            .captures_iter(&caps[2])
            .map(|a| (a[1].to_string(), a[2].to_string()))
            .collect();
        let get = |k: &str| {
            attrs
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.clone())
        };
        let Some(name) = get("Include").or_else(|| get("Update")) else {
            continue;
        };
        let version = get("Version")
            .or_else(|| {
                caps.get(4)
                    .and_then(|b| child.captures(b.as_str()))
                    .map(|v| v[1].to_string())
            })
            .unwrap_or_default();
        let at = caps.get(0).unwrap().start();
        c.add(
            "NuGet",
            &name,
            nuget_exact(&version),
            &version,
            file,
            line_at(text, at),
            DepKind::Manifest,
        );
    }
}

fn packages_config(c: &mut Collector, file: &str, text: &str) {
    static PKG: OnceLock<Regex> = OnceLock::new();
    static ATTR: OnceLock<Regex> = OnceLock::new();
    let pkg = re(&PKG, r"<package\b([^>]*)/?>");
    let attr = re(&ATTR, r#"(\w+)\s*=\s*"([^"]*)""#);
    for caps in pkg.captures_iter(text) {
        let attrs: Vec<(String, String)> = attr
            .captures_iter(&caps[1])
            .map(|a| (a[1].to_ascii_lowercase(), a[2].to_string()))
            .collect();
        let get = |k: &str| attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        if let (Some(id), Some(version)) = (get("id"), get("version")) {
            let at = caps.get(0).unwrap().start();
            c.add(
                "NuGet",
                &id,
                nuget_exact(&version),
                &version,
                file,
                line_at(text, at),
                DepKind::Manifest,
            );
        }
    }
}

fn nuget_lock(c: &mut Collector, file: &str, text: &str) {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let Some(frameworks) = json.get("dependencies").and_then(Value::as_object) else {
        return;
    };
    let lines = npm_key_lines(text);
    for deps in frameworks.values().filter_map(Value::as_object) {
        for (name, info) in deps {
            if info.get("type").and_then(Value::as_str) == Some("Project") {
                continue;
            }
            if let Some(v) = info.get("resolved").and_then(Value::as_str) {
                let line = lines.get(name.as_str()).copied().unwrap_or(1);
                c.add(
                    "NuGet",
                    name,
                    Some(v.to_string()),
                    v,
                    file,
                    line,
                    DepKind::Lockfile,
                );
            }
        }
    }
}

/// A third-party Python module the code imports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportedModule {
    /// Top-level name as imported (`fastapi`, `yaml`), not the
    /// distribution name, which may differ (`PyYAML`).
    pub module: String,
    /// The first import of it.
    pub file: String,
    pub line: u32,
    /// Files that import it.
    pub files: usize,
}

/// Modules of the Python standard library, current and removed ones
/// (Python 2 names included), sorted for binary search.
const PYTHON_STDLIB: &[&str] = &[
    "BaseHTTPServer",
    "CGIHTTPServer",
    "ConfigParser",
    "Cookie",
    "HTMLParser",
    "Queue",
    "SimpleHTTPServer",
    "SimpleXMLRPCServer",
    "SocketServer",
    "StringIO",
    "Tkinter",
    "UserDict",
    "UserList",
    "UserString",
    "__builtin__",
    "__future__",
    "__main__",
    "_abc",
    "_aix_support",
    "_android_support",
    "_apple_support",
    "_ast",
    "_asyncio",
    "_bisect",
    "_blake2",
    "_bz2",
    "_codecs",
    "_codecs_cn",
    "_codecs_hk",
    "_codecs_iso2022",
    "_codecs_jp",
    "_codecs_kr",
    "_codecs_tw",
    "_collections",
    "_collections_abc",
    "_colorize",
    "_compat_pickle",
    "_compression",
    "_contextvars",
    "_csv",
    "_ctypes",
    "_curses",
    "_curses_panel",
    "_datetime",
    "_dbm",
    "_decimal",
    "_dummy_thread",
    "_elementtree",
    "_frozen_importlib",
    "_frozen_importlib_external",
    "_functools",
    "_gdbm",
    "_hashlib",
    "_heapq",
    "_imp",
    "_interpchannels",
    "_interpqueues",
    "_interpreters",
    "_io",
    "_ios_support",
    "_json",
    "_locale",
    "_lsprof",
    "_lzma",
    "_markupbase",
    "_md5",
    "_multibytecodec",
    "_multiprocessing",
    "_opcode",
    "_opcode_metadata",
    "_operator",
    "_osx_support",
    "_overlapped",
    "_pickle",
    "_posixshmem",
    "_posixsubprocess",
    "_py_abc",
    "_pydatetime",
    "_pydecimal",
    "_pyio",
    "_pylong",
    "_pyrepl",
    "_queue",
    "_random",
    "_scproxy",
    "_sha1",
    "_sha2",
    "_sha3",
    "_signal",
    "_sitebuiltins",
    "_socket",
    "_sqlite3",
    "_sre",
    "_ssl",
    "_stat",
    "_statistics",
    "_string",
    "_strptime",
    "_struct",
    "_suggestions",
    "_symtable",
    "_sysconfig",
    "_thread",
    "_threading_local",
    "_tkinter",
    "_tokenize",
    "_tracemalloc",
    "_typing",
    "_uuid",
    "_warnings",
    "_weakref",
    "_weakrefset",
    "_winapi",
    "_wmi",
    "_zoneinfo",
    "abc",
    "antigravity",
    "anydbm",
    "argparse",
    "array",
    "ast",
    "asynchat",
    "asyncio",
    "asyncore",
    "atexit",
    "base64",
    "bdb",
    "binascii",
    "binhex",
    "bisect",
    "builtins",
    "bz2",
    "cPickle",
    "cProfile",
    "cStringIO",
    "calendar",
    "cgi",
    "cgitb",
    "chunk",
    "cmath",
    "cmd",
    "code",
    "codecs",
    "codeop",
    "collections",
    "colorsys",
    "commands",
    "compileall",
    "concurrent",
    "configparser",
    "contextlib",
    "contextvars",
    "cookielib",
    "copy",
    "copy_reg",
    "copyreg",
    "crypt",
    "csv",
    "ctypes",
    "curses",
    "dataclasses",
    "datetime",
    "dbhash",
    "dbm",
    "decimal",
    "difflib",
    "dis",
    "distutils",
    "doctest",
    "dumbdbm",
    "dummy_threading",
    "email",
    "encodings",
    "ensurepip",
    "enum",
    "errno",
    "exceptions",
    "faulthandler",
    "fcntl",
    "filecmp",
    "fileinput",
    "fnmatch",
    "formatter",
    "fractions",
    "ftplib",
    "functools",
    "gc",
    "gdbm",
    "genericpath",
    "getopt",
    "getpass",
    "gettext",
    "glob",
    "graphlib",
    "grp",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "htmlentitydefs",
    "htmllib",
    "http",
    "httplib",
    "idlelib",
    "imaplib",
    "imghdr",
    "imp",
    "importlib",
    "imputil",
    "inspect",
    "io",
    "ipaddress",
    "itertools",
    "json",
    "keyword",
    "lib2to3",
    "linecache",
    "locale",
    "logging",
    "lzma",
    "macpath",
    "mailbox",
    "mailcap",
    "markupbase",
    "marshal",
    "math",
    "md5",
    "mhlib",
    "mimetools",
    "mimetypes",
    "mimify",
    "mmap",
    "modulefinder",
    "msilib",
    "msvcrt",
    "multifile",
    "multiprocessing",
    "netrc",
    "new",
    "nis",
    "nntplib",
    "nt",
    "ntpath",
    "nturl2path",
    "numbers",
    "opcode",
    "operator",
    "optparse",
    "os",
    "ossaudiodev",
    "parser",
    "pathlib",
    "pdb",
    "pickle",
    "pickletools",
    "pipes",
    "pkgutil",
    "platform",
    "plistlib",
    "popen2",
    "poplib",
    "posix",
    "posixfile",
    "posixpath",
    "pprint",
    "profile",
    "pstats",
    "pty",
    "pwd",
    "py_compile",
    "pyclbr",
    "pydoc",
    "pydoc_data",
    "pyexpat",
    "queue",
    "quopri",
    "random",
    "re",
    "readline",
    "repr",
    "reprlib",
    "resource",
    "rfc822",
    "rlcompleter",
    "robotparser",
    "runpy",
    "sched",
    "secrets",
    "select",
    "selectors",
    "sets",
    "sgmllib",
    "sha",
    "shelve",
    "shlex",
    "shutil",
    "signal",
    "site",
    "smtpd",
    "smtplib",
    "sndhdr",
    "socket",
    "socketserver",
    "spwd",
    "sqlite3",
    "sre_compile",
    "sre_constants",
    "sre_parse",
    "ssl",
    "stat",
    "statistics",
    "statvfs",
    "string",
    "stringprep",
    "struct",
    "subprocess",
    "sunau",
    "symbol",
    "symtable",
    "sys",
    "sysconfig",
    "syslog",
    "tabnanny",
    "tarfile",
    "telnetlib",
    "tempfile",
    "termios",
    "textwrap",
    "this",
    "thread",
    "threading",
    "time",
    "timeit",
    "tkMessageBox",
    "tkinter",
    "token",
    "tokenize",
    "tomllib",
    "trace",
    "traceback",
    "tracemalloc",
    "tty",
    "turtle",
    "turtledemo",
    "types",
    "typing",
    "unicodedata",
    "unittest",
    "urllib",
    "urllib2",
    "urlparse",
    "user",
    "uu",
    "uuid",
    "venv",
    "warnings",
    "wave",
    "weakref",
    "webbrowser",
    "whichdb",
    "winreg",
    "winsound",
    "wsgiref",
    "xdrlib",
    "xml",
    "xmlrpc",
    "xmlrpclib",
    "zipapp",
    "zipfile",
    "zipimport",
    "zlib",
    "zoneinfo",
];

/// Python modules the project imports that are neither in the standard
/// library nor part of the project: what a dependency list should name.
pub fn python_imports(
    project: &crate::project::Project,
    include_tests: bool,
) -> Vec<ImportedModule> {
    static IMPORT: OnceLock<Regex> = OnceLock::new();
    let import = IMPORT.get_or_init(|| {
        Regex::new(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][\w.]*(?:\s+as\s+\w+)?(?:\s*,\s*[A-Za-z_][\w.]*(?:\s+as\s+\w+)?)*))")
            .expect("import pattern")
    });
    let python: Vec<&crate::project::ModuleInfo> = project
        .modules
        .iter()
        .filter(|m| m.lang == crate::Language::Python)
        .collect();
    // Names the project itself provides: any segment of a module's dotted
    // name, since the code may run with a subdirectory on `sys.path`.
    let local: HashSet<&str> = python.iter().flat_map(|m| m.name.split('.')).collect();
    let mut found: Vec<ImportedModule> = Vec::new();
    for m in python.iter().filter(|m| include_tests || !m.is_test) {
        let mut in_file: HashSet<String> = HashSet::new();
        // Inside a triple-quoted string: its text is not code.
        let mut quoted: Option<&str> = None;
        for (i, line) in m.source().lines().enumerate() {
            let was_quoted = quoted.is_some();
            for q in ["\"\"\"", "'''"] {
                let n = line.matches(q).count();
                if n % 2 == 1 && quoted.is_none_or(|open| open == q) {
                    quoted = if quoted.is_some() { None } else { Some(q) };
                }
            }
            if was_quoted {
                continue;
            }
            let Some(c) = import.captures(line) else {
                continue;
            };
            let names: Vec<&str> = match (c.get(1), c.get(2)) {
                (Some(from), _) => vec![from.as_str()],
                (None, Some(list)) => list
                    .as_str()
                    .split(',')
                    .filter_map(|part| part.split_whitespace().next())
                    .collect(),
                _ => continue,
            };
            for name in names {
                let top = name.split('.').next().unwrap_or(name);
                if top.is_empty()
                    || PYTHON_STDLIB.binary_search(&top).is_ok()
                    || local.contains(top)
                    || !in_file.insert(top.to_string())
                {
                    continue;
                }
                match found.iter_mut().find(|f| f.module == top) {
                    Some(f) => f.files += 1,
                    None => found.push(ImportedModule {
                        module: top.to_string(),
                        file: m.path.clone(),
                        line: i as u32 + 1,
                        files: 1,
                    }),
                }
            }
        }
    }
    found.sort_by(|a, b| {
        a.module
            .to_ascii_lowercase()
            .cmp(&b.module.to_ascii_lowercase())
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(f: fn(&mut Collector, &str, &str), text: &str) -> Vec<(String, Option<String>, u32)> {
        let root = Path::new("/");
        let mut c = Collector {
            root,
            out: Vec::new(),
            seen: HashSet::new(),
            dev: false,
        };
        f(&mut c, "f", text);
        c.out.sort_by_key(|d| d.line);
        c.out
            .into_iter()
            .map(|d| (d.name, d.version, d.line))
            .collect()
    }

    fn parse_dev(f: fn(&mut Collector, &str, &str), text: &str) -> Vec<(String, bool)> {
        let root = Path::new("/");
        let mut c = Collector {
            root,
            out: Vec::new(),
            seen: HashSet::new(),
            dev: false,
        };
        f(&mut c, "f", text);
        c.out.sort_by_key(|d| d.line);
        c.out.into_iter().map(|d| (d.name, d.dev)).collect()
    }

    #[test]
    fn npm_dev_dependencies_are_marked() {
        // devDependencies and optionalDependencies are dev; dependencies are not.
        let pkg = "{\n  \"dependencies\": {\n    \"express\": \"4.18.0\"\n  },\n  \"devDependencies\": {\n    \"jest\": \"29.0.0\"\n  },\n  \"optionalDependencies\": {\n    \"fsevents\": \"2.3.2\"\n  }\n}\n";
        assert_eq!(
            parse_dev(package_json, pkg),
            vec![
                ("express".to_string(), false),
                ("jest".to_string(), true),
                ("fsevents".to_string(), true),
            ]
        );
        // Lock-file v3 carries the dev marker per installed package.
        let lock = "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"\": {\"name\": \"app\"},\n    \"node_modules/express\": {\"version\": \"4.18.0\"},\n    \"node_modules/jest\": {\"version\": \"29.0.0\", \"dev\": true}\n  }\n}\n";
        let mut got = parse_dev(package_lock, lock);
        got.sort();
        assert_eq!(
            got,
            vec![("express".to_string(), false), ("jest".to_string(), true),]
        );
    }

    fn pinned(name: &str, v: &str, line: u32) -> (String, Option<String>, u32) {
        (name.to_string(), Some(v.to_string()), line)
    }

    fn loose(name: &str, line: u32) -> (String, Option<String>, u32) {
        (name.to_string(), None, line)
    }

    #[test]
    fn requirements_pins_and_ranges() {
        let text = "# web\nFlask==0.12.2\njinja2>=2.10  # templates\nrequests[security] == 2.19.1 ; python_version > '3'\n-r base.txt\nDjango==2.2.* \nurllib3==1.24.1 \\\n    --hash=sha256:abc\n-e git+https://x/y.git#egg=z\nuvicorn\n";
        assert_eq!(
            parse(requirements_txt, text),
            vec![
                pinned("Flask", "0.12.2", 2),
                loose("jinja2", 3),
                pinned("requests", "2.19.1", 4),
                loose("Django", 6),
                pinned("urllib3", "1.24.1", 7),
                loose("uvicorn", 10),
            ]
        );
    }

    #[test]
    fn prose_named_like_requirements_is_not_read() {
        let doc = "Constraints\n===========\n\nPostgreSQL supports additional data integrity constraints.\nYou can install it using the\noperation.\n";
        assert_eq!(parse(requirements_txt, doc), vec![]);
    }

    #[test]
    fn python_lock_files_and_pyproject() {
        let poetry = "[[package]]\nname = \"jinja2\"\nversion = \"2.10\"\n\n[[package]]\nname = \"mylib\"\nversion = \"0.1.0\"\n\n[package.source]\ntype = \"directory\"\nurl = \"../mylib\"\n";
        assert_eq!(
            parse(python_lock, poetry),
            vec![pinned("jinja2", "2.10", 2)]
        );
        let uv = "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n[[package]]\nname = \"fastapi\"\nversion = \"0.65.1\"\nsource = { registry = \"https://pypi.org/simple\" }\n";
        assert_eq!(parse(python_lock, uv), vec![pinned("fastapi", "0.65.1", 7)]);
        let toml = "[project]\nname = \"app\"\ndependencies = [\n  \"fastapi==0.65.1\",\n  \"jinja2>=3\",\n]\n\n[tool.poetry.dependencies]\npython = \"^3.10\"\nrequests = \"2.19.1\"\npyyaml = { version = \"==5.3\", extras = [\"x\"] }\n";
        assert_eq!(
            parse(pyproject, toml),
            vec![
                pinned("fastapi", "0.65.1", 4),
                loose("jinja2", 5),
                loose("requests", 10),
                pinned("pyyaml", "5.3", 11),
            ]
        );
        let lock =
            "{\n  \"default\": {\n    \"flask\": {\n      \"version\": \"==1.0\"\n    }\n  }\n}\n";
        assert_eq!(parse(pipfile_lock, lock), vec![pinned("flask", "1.0", 3)]);
    }

    #[test]
    fn npm_manifests_and_locks() {
        let pkg = "{\n  \"dependencies\": {\n    \"lodash\": \"4.17.4\",\n    \"express\": \"^4.16.0\",\n    \"old\": \"npm:jquery@1.12.4\",\n    \"local\": \"file:../x\"\n  }\n}\n";
        assert_eq!(
            parse(package_json, pkg),
            vec![
                pinned("lodash", "4.17.4", 3),
                loose("express", 4),
                pinned("jquery", "1.12.4", 5),
            ]
        );
        let lock = "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"\": {\"name\": \"app\"},\n    \"node_modules/minimist\": {\n      \"version\": \"0.0.8\"\n    },\n    \"node_modules/a/node_modules/@scope/b\": {\n      \"version\": \"1.0.0\"\n    }\n  }\n}\n";
        assert_eq!(
            parse(package_lock, lock),
            vec![
                pinned("minimist", "0.0.8", 5),
                pinned("@scope/b", "1.0.0", 8)
            ]
        );
        let v1 = "{\n  \"dependencies\": {\n    \"qs\": {\n      \"version\": \"6.5.1\",\n      \"dependencies\": {\n        \"side\": {\"version\": \"1.0.0\"}\n      }\n    }\n  }\n}\n";
        assert_eq!(
            parse(package_lock, v1),
            vec![pinned("qs", "6.5.1", 3), pinned("side", "1.0.0", 6)]
        );
        let yarn = "# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.1.2\"\n  resolved \"x\"\n\nlodash@^4.17.4:\n  version \"4.17.10\"\n";
        assert_eq!(
            parse(yarn_lock, yarn),
            vec![
                pinned("@babel/core", "7.1.2", 3),
                pinned("lodash", "4.17.10", 7)
            ]
        );
        let berry = "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.4\":\n  version: 4.17.20\n  resolution: \"lodash@npm:4.17.20\"\n";
        assert_eq!(
            parse(yarn_lock, berry),
            vec![pinned("lodash", "4.17.20", 4)]
        );
        let pnpm = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies: {}\n\npackages:\n\n  lodash@4.17.20:\n    resolution: {integrity: x}\n\n  '@types/node@18.0.0':\n    resolution: {integrity: y}\n\n  react-dom@18.2.0(react@18.2.0):\n    resolution: {}\n";
        assert_eq!(
            parse(pnpm_lock, pnpm),
            vec![
                pinned("lodash", "4.17.20", 9),
                pinned("@types/node", "18.0.0", 12),
                pinned("react-dom", "18.2.0", 15),
            ]
        );
    }

    #[test]
    fn bundled_libraries_by_banner_and_name() {
        let mut c = Collector {
            root: Path::new("/"),
            out: Vec::new(),
            seen: HashSet::new(),
            dev: false,
        };
        bundled_script(
            &mut c,
            "static/js/jquery.min.js",
            "jquery.min.js",
            "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */\n!function(e,t){}",
        );
        bundled_script(
            &mut c,
            "static/js/bootstrap-4.1.3.js",
            "bootstrap-4.1.3.js",
            "/* no banner */",
        );
        bundled_script(
            &mut c,
            "static/js/lodash.min.js",
            "lodash.min.js",
            "/**\n * @license\n * Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE\n */\n;(function(){function n(n,t,r){switch(r.length){case 0:return n.call(t)}}var u,i=\"4.17.15\",o=200,f=\"Unsupported core-js use.\";})",
        );
        bundled_script(
            &mut c,
            "static/js/app.js",
            "app.js",
            "// requires jQuery v1.7 or later\nconsole.log(1)",
        );
        let got: Vec<_> = c
            .out
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_deref(), d.file.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("jquery", Some("3.4.1"), "static/js/jquery.min.js"),
                ("bootstrap", Some("4.1.3"), "static/js/bootstrap-4.1.3.js"),
                ("lodash", Some("4.17.15"), "static/js/lodash.min.js"),
            ]
        );
    }

    #[test]
    fn cdn_urls_in_pages() {
        let page = "<script src=\"https://code.jquery.com/jquery-1.12.4.min.js\"></script>\n<link href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css\">\n<script src=\"https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.11/lodash.min.js\"></script>\n<script src=\"https://cdn.jsdelivr.net/npm/vue@2.5.16/dist/vue.js\"></script>\n<script src=\"https://unpkg.com/@popperjs/core@2.11.8/dist/umd/popper.min.js\"></script>\n<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5/dist/js/bootstrap.js\"></script>\n<script src=\"//ajax.googleapis.com/ajax/libs/angularjs/1.6.9/angular.min.js\"></script>\n";
        assert_eq!(
            parse(cdn_links, page),
            vec![
                pinned("jquery", "1.12.4", 1),
                pinned("bootstrap", "4.1.3", 2),
                pinned("lodash", "4.17.11", 3),
                pinned("vue", "2.5.16", 4),
                pinned("@popperjs/core", "2.11.8", 5),
                pinned("angular", "1.6.9", 7),
            ]
        );
    }

    #[test]
    fn php_java_go_rust_ruby_and_dotnet() {
        let lock = "{\n    \"packages\": [\n        {\n            \"name\": \"twig/twig\",\n            \"version\": \"v1.35.0\"\n        }\n    ]\n}\n";
        assert_eq!(
            parse(composer_lock, lock),
            vec![pinned("twig/twig", "1.35.0", 4)]
        );
        let cj = "{\n  \"require\": {\n    \"php\": \">=7.2\",\n    \"guzzlehttp/guzzle\": \"6.3.0\",\n    \"monolog/monolog\": \"^1.0\"\n  }\n}\n";
        assert_eq!(
            parse(composer_json, cj),
            vec![
                pinned("guzzlehttp/guzzle", "6.3.0", 4),
                loose("monolog/monolog", 5)
            ]
        );
        let pom = "<project>\n  <properties>\n    <jackson.version>2.9.8</jackson.version>\n  </properties>\n  <dependencies>\n    <!-- <dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency> -->\n    <dependency>\n      <groupId>com.fasterxml.jackson.core</groupId>\n      <artifactId>jackson-databind</artifactId>\n      <version>${jackson.version}</version>\n      <exclusions><exclusion><groupId>a</groupId><artifactId>b</artifactId></exclusion></exclusions>\n    </dependency>\n    <dependency>\n      <groupId>org.slf4j</groupId>\n      <artifactId>slf4j-api</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n";
        assert_eq!(
            parse(pom_xml, pom),
            vec![
                pinned("com.fasterxml.jackson.core:jackson-databind", "2.9.8", 9),
                loose("org.slf4j:slf4j-api", 15),
            ]
        );
        let gradle_text = "ext {\n  springVersion = '5.0.0.RELEASE'\n}\ndependencies {\n  implementation 'org.apache.commons:commons-text:1.9'\n  implementation \"org.springframework:spring-web:$springVersion\"\n  testImplementation group: 'junit', name: 'junit', version: '4.12'\n}\n";
        assert_eq!(
            parse(gradle, gradle_text),
            vec![
                pinned("org.apache.commons:commons-text", "1.9", 5),
                pinned("org.springframework:spring-web", "5.0.0.RELEASE", 6),
                pinned("junit:junit", "4.12", 7),
            ]
        );
        let gomod = "module x\n\ngo 1.20\n\nrequire github.com/gin-gonic/gin v1.6.0\n\nrequire (\n\tgolang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect\n\tgithub.com/a/b v2.0.0+incompatible\n)\n";
        assert_eq!(
            parse(go_mod, gomod),
            vec![
                pinned("github.com/gin-gonic/gin", "v1.6.0", 5),
                pinned("golang.org/x/net", "v0.0.0-20210226172049-e18ecbb05110", 8),
                pinned("github.com/a/b", "v2.0.0", 9),
            ]
        );
        let cargo = "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"smallvec\"\nversion = \"1.6.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        assert_eq!(
            parse(cargo_lock, cargo),
            vec![pinned("smallvec", "1.6.0", 6)]
        );
        let gems = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.10.4-x86_64-linux)\n      mini_portile2 (~> 2.4.0)\n    rails (5.2.3)\n\nPLATFORMS\n  ruby\n";
        assert_eq!(
            parse(gemfile_lock, gems),
            vec![pinned("nokogiri", "1.10.4", 4), pinned("rails", "5.2.3", 6)]
        );
        let csproj = "<Project>\n  <ItemGroup>\n    <PackageReference Include=\"Newtonsoft.Json\" Version=\"11.0.1\" />\n    <PackageReference Include=\"Serilog\">\n      <Version>2.*</Version>\n    </PackageReference>\n  </ItemGroup>\n</Project>\n";
        assert_eq!(
            parse(msbuild, csproj),
            vec![pinned("Newtonsoft.Json", "11.0.1", 3), loose("Serilog", 4)]
        );
        let config = "<packages>\n  <package id=\"jQuery\" version=\"1.7.1\" targetFramework=\"net45\" />\n</packages>\n";
        assert_eq!(
            parse(packages_config, config),
            vec![pinned("jQuery", "1.7.1", 2)]
        );
    }

    #[test]
    fn lists_third_party_python_imports() {
        let dir = std::env::temp_dir().join(format!("deps-imports-{}", std::process::id()));
        let files = [
            (
                "app/main.py",
                "import os, json\nfrom fastapi import FastAPI\nimport sqlalchemy.orm as orm\nfrom .models import User\nfrom app.models import Base\nfrom models import Base\n\"\"\"\nimport notreal\n\"\"\"\nimport yaml\n",
            ),
            ("app/models.py", "from sqlalchemy import Column\nfrom __future__ import annotations\n"),
            ("app/__init__.py", ""),
            ("tests/test_main.py", "import pytest\n"),
        ];
        for (path, text) in files {
            let p = dir.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        let project = crate::project::Project::from_dir(&dir).unwrap();
        let found: Vec<(String, String, u32, usize)> = python_imports(&project, false)
            .into_iter()
            .map(|m| (m.module, m.file, m.line, m.files))
            .collect();
        let row = |m: &str, f: &str, l: u32, n: usize| (m.to_string(), f.to_string(), l, n);
        assert_eq!(
            found,
            vec![
                row("fastapi", "app/main.py", 2, 1),
                row("sqlalchemy", "app/main.py", 3, 2),
                row("yaml", "app/main.py", 10, 1),
            ]
        );
        let with_tests = python_imports(&project, true);
        assert!(with_tests.iter().any(|m| m.module == "pytest"));
        std::fs::remove_dir_all(dir).ok();
    }
}
