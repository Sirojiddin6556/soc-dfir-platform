//! A set of source files analyzed together, so calls across files resolve.

use crate::ir::Module;
use crate::Language;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Files larger than this are skipped: generated or minified code.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_FILES: usize = 50_000;

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".tox",
    "site-packages",
    "target",
    "build",
    "dist",
    ".idea",
    ".vscode",
    "vendor",
];

pub struct ModuleInfo {
    /// Dotted module name for Python, the relative path otherwise.
    pub name: String,
    /// Path relative to the project root, with `/` separators.
    pub path: String,
    pub lang: Language,
    pub is_package: bool,
    /// Test code (see `is_test_path`).
    pub is_test: bool,
    pub ir: Module,
    pub parse_errors: bool,
    /// Line of the first syntax error.
    pub first_error: Option<u32>,
    source: String,
}

impl ModuleInfo {
    pub fn line_text(&self, line: u32) -> String {
        let text = self
            .source
            .lines()
            .nth(line.saturating_sub(1) as usize)
            .unwrap_or("")
            .trim();
        if text.chars().count() > 240 {
            let cut: String = text.chars().take(240).collect();
            format!("{cut}…")
        } else {
            text.to_string()
        }
    }

    pub fn line_count(&self) -> usize {
        self.source.lines().count()
    }
}

#[derive(Default)]
pub struct Project {
    pub modules: Vec<ModuleInfo>,
    by_name: HashMap<String, usize>,
    packages: HashSet<String>,
    /// Files that were found but not analyzed, with the reason.
    pub skipped: Vec<(String, String)>,
    /// Values of keys in the project's `.properties` files, every value
    /// found for a key.
    pub config: HashMap<String, Vec<String>>,
}

pub fn language_of(path: &Path) -> Option<Language> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "py" => Language::Python,
        "php" | "phtml" | "php5" | "php7" | "inc" => Language::Php,
        "java" => Language::Java,
        "c" | "h" => Language::C,
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => Language::Cpp,
        _ => return None,
    })
}

/// The language of a file given its text too: a `.h` header holding
/// classes or namespaces is C++.
pub fn language_of_source(path: &Path, source: &str) -> Option<Language> {
    let lang = language_of(path)?;
    let header = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("h"));
    if lang == Language::C && header && looks_like_cpp(source) {
        return Some(Language::Cpp);
    }
    Some(lang)
}

/// C++ declarations outside `#ifdef __cplusplus` blocks, which C headers
/// keep for their C++ users.
fn looks_like_cpp(source: &str) -> bool {
    // `#if` nesting inside a `__cplusplus` block, while in one.
    let mut guarded: Option<usize> = None;
    for line in source.lines() {
        let l = line.trim_start();
        if let Some(d) = l.strip_prefix('#').map(str::trim_start) {
            let opens = d.starts_with("if");
            match guarded.as_mut() {
                Some(depth) if opens => *depth += 1,
                Some(0) if d.starts_with("endif") => guarded = None,
                Some(depth) if d.starts_with("endif") => *depth -= 1,
                None if opens && d.contains("__cplusplus") => guarded = Some(0),
                _ => {}
            }
            continue;
        }
        if guarded.is_some() {
            continue;
        }
        let cpp = [
            "class ",
            "namespace ",
            "template<",
            "template <",
            "using namespace ",
        ]
        .iter()
        .any(|k| l.starts_with(k))
            || matches!(l.trim_end(), "public:" | "private:" | "protected:");
        if cpp {
            return true;
        }
    }
    false
}

impl Project {
    /// Loads every supported source file under `root`.
    pub fn from_dir(root: &Path) -> std::io::Result<Project> {
        let mut files = Vec::new();
        let mut skipped = Vec::new();
        let mut config_files = Vec::new();
        walk(root, root, &mut files, &mut skipped, &mut config_files)?;
        files.sort();
        let mut sources = Vec::new();
        for rel in files {
            if sources.len() >= MAX_FILES {
                skipped.push((rel, "превышен предел числа файлов".into()));
                continue;
            }
            let full = root.join(&rel);
            match std::fs::read(&full) {
                Ok(bytes) => sources.push((rel, String::from_utf8_lossy(&bytes).into_owned())),
                Err(e) => skipped.push((rel, e.to_string())),
            }
        }
        let dirs_with_init: HashSet<String> = sources
            .iter()
            .filter(|(p, _)| p.ends_with("/__init__.py") || p == "__init__.py")
            .map(|(p, _)| {
                p.rsplit_once('/')
                    .map(|(d, _)| d.to_string())
                    .unwrap_or_default()
            })
            .collect();
        let mut project = Project::from_sources_with(sources, &dirs_with_init);
        project.skipped.extend(skipped);
        for rel in config_files {
            if let Ok(text) = std::fs::read_to_string(root.join(&rel)) {
                project.add_properties(&text);
            }
        }
        Ok(project)
    }

    /// Builds a project from in-memory files (`path`, `source`).
    pub fn from_sources(sources: Vec<(String, String)>) -> Project {
        Project::from_sources_with(sources, &HashSet::new())
    }

    fn from_sources_with(
        sources: Vec<(String, String)>,
        dirs_with_init: &HashSet<String>,
    ) -> Project {
        let mut project = Project::default();
        let mut aliases: Vec<(String, usize)> = Vec::new();
        let mut headers = CHeaders::new(&sources);
        for (path, source) in sources {
            let Some(lang) = language_of_source(Path::new(&path), &source) else {
                continue;
            };
            // C and C++ are parsed after preprocessing, which keeps lines
            // where they were; snippets still come from the original.
            let parsed = match lang {
                Language::C | Language::Cpp => {
                    headers.preprocess(&path, &source, lang == Language::Cpp)
                }
                _ => String::new(),
            };
            let text = if parsed.is_empty() { &source } else { &parsed };
            let Some(tree) = crate::parse_tree(lang, text) else {
                project.skipped.push((path, "не удалось разобрать".into()));
                continue;
            };
            let Some(ir) = crate::lower_tree(lang, &tree, text) else {
                project
                    .skipped
                    .push((path, "язык пока не поддерживается".into()));
                continue;
            };
            let (name, is_package) = match (lang, &ir.package) {
                // Java classes are named by package: `org.example.Foo`.
                (Language::Java, package) => {
                    let stem = Path::new(&path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");
                    match package {
                        Some(p) => (format!("{p}.{stem}"), false),
                        None => (stem.to_string(), false),
                    }
                }
                _ => module_name(&path, lang),
            };
            let idx = project.modules.len();
            if lang == Language::Java {
                let package = ir.package.clone().unwrap_or_default();
                let mut prefix = String::new();
                for p in package.split('.').filter(|p| !p.is_empty()) {
                    if !prefix.is_empty() {
                        prefix.push('.');
                    }
                    prefix.push_str(p);
                    project.packages.insert(prefix.clone());
                }
                // Other classes declared in the file are reachable by their
                // own qualified names.
                for s in &ir.body {
                    if let crate::ir::Stmt::ClassDef(c) = s {
                        let q = if package.is_empty() {
                            c.name.clone()
                        } else {
                            format!("{package}.{}", c.name)
                        };
                        aliases.push((q, idx));
                    }
                }
            }
            if lang == Language::Python {
                // Also reachable without the leading directories that are not
                // packages, the way `sys.path` usually points into a project.
                let parts: Vec<&str> = name.split('.').collect();
                let dirs: Vec<&str> = path.split('/').collect();
                for cut in 1..parts.len() {
                    let dir = dirs[..cut].join("/");
                    if !dirs_with_init.contains(&dir) {
                        aliases.push((parts[cut..].join("."), idx));
                    }
                }
                let mut prefix = String::new();
                for p in parts.iter().take(parts.len().saturating_sub(1)) {
                    if !prefix.is_empty() {
                        prefix.push('.');
                    }
                    prefix.push_str(p);
                    project.packages.insert(prefix.clone());
                }
            }
            project.by_name.entry(name.clone()).or_insert(idx);
            project.modules.push(ModuleInfo {
                name,
                is_test: is_test_path(&path),
                path,
                lang,
                is_package,
                parse_errors: tree.root_node().has_error(),
                first_error: first_error(tree.root_node()),
                ir,
                source,
            });
        }
        for (alias, idx) in aliases {
            if !project.by_name.contains_key(&alias) {
                let parts: Vec<&str> = alias.split('.').collect();
                let mut prefix = String::new();
                for p in parts.iter().take(parts.len().saturating_sub(1)) {
                    if !prefix.is_empty() {
                        prefix.push('.');
                    }
                    prefix.push_str(p);
                    project.packages.insert(prefix.clone());
                }
                project.by_name.insert(alias, idx);
            }
        }
        project
    }

    /// Reads `key=value` / `key: value` lines of a Java properties file.
    pub fn add_properties(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            let Some(pos) = line.find(['=', ':']) else {
                continue;
            };
            let key = line[..pos].trim().to_string();
            let value = line[pos + 1..].trim().to_string();
            let values = self.config.entry(key).or_default();
            if !values.contains(&value) {
                values.push(value);
            }
        }
    }

    pub fn module_index(&self, name: &str) -> Option<usize> {
        self.by_name.get(name).copied()
    }

    pub fn is_module_or_package(&self, name: &str) -> bool {
        self.by_name.contains_key(name) || self.packages.contains(name)
    }
}

/// Macros of the project's C and C++ headers, found by file name for
/// `#include "name.h"` (the same directory first).
struct CHeaders {
    by_name: HashMap<String, Vec<(String, String)>>,
    cache: HashMap<String, crate::lower::cpre::Macros>,
    loading: HashSet<String>,
}

impl CHeaders {
    fn new(sources: &[(String, String)]) -> CHeaders {
        let mut by_name: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for (path, src) in sources {
            let lower = path.to_ascii_lowercase();
            if [".h", ".hh", ".hpp", ".hxx", ".inc", ".def"]
                .iter()
                .any(|e| lower.ends_with(e))
            {
                let name = path.rsplit('/').next().unwrap_or(path).to_string();
                by_name
                    .entry(name)
                    .or_default()
                    .push((path.clone(), src.clone()));
            }
        }
        CHeaders {
            by_name,
            cache: HashMap::new(),
            loading: HashSet::new(),
        }
    }

    fn find(&self, from: &str, include: &str) -> Option<(String, String)> {
        let name = include.rsplit('/').next().unwrap_or(include);
        let found = self.by_name.get(name)?;
        let dir = from.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        found
            .iter()
            .find(|(p, _)| p.rsplit_once('/').map(|(d, _)| d).unwrap_or("") == dir)
            .or_else(|| found.iter().find(|(p, _)| p.ends_with(include)))
            .or_else(|| found.first())
            .cloned()
    }

    /// The macros a header defines when read on its own.
    fn macros_of(&mut self, path: &str, src: &str, cpp: bool) -> crate::lower::cpre::Macros {
        if let Some(m) = self.cache.get(path) {
            return m.clone();
        }
        if !self.loading.insert(path.to_string()) {
            return Default::default();
        }
        let mut macros = crate::lower::cpre::predefined(cpp);
        let from = path.to_string();
        crate::lower::cpre::preprocess(src, &mut macros, &mut |inc, m| {
            if let Some((p, s)) = self.find(&from, inc) {
                let found = self.macros_of(&p, &s, cpp);
                for (k, v) in found {
                    m.entry(k).or_insert(v);
                }
            }
        });
        self.loading.remove(path);
        self.cache.insert(path.to_string(), macros.clone());
        macros
    }

    fn preprocess(&mut self, path: &str, src: &str, cpp: bool) -> String {
        let mut macros = crate::lower::cpre::predefined(cpp);
        let from = path.to_string();
        crate::lower::cpre::preprocess(src, &mut macros, &mut |inc, m| {
            if let Some((p, s)) = self.find(&from, inc) {
                if p == from {
                    return;
                }
                let found = self.macros_of(&p, &s, cpp);
                for (k, v) in found {
                    m.entry(k).or_insert(v);
                }
            }
        })
    }
}

fn module_name(path: &str, lang: Language) -> (String, bool) {
    if lang != Language::Python {
        return (path.to_string(), false);
    }
    let stem = path.strip_suffix(".py").unwrap_or(path);
    let dotted = stem.replace('/', ".");
    match dotted.strip_suffix(".__init__") {
        Some(pkg) => (pkg.to_string(), true),
        None if dotted == "__init__" => (String::new(), true),
        None => (dotted, false),
    }
}

/// Test code by the conventions of the languages: a `test`, `tests` or
/// `__tests__` directory, `test_*.py`, `*_test.py`, `tests.py`,
/// `conftest.py`, `*Test.java`, `*Tests.java`, `*IT.java`.
fn first_error(root: tree_sitter::Node) -> Option<u32> {
    if !root.has_error() {
        return None;
    }
    let mut node = root;
    'down: loop {
        let mut cursor = node.walk();
        for c in node.children(&mut cursor) {
            if c.is_error() || c.is_missing() {
                return Some(c.start_position().row as u32 + 1);
            }
            if c.has_error() {
                node = c;
                continue 'down;
            }
        }
        return Some(node.start_position().row as u32 + 1);
    }
}

pub fn is_test_path(path: &str) -> bool {
    let mut parts: Vec<&str> = path.split('/').collect();
    let file = parts.pop().unwrap_or("");
    if parts
        .iter()
        .any(|d| matches!(*d, "test" | "tests" | "__tests__"))
    {
        return true;
    }
    match file.rsplit_once('.') {
        Some((stem, "py")) => {
            stem.starts_with("test_")
                || stem.ends_with("_test")
                || matches!(stem, "tests" | "conftest")
        }
        Some((stem, "java")) => {
            stem.ends_with("Test")
                || stem.ends_with("Tests")
                || stem.ends_with("TestCase")
                || stem.ends_with("IT")
        }
        _ => false,
    }
}

fn walk(
    root: &Path,
    dir: &Path,
    out: &mut Vec<String>,
    skipped: &mut Vec<(String, String)>,
    config: &mut Vec<String>,
) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) || name.starts_with('.') && name.len() > 1 {
                continue;
            }
            walk(root, &path, out, skipped, config)?;
        } else if ft.is_file() && name.ends_with(".properties") && config.len() < 1000 {
            if entry
                .metadata()
                .map(|m| m.len() < 1024 * 1024)
                .unwrap_or(false)
            {
                config.push(
                    path.strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        } else if ft.is_file() && language_of(&path).is_some() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            match entry.metadata() {
                Ok(m) if m.len() > MAX_FILE_BYTES => {
                    skipped.push((rel, "файл слишком большой".into()))
                }
                Ok(_) => out.push(rel),
                Err(e) => skipped.push((rel, e.to_string())),
            }
        }
    }
    Ok(())
}
