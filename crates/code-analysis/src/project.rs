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
    pub ir: Module,
    pub parse_errors: bool,
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

impl Project {
    /// Loads every supported source file under `root`.
    pub fn from_dir(root: &Path) -> std::io::Result<Project> {
        let mut files = Vec::new();
        let mut skipped = Vec::new();
        walk(root, root, &mut files, &mut skipped)?;
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
        for (path, source) in sources {
            let Some(lang) = language_of(Path::new(&path)) else {
                continue;
            };
            let Some(tree) = crate::parse_tree(lang, &source) else {
                project.skipped.push((path, "не удалось разобрать".into()));
                continue;
            };
            let Some(ir) = crate::lower_tree(lang, &tree, &source) else {
                project
                    .skipped
                    .push((path, "язык пока не поддерживается".into()));
                continue;
            };
            let (name, is_package) = module_name(&path, lang);
            let idx = project.modules.len();
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
                path,
                lang,
                is_package,
                parse_errors: tree.root_node().has_error(),
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

    pub fn module_index(&self, name: &str) -> Option<usize> {
        self.by_name.get(name).copied()
    }

    pub fn is_module_or_package(&self, name: &str) -> bool {
        self.by_name.contains_key(name) || self.packages.contains(name)
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

fn walk(
    root: &Path,
    dir: &Path,
    out: &mut Vec<String>,
    skipped: &mut Vec<(String, String)>,
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
            walk(root, &path, out, skipped)?;
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
