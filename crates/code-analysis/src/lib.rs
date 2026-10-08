#![forbid(unsafe_code)]

//! Static analysis of source code for security defects.

pub mod interp;
pub mod ir;
pub mod lower;
pub mod models;
pub mod project;
pub mod rules;
pub mod value;

use serde::Serialize;

/// Source languages the analyzer understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Python,
    Php,
    Java,
    C,
    Cpp,
}

impl Language {
    fn grammar(self) -> tree_sitter::Language {
        match self {
            Language::Python => tree_sitter_python::LANGUAGE.into(),
            Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
            Language::Java => tree_sitter_java::LANGUAGE.into(),
            Language::C => tree_sitter_c::LANGUAGE.into(),
            Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        }
    }
}

pub fn parse_tree(lang: Language, src: &str) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&lang.grammar()).ok()?;
    parser.parse(src, None)
}

/// Lowers a parsed file into the shared IR.
pub fn lower_tree(lang: Language, tree: &tree_sitter::Tree, src: &str) -> Option<ir::Module> {
    match lang {
        Language::Python => Some(lower::python::lower(tree.root_node(), src)),
        Language::Java => Some(lower::java::lower(tree.root_node(), src)),
        _ => None,
    }
}

/// Parses and lowers one file into the shared IR.
pub fn lower(lang: Language, src: &str) -> Option<ir::Module> {
    let tree = parse_tree(lang, src)?;
    lower_tree(lang, &tree, src)
}

impl Language {
    pub fn name(self) -> &'static str {
        match self {
            Language::Python => "python",
            Language::Php => "php",
            Language::Java => "java",
            Language::C => "c",
            Language::Cpp => "cpp",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub findings: Vec<rules::Finding>,
    pub files: usize,
    pub lines: usize,
    /// Files per language that were analyzed.
    pub languages: Vec<(String, usize)>,
    pub skipped: Vec<(String, String)>,
    pub parse_errors: Vec<String>,
    /// Test files: loaded so calls resolve, not analyzed unless asked.
    pub test_files: usize,
    /// Time spent reading and parsing the files, then analyzing them.
    pub load_ms: u64,
    pub analysis_ms: u64,
}

/// Stack for the analysis thread: the interpreter recurses through calls,
/// imports and nested expressions.
const STACK_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Also look for defects in test code, which does not run in
    /// production.
    pub include_tests: bool,
}

/// Loads and analyzes every supported file under `root`, on a thread with
/// a stack large enough for deep projects.
pub fn analyze_dir(root: &std::path::Path) -> std::io::Result<Report> {
    analyze_dir_with(root, Options::default())
}

pub fn analyze_dir_with(root: &std::path::Path, options: Options) -> std::io::Result<Report> {
    let root = root.to_path_buf();
    std::thread::Builder::new()
        .name("code-analysis".into())
        .stack_size(STACK_BYTES)
        .spawn(move || {
            let started = std::time::Instant::now();
            let project = project::Project::from_dir(&root)?;
            let load_ms = started.elapsed().as_millis() as u64;
            let mut report = analyze_with(&project, options);
            report.load_ms = load_ms;
            Ok(report)
        })?
        .join()
        .map_err(|_| std::io::Error::other("анализ кода завершился аварийно"))?
}

/// Analyzes every file of a project.
pub fn analyze(project: &project::Project) -> Report {
    analyze_with(project, Options::default())
}

pub fn analyze_with(project: &project::Project, options: Options) -> Report {
    let started = std::time::Instant::now();
    let mut interp = interp::Interp::new(project);
    let mut languages: Vec<(String, usize)> = Vec::new();
    for (i, m) in project.modules.iter().enumerate() {
        match languages.iter_mut().find(|(l, _)| l == m.lang.name()) {
            Some(slot) => slot.1 += 1,
            None => languages.push((m.lang.name().to_string(), 1)),
        }
        if matches!(m.lang, Language::Python | Language::Java)
            && (options.include_tests || !m.is_test)
        {
            interp.analyze_module(i);
        }
    }
    let mut findings = std::mem::take(&mut interp.findings);
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule.cmp(&b.rule))
    });
    Report {
        findings,
        files: project.modules.len(),
        lines: project.modules.iter().map(|m| m.line_count()).sum(),
        languages,
        skipped: project.skipped.clone(),
        parse_errors: project
            .modules
            .iter()
            .filter(|m| m.parse_errors)
            .map(|m| m.path.clone())
            .collect(),
        test_files: if options.include_tests {
            0
        } else {
            project.modules.iter().filter(|m| m.is_test).count()
        },
        load_ms: 0,
        analysis_ms: started.elapsed().as_millis() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_grammar_loads() {
        for lang in [
            Language::Python,
            Language::Php,
            Language::Java,
            Language::C,
            Language::Cpp,
        ] {
            let tree = parse_tree(lang, "").expect("grammar loads");
            assert!(!tree.root_node().has_error());
        }
    }
}
