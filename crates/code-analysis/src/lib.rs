#![forbid(unsafe_code)]

//! Static analysis of source code for security defects.

pub mod cmembers;
pub mod files;
pub mod interp;
pub mod ir;
pub mod lower;
pub mod models;
pub mod project;
pub mod rules;
pub mod secrets;
pub mod value;
pub mod webapp;

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
        Language::Php => Some(lower::php::lower(tree.root_node(), src)),
        Language::C | Language::Cpp => Some(lower::c::lower(tree.root_node(), src)),
    }
}

/// Parses and lowers one file into the shared IR.
pub fn lower(lang: Language, src: &str) -> Option<ir::Module> {
    if matches!(lang, Language::C | Language::Cpp) {
        let mut macros = lower::cpre::predefined(lang == Language::Cpp);
        let text = lower::cpre::preprocess(src, &mut macros, &mut |_, _| {});
        let tree = parse_tree(lang, &text)?;
        return lower_tree(lang, &tree, &text);
    }
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
    /// Files analyzed by a language front end.
    pub files: usize,
    /// Other files checked as text (secrets, templates), per kind.
    pub other_files: Vec<(String, usize)>,
    /// Files not checked at all, per reason: media, archives, bundles.
    pub unchecked_files: Vec<(String, usize)>,
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
    /// Also treat file contents, command output and session data as
    /// untrusted, not only the request: finds second-order flaws at the
    /// cost of more findings to review.
    pub external_sources: bool,
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

/// Interpreter steps the second run over C entries may always take.
const MIN_SECOND_ROUND: usize = 10_000_000;

/// Analyzes every file of a project.
pub fn analyze(project: &project::Project) -> Report {
    analyze_with(project, Options::default())
}

pub fn analyze_with(project: &project::Project, options: Options) -> Report {
    let started = std::time::Instant::now();
    let mut interp = interp::Interp::new(project);
    interp.external_sources = options.external_sources;
    let mut languages: Vec<(String, usize)> = Vec::new();
    for (i, m) in project.modules.iter().enumerate() {
        match languages.iter_mut().find(|(l, _)| l == m.lang.name()) {
            Some(slot) => slot.1 += 1,
            None => languages.push((m.lang.name().to_string(), 1)),
        }
        if options.include_tests || !m.is_test {
            interp.analyze_module(i);
        }
    }
    // C entries again, with the user data entries stored in globals. That
    // run may cost as much as the first one and no more: where one global
    // reaches everything (nginx keeps its connection pool in `ngx_cycle`)
    // it would explore every entry again with all of it tainted.
    if interp.seed_c_globals() {
        let first = interp.work;
        interp.work_limit = Some(first + first.max(MIN_SECOND_ROUND));
        for (i, m) in project.modules.iter().enumerate() {
            if matches!(m.lang, Language::C | Language::Cpp)
                && (options.include_tests || !m.is_test)
            {
                interp.analyze_module(i);
            }
        }
    }
    let mut findings = std::mem::take(&mut interp.findings);
    findings.extend(text_findings(project, options));
    findings.extend(webapp_findings(project, options));
    // A password under MD5 is one finding: the password rule says more.
    let password_hashes: std::collections::HashSet<(String, u32)> = findings
        .iter()
        .filter(|f| f.rule == "weak-password-hash")
        .map(|f| (f.file.clone(), f.line))
        .collect();
    findings
        .retain(|f| f.rule != "weak-hash" || !password_hashes.contains(&(f.file.clone(), f.line)));
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule.cmp(&b.rule))
    });
    let mut other_files: Vec<(String, usize)> = Vec::new();
    for t in &project.texts {
        if !options.include_tests && t.is_test {
            continue;
        }
        match other_files.iter_mut().find(|(k, _)| k == t.kind.label()) {
            Some(slot) => slot.1 += 1,
            None => other_files.push((t.kind.label().to_string(), 1)),
        }
    }
    Report {
        findings,
        other_files,
        unchecked_files: project
            .unchecked
            .iter()
            .map(|(k, n)| (k.clone(), *n))
            .collect(),
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

/// Findings of the web application model: CSRF, changes on GET, logins
/// without a limit on attempts and the like.
fn webapp_findings(project: &project::Project, options: Options) -> Vec<rules::Finding> {
    webapp::check(project, options.include_tests)
        .into_iter()
        .map(|h| {
            let m = &project.modules[h.module];
            let snippet = m.line_text(h.line);
            let column = m
                .source()
                .lines()
                .nth(h.line.saturating_sub(1) as usize)
                .map(|l| (l.len() - l.trim_start().len()) as u32 + 1)
                .unwrap_or(1);
            let at = rules::Location {
                file: m.path.clone(),
                line: h.line,
                column,
                note: format!("сток: {}", h.what),
            };
            rules::Finding {
                rule: h.rule.id.to_string(),
                cwe: h.rule.cwe,
                severity: h.rule.severity,
                title: h.rule.title.to_string(),
                message: format!("{}: {}", h.rule.title, h.what),
                file: m.path.clone(),
                line: h.line,
                column,
                snippet,
                source: None,
                trace: vec![at],
                other_sources: Vec::new(),
            }
        })
        .collect()
}

/// Findings of the checks that read files as text: secrets in code of
/// every language and in the files no front end reads.
fn text_findings(project: &project::Project, options: Options) -> Vec<rules::Finding> {
    let mut out = Vec::new();
    let code = project
        .modules
        .iter()
        .filter(|m| options.include_tests || !m.is_test)
        .map(|m| (m.path.as_str(), m.source(), secrets::Origin::Code));
    let texts = project
        .texts
        .iter()
        .filter(|t| options.include_tests || !t.is_test)
        .map(|t| {
            (
                t.path.as_str(),
                t.text.as_str(),
                secrets::Origin::Text(t.kind),
            )
        });
    for (path, text, origin) in code.chain(texts) {
        let cx = secrets::Context {
            origin,
            sample: files::is_sample_path(path),
            ignored: files::ignored_by_git(&project.gitignores, path),
            lines: files::line_settings(path),
        };
        let hits = secrets::scan(text, cx);
        if hits.is_empty() {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        for h in &hits {
            let line = lines.get(h.line as usize - 1).copied().unwrap_or("");
            let hides: Vec<(usize, usize)> = hits
                .iter()
                .filter(|o| o.line == h.line)
                .map(|o| o.hide)
                .collect();
            let shown = secrets::masked_line(line, &hides);
            let mut snippet = shown.trim().to_string();
            if snippet.chars().count() > 240 {
                snippet = format!("{}…", snippet.chars().take(240).collect::<String>());
            }
            let at = rules::Location {
                file: path.to_string(),
                line: h.line,
                column: h.column,
                note: format!("сток: {}", h.what),
            };
            out.push(rules::Finding {
                rule: h.rule.id.to_string(),
                cwe: h.rule.cwe,
                severity: h.rule.severity,
                title: h.rule.title.to_string(),
                message: format!("{}: {}", h.rule.title, h.what),
                file: path.to_string(),
                line: h.line,
                column: h.column,
                snippet,
                source: None,
                trace: vec![at],
                other_sources: Vec::new(),
            });
        }
    }
    out
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
