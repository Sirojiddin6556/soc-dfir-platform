//! Project files that no language front end reads: templates, scripts,
//! configuration, documentation. They are checked as text (`secrets`,
//! `templates`), so a scan looks at every file and says which it skipped.

/// Text files larger than this are not checked: data dumps, bundles.
pub const MAX_TEXT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextKind {
    /// HTML and template languages (Jinja, Twig, ERB, JSP, Vue).
    Template,
    /// JavaScript and TypeScript.
    Script,
    /// `.env` files: settings and secrets kept next to the code.
    Env,
    /// YAML, JSON, TOML, INI, XML, properties, Dockerfiles.
    Config,
    /// Shell and batch scripts.
    Shell,
    /// Markdown, plain text.
    Doc,
    /// Any other text.
    Other,
}

impl TextKind {
    /// How the report names files of this kind.
    pub fn label(self) -> &'static str {
        match self {
            TextKind::Template => "шаблоны",
            TextKind::Script => "JS/TS",
            TextKind::Env => ".env",
            TextKind::Config => "конфигурация",
            TextKind::Shell => "скрипты оболочки",
            TextKind::Doc => "документация",
            TextKind::Other => "прочий текст",
        }
    }

    /// Settings are read as `key = value` lines.
    pub fn is_settings(self) -> bool {
        matches!(self, TextKind::Env | TextKind::Config | TextKind::Shell)
    }
}

/// Whether the lines of a settings file are `key = value` or `key: value`
/// pairs (`.env`, INI, YAML, properties), not JSON or XML, whose values
/// are quoted.
pub fn line_settings(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    !matches!(ext, "json" | "xml" | "plist" | "gradle" | "tf" | "tfvars")
}

pub struct TextFile {
    /// Path relative to the project root, with `/` separators.
    pub path: String,
    pub kind: TextKind,
    pub text: String,
    pub is_test: bool,
}

/// The kind of a file no front end reads, by its name; `None` for files
/// that are never text (images, archives, databases).
pub fn text_kind(path: &str) -> Option<TextKind> {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
        return Some(TextKind::Env);
    }
    if name == "dockerfile" || name.starts_with("dockerfile.") || name.ends_with(".dockerfile") {
        return Some(TextKind::Config);
    }
    if matches!(
        name.as_str(),
        ".npmrc" | ".pypirc" | ".netrc" | ".htpasswd" | ".htaccess" | ".git-credentials"
    ) {
        return Some(TextKind::Config);
    }
    let ext = match name.rsplit_once('.') {
        Some((_, e)) => e,
        None => return Some(TextKind::Other),
    };
    Some(match ext {
        "html" | "htm" | "xhtml" | "jinja" | "jinja2" | "j2" | "twig" | "tpl" | "mustache"
        | "hbs" | "handlebars" | "ejs" | "erb" | "jsp" | "jspx" | "vue" | "svelte" | "njk"
        | "liquid" | "ftl" | "vm" | "cshtml" | "razor" => TextKind::Template,
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" => TextKind::Script,
        "yml" | "yaml" | "json" | "toml" | "ini" | "cfg" | "conf" | "config" | "xml"
        | "properties" | "tf" | "tfvars" | "plist" | "gradle" | "cnf" => TextKind::Config,
        "sh" | "bash" | "zsh" | "ksh" | "bat" | "cmd" | "ps1" | "psm1" => TextKind::Shell,
        "md" | "markdown" | "txt" | "rst" | "adoc" => TextKind::Doc,
        // Never text, or text no rule reads: media, archives, databases,
        // fonts, compiled code, source maps, lock files and certificates.
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "ico" | "webp" | "svg" | "tif" | "tiff"
        | "mp3" | "mp4" | "wav" | "avi" | "mov" | "webm" | "ogg" | "flac" | "pdf" | "zip"
        | "gz" | "tgz" | "bz2" | "xz" | "7z" | "rar" | "tar" | "jar" | "war" | "ear" | "class"
        | "pyc" | "pyo" | "so" | "dll" | "exe" | "o" | "a" | "lib" | "obj" | "bin" | "dat"
        | "db" | "sqlite" | "sqlite3" | "woff" | "woff2" | "ttf" | "otf" | "eot" | "map"
        | "lock" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "psd" | "wasm" | "der"
        | "crt" | "cer" | "p12" | "pfx" | "keystore" | "jks" => return None,
        _ => TextKind::Other,
    })
}

/// Text that is not a bundle or a binary blob: no NUL byte near the start
/// and no line of minified code.
pub fn looks_like_text(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(8192)];
    !head.contains(&0)
}

/// Minified scripts and styles: one long line holds the whole file.
pub fn is_minified(path: &str, text: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.contains(".min.") || (text.len() > 5000 && text.lines().take(5).any(|l| l.len() > 2000))
}

/// Whether `.gitignore` files of the project keep `path` out of git: a
/// line naming the file, its name or a pattern such as `.env*` or `*.env`.
pub fn ignored_by_git(root_ignores: &[(String, String)], path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    root_ignores.iter().any(|(dir, text)| {
        let inside = dir.is_empty() || path.starts_with(&format!("{dir}/"));
        inside
            && text.lines().any(|l| {
                let l = l.trim();
                if l.is_empty() || l.starts_with('#') || l.starts_with('!') {
                    return false;
                }
                let pat = l.trim_start_matches('/');
                let rel = if dir.is_empty() {
                    path.to_string()
                } else {
                    path[dir.len() + 1..].to_string()
                };
                glob_match(pat, name) || glob_match(pat, &rel)
            })
    })
}

/// `*` and `?` patterns of `.gitignore`, enough for file names.
fn glob_match(pat: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], t) || (!t.is_empty() && t[0] != b'/' && go(p, &t[1..])),
            (Some(b'?'), Some(c)) if *c != b'/' => go(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &t[1..]),
            _ => false,
        }
    }
    go(pat.as_bytes(), text.as_bytes())
}

/// Files of directories that hold samples rather than the program:
/// placeholder secrets there are not findings.
pub fn is_sample_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let sample_name = name.contains("example")
        || name.contains("sample")
        || [".dist", ".template", ".default", "-tpl", ".orig", ".bak"]
            .iter()
            .any(|s| name.ends_with(s));
    sample_name
        || lower.split('/').any(|d| {
            matches!(
                d,
                "example"
                    | "examples"
                    | "sample"
                    | "samples"
                    | "docs"
                    | "doc"
                    | "fixtures"
                    | "testdata"
                    | "test-data"
                    | "test_data"
                    | "testing"
                    | "regress"
                    | "unittests"
                    | "unittest"
                    | "tutorial"
                    | "tutorials"
                    | "demo"
                    | "demos"
                    | "mocks"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_by_name() {
        assert_eq!(text_kind(".env"), Some(TextKind::Env));
        assert_eq!(text_kind("deploy/.env.production"), Some(TextKind::Env));
        assert_eq!(
            text_kind("templates/admin/login.html"),
            Some(TextKind::Template)
        );
        assert_eq!(text_kind("static/app.js"), Some(TextKind::Script));
        assert_eq!(text_kind("config/settings.yaml"), Some(TextKind::Config));
        assert_eq!(text_kind("Dockerfile"), Some(TextKind::Config));
        assert_eq!(text_kind("logo.png"), None);
        assert_eq!(text_kind("shifotech.db"), None);
    }

    #[test]
    fn gitignore_patterns() {
        let ig = vec![(String::new(), ".env\n*.log\n".to_string())];
        assert!(ignored_by_git(&ig, ".env"));
        assert!(ignored_by_git(&ig, "app/.env"));
        assert!(!ignored_by_git(&ig, ".env.production"));
        let ig = vec![(String::new(), ".env*\n".to_string())];
        assert!(ignored_by_git(&ig, ".env.production"));
        let ig = vec![("web".to_string(), "/.env\n".to_string())];
        assert!(ignored_by_git(&ig, "web/.env"));
        assert!(!ignored_by_git(&ig, ".env"));
    }
}
