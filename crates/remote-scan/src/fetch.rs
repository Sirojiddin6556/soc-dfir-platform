//! What a project fetch over SFTP downloads, and what it leaves on the server.
//!
//! The predicates and limits here are transport-free so they can be unit
//! tested without a network; [`crate::ssh`] drives them against a live SFTP
//! session. The fetch is **read-only**: it only lists directories and reads
//! files, never writes, renames or removes anything on the target.

use serde::Serialize;

/// Bounds on a project fetch, so a huge or hostile tree cannot fill the disk
/// or hang the scan. Defaults are generous enough for real source trees but
/// stop well short of a whole server.
#[derive(Debug, Clone, Copy)]
pub struct FetchLimits {
    /// Files downloaded, at most.
    pub max_files: usize,
    /// Bytes downloaded in total, at most.
    pub max_total_bytes: u64,
    /// A single file larger than this is skipped (likely generated data,
    /// not source).
    pub max_file_bytes: u64,
    /// Directory nesting followed, at most (a guard against symlink-free but
    /// pathologically deep trees).
    pub max_depth: usize,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            max_files: 20_000,
            max_total_bytes: 300 * 1024 * 1024,
            max_file_bytes: 8 * 1024 * 1024,
            max_depth: 50,
        }
    }
}

/// What the fetch brought back and what it deliberately left behind, so the
/// report can say honestly how complete the copy was.
#[derive(Debug, Default, Clone, Serialize)]
pub struct FetchSummary {
    pub files: usize,
    pub bytes: u64,
    /// Dependency/build/VCS directories not descended into (relative paths).
    pub skipped_dirs: Vec<String>,
    /// Files skipped because they are larger than `max_file_bytes`.
    pub skipped_large: Vec<String>,
    /// Files skipped because their extension is binary or media.
    pub skipped_binary: Vec<String>,
    /// Symlinks not followed (relative paths), so the fetch cannot escape the
    /// tree or loop.
    pub skipped_symlinks: Vec<String>,
    /// True when a limit stopped the fetch, so the copy is partial.
    pub truncated: bool,
    /// Human-readable reason the fetch was cut short, when `truncated`.
    pub limit_hit: Option<String>,
}

/// Directory names never descended into: third-party code, build output and
/// version-control metadata. Skipping them keeps the copy to the project's
/// own source; manifests (package.json, composer.json, pom.xml, ...) that the
/// dependency check reads live at the project root, not inside these.
const EXCLUDED_DIRS: &[&str] = &[
    ".git",
    ".svn",
    ".hg",
    ".bzr",
    "node_modules",
    "bower_components",
    "vendor",
    "target",
    "build",
    "dist",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".gradle",
    ".idea",
    ".vs",
    ".vscode",
    "obj",
    "coverage",
    ".cache",
    ".terraform",
    "Pods",
    "DerivedData",
    "elm-stuff",
    ".dart_tool",
];

/// True when a directory with this exact name should not be entered.
pub fn is_excluded_dir(name: &str) -> bool {
    EXCLUDED_DIRS.contains(&name)
}

/// Binary and media file extensions not worth downloading: source analysis
/// ignores them and they only inflate the transfer. Kept lower-case; the
/// caller lower-cases the name first.
const BINARY_EXTENSIONS: &[&str] = &[
    // images
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tiff", "tif", "heic", "psd", "ai",
    // video / audio
    "mp4", "mov", "avi", "mkv", "webm", "flv", "wmv", "mp3", "wav", "flac", "ogg", "aac", "m4a",
    // archives / packages
    "zip", "tar", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "jar", "war", "ear", "whl", "egg",
    "apk", "ipa", "deb", "rpm", "dmg", "iso", // documents
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", // fonts
    "ttf", "otf", "woff", "woff2", "eot", // compiled / data blobs
    "exe", "dll", "so", "dylib", "o", "obj", "a", "lib", "class", "pyc", "pyo", "wasm", "bin",
    "dat", "db", "sqlite", "sqlite3", "mdb", "pack", "idx",
];

/// True when a file name's extension marks it as binary or media and it should
/// not be downloaded.
pub fn is_binary_path(name: &str) -> bool {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => {
            BINARY_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_dependency_build_and_vcs_directories() {
        for d in [
            ".git",
            "node_modules",
            "vendor",
            "target",
            "__pycache__",
            ".venv",
        ] {
            assert!(is_excluded_dir(d), "{d} should be excluded");
        }
        // The project's own source directories are kept.
        for d in ["src", "app", "lib", "tests", "server", "components"] {
            assert!(!is_excluded_dir(d), "{d} should be kept");
        }
    }

    #[test]
    fn skips_binary_and_media_but_keeps_source_and_config() {
        for f in [
            "logo.PNG",
            "demo.mp4",
            "bundle.zip",
            "app.jar",
            "report.pdf",
            "font.woff2",
            "libssl.so",
            "data.sqlite",
        ] {
            assert!(is_binary_path(f), "{f} should be skipped");
        }
        // Source, markup and dependency manifests are downloaded.
        for f in [
            "views.py",
            "index.js",
            "Main.java",
            "composer.json",
            "package.json",
            "pom.xml",
            "requirements.txt",
            "config.yaml",
            "Dockerfile",
            ".env",
            "README.md",
            "styles.css",
        ] {
            assert!(!is_binary_path(f), "{f} should be downloaded");
        }
    }

    #[test]
    fn dotfiles_without_an_extension_are_not_binary() {
        assert!(!is_binary_path(".env"));
        assert!(!is_binary_path(".gitignore"));
        assert!(!is_binary_path("Makefile"));
    }
}
