#![forbid(unsafe_code)]

//! Local vulnerability database for host scanning.
//!
//! `vulndb.update` downloads the public feeds -- OSV distribution advisories
//! (Debian, Ubuntu, AlmaLinux, Rocky Linux) on Linux, the Microsoft Security
//! Response Center monthly security updates on Windows, the CISA KEV catalog
//! and FIRST EPSS scores -- and imports them into `<data dir>/vulndb/vuln.db`.
//! `scan.cve` matches this machine against it: installed dpkg/rpm packages on
//! Linux, the OS product and build (with UBR) on Windows. OSV advisories of
//! application packages (PyPI, npm, Maven ...) are loaded on request for
//! the dependency check of code analysis.
//!
//! With `SOC_VULNDB_OFFLINE_DIR` set the engine never goes online and reads
//! the same files from that directory instead (air-gapped installs):
//!   Ubuntu_24.04_LTS.zip (or Ubuntu.zip), PyPI.zip, 2026-Sep.json (MSRC CVRF
//!   documents, any number), known_exploited_vulnerabilities.json,
//!   epss_scores-current.csv.gz

use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use vulnerability_engine::deps::{self, DependencyCheck, PackageQuery};
use vulnerability_engine::feeds::{self, FeedSource};
use vulnerability_engine::msrc::{self, WindowsHostFacts};
use vulnerability_engine::package_scan::{self, InstalledPackage};
use vulnerability_engine::VulnDbRepository;

const OSV_BUCKET: &str = "https://osv-vulnerabilities.storage.googleapis.com";
const KEV_URLS: [&str; 2] = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    // CISA's own mirror of the same catalog.
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
];
const EPSS_URLS: [&str; 2] = [
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
];
const MSRC_API: &str = "https://api.msrc.microsoft.com/cvrf/v3.0";
/// Monthly MSRC documents downloaded when the request names no number.
pub const DEFAULT_MSRC_MONTHS: u32 = 12;
const MAX_MSRC_MONTHS: u32 = 120;
const KEV_FILE: &str = "known_exploited_vulnerabilities.json";
const EPSS_FILES: [&str; 2] = ["epss_scores-current.csv.gz", "epss_scores-current.csv"];
/// The whole-Ubuntu export is ~800 MB; anything far beyond that is not a feed.
const MAX_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize)]
pub struct UpdateJob {
    pub running: bool,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    /// What the update is doing right now, for the progress line.
    pub current: Option<String>,
    pub steps: Vec<UpdateStep>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateStep {
    pub feed: String,
    pub ok: bool,
    /// The source reported no change since the last import.
    pub unchanged: bool,
    pub source: Option<String>,
    pub records: Option<u64>,
    pub message: String,
}

pub struct VulnDbService {
    dir: PathBuf,
    offline_dir: Option<PathBuf>,
    repo: Mutex<Option<VulnDbRepository>>,
    job: Mutex<UpdateJob>,
    /// The status line's host description; collecting it runs dpkg/rpm or
    /// PowerShell, too slow for the UI's once-a-second polling.
    host_cache: Mutex<Option<(std::time::Instant, Value)>>,
}

/// What scanning can see of the machine the engine runs on.
enum LocalHost {
    Linux(platform_linux::PackageInventory),
    Windows(Result<WindowsHostFacts, String>),
}

fn local_host() -> LocalHost {
    if cfg!(windows) {
        LocalHost::Windows(platform_windows::system::collect_os_info().and_then(windows_facts_from))
    } else {
        LocalHost::Linux(platform_linux::collect_package_inventory())
    }
}

pub fn windows_facts_from(
    os: platform_windows::system::WindowsOsInfo,
) -> Result<WindowsHostFacts, String> {
    let build = os
        .build
        .ok_or_else(|| "Win32_OperatingSystem не вернул номер сборки".to_string())?;
    Ok(WindowsHostFacts {
        caption: os.caption.trim().to_string(),
        version: os.version,
        build,
        ubr: os.ubr,
        display_version: os.display_version,
        installation_type: os.installation_type,
        product_type: os.product_type,
        architecture: os.architecture,
        installed_kbs: os.kbs,
    })
}

fn windows_display_name(facts: &WindowsHostFacts) -> String {
    let mut name = facts.caption.clone();
    if !facts.display_version.is_empty() {
        name = format!("{name} {}", facts.display_version);
    }
    name
}

/// A feed file ready to import.
struct Fetched {
    path: PathBuf,
    /// Downloaded into our directory (deleted after import) or user-provided.
    temporary: bool,
    source: FeedSource,
}

enum FetchOutcome {
    Unchanged(String),
    New(Fetched),
}

enum FetchError {
    NotFound(String),
    Failed(String),
}

impl FetchError {
    fn message(self) -> String {
        match self {
            FetchError::NotFound(m) | FetchError::Failed(m) => m,
        }
    }
}

fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(20)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .user_agent(concat!("soc-dfir-platform/", env!("CARGO_PKG_VERSION")))
            // The OS trust store, so corporate TLS-inspecting proxies work too.
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .into()
    })
}

/// "Ubuntu:24.04:LTS" -> "Ubuntu%3A24.04%3ALTS"-free path segment: OSV
/// bucket object names keep ':' and only need spaces escaped.
fn bucket_segment(ecosystem: &str) -> String {
    let mut out = String::new();
    for b in ecosystem.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// File-system friendly name of an ecosystem ("Rocky Linux:9" -> "Rocky_Linux_9").
fn file_stem(ecosystem: &str) -> String {
    ecosystem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// "Debian:12", "Ubuntu:24.04:LTS", "Rocky Linux:9": a supported
/// distribution, a numeric release and an optional ":LTS"; or an
/// application package ecosystem ("PyPI", "npm" ...).
fn valid_ecosystem(ecosystem: &str) -> bool {
    if deps::is_language_ecosystem(ecosystem) {
        return true;
    }
    let mut parts = ecosystem.split(':');
    let (Some(base), Some(release)) = (parts.next(), parts.next()) else {
        return false;
    };
    let rest: Vec<&str> = parts.collect();
    package_scan::is_supported_ecosystem(base)
        && !release.is_empty()
        && release.len() <= 16
        && release.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && release.as_bytes()[0].is_ascii_digit()
        && (rest.is_empty() || rest == ["LTS"])
}

fn mib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0))
}

fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Clears `running` even if the update thread panics.
struct RunningGuard<'a>(&'a VulnDbService);

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        let mut job = self.0.job.lock().unwrap_or_else(|p| p.into_inner());
        job.running = false;
        job.current = None;
        job.finished_at = Some(Utc::now().to_rfc3339());
    }
}

impl VulnDbService {
    pub fn new(dir: PathBuf, offline_dir: Option<PathBuf>) -> Self {
        Self {
            dir,
            offline_dir,
            repo: Mutex::new(None),
            job: Mutex::new(UpdateJob::default()),
            host_cache: Mutex::new(None),
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.join("vuln.db")
    }

    fn repo(&self) -> Result<VulnDbRepository, String> {
        let mut guard = self.repo.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(repo) = guard.as_ref() {
            return Ok(repo.clone());
        }
        let repo = VulnDbRepository::open_or_create(self.db_path()).map_err(|e| {
            format!(
                "Не удалось открыть базу уязвимостей {}: {}",
                self.db_path().display(),
                e
            )
        })?;
        *guard = Some(repo.clone());
        Ok(repo)
    }

    fn set_current(&self, text: String) {
        self.job.lock().unwrap_or_else(|p| p.into_inner()).current = Some(text);
    }

    fn push_step(&self, step: UpdateStep) {
        self.job
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .steps
            .push(step);
    }

    /// Feed list for the UI and API: what is loaded, when, from where.
    fn feeds_json(&self, repo: &VulnDbRepository) -> Vec<Value> {
        let Ok(snapshot) = repo.get_snapshot_info() else {
            return Vec::new();
        };
        snapshot
            .feeds
            .iter()
            .map(|f| {
                let (kind, ecosystem) = if let Some(eco) = f.name.strip_prefix("osv:") {
                    ("osv", Some(eco.to_string()))
                } else if f.name == msrc::MSRC_FEED {
                    ("msrc", None)
                } else if f.name == feeds::KEV_FEED {
                    ("kev", None)
                } else if f.name == feeds::EPSS_FEED {
                    ("epss", None)
                } else {
                    ("other", None)
                };
                let source = feeds::feed_source(repo, &f.name)
                    .ok()
                    .flatten()
                    .map(|s| s.source);
                json!({
                    "name": f.name,
                    "kind": kind,
                    "ecosystem": ecosystem,
                    "records": f.records_count,
                    "version_date": f.version_date,
                    "checked_at": f.imported_at.to_rfc3339(),
                    "stale": f.is_stale,
                    "source": source,
                })
            })
            .collect()
    }

    fn host_json(&self) -> Value {
        let mut cache = self.host_cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, value)) = cache.as_ref() {
            if at.elapsed() < Duration::from_secs(60) {
                return value.clone();
            }
        }
        let value = match local_host() {
            LocalHost::Linux(inventory) => {
                let supported = inventory
                    .ecosystem
                    .as_deref()
                    .map(package_scan::is_supported_ecosystem)
                    .unwrap_or(false);
                json!({
                    "platform": "linux",
                    "os": inventory.os_name,
                    "ecosystem": inventory.ecosystem,
                    "supported": supported,
                    "packages": inventory.packages.len(),
                })
            }
            LocalHost::Windows(Ok(facts)) => {
                let product = msrc::msrc_product_name(&facts);
                json!({
                    "platform": "windows",
                    "os": windows_display_name(&facts),
                    "build": facts.full_build(),
                    "product": product.as_ref().ok(),
                    "supported": product.is_ok(),
                    "detail": product.err(),
                    "installed_updates": facts.installed_kbs.len(),
                    "ecosystem": null,
                    "packages": 0,
                })
            }
            LocalHost::Windows(Err(e)) => json!({
                "platform": "windows",
                "os": "Windows",
                "supported": false,
                "detail": e,
                "ecosystem": null,
                "packages": 0,
            }),
        };
        *cache = Some((std::time::Instant::now(), value.clone()));
        value
    }

    pub fn status(&self) -> Value {
        let host = self.host_json();
        let job = self.job.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let (available, error, feeds) = match self.repo() {
            Ok(repo) => (true, None, self.feeds_json(&repo)),
            Err(e) => (false, Some(e), Vec::new()),
        };
        json!({
            "db_path": self.db_path().display().to_string(),
            "available": available,
            "error": error,
            "offline_dir": self.offline_dir.as_ref().map(|p| p.display().to_string()),
            "feeds": feeds,
            "host": host,
            "update": job,
        })
    }

    /// Advisories for application packages, from the OSV data of their
    /// ecosystems loaded so far.
    pub fn check_dependencies(&self, queries: &[PackageQuery]) -> Result<DependencyCheck, String> {
        let repo = self.repo()?;
        deps::check_packages(&repo, queries)
            .map_err(|e| format!("Не удалось проверить зависимости по базе уязвимостей: {e}"))
    }

    /// When the OSV data of each loaded ecosystem was last imported or
    /// confirmed current, by ecosystem name.
    pub fn osv_checked_at(&self) -> std::collections::HashMap<String, String> {
        let Ok(snapshot) = self
            .repo()
            .and_then(|r| r.get_snapshot_info().map_err(|e| e.to_string()))
        else {
            return Default::default();
        };
        snapshot
            .feeds
            .iter()
            .filter_map(|f| {
                let eco = f.name.strip_prefix("osv:")?;
                Some((eco.to_string(), f.imported_at.to_rfc3339()))
            })
            .collect()
    }

    /// Whether a database update is running now.
    pub fn updating(&self) -> bool {
        self.job.lock().unwrap_or_else(|p| p.into_inner()).running
    }

    /// Starts a background update of the OSV data for `ecosystems` (the local
    /// distribution when empty), the last `msrc_months` MSRC documents (by
    /// default on Windows only), plus KEV and EPSS.
    pub fn start_update(
        self: &Arc<Self>,
        ecosystems: Vec<String>,
        msrc_months: Option<u32>,
    ) -> Result<Value, String> {
        if let Some(m) = msrc_months {
            if m == 0 || m > MAX_MSRC_MONTHS {
                return Err(format!("msrc_months должно быть от 1 до {MAX_MSRC_MONTHS}"));
            }
        }
        let msrc_months = msrc_months.or(if cfg!(windows) && ecosystems.is_empty() {
            Some(DEFAULT_MSRC_MONTHS)
        } else {
            None
        });
        let mut ecosystems: Vec<String> = ecosystems
            .into_iter()
            .map(|e| e.trim().to_string())
            .collect();
        if let Some(bad) = ecosystems.iter().find(|e| !valid_ecosystem(e)) {
            return Err(format!(
                "Экосистема '{bad}' не поддерживается: доступны Debian:N, Ubuntu:NN.NN[:LTS], AlmaLinux:N, Rocky Linux:N, {}",
                deps::LANGUAGE_ECOSYSTEMS.join(", ")
            ));
        }
        if ecosystems.is_empty() && !cfg!(windows) {
            if let Some(eco) = platform_linux::collect_package_inventory()
                .ecosystem
                .filter(|e| package_scan::is_supported_ecosystem(e))
            {
                ecosystems.push(eco);
            }
        }
        ecosystems.dedup();
        self.repo()?;

        {
            let mut job = self.job.lock().unwrap_or_else(|p| p.into_inner());
            if job.running {
                return Err("Обновление базы уже выполняется".to_string());
            }
            *job = UpdateJob {
                running: true,
                started_at: Some(Utc::now().to_rfc3339()),
                finished_at: None,
                current: Some("Подготовка".to_string()),
                steps: Vec::new(),
            };
        }

        let service = Arc::clone(self);
        let planned = ecosystems.clone();
        std::thread::Builder::new()
            .name("vulndb-update".into())
            .spawn(move || service.run_update(ecosystems, msrc_months))
            .map_err(|e| {
                self.job.lock().unwrap_or_else(|p| p.into_inner()).running = false;
                format!("Не удалось запустить обновление: {e}")
            })?;

        Ok(json!({
            "started": true,
            "ecosystems": planned,
            "msrc_months": msrc_months,
            "offline": self.offline_dir.is_some(),
        }))
    }

    fn run_update(&self, ecosystems: Vec<String>, msrc_months: Option<u32>) {
        let _guard = RunningGuard(self);
        let repo = match self.repo() {
            Ok(r) => r,
            Err(e) => {
                self.push_step(UpdateStep {
                    feed: "vulndb".into(),
                    ok: false,
                    unchanged: false,
                    source: None,
                    records: None,
                    message: e,
                });
                return;
            }
        };
        for eco in &ecosystems {
            let step = self.update_osv(&repo, eco);
            self.push_step(step);
        }
        if let Some(months) = msrc_months {
            let step = self.update_msrc(&repo, months as usize);
            self.push_step(step);
        }
        let step = self.update_kev(&repo);
        self.push_step(step);
        let step = self.update_epss(&repo);
        self.push_step(step);
    }

    fn update_osv(&self, repo: &VulnDbRepository, ecosystem: &str) -> UpdateStep {
        let feed = feeds::osv_feed_name(ecosystem);
        let base = ecosystem.split(':').next().unwrap_or(ecosystem);
        let mut urls = vec![format!(
            "{OSV_BUCKET}/{}/all.zip",
            bucket_segment(ecosystem)
        )];
        let mut files = vec![
            format!("{}.zip", file_stem(ecosystem)),
            format!("{ecosystem}/all.zip"),
        ];
        if base != ecosystem {
            // Not every release has its own export (AlmaLinux:9 has none);
            // the distribution-wide one is filtered to the release on import.
            urls.push(format!("{OSV_BUCKET}/{}/all.zip", bucket_segment(base)));
            files.push(format!("{}.zip", file_stem(base)));
            files.push(format!("{base}/all.zip"));
        }
        let label = format!("OSV {ecosystem}");
        let fetched = match self.fetch(repo, &feed, &label, &urls, &files) {
            Ok(f) => f,
            Err(message) => return failed_step(feed, message),
        };
        let fetched = match fetched {
            FetchOutcome::Unchanged(source) => return unchanged_step(repo, feed, source),
            FetchOutcome::New(f) => f,
        };

        self.set_current(format!("{label}: импорт записей"));
        let result = std::fs::File::open(&fetched.path)
            .map_err(|e| e.to_string())
            .and_then(|file| {
                feeds::import_osv_archive(
                    repo,
                    BufReader::new(file),
                    ecosystem,
                    &fetched.source.sha256,
                    |done, total| {
                        self.set_current(format!("{label}: импорт {done} из {total} записей"))
                    },
                )
                .map_err(|e| e.to_string())
            });
        if fetched.temporary {
            let _ = std::fs::remove_file(&fetched.path);
        }
        match result {
            Ok(stats) => {
                let _ = feeds::record_feed_source(repo, &feed, &fetched.source);
                let mut message = format!(
                    "{} записей, {} диапазонов версий",
                    stats.records, stats.affected_rows
                );
                if stats.unreadable_files > 0 {
                    message.push_str(&format!(
                        "; {} файлов архива не разобрано",
                        stats.unreadable_files
                    ));
                }
                UpdateStep {
                    feed,
                    ok: true,
                    unchanged: false,
                    source: Some(fetched.source.source),
                    records: Some(stats.records as u64),
                    message,
                }
            }
            Err(e) => failed_step(feed, format!("Импорт {label} не удался: {e}")),
        }
    }

    fn update_kev(&self, repo: &VulnDbRepository) -> UpdateStep {
        let feed = feeds::KEV_FEED.to_string();
        let urls: Vec<String> = KEV_URLS.iter().map(|u| u.to_string()).collect();
        let fetched = match self.fetch(repo, &feed, "CISA KEV", &urls, &[KEV_FILE.to_string()]) {
            Ok(FetchOutcome::New(f)) => f,
            Ok(FetchOutcome::Unchanged(source)) => return unchanged_step(repo, feed, source),
            Err(message) => return failed_step(feed, message),
        };
        self.set_current("CISA KEV: импорт".to_string());
        let result = std::fs::read_to_string(&fetched.path)
            .map_err(|e| e.to_string())
            .and_then(|text| {
                feeds::import_kev_catalog(repo, &text, &fetched.source.sha256)
                    .map_err(|e| e.to_string())
            });
        self.finish_simple_import(
            repo,
            feed,
            fetched,
            result,
            "уязвимостей, эксплуатируемых в атаках",
        )
    }

    fn update_epss(&self, repo: &VulnDbRepository) -> UpdateStep {
        let feed = feeds::EPSS_FEED.to_string();
        let urls: Vec<String> = EPSS_URLS.iter().map(|u| u.to_string()).collect();
        let files: Vec<String> = EPSS_FILES.iter().map(|f| f.to_string()).collect();
        let fetched = match self.fetch(repo, &feed, "FIRST EPSS", &urls, &files) {
            Ok(FetchOutcome::New(f)) => f,
            Ok(FetchOutcome::Unchanged(source)) => return unchanged_step(repo, feed, source),
            Err(message) => return failed_step(feed, message),
        };
        self.set_current("FIRST EPSS: импорт".to_string());
        let result = std::fs::read(&fetched.path)
            .map_err(|e| e.to_string())
            .and_then(|data| {
                feeds::import_epss_scores(repo, &data, &fetched.source.sha256)
                    .map_err(|e| e.to_string())
            });
        self.finish_simple_import(
            repo,
            feed,
            fetched,
            result,
            "оценок вероятности эксплуатации",
        )
    }

    /// Imports the newest `months` MSRC monthly documents. A document whose
    /// revision date has not changed since its last import is not fetched again.
    fn update_msrc(&self, repo: &VulnDbRepository, months: usize) -> UpdateStep {
        let feed = msrc::MSRC_FEED.to_string();
        let imported: std::collections::HashMap<String, msrc::ImportedDocument> =
            msrc::imported_documents(repo)
                .unwrap_or_default()
                .into_iter()
                .map(|d| (d.id.clone(), d))
                .collect();
        let wanted = match &self.offline_dir {
            Some(dir) => offline_msrc_documents(dir),
            None => self.msrc_index(months),
        };
        let wanted = match wanted {
            Ok(list) if !list.is_empty() => list,
            Ok(_) => {
                return failed_step(
                    feed,
                    match &self.offline_dir {
                        Some(dir) => format!(
                            "MSRC: в каталоге {} нет документов вида 2026-Sep.json",
                            dir.display()
                        ),
                        None => "MSRC: в списке обновлений нет ни одного ежемесячного документа"
                            .to_string(),
                    },
                )
            }
            Err(e) => return failed_step(feed, e),
        };

        let total = wanted.len();
        let mut fresh = 0usize;
        let mut unchanged = 0usize;
        let mut bytes = 0u64;
        let mut errors: Vec<String> = Vec::new();
        for (i, doc) in wanted.iter().enumerate() {
            let label = format!("MSRC {} ({} из {total})", doc.id, i + 1);
            let previous = imported.get(&doc.id);
            if let (Some(rev), Some(prev)) = (&doc.revision, previous) {
                if same_revision(rev, prev.current_release.as_deref()) {
                    unchanged += 1;
                    continue;
                }
            }
            let (path, temporary, source) = if self.offline_dir.is_some() {
                let path = PathBuf::from(&doc.location);
                self.set_current(format!("{label}: проверка {}", path.display()));
                let (sha256, size) = match sha256_file(&path) {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!("{}: {e}", doc.id));
                        continue;
                    }
                };
                if previous.map(|p| p.sha256 == sha256).unwrap_or(false) {
                    unchanged += 1;
                    continue;
                }
                let source = FeedSource {
                    source: doc.location.clone(),
                    etag: None,
                    last_modified: None,
                    bytes: size,
                    sha256,
                    fetched_at: Utc::now().to_rfc3339(),
                };
                (path, false, source)
            } else {
                if let Err(e) = std::fs::create_dir_all(self.dir.join("downloads")) {
                    return failed_step(feed, format!("Не удалось создать каталог загрузок: {e}"));
                }
                let dest = self
                    .dir
                    .join("downloads")
                    .join(format!("msrc-{}.download", doc.id));
                match self.download(&doc.location, &dest, None, &label, Some("application/json")) {
                    Ok(Some(source)) => (dest, true, source),
                    Ok(None) => {
                        unchanged += 1;
                        continue;
                    }
                    Err(e) => {
                        errors.push(format!("{}: {}", doc.id, e.message()));
                        continue;
                    }
                }
            };
            self.set_current(format!("{label}: импорт"));
            let result = std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|data| {
                    msrc::import_msrc_document(
                        repo,
                        &doc.id,
                        &data,
                        &msrc::DocumentSource {
                            source: source.source.clone(),
                            sha256: source.sha256.clone(),
                            bytes: source.bytes,
                        },
                    )
                    .map_err(|e| e.to_string())
                });
            if temporary {
                let _ = std::fs::remove_file(&path);
            }
            match result {
                Ok(_) => {
                    fresh += 1;
                    bytes += source.bytes;
                }
                Err(e) => errors.push(format!("{}: {e}", doc.id)),
            }
        }

        if fresh == 0 && unchanged == 0 {
            return failed_step(feed, format!("MSRC: {}", errors.join("; ")));
        }
        let origin = match &self.offline_dir {
            Some(dir) => dir.display().to_string(),
            None => MSRC_API.to_string(),
        };
        if fresh == 0 {
            let _ = feeds::touch_feed(repo, &feed);
        } else {
            let _ = feeds::record_feed_source(
                repo,
                &feed,
                &FeedSource {
                    source: origin.clone(),
                    etag: None,
                    last_modified: None,
                    bytes,
                    sha256: String::new(),
                    fetched_at: Utc::now().to_rfc3339(),
                },
            );
        }
        let cves = repo
            .get_snapshot_info()
            .ok()
            .and_then(|s| s.feeds.into_iter().find(|f| f.name == feed))
            .map(|f| f.records_count)
            .unwrap_or(0);
        let mut message = format!(
            "{total} ежемесячных документов: новых {fresh}, без изменений {unchanged}; уязвимостей Windows в базе: {cves}"
        );
        if !errors.is_empty() {
            message.push_str(&format!("; не загружены: {}", errors.join("; ")));
        }
        UpdateStep {
            feed,
            ok: errors.is_empty(),
            unchanged: fresh == 0 && errors.is_empty(),
            source: Some(origin),
            records: Some(cves),
            message,
        }
    }

    /// The newest `months` monthly security update documents from the MSRC index.
    fn msrc_index(&self, months: usize) -> Result<Vec<MsrcDocumentRef>, String> {
        let url = format!("{MSRC_API}/updates");
        self.set_current(format!("MSRC: список документов ({url})"));
        let response = agent()
            .get(&url)
            .header("Accept", "application/json")
            .call()
            .map_err(|e| format!("MSRC {url}: {e}"))?;
        if response.status().as_u16() != 200 {
            return Err(format!("MSRC {url}: HTTP {}", response.status().as_u16()));
        }
        let body = response
            .into_body()
            .into_with_config()
            .limit(16 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| format!("MSRC {url}: {e}"))?;
        parse_msrc_index(&body, months).map_err(|e| format!("MSRC {url}: {e}"))
    }

    fn finish_simple_import(
        &self,
        repo: &VulnDbRepository,
        feed: String,
        fetched: Fetched,
        result: Result<usize, String>,
        what: &str,
    ) -> UpdateStep {
        if fetched.temporary {
            let _ = std::fs::remove_file(&fetched.path);
        }
        match result {
            Ok(count) => {
                let _ = feeds::record_feed_source(repo, &feed, &fetched.source);
                UpdateStep {
                    feed,
                    ok: true,
                    unchanged: false,
                    source: Some(fetched.source.source),
                    records: Some(count as u64),
                    message: format!("{count} {what}"),
                }
            }
            Err(e) => failed_step(feed.clone(), format!("Импорт {feed} не удался: {e}")),
        }
    }

    /// Gets a feed file: from the offline directory when one is configured,
    /// otherwise by downloading the first URL that answers.
    fn fetch(
        &self,
        repo: &VulnDbRepository,
        feed: &str,
        label: &str,
        urls: &[String],
        offline_files: &[String],
    ) -> Result<FetchOutcome, String> {
        let previous = feeds::feed_source(repo, feed).ok().flatten();

        if let Some(dir) = &self.offline_dir {
            let Some(path) = offline_files
                .iter()
                .map(|name| dir.join(name))
                .find(|p| p.is_file())
            else {
                return Err(format!(
                    "{label}: в каталоге {} нет ни одного из файлов: {}",
                    dir.display(),
                    offline_files.join(", ")
                ));
            };
            self.set_current(format!("{label}: проверка {}", path.display()));
            let (sha256, bytes) = sha256_file(&path)
                .map_err(|e| format!("{label}: не удалось прочитать {}: {e}", path.display()))?;
            let source = path.display().to_string();
            if previous
                .as_ref()
                .map(|p| p.sha256 == sha256)
                .unwrap_or(false)
            {
                return Ok(FetchOutcome::Unchanged(source));
            }
            return Ok(FetchOutcome::New(Fetched {
                path,
                temporary: false,
                source: FeedSource {
                    source,
                    etag: None,
                    last_modified: None,
                    bytes,
                    sha256,
                    fetched_at: Utc::now().to_rfc3339(),
                },
            }));
        }

        std::fs::create_dir_all(self.dir.join("downloads"))
            .map_err(|e| format!("Не удалось создать каталог загрузок: {e}"))?;
        let dest = self
            .dir
            .join("downloads")
            .join(format!("{}.download", file_stem(feed)));
        let mut errors = Vec::new();
        for url in urls {
            let etag = previous
                .as_ref()
                .filter(|p| &p.source == url)
                .and_then(|p| p.etag.clone());
            match self.download(url, &dest, etag.as_deref(), label, None) {
                Ok(Some(source)) => {
                    return Ok(FetchOutcome::New(Fetched {
                        path: dest,
                        temporary: true,
                        source,
                    }))
                }
                Ok(None) => return Ok(FetchOutcome::Unchanged(url.clone())),
                Err(e) => errors.push(e.message()),
            }
        }
        Err(format!("{label}: {}", errors.join("; ")))
    }

    /// Streams `url` into `dest`. `Ok(None)` means the server answered
    /// 304 Not Modified for `etag`.
    fn download(
        &self,
        url: &str,
        dest: &Path,
        etag: Option<&str>,
        label: &str,
        accept: Option<&str>,
    ) -> Result<Option<FeedSource>, FetchError> {
        self.set_current(format!("{label}: соединение с {url}"));
        let mut request = agent().get(url);
        if let Some(tag) = etag {
            request = request.header("If-None-Match", tag);
        }
        if let Some(accept) = accept {
            request = request.header("Accept", accept);
        }
        let response = request
            .call()
            .map_err(|e| FetchError::Failed(format!("{url}: {e}")))?;
        let status = response.status().as_u16();
        match status {
            200 => {}
            304 => return Ok(None),
            404 => return Err(FetchError::NotFound(format!("{url}: HTTP 404"))),
            other => return Err(FetchError::Failed(format!("{url}: HTTP {other}"))),
        }
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        };
        let new_etag = header("etag");
        let last_modified = header("last-modified");
        let total: Option<u64> = header("content-length").and_then(|v| v.parse().ok());

        let part = dest.with_extension("part");
        let mut out = std::fs::File::create(&part)
            .map_err(|e| FetchError::Failed(format!("{}: {e}", part.display())))?;
        let mut reader = response
            .into_body()
            .into_with_config()
            .limit(MAX_DOWNLOAD_BYTES)
            .reader();
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut done = 0u64;
        let mut last_report = 0u64;
        let result: std::io::Result<()> = (|| {
            loop {
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n])?;
                hasher.update(&buf[..n]);
                done += n as u64;
                if done - last_report >= 1 << 20 {
                    last_report = done;
                    self.set_current(match total {
                        Some(t) => format!("{label}: скачано {} из {} МБ", mib(done), mib(t)),
                        None => format!("{label}: скачано {} МБ", mib(done)),
                    });
                }
            }
            out.flush()
        })();
        drop(out);
        if let Err(e) = result {
            let _ = std::fs::remove_file(&part);
            return Err(FetchError::Failed(format!("{url}: обрыв загрузки: {e}")));
        }
        if let Some(t) = total {
            if t != done {
                let _ = std::fs::remove_file(&part);
                return Err(FetchError::Failed(format!(
                    "{url}: получено {done} байт из {t}"
                )));
            }
        }
        std::fs::rename(&part, dest)
            .map_err(|e| FetchError::Failed(format!("{}: {e}", dest.display())))?;
        Ok(Some(FeedSource {
            source: url.to_string(),
            etag: new_etag,
            last_modified,
            bytes: done,
            sha256: hex::encode(hasher.finalize()),
            fetched_at: Utc::now().to_rfc3339(),
        }))
    }

    /// Matches this machine's installed packages against the database.
    pub fn scan_local_packages(&self, host_id: &str) -> Value {
        let hostname = crate::default_host_id();
        let base = |status: &str, detail: String| {
            json!({
                "host_id": host_id,
                "hostname": hostname,
                "scanned_at": Utc::now().to_rfc3339(),
                "status": status,
                "status_detail": detail,
                "findings": [],
                "calculated_risk": 0.0,
            })
        };
        if crate::host_inspector::local_host_key(host_id).is_none() {
            return base(
                "NOT_LOCAL_HOST",
                format!(
                    "Хост '{host_id}' не является этой машиной ({hostname}): список пакетов собирается только локально"
                ),
            );
        }

        if let LocalHost::Windows(facts) = local_host() {
            return self.scan_windows(host_id, facts);
        }

        let inventory = platform_linux::collect_package_inventory();
        let Some(ecosystem) = inventory
            .ecosystem
            .clone()
            .filter(|e| package_scan::is_supported_ecosystem(e))
        else {
            let detail = format!(
                "Дистрибутив {} не поддерживается: базы OSV подключены для Debian, Ubuntu, AlmaLinux и Rocky Linux",
                inventory.os_name
            );
            let mut v = base("UNSUPPORTED_PLATFORM", detail);
            v["os"] = json!(inventory.os_name);
            return v;
        };
        if inventory.packages.is_empty() {
            let mut v = base(
                "NO_PACKAGE_INVENTORY",
                format!(
                    "Список установленных пакетов пуст: {}",
                    inventory.errors.join("; ")
                ),
            );
            v["os"] = json!(inventory.os_name);
            return v;
        }
        let repo = match self.repo() {
            Ok(r) => r,
            Err(e) => return base("DATASET_UNAVAILABLE", e),
        };

        let packages: Vec<InstalledPackage> = inventory
            .packages
            .iter()
            .filter(|p| p.source == "dpkg" || p.source == "rpm")
            .map(|p| InstalledPackage {
                name: p.product.clone(),
                version: p.version.clone(),
                source_name: p.source_package.clone(),
                source_version: p.source_version.clone(),
            })
            .collect();
        let report = match package_scan::scan_installed_packages(&repo, &ecosystem, &packages) {
            Ok(r) => r,
            Err(e) => {
                return base(
                    "DATASET_CORRUPT",
                    format!("Ошибка чтения базы уязвимостей: {e}"),
                )
            }
        };

        let feeds = self.feeds_json(&repo);
        let osv_feed = feeds
            .iter()
            .find(|f| f["name"] == feeds::osv_feed_name(&ecosystem).as_str());
        let dataset_stale = osv_feed
            .map(|f| f["stale"].as_bool().unwrap_or(false))
            .unwrap_or(false);
        let (status, detail) = if report.ecosystem_rows == 0 {
            (
                "VULNDB_EMPTY",
                format!(
                    "База уязвимостей для {ecosystem} не загружена: обновите базу, иначе проверка ничего не доказывает"
                ),
            )
        } else if report.findings.is_empty() {
            (
                "NO_KNOWN_MATCHED_VULNERABILITIES",
                format!(
                    "Известных уязвимостей в {} пакетах не найдено по базе OSV {ecosystem}",
                    report.packages_total
                ),
            )
        } else {
            (
                "VULNERABILITIES_FOUND",
                format!(
                    "Найдено {} уязвимостей в {} компонентах",
                    report.findings.len(),
                    report
                        .findings
                        .iter()
                        .map(|f| f.component.as_str())
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                ),
            )
        };
        let calculated_risk = report
            .findings
            .iter()
            .filter_map(|f| f.cvss_score)
            .fold(0.0f64, f64::max);
        let kev_loaded = feeds.iter().any(|f| f["kind"] == "kev");
        let epss_loaded = feeds.iter().any(|f| f["kind"] == "epss");

        json!({
            "host_id": host_id,
            "hostname": hostname,
            "os": inventory.os_name,
            "scanned_at": Utc::now().to_rfc3339(),
            "status": status,
            "status_detail": detail,
            "dataset_stale": dataset_stale,
            "ecosystem": ecosystem,
            "packages_total": report.packages_total,
            "components_checked": report.components_checked,
            "components_with_advisories": report.components_with_advisories,
            "summary": {
                "total": report.findings.len(),
                "critical": report.severity_counts.critical,
                "high": report.severity_counts.high,
                "medium": report.severity_counts.medium,
                "low": report.severity_counts.low,
                "unknown": report.severity_counts.unknown,
                "kev": report.kev_count,
                "no_fix": report.no_fix_count,
                "patched": report.patched_count,
            },
            "findings": report.findings,
            "calculated_risk": calculated_risk,
            "database": {
                "feeds": feeds,
                "kev_loaded": kev_loaded,
                "epss_loaded": epss_loaded,
            },
            "collection_errors": inventory.errors,
        })
    }
}

/// A monthly MSRC document to import: where it is (a URL, or a file in the
/// offline directory) and, from the online index, its current revision.
#[derive(Debug, Clone, PartialEq)]
struct MsrcDocumentRef {
    id: String,
    location: String,
    revision: Option<String>,
}

/// Picks the newest `months` monthly security update documents from the
/// MSRC `updates` index (other entries are release notes and the like).
fn parse_msrc_index(body: &str, months: usize) -> Result<Vec<MsrcDocumentRef>, String> {
    let index: Value = serde_json::from_str(body).map_err(|e| format!("ответ не JSON: {e}"))?;
    let list = index["value"]
        .as_array()
        .ok_or_else(|| "в ответе нет списка документов".to_string())?;
    let mut docs: Vec<MsrcDocumentRef> = list
        .iter()
        .filter_map(|item| {
            let id = item["ID"].as_str()?;
            let title = item["DocumentTitle"].as_str().unwrap_or("");
            if !msrc::is_document_id(id) || !title.contains("Security Update") {
                return None;
            }
            Some(MsrcDocumentRef {
                id: id.to_string(),
                location: format!("{MSRC_API}/cvrf/{id}"),
                revision: item["CurrentReleaseDate"].as_str().map(str::to_string),
            })
        })
        .collect();
    docs.sort_by_key(|d| std::cmp::Reverse(msrc::document_month(&d.id)));
    docs.dedup_by(|a, b| a.id == b.id);
    docs.truncate(months);
    Ok(docs)
}

/// MSRC documents in the offline directory: `2026-Sep.json` or
/// `msrc-2026-Sep.json`, newest first.
fn offline_msrc_documents(dir: &Path) -> Result<Vec<MsrcDocumentRef>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("MSRC: не удалось прочитать каталог {}: {e}", dir.display()))?;
    let mut docs: Vec<MsrcDocumentRef> = entries
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?;
            let stem = name.strip_suffix(".json")?;
            let id = stem.strip_prefix("msrc-").unwrap_or(stem);
            if !msrc::is_document_id(id) || !path.is_file() {
                return None;
            }
            Some(MsrcDocumentRef {
                id: id.to_string(),
                location: path.display().to_string(),
                revision: None,
            })
        })
        .collect();
    docs.sort_by(|a, b| {
        msrc::document_month(&b.id)
            .cmp(&msrc::document_month(&a.id))
            .then(a.location.cmp(&b.location))
    });
    docs.dedup_by(|a, b| a.id == b.id);
    Ok(docs)
}

/// The index gives revision dates with a zone suffix, the document itself
/// without one: `2026-10-07T01:57:28Z` vs `2026-10-07T01:57:28`.
fn same_revision(index: &str, imported: Option<&str>) -> bool {
    let trim = |s: &str| s.trim().trim_end_matches('Z').to_string();
    imported.map(|i| trim(i) == trim(index)).unwrap_or(false)
}

impl VulnDbService {
    /// Matches a Windows host (product, build with update revision, installed
    /// KBs) against the imported MSRC documents. Takes the facts as input so
    /// it runs, and is tested, on any platform.
    fn scan_windows(&self, host_id: &str, facts: Result<WindowsHostFacts, String>) -> Value {
        let hostname = crate::default_host_id();
        let base = |status: &str, detail: String, os: &str| {
            json!({
                "host_id": host_id,
                "hostname": hostname,
                "platform": "windows",
                "os": os,
                "scanned_at": Utc::now().to_rfc3339(),
                "status": status,
                "status_detail": detail,
                "findings": [],
                "calculated_risk": 0.0,
            })
        };
        let facts = match facts {
            Ok(f) => f,
            Err(e) => {
                return base(
                    "UNSUPPORTED_PLATFORM",
                    format!("Не удалось определить версию и сборку Windows: {e}"),
                    "Windows",
                )
            }
        };
        let os = windows_display_name(&facts);
        let build = facts.full_build();
        let product = match msrc::msrc_product_name(&facts) {
            Ok(p) => p,
            Err(e) => {
                let mut v = base("UNSUPPORTED_PLATFORM", e, &os);
                v["build"] = json!(build);
                return v;
            }
        };
        let repo = match self.repo() {
            Ok(r) => r,
            Err(e) => return base("DATASET_UNAVAILABLE", e, &os),
        };
        let report = match msrc::scan_windows_host(&repo, &facts, &product) {
            Ok(r) => r,
            Err(e) => {
                return base(
                    "DATASET_CORRUPT",
                    format!("Ошибка чтения базы уязвимостей: {e}"),
                    &os,
                )
            }
        };

        let feeds = self.feeds_json(&repo);
        let dataset_stale = feeds
            .iter()
            .find(|f| f["kind"] == "msrc")
            .map(|f| f["stale"].as_bool().unwrap_or(false))
            .unwrap_or(false);
        let window = match (report.documents.last(), report.documents.first()) {
            (Some(oldest), Some(newest)) if oldest != newest => format!("{oldest} – {newest}"),
            (Some(only), _) => only.clone(),
            _ => String::new(),
        };
        let (status, mut detail) = if report.documents.is_empty() {
            (
                "VULNDB_EMPTY",
                "Бюллетени безопасности Microsoft (MSRC) не загружены: обновите базу, иначе проверка ничего не доказывает"
                    .to_string(),
            )
        } else if !report.product_known {
            (
                "PRODUCT_NOT_IN_DATABASE",
                format!(
                    "{product} не встречается в загруженных бюллетенях MSRC ({window}): за эти месяцы Microsoft не выпускала для него исправлений, сопоставить сборку {build} не с чем"
                ),
            )
        } else if report.findings.is_empty() {
            (
                "NO_KNOWN_MATCHED_VULNERABILITIES",
                format!(
                    "Сборка {build} содержит исправления для {} из {} уязвимостей {product} по бюллетеням MSRC за {window}",
                    report.patched_count, report.cves_for_product
                ),
            )
        } else {
            (
                "VULNERABILITIES_FOUND",
                format!(
                    "Сборке {build} не хватает исправлений для {} из {} уязвимостей {product} по бюллетеням MSRC за {window}",
                    report.findings.len(),
                    report.cves_for_product
                ),
            )
        };
        if !report.unverified.is_empty() {
            detail.push_str(&format!(
                ". Для {} уязвимостей исправления выпущены только для другой ветки сборок, сравнить их с {build} нельзя",
                report.unverified.len()
            ));
        }
        if report.older_than_window {
            detail.push_str(&format!(
                ". Сборка старше самого раннего загруженного бюллетеня ({}): уязвимости более ранних месяцев не проверялись, загрузите бюллетени за больший срок",
                report.documents.last().map(String::as_str).unwrap_or("")
            ));
        }
        let calculated_risk = report
            .findings
            .iter()
            .filter_map(|f| f.cvss_score)
            .fold(0.0f64, f64::max);
        let no_fix = report
            .findings
            .iter()
            .filter(|f| matches!(f.status, package_scan::FindingStatus::NoFix))
            .count();
        let kev_loaded = feeds.iter().any(|f| f["kind"] == "kev");
        let epss_loaded = feeds.iter().any(|f| f["kind"] == "epss");

        json!({
            "host_id": host_id,
            "hostname": hostname,
            "platform": "windows",
            "os": os,
            "scanned_at": Utc::now().to_rfc3339(),
            "status": status,
            "status_detail": detail,
            "dataset_stale": dataset_stale,
            "ecosystem": null,
            "summary": {
                "total": report.findings.len(),
                "critical": report.severity_counts.critical,
                "high": report.severity_counts.high,
                "medium": report.severity_counts.medium,
                "low": report.severity_counts.low,
                "unknown": report.severity_counts.unknown,
                "kev": report.kev_count,
                "exploited": report.exploited_count,
                "no_fix": no_fix,
                "patched": report.patched_count,
                "unverified": report.unverified.len(),
            },
            "findings": report.findings,
            "calculated_risk": calculated_risk,
            "database": {
                "feeds": feeds,
                "kev_loaded": kev_loaded,
                "epss_loaded": epss_loaded,
            },
            "windows": {
                "product": report.product,
                "build": report.build,
                "installed_updates": facts.installed_kbs,
                "documents": report.documents,
                "cves_for_product": report.cves_for_product,
                "unverified": report.unverified,
                "older_than_window": report.older_than_window,
            },
            "collection_errors": [],
        })
    }
}

fn failed_step(feed: String, message: String) -> UpdateStep {
    tracing::warn!("vulndb update: {message}");
    UpdateStep {
        feed,
        ok: false,
        unchanged: false,
        source: None,
        records: None,
        message,
    }
}

fn unchanged_step(repo: &VulnDbRepository, feed: String, source: String) -> UpdateStep {
    let _ = feeds::touch_feed(repo, &feed);
    UpdateStep {
        feed,
        ok: true,
        unchanged: true,
        source: Some(source),
        records: None,
        message: "Источник не изменился с прошлого обновления".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_and_file_names() {
        assert_eq!(bucket_segment("Ubuntu:24.04:LTS"), "Ubuntu:24.04:LTS");
        assert_eq!(bucket_segment("Rocky Linux:9"), "Rocky%20Linux:9");
        assert_eq!(file_stem("Ubuntu:24.04:LTS"), "Ubuntu_24.04_LTS");
        assert_eq!(file_stem("Rocky Linux:9"), "Rocky_Linux_9");
    }

    #[test]
    fn ecosystem_validation() {
        assert!(valid_ecosystem("Ubuntu:24.04:LTS"));
        assert!(valid_ecosystem("Debian:12"));
        assert!(valid_ecosystem("Rocky Linux:9"));
        assert!(valid_ecosystem("PyPI"));
        assert!(valid_ecosystem("crates.io"));
        assert!(!valid_ecosystem("pypi"));
        assert!(!valid_ecosystem("PyPI:1"));
        assert!(!valid_ecosystem("Debian:../../etc"));
        assert!(!valid_ecosystem("Debian:.."));
        assert!(!valid_ecosystem("Debian"));
        assert!(!valid_ecosystem("Ubuntu:24.04:LTS:x"));
        assert!(!valid_ecosystem(""));
    }

    const MSRC_TESTDATA: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vulnerability-engine/testdata"
    );

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("soc-vulndb-{tag}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An offline directory holding the trimmed real MSRC documents.
    fn offline_with_msrc_documents() -> PathBuf {
        let dir = temp_dir("offline");
        for id in ["2026-Aug", "2025-Jan", "2024-Oct"] {
            let name = if id == "2025-Jan" {
                format!("msrc-{id}.json")
            } else {
                format!("{id}.json")
            };
            std::fs::copy(format!("{MSRC_TESTDATA}/msrc-{id}.json"), dir.join(name)).unwrap();
        }
        dir
    }

    fn server_2025(ubr: u32) -> WindowsHostFacts {
        WindowsHostFacts {
            caption: "Microsoft Windows Server 2025 Datacenter".into(),
            version: "10.0.26100".into(),
            build: 26100,
            ubr: Some(ubr),
            display_version: "24H2".into(),
            installation_type: "Server".into(),
            product_type: Some(3),
            architecture: "x86_64".into(),
            installed_kbs: vec!["KB5054979".into()],
        }
    }

    #[test]
    fn msrc_index_keeps_the_newest_monthly_security_updates() {
        let index = r#"{"value":[
            {"ID":"2000-Feb","CurrentReleaseDate":"2026-02-19T01:07:19Z","DocumentTitle":"Mariner Release Notes"},
            {"ID":"2026-Jul","CurrentReleaseDate":"2026-10-06T07:00:00Z","DocumentTitle":"July 2026 Security Updates"},
            {"ID":"2026-Oct","CurrentReleaseDate":"2026-10-07T01:51:58Z","DocumentTitle":"October 2026 Early Security Updates"},
            {"ID":"2026-Aug","CurrentReleaseDate":"2026-10-07T01:57:28Z","DocumentTitle":"August 2026 Security Updates"},
            {"ID":"2026-Aug-OOB","CurrentReleaseDate":"2026-10-07T01:57:28Z","DocumentTitle":"August 2026 Security Updates"},
            {"ID":"2025-Jan","DocumentTitle":"January 2025 Security Updates"}
        ]}"#;
        let docs = parse_msrc_index(index, 3).unwrap();
        let ids: Vec<&str> = docs.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, vec!["2026-Oct", "2026-Aug", "2026-Jul"]);
        assert_eq!(
            docs[1],
            MsrcDocumentRef {
                id: "2026-Aug".into(),
                location: format!("{MSRC_API}/cvrf/2026-Aug"),
                revision: Some("2026-10-07T01:57:28Z".into()),
            }
        );
        assert_eq!(parse_msrc_index(index, 12).unwrap().len(), 4);
        assert!(parse_msrc_index("<html>", 12).is_err());
        assert!(parse_msrc_index(r#"{"error":"x"}"#, 12).is_err());
    }

    #[test]
    fn msrc_revision_dates_compare_without_zone() {
        assert!(same_revision(
            "2026-10-07T01:57:28Z",
            Some("2026-10-07T01:57:28")
        ));
        assert!(!same_revision(
            "2026-10-07T01:57:28Z",
            Some("2026-10-06T07:00:00")
        ));
        assert!(!same_revision("2026-10-07T01:57:28Z", None));
    }

    #[test]
    fn offline_msrc_documents_are_found_by_name() {
        let dir = offline_with_msrc_documents();
        for junk in [
            "notes.json",
            "2026-Foo.json",
            "Ubuntu.zip",
            "2026-Sep.json.bak",
        ] {
            std::fs::write(dir.join(junk), "{}").unwrap();
        }
        std::fs::create_dir(dir.join("2026-Sep.json")).unwrap();
        let ids: Vec<String> = offline_msrc_documents(&dir)
            .unwrap()
            .into_iter()
            .map(|d| d.id)
            .collect();
        assert_eq!(ids, vec!["2026-Aug", "2025-Jan", "2024-Oct"]);
        assert!(offline_msrc_documents(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_scan_reports_what_the_build_lacks() {
        let data = temp_dir("data");
        let offline = offline_with_msrc_documents();
        let service = VulnDbService::new(data.join("vulndb"), Some(offline.clone()));

        let empty = service.scan_windows("local", Ok(server_2025(33158)));
        assert_eq!(empty["status"], "VULNDB_EMPTY");

        let repo = service.repo().unwrap();
        let step = service.update_msrc(&repo, 12);
        assert!(step.ok, "{}", step.message);
        assert!(!step.unchanged);
        assert!(step.message.contains("новых 3"), "{}", step.message);
        let again = service.update_msrc(&repo, 12);
        assert!(again.ok && again.unchanged, "{}", again.message);
        assert!(
            again.message.contains("без изменений 3"),
            "{}",
            again.message
        );

        // July 2026 update on Server 2025: the August fixes are missing.
        let v = service.scan_windows("local", Ok(server_2025(33158)));
        assert_eq!(v["status"], "VULNERABILITIES_FOUND", "{v}");
        assert_eq!(v["platform"], "windows");
        assert_eq!(v["os"], "Microsoft Windows Server 2025 Datacenter 24H2");
        assert_eq!(v["summary"]["total"], 4);
        assert_eq!(v["summary"]["patched"], 2);
        assert_eq!(v["summary"]["exploited"], 1);
        assert_eq!(v["summary"]["unverified"], 0);
        assert_eq!(v["findings"][0]["id"], "CVE-2026-68820");
        assert_eq!(v["findings"][0]["exploited"], true);
        assert_eq!(v["findings"][0]["fixed_version"], "10.0.26100.33296");
        assert_eq!(v["findings"][0]["status"], "fix_available");
        assert_eq!(v["calculated_risk"], 7.9);
        assert_eq!(v["windows"]["product"], "Windows Server 2025");
        assert_eq!(v["windows"]["build"], "10.0.26100.33158");
        assert_eq!(
            v["windows"]["documents"],
            json!(["2026-Aug", "2025-Jan", "2024-Oct"])
        );
        assert_eq!(v["windows"]["older_than_window"], false);
        assert_eq!(v["windows"]["installed_updates"], json!(["KB5054979"]));
        assert_eq!(v["database"]["feeds"][0]["kind"], "msrc");
        let detail = v["status_detail"].as_str().unwrap();
        assert!(detail.contains("4 из 6"), "{detail}");
        assert!(detail.contains("2024-Oct – 2026-Aug"), "{detail}");

        // The September update closes everything loaded.
        let current = service.scan_windows("local", Ok(server_2025(33438)));
        assert_eq!(current["status"], "NO_KNOWN_MATCHED_VULNERABILITIES");
        assert_eq!(current["summary"]["patched"], 6);
        assert_eq!(current["findings"], json!([]));

        // A 2024 Windows 11 build predates even the oldest loaded month.
        let mut old = server_2025(2000);
        old.caption = "Microsoft Windows 11 Pro".into();
        old.installation_type = "Client".into();
        old.product_type = Some(1);
        let old = service.scan_windows("local", Ok(old));
        assert_eq!(
            old["windows"]["product"],
            "Windows 11 Version 24H2 for x64-based Systems"
        );
        assert_eq!(old["windows"]["older_than_window"], true);
        assert!(old["status_detail"]
            .as_str()
            .unwrap()
            .contains("старше самого раннего загруженного бюллетеня (2024-Oct)"));

        // Windows Server 2012 R2 has no entries in these documents.
        let mut r2 = server_2025(22000);
        r2.caption = "Microsoft Windows Server 2012 R2 Standard".into();
        r2.version = "6.3.9600".into();
        r2.build = 9600;
        let r2 = service.scan_windows("local", Ok(r2));
        assert_eq!(r2["status"], "PRODUCT_NOT_IN_DATABASE", "{r2}");

        let failed = service.scan_windows("local", Err("WMI недоступен".into()));
        assert_eq!(failed["status"], "UNSUPPORTED_PLATFORM");
        assert!(failed["status_detail"]
            .as_str()
            .unwrap()
            .contains("WMI недоступен"));

        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&offline);
    }

    #[test]
    fn windows_os_info_becomes_host_facts() {
        let os = platform_windows::system::WindowsOsInfo {
            caption: "Microsoft Windows Server 2025 Datacenter ".into(),
            version: "10.0.26100".into(),
            build: Some(26100),
            ubr: Some(33438),
            display_version: "24H2".into(),
            installation_type: "Server Core".into(),
            product_type: Some(3),
            os_architecture: "64-bit".into(),
            architecture: "x86_64".into(),
            kbs: vec!["KB5122871".into()],
            ip_addresses: Vec::new(),
        };
        let facts = windows_facts_from(os.clone()).unwrap();
        assert_eq!(facts.caption, "Microsoft Windows Server 2025 Datacenter");
        assert_eq!(facts.full_build(), "10.0.26100.33438");
        assert_eq!(facts.installed_kbs, vec!["KB5122871"]);
        assert_eq!(
            msrc::msrc_product_name(&facts).unwrap(),
            "Windows Server 2025 (Server Core installation)"
        );
        let no_build = platform_windows::system::WindowsOsInfo { build: None, ..os };
        assert!(windows_facts_from(no_build).is_err());
    }
}
