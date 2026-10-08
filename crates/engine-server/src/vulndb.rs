#![forbid(unsafe_code)]

//! Local vulnerability database for host package scanning.
//!
//! `vulndb.update` downloads the public feeds -- OSV distribution advisories
//! (Debian, Ubuntu, AlmaLinux, Rocky Linux), the CISA KEV catalog and FIRST
//! EPSS scores -- and imports them into `<data dir>/vulndb/vuln.db`.
//! `scan.cve` matches this machine's installed packages against it.
//!
//! With `SOC_VULNDB_OFFLINE_DIR` set the engine never goes online and reads
//! the same files from that directory instead (air-gapped installs):
//!   Ubuntu_24.04_LTS.zip (or Ubuntu.zip), known_exploited_vulnerabilities.json,
//!   epss_scores-current.csv.gz

use chrono::Utc;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use vulnerability_engine::feeds::{self, FeedSource};
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
/// distribution, a numeric release and an optional ":LTS".
fn valid_ecosystem(ecosystem: &str) -> bool {
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

    pub fn status(&self) -> Value {
        let inventory = platform_linux::collect_package_inventory();
        let host_ecosystem = inventory.ecosystem.clone();
        let supported = host_ecosystem
            .as_deref()
            .map(package_scan::is_supported_ecosystem)
            .unwrap_or(false);
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
            "host": {
                "os": inventory.os_name,
                "ecosystem": host_ecosystem,
                "supported": supported,
                "packages": inventory.packages.len(),
            },
            "update": job,
        })
    }

    /// Starts a background update of the OSV data for `ecosystems` (the local
    /// distribution when empty) plus KEV and EPSS.
    pub fn start_update(self: &Arc<Self>, ecosystems: Vec<String>) -> Result<Value, String> {
        let mut ecosystems: Vec<String> = ecosystems
            .into_iter()
            .map(|e| e.trim().to_string())
            .collect();
        if let Some(bad) = ecosystems.iter().find(|e| !valid_ecosystem(e)) {
            return Err(format!(
                "Экосистема '{bad}' не поддерживается: доступны Debian:N, Ubuntu:NN.NN[:LTS], AlmaLinux:N, Rocky Linux:N"
            ));
        }
        if ecosystems.is_empty() {
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
            .spawn(move || service.run_update(ecosystems))
            .map_err(|e| {
                self.job.lock().unwrap_or_else(|p| p.into_inner()).running = false;
                format!("Не удалось запустить обновление: {e}")
            })?;

        Ok(json!({
            "started": true,
            "ecosystems": planned,
            "offline": self.offline_dir.is_some(),
        }))
    }

    fn run_update(&self, ecosystems: Vec<String>) {
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
            match self.download(url, &dest, etag.as_deref(), label) {
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
    ) -> Result<Option<FeedSource>, FetchError> {
        self.set_current(format!("{label}: соединение с {url}"));
        let mut request = agent().get(url);
        if let Some(tag) = etag {
            request = request.header("If-None-Match", tag);
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

        let inventory = platform_linux::collect_package_inventory();
        let Some(ecosystem) = inventory
            .ecosystem
            .clone()
            .filter(|e| package_scan::is_supported_ecosystem(e))
        else {
            let detail = if cfg!(windows) {
                "Сопоставление CVE для Windows (обновления KB и сборка ОС) пока не реализовано: \
                 поиск CVE работает для пакетов Debian, Ubuntu, AlmaLinux и Rocky Linux"
                    .to_string()
            } else {
                format!(
                    "Дистрибутив {} не поддерживается: базы OSV подключены для Debian, Ubuntu, AlmaLinux и Rocky Linux",
                    inventory.os_name
                )
            };
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
        assert!(!valid_ecosystem("PyPI"));
        assert!(!valid_ecosystem("Debian:../../etc"));
        assert!(!valid_ecosystem("Debian:.."));
        assert!(!valid_ecosystem("Debian"));
        assert!(!valid_ecosystem("Ubuntu:24.04:LTS:x"));
        assert!(!valid_ecosystem(""));
    }
}
