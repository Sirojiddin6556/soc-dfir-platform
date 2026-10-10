#![forbid(unsafe_code)]

use correlation_engine::DeterministicCorrelationEngine;
use storage_sqlite::SqliteStorage;

use std::path::PathBuf;
use std::sync::Arc;

pub mod auth;
pub mod code_scan;
pub mod dispatch;
pub mod host_inspector;
pub mod http;
pub mod vulndb;
pub mod web_scan;

pub use http::{bind_server, handle_connection, run_embedded_server, run_server_loop};

/// Real hostname of the machine this engine is running on, resolved once and
/// cached. Used as the default `host_id` wherever a request omits one --
/// never a placeholder like a hardcoded machine name.
pub fn default_host_id() -> &'static str {
    static HOSTNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOSTNAME.get_or_init(platform_windows::local_hostname)
}

pub struct EngineApp {
    pub storage: SqliteStorage,
    pub correlation: DeterministicCorrelationEngine,
    pub login_throttle: auth::LoginThrottle,
    pub vulndb: Arc<vulndb::VulnDbService>,
    pub code_scan: Arc<code_scan::CodeScanService>,
    pub web_scan: Arc<web_scan::WebScanService>,
}

impl EngineApp {
    /// Opens (or creates) a persistent, on-disk case database under `db_path` so
    /// cases, facts and evidence survive process restarts. This is the
    /// constructor production entry points (desktop-app, engine-server bin) must use.
    pub fn new(
        cas_root: PathBuf,
        db_path: PathBuf,
    ) -> Result<Self, storage_sqlite::SqliteStorageError> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let storage = SqliteStorage::open(db_path)?;
        Ok(Self::from_storage(storage, cas_root))
    }

    /// Ephemeral, in-memory database. Use only for tests -- all data is lost
    /// when the process exits.
    pub fn new_in_memory(cas_root: PathBuf) -> Self {
        let storage = SqliteStorage::open_in_memory().expect("Failed to init in-memory DB");
        Self::from_storage(storage, cas_root)
    }

    fn from_storage(storage: SqliteStorage, cas_root: PathBuf) -> Self {
        let data_dir = cas_root.parent().unwrap_or(&cas_root).to_path_buf();
        // SOC_VULNDB_OFFLINE_DIR: import feeds from this directory, never download.
        let offline_dir = std::env::var_os("SOC_VULNDB_OFFLINE_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        let vulndb = Arc::new(vulndb::VulnDbService::new(
            data_dir.join("vulndb"),
            offline_dir,
        ));

        Self {
            storage,
            correlation: DeterministicCorrelationEngine::new(),
            login_throttle: auth::LoginThrottle::new(),
            code_scan: Arc::new(code_scan::CodeScanService::new(vulndb.clone())),
            web_scan: Arc::new(web_scan::WebScanService::new()),
            vulndb,
        }
    }
}
