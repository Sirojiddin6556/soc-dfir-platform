#![forbid(unsafe_code)]

use correlation_engine::DeterministicCorrelationEngine;
use diagram_engine::DiagramEngine;
use graph_engine::DeterministicGraphEngine;
use privilege_broker::PrivilegeBroker;
use storage_cas::ContentAddressedStorage;
use storage_sqlite::SqliteStorage;
use workflow_dag::{ResourceLimiter, WorkflowScheduler};

use std::path::PathBuf;

pub mod analysis;
pub mod auth;
pub mod collaboration;
pub mod ctf_dispatch;
pub mod dispatch;
pub mod evidence;
pub mod host_inspector;
pub mod http;
pub mod investigation;
pub mod membership;
pub mod scanner;
pub mod scenario_eval;
pub mod scope;
pub mod target_parser;

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
    pub cas: ContentAddressedStorage,
    pub session_mgr: evidence::IngestSessionManager,
    pub scheduler: WorkflowScheduler,
    pub broker: PrivilegeBroker,
    pub correlation: DeterministicCorrelationEngine,
    pub graph: DeterministicGraphEngine,
    pub diagram: DiagramEngine,
    pub verifier: scenario_verifier::ScenarioVerifier,
    pub scoring: scoring_engine::ScoringEngine,
    pub job_engine: core_domain::ctf::LocalJobEngine,
    pub login_throttle: auth::LoginThrottle,
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
        let staging_dir = cas_root.parent().unwrap_or(&cas_root).join("staging");
        let staging = evidence::StagingManager::new(staging_dir);
        let session_mgr = evidence::IngestSessionManager::new(staging);
        let cas = ContentAddressedStorage::new(cas_root);
        let limiter = ResourceLimiter::new(8, 4, 4, 2, 2);
        let scheduler = WorkflowScheduler::new(limiter);
        let broker = PrivilegeBroker::new(vec![
            core_domain::broker::BrokerCapability::ReadProcesses,
            core_domain::broker::BrokerCapability::ReadFirewall,
            core_domain::broker::BrokerCapability::NetworkScan,
            core_domain::broker::BrokerCapability::CapturePcap,
            core_domain::broker::BrokerCapability::ReadRegistry,
        ]);

        Self {
            storage,
            cas,
            session_mgr,
            scheduler,
            broker,
            correlation: DeterministicCorrelationEngine::new(),
            graph: DeterministicGraphEngine::new(),
            diagram: DiagramEngine::new(),
            verifier: scenario_verifier::ScenarioVerifier::new(),
            scoring: scoring_engine::ScoringEngine::new(),
            job_engine: core_domain::ctf::LocalJobEngine::new(),
            login_throttle: auth::LoginThrottle::new(),
        }
    }
}
