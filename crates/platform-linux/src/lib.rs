use thiserror::Error;

#[derive(Error, Debug)]
pub enum LinuxPlatformError {
    #[error("Syscall failed: {0}")]
    SyscallFailed(String),
}

pub struct LinuxPlatformHooks;

impl LinuxPlatformHooks {
    pub fn new() -> Self {
        Self
    }

    /// Safe wrapper around OS process query
    pub fn get_current_process_id(&self) -> u32 {
        std::process::id()
    }
}

impl Default for LinuxPlatformHooks {
    fn default() -> Self {
        Self::new()
    }
}
