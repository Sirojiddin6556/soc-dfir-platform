use thiserror::Error;

#[derive(Error, Debug)]
pub enum WindowsPlatformError {
    #[error("API call failed: {0}")]
    ApiFailed(String),
}

pub struct WindowsPlatformHooks;

impl WindowsPlatformHooks {
    pub fn new() -> Self {
        Self
    }

    /// Safe wrapper around OS process query
    pub fn get_current_process_id(&self) -> u32 {
        std::process::id()
    }
}

impl Default for WindowsPlatformHooks {
    fn default() -> Self {
        Self::new()
    }
}
