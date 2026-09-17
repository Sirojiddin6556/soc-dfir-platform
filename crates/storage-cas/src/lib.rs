#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Error, Debug)]
pub enum CasError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Integrity check failed for {0}: expected {1}, got {2}")]
    IntegrityViolation(String, String, String),
}

#[derive(Debug, Clone)]
pub struct ContentAddressedStorage {
    root_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifactHashes {
    pub blake3: String,
    pub sha256: String,
    pub size_bytes: u64,
}

impl ContentAddressedStorage {
    pub fn new<P: AsRef<Path>>(root_dir: P) -> Self {
        Self {
            root_dir: root_dir.as_ref().to_path_buf(),
        }
    }

    /// Derives structured two-level path: `root/ab/cd/abcdef...`
    pub fn get_path_for_blake3(&self, blake3_hex: &str) -> PathBuf {
        let prefix1 = &blake3_hex[0..2];
        let prefix2 = &blake3_hex[2..4];
        self.root_dir.join(prefix1).join(prefix2).join(blake3_hex)
    }

    /// Atomically stores data by computing BLAKE3 (locator) and SHA-256 (forensic)
    pub async fn store_bytes(&self, data: &[u8]) -> Result<StoredArtifactHashes, CasError> {
        let b3_hash = blake3::hash(data).to_hex().to_string();

        let mut hasher = Sha256::new();
        hasher.update(data);
        let s256_hash = hex::encode(hasher.finalize());

        let target_path = self.get_path_for_blake3(&b3_hash);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        if !target_path.exists() {
            let temp_path = target_path.with_extension("tmp");
            let mut file = fs::File::create(&temp_path).await?;
            file.write_all(data).await?;
            file.flush().await?;
            drop(file);
            fs::rename(&temp_path, &target_path).await?;
        }

        Ok(StoredArtifactHashes {
            blake3: b3_hash,
            sha256: s256_hash,
            size_bytes: data.len() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cas_dual_hash_storage() {
        let temp_dir = std::env::temp_dir().join(format!("cas_test_{}", uuid::Uuid::new_v4()));
        let cas = ContentAddressedStorage::new(&temp_dir);

        let payload = b"Forensic EVTX test buffer";
        let hashes = cas.store_bytes(payload).await.unwrap();

        assert_eq!(hashes.size_bytes, payload.len() as u64);
        assert!(!hashes.blake3.is_empty());
        assert!(!hashes.sha256.is_empty());

        let file_path = cas.get_path_for_blake3(&hashes.blake3);
        assert!(file_path.exists());

        let _ = fs::remove_dir_all(temp_dir).await;
    }
}
