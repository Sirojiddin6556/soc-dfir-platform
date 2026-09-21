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

    /// Checks if an object with the specified BLAKE3 hash already exists in CAS.
    pub fn has_object(&self, blake3_hex: &str) -> bool {
        self.get_path_for_blake3(blake3_hex).exists()
    }

    /// Atomically moves or copies a staging file into CAS under its verified BLAKE3 hash.
    /// If an identical object already exists in CAS, dedup is performed and the staging file is removed.
    pub async fn commit_staging_file(
        &self,
        staging_path: &Path,
        expected_blake3: &str,
        expected_sha256: &str,
        expected_size: u64,
    ) -> Result<StoredArtifactHashes, CasError> {
        let target_path = self.get_path_for_blake3(expected_blake3);

        if target_path.exists() {
            let meta = fs::metadata(&target_path).await?;
            if meta.len() == expected_size {
                // Object already exists with matching size: deduplicate!
                let _ = fs::remove_file(staging_path).await;
                return Ok(StoredArtifactHashes {
                    blake3: expected_blake3.to_string(),
                    sha256: expected_sha256.to_string(),
                    size_bytes: expected_size,
                });
            }
        }

        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Atomic move into CAS directory via temp file in same directory
        let temp_target = target_path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        if let Err(rename_err) = fs::rename(staging_path, &temp_target).await {
            // Cross-device rename fallback: copy then remove
            tracing::debug!("Cross-device rename fallback: {}", rename_err);
            fs::copy(staging_path, &temp_target).await?;
            let _ = fs::remove_file(staging_path).await;
        }

        // On Windows, sync_all requires write access on the handle
        if let Ok(file) = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&temp_target)
            .await
        {
            let _ = file.sync_all().await;
        }

        fs::rename(&temp_target, &target_path).await?;

        Ok(StoredArtifactHashes {
            blake3: expected_blake3.to_string(),
            sha256: expected_sha256.to_string(),
            size_bytes: expected_size,
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

    #[tokio::test]
    async fn test_commit_staging_file_and_dedup() {
        let temp_dir =
            std::env::temp_dir().join(format!("cas_commit_test_{}", uuid::Uuid::new_v4()));
        let staging_dir = temp_dir.join("staging");
        let cas_dir = temp_dir.join("cas");
        fs::create_dir_all(&staging_dir).await.unwrap();

        let cas = ContentAddressedStorage::new(&cas_dir);
        let payload = b"Forensic PCAP-NG test buffer for commit";
        let b3 = blake3::hash(payload).to_hex().to_string();
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, payload);
        let s256 = hex::encode(sha2::Digest::finalize(hasher));

        // Create staging file
        let staging_file = staging_dir.join("test_session.part");
        fs::write(&staging_file, payload).await.unwrap();

        // Commit staging file
        let hashes = cas
            .commit_staging_file(&staging_file, &b3, &s256, payload.len() as u64)
            .await
            .unwrap();
        assert_eq!(hashes.blake3, b3);
        assert_eq!(hashes.sha256, s256);
        assert!(cas.has_object(&b3));
        assert!(!staging_file.exists()); // Staging file was moved

        // Second upload of identical content: staging file created again
        fs::write(&staging_file, payload).await.unwrap();
        let hashes2 = cas
            .commit_staging_file(&staging_file, &b3, &s256, payload.len() as u64)
            .await
            .unwrap();
        assert_eq!(hashes2.blake3, b3);
        assert!(!staging_file.exists()); // Deduplicated: staging file was removed

        let _ = fs::remove_dir_all(temp_dir).await;
    }
}
