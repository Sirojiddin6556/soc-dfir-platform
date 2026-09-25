#![forbid(unsafe_code)]

pub mod safe_archive;

use async_trait::async_trait;
use core_domain::ctf::entities::{ArtifactId, Blake3Hash, IngestMetadata};
use core_domain::ctf::traits::CasStorageService;
use core_domain::error::DomainError;
pub use safe_archive::SafeArchiveExtractor;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

pub const MAX_SLICE_LENGTH: usize = 65_536; // 64 KB limit

#[derive(Error, Debug)]
pub enum CasError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Integrity check failed for {0}: expected {1}, got {2}")]
    IntegrityViolation(String, String, String),
}

impl From<CasError> for DomainError {
    fn from(err: CasError) -> Self {
        match err {
            CasError::IntegrityViolation(id, exp, got) => DomainError::SecurityViolation(format!(
                "Hash mismatch for {}: expected {}, got {}",
                id, exp, got
            )),
            CasError::Io(e) => DomainError::Storage(format!("CAS IO error: {}", e)),
        }
    }
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

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Derives structured two-level path: `root/ab/cd/abcdef...`
    pub fn get_path_for_blake3(&self, blake3_hex: &str) -> PathBuf {
        let prefix1 = if blake3_hex.len() >= 2 {
            &blake3_hex[0..2]
        } else {
            "00"
        };
        let prefix2 = if blake3_hex.len() >= 4 {
            &blake3_hex[2..4]
        } else {
            "00"
        };
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
            let temp_path = target_path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
            let mut file = fs::File::create(&temp_path).await?;
            file.write_all(data).await?;
            file.flush().await?;
            drop(file);

            // WORM read-only mode
            let mut perms = fs::metadata(&temp_path).await?.permissions();
            perms.set_readonly(true);
            let _ = fs::set_permissions(&temp_path, perms).await;

            fs::rename(&temp_path, &target_path).await?;
        }

        Ok(StoredArtifactHashes {
            blake3: b3_hash,
            sha256: s256_hash,
            size_bytes: data.len() as u64,
        })
    }

    pub fn has_object(&self, blake3_hex: &str) -> bool {
        self.get_path_for_blake3(blake3_hex).exists()
    }

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

        let temp_target = target_path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        if let Err(rename_err) = fs::rename(staging_path, &temp_target).await {
            tracing::debug!("Cross-device rename fallback: {}", rename_err);
            fs::copy(staging_path, &temp_target).await?;
            let _ = fs::remove_file(staging_path).await;
        }

        if let Ok(file) = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&temp_target)
            .await
        {
            let _ = file.sync_all().await;
        }

        let mut perms = fs::metadata(&temp_target).await?.permissions();
        perms.set_readonly(true);
        let _ = fs::set_permissions(&temp_target, perms).await;

        fs::rename(&temp_target, &target_path).await?;

        Ok(StoredArtifactHashes {
            blake3: expected_blake3.to_string(),
            sha256: expected_sha256.to_string(),
            size_bytes: expected_size,
        })
    }
}

#[async_trait]
impl CasStorageService for ContentAddressedStorage {
    async fn store_stream<R: AsyncRead + Unpin + Send>(
        &self,
        mut reader: R,
        _meta: IngestMetadata,
    ) -> Result<ArtifactId, DomainError> {
        let tmp_dir = self.root_dir.join("tmp");
        fs::create_dir_all(&tmp_dir)
            .await
            .map_err(|e| DomainError::storage(e.to_string()))?;
        let temp_file_path = tmp_dir.join(format!("stream_{}.part", uuid::Uuid::new_v4()));

        let mut file = fs::File::create(&temp_file_path)
            .await
            .map_err(|e| DomainError::storage(e.to_string()))?;

        let mut b3_hasher = blake3::Hasher::new();
        let mut sha256_hasher = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut total_bytes: u64 = 0;

        loop {
            let n = reader
                .read(&mut buffer)
                .await
                .map_err(|e| DomainError::storage(e.to_string()))?;
            if n == 0 {
                break;
            }
            let chunk = &buffer[..n];
            b3_hasher.update(chunk);
            sha256_hasher.update(chunk);
            file.write_all(chunk)
                .await
                .map_err(|e| DomainError::storage(e.to_string()))?;
            total_bytes += n as u64;
        }
        file.flush()
            .await
            .map_err(|e| DomainError::storage(e.to_string()))?;
        drop(file);

        let b3_hash = b3_hasher.finalize().to_hex().to_string();
        let sha256_hash = hex::encode(sha256_hasher.finalize());

        self.commit_staging_file(&temp_file_path, &b3_hash, &sha256_hash, total_bytes)
            .await
            .map_err(|e| DomainError::from(e))?;

        Ok(b3_hash)
    }

    async fn read_slice(
        &self,
        hash: &Blake3Hash,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, DomainError> {
        if length > MAX_SLICE_LENGTH {
            return Err(DomainError::Validation(format!(
                "Requested slice length {} exceeds maximum allowed limit of {} bytes",
                length, MAX_SLICE_LENGTH
            )));
        }

        let file_path = self.get_path_for_blake3(hash);
        if !file_path.exists() {
            return Err(DomainError::not_found("Artifact", hash));
        }

        let mut file = fs::File::open(&file_path)
            .await
            .map_err(|e| DomainError::storage(e.to_string()))?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| DomainError::storage(e.to_string()))?;

        let mut buf = vec![0u8; length];
        let bytes_read = file
            .read(&mut buf)
            .await
            .map_err(|e| DomainError::storage(e.to_string()))?;
        buf.truncate(bytes_read);

        Ok(buf)
    }

    async fn verify_integrity(&self, hash: &Blake3Hash) -> Result<bool, DomainError> {
        let file_path = self.get_path_for_blake3(hash);
        if !file_path.exists() {
            return Err(DomainError::not_found("Artifact", hash));
        }

        let mut file = fs::File::open(&file_path)
            .await
            .map_err(|e| DomainError::storage(e.to_string()))?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 65536];

        loop {
            let n = file
                .read(&mut buffer)
                .await
                .map_err(|e| DomainError::storage(e.to_string()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let computed = hasher.finalize().to_hex().to_string();
        Ok(computed == *hash)
    }

    async fn unpack_archive_safe(
        &self,
        artifact_id: &ArtifactId,
        target_dir: &Path,
    ) -> Result<Vec<ArtifactId>, DomainError> {
        let archive_path = self.get_path_for_blake3(artifact_id);
        if !archive_path.exists() {
            return Err(DomainError::not_found("Artifact", artifact_id));
        }

        let extracted_files = SafeArchiveExtractor::extract_zip(&archive_path, target_dir)?;
        let mut artifact_ids = Vec::with_capacity(extracted_files.len());

        for (_path, data) in extracted_files {
            let hashes = self.store_bytes(&data).await.map_err(DomainError::from)?;
            artifact_ids.push(hashes.blake3);
        }

        Ok(artifact_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cas_streaming_and_slice_reading() {
        let temp_dir =
            std::env::temp_dir().join(format!("cas_stream_test_{}", uuid::Uuid::new_v4()));
        let cas = ContentAddressedStorage::new(&temp_dir);

        let payload = vec![0x42u8; 128 * 1024]; // 128 KB
        let cursor = std::io::Cursor::new(payload.clone());

        let meta = IngestMetadata {
            original_name: "test_large.bin".into(),
            mime_type: Some("application/octet-stream".into()),
            case_id: None,
            challenge_id: None,
            role: None,
            alias: None,
        };

        let artifact_id = cas.store_stream(cursor, meta).await.unwrap();
        assert!(!artifact_id.is_empty());

        // Verify integrity
        let ok = cas.verify_integrity(&artifact_id).await.unwrap();
        assert!(ok);

        // Read 64 KB slice at offset 0
        let slice = cas.read_slice(&artifact_id, 0, 65536).await.unwrap();
        assert_eq!(slice.len(), 65536);
        assert_eq!(slice[0], 0x42);

        // Reject > 64 KB request
        let err = cas.read_slice(&artifact_id, 0, 70000).await.unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)));

        let _ = fs::remove_dir_all(temp_dir).await;
    }

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
