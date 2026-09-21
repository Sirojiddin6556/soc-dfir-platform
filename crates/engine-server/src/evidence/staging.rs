#![forbid(unsafe_code)]

use core_domain::id::EntityId;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

#[derive(Error, Debug)]
pub enum StagingError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Offset mismatch: expected {expected}, got {actual}")]
    OffsetMismatch { expected: u64, actual: u64 },

    #[error("File exceeds maximum declared size: {current} > {max}")]
    SizeExceeded { current: u64, max: u64 },

    #[error("Staging file not found: {0}")]
    NotFound(String),
}

#[derive(Clone)]
pub struct StagingManager {
    staging_dir: PathBuf,
}

impl StagingManager {
    pub fn new<P: AsRef<Path>>(staging_dir: P) -> Self {
        Self {
            staging_dir: staging_dir.as_ref().to_path_buf(),
        }
    }

    pub fn staging_path(&self, session_id: EntityId) -> PathBuf {
        self.staging_dir.join(format!("{}.part", session_id))
    }

    pub async fn ensure_dir(&self) -> Result<(), std::io::Error> {
        if !self.staging_dir.exists() {
            fs::create_dir_all(&self.staging_dir).await?;
        }
        Ok(())
    }

    /// Appends a raw binary chunk at the strictly verified sequential offset.
    /// Memory consumption: strictly limited to the size of the incoming chunk buffer.
    pub async fn append_chunk(
        &self,
        session_id: EntityId,
        expected_offset: u64,
        max_size: u64,
        chunk_data: &[u8],
    ) -> Result<u64, StagingError> {
        self.ensure_dir().await?;
        let path = self.staging_path(session_id);

        let current_len = if path.exists() {
            fs::metadata(&path).await?.len()
        } else {
            0
        };

        if current_len != expected_offset {
            return Err(StagingError::OffsetMismatch {
                expected: current_len,
                actual: expected_offset,
            });
        }

        let new_len = current_len + chunk_data.len() as u64;
        if new_len > max_size {
            return Err(StagingError::SizeExceeded {
                current: new_len,
                max: max_size,
            });
        }

        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .await?;

        file.seek(SeekFrom::Start(current_len)).await?;
        file.write_all(chunk_data).await?;
        file.flush().await?;

        Ok(new_len)
    }

    /// Reads the staging file from disk in streaming 64 KB blocks and computes
    /// both SHA-256 and BLAKE3 hashes concurrently. Memory usage remains O(64 KB).
    pub async fn scan_and_rehash(
        &self,
        session_id: EntityId,
    ) -> Result<(u64, String, String), StagingError> {
        let path = self.staging_path(session_id);
        if !path.exists() {
            return Err(StagingError::NotFound(path.display().to_string()));
        }

        let mut file = fs::File::open(&path).await?;
        let mut s256 = Sha256::new();
        let mut b3 = blake3::Hasher::new();

        let mut buffer = [0u8; 65536];
        let mut total_read = 0u64;

        loop {
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            s256.update(&buffer[..n]);
            b3.update(&buffer[..n]);
            total_read += n as u64;
        }

        let sha256_hex = hex::encode(s256.finalize());
        let blake3_hex = b3.finalize().to_hex().to_string();

        Ok((total_read, sha256_hex, blake3_hex))
    }

    /// Reads the first N bytes (magic header) of the staging file without reading the whole file.
    pub async fn read_header(
        &self,
        session_id: EntityId,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StagingError> {
        let path = self.staging_path(session_id);
        if !path.exists() {
            return Err(StagingError::NotFound(path.display().to_string()));
        }

        let mut file = fs::File::open(&path).await?;
        let mut buf = vec![0u8; max_bytes];
        let n = file.read(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    pub async fn delete_staging(&self, session_id: EntityId) {
        let path = self.staging_path(session_id);
        if path.exists() {
            let _ = fs::remove_file(&path).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_staging_append_and_rehash() {
        let temp_dir = std::env::temp_dir().join(format!("staging_test_{}", uuid::Uuid::new_v4()));
        let mgr = StagingManager::new(&temp_dir);
        let session_id = EntityId::new_v7();

        let chunk1 = b"Part 1 of forensic payload | ";
        let chunk2 = b"Part 2 of forensic payload";

        // Chunk 1 at offset 0
        let len1 = mgr
            .append_chunk(session_id, 0, 1048576, chunk1)
            .await
            .unwrap();
        assert_eq!(len1, chunk1.len() as u64);

        // Chunk 2 at offset len1
        let len2 = mgr
            .append_chunk(session_id, len1, 1048576, chunk2)
            .await
            .unwrap();
        assert_eq!(len2, (chunk1.len() + chunk2.len()) as u64);

        // Wrong offset rejected
        let err = mgr
            .append_chunk(session_id, 0, 1048576, b"wrong")
            .await
            .unwrap_err();
        assert!(matches!(err, StagingError::OffsetMismatch { .. }));

        // Streaming rehash matches combined bytes
        let mut combined = Vec::new();
        combined.extend_from_slice(chunk1);
        combined.extend_from_slice(chunk2);

        let expected_b3 = blake3::hash(&combined).to_hex().to_string();
        let expected_s256 = hex::encode(sha2::Sha256::digest(&combined));

        let (re_len, re_s256, re_b3) = mgr.scan_and_rehash(session_id).await.unwrap();
        assert_eq!(re_len, combined.len() as u64);
        assert_eq!(re_b3, expected_b3);
        assert_eq!(re_s256, expected_s256);

        mgr.delete_staging(session_id).await;
        assert!(!mgr.staging_path(session_id).exists());

        let _ = fs::remove_dir_all(temp_dir).await;
    }
}
