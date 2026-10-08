use core_domain::error::DomainError;
use flate2::read::DeflateDecoder;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const MAX_FILES_COUNT: usize = 10_000;
pub const MAX_SINGLE_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GB
pub const MAX_TOTAL_UNCOMPRESSED_SIZE: u64 = 5 * 1024 * 1024 * 1024; // 5 GB
pub const MAX_COMPRESSION_RATIO: f64 = 100.0;

#[derive(Debug, Clone)]
pub struct SafeZipEntry {
    pub name: String,
    pub compression_method: u16,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_header_offset: u64,
    pub is_dir: bool,
}

pub struct SafeArchiveExtractor;

impl SafeArchiveExtractor {
    pub fn sanitize_rel_path(raw_name: &str) -> Result<PathBuf, DomainError> {
        let clean = raw_name
            .trim_start_matches('/')
            .trim_start_matches('\\')
            .trim();

        // Reject Windows drive letters like C:
        if clean.len() >= 2 && clean.chars().nth(1) == Some(':') {
            return Err(DomainError::SecurityViolation(format!(
                "Absolute drive letter path rejected in archive: {}",
                raw_name
            )));
        }

        let mut path = PathBuf::new();
        for component in clean.split(['/', '\\']) {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." {
                return Err(DomainError::SecurityViolation(format!(
                    "Path traversal attempt (..) detected in archive entry: {}",
                    raw_name
                )));
            }
            path.push(component);
        }

        if path.as_os_str().is_empty() {
            return Err(DomainError::Validation(
                "Empty relative path in archive entry".into(),
            ));
        }

        Ok(path)
    }

    pub fn extract_zip<P: AsRef<Path>>(
        zip_path: P,
        target_dir: &Path,
    ) -> Result<Vec<(PathBuf, Vec<u8>)>, DomainError> {
        let mut file = File::open(zip_path.as_ref())
            .map_err(|e| DomainError::storage(format!("Cannot open archive file: {}", e)))?;

        let file_len = file
            .seek(SeekFrom::End(0))
            .map_err(|e| DomainError::storage(format!("Seek failed: {}", e)))?;

        // Locate End of Central Directory Record (EOCD)
        let eocd_sig = [0x50, 0x4b, 0x05, 0x06];
        let max_search = file_len.min(65536 + 22);
        let search_start = file_len - max_search;

        file.seek(SeekFrom::Start(search_start))
            .map_err(|e| DomainError::storage(format!("Seek failed: {}", e)))?;
        let mut search_buf = vec![0u8; max_search as usize];
        file.read_exact(&mut search_buf)
            .map_err(|e| DomainError::storage(format!("Read EOCD search buffer failed: {}", e)))?;

        let mut eocd_offset = None;
        for i in (0..search_buf.len().saturating_sub(21)).rev() {
            if search_buf[i..i + 4] == eocd_sig {
                eocd_offset = Some(search_start + i as u64);
                break;
            }
        }

        let eocd_pos = eocd_offset.ok_or_else(|| {
            DomainError::Validation("Archive is not a valid ZIP file (EOCD not found)".into())
        })?;

        file.seek(SeekFrom::Start(eocd_pos + 8))
            .map_err(|e| DomainError::storage(format!("Seek to EOCD counts failed: {}", e)))?;
        let mut counts_buf = [0u8; 12];
        file.read_exact(&mut counts_buf)
            .map_err(|e| DomainError::storage(format!("Read EOCD header failed: {}", e)))?;

        let total_entries = u16::from_le_bytes([counts_buf[2], counts_buf[3]]) as usize;
        let cd_offset =
            u32::from_le_bytes([counts_buf[8], counts_buf[9], counts_buf[10], counts_buf[11]])
                as u64;

        if total_entries > MAX_FILES_COUNT {
            return Err(DomainError::ResourceLimit(format!(
                "Archive entries count ({}) exceeds maximum allowed quota ({})",
                total_entries, MAX_FILES_COUNT
            )));
        }

        // Parse Central Directory
        file.seek(SeekFrom::Start(cd_offset))
            .map_err(|e| DomainError::storage(format!("Seek to CD failed: {}", e)))?;

        let mut entries = Vec::with_capacity(total_entries);
        let mut total_uncompressed: u64 = 0;

        for _ in 0..total_entries {
            let mut cd_header = [0u8; 46];
            file.read_exact(&mut cd_header)
                .map_err(|e| DomainError::storage(format!("Read CD header failed: {}", e)))?;

            if cd_header[0..4] != [0x50, 0x4b, 0x01, 0x02] {
                return Err(DomainError::Validation(
                    "Corrupt central directory record".into(),
                ));
            }

            let comp_method = u16::from_le_bytes([cd_header[10], cd_header[11]]);
            let comp_size =
                u32::from_le_bytes([cd_header[20], cd_header[21], cd_header[22], cd_header[23]])
                    as u64;
            let uncomp_size =
                u32::from_le_bytes([cd_header[24], cd_header[25], cd_header[26], cd_header[27]])
                    as u64;
            let name_len = u16::from_le_bytes([cd_header[28], cd_header[29]]) as usize;
            let extra_len = u16::from_le_bytes([cd_header[30], cd_header[31]]) as usize;
            let comment_len = u16::from_le_bytes([cd_header[32], cd_header[33]]) as usize;
            let local_header_offset =
                u32::from_le_bytes([cd_header[42], cd_header[43], cd_header[44], cd_header[45]])
                    as u64;

            let mut name_buf = vec![0u8; name_len];
            file.read_exact(&mut name_buf)
                .map_err(|e| DomainError::storage(format!("Read filename failed: {}", e)))?;
            let name = String::from_utf8_lossy(&name_buf).to_string();

            // Skip extra and comment fields
            if extra_len + comment_len > 0 {
                file.seek(SeekFrom::Current((extra_len + comment_len) as i64))
                    .map_err(|e| DomainError::storage(format!("Seek skip failed: {}", e)))?;
            }

            // Zip-Bomb quota check
            if uncomp_size > MAX_SINGLE_FILE_SIZE {
                return Err(DomainError::ResourceLimit(format!(
                    "File '{}' uncompressed size ({}) exceeds single file quota ({})",
                    name, uncomp_size, MAX_SINGLE_FILE_SIZE
                )));
            }

            total_uncompressed += uncomp_size;
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_SIZE {
                return Err(DomainError::ResourceLimit(format!(
                    "Total uncompressed size ({}) exceeds archive quota ({})",
                    total_uncompressed, MAX_TOTAL_UNCOMPRESSED_SIZE
                )));
            }

            // Ratio check (for files > 64KB)
            if uncomp_size > 65536 {
                let ratio = uncomp_size as f64 / comp_size.max(1) as f64;
                if ratio > MAX_COMPRESSION_RATIO {
                    return Err(DomainError::SecurityViolation(format!(
                        "Zip-bomb detected in '{}': compression ratio {:.1}:1 exceeds limit {}:1",
                        name, ratio, MAX_COMPRESSION_RATIO
                    )));
                }
            }

            let is_dir = name.ends_with('/') || name.ends_with('\\');
            entries.push(SafeZipEntry {
                name,
                compression_method: comp_method,
                compressed_size: comp_size,
                uncompressed_size: uncomp_size,
                local_header_offset,
                is_dir,
            });
        }

        // Canonical base check
        let base_canon = target_dir
            .canonicalize()
            .unwrap_or_else(|_| target_dir.to_path_buf());

        let mut extracted_files = Vec::new();

        for entry in entries {
            if entry.is_dir {
                continue;
            }

            let safe_rel = Self::sanitize_rel_path(&entry.name)?;
            let dest_path = target_dir.join(&safe_rel);

            // Path Traversal verification: canonical check
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    DomainError::storage(format!("Failed to create extract directory: {}", e))
                })?;
                let parent_canon = parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf());
                if !parent_canon.starts_with(&base_canon) {
                    return Err(DomainError::SecurityViolation(format!(
                        "Zip-Slip directory traversal prevented: path {:?} escapes base {:?}",
                        parent_canon, base_canon
                    )));
                }
            }

            // Read entry data
            file.seek(SeekFrom::Start(entry.local_header_offset))
                .map_err(|e| DomainError::storage(format!("Seek to local header failed: {}", e)))?;
            let mut local_hdr = [0u8; 30];
            file.read_exact(&mut local_hdr)
                .map_err(|e| DomainError::storage(format!("Read local header failed: {}", e)))?;

            if local_hdr[0..4] != [0x50, 0x4b, 0x03, 0x04] {
                return Err(DomainError::Validation(
                    "Corrupt local file header in ZIP".into(),
                ));
            }

            let loc_name_len = u16::from_le_bytes([local_hdr[26], local_hdr[27]]) as usize;
            let loc_extra_len = u16::from_le_bytes([local_hdr[28], local_hdr[29]]) as usize;
            file.seek(SeekFrom::Current((loc_name_len + loc_extra_len) as i64))
                .map_err(|e| DomainError::storage(format!("Skip local extra failed: {}", e)))?;

            let mut raw_data = vec![0u8; entry.compressed_size as usize];
            file.read_exact(&mut raw_data)
                .map_err(|e| DomainError::storage(format!("Read entry data failed: {}", e)))?;

            let decompressed = match entry.compression_method {
                0 => raw_data, // Stored
                8 => {
                    let mut decoder = DeflateDecoder::new(&raw_data[..]);
                    let mut uncompressed = Vec::with_capacity(entry.uncompressed_size as usize);
                    decoder.read_to_end(&mut uncompressed).map_err(|e| {
                        DomainError::Validation(format!(
                            "Deflate decompression error for '{}': {}",
                            entry.name, e
                        ))
                    })?;
                    uncompressed
                }
                m => {
                    return Err(DomainError::Validation(format!(
                        "Unsupported ZIP compression method: {}",
                        m
                    )));
                }
            };

            std::fs::write(&dest_path, &decompressed).map_err(|e| {
                DomainError::storage(format!(
                    "Failed to write extracted file {:?}: {}",
                    dest_path, e
                ))
            })?;

            extracted_files.push((dest_path, decompressed));
        }

        Ok(extracted_files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal_sanitizer() {
        // Zip-Slip attack vectors
        assert!(SafeArchiveExtractor::sanitize_rel_path("../../etc/passwd").is_err());
        assert!(SafeArchiveExtractor::sanitize_rel_path("..\\..\\windows\\system32").is_err());
        assert!(SafeArchiveExtractor::sanitize_rel_path("C:\\cmd.exe").is_err());
        assert!(SafeArchiveExtractor::sanitize_rel_path("/absolute/path").is_ok()); // leading slash stripped safely
        let ok_path = SafeArchiveExtractor::sanitize_rel_path("folder/sub/chal.bin").unwrap();
        assert_eq!(
            ok_path,
            PathBuf::from("folder").join("sub").join("chal.bin")
        );
    }
}
