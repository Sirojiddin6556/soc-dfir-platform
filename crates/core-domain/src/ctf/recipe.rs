use super::pipeline_entities::{RecipeOp, RecipePreview};
use crate::error::DomainError;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use regex::Regex;
use std::io::{Read, Write};

pub const DEFAULT_FLAG_REGEX: &str =
    r"(?i)(?:flag|ctf|sec|vuln)\{[a-zA-Z0-9_\-\+\.!@#$%^&*?]{3,128}\}";

pub fn apply_op(input: &[u8], op: &RecipeOp) -> Result<Vec<u8>, DomainError> {
    match op {
        RecipeOp::HexDecode => {
            let s = std::str::from_utf8(input).map_err(|e| {
                DomainError::Validation(format!("Invalid UTF-8 for Hex decode: {}", e))
            })?;
            // robust hex clean: strip whitespace and leading 0x if present
            let hex_clean = s
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X")
                .replace([' ', '\n', '\r', '\t'], "");
            hex::decode(&hex_clean)
                .map_err(|e| DomainError::Validation(format!("Hex decode failed: {}", e)))
        }
        RecipeOp::HexEncode => Ok(hex::encode(input).into_bytes()),
        RecipeOp::Base64Decode => {
            let s = std::str::from_utf8(input).map_err(|e| {
                DomainError::Validation(format!("Invalid UTF-8 for Base64 decode: {}", e))
            })?;
            let clean = s.trim().replace(['\r', '\n', ' '], "");
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(clean.as_bytes())
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(clean.as_bytes()))
                .map_err(|e| DomainError::Validation(format!("Base64 decode failed: {}", e)))
        }
        RecipeOp::Base64Encode => {
            use base64::Engine;
            Ok(base64::engine::general_purpose::STANDARD
                .encode(input)
                .into_bytes())
        }
        RecipeOp::Xor { key } => {
            if key.is_empty() {
                return Err(DomainError::Validation(
                    "XOR key cannot be empty".to_string(),
                ));
            }
            let mut out = Vec::with_capacity(input.len());
            for (i, byte) in input.iter().enumerate() {
                out.push(byte ^ key[i % key.len()]);
            }
            Ok(out)
        }
        RecipeOp::Rot13 => {
            let mut out = Vec::with_capacity(input.len());
            for &b in input {
                if b.is_ascii_lowercase() {
                    out.push(b'a' + (b - b'a' + 13) % 26);
                } else if b.is_ascii_uppercase() {
                    out.push(b'A' + (b - b'A' + 13) % 26);
                } else {
                    out.push(b);
                }
            }
            Ok(out)
        }
        RecipeOp::ZlibDecompress => {
            let mut decoder = ZlibDecoder::new(input);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).map_err(|e| {
                DomainError::Validation(format!("zlib decompression failed: {}", e))
            })?;
            Ok(decompressed)
        }
        RecipeOp::ZlibCompress => {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(input)
                .map_err(|e| DomainError::Validation(format!("zlib compression failed: {}", e)))?;
            encoder
                .finish()
                .map_err(|e| DomainError::Validation(format!("zlib finish failed: {}", e)))
        }
        RecipeOp::UrlDecode => {
            let s = std::str::from_utf8(input).map_err(|e| {
                DomainError::Validation(format!("Invalid UTF-8 for URL decode: {}", e))
            })?;
            let decoded = urlencoding_decode(s)?;
            Ok(decoded.into_bytes())
        }
        RecipeOp::UrlEncode => {
            let mut encoded = String::new();
            for &byte in input {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                    encoded.push(byte as char);
                } else {
                    encoded.push_str(&format!("%{:02X}", byte));
                }
            }
            Ok(encoded.into_bytes())
        }
    }
}

pub fn apply_pipeline(input: &[u8], ops: &[RecipeOp]) -> Result<Vec<u8>, DomainError> {
    let mut current = input.to_vec();
    for op in ops {
        current = apply_op(&current, op)?;
    }
    Ok(current)
}

pub fn scan_flags(text: &str, custom_pattern: Option<&str>) -> Vec<String> {
    let pattern = custom_pattern.unwrap_or(DEFAULT_FLAG_REGEX);
    let re = match Regex::new(pattern) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut flags = Vec::new();
    for mat in re.find_iter(text) {
        let flag = mat.as_str().to_string();
        if !flags.contains(&flag) {
            flags.push(flag);
        }
    }
    flags
}

pub fn preview_pipeline(
    input: &[u8],
    ops: &[RecipeOp],
    flag_pattern: Option<&str>,
) -> Result<RecipePreview, DomainError> {
    let output = apply_pipeline(input, ops)?;

    let input_sample = format_sample(input, 64);
    let output_sample = format_sample(&output, 64);

    let output_lossy = String::from_utf8_lossy(&output);
    let detected_flags = scan_flags(&output_lossy, flag_pattern);

    Ok(RecipePreview {
        input_sample,
        output_sample,
        input_len: input.len(),
        output_len: output.len(),
        detected_flags,
    })
}

fn format_sample(bytes: &[u8], max_len: usize) -> String {
    let slice = if bytes.len() > max_len {
        &bytes[..max_len]
    } else {
        bytes
    };
    match std::str::from_utf8(slice) {
        Ok(s) => {
            let sanitized: String = s
                .chars()
                .map(|c| if c.is_control() { '.' } else { c })
                .collect();
            if bytes.len() > max_len {
                format!("{}...", sanitized)
            } else {
                sanitized
            }
        }
        Err(_) => {
            let hex_str = hex::encode(slice);
            if bytes.len() > max_len {
                format!("{}...", hex_str)
            } else {
                hex_str
            }
        }
    }
}

fn urlencoding_decode(s: &str) -> Result<String, DomainError> {
    let mut bytes = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' && i + 2 < chars.len() {
            let hex_pair = format!("{}{}", chars[i + 1], chars[i + 2]);
            if let Ok(b) = u8::from_str_radix(&hex_pair, 16) {
                bytes.push(b);
                i += 3;
                continue;
            }
        } else if chars[i] == '+' {
            bytes.push(b' ');
            i += 1;
            continue;
        }
        bytes.push(chars[i] as u8);
        i += 1;
    }
    String::from_utf8(bytes)
        .map_err(|e| DomainError::Validation(format!("URL decode UTF-8 error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode_decode() {
        let raw = b"secret_pwn_bytes_1337";
        let encoded = apply_op(raw, &RecipeOp::HexEncode).unwrap();
        let decoded = apply_op(&encoded, &RecipeOp::HexDecode).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_base64_encode_decode() {
        let raw = b"flag{base64_test_success}";
        let encoded = apply_op(raw, &RecipeOp::Base64Encode).unwrap();
        let decoded = apply_op(&encoded, &RecipeOp::Base64Decode).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_xor_reversible() {
        let raw = b"crypto_xor_challenge";
        let key = b"KEY42";
        let xored = apply_op(raw, &RecipeOp::Xor { key: key.to_vec() }).unwrap();
        assert_ne!(xored, raw);
        let restored = apply_op(&xored, &RecipeOp::Xor { key: key.to_vec() }).unwrap();
        assert_eq!(restored, raw);
    }

    #[test]
    fn test_rot13() {
        let raw = b"Hello, World!";
        let rot = apply_op(raw, &RecipeOp::Rot13).unwrap();
        assert_eq!(rot, b"Uryyb, Jbeyq!");
        let restored = apply_op(&rot, &RecipeOp::Rot13).unwrap();
        assert_eq!(restored, raw);
    }

    #[test]
    fn test_zlib_compress_decompress() {
        let raw = b"CTF{zlib_compression_in_memory_pipeline}";
        let compressed = apply_op(raw, &RecipeOp::ZlibCompress).unwrap();
        let decompressed = apply_op(&compressed, &RecipeOp::ZlibDecompress).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn test_url_encode_decode() {
        let raw = b"param=hello world&flag=1";
        let encoded = apply_op(raw, &RecipeOp::UrlEncode).unwrap();
        assert!(std::str::from_utf8(&encoded).unwrap().contains("%20"));
        let decoded = apply_op(&encoded, &RecipeOp::UrlDecode).unwrap();
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_flag_scanner() {
        let text = "Analyzing memory: found token ctf{m3m0ry_unp4cked_fl4g!} and junk flag{second_flag_here}";
        let flags = scan_flags(text, None);
        assert_eq!(flags.len(), 2);
        assert_eq!(flags[0], "ctf{m3m0ry_unp4cked_fl4g!}");
        assert_eq!(flags[1], "flag{second_flag_here}");
    }

    #[test]
    fn test_recipe_pipeline_preview() {
        // pipeline: raw string -> Rot13 -> Base64
        let secret = b"flag{hidden_in_pipeline}";
        let rot = apply_op(secret, &RecipeOp::Rot13).unwrap();
        let b64 = apply_op(&rot, &RecipeOp::Base64Encode).unwrap();

        // solve pipeline: Base64Decode -> Rot13
        let ops = vec![RecipeOp::Base64Decode, RecipeOp::Rot13];
        let preview = preview_pipeline(&b64, &ops, None).unwrap();

        assert_eq!(preview.detected_flags.len(), 1);
        assert_eq!(preview.detected_flags[0], "flag{hidden_in_pipeline}");
    }
}
