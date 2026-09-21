#![forbid(unsafe_code)]

use super::session::IngestSessionManager;
use core_domain::id::EntityId;
use storage_sqlite::SqliteStorage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn handle_binary_upload_chunk(
    mut stream: TcpStream,
    path: &str,
    headers_str: &str,
    session_mgr: &IngestSessionManager,
    storage: &SqliteStorage,
    initial_body: &[u8],
    content_length: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Extract session_id from /ingest/{session_id}/chunk
    let session_id_str = path
        .trim_start_matches("/ingest/")
        .trim_end_matches("/chunk");

    let session_id = match EntityId::parse(session_id_str) {
        Ok(id) => id,
        Err(_) => {
            let resp =
                "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid session ID";
            stream.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
    };

    // Parse Authorization header
    let token = headers_str
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .and_then(|l| l.split_whitespace().nth(2))
        .or_else(|| {
            headers_str
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim())
        })
        .unwrap_or("");

    if token.is_empty() {
        let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nMissing authorization token";
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    // Parse Upload-Offset header
    let offset: u64 = headers_str
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("upload-offset:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);

    // Stream the payload chunk: write initial_body, then read remaining content_length
    let mut total_chunk_bytes = Vec::with_capacity(initial_body.len().min(content_length));
    total_chunk_bytes.extend_from_slice(initial_body);

    let mut remaining = content_length.saturating_sub(initial_body.len());
    let mut buf = [0u8; 16384];

    while remaining > 0 {
        let to_read = remaining.min(buf.len());
        let n = stream.read(&mut buf[..to_read]).await?;
        if n == 0 {
            break;
        }
        total_chunk_bytes.extend_from_slice(&buf[..n]);
        remaining -= n;
    }

    match session_mgr
        .write_chunk(session_id, token, offset, &total_chunk_bytes, storage)
        .await
    {
        Ok(new_len) => {
            let resp =
                format!("HTTP/1.1 200 OK\r\nUpload-Offset: {new_len}\r\nContent-Length: 0\r\n\r\n");
            stream.write_all(resp.as_bytes()).await?;
        }
        Err(problem) => {
            let status_code = match problem.status {
                401 => "401 Unauthorized",
                404 => "404 Not Found",
                409 => "409 Conflict",
                _ => "400 Bad Request",
            };
            let body = serde_json::to_string(&problem).unwrap_or_default();
            let resp = format!(
                "HTTP/1.1 {status_code}\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).await?;
        }
    }

    Ok(())
}
