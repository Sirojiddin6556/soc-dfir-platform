#![forbid(unsafe_code)]

use chrono::Utc;
use core_domain::id::EntityId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadTokenClaims {
    pub session_id: EntityId,
    pub case_id: EntityId,
    pub actor_id: String,
    pub max_size_bytes: u64,
    pub expires_at_epoch: i64,
}

#[derive(Clone)]
pub struct TokenManager {
    secret_key: [u8; 32],
}

impl TokenManager {
    pub fn new() -> Self {
        // Deterministic or system-backed secret key for local engine process
        let mut key = [0u8; 32];
        let seed = b"SOCDFIR-UPLOAD-CAPABILITY-KEY-V1";
        key.copy_from_slice(&seed[0..32]);
        Self { secret_key: key }
    }

    pub fn generate_token(&self, claims: &UploadTokenClaims) -> String {
        let claims_json = serde_json::to_string(claims).unwrap_or_default();
        let claims_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            claims_json.as_bytes(),
        );

        let sig = blake3::keyed_hash(&self.secret_key, claims_json.as_bytes());
        let sig_hex = sig.to_hex().to_string();

        format!("{claims_b64}.{sig_hex}")
    }

    pub fn validate_token(&self, token: &str) -> Result<UploadTokenClaims, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err("Malformed upload token format".to_string());
        }

        let claims_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[0])
                .map_err(|e| format!("Invalid base64 in upload token: {e}"))?;

        let expected_sig = blake3::keyed_hash(&self.secret_key, &claims_bytes);
        if expected_sig.to_hex().as_str() != parts[1] {
            return Err("Invalid upload token signature".to_string());
        }

        let claims: UploadTokenClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|e| format!("Corrupt claims in upload token: {e}"))?;

        let now = Utc::now().timestamp();
        if now > claims.expires_at_epoch {
            return Err("Upload token expired".to_string());
        }

        Ok(claims)
    }

    pub fn hash_token(&self, token: &str) -> String {
        blake3::hash(token.as_bytes()).to_hex().to_string()
    }
}

impl Default for TokenManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_roundtrip_and_expiry() {
        let mgr = TokenManager::new();
        let session_id = EntityId::new_v7();
        let case_id = EntityId::new_v7();

        let claims = UploadTokenClaims {
            session_id,
            case_id,
            actor_id: "forensic_analyst".to_string(),
            max_size_bytes: 1048576,
            expires_at_epoch: Utc::now().timestamp() + 3600,
        };

        let token = mgr.generate_token(&claims);
        let validated = mgr.validate_token(&token).unwrap();
        assert_eq!(validated.session_id, session_id);
        assert_eq!(validated.actor_id, "forensic_analyst");

        // Tampered token test
        let tampered = format!("tampered.{}", token.split('.').nth(1).unwrap());
        assert!(mgr.validate_token(&tampered).is_err());

        // Expired token test
        let expired_claims = UploadTokenClaims {
            session_id,
            case_id,
            actor_id: "forensic_analyst".to_string(),
            max_size_bytes: 1048576,
            expires_at_epoch: Utc::now().timestamp() - 10,
        };
        let expired_token = mgr.generate_token(&expired_claims);
        assert!(mgr.validate_token(&expired_token).is_err());
    }
}
