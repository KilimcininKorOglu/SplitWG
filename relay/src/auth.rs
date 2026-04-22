use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::http::{HeaderMap, StatusCode};

pub fn validate_token(headers: &HeaderMap, token_hashes: &[String]) -> Result<(), StatusCode> {
    if token_hashes.is_empty() {
        return Ok(());
    }

    let header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let argon2 = Argon2::default();
    for hash_str in token_hashes {
        if let Ok(hash) = PasswordHash::new(hash_str) {
            if argon2.verify_password(token.as_bytes(), &hash).is_ok() {
                return Ok(());
            }
        }
    }

    Err(StatusCode::FORBIDDEN)
}
