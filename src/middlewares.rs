use crate::state::AppState;

use axum::{extract::State, http::StatusCode, middleware::Next};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::sync::Arc;

// Basic auth middleware
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok());

    match auth_header {
        Some(auth) if auth.starts_with("Basic ") => {
            let credentials = auth.trim_start_matches("Basic ").trim();
            if let Ok(decoded) = BASE64.decode(credentials) {
                if let Ok(auth_str) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = auth_str.split(':').collect();
                    if parts.len() == 2 {
                        let (username, password) = (parts[0], parts[1]);
                        if username == state.config.http_username
                            && password == state.config.http_password
                        {
                            return Ok(next.run(request).await);
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Err(StatusCode::UNAUTHORIZED)
}
