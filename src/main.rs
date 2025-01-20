use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    middleware::{self, Next},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use opensearch::{
    auth::Credentials,
    http::{
        transport::{SingleNodeConnectionPool, TransportBuilder},
        Url,
    },
    OpenSearch,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// Configuration struct
#[derive(Debug, Deserialize, Clone)]
struct Config {
    // HTTP Server auth
    http_host: String,
    http_port: String,
    http_username: String,
    http_password: String,

    // OpenSearch auth
    opensearch_url: String,
    opensearch_username: String,
    opensearch_password: String,
    index_name: String,
}

// Log entry structure
#[derive(Debug, Serialize, Deserialize)]
struct LogEntry {
    timestamp: String,
    level: String,
    message: String,
    metadata: serde_json::Value,
}

// Application state
struct AppState {
    config: Config,
    opensearch_client: OpenSearch,
}

// Pipeline trait for processing logs
#[async_trait::async_trait]
trait Pipeline: Send + Sync {
    async fn process(&self, log: LogEntry) -> Result<LogEntry>;
}

// Simple pipeline implementation
struct SimplePipeline;

#[async_trait::async_trait]
impl Pipeline for SimplePipeline {
    async fn process(&self, mut log: LogEntry) -> Result<LogEntry> {
        // Add processing timestamp
        log.metadata["processed_at"] = serde_json::Value::String(chrono::Utc::now().to_rfc3339());
        Ok(log)
    }
}

// Basic auth middleware
async fn auth_middleware(
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

// Handler for receiving logs
async fn ingest_logs(
    State(state): State<Arc<AppState>>,
    Json(log): Json<LogEntry>,
) -> Result<StatusCode, StatusCode> {
    let pipeline = SimplePipeline;

    // Process log through pipeline
    let processed_log = pipeline.process(log).await.map_err(|e| {
        tracing::error!("Failed to process log through pipeline: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Successfully processed log through pipeline");

    // Index log in OpenSearch
    let response = state
        .opensearch_client
        .index(opensearch::IndexParts::Index(&state.config.index_name))
        .body(processed_log)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to index log in OpenSearch: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if response.status_code().is_success() {
        tracing::info!(
            "Successfully indexed log in OpenSearch index '{}'",
            state.config.index_name
        );
        Ok(StatusCode::CREATED)
    } else {
        tracing::error!(
            "Failed to index log - OpenSearch returned status code: {}",
            response.status_code()
        );
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = Config {
        http_username: std::env::var("HTTP_USERNAME").expect("HTTP_USERNAME must be set"),
        http_password: std::env::var("HTTP_PASSWORD").expect("HTTP_PASSWORD must be set"),
        http_host: std::env::var("HTTP_HOSTNAME").expect("HTTP_HOSTNAME must be set"),
        http_port: std::env::var("HTTP_PORT").expect("HTTP_PORT must be set"),
        opensearch_url: std::env::var("OPENSEARCH_URL").expect("OPENSEARCH_URL must be set"),
        opensearch_username: std::env::var("OPENSEARCH_USERNAME")
            .expect("OPENSEARCH_USERNAME must be set"),
        opensearch_password: std::env::var("OPENSEARCH_PASSWORD")
            .expect("OPENSEARCH_PASSWORD must be set"),
        index_name: std::env::var("INDEX_NAME").unwrap_or_else(|_| "logs".to_string()),
    };

    // Create transport with basic auth
    let credentials = Credentials::Basic(
        config.opensearch_username.clone(),
        config.opensearch_password.clone(),
    );
    let conn_pool = SingleNodeConnectionPool::new(Url::parse(&config.opensearch_url)?);
    let transport = TransportBuilder::new(conn_pool)
        .auth(credentials)
        .disable_proxy()
        .build()?;
    let client = OpenSearch::new(transport);

    // Create shared state
    let state = Arc::new(AppState {
        config: config.clone(),
        opensearch_client: client,
    });

    // Build router with authentication
    let app = Router::new()
        .route("/", post(ingest_logs))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state);

    // Start server
    let addr = format!("{}:{}", config.http_host, config.http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
