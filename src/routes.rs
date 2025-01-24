use anyhow::Result;
use axum::{extract::State, http::StatusCode, Json};

use std::sync::Arc;

use crate::entry::LogEntry;
use crate::pipelines::Pipeline;
use crate::pipelines::SimplePipeline;
use crate::state::AppState;

// Handler for receiving logs
pub async fn ingest_logs(
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
