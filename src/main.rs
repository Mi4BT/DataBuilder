mod config;
mod entry;
mod logger;
mod middlewares;
mod pipelines;
mod routes;
mod state;

use anyhow::Result;
use axum::{middleware, routing::post, Router};
use tracing_subscriber::prelude::*;

use opensearch::{
    auth::Credentials,
    cert::CertificateValidation,
    http::{
        transport::{SingleNodeConnectionPool, TransportBuilder},
        Url,
    },
    OpenSearch,
};
use std::sync::Arc;

use crate::config::load_config;
use crate::logger::OpenSearchLayer;
use crate::middlewares::auth_middleware;
use crate::routes::ingest_logs;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = load_config();

    // Create transport with basic auth
    let credentials = Credentials::Basic(
        config.opensearch_username.clone(),
        config.opensearch_password.clone(),
    );
    let conn_pool = SingleNodeConnectionPool::new(Url::parse(&config.opensearch_url)?);
    let transport = TransportBuilder::new(conn_pool)
        .auth(credentials)
        .cert_validation(CertificateValidation::None)
        .disable_proxy()
        .build()?;
    let client = OpenSearch::new(transport);
    let opensearch_layer = OpenSearchLayer::new(client.clone());

    tracing_subscriber::registry().with(opensearch_layer).init();

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
