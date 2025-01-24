use opensearch::{
    auth::Credentials,
    cert::CertificateValidation,
    http::{
        transport::{SingleNodeConnectionPool, TransportBuilder},
        Url,
    },
    OpenSearch,
};

use serde_json::json;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tracing::{info, instrument};
use tracing_subscriber::Layer;

pub struct OpenSearchLayer {
    opensearch_client: Arc<OpenSearch>,
}

impl OpenSearchLayer {
    pub fn new(client: OpenSearch) -> Self {
        Self {
            opensearch_client: Arc::new(client),
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for OpenSearchLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = serde_json::Map::new();
        event.record(
            &mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
                visitor.insert(field.name().to_string(), json!(format!("{:?}", value)));
            },
        );

        let log_entry = json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "fields": visitor,
        });

        // Clone l'Arc pour éviter les emprunts de durée de vie
        let opensearch_client = Arc::clone(&self.opensearch_client);

        tokio::spawn(async move {
            if let Err(e) = opensearch_client
                .index(opensearch::IndexParts::Index("data-builder-log"))
                .body(log_entry)
                .send()
                .await
            {
                tracing::error!("Failed to index log in OpenSearch: {:?}", e);
            }
        });
    }
}
