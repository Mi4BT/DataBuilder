use crate::entry::LogEntry;
use anyhow::Result;

// Pipeline trait for processing logs
#[async_trait::async_trait]
pub trait Pipeline: Send + Sync {
    async fn process(&self, log: LogEntry) -> Result<LogEntry>;
}

// Simple pipeline implementation
pub struct SimplePipeline;

#[async_trait::async_trait]
impl Pipeline for SimplePipeline {
    async fn process(&self, mut log: LogEntry) -> Result<LogEntry> {
        // Add processing timestamp
        log.metadata["processed_at"] = serde_json::Value::String(chrono::Utc::now().to_rfc3339());
        Ok(log)
    }
}
