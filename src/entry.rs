use serde::{Deserialize, Serialize};

// Log entry structure
#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
    pub metadata: serde_json::Value,
}
