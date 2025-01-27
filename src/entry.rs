use serde::{Deserialize, Serialize};

// Log entry structure
#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub trace_id: String,
    pub level: String,
    pub message: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogLocationEntry {
    pub plateform: String,
    pub instance: String,
    pub executor: String,
    pub file: LogLocationEntryFile,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogLocationEntryFile {
    pub name: String,
    pub line: String,
}
