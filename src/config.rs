use serde::Deserialize;

// Configuration struct
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    // HTTP Server auth
    pub http_host: String,
    pub http_port: String,
    pub http_username: String,
    pub http_password: String,

    // OpenSearch auth
    pub opensearch_url: String,
    pub opensearch_username: String,
    pub opensearch_password: String,
    pub index_name: String,
}

pub fn load_config() -> Config {
    Config {
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
    }
}
