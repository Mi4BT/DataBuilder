use crate::config::Config;
use opensearch::OpenSearch;

// Application state
pub struct AppState {
    pub config: Config,
    pub opensearch_client: OpenSearch,
}
