#[derive(Clone, Debug)]
pub struct NamedHttpClientConfig {
    pub name: String,
    pub base_url: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub struct OutboundHttpJob {
    pub client: String,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

// Intentionally no filesystem, process execution, or arbitrary network capability here.
// Roto filters should only be able to enqueue jobs for Rust-defined named clients.