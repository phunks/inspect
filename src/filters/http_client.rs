use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use rama::{
    Service,
    http::{
        Body,
        Request,
        client::EasyHttpWebClient,
    },
};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use crate::filters::types::{OutboundHttpBodySource, OutboundHttpJob};

#[derive(Clone, Debug, Deserialize)]
pub struct NamedHttpClientConfig {
    pub name: String,
    pub base_url: String,
    #[serde(default = "default_outbound_http_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub struct OutboundHttpPoolConfig {
    pub base_url: String,
    pub timeout_ms: u64,
}

impl From<NamedHttpClientConfig> for OutboundHttpPoolConfig {
    fn from(config: NamedHttpClientConfig) -> Self {
        Self {
            base_url: config.base_url,
            timeout_ms: config.timeout_ms,
        }
    }
}

#[derive(Clone)]
pub struct OutboundHttpClientPool {
    tx: mpsc::Sender<OutboundHttpJob>,
    configs: Arc<HashMap<String, OutboundHttpPoolConfig>>,
}

impl OutboundHttpClientPool {
    pub fn new(
        configs: HashMap<String, OutboundHttpPoolConfig>,
        queue_size: usize,
    ) -> (Self, mpsc::Receiver<OutboundHttpJob>) {
        let (tx, rx) = mpsc::channel(queue_size);

        (
            Self {
                tx,
                configs: Arc::new(configs),
            },
            rx,
        )
    }

    pub fn configs(&self) -> Arc<HashMap<String, OutboundHttpPoolConfig>> {
        self.configs.clone()
    }

    pub fn try_enqueue(&self, job: OutboundHttpJob) {
        if !self.configs.contains_key(&job.client) {
            warn!(
                client = job.client,
                "drop outbound http job: unknown client"
            );
            return;
        }

        if let Err(err) = self.tx.try_send(job) {
            warn!(
                error = ?err,
                "drop outbound http job: queue full or closed"
            );
        }
    }
}

pub async fn run_outbound_http_worker(
    mut rx: mpsc::Receiver<OutboundHttpJob>,
    configs: Arc<HashMap<String, OutboundHttpPoolConfig>>,
) {
    let client = EasyHttpWebClient::default();

    while let Some(job) = rx.recv().await {
        let Some(config) = configs.get(&job.client).cloned() else {
            warn!(
                client = job.client,
                "drop outbound http job: unknown client"
            );
            continue;
        };

        let request = match build_outbound_request(&config, job) {
            Ok(request) => request,
            Err(err) => {
                warn!(
                    error = ?err,
                    "drop outbound http job: failed to build request"
                );
                continue;
            }
        };

        let timeout = Duration::from_millis(config.timeout_ms);

        tokio::spawn({
            let client = client.clone();

            async move {
                match tokio::time::timeout(timeout, client.serve(request)).await {
                    Ok(Ok(response)) => {
                        debug!(
                            status = response.status().as_u16(),
                            "outbound http job completed"
                        );
                    }
                    Ok(Err(err)) => {
                        warn!(
                            error = ?err,
                            "outbound http job failed"
                        );
                    }
                    Err(_) => {
                        warn!(
                            timeout_ms = timeout.as_millis(),
                            "outbound http job timed out"
                        );
                    }
                }
            }
        });
    }
}

fn build_outbound_request(
    config: &OutboundHttpPoolConfig,
    job: OutboundHttpJob,
) -> anyhow::Result<Request> {
    let uri = outbound_url(&config.base_url, &job.path);

    let body = match job.body {
        OutboundHttpBodySource::Bytes(bytes) => bytes,
        OutboundHttpBodySource::CapturedRequest
        | OutboundHttpBodySource::CapturedResponse
        | OutboundHttpBodySource::CapturedRequestJson
        | OutboundHttpBodySource::CapturedResponseJson
        | OutboundHttpBodySource::CapturedFlowJson => {
            anyhow::bail!("unresolved captured outbound http body source")
        }
    };

    let mut builder = Request::builder()
        .method(job.method.as_str())
        .uri(uri);

    for header in job.headers {
        builder = builder.header(header.name.as_str(), header.value.as_str());
    }

    Ok(builder.body(Body::from(body))?)
}

fn outbound_url(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }

    let base = base_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');

    format!("{base}/{path}")
}

fn default_outbound_http_timeout_ms() -> u64 {
    5_000
}

// Intentionally no filesystem, process execution, or arbitrary network capability here.
// Roto filters should only be able to enqueue jobs for Rust-defined named clients.