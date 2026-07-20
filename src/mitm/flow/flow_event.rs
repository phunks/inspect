

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

#[derive(Clone, Debug)]
pub enum FlowEvent {
    RequestCommitted(RequestCommitted),
    ResponseCommitted(ResponseCommitted),
    TunnelFailed(TunnelFailed),
}

#[derive(Clone, Debug)]
pub struct TunnelFailed {
    pub id: String,
    pub seq: u64,
    pub flow_key: String,
    pub time: String,
    pub epoch_ms: i64,
    pub host: String,
    pub port: u16,
    pub stage: String,
    pub error: String,
    pub marks: Vec<FlowMark>,
}

#[derive(Clone, Debug)]
pub struct RequestCommitted {
    pub id: String,
    pub seq: u64,
    pub flow_key: String,
    pub time: String,
    pub epoch_ms: i64,
    pub method: String,
    pub protocol: String,
    pub host: String,
    pub uri: String,
    pub query_str: String,
    pub version: String,
    pub marks: Vec<FlowMark>,
}

#[derive(Clone, Debug)]
pub struct ResponseCommitted {
    pub id: String,
    pub flow_key: String,
    pub status: u16,
    pub elapsed_ms: i64,
    pub version: String,
    pub marks: Vec<FlowMark>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowMark {
    pub label: String,
    pub color: Option<String>,
}

#[derive(Clone)]
pub struct FlowEventPublisher {
    tx: mpsc::Sender<Arc<FlowEvent>>,
}

impl FlowEventPublisher {
    pub fn channel(buffer: usize) -> (Self, mpsc::Receiver<Arc<FlowEvent>>) {
        let (tx, rx) = mpsc::channel(buffer);
        (Self { tx }, rx)
    }

    pub fn publish(&self, event: FlowEvent) {
        if let Err(err) = self.tx.try_send(Arc::new(event)) {
            warn!(?err, "flow event queue full; dropped event");
        }
    }
}

pub trait FlowEventSink: Send + Sync {
    fn publish(&self, event: Arc<FlowEvent>);
}

pub struct FlowEventDispatcher {
    sinks: Vec<Box<dyn FlowEventSink>>,
}

impl FlowEventDispatcher {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    pub fn with_sink(mut self, sink: impl FlowEventSink + 'static) -> Self {
        self.sinks.push(Box::new(sink));
        self
    }

    pub async fn run(self, mut rx: mpsc::Receiver<Arc<FlowEvent>>) {
        while let Some(event) = rx.recv().await {
            for sink in &self.sinks {
                sink.publish(event.clone());
            }
        }
    }
}

impl Default for FlowEventDispatcher {
    fn default() -> Self {
        Self::new()
    }
}