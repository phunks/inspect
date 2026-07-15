use std::sync::Arc;
use tokio::sync::mpsc;

use crate::mitm::flow::flow_event::{
    FlowEvent,
    FlowEventSink,
    FlowMark,
};
use crate::mitm::proxy::{PacketCompleted, PacketEvent, PacketMarked, PacketStarted, PacketTunnelFailed};

pub struct TuiSink {
    tx: mpsc::Sender<PacketEvent>,
}

impl TuiSink {
    pub fn new(tx: mpsc::Sender<PacketEvent>) -> Self {
        Self { tx }
    }

    fn send_mark(&self, id: &str, flow_key: &str, mark: &FlowMark) {
        let _ = self.tx.try_send(PacketEvent::Marked(PacketMarked {
            id: id.to_string(),
            flow_key: flow_key.to_string(),
            label: mark.label.clone(),
            color: mark.color.clone(),
        }));
    }
}

impl FlowEventSink for TuiSink {
    fn publish(&self, event: Arc<FlowEvent>) {
        match event.as_ref() {
            FlowEvent::TunnelFailed(event) => {
                let _ = self.tx.try_send(PacketEvent::TunnelFailed(
                    PacketTunnelFailed {
                        id: event.id.clone(),
                        seq: event.seq,
                        flow_key: event.flow_key.clone(),
                        time: event.time.clone(),
                        epoch_ms: event.epoch_ms,
                        host: event.host.clone(),
                        port: event.port,
                        stage: event.stage.clone(),
                        error: event.error.clone(),
                    },
                ));
            }
            FlowEvent::RequestCommitted(event) => {
                let _ = self.tx.try_send(PacketEvent::Started(PacketStarted {
                    id: event.id.clone(),
                    seq: event.seq,
                    flow_key: event.flow_key.clone(),
                    time: event.time.clone(),
                    epoch_ms: event.epoch_ms,
                    method: event.method.clone(),
                    protocol: event.protocol.clone(),
                    host: event.host.clone(),
                    uri: event.uri.clone(),
                    query_str: event.query_str.clone(),
                    version: event.version.clone(),
                }));

                for mark in &event.marks {
                    self.send_mark(&event.id, &event.flow_key, mark);
                }
            }
            FlowEvent::ResponseCommitted(event) => {
                let _ = self.tx.try_send(PacketEvent::Completed(PacketCompleted {
                    id: event.id.clone(),
                    status: event.status,
                    elapsed_ms: event.elapsed_ms,
                    version: event.version.clone(),
                }));

                for mark in &event.marks {
                    self.send_mark(&event.id, &event.flow_key, mark);
                }
            }
        }
    }
}