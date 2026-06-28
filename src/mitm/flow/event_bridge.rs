use crate::mitm::flow::{
    FlowEvent,
    FlowEventPublisher,
    FlowMark,
    RequestCommit,
    RequestCommitted,
    ResponseCommit,
    ResponseCommitted,
};

pub(crate) fn publish_request_committed(
    events: &FlowEventPublisher,
    commit: &RequestCommit,
    marks: Vec<FlowMark>,
) {
    events.publish(FlowEvent::RequestCommitted(RequestCommitted {
        id: commit.id.clone(),
        seq: commit.seq,
        flow_key: commit.flow_key.clone(),
        time: commit.time.clone(),
        epoch_ms: commit.epoch_ms,
        method: commit.method.clone(),
        protocol: commit.protocol.clone(),
        host: commit.host.clone(),
        uri: commit.uri.clone(),
        query_str: commit.query_str.clone(),
        version: commit.version.clone(),
        marks,
    }));
}

pub(crate) fn publish_response_committed(
    events: &FlowEventPublisher,
    commit: &ResponseCommit,
    marks: Vec<FlowMark>,
) {
    events.publish(FlowEvent::ResponseCommitted(ResponseCommitted {
        id: commit.id.clone(),
        flow_key: commit.flow_key.clone(),
        status: commit.display_status,
        elapsed_ms: commit.elapsed_ms,
        version: commit.version.clone(),
        marks,
    }));
}