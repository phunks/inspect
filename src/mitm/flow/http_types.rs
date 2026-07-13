
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;
use crate::filters::{FilterRequest, FilterRequestView, FilterSyntheticResponse};
use crate::filters::types::OutboundHttpJob;
use crate::mitm::flow::{FlowMark, ResponseOrigin};

pub(crate) struct RequestDispatchContext {
    pub(crate) id: Uuid,
    pub(crate) seq: u64,
    pub(crate) flow_key: String,
    pub(crate) flow_dir: std::path::PathBuf,
    pub(crate) time: chrono::DateTime<Utc>,
    pub(crate) started_at: std::time::Instant,
    pub(crate) tls_sni: Option<String>,
    pub(crate) protocol: String,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) method: String,
}

impl RequestDispatchContext {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn request_view<'a>(
        &'a self,
        method: &'a str,
    ) -> FilterRequestView<'a> {
        FilterRequestView {
            host: &self.host,
            path: self.path(),
            method,
        }
    }
    pub(crate) fn into_response_input(
        self,
        filter_request: FilterRequest,
        origin: ResponseOrigin,
        upstream_status: Option<u16>,
        upstream_remote_addr: Option<String>,
        tls_upstream: Option<Value>,
        upstream_error_message: Option<String>,
    ) -> ResponseDispatchInput {
        let req_path = self.path().to_string();

        ResponseDispatchInput {
            id: self.id,
            seq: self.seq,
            flow_key: self.flow_key,
            flow_dir: self.flow_dir,
            started_at: self.started_at,
            tls_sni: self.tls_sni,
            req_host: self.host,
            req_path,
            req_method: self.method,
            filter_request,
            origin,
            upstream_status,
            upstream_remote_addr,
            tls_upstream,
            upstream_error_message,
        }
    }
}

pub(crate) struct ResponseDispatchInput {
    pub(crate) id: Uuid,
    pub(crate) seq: u64,
    pub(crate) flow_key: String,
    pub(crate) flow_dir: std::path::PathBuf,
    pub(crate) started_at: std::time::Instant,
    pub(crate) tls_sni: Option<String>,
    pub(crate) req_host: String,
    pub(crate) req_path: String,
    pub(crate) req_method: String,
    pub(crate) filter_request: FilterRequest,
    pub(crate) origin: ResponseOrigin,
    pub(crate) upstream_status: Option<u16>,
    pub(crate) upstream_remote_addr: Option<String>,
    pub(crate) tls_upstream: Option<Value>,
    pub(crate) upstream_error_message: Option<String>,
}

pub(crate) struct RequestDispatchOutput {
    pub filter_request: FilterRequest,
    pub marks: Vec<FlowMark>,
    pub synthetic_response: Option<FilterSyntheticResponse>,
    pub drop_client_response: bool,
}

pub(crate) struct ResponseFilterDispatchOutput {
    pub marks: Vec<FlowMark>,
    pub outbound_http: Vec<OutboundHttpJob>,
    pub drop_client_response: bool,
}

impl ResponseDispatchInput {
    pub(crate) fn request_view(&self) -> FilterRequestView<'_> {
        FilterRequestView {
            host: &self.req_host,
            path: &self.req_path,
            method: &self.req_method,
        }
    }
}