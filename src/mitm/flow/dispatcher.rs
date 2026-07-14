use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::BodyExt;
use rama::{
    error::OpaqueError,
    http::{
        body::{Frame, SizeHint},
        service::web::response::IntoResponse,
        Body,
        Request,
        Response,
        StatusCode,
        StreamingBody,
        Version,
    },
    net::{
        address::ProxyAddress,
        http::RequestContext,
    },
    telemetry::tracing,
};
use rama::extensions::{ExtensionsMut, ExtensionsRef};
use tracing::info;
use uuid::Uuid;

use crate::filters::{
    FilterFlow,
    FilterHeader,
    FilterManager,
    FilterRequest,
    FilterResponseView,
    FilterSyntheticResponse
};
use crate::filters::http_client::OutboundHttpClientPool;
use crate::filters::engine::json::capture::{
    json_filter_flow_bytes,
    json_filter_request_bytes,
    json_filter_response_bytes
};
use crate::filters::types::{
    OutboundHttpBodySource,
    OutboundHttpJob
};
use crate::mitm::flow::{
    CaptureService,
    EffectiveRequestCapture,
    EffectiveResponseCapture,
    FlowEventPublisher,
    FlowMark,
    ResponseCommit,
    ResponseOrigin
};
use crate::mitm::flow::capture_service::build_response_head_text;
use crate::mitm::flow::event_bridge::{
    publish_request_committed,
    publish_response_committed
};
use crate::mitm::flow::filter_bridge::{
    apply_request_patch,
    apply_response_patch,
    build_filter_request,
    build_filter_response,
    flow_marks_from_request_action,
    flow_marks_from_response_action,
    normalized_content_type,
};
use crate::mitm::flow::filter_runtime::FlowFilterRuntime;
use crate::mitm::flow::http_types::{
    RequestDispatchContext,
    RequestDispatchOutput,
    ResponseDispatchInput,
    ResponseFilterDispatchOutput
};
use crate::mitm::flow::state_store::FilterStateLimits;
use crate::mitm::flow::tls_metadata::{
    tls_sni_from_extensions,
    upstream_tls_info_from_extensions
};
use crate::mitm::flow::sse_capture::SseCapture;

pub type FlowDispatchResult<T> = Result<T, FlowDispatchError>;

#[derive(Debug)]
pub enum FlowDispatchError {
    BadRequest,
    Upstream(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for FlowDispatchError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

pub struct UpstreamFlowResult {
    pub response: Response,
    pub upstream_err: Option<String>,
    pub upstream_status: Option<u16>,
    pub upstream_remote_addr: Option<String>,
}

pub trait UpstreamFlowClient: Send + Sync {
    fn serve(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = UpstreamFlowResult> + Send + '_>>;

    fn serve_websocket(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>>;
}

#[derive(Clone)]
pub struct FlowDispatcherConfig {
    pub upstream_proxy: Option<ProxyAddress>,
    pub body_save_limit_bytes: Option<usize>,
    pub body_omit_content_types: Arc<[String]>,
    pub sse_capture_max_events: usize,
    pub sse_capture_max_event_bytes: usize,
    pub filter_state_enabled: bool,
    pub filter_state_limits: FilterStateLimits,
}

#[derive(Clone)]
pub struct FlowDispatcher {
    capture: CaptureService,
    filters: FlowFilterRuntime,
    events: FlowEventPublisher,
    upstream_client: Arc<dyn UpstreamFlowClient>,
    seq: Arc<AtomicU64>,
    outbound_http_pool: Option<OutboundHttpClientPool>,
    config: FlowDispatcherConfig,
}

impl FlowDispatcher {
    pub fn new(
        capture: CaptureService,
        filters: FilterManager,
        events: FlowEventPublisher,
        upstream_client: Arc<dyn UpstreamFlowClient>,
        seq: Arc<AtomicU64>,
        outbound_http_pool: Option<OutboundHttpClientPool>,
        config: FlowDispatcherConfig,
    ) -> Self {
        Self {
            filters: FlowFilterRuntime::new(
                filters,
                capture.clone(),
                config.filter_state_enabled.then(|| {
                    crate::mitm::flow::state_store::FilterStateStore::new(config.filter_state_limits.clone())
                }),
            ),
            capture,
            events,
            upstream_client,
            seq,
            outbound_http_pool,
            config,
        }
    }

    pub(crate) fn capture(&self) -> &CaptureService {
        &self.capture
    }

    pub(crate) fn events(&self) -> &FlowEventPublisher {
        &self.events
    }

    pub(crate) fn upstream_client(&self) -> &Arc<dyn UpstreamFlowClient> {
        &self.upstream_client
    }

    pub(crate) fn upstream_proxy(&self) -> Option<ProxyAddress> {
        self.config.upstream_proxy.clone()
    }

    pub(crate) fn seq(&self) -> &Arc<AtomicU64> {
        &self.seq
    }

    pub(crate) fn config(&self) -> &FlowDispatcherConfig {
        &self.config
    }

    pub async fn dispatch(&self, req: Request) -> Result<Response, Infallible> {
        match self.dispatch_http(req).await {
            Ok(response) => Ok(response),
            Err(FlowDispatchError::BadRequest) => Ok(StatusCode::BAD_REQUEST.into_response()),
            Err(err) => {
                tracing::error!(error = ?err, "failed to dispatch HTTP MITM flow");
                Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        }
    }

    async fn dispatch_http(&self, req: Request) -> FlowDispatchResult<Response> {
        let (mut req_parts, req_body) = req.into_parts();

        if let Some(upstream_proxy) = self.config.upstream_proxy.clone() {
            req_parts.extensions_mut().insert(upstream_proxy);
        }

        let ctx = self.new_request_context(&req_parts)?;
        let mut req_body_bytes = collect_body(req_body, "request").await;

        let RequestDispatchOutput {
            filter_request,
            marks,
            synthetic_response,
            drop_client_response,
        } = self.dispatch_request_filters(
            &ctx,
            &mut req_parts,
            &mut req_body_bytes,
        );

        if drop_client_response {
            tracing::info!(
                id = %ctx.id,
                flow_key = %ctx.flow_key,
                method = %req_parts.method,
                host = %ctx.host,
                path = %ctx.path(),
                marks = marks.len(),
                "request dropped by request filter before upstream"
            );

            self.commit_request(
                &ctx,
                &req_parts,
                &req_body_bytes,
                marks,
            )
                .await?;

            return Ok(
                Response::builder()
                    .status(444)
                    .header("connection", "close")
                    .body(Body::from(Bytes::new()))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            );
        }

        self.commit_request(
            &ctx,
            &req_parts,
            &req_body_bytes,
            marks,
        )
            .await?;

        if let Some(synthetic_response) = synthetic_response {
            return self
                .dispatch_synthetic_response(
                    ctx,
                    req_parts.version,
                    filter_request,
                    synthetic_response,
                )
                .await;
        }

        let upstream_req = Request::from_parts(req_parts, Body::from(req_body_bytes));
        let upstream_result = self.upstream_client.serve(upstream_req).await;

        self.dispatch_upstream_response(
            ctx,
            filter_request,
            upstream_result,
        )
            .await
    }

    fn new_request_context(
        &self,
        req_parts: &rama::http::request::Parts,
    ) -> FlowDispatchResult<RequestDispatchContext> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let id = Uuid::new_v4();
        let time = Utc::now();
        let started_at = std::time::Instant::now();

        let tls_sni = tls_sni_from_extensions(req_parts.extensions());

        let req_ctx = RequestContext::try_from(req_parts).map_err(|err| {
            tracing::error!("error extracting request context: {err:?}");
            FlowDispatchError::BadRequest
        })?;

        let protocol = req_ctx.protocol.to_string();
        let host = req_ctx.authority.host.to_string();
        let uri = req_parts.uri.clone();
        let method = req_parts.method.to_string();

        let uuid_simple = id.simple().to_string();
        let uuid_prefix = &uuid_simple[..8];
        let flow_key = format!("{seq:06}-{uuid_prefix}");
        let flow_dir = self.capture.paths().flows_dir.join(&flow_key);

        Ok(RequestDispatchContext {
            id,
            seq,
            flow_key,
            flow_dir,
            time,
            started_at,
            tls_sni,
            protocol,
            host,
            uri,
            method,
        })
    }

    fn dispatch_request_filters(
        &self,
        ctx: &RequestDispatchContext,
        req_parts: &mut rama::http::request::Parts,
        req_body_bytes: &mut Bytes,
    ) -> RequestDispatchOutput {
        let req_filter_view = ctx.request_view(req_parts.method.as_str());

        let filter_request = build_filter_request(
            &ctx.id,
            ctx.seq,
            &ctx.flow_key,
            req_parts,
            &ctx.protocol,
            &ctx.host,
            req_body_bytes,
            ctx.tls_sni.clone(),
        );

        let request_action = self.filters.run_request_filters(
            &req_filter_view,
            &filter_request,
        );

        let marks = flow_marks_from_request_action(&request_action);
        let synthetic_response = request_action.synthetic_response;
        let drop_client_response = request_action.drop_client_response;
        
        if let Some(patch) = request_action.request {
            apply_request_patch(req_parts, req_body_bytes, patch);
        }

        RequestDispatchOutput {
            filter_request,
            marks,
            synthetic_response,
            drop_client_response,
        }
    }

    async fn commit_request(
        &self,
        ctx: &RequestDispatchContext,
        req_parts: &rama::http::request::Parts,
        req_body_bytes: &Bytes,
        marks: Vec<FlowMark>,
    ) -> FlowDispatchResult<()> {
        let request_commit = self
            .capture
            .commit_request(EffectiveRequestCapture {
                id: ctx.id,
                seq: ctx.seq,
                flow_key: ctx.flow_key.clone(),
                time: ctx.time,
                flow_dir: ctx.flow_dir.clone(),
                method: req_parts.method.as_str().to_string(),
                uri: req_parts.uri.clone(),
                version: req_parts.version,
                headers: req_parts.headers.clone(),
                body_bytes: req_body_bytes.clone(),
                protocol: ctx.protocol.clone(),
                host: ctx.host.clone(),
                tls_sni: ctx.tls_sni.clone(),
            })
            .await?;

        publish_request_committed(&self.events, &request_commit, marks);

        Ok(())
    }

    async fn dispatch_synthetic_response(
        &self,
        ctx: RequestDispatchContext,
        version: Version,
        filter_request: FilterRequest,
        synthetic_response: FilterSyntheticResponse,
    ) -> FlowDispatchResult<Response> {
        info!(
            id = %ctx.id,
            flow_key = %ctx.flow_key,
            status = synthetic_response.status,
            "return synthetic response from roto filter"
        );

        let response = build_synthetic_response(version, synthetic_response);

        self.dispatch_response(
            ctx.into_response_input(
                filter_request,
                ResponseOrigin::Synthetic,
                None,
                None,
                None,
                None,
            ),
            response,
        )
            .await
    }

    async fn dispatch_upstream_response(
        &self,
        ctx: RequestDispatchContext,
        filter_request: FilterRequest,
        upstream_result: UpstreamFlowResult,
    ) -> FlowDispatchResult<Response> {
        let (input, response) =
            split_upstream_result(ctx, filter_request, upstream_result);

        self.dispatch_response(input, response).await
    }

    async fn dispatch_response(
        &self,
        input: ResponseDispatchInput,
        response: Response,
    ) -> FlowDispatchResult<Response> {
        let elapsed_ms = input.started_at.elapsed().as_millis() as i64;

        let (mut res_parts, res_body) = response.into_parts();

        if is_sse_response(&res_parts.headers) {
            return self
                .dispatch_sse_response(input, res_parts, res_body, elapsed_ms)
                .await;
        }

        let mut res_body_bytes = collect_body(res_body, "response").await;

        let response_filter_output = self.dispatch_response_filters(
            &input,
            &mut res_parts,
            &mut res_body_bytes,
            elapsed_ms,
        );

        let response_marks = response_filter_output.marks;
        let drop_client_response = response_filter_output.drop_client_response;
        let outbound_http = self.resolve_outbound_http_jobs(
            response_filter_output.outbound_http,
            &input,
            &res_parts,
            &res_body_bytes,
        );
        self.dispatch_outbound_http(outbound_http);

        let response_commit = self
            .commit_response(
                &input,
                &res_parts,
                &res_body_bytes,
                elapsed_ms,
            )
            .await?;

        self.dispatch_completed_filters(
            &input,
            &res_parts,
            &res_body_bytes,
            elapsed_ms,
        );

        publish_response_committed(&self.events, &response_commit, response_marks);

        if drop_client_response {
            tracing::info!(
                    id = %input.id,
                    flow_key = %input.flow_key,
                    status = %res_parts.status,
                    "response dropped by response filter"
                );

            return Ok(
                Response::builder()
                    .status(444)
                    .header("connection", "close")
                    .body(Body::from(Bytes::new()))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
            );
        }

        Ok(Response::from_parts(res_parts, Body::from(res_body_bytes)))
    }

    async fn dispatch_sse_response(
        &self,
        input: ResponseDispatchInput,
        res_parts: rama::http::response::Parts,
        res_body: Body,
        elapsed_ms: i64,
    ) -> FlowDispatchResult<Response> {
        tracing::debug!(
            id = %input.id,
            flow_key = %input.flow_key,
            status = %res_parts.status,
            max_events = self.config.sse_capture_max_events,
            max_event_bytes = self.config.sse_capture_max_event_bytes,
            "proxy SSE response as a streaming body"
        );

        // Commit headers and response metadata now, rather than waiting for EOF.
        // SSE streams may be long-lived or intentionally never terminate.
        let response_commit = self
            .commit_response(&input, &res_parts, &Bytes::new(), elapsed_ms)
            .await?;

        publish_response_committed(&self.events, &response_commit, Vec::new());

        let capture = SseCapture::start(
            input.flow_dir.clone(),
            self.config.sse_capture_max_events,
            self.config.sse_capture_max_event_bytes,
        );

        Ok(Response::from_parts(
            res_parts,
            Body::new(SseCaptureBody {
                inner: res_body,
                capture,
            }),
        ))
    }

    async fn commit_response(
        &self,
        input: &ResponseDispatchInput,
        res_parts: &rama::http::response::Parts,
        res_body_bytes: &Bytes,
        elapsed_ms: i64,
    ) -> FlowDispatchResult<ResponseCommit> {
        let response_commit = self
            .capture
            .commit_response(EffectiveResponseCapture {
                id: input.id,
                seq: input.seq,
                flow_key: input.flow_key.clone(),
                flow_dir: input.flow_dir.clone(),
                status: res_parts.status,
                version: res_parts.version,
                headers: res_parts.headers.clone(),
                body_bytes: res_body_bytes.clone(),
                elapsed_ms,
                origin: input.origin.clone(),
                upstream_status: input.upstream_status,
                upstream_remote_addr: input.upstream_remote_addr.clone(),
                tls_sni: input.tls_sni.clone(),
                tls_upstream: input.tls_upstream.clone(),
                upstream_error_message: input.upstream_error_message.clone(),
            })
            .await?;

        Ok(response_commit)
    }

    fn dispatch_response_filters(
        &self,
        input: &ResponseDispatchInput,
        res_parts: &mut rama::http::response::Parts,
        res_body_bytes: &mut Bytes,
        elapsed_ms: i64,
    ) -> ResponseFilterDispatchOutput {
        let res_content_type = normalized_content_type(&res_parts.headers);

        let req_view = input.request_view();
        let res_filter_view = FilterResponseView {
            request: req_view,
            status: res_parts.status.as_u16(),
            content_type: res_content_type.as_deref(),
        };

        let filter_response = build_filter_response(
            res_parts,
            res_body_bytes,
            input.upstream_status,
            elapsed_ms,
        );

        let filter_flow = FilterFlow {
            id: input.id.to_string(),
            seq: input.seq,
            flow_key: input.flow_key.clone(),
            request: input.filter_request.clone(),
            response: Some(filter_response.clone()),
        };

        let response_action = self.filters.run_response_filters(
            &res_filter_view,
            &filter_flow,
            &filter_response,
        );

        let response_marks = flow_marks_from_response_action(&response_action);
        let outbound_http = response_action.outbound_http;
        let drop_client_response = response_action.drop_client_response;

        if let Some(patch) = response_action.response {
            apply_response_patch(res_parts, res_body_bytes, patch);
        }

        ResponseFilterDispatchOutput {
            marks: response_marks,
            outbound_http,
            drop_client_response,
        }
    }

    fn dispatch_outbound_http(&self, jobs: Vec<OutboundHttpJob>) {
        if jobs.is_empty() {
            return;
        }

        let Some(pool) = self.outbound_http_pool.as_ref() else {
            tracing::warn!(
                        count = jobs.len(),
                        "drop outbound http jobs: outbound http client pool is not configured"
                    );
            return;
        };

        for job in jobs {
            pool.try_enqueue(job);
        }
    }

    fn resolve_outbound_http_jobs(
        &self,
        jobs: Vec<OutboundHttpJob>,
        input: &ResponseDispatchInput,
        res_parts: &rama::http::response::Parts,
        res_body_bytes: &Bytes,
    ) -> Vec<OutboundHttpJob> {
        jobs
            .into_iter()
            .map(|job| self.resolve_outbound_http_job(job, input, res_parts, res_body_bytes))
            .collect()
    }

    fn resolve_outbound_http_job(
        &self,
        mut job: OutboundHttpJob,
        input: &ResponseDispatchInput,
        res_parts: &rama::http::response::Parts,
        res_body_bytes: &Bytes,
    ) -> OutboundHttpJob {
        job.body = match job.body {
            OutboundHttpBodySource::Bytes(bytes) => OutboundHttpBodySource::Bytes(bytes),
            OutboundHttpBodySource::CapturedRequest => {
                OutboundHttpBodySource::Bytes(raw_filter_request_bytes(&input.filter_request))
            }
            OutboundHttpBodySource::CapturedResponse => {
                OutboundHttpBodySource::Bytes(raw_response_bytes(res_parts, res_body_bytes))
            }
            OutboundHttpBodySource::CapturedRequestJson => {
                OutboundHttpBodySource::Bytes(json_filter_request_bytes(&input.filter_request))
            }
            OutboundHttpBodySource::CapturedResponseJson => {
                OutboundHttpBodySource::Bytes(json_filter_response_bytes(
                    res_parts,
                    res_body_bytes,
                    input.upstream_status,
                    input.started_at.elapsed().as_millis() as i64,
                ))
            }
            OutboundHttpBodySource::CapturedFlowJson => {
                OutboundHttpBodySource::Bytes(json_filter_flow_bytes(
                    input,
                    res_parts,
                    res_body_bytes,
                    input.started_at.elapsed().as_millis() as i64,
                ))
            }
        };

        job
    }

    fn dispatch_completed_filters(
        &self,
        input: &ResponseDispatchInput,
        res_parts: &rama::http::response::Parts,
        res_body_bytes: &Bytes,
        elapsed_ms: i64,
    ) {
        self.filters.run_completed_filters(
            &input.request_view(),
            &FilterFlow {
                id: input.id.to_string(),
                seq: input.seq,
                flow_key: input.flow_key.clone(),
                request: input.filter_request.clone(),
                response: Some(build_filter_response(
                    res_parts,
                    res_body_bytes,
                    input.upstream_status,
                    elapsed_ms,
                )),
            },
        );
    }
}

async fn collect_body(body: Body, label: &str) -> Bytes {
    match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            tracing::error!("failed to collect {label} body: {err}");
            Bytes::new()
        }
    }
}

struct SseCaptureBody {
    inner: Body,
    capture: SseCapture,
}

impl StreamingBody for SseCaptureBody {
    type Data = Bytes;
    type Error = OpaqueError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(bytes) = frame.data_ref() {
                    self.capture.push(bytes.as_ref());
                }

                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                self.capture.finish();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn is_sse_response(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
}

fn build_synthetic_response(
    version: Version,
    synthetic_response: FilterSyntheticResponse,
) -> Response {
    let mut builder = Response::builder()
        .status(synthetic_response.status)
        .version(version);

    for header in &synthetic_response.headers {
        builder = builder.header(header.name.as_str(), header.value.as_str());
    }

    builder
        .body(Body::from(Bytes::from(synthetic_response.body)))
        .unwrap_or_else(|err| {
            tracing::error!("failed to build synthetic response: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}

fn split_upstream_result(
    ctx: RequestDispatchContext,
    filter_request: FilterRequest,
    upstream_result: UpstreamFlowResult,
) -> (ResponseDispatchInput, Response) {
    let upstream_err = upstream_result.upstream_err;
    let upstream_status = upstream_result.upstream_status;
    let upstream_remote_addr = upstream_result.upstream_remote_addr;
    let tls_upstream = upstream_tls_info_from_extensions(upstream_result.response.extensions());

    let origin = if upstream_err.is_some() {
        ResponseOrigin::ProxyError
    } else {
        ResponseOrigin::Upstream
    };

    let input = ctx.into_response_input(
        filter_request,
        origin,
        upstream_status,
        upstream_remote_addr,
        tls_upstream,
        upstream_err,
    );

    (input, upstream_result.response)
}

fn raw_filter_request_bytes(req: &FilterRequest) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(
        format!("{} {} {}\r\n", req.method, request_target(req), req.version).as_bytes(),
    );

    if let Some(tls_sni) = req.tls_sni.as_deref() {
        out.extend_from_slice(format!("X-Inspect-TLS-SNI: {tls_sni}\r\n").as_bytes());
    }

    append_filter_headers(&mut out, &req.headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body.bytes);

    out
}

fn raw_response_bytes(
    res_parts: &rama::http::response::Parts,
    res_body_bytes: &Bytes,
) -> Vec<u8> {
    let mut out = build_response_head_text(
        res_parts.version,
        res_parts.status,
        &res_parts.headers,
    )
        .into_bytes();

    out.extend_from_slice(res_body_bytes);
    out
}

fn append_filter_headers(out: &mut Vec<u8>, headers: &[FilterHeader]) {
    for header in headers {
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
}

fn request_target(req: &FilterRequest) -> String {
    if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    }
}