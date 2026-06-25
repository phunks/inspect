
use rama::{
    error::{ErrorContext, OpaqueError}, extensions::{ExtensionsMut, ExtensionsRef},
    http::{
        layer::{
            compression::CompressionLayer,
            map_response_body::MapResponseBodyLayer,
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        }, matcher::MethodMatcher,
        server::HttpServer, service::web::response::IntoResponse,
        Body,
        Request,
        Response,
        StatusCode,
        Version,
    },
    layer::{AddInputExtensionLayer, ConsumeErrLayer},
    net::{
        http::RequestContext, proxy::ProxyTarget, stream::layer::http::BodyLimitLayer,
        tls::server::{ServerAuth, ServerConfig},
    },
    rt::Executor,
    service::service_fn,
    tcp::{server::TcpListener},
    telemetry::tracing,
    tls::boring::{
        client::EmulateTlsProfileLayer, client::ExtendedTlsParameters,
        server::{TlsAcceptorData, TlsAcceptorLayer},
    },
    ua::{
        layer::emulate::UserAgentEmulateLayer,
        profile::UserAgentDatabase,
    },
    Layer,
    Service,
};
use std::{convert::Infallible, io};
use std::fmt::{Debug, Formatter};
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use rama::net::address::{Host, HostWithPort, ProxyAddress};
use flate2::read;
use http::HeaderValue;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use uuid::Uuid;
use serde::Serialize;
use chrono::{DateTime, Utc};
use rama::extensions::{Extensions, InputExtensions};
use rama::http::ws::handshake::server::WebSocketMatcher;
use rama::matcher::Matcher;
use rama::net::tls::DataEncoding;
use rama::net::tls::server::SniRouter;
use rama::tls::boring::core::hash::MessageDigest;
use rama::tls::boring::core::x509::X509;
use tracing::{debug, info, info_span};
use tracing_futures::Instrument;
use tokio::sync::watch;
use crate::filters::{
    FilterBody,
    FilterFlow,
    FilterHeader,
    FilterManager,
    FilterRequest,
    FilterRequestPatch,
    FilterRequestView,
    FilterResponse,
    FilterResponsePatch,
    FilterResponseView,
    RequestAction,
    ResponseAction,
};
use crate::mitm::capture::CapturePaths;
use crate::mitm::store_metadata::{DbState, RequestMetadata, RequestResponseEvent, ResponseMetadata};
use crate::mitm::dynamic_ca::DynamicIssuer;
use crate::mitm::client::{new_upstream_client, UpstreamClient};
use crate::mitm::tls_sni::{ConnectSniRouterService, IngressSNI};
use crate::options::{ProxyMode, UaProfile};

const PROXY_BODY_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const WEBSOCKET_NOT_CAPTURED_MESSAGE: &str =
    "<WebSocket upgraded; payload is not captured by inspect. Use tcpdump + SSLKEYLOGFILE + Wireshark.>\n";

pub type AnyError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type AnyResult<T> = Result<T, AnyError>;

#[derive(Debug, Clone, Serialize)]
pub enum PacketEvent {
    Started(PacketStarted),
    Completed(PacketCompleted),
    Marked(PacketMarked),
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketStarted {
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
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketCompleted {
    pub id: String,
    pub status: u16,
    pub elapsed_ms: i64,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketMarked {
    pub id: String,
    pub flow_key: String,
    pub label: String,
    pub color: Option<String>,
}

#[derive(Clone)]
struct State {
    mitm_tls_service_data: TlsAcceptorData,
    upstream_proxy: Option<ProxyAddress>,
    exec: Executor,
    dbstate: DbState,
    capture_paths: CapturePaths,
    body_save_limit_bytes: Option<usize>,
    body_omit_content_types: Arc<[String]>,
    proxy_body_limit_bytes: Option<usize>,
    seq: Arc<AtomicU64>,
    tui_callback: Option<Arc<dyn Fn(PacketEvent) + Send + Sync>>,
    _ua_profile: UaProfile,
    proxy_mode: ProxyMode,
    ua_db: Arc<UserAgentDatabase>,
    upstream_client: UpstreamClient,
    filter_manager: FilterManager,
}

impl Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("mitm_tls_service_data", &"...")
            .field("upstream_proxy", &self.upstream_proxy)
            .field("exec", &self.exec)
            .field("dbstate", &self.dbstate)
            .field("filters_dir", &self.filter_manager.filters_dir())
            .field(
                "packet_callback",
                &self.tui_callback.as_ref().map(|_| "Fn(PacketEvent)"),
            )
            .finish()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn mitm_proxy_main(
    upstream_proxy: Option<String>,
    service_port: String,
    ua_profile: UaProfile,
    connect_ua_profile: Option<UaProfile>,
    proxy_mode: ProxyMode,
    upstream_handshake_timeout_ms: u64,
    upstream_request_timeout_sec: u64,
    body_save_limit_bytes: Option<usize>,
    body_omit_content_types: Vec<String>,
    filter_manager: FilterManager,
    packet_callback: Option<Arc<dyn Fn(PacketEvent) + Send + Sync>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> AnyResult<()> {
    let mitm_tls_service_data =
        new_mitm_tls_service_data().await.context("generate self-signed mitm tls cert")?;

    let upstream_client = new_upstream_client(
        proxy_mode,
        ua_profile,
        connect_ua_profile,
        Duration::from_millis(upstream_handshake_timeout_ms),
        Duration::from_secs(upstream_request_timeout_sec),
    );

    let upstream_proxy = match upstream_proxy {
        None => None,
        Some(a) => {
            let ip = a.split(":").next().unwrap();
            let port = a.split(":").last().unwrap();
            Some(ProxyAddress {
                address: HostWithPort { host: Host::from(IpAddr::from_str(ip)?), port: port.parse()? },
                credential: None,
                protocol: Some(rama::net::Protocol::HTTP),
            })
        }
    };
    let graceful = rama::graceful::Shutdown::default();

    let exec = Executor::graceful(graceful.guard());

    let state = State {
        mitm_tls_service_data,
        upstream_proxy,
        exec: exec.clone(),
        dbstate: DbState::new().await.expect("dbstate"),
        capture_paths: CapturePaths::new(),
        body_save_limit_bytes,
        body_omit_content_types: body_omit_content_types
            .into_iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .into(),
        proxy_body_limit_bytes: body_save_limit_bytes
            .map(|limit| limit.max(PROXY_BODY_LIMIT_BYTES)),
        seq: Arc::new(AtomicU64::new(0)),
        tui_callback: packet_callback,
        _ua_profile: ua_profile,
        proxy_mode,
        ua_db: Arc::new(UserAgentDatabase::try_embedded()?),
        upstream_client,
        filter_manager,
    };

    let dbstate = state.dbstate.clone();
    info!(
        ?proxy_mode,
        request_ua_profile = ?ua_profile,
        connect_ua_profile = ?connect_ua_profile,
        "Starting mitm proxy with upstream proxy"
    );
    let handle = graceful.spawn_task_fn(async move |guard| {
        info!("starting tcp proxy on {service_port}");
        let tcp_service = TcpListener::build()
            .bind(service_port)
            .await
            .expect("bind tcp proxy to {service_port}}");

        let http_mitm_service = new_http_mitm_proxy(&state);
        let http_service = HttpServer::auto(exec).service(
            (
                TraceLayer::new_for_http(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                // ProxyAuthLayer::new(Basic::new_static("john", "secret")),
                ConsumeErrLayer::default(),
                UpgradeLayer::new(
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    service_fn(http_connect_proxy),
                ),
            )
                .into_layer(http_mitm_service),
        );

        if let Some(proxy_body_limit_bytes) = state.proxy_body_limit_bytes {
            tcp_service
                .serve_graceful(
                    guard,
                    (
                        AddInputExtensionLayer::new(state),
                        // protect the http proxy from too large bodies,
                        // both from request and response end
                        BodyLimitLayer::symmetric(proxy_body_limit_bytes),
                    )
                        .into_layer(http_service),
                )
                .await;
        } else {
            tcp_service
                .serve_graceful(
                    guard,
                    AddInputExtensionLayer::new(state)
                        .into_layer(http_service),
                )
                .await;
        }
    });

    let _ = shutdown_rx.changed().await;
    dbstate.flush_sqlite_wal_on_exit().await?;
    handle.abort();
    Ok(())
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
        Ok(authority) => {
            info!(
                server.address = %authority.host,
                server.port = %authority.port,
                "accept CONNECT (lazy): insert proxy target into context",
            );
            req.extensions_mut().insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!("error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), req))
}

async fn http_connect_proxy(mut upgraded: Upgraded) -> Result<(), Infallible> {
    // In the past we deleted the request context here, as such:
    // ```
    // ctx.remove::<RequestContext>();
    // ```
    // This is however not correct, as the request context remains true.
    // The user proxies here with a target as aim. This target, incoming version
    // and so on does not change. This initial context remains true
    // and should be preserved. This is especially important,
    // as we otherwise might not be able to define the scheme/authority
    // for upstream http requests.
    // let state = upgraded.extensions().get::<State>().unwrap();
    let client_target = upgraded
        .extensions()
        .get::<ProxyTarget>()
        .map(|pt| pt.0.clone())
        .into_iter();

    let span = info_span!(
        "https_conn",
        // ?upstream,
        ?client_target,
    );

    async move {
        let state = upgraded.extensions().get::<State>().unwrap();
        let http_service = new_http_mitm_proxy(state);
        #[allow(clippy::single_match)]
        match upgraded
            .extensions()
            .get::<State>()
            .unwrap()
            .upstream_proxy.clone() {
            Some(a) => {
                upgraded.extensions_mut().insert(a);
            },
            None => {}
        };

        let executor = upgraded
            .extensions()
            .get::<Executor>()
            .cloned()
            .unwrap_or_default();
        let http_transport_service = HttpServer::auto(executor).service(http_service);

        let https_service = TlsAcceptorLayer::new(
            upgraded
                .extensions()
                .get::<State>()
                .unwrap()
                .mitm_tls_service_data
                .clone(),
        )
            .with_store_client_hello(true)
            .into_layer(http_transport_service);

        let sni_router = SniRouter::new(ConnectSniRouterService {
            https_service,
        });

        if let Err(err) = sni_router.serve(upgraded).await {
            tracing::error!("error serving HTTPS connection: {err:?}");
        }

        Ok(())
    }
        .instrument(span)
        .await
}

fn new_http_mitm_proxy(state: &State) -> impl Service<Request, Output = Response, Error = Infallible> {
    (
        MapResponseBodyLayer::new(Body::new),
        TraceLayer::new_for_http(),
        ConsumeErrLayer::default(),
        UserAgentEmulateLayer::new(state.ua_db.clone())
            .with_try_auto_detect_user_agent(state.proxy_mode == ProxyMode::Emulate)
            .with_is_optional(true),
        // RemoveResponseHeaderLayer::hop_by_hop(),
        // RemoveRequestHeaderLayer::hop_by_hop(),
        CompressionLayer::new(),
        AddRequiredRequestHeadersLayer::new(),
        EmulateTlsProfileLayer::new(),
    )
        .into_layer(service_fn(http_mitm_proxy))
}

fn decode_reader(header_value: &HeaderValue, bytes: &[u8]) -> io::Result<Bytes> {
    let mut buf = Vec::new();
    let enc = header_value
        .to_str()
        .unwrap_or_default()
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let res = match enc.as_str() {
        "gzip" => read::GzDecoder::new(bytes).read_to_end(&mut buf),
        "deflate" => read::DeflateDecoder::new(bytes).read_to_end(&mut buf),
        "br" => {
            let mut decoder = brotli::Decompressor::new(bytes, 4096);
            decoder.read_to_end(&mut buf)
        }
        "zstd" => {
            match zstd::stream::decode_all(bytes) {
                Ok(decoded) => {
                    buf = decoded;
                    Ok(buf.len())
                }
                Err(err) => Err(io::Error::new(io::ErrorKind::InvalidData, err)),
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported content-encoding: {enc}"),
        )),
    };

    match res {
        Ok(_) => Ok(Bytes::from(buf)),
        Err(e) => {
            tracing::warn!("decode error: {e}");
            Ok(Bytes::copy_from_slice(bytes))
        }
    }
}

fn body_for_storage(parts: &rama::http::response::Parts, res_body_bytes: &Bytes) -> Bytes {
    body_for_storage_by_headers(&parts.headers, res_body_bytes)
}

fn request_body_for_storage(parts: &rama::http::request::Parts, req_body_bytes: &Bytes) -> Bytes {
    body_for_storage_by_headers(&parts.headers, req_body_bytes)
}

fn body_for_storage_by_headers(headers: &http::HeaderMap, body_bytes: &Bytes) -> Bytes {
    if let Some(enc) = headers.get(http::header::CONTENT_ENCODING) {
        return decode_reader(enc, body_bytes).unwrap_or_else(|e| {
            tracing::warn!("failed to decode body for storage: {e}");
            body_bytes.clone()
        });
    }

    decode_body_by_magic_number(body_bytes).unwrap_or_else(|| body_bytes.clone())
}

fn decode_body_by_magic_number(body_bytes: &Bytes) -> Option<Bytes> {
    let bytes = body_bytes.as_ref();

    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut buf = Vec::new();

        match read::GzDecoder::new(bytes).read_to_end(&mut buf) {
            Ok(_) => return Some(Bytes::from(buf)),
            Err(e) => {
                tracing::warn!("failed to decode gzip body by magic number: {e}");
                return None;
            }
        }
    }

    None
}

async fn http_mitm_proxy (
    req: Request
) -> Result<Response, Infallible> {
    // This function will receive all requests going through this proxy,
    // be it sent via HTTP or HTTPS, both are equally visible. Hence... MITM

    let (mut parts, body) = req.into_parts();

    let state = parts.extensions().get::<State>().cloned().unwrap();

    if let Some(upstream_proxy) = state.upstream_proxy.clone() {
        parts.extensions_mut().insert(upstream_proxy);
    }

    let req = Request::from_parts(parts, body);

    if WebSocketMatcher::new().matches(None, &req) {
        return Ok(capture_websocket_handshake(state, req).await);
    }

    let (mut parts, body) = req.into_parts();

    let dbstate = state.dbstate.clone();
    let tui_callback = state.tui_callback.clone();
    let capture_paths = state.capture_paths.clone();
    let seq = state.seq.fetch_add(1, Ordering::Relaxed) + 1;

    let tls_sni = tls_sni_from_extensions(parts.extensions());

    let req_ctx = match RequestContext::try_from(&parts) {
        Ok(ctx) => ctx,
        Err(err) => {
            tracing::error!("error extracting request context: {err:?}");
            return Ok(StatusCode::BAD_REQUEST.into_response());
        }
    };

    let req_protocol = req_ctx.protocol.to_string();
    let req_host = req_ctx.authority.host.to_string();

    let id = Uuid::new_v4();
    let time = Utc::now();
    let uri = parts.uri.clone();

    let uuid_simple = id.simple().to_string();
    let uuid_prefix = &uuid_simple[..8];
    let flow_key = format!("{seq:06}-{uuid_prefix}");
    let flow_dir = capture_paths.flows_dir.join(&flow_key);

    if let Err(e) = tokio::fs::create_dir_all(&flow_dir).await {
        tracing::error!("failed to create flow dir {}: {e}", flow_dir.display());
    }

    let req_head_path = flow_dir.join("request.head");

    let res_head_path = flow_dir.join("response.head");
    let ssl_tls_path = flow_dir.join("ssl_tls.json");

    let req_method = parts.method.to_string().clone();

    if let Some(cb) = tui_callback.as_ref() {
        cb(PacketEvent::Started(PacketStarted {
            id: id.to_string(),
            seq,
            flow_key: flow_key.clone(),
            time: rfc3999z(&time),
            epoch_ms: time.timestamp_millis(),
            method: req_method.clone(),
            protocol: req_protocol.clone(),
            host: req_host.clone(),
            uri: uri.path().to_string(),
            query_str: uri.query().unwrap_or_default().into(),
            version: version_to_string(parts.version),
        }));
    }

    let mut req_body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!("failed to collect request body: {e}");
            Bytes::new()
        }
    };

    let req_filter_view = FilterRequestView {
        host: &req_host,
        path: uri.path(),
        method: parts.method.as_str(),
    };

    let filter_request = build_filter_request(
        &id,
        seq,
        &flow_key,
        &parts,
        &req_protocol,
        &req_host,
        &req_body_bytes,
        tls_sni.clone(),
    );

    let started_at = std::time::Instant::now();

    let request_action = run_request_filters(&state, &req_filter_view, &filter_request);

    let synthetic_response = request_action.synthetic_response;
    if let Some(patch) = request_action.request {
        let mut patched_parts = parts;
        apply_request_patch(&mut patched_parts, &mut req_body_bytes, patch);
        parts = patched_parts;
    }

    let req_body_path = flow_dir.join(body_file_name("request.body", &parts.headers));
    let req_head_text = build_request_head_text(&parts, tls_sni.as_deref());
    let _ = tokio::fs::write(&req_head_path, req_head_text).await;

    let req_omit_reason = body_omit_reason_by_content_type(
        &parts.headers,
        &state.body_omit_content_types,
    );

    let stored_req_body_bytes = if let Some(reason) = req_omit_reason.as_deref() {
        Bytes::from(format!("<body omitted by inspect: {reason}>\n"))
    } else if state.body_save_limit_bytes.is_none() {
        req_body_bytes.clone()
    } else {
        request_body_for_storage(&parts, &req_body_bytes)
    };

    let req_storage_info = if req_omit_reason.is_some() {
        BodyStorageInfo {
            saved_size: stored_req_body_bytes.len(),
            truncated: true,
        }
    } else {
        body_storage_info(stored_req_body_bytes.len(), state.body_save_limit_bytes)
    };

    let req_body_save_limit = if req_omit_reason.is_some() {
        Some(0)
    } else {
        state.body_save_limit_bytes.map(|limit| limit as i64)
    };

    let _ = write_body_for_storage(
        &req_body_path,
        &stored_req_body_bytes,
        if req_omit_reason.is_some() {
            None
        } else {
            state.body_save_limit_bytes
        },
    ).await;

    dbstate.event_sender.send(RequestResponseEvent::Request(RequestMetadata{
        id: id.to_string(),
        seq: seq as i64,
        flow_key: flow_key.clone(),
        flow_dir: flow_dir.to_string_lossy().to_string(),
        request_head_path: req_head_path.to_string_lossy().to_string(),
        request_body_path: req_body_path.to_string_lossy().to_string(),
        time: rfc3999z(&time),
        epoch_ms: time.timestamp_millis(),
        method: parts.method.as_str().into(),
        protocol: req_protocol.clone(),
        host: req_host.clone(),
        uri: parts.uri.path().to_string(),
        query_str: parts.uri.query().unwrap_or_default().into(),
        version: version_to_string(parts.version),
        tls_sni: tls_sni.clone(),
        headers: headers_to_json(&parts.headers),
        body_size: req_body_bytes.len() as i64,
        body_saved_size: req_storage_info.saved_size as i64,
        body_truncated: req_storage_info.truncated,
        body_save_limit: req_body_save_limit,
    })).unwrap_or_else(|e|
        tracing::error!("error sending request event: {e:?}"));

    if let Some(synthetic_response) = synthetic_response {
        return Ok(
            capture_synthetic_response(
                &state,
                &dbstate,
                tui_callback.clone(),
                &id,
                seq,
                &flow_key,
                &flow_dir,
                &res_head_path,
                &ssl_tls_path,
                started_at,
                parts.version,
                tls_sni.clone(),
                synthetic_response,
            )
                .await,
        );
    }

    let req = Request::from_parts(parts, Body::from(req_body_bytes));

    let upstream_result = state.upstream_client.serve(req).await;
    let res = upstream_result.response;
    let upstream_err = upstream_result.upstream_err;
    let upstream_status = upstream_result.upstream_status;
    let upstream_remote_addr = upstream_result.upstream_remote_addr;

    let elapsed_ms = started_at.elapsed().as_millis() as i64;

    let tls_upstream = upstream_tls_info_from_extensions(res.extensions());
    let ssl_tls_json = json!({
        "request": {
            "tls_sni": tls_sni,
        },
        "response": {
            "upstream_tls": tls_upstream,
        }
    });

    let ssl_tls_text = serde_json::to_string_pretty(&ssl_tls_json)
        .unwrap_or_else(|_| ssl_tls_json.to_string());

    let _ = tokio::fs::write(&ssl_tls_path, ssl_tls_text).await;

    let tls_upstream = upstream_tls_info_from_extensions(res.extensions());

    let (mut parts, body) = res.into_parts();

    let mut res_body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!("failed to collect response body: {e}");
            Bytes::new()
        }
    };

    let res_content_type = normalized_content_type(&parts.headers);

    let res_filter_view = FilterResponseView {
        request: FilterRequestView {
            host: &req_host,
            path: uri.path(),
            method: req_method.as_str(),
        },
        status: parts.status.as_u16(),
        content_type: res_content_type.as_deref(),
    };

    let filter_response = build_filter_response(
        &parts,
        &res_body_bytes,
        upstream_status,
        elapsed_ms,
    );

    let filter_flow = FilterFlow {
        id: id.to_string(),
        seq,
        flow_key: flow_key.clone(),
        request: filter_request.clone(),
        response: Some(filter_response.clone()),
    };

    let response_action = run_response_filters(
        &state,
        &res_filter_view,
        &filter_flow,
        &filter_response,
    );

    if let Some(patch) = response_action.response {
        apply_response_patch(&mut parts, &mut res_body_bytes, patch);
    }

    let res_head_text = build_response_head_text(&parts);
    let _ = tokio::fs::write(&res_head_path, res_head_text).await;

    let proxy_status = parts.status.as_u16();
    let res_body_path = flow_dir.join(body_file_name("response.body", &parts.headers));

    let body_size = res_body_bytes.len() as i64;
    let body_saved_size;
    let body_truncated;
    let body_save_limit;

    if let Some(msg) = upstream_err.as_deref() {
        let storage_info = body_storage_info(msg.len(), state.body_save_limit_bytes);
        body_saved_size = storage_info.saved_size as i64;
        body_truncated = storage_info.truncated;
        body_save_limit = state.body_save_limit_bytes.map(|limit| limit as i64);

        let _ = write_body_for_storage(
            &res_body_path,
            msg.as_bytes(),
            state.body_save_limit_bytes,
        ).await;
    } else {
        let res_omit_reason = body_omit_reason_by_content_type(
            &parts.headers,
            &state.body_omit_content_types,
        );

        let stored_body_bytes = if let Some(reason) = res_omit_reason.as_deref() {
            Bytes::from(format!("<body omitted by inspect: {reason}>\n"))
        } else if state.body_save_limit_bytes.is_none() {
            res_body_bytes.clone()
        } else {
            body_for_storage(&parts, &res_body_bytes)
        };

        let storage_info = if res_omit_reason.is_some() {
            BodyStorageInfo {
                saved_size: stored_body_bytes.len(),
                truncated: true,
            }
        } else {
            body_storage_info(stored_body_bytes.len(), state.body_save_limit_bytes)
        };

        body_saved_size = storage_info.saved_size as i64;
        body_truncated = storage_info.truncated;
        body_save_limit = if res_omit_reason.is_some() {
            Some(0)
        } else {
            state.body_save_limit_bytes.map(|limit| limit as i64)
        };

        let _ = write_body_for_storage(
            &res_body_path,
            &stored_body_bytes,
            if res_omit_reason.is_some() {
                None
            } else {
                state.body_save_limit_bytes
            },
        ).await;
    }

    dbstate.event_sender.send(RequestResponseEvent::Response(ResponseMetadata {
        id: id.to_string(),
        seq: seq as i64,
        flow_key: flow_key.clone(),
        flow_dir: flow_dir.to_string_lossy().to_string(),
        response_head_path: res_head_path.to_string_lossy().to_string(),
        response_body_path: res_body_path.to_string_lossy().to_string(),
        elapsed: elapsed_ms,
        status: proxy_status,
        upstream_status,
        version: version_to_string(parts.version),
        tls_upstream,
        upstream_remote_addr,
        headers: headers_to_json(&parts.headers),
        body_size,
        body_saved_size,
        body_truncated,
        body_save_limit,
    })).unwrap_or_else(|e| tracing::error!("error sending response event: {e:?}"));

    let completed_filter_response = build_filter_response(
        &parts,
        &res_body_bytes,
        upstream_status,
        elapsed_ms,
    );

    let completed_filter_flow = FilterFlow {
        id: id.to_string(),
        seq,
        flow_key: flow_key.clone(),
        request: filter_request,
        response: Some(completed_filter_response),
    };

    run_completed_filters(
        &state,
        &FilterRequestView {
            host: &req_host,
            path: uri.path(),
            method: req_method.as_str(),
        },
        &completed_filter_flow,
    );

    if let Some(cb) = tui_callback {
        let display_status = upstream_status.unwrap_or(proxy_status);
        cb(PacketEvent::Completed(PacketCompleted {
            id: id.to_string(),
            status: display_status,
            elapsed_ms,
            version: version_to_string(parts.version),
        }));
    }

    Ok(Response::from_parts(parts, Body::from(res_body_bytes)))
}

#[allow(clippy::too_many_arguments)]
async fn capture_synthetic_response(
    state: &State,
    dbstate: &DbState,
    tui_callback: Option<Arc<dyn Fn(PacketEvent) + Send + Sync>>,
    id: &Uuid,
    seq: u64,
    flow_key: &str,
    flow_dir: &std::path::Path,
    res_head_path: &std::path::Path,
    ssl_tls_path: &std::path::Path,
    started_at: std::time::Instant,
    version: Version,
    tls_sni: Option<String>,
    synthetic_response: crate::filters::FilterSyntheticResponse,
) -> Response {
    info!(
        id = %id,
        flow_key,
        status = synthetic_response.status,
        "return synthetic response from roto filter"
    );

    let elapsed_ms = started_at.elapsed().as_millis() as i64;

    let ssl_tls_json = json!({
        "request": {
            "tls_sni": tls_sni,
        },
        "response": {
            "upstream_tls": null,
            "synthetic": true,
        }
    });

    let ssl_tls_text = serde_json::to_string_pretty(&ssl_tls_json)
        .unwrap_or_else(|_| ssl_tls_json.to_string());

    let _ = tokio::fs::write(ssl_tls_path, ssl_tls_text).await;

    let mut builder = Response::builder()
        .status(synthetic_response.status)
        .version(version);

    for header in &synthetic_response.headers {
        builder = builder.header(header.name.as_str(), header.value.as_str());
    }

    let response = builder
        .body(Body::from(Bytes::from(synthetic_response.body.clone())))
        .unwrap_or_else(|err| {
            tracing::error!("failed to build synthetic response: {err}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        });

    let (parts, body) = response.into_parts();

    let res_head_text = build_response_head_text(&parts);
    let _ = tokio::fs::write(res_head_path, res_head_text).await;

    let res_body_path = flow_dir.join(body_file_name("response.body", &parts.headers));

    let res_body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            tracing::error!("failed to collect synthetic response body: {err}");
            Bytes::new()
        }
    };

    let body_size = res_body_bytes.len() as i64;

    let storage_info = body_storage_info(res_body_bytes.len(), state.body_save_limit_bytes);

    let _ = write_body_for_storage(
        &res_body_path,
        &res_body_bytes,
        state.body_save_limit_bytes,
    )
        .await;

    dbstate
        .event_sender
        .send(RequestResponseEvent::Response(ResponseMetadata {
            id: id.to_string(),
            seq: seq as i64,
            flow_key: flow_key.to_string(),
            flow_dir: flow_dir.to_string_lossy().to_string(),
            response_head_path: res_head_path.to_string_lossy().to_string(),
            response_body_path: res_body_path.to_string_lossy().to_string(),
            elapsed: elapsed_ms,
            status: parts.status.as_u16(),
            upstream_status: None,
            version: version_to_string(parts.version),
            tls_upstream: None,
            upstream_remote_addr: None,
            headers: headers_to_json(&parts.headers),
            body_size,
            body_saved_size: storage_info.saved_size as i64,
            body_truncated: storage_info.truncated,
            body_save_limit: state.body_save_limit_bytes.map(|limit| limit as i64),
        }))
        .unwrap_or_else(|err| {
            tracing::error!("error sending synthetic response event: {err:?}");
        });

    if let Some(cb) = tui_callback {
        cb(PacketEvent::Completed(PacketCompleted {
            id: id.to_string(),
            status: parts.status.as_u16(),
            elapsed_ms,
            version: version_to_string(parts.version),
        }));
    }

    Response::from_parts(parts, Body::from(res_body_bytes))
}

fn body_file_name(base: &str, headers: &http::HeaderMap) -> String {
    let Some(content_encoding) = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
    else {
        return base.to_string();
    };

    let suffixes = content_encoding
        .split(',')
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter_map(|encoding| match encoding.as_str() {
            "gzip" | "x-gzip" => Some("gz"),
            "br" => Some("br"),
            "zstd" => Some("zst"),
            "deflate" => Some("deflate"),
            "identity" => None,
            _ => None,
        })
        .collect::<Vec<_>>();

    if suffixes.is_empty() {
        base.to_string()
    } else {
        format!("{base}.{}", suffixes.join("."))
    }
}

fn body_omit_reason_by_content_type(
    headers: &http::HeaderMap,
    omit_content_types: &[String],
) -> Option<String> {
    let content_type = normalized_content_type(headers)?;

    omit_content_types
        .iter()
        .find(|pattern| content_type.starts_with(pattern.as_str()))
        .map(|pattern| {
            format!("content-type {content_type} matched omit rule {pattern}")
        })
}

fn normalized_content_type(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

async fn capture_websocket_handshake(state: State, req: Request) -> Response {
    let dbstate = state.dbstate.clone();
    let tui_callback = state.tui_callback.clone();
    let capture_paths = state.capture_paths.clone();
    let seq = state.seq.fetch_add(1, Ordering::Relaxed) + 1;

    let tls_sni = tls_sni_from_extensions(req.extensions());

    let req_ctx = match RequestContext::try_from(&req) {
        Ok(ctx) => ctx,
        Err(err) => {
            tracing::error!("error extracting websocket request context: {err:?}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let req_protocol = websocket_scheme_from_http_scheme(&req_ctx.protocol.to_string());
    let req_host = req_ctx.authority.host.to_string();

    let id = Uuid::new_v4();
    let time = Utc::now();
    let uri = req.uri().clone();

    let uuid_simple = id.simple().to_string();
    let uuid_prefix = &uuid_simple[..8];
    let flow_key = format!("{seq:06}-{uuid_prefix}");
    let flow_dir = capture_paths.flows_dir.join(&flow_key);

    if let Err(e) = tokio::fs::create_dir_all(&flow_dir).await {
        tracing::error!("failed to create websocket flow dir {}: {e}", flow_dir.display());
    }

    let req_head_path = flow_dir.join("request.head");
    let req_body_path = flow_dir.join("request.body");
    let res_head_path = flow_dir.join("response.head");
    let res_body_path = flow_dir.join("response.body");
    let ssl_tls_path = flow_dir.join("ssl_tls.json");

    let (parts, body) = req.into_parts();
    let req_method = parts.method.to_string();

    let req_head_text = build_request_head_text(&parts, tls_sni.as_deref());
    let _ = tokio::fs::write(&req_head_path, req_head_text).await;
    let _ = tokio::fs::write(&req_body_path, "<empty>\n").await;

    let ssl_tls_json = json!({
        "request": {
            "tls_sni": tls_sni.clone(),
        },
        "response": {
            "upstream_tls": null,
            "note": "websocket payload is not captured"
        }
    });

    let ssl_tls_text = serde_json::to_string_pretty(&ssl_tls_json)
        .unwrap_or_else(|_| ssl_tls_json.to_string());

    let _ = tokio::fs::write(&ssl_tls_path, ssl_tls_text).await;

    dbstate.event_sender.send(RequestResponseEvent::Request(RequestMetadata {
        id: id.to_string(),
        seq: seq as i64,
        flow_key: flow_key.clone(),
        flow_dir: flow_dir.to_string_lossy().to_string(),
        request_head_path: req_head_path.to_string_lossy().to_string(),
        request_body_path: req_body_path.to_string_lossy().to_string(),
        time: rfc3999z(&time),
        epoch_ms: time.timestamp_millis(),
        method: req_method,
        protocol: req_protocol.clone(),
        host: req_host.clone(),
        uri: uri.path().to_string(),
        query_str: uri.query().unwrap_or_default().into(),
        version: version_to_string(parts.version),
        tls_sni,
        headers: headers_to_json(&parts.headers),
        body_size: 0,
        body_saved_size: 0,
        body_truncated: false,
        body_save_limit: state.body_save_limit_bytes.map(|limit| limit as i64),
    })).unwrap_or_else(|e| {
        tracing::error!("error sending websocket request event: {e:?}");
    });

    if let Some(cb) = tui_callback.as_ref() {
        cb(PacketEvent::Started(PacketStarted {
            id: id.to_string(),
            seq,
            flow_key: flow_key.clone(),
            time: rfc3999z(&time),
            epoch_ms: time.timestamp_millis(),
            method: "WS".to_string(),
            protocol: req_protocol.clone(),
            host: req_host.clone(),
            uri: uri.path().to_string(),
            query_str: uri.query().unwrap_or_default().into(),
            version: version_to_string(parts.version),
        }));
    }

    let req = Request::from_parts(parts, body);
    let started_at = std::time::Instant::now();

    let res = state.upstream_client.serve_websocket(req).await;

    let elapsed_ms = started_at.elapsed().as_millis() as i64;
    let (parts, body) = res.into_parts();
    let proxy_status = parts.status.as_u16();

    let res_head_text = build_response_head_text(&parts);
    let _ = tokio::fs::write(&res_head_path, res_head_text).await;
    let _ = tokio::fs::write(&res_body_path, WEBSOCKET_NOT_CAPTURED_MESSAGE).await;

    dbstate.event_sender.send(RequestResponseEvent::Response(ResponseMetadata {
        id: id.to_string(),
        seq: seq as i64,
        flow_key: flow_key.clone(),
        flow_dir: flow_dir.to_string_lossy().to_string(),
        response_head_path: res_head_path.to_string_lossy().to_string(),
        response_body_path: res_body_path.to_string_lossy().to_string(),
        elapsed: elapsed_ms,
        status: proxy_status,
        upstream_status: Some(proxy_status),
        version: version_to_string(parts.version),
        tls_upstream: None,
        upstream_remote_addr: None,
        headers: headers_to_json(&parts.headers),
        body_size: 0,
        body_saved_size: WEBSOCKET_NOT_CAPTURED_MESSAGE.len() as i64,
        body_truncated: false,
        body_save_limit: state.body_save_limit_bytes.map(|limit| limit as i64),
    })).unwrap_or_else(|e| {
        tracing::error!("error sending websocket response event: {e:?}");
    });

    if let Some(cb) = tui_callback {
        cb(PacketEvent::Completed(PacketCompleted {
            id: id.to_string(),
            status: proxy_status,
            elapsed_ms,
            version: version_to_string(parts.version),
        }));
    }

    Response::from_parts(parts, body)
}

fn websocket_scheme_from_http_scheme(scheme: &str) -> String {
    match scheme {
        "https" => "wss".to_string(),
        "http" => "ws".to_string(),
        other => other.to_string(),
    }
}

async fn write_body_limited(
    path: &std::path::Path,
    bytes: &[u8],
    max_len: usize,
) -> std::io::Result<()> {
    let take_len = bytes.len().min(max_len);
    let mut out = Vec::with_capacity(take_len + 64);
    out.extend_from_slice(&bytes[..take_len]);

    if bytes.len() > max_len {
        out.extend_from_slice(format!(
            "\n<< mitm truncated: max_len={} bytes, total={} bytes >>",
            max_len, bytes.len()
        ).as_bytes());
    }

    tokio::fs::write(path, out).await
}

struct BodyStorageInfo {
    saved_size: usize,
    truncated: bool,
}

fn body_storage_info(body_len: usize, max_len: Option<usize>) -> BodyStorageInfo {
    match max_len {
        Some(max_len) => BodyStorageInfo {
            saved_size: body_len.min(max_len),
            truncated: body_len > max_len,
        },
        None => BodyStorageInfo {
            saved_size: body_len,
            truncated: false,
        },
    }
}

async fn write_body_for_storage(
    path: &std::path::Path,
    bytes: &[u8],
    max_len: Option<usize>,
) -> std::io::Result<()> {
    match max_len {
        Some(max_len) => write_body_limited(path, bytes, max_len).await,
        None => tokio::fs::write(path, bytes).await,
    }
}

fn rfc3999z(time: &DateTime<Utc>) -> String {
    time.to_rfc3339_opts(chrono::format::SecondsFormat::Millis, true)
}

fn version_to_string(v: Version) -> String {
    match v {
        Version::HTTP_09 => "HTTP/0.9".into(),
        Version::HTTP_10 => "HTTP/1.0".into(),
        Version::HTTP_11 => "HTTP/1.1".into(),
        Version::HTTP_2 => "HTTP/2".into(),
        Version::HTTP_3 => "HTTP/3".into(),
        other => format!("{other:?}"),
    }
}

fn tls_sni_from_extensions(extensions: &Extensions) -> Option<String> {
    extensions
        .get::<IngressSNI>()
        .map(|sni| sni.0.to_string())
}

fn upstream_tls_info_from_extensions(extensions: &Extensions) -> Option<Value> {
    let params = extensions
        .get::<ExtendedTlsParameters>()
        .or_else(|| {
            extensions
                .get::<InputExtensions>()
                .and_then(|input| input.0.get::<ExtendedTlsParameters>())
        })?;

    let negotiated = &params.negotiated;

    let certificates = match negotiated.peer_certificate_chain.as_ref() {
        Some(DataEncoding::DerStack(chain)) => chain
            .iter()
            .filter_map(|der| certificate_der_to_json(der).ok())
            .collect::<Vec<_>>(),
        Some(DataEncoding::Der(der)) => certificate_der_to_json(der)
            .ok()
            .into_iter()
            .collect::<Vec<_>>(),
        Some(DataEncoding::Pem(_)) | None => Vec::new(),
    };

    Some(json!({
        "secure_protocol": params
            .protocol_version
            .clone()
            .unwrap_or_else(|| format!("{:?}", negotiated.protocol_version)),
        "alpn": negotiated
            .application_layer_protocol
            .as_ref()
            .map(|proto| proto.to_string()),
        "cipher": params.cipher,
        "cipher_standard_name": params.cipher_standard_name,
        "cipher_description": params.cipher_description,
        "bits": params.bits,
        "algorithm_bits": params.algorithm_bits,
        "key_exchange_curve": params.curve_name,
        "client_random": hex_upper(&params.client_random),
        "server_random": hex_upper(&params.server_random),
        "certificate_chain": certificates,
    }))
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("")
}

pub fn certificate_der_to_json(der: &[u8]) -> anyhow::Result<Value> {
    let cert = X509::from_der(der)?;

    let subject = x509_name_to_string(cert.subject_name());
    let issuer = x509_name_to_string(cert.issuer_name());

    let serial_number = cert
        .serial_number()
        .to_bn()?
        .to_hex_str()?
        .to_string();

    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    let sha256 = cert.digest(MessageDigest::sha256())?;
    let thumbprint_sha256 = sha256
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("");

    let subject_alt_names = cert
        .subject_alt_names()
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.dnsname().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(json!({
        "subject": subject,
        "issuer": issuer,
        "serial_number": serial_number,
        "not_before": not_before,
        "not_after": not_after,
        "thumbprint_sha256": thumbprint_sha256,
        "subject_alt_names": subject_alt_names,
    }))
}

fn x509_name_to_string(name: &rama::tls::boring::core::x509::X509NameRef) -> String {
    name.entries()
        .map(|entry| {
            let key = entry
                .object()
                .nid()
                .short_name()
                .unwrap_or("UNKNOWN");

            let value = entry
                .data()
                .as_utf8()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| STANDARD.encode(entry.data().as_slice()));

            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn headers_to_json(headers: &http::HeaderMap) -> Value {
    let mut map = serde_json::Map::new();
    for (name, value) in headers {
        let key = name.as_str();
        let val = value
            .to_str()
            .map(|v| json!(v))
            .unwrap_or_else(|_| {
                json!(STANDARD.encode(value.as_bytes()))
            });

        match map.get_mut(key) {
            Some(existing) => {
                if let Some(arr) = existing.as_array_mut() {
                    arr.push(val);
                } else {
                    *existing = json!([existing, val]);
                }
            }
            None => {
                map.insert(key.to_string(), val);
            }
        }
    }
    Value::Object(map)
}

fn build_request_head_text(parts: &rama::http::request::Parts, tls_sni: Option<&str>) -> String {
    let mut out = String::new();

    if let Some(tls_sni) = tls_sni {
        out.push_str(&format!("X-Inspect-TLS-SNI: {tls_sni}\r\n"));
    }

    out.push_str(&format!(
        "{} {} {}\r\n",
        parts.method,
        parts.uri,
        version_to_string(parts.version)
    ));
    for (name, value) in &parts.headers {
        let v = value.to_str().unwrap_or("<binary>");
        out.push_str(&format!("{name}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out
}

fn build_response_head_text(parts: &rama::http::response::Parts) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} {}\r\n",
        version_to_string(parts.version),
        parts.status
    ));
    for (name, value) in &parts.headers {
        let v = value.to_str().unwrap_or("<binary>");
        out.push_str(&format!("{name}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out
}

// NOTE: for a production service you ideally use
// an issued TLS cert (if possible via ACME). Or at the very least
// load it in from memory/file, so that your clients can install the certificate for trust.
async fn new_mitm_tls_service_data() -> Result<TlsAcceptorData, OpaqueError> {
    let dynamic_issuer = DynamicIssuer::default();

    let tls_server_config = ServerConfig::new(
        ServerAuth::CertIssuer(rama::net::tls::server::ServerCertIssuerData {
            kind: dynamic_issuer.into(),
            cache_kind: rama::net::tls::server::CacheKind::Disabled,
    }));

    tls_server_config
        .try_into()
        .context("create tls server config")
}

fn filter_headers_from_header_map(headers: &http::HeaderMap) -> Vec<FilterHeader> {
    headers
        .iter()
        .map(|(name, value)| FilterHeader {
            name: name.as_str().to_string(),
            value: value
                .to_str()
                .map(str::to_string)
                .unwrap_or_else(|_| STANDARD.encode(value.as_bytes())),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn build_filter_request(
    id: &Uuid,
    seq: u64,
    flow_key: &str,
    parts: &rama::http::request::Parts,
    req_protocol: &str,
    req_host: &str,
    req_body_bytes: &Bytes,
    tls_sni: Option<String>,
) -> FilterRequest {
    FilterRequest {
        id: id.to_string(),
        seq,
        flow_key: flow_key.to_string(),
        method: parts.method.as_str().to_string(),
        scheme: req_protocol.to_string(),
        host: req_host.to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or_default().to_string(),
        version: version_to_string(parts.version),
        headers: filter_headers_from_header_map(&parts.headers),
        body: FilterBody {
            bytes: req_body_bytes.to_vec(),
            text: std::str::from_utf8(req_body_bytes)
                .ok()
                .map(str::to_string),
            content_type: normalized_content_type(&parts.headers),
            encoding: parts
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            truncated: false,
        },
        tls_sni,
    }
}

fn build_filter_response(
    parts: &rama::http::response::Parts,
    res_body_bytes: &Bytes,
    upstream_status: Option<u16>,
    elapsed_ms: i64,
) -> FilterResponse {
    FilterResponse {
        status: parts.status.as_u16(),
        version: version_to_string(parts.version),
        headers: filter_headers_from_header_map(&parts.headers),
        body: FilterBody {
            bytes: res_body_bytes.to_vec(),
            text: std::str::from_utf8(res_body_bytes)
                .ok()
                .map(str::to_string),
            content_type: normalized_content_type(&parts.headers),
            encoding: parts
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            truncated: false,
        },
        upstream_status,
        elapsed_ms: Some(elapsed_ms),
    }
}

fn run_request_filters(
    state: &State,
    req_view: &FilterRequestView<'_>,
    req: &FilterRequest,
) -> RequestAction {
    let filters = state.filter_manager.current();
    let mut matched = 0usize;
    let mut combined = RequestAction::pass();

    for filter in filters.matching_request(req_view) {
        matched += 1;

        info!(
            filter = filter.name(),
            priority = filter.priority,
            host = req_view.host,
            path = req_view.path,
            method = req_view.method,
            "matched request roto filter"
        );

        match filter.on_request(req) {
            Ok(action) => {
                debug!(
                    filter = filter.name(),
                    marks = action.marks.len(),
                    tags = action.tags.len(),
                    notes = action.notes.len(),
                    outbound_http = action.outbound_http.len(),
                    continue_filters = action.continue_filters,
                    synthetic_response = action.synthetic_response.is_some(),
                    request_patch = action.request.is_some(),
                    "request roto filter action"
                );

                emit_filter_marks(state, &req.id, &req.flow_key, &action.marks);
                emit_filter_tags(state, &req.id, &req.flow_key, &action.tags);
                emit_filter_notes(state, &req.id, &req.flow_key, &action.notes);

                merge_request_action(&mut combined, action);

                if !combined.continue_filters {
                    break;
                }
            }
            Err(err) => {
                tracing::warn!(
                    filter = filter.name(),
                    error = ?err,
                    "request roto filter failed"
                );
            }
        }
    }

    if matched == 0 {
        info!(
            loaded_filters = filters.len(),
            host = req_view.host,
            path = req_view.path,
            method = req_view.method,
            "no request roto filter matched"
        );
    }

    combined
}

fn merge_request_action(dst: &mut RequestAction, src: RequestAction) {
    if src.request.is_some() {
        dst.request = src.request;
    }

    if src.synthetic_response.is_some() {
        dst.synthetic_response = src.synthetic_response;
        dst.continue_filters = false;
    } else {
        dst.continue_filters = src.continue_filters;
    }

    dst.marks.extend(src.marks);
    dst.tags.extend(src.tags);
    dst.notes.extend(src.notes);
    dst.outbound_http.extend(src.outbound_http);
}

fn run_response_filters(
    state: &State,
    res_view: &FilterResponseView<'_>,
    flow: &FilterFlow,
    res: &FilterResponse,
) -> ResponseAction {
    let filters = state.filter_manager.current();
    let mut matched = 0usize;
    let mut combined = ResponseAction::pass();

    for filter in filters.matching_response(res_view) {
        matched += 1;

        info!(
            filter = filter.name(),
            priority = filter.priority,
            host = res_view.request.host,
            path = res_view.request.path,
            method = res_view.request.method,
            status = res_view.status,
            content_type = res_view.content_type,
            "matched response roto filter"
        );

        match filter.on_response(flow, res) {
            Ok(action) => {
                debug!(
                    filter = filter.name(),
                    marks = action.marks.len(),
                    tags = action.tags.len(),
                    notes = action.notes.len(),
                    outbound_http = action.outbound_http.len(),
                    continue_filters = action.continue_filters,
                    "response roto filter action"
                );

                emit_filter_marks(state, &flow.id, &flow.flow_key, &action.marks);
                emit_filter_tags(state, &flow.id, &flow.flow_key, &action.tags);
                emit_filter_notes(state, &flow.id, &flow.flow_key, &action.notes);

                merge_response_action(&mut combined, action);

                if !combined.continue_filters {
                    break;
                }
            }
            Err(err) => {
                tracing::warn!(
                    filter = filter.name(),
                    error = ?err,
                    "response roto filter failed"
                );
            }
        }
    }

    if matched == 0 {
        debug!(
            loaded_filters = filters.len(),
            host = res_view.request.host,
            path = res_view.request.path,
            method = res_view.request.method,
            status = res_view.status,
            content_type = res_view.content_type,
            "no response roto filter matched"
        );
    }

    combined
}

fn merge_response_action(dst: &mut ResponseAction, src: ResponseAction) {
    if src.response.is_some() {
        dst.response = src.response;
    }

    dst.marks.extend(src.marks);
    dst.tags.extend(src.tags);
    dst.notes.extend(src.notes);
    dst.outbound_http.extend(src.outbound_http);
    dst.continue_filters = src.continue_filters;
}

fn run_completed_filters(
    state: &State,
    req_view: &FilterRequestView<'_>,
    flow: &FilterFlow,
) {
    let filters = state.filter_manager.current();
    let mut matched = 0usize;

    for filter in filters.matching_completed(req_view) {
        matched += 1;

        info!(
            filter = filter.name(),
            priority = filter.priority,
            host = req_view.host,
            path = req_view.path,
            method = req_view.method,
            "matched completed roto filter"
        );

        match filter.on_completed(flow) {
            Ok(action) => {
                debug!(
                    filter = filter.name(),
                    marks = action.marks.len(),
                    tags = action.tags.len(),
                    notes = action.notes.len(),
                    outbound_http = action.outbound_http.len(),
                    continue_filters = action.continue_filters,
                    "completed roto filter action"
                );

                emit_filter_marks(state, &flow.id, &flow.flow_key, &action.marks);
                emit_filter_tags(state, &flow.id, &flow.flow_key, &action.tags);
                emit_filter_notes(state, &flow.id, &flow.flow_key, &action.notes);

                if !action.continue_filters {
                    break;
                }
            }
            Err(err) => {
                tracing::warn!(
                    filter = filter.name(),
                    error = ?err,
                    "completed roto filter failed"
                );
            }
        }
    }

    if matched == 0 {
        debug!(
            loaded_filters = filters.len(),
            host = req_view.host,
            path = req_view.path,
            method = req_view.method,
            "no completed roto filter matched"
        );
    }
}

fn emit_filter_marks(
    state: &State,
    id: &str,
    flow_key: &str,
    marks: &[crate::filters::FilterMark],
) {
    let Some(callback) = state.tui_callback.as_ref() else {
        return;
    };

    for mark in marks {
        callback(PacketEvent::Marked(PacketMarked {
            id: id.to_string(),
            flow_key: flow_key.to_string(),
            label: mark.label.clone(),
            color: mark.color.clone(),
        }));
    }
}

fn emit_filter_notes(
    state: &State,
    id: &str,
    flow_key: &str,
    notes: &[String],
) {
    let Some(callback) = state.tui_callback.as_ref() else {
        return;
    };

    for note in notes {
        callback(PacketEvent::Marked(PacketMarked {
            id: id.to_string(),
            flow_key: flow_key.to_string(),
            label: note.clone(),
            color: Some("blue".to_string()),
        }));
    }
}

fn emit_filter_tags(
    state: &State,
    id: &str,
    flow_key: &str,
    tags: &[String],
) {
    let Some(callback) = state.tui_callback.as_ref() else {
        return;
    };

    for tag in tags {
        callback(PacketEvent::Marked(PacketMarked {
            id: id.to_string(),
            flow_key: flow_key.to_string(),
            label: tag.clone(),
            color: Some("green".to_string()),
        }));
    }
}

fn apply_request_patch(
    parts: &mut rama::http::request::Parts,
    body: &mut Bytes,
    patch: FilterRequestPatch,
) {
    if let Some(method) = patch.method {
        match method.parse() {
            Ok(method) => {
                parts.method = method;
            }
            Err(err) => {
                tracing::warn!(
                    method,
                    error = ?err,
                    "ignored invalid request method from filter patch"
                );
            }
        }
    }

    if patch.path.is_some() || patch.query.is_some() {
        let current_path = parts.uri.path().to_string();
        let current_query = parts.uri.query().map(str::to_string);

        let next_path = patch.path.unwrap_or(current_path);
        let next_query = patch.query.or(current_query);

        let path_and_query = match next_query {
            Some(query) if !query.is_empty() => format!("{next_path}?{query}"),
            _ => next_path,
        };

        match path_and_query.parse() {
            Ok(path_and_query) => {
                let mut uri_parts = parts.uri.clone().into_parts();
                uri_parts.path_and_query = Some(path_and_query);

                match http::Uri::from_parts(uri_parts) {
                    Ok(uri) => {
                        parts.uri = uri;
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = ?err,
                            "ignored invalid request uri from filter patch"
                        );
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    path_and_query,
                    error = ?err,
                    "ignored invalid request path/query from filter patch"
                );
            }
        }
    }

    apply_header_patch(
        &mut parts.headers,
        patch.set_headers,
        patch.remove_headers,
    );

    if let Some(body_patch) = patch.body {
        *body = Bytes::from(body_patch.bytes);

        remove_body_integrity_headers(&mut parts.headers);

        if let Some(content_type) = body_patch.content_type {
            match HeaderValue::from_str(&content_type) {
                Ok(value) => {
                    parts.headers.insert(http::header::CONTENT_TYPE, value);
                }
                Err(err) => {
                    tracing::warn!(
                        content_type,
                        error = ?err,
                        "ignored invalid request content-type from filter patch"
                    );
                }
            }
        }
    }
}

fn apply_response_patch(
    parts: &mut rama::http::response::Parts,
    body: &mut Bytes,
    patch: FilterResponsePatch,
) {
    if let Some(status) = patch.status {
        match StatusCode::from_u16(status) {
            Ok(status) => {
                parts.status = status;
            }
            Err(err) => {
                tracing::warn!(
                    status,
                    error = ?err,
                    "ignored invalid response status from filter patch"
                );
            }
        }
    }

    apply_header_patch(
        &mut parts.headers,
        patch.set_headers,
        patch.remove_headers,
    );

    if let Some(body_patch) = patch.body {
        *body = Bytes::from(body_patch.bytes);

        remove_body_integrity_headers(&mut parts.headers);

        if let Some(content_type) = body_patch.content_type {
            match HeaderValue::from_str(&content_type) {
                Ok(value) => {
                    parts.headers.insert(http::header::CONTENT_TYPE, value);
                }
                Err(err) => {
                    tracing::warn!(
                        content_type,
                        error = ?err,
                        "ignored invalid response content-type from filter patch"
                    );
                }
            }
        }
    }
}

fn apply_header_patch(
    headers: &mut http::HeaderMap,
    set_headers: Vec<FilterHeader>,
    remove_headers: Vec<String>,
) {
    for name in remove_headers {
        match http::HeaderName::from_bytes(name.as_bytes()) {
            Ok(name) => {
                headers.remove(name);
            }
            Err(err) => {
                tracing::warn!(
                    header = name,
                    error = ?err,
                    "ignored invalid header name from filter remove patch"
                );
            }
        }
    }

    for header in set_headers {
        let name = match http::HeaderName::from_bytes(header.name.as_bytes()) {
            Ok(name) => name,
            Err(err) => {
                tracing::warn!(
                    header = header.name,
                    error = ?err,
                    "ignored invalid header name from filter set patch"
                );
                continue;
            }
        };

        let value = match HeaderValue::from_str(&header.value) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    header = header.name,
                    error = ?err,
                    "ignored invalid header value from filter set patch"
                );
                continue;
            }
        };

        headers.insert(name, value);
    }
}

fn remove_body_integrity_headers(headers: &mut http::HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::CONTENT_ENCODING);
    headers.remove(http::header::ETAG);
    headers.remove("content-md5");
}