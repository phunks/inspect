
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
use bytes::Bytes;
use rama::net::address::{Host, HostWithPort, ProxyAddress};
use flate2::read;
use http::HeaderValue;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use uuid::Uuid;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use chrono::{DateTime, Utc};
use rama::extensions::{Extensions, InputExtensions};
use rama::http::ws::handshake::server::WebSocketMatcher;
use rama::matcher::Matcher;
use rama::net::tls::DataEncoding;
use rama::net::tls::server::SniRouter;
use rama::tls::boring::core::hash::MessageDigest;
use rama::tls::boring::core::x509::X509;
use tracing::{info, info_span};
use tracing_futures::Instrument;
use tokio::sync::watch;
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


// #[derive(Debug, Clone, Serialize)]
// pub struct PacketSummary {
//     pub id: String,
//     pub flow_key: String,
//     pub time: String,
//     pub epoch_ms: i64,
//     pub method: String,
//     pub protocol: String,
//     pub host: String,
//     pub uri: String,
//     pub query_str: String,
//     pub status: u16,
//     pub version: String,
//     // pub elapsed:
// }

#[derive(Debug, Clone, Serialize)]
pub enum PacketEvent {
    Started(PacketStarted),
    Completed(PacketCompleted),
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

#[derive(Clone)]
struct State {
    mitm_tls_service_data: TlsAcceptorData,
    upstream_proxy: Option<ProxyAddress>,
    exec: Executor,
    dbstate: DbState,
    capture_paths: CapturePaths,
    body_save_limit_bytes: Option<usize>,
    proxy_body_limit_bytes: Option<usize>,
    seq: Arc<AtomicU64>,
    tui_callback: Option<Arc<dyn Fn(PacketEvent) + Send + Sync>>,
    _ua_profile: UaProfile,
    proxy_mode: ProxyMode,
    ua_db: Arc<UserAgentDatabase>,
    upstream_client: UpstreamClient,
}

impl Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("mitm_tls_service_data", &"...")
            .field("upstream_proxy", &self.upstream_proxy)
            .field("exec", &self.exec)
            .field("dbstate", &self.dbstate)
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
        proxy_body_limit_bytes: body_save_limit_bytes
            .map(|limit| limit.max(PROXY_BODY_LIMIT_BYTES)),
        seq: Arc::new(AtomicU64::new(0)),
        tui_callback: packet_callback,
        _ua_profile: ua_profile,
        proxy_mode,
        ua_db: Arc::new(UserAgentDatabase::try_embedded()?),
        upstream_client,
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

    let (parts, body) = req.into_parts();

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
    let req_body_path = flow_dir.join("request.body");
    let res_head_path = flow_dir.join("response.head");
    let res_body_path = flow_dir.join("response.body");
    let ssl_tls_path = flow_dir.join("ssl_tls.json");

    let req_head_text = build_request_head_text(&parts, tls_sni.as_deref());
    let _ = tokio::fs::write(&req_head_path, req_head_text).await;

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

    let req_body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!("failed to collect request body: {e}");
            Bytes::new()
        }
    };

    let stored_req_body_bytes = request_body_for_storage(&parts, &req_body_bytes);
    let req_storage_info =
        body_storage_info(stored_req_body_bytes.len(), state.body_save_limit_bytes);

    let _ = write_body_for_storage(
        &req_body_path,
        &stored_req_body_bytes,
        state.body_save_limit_bytes,
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
        uri: uri.path().to_string(),
        query_str: uri.query().unwrap_or_default().into(),
        version: version_to_string(parts.version),
        tls_sni: tls_sni.clone(),
        headers: headers_to_json(&parts.headers),
        body_size: req_body_bytes.len() as i64,
        body_saved_size: req_storage_info.saved_size as i64,
        body_truncated: req_storage_info.truncated,
        body_save_limit: state.body_save_limit_bytes.map(|limit| limit as i64),
    })).unwrap_or_else(|e|
        tracing::error!("error sending request event: {e:?}"));

    let req = Request::from_parts(parts, Body::from(req_body_bytes));

    let started_at = std::time::Instant::now();

    let (res, upstream_err, upstream_status): (Response, Option<String>, Option<u16>) =
        state.upstream_client.serve(req).await;

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

    let (parts, body) = res.into_parts();
    let proxy_status = parts.status.as_u16();

    let res_head_text = build_response_head_text(&parts);
    let _ = tokio::fs::write(&res_head_path, res_head_text).await;

    let res_body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!("failed to collect response body: {e}");
            Bytes::new()
        }
    };

    let body_size = res_body_bytes.len() as i64;
    let body_saved_size;
    let body_truncated;
    let body_save_limit = state.body_save_limit_bytes.map(|limit| limit as i64);

    if let Some(msg) = upstream_err.as_deref() {
        let storage_info = body_storage_info(msg.len(), state.body_save_limit_bytes);
        body_saved_size = storage_info.saved_size as i64;
        body_truncated = storage_info.truncated;

        let _ = write_body_for_storage(
            &res_body_path,
            msg.as_bytes(),
            state.body_save_limit_bytes,
        ).await;
    } else {
        let stored_body_bytes = body_for_storage(&parts, &res_body_bytes);
        let storage_info = body_storage_info(stored_body_bytes.len(), state.body_save_limit_bytes);
        body_saved_size = storage_info.saved_size as i64;
        body_truncated = storage_info.truncated;

        let _ = write_body_for_storage(
            &res_body_path,
            &stored_body_bytes,
            state.body_save_limit_bytes,
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
        headers: headers_to_json(&parts.headers),
        body_size,
        body_saved_size,
        body_truncated,
        body_save_limit,
    })).unwrap_or_else(|e| tracing::error!("error sending response event: {e:?}"));

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

