use crate::filters::FilterManager;
use crate::filters::http_client::OutboundHttpClientPool;
use crate::mitm::capture::CapturePaths;
use crate::mitm::client::{UpstreamClient, new_upstream_client};
use crate::mitm::dynamic_ca::DynamicIssuer;
use crate::mitm::flow::dispatcher::UpstreamFlowResult;
use crate::mitm::flow::state_store::FilterStateLimits;
use crate::mitm::flow::websocket::dispatch_websocket_handshake;
use crate::mitm::flow::{
    CaptureService, FlowDispatcher, FlowDispatcherConfig, FlowEvent, FlowEventPublisher,
    TunnelFailed, TunnelFailureCapture, UpstreamFlowClient, flow_marks_from_connect_action,
};
use crate::mitm::store_metadata::DbState;
use crate::mitm::tls_sni::ConnectSniRouterService;
use crate::options::{FilterStateConfig, ProxyMode, UaProfile};
use chrono::Utc;
use rama::http::ws::handshake::matcher::WebSocketMatcher;
use rama::matcher::Matcher;
use rama::net::address::{Host, HostWithPort, ProxyAddress};
use rama::tls::server::{SniRouter, TlsServerConfig};
use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::{Extension, ExtensionsRef},
    http::{
        Body, Request, Response, StatusCode,
        layer::{
            compression::CompressionLayer,
            map_response_body::MapResponseBodyLayer,
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::{AddInputExtensionLayer, ConsumeErrLayer},
    net::AuthorityInputExt,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::boring::{
        client::EmulateTlsProfileLayer,
        server::{BoringServerConfigExt, CacheKind, ServerCertIssuerData, TlsAcceptorLayer},
    },
    ua::{layer::emulate::UserAgentEmulateLayer, profile::UserAgentDatabase},
};
use serde::Serialize;
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, info_span};
use tracing_futures::Instrument;
use uuid::Uuid;

// const PROXY_BODY_LIMIT_BYTES: usize = 16 * 1024 * 1024;
// const WEBSOCKET_NOT_CAPTURED_MESSAGE: &str =
//     "<WebSocket upgraded; payload is not captured by inspect. Use tcpdump + SSLKEYLOGFILE + Wireshark.>\n";

pub type AnyError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type AnyResult<T> = Result<T, AnyError>;

#[derive(Debug, Clone, Serialize)]
pub enum PacketEvent {
    Started(PacketStarted),
    Completed(PacketCompleted),
    Marked(PacketMarked),
    TunnelFailed(PacketTunnelFailed),
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketEventMark {
    pub label: String,
    pub color: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketTunnelFailed {
    pub id: String,
    pub seq: u64,
    pub flow_key: String,
    pub time: String,
    pub epoch_ms: i64,
    pub host: String,
    pub port: u16,
    pub stage: String,
    pub error: String,
    pub marks: Vec<PacketEventMark>,
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

#[derive(Clone, Extension)]
struct State {
    mitm_tls_service_data: TlsServerConfig,
    _exec: Executor,
    flow_dispatcher: FlowDispatcher,
    proxy_mode: ProxyMode,
    ua_db: Arc<UserAgentDatabase>,
}

impl Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("mitm_tls_service_data", &"...")
            .field("proxy_mode", &self.proxy_mode)
            .finish()
    }
}

impl UpstreamFlowClient for UpstreamClient {
    fn serve(&self, req: Request) -> Pin<Box<dyn Future<Output = UpstreamFlowResult> + Send + '_>> {
        Box::pin(async move {
            let result = UpstreamClient::serve(self, req).await;

            UpstreamFlowResult {
                response: result.response,
                upstream_err: result.upstream_err,
                upstream_status: result.upstream_status,
                upstream_remote_addr: result.upstream_remote_addr,
            }
        })
    }

    fn serve_websocket(&self, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { UpstreamClient::serve_websocket(self, req).await })
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn mitm_proxy_main(
    upstream_proxy: Option<String>,
    upstream_no_proxy: Vec<String>,
    service_port: String,
    ua_profile: UaProfile,
    connect_ua_profile: Option<UaProfile>,
    connect_ua: Option<String>,
    proxy_mode: ProxyMode,
    upstream_handshake_timeout_ms: u64,
    upstream_request_timeout_sec: u64,
    body_save_limit_bytes: Option<usize>,
    body_omit_content_types: Vec<String>,
    stream_body_threshold_bytes: usize,
    sse_capture_max_events: usize,
    sse_capture_max_event_bytes: usize,
    outbound_http_pool: Option<OutboundHttpClientPool>,
    filter_manager: FilterManager,
    flow_events: FlowEventPublisher,
    filter_state: FilterStateConfig,
    store_dbstate: DbState,
    capture_paths: CapturePaths,
    mut shutdown_rx: watch::Receiver<bool>,
) -> AnyResult<()> {
    let mitm_tls_service_data =
        new_mitm_tls_service_data().context("generate self-signed mitm tls cert")?;

    info!(
        ?proxy_mode,
        connect_ua_profile = ?connect_ua_profile,
        connect_ua = ?connect_ua,
        "Starting mitm proxy with upstream proxy"
    );

    let upstream_client = new_upstream_client(
        proxy_mode,
        ua_profile,
        connect_ua_profile,
        connect_ua,
        Duration::from_millis(upstream_handshake_timeout_ms),
        Duration::from_secs(upstream_request_timeout_sec),
    );

    let upstream_proxy = match upstream_proxy {
        None => None,
        Some(a) => {
            let ip = a.split(":").next().unwrap();
            let port = a.split(":").last().unwrap();
            Some(ProxyAddress {
                address: HostWithPort {
                    host: Host::from(IpAddr::from_str(ip)?),
                    port: port.parse()?,
                },
                credential: None,
                protocol: Some(rama::net::Protocol::HTTP),
            })
        }
    };
    let graceful = rama::graceful::Shutdown::default();

    let exec = Executor::graceful(graceful.guard());

    let capture = CaptureService::new(
        store_dbstate.clone(),
        capture_paths,
        body_save_limit_bytes,
        body_omit_content_types.clone(),
    );

    let body_omit_content_types: Arc<[String]> = body_omit_content_types
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .into();

    // let proxy_body_limit_bytes = body_save_limit_bytes
    //     .map(|limit| limit.max(PROXY_BODY_LIMIT_BYTES));

    let seq = Arc::new(AtomicU64::new(0));

    let flow_dispatcher = FlowDispatcher::new(
        capture.clone(),
        filter_manager.clone(),
        flow_events.clone(),
        Arc::new(upstream_client.clone()),
        seq.clone(),
        outbound_http_pool,
        FlowDispatcherConfig {
            upstream_proxy: upstream_proxy.clone(),
            upstream_no_proxy: upstream_no_proxy.into(),
            body_save_limit_bytes,
            body_omit_content_types: body_omit_content_types.clone(),
            stream_body_threshold_bytes,
            sse_capture_max_events,
            sse_capture_max_event_bytes,
            filter_state_enabled: filter_state.enabled,
            filter_state_limits: FilterStateLimits {
                ttl: Duration::from_secs(filter_state.ttl_sec),
                max_entry_bytes: filter_state.max_entry_bytes,
                max_connection_bytes: filter_state.max_connection_bytes,
                max_filter_bytes: filter_state.max_filter_bytes,
                max_total_bytes: filter_state.max_total_bytes,
            },
        },
    );

    let state = State {
        mitm_tls_service_data,
        _exec: exec.clone(),
        flow_dispatcher,
        proxy_mode,
        ua_db: Arc::new(UserAgentDatabase::try_embedded()?),
    };

    let dbstate = store_dbstate.clone();

    let handle = graceful.spawn_task_fn(async move |_guard| {
        info!("starting tcp proxy on {service_port}");
        let tcp_service = TcpListener::build(exec.clone())
            .bind_address(service_port)
            .await
            .expect("bind tcp proxy to {service_port}}");

        let http_mitm_service = new_http_mitm_proxy(&state);
        let http_service = HttpServer::auto(exec.clone()).service(
            (
                TraceLayer::new_for_http(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                // ProxyAuthLayer::new(Basic::new_static("john", "secret")),
                ConsumeErrLayer::default(),
                UpgradeLayer::new_with_services(
                    exec.clone(),
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    service_fn(http_connect_proxy),
                ),
            )
                .into_layer(http_mitm_service),
        );

        tcp_service
            .serve(AddInputExtensionLayer::new(state).into_layer(http_service))
            .await;
    });

    let _ = shutdown_rx.changed().await;
    dbstate.flush_sqlite_wal_on_exit().await?;
    handle.abort();
    Ok(())
}

async fn http_connect_accept(
    req: Request,
) -> Result<rama::http::layer::upgrade::UpgradeResponse<Request, Response>, Response> {
    let authority = match req.authority() {
        Some(authority) => {
            HostWithPort::new(authority.host.clone(), authority.port_u16().unwrap_or(443))
        }
        None => {
            tracing::error!("error extracting CONNECT authority");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    };

    if let Some(state) = req.extensions().get_ref::<State>().cloned() {
        let connect = state
            .flow_dispatcher
            .dispatch_connect_filters(authority.host.to_string(), authority.port);

        if connect.action.drop_tunnel {
            let status = connect
                .action
                .reject_status
                .and_then(|status| StatusCode::from_u16(status).ok());

            let now = Utc::now();
            let id = Uuid::new_v4().to_string();
            let seq = state.flow_dispatcher.seq().fetch_add(1, Ordering::Relaxed) + 1;
            let flow_key = format!("{seq:06}-{}", &id[..8]);

            let marks = flow_marks_from_connect_action(&connect.action);
            let stage = "Roto connect_action".to_string();
            let error = match status {
                Some(status) => format!("CONNECT denied by Roto with status {}", status.as_u16()),
                None => "CONNECT dropped by Roto".to_string(),
            };

            state
                .flow_dispatcher
                .events()
                .publish(FlowEvent::TunnelFailed(TunnelFailed {
                    id,
                    seq,
                    flow_key,
                    time: now.to_rfc3339(),
                    epoch_ms: now.timestamp_millis(),
                    host: connect.host,
                    port: connect.port,
                    stage,
                    error,
                    marks,
                }));

            info!(
                server.address = %authority.host,
                server.port = %authority.port,
                reject_status = ?status,
                marks = connect.action.marks.len(),
                "CONNECT tunnel blocked by roto connect_action before upstream"
            );

            if let Some(status) = status {
                return Err(Response::builder()
                    .status(status)
                    .header("connection", "close")
                    .body(Body::empty())
                    .unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response()));
            }

            return Err(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("connection", "close")
                .body(Body::empty())
                .unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response()));
        }
    }

    info!(
        server.address = %authority.host,
        server.port = %authority.port,
        "accept CONNECT (lazy): insert proxy target into context",
    );

    let state = req
        .extensions()
        .get_ref::<State>()
        .cloned()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;
    let executor = crate::mitm::websocket::ConnectionExecutor(state._exec.clone());
    // 0.4 deliberately does not copy request extensions onto upgraded transport.
    Ok(
        rama::http::layer::upgrade::UpgradeResponse::new(req, StatusCode::OK.into_response())
            .with_extension(ProxyTarget(authority))
            .with_extension(state)
            .with_extension(executor),
    )
}

async fn http_connect_proxy(upgraded: Upgraded) -> Result<(), Infallible> {
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
    // let state = upgraded.extensions().get_ref::<State>().unwrap();
    let client_target = upgraded
        .extensions()
        .get_ref::<ProxyTarget>()
        .map(|pt| pt.0.clone());

    let span = info_span!("https_conn", ?client_target,);

    async move {
        let state = upgraded.extensions().get_ref::<State>().cloned().unwrap();

        let http_service = new_http_mitm_proxy(&state);

        if let Some(target) = client_target.as_ref()
            && let Some(upstream_proxy) = state
                .flow_dispatcher
                .upstream_proxy_for_host(&target.host.to_string(), Some(target.port))
        {
            upgraded
                .extensions()
                .insert(rama::net::client::ProxyRoutes::from(upstream_proxy));
        }

        let http_transport_server = new_https_http_server(state._exec.clone());
        let http_transport_service = http_transport_server.service(http_service);

        let https_service = TlsAcceptorLayer::new(
            upgraded
                .extensions()
                .get_ref::<State>()
                .unwrap()
                .mitm_tls_service_data
                .clone(),
        )
        .with_store_client_hello(true)
        .into_layer(http_transport_service);

        let sni_router = SniRouter::new(ConnectSniRouterService { https_service });

        if let Err(err) = sni_router.serve(upgraded).await {
            let error = format!("{err:#}");

            tracing::error!(
                error = %error,
                "error serving HTTPS connection"
            );

            if let Some(target) = client_target.as_ref() {
                let now = Utc::now();
                let id = Uuid::new_v4().to_string();
                let seq = state.flow_dispatcher.seq().fetch_add(1, Ordering::Relaxed) + 1;
                let flow_key = format!("{seq:06}-{}", &id[..8]);
                let flow_dir = state
                    .flow_dispatcher
                    .capture()
                    .paths()
                    .flows_dir
                    .join(&flow_key);

                let capture = TunnelFailureCapture {
                    id: id.clone(),
                    seq,
                    flow_key: flow_key.clone(),
                    flow_dir,
                    time: now,
                    host: target.host.to_string(),
                    port: target.port,
                    stage: "TLS accept / handshake".to_string(),
                    error: error.clone(),
                };

                if let Err(err) = state
                    .flow_dispatcher
                    .capture()
                    .commit_tunnel_failure(capture)
                    .await
                {
                    tracing::error!(
                        error = ?err,
                        flow_key = %flow_key,
                        "failed to persist TLS tunnel failure"
                    );
                }

                state
                    .flow_dispatcher
                    .events()
                    .publish(FlowEvent::TunnelFailed(TunnelFailed {
                        id,
                        seq,
                        flow_key,
                        time: now.to_rfc3339(),
                        epoch_ms: now.timestamp_millis(),
                        host: target.host.to_string(),
                        port: target.port,
                        stage: "TLS accept / handshake".to_string(),
                        error,
                        marks: Vec::new(),
                    }));
            }
        }

        Ok(())
    }
    .instrument(span)
    .await
}

fn new_http_mitm_proxy(
    state: &State,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    Arc::new(
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
            .into_layer(service_fn(http_mitm_proxy)),
    )
}

async fn http_mitm_proxy(mut req: Request) -> Result<Response, Infallible> {
    let state = req.extensions().get_ref::<State>().cloned().unwrap();
    normalize_https_request_uri(&mut req);

    if WebSocketMatcher::new().matches(None, &req) {
        return Ok(dispatch_websocket_handshake(&state.flow_dispatcher, req).await);
    }

    state.flow_dispatcher.dispatch(req).await
}

const HTTPS_MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;

fn new_https_http_server(
    executor: Executor,
) -> HttpServer<rama::http::core::server::conn::auto::Builder> {
    let mut server = HttpServer::auto(executor);
    server
        .http1_mut()
        .set_header_read_timeout(Duration::from_secs(60));
    // Browser API requests can exceed Rama's default 16 KiB with cookies and
    // authentication headers. Keep a finite limit, but allow these requests to
    // reach the dispatcher/capture instead of receiving an automatic 431.
    server
        .h2_mut()
        .set_max_header_list_size(HTTPS_MAX_HEADER_LIST_SIZE);
    server
}

fn normalize_https_request_uri(req: &mut Request) {
    // SNI contains no port. Preserve the CONNECT target's non-default port
    // when Rama resolves an origin-form URI through TLS context.
    if req.uri().port_u16().is_none()
        && let Some(target) = req.extensions().get_ref::<ProxyTarget>().cloned()
    {
        req.uri_mut()
            .set_scheme(rama::net::Protocol::HTTPS)
            .set_host(target.0.host)
            .set_port(target.0.port);
    }

    // Keep the effective HTTPS destination, but do not emit its default port
    // in HTTP/2 :authority (or in the captured absolute URI).
    if req.uri().scheme() == Some(&rama::net::Protocol::HTTPS) && req.uri().port_u16() == Some(443)
    {
        req.uri_mut().unset_port();
    }
}

// NOTE: for a production service you ideally use
// an issued TLS cert (if possible via ACME). Or at the very least
// load it in from memory/file, so that your clients can install the certificate for trust.
fn new_mitm_tls_service_data() -> Result<TlsServerConfig, BoxError> {
    let dynamic_issuer = DynamicIssuer::default();

    Ok(TlsServerConfig::new()
        .with_alpn_http_auto()
        .with_keylog(rama::tls::KeyLogIntent::Environment)
        .with_cert_issuer(
            ServerCertIssuerData::new(dynamic_issuer).with_cache_kind(CacheKind::Disabled),
        ))
}

#[derive(Debug, Clone, Extension)]
struct ProxyTarget(HostWithPort);

#[cfg(test)]
mod tests {
    use super::*;
    use rama::tls::client::{ServerVerifyMode, TlsClientConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn https_http2_header_limit() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        use rama::http::{BodyExtractExt, Version};

                        // The default server reproduces the pre-dispatch 431;
                        // the production builder accepts 32 KiB, but not 80 KiB.
                        for (configured, size, expected) in [
                            (
                                false,
                                32 * 1024,
                                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                            ),
                            (true, 32 * 1024, StatusCode::OK),
                            (true, 80 * 1024, StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE),
                        ] {
                            let listener =
                                TcpListener::bind_address("127.0.0.1:0", Executor::default())
                                    .await
                                    .unwrap();
                            let address = listener.local_addr().unwrap();
                            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
                            let builder = if configured {
                                new_https_http_server(Executor::default())
                            } else {
                                HttpServer::auto(Executor::default())
                            };
                            let server = TlsAcceptorLayer::new(
                                TlsServerConfig::generated_http_auto().unwrap(),
                            )
                            .into_layer(builder.service(service_fn(move |req: Request| {
                                let tx = tx.clone();
                                async move {
                                    assert_eq!(req.version(), Version::HTTP_2);
                                    tx.send(req.headers()["cookie"].as_bytes().len())
                                        .await
                                        .unwrap();
                                    Ok::<_, Infallible>(Response::new(rama::http::Body::from("ok")))
                                }
                            })));
                            let task = tokio::spawn(listener.serve(server));
                            let client = new_upstream_client(
                                ProxyMode::Observe,
                                UaProfile::Auto,
                                None,
                                None,
                                Duration::from_secs(5),
                                Duration::from_secs(5),
                            );
                            let request = Request::builder()
                                .uri(format!("https://localhost:{}/probe", address.port()))
                                .version(Version::HTTP_2)
                                .header("cookie", format!("session={}", "a".repeat(size)))
                                .body(rama::http::Body::empty())
                                .unwrap();
                            request
                                .extensions()
                                .insert(rama::net::http::TargetHttpVersion(Version::HTTP_2));
                            let result = tokio::time::timeout(
                                Duration::from_secs(10),
                                Box::pin(client.serve(request)),
                            )
                            .await
                            .unwrap();
                            assert!(result.upstream_err.is_none(), "{:?}", result.upstream_err);
                            assert_eq!(result.response.version(), Version::HTTP_2);
                            assert_eq!(result.response.status(), expected);
                            let body = result.response.into_body().try_into_string().await.unwrap();
                            if expected == StatusCode::OK {
                                assert_eq!(body, "ok");
                                assert_eq!(rx.recv().await.unwrap(), size + "session=".len());
                            } else {
                                assert!(rx.try_recv().is_err(), "rejected request reached handler");
                            }
                            task.abort();
                        }
                    });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn https_uri_omits_default_port_in_http2_authority() {
        for (input, target, expected_uri, expected_authority) in [
            (
                "/asset.css?v=1",
                Some("chatgpt.com:443"),
                "https://chatgpt.com/asset.css?v=1",
                "chatgpt.com",
            ),
            (
                "https://chatgpt.com:443/asset.css?v=1",
                Some("chatgpt.com:443"),
                "https://chatgpt.com/asset.css?v=1",
                "chatgpt.com",
            ),
            (
                "https://chatgpt.com/",
                Some("chatgpt.com:443"),
                "https://chatgpt.com/",
                "chatgpt.com",
            ),
            (
                "/probe",
                Some("localhost:8443"),
                "https://localhost:8443/probe",
                "localhost:8443",
            ),
            (
                "https://localhost:9443/probe",
                Some("localhost:8443"),
                "https://localhost:9443/probe",
                "localhost:9443",
            ),
            (
                "https://[::1]:443/probe",
                None,
                "https://[::1]/probe",
                "[::1]",
            ),
            (
                "http://example.com:443/probe",
                None,
                "http://example.com:443/probe",
                "example.com:443",
            ),
        ] {
            let mut req = Request::builder().uri(input).body(Body::empty()).unwrap();
            if let Some(target) = target {
                req.extensions()
                    .insert(ProxyTarget(target.parse().unwrap()));
            }
            normalize_https_request_uri(&mut req);
            assert_eq!(req.uri().to_string(), expected_uri);
            let mut authority = bytes::BytesMut::new();
            req.uri().write_h2_authority(&mut authority).unwrap();
            assert_eq!(authority.as_ref(), expected_authority.as_bytes());
        }
    }

    #[test]
    fn connect_mitm_preserves_state_and_captures_upstream_tls() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(connect_roundtrip());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn connect_roundtrip() {
        let origin_listener = TcpListener::bind_address("127.0.0.1:0", Executor::default())
            .await
            .unwrap();
        let origin_address = origin_listener.local_addr().unwrap();
        let origin = TlsAcceptorLayer::new(TlsServerConfig::generated_http_auto().unwrap())
            .into_layer(HttpServer::auto(Executor::default()).service(service_fn(
                async |_: Request| Ok::<_, Infallible>(Response::new(Body::from("mitm-ok"))),
            )));
        let origin_task = tokio::spawn(origin_listener.serve(origin));

        let root = std::env::temp_dir().join(format!("inspect-rama04-{}", Uuid::new_v4()));
        let paths = CapturePaths {
            db_path: root.join("index.sqlite"),
            flows_dir: root.join("flows"),
            filters_dir: root.join("filters"),
            generated_filters_dir: root.join("filters/generated"),
            quarantine_filters_dir: root.join("filters/quarantine"),
            root: root.clone(),
        };
        std::fs::create_dir_all(&paths.flows_dir).unwrap();
        std::fs::create_dir_all(&paths.filters_dir).unwrap();
        let db = DbState::new_for_paths(&paths).await.unwrap();
        let capture = CaptureService::new(db.clone(), paths.clone(), None, Vec::new());
        let (events, _receiver) = FlowEventPublisher::channel(32);
        let client = new_upstream_client(
            ProxyMode::Observe,
            UaProfile::Auto,
            None,
            None,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let dispatcher = FlowDispatcher::new(
            capture,
            FilterManager::new(&paths.filters_dir),
            events,
            Arc::new(client),
            Arc::new(AtomicU64::new(0)),
            None,
            FlowDispatcherConfig {
                upstream_proxy: None,
                upstream_no_proxy: Arc::from([]),
                body_save_limit_bytes: None,
                body_omit_content_types: Arc::from([]),
                stream_body_threshold_bytes: usize::MAX,
                sse_capture_max_events: 10,
                sse_capture_max_event_bytes: 1024,
                filter_state_enabled: false,
                filter_state_limits: FilterStateLimits::default(),
            },
        );
        let state = State {
            mitm_tls_service_data: TlsServerConfig::new().with_alpn_http_1().with_cert_issuer(
                ServerCertIssuerData::new(DynamicIssuer::ephemeral())
                    .with_cache_kind(CacheKind::Disabled),
            ),
            _exec: Executor::default(),
            flow_dispatcher: dispatcher,
            proxy_mode: ProxyMode::Observe,
            ua_db: Arc::new(UserAgentDatabase::try_embedded().unwrap()),
        };
        let listener = TcpListener::bind_address("127.0.0.1:0", Executor::default())
            .await
            .unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let service = HttpServer::auto(Executor::default()).service(
            (
                ConsumeErrLayer::default(),
                UpgradeLayer::new_with_services(
                    Executor::default(),
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    service_fn(http_connect_proxy),
                ),
            )
                .into_layer(new_http_mitm_proxy(&state)),
        );
        let proxy_task =
            tokio::spawn(listener.serve(AddInputExtensionLayer::new(state).into_layer(service)));

        let mut stream = tokio::net::TcpStream::connect(proxy_address).await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
                    origin_address.port(),
                    origin_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(
                tokio::time::timeout(Duration::from_secs(10), stream.read_u8())
                    .await
                    .unwrap()
                    .unwrap(),
            );
            assert!(head.len() < 8192);
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
        let config = TlsClientConfig::default_http()
            .with_alpn_http_1()
            .with_server_verify(ServerVerifyMode::Disable);
        let mut tls = rama::tls::boring::client::TlsConnectorData::try_from(&config).unwrap();
        // Low-level TLS needs an explicit peer identity for SNI.
        tls.server_name = Some(Host::from_static("localhost"));
        let mut stream =
            rama::tls::boring::client::tls_connect(rama::ServiceInput::new(stream), Some(tls))
                .await
                .unwrap();
        stream
            .write_all(
                format!(
                    "GET /probe HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
                    origin_address.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&response).contains("mitm-ok"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        let mut found = false;
        for entry in std::fs::read_dir(&paths.flows_dir).unwrap() {
            let path = entry.unwrap().path().join("ssl_tls.json");
            if let Ok(text) = std::fs::read_to_string(path) {
                assert!(text.contains("client_random"), "{text}");
                assert!(text.contains("certificate_chain"), "{text}");
                found = true;
            }
        }
        assert!(found, "expected persisted TLS capture");
        proxy_task.abort();
        origin_task.abort();
        db.db_pool.close().await;
        let _ = std::fs::remove_dir_all(root);
    }
}
