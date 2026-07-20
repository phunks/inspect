
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
    },
    layer::{AddInputExtensionLayer, ConsumeErrLayer},
    net::{
        http::RequestContext, proxy::ProxyTarget,
        tls::server::{ServerAuth, ServerConfig},
    },
    rt::Executor,
    service::service_fn,
    tcp::{server::TcpListener},
    telemetry::tracing,
    tls::boring::{
        client::EmulateTlsProfileLayer,
        server::{TlsAcceptorData, TlsAcceptorLayer},
    },
    ua::{
        layer::emulate::UserAgentEmulateLayer,
        profile::UserAgentDatabase,
    },
    Layer,
    Service,
};
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::net::IpAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use chrono::Utc;
use rama::net::address::{Host, HostWithPort, ProxyAddress};
use serde::Serialize;
use rama::http::ws::handshake::server::WebSocketMatcher;
use rama::matcher::Matcher;
use rama::net::tls::server::SniRouter;
use tracing::{info, info_span};
use tracing_futures::Instrument;
use tokio::sync::watch;
use uuid::Uuid;
use crate::filters::FilterManager;
use crate::filters::http_client::OutboundHttpClientPool;
use crate::mitm::capture::CapturePaths;
use crate::mitm::client::{new_upstream_client, UpstreamClient};
use crate::mitm::dynamic_ca::DynamicIssuer;
use crate::mitm::flow::dispatcher::UpstreamFlowResult;
use crate::mitm::flow::{
    CaptureService,
    FlowDispatcher,
    FlowDispatcherConfig,
    FlowEvent,
    TunnelFailed,
    FlowEventPublisher,
    UpstreamFlowClient,
    TunnelFailureCapture,
    flow_marks_from_connect_action,
};
use crate::mitm::flow::state_store::FilterStateLimits;
use crate::mitm::flow::websocket::dispatch_websocket_handshake;
use crate::mitm::store_metadata::DbState;
use crate::mitm::tls_sni::ConnectSniRouterService;
use crate::options::{FilterStateConfig, ProxyMode, UaProfile};

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

#[derive(Clone)]
struct State {
    mitm_tls_service_data: TlsAcceptorData,
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
    fn serve(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = UpstreamFlowResult> + Send + '_>> {
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

    fn serve_websocket(
        &self,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            UpstreamClient::serve_websocket(self, req).await
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn mitm_proxy_main(
    upstream_proxy: Option<String>,
    service_port: String,
    ua_profile: UaProfile,
    connect_ua_profile: Option<UaProfile>,
    connect_ua: Option<String>,
    proxy_mode: ProxyMode,
    upstream_handshake_timeout_ms: u64,
    upstream_request_timeout_sec: u64,
    body_save_limit_bytes: Option<usize>,
    body_omit_content_types: Vec<String>,
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
        new_mitm_tls_service_data().await.context("generate self-signed mitm tls cert")?;

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
                address: HostWithPort { host: Host::from(IpAddr::from_str(ip)?), port: port.parse()? },
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
            body_save_limit_bytes,
            body_omit_content_types: body_omit_content_types.clone(),
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

        tcp_service
            .serve_graceful(
                guard,
                AddInputExtensionLayer::new(state)
                    .into_layer(http_service),
            )
            .await;
    });

    let _ = shutdown_rx.changed().await;
    dbstate.flush_sqlite_wal_on_exit().await?;
    handle.abort();
    Ok(())
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    let authority = match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
        Ok(authority) => authority,
        Err(err) => {
            tracing::error!("error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    };

    if let Some(state) = req.extensions().get::<State>().cloned() {
        let connect = state.flow_dispatcher.dispatch_connect_filters(
            authority.host.to_string(),
            authority.port,
        );

        if connect.action.drop_tunnel {
            let status = connect
                .action
                .reject_status
                .and_then(|status| StatusCode::from_u16(status).ok());

            let now = Utc::now();
            let id = Uuid::new_v4().to_string();
            let seq = state
                .flow_dispatcher
                .seq()
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            let flow_key = format!("{seq:06}-{}", &id[..8]);

            let marks = flow_marks_from_connect_action(&connect.action);
            let stage = "Roto connect_action".to_string();
            let error = match status {
                Some(status) => format!("CONNECT denied by Roto with status {}", status.as_u16()),
                None => "CONNECT dropped by Roto".to_string(),
            };

            state.flow_dispatcher.events().publish(FlowEvent::TunnelFailed(
                TunnelFailed {
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
                },
            ));

            info!(
                    server.address = %authority.host,
                    server.port = %authority.port,
                    reject_status = ?status,
                    marks = connect.action.marks.len(),
                    "CONNECT tunnel blocked by roto connect_action before upstream"
                );

            if let Some(status) = status {
                return Err(
                    Response::builder()
                        .status(status)
                        .header("connection", "close")
                        .body(Body::empty())
                        .unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response())
                );
            }

            return Err(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("connection", "close")
                    .body(Body::empty())
                    .unwrap_or_else(|_| StatusCode::FORBIDDEN.into_response())
            );
        }
    }

    info!(
        server.address = %authority.host,
        server.port = %authority.port,
        "accept CONNECT (lazy): insert proxy target into context",
    );

    req.extensions_mut().insert(ProxyTarget(authority));

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
        .map(|pt| pt.0.clone());

    let span = info_span!(
        "https_conn",
        ?client_target,
    );

    async move {
        let state = upgraded
            .extensions()
            .get::<State>()
            .cloned()
            .unwrap();

        let http_service = new_http_mitm_proxy(&state);

        if let Some(upstream_proxy) = state.flow_dispatcher.upstream_proxy() {
            upgraded.extensions_mut().insert(upstream_proxy);
        }

        let executor = upgraded
            .extensions()
            .get::<Executor>()
            .cloned()
            .unwrap_or_default();
        // let http_transport_service = HttpServer::auto(executor).service(http_service);
        let mut http_transport_server = HttpServer::auto(executor);
        http_transport_server
            .http1_mut()
            .set_header_read_timeout(Duration::from_secs(60));
        let http_transport_service = http_transport_server.service(http_service);

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
            let error = format!("{err:#}");

            tracing::error!(
                    error = %error,
                    "error serving HTTPS connection"
                );

            if let Some(target) = client_target.as_ref() {
                let now = Utc::now();
                let id = Uuid::new_v4().to_string();
                let seq = state
                    .flow_dispatcher
                    .seq()
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
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

                if let Err(err) = state.flow_dispatcher.capture().commit_tunnel_failure(capture).await {
                    tracing::error!(
                            error = ?err,
                            flow_key = %flow_key,
                            "failed to persist TLS tunnel failure"
                        );
                }

                state.flow_dispatcher.events().publish(FlowEvent::TunnelFailed(
                    TunnelFailed {
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
                    },
                ));
            }
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

async fn http_mitm_proxy(req: Request) -> Result<Response, Infallible> {
    let state = req.extensions().get::<State>().cloned().unwrap();

    if WebSocketMatcher::new().matches(None, &req) {
        return Ok(dispatch_websocket_handshake(
            &state.flow_dispatcher,
            req,
        ).await);
    }

    state.flow_dispatcher.dispatch(req).await
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