
use rama::{
    error::ErrorContext,
    extensions::{Extension, ExtensionsRef},
    http::{
        layer::{
            compression::CompressionLayer,
            map_response_body::MapResponseBodyLayer,
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            upgrade::{
                DefaultHttpProxyConnectReplyService,
                UpgradeLayer,
                Upgraded,
            },
        },
        matcher::MethodMatcher,
        server::HttpServer,
        Body,
        BodyLimitLayer,
        Request,
        Response,
    },
    layer::{AddInputExtensionLayer, ConsumeErrLayer},
    matcher::Matcher,
    net::address::{Host, HostWithPort, ProxyAddress},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::{
        boring::{
            client::EmulateTlsProfileLayer,
            server::TlsAcceptorLayer,
        },
        server::TlsServerConfig,
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
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use rama::error::BoxError;
use rama::http::ws::handshake::matcher::WebSocketMatcher;
use rama::tls::boring::server::{BoringServerConfigExt, CacheKind, ServerCertIssuerData};
use rama::tls::server::SniRouter;
use serde::Serialize;
use tokio::sync::watch;
use tracing::{info, info_span};
use tracing_futures::Instrument;
use crate::filters::FilterManager;
use crate::filters::http_client::OutboundHttpClientPool;
use crate::mitm::capture::CapturePaths;
use crate::mitm::client::{new_upstream_client, UpstreamClient};
use crate::mitm::dynamic_ca::DynamicIssuer;
use crate::mitm::flow::{CaptureService, FlowDispatcher, FlowDispatcherConfig, FlowEventPublisher, UpstreamFlowClient};
use crate::mitm::flow::dispatcher::UpstreamFlowResult;
use crate::mitm::flow::state_store::FilterStateLimits;
use crate::mitm::flow::websocket::dispatch_websocket_handshake;
use crate::mitm::store_metadata::DbState;
use crate::mitm::tls_sni::ConnectSniRouterService;
use crate::options::{FilterStateConfig, ProxyMode, UaProfile};

const PROXY_BODY_LIMIT_BYTES: usize = 16 * 1024 * 1024;
// const WEBSOCKET_NOT_CAPTURED_MESSAGE: &str =
//     "<WebSocket upgraded; payload is not captured by inspect. Use tcpdump + SSLKEYLOGFILE + Wireshark.>\n";

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

#[derive(Clone, Extension)]
struct State {
    mitm_tls_service_data: TlsServerConfig,
    exec: Executor,
    proxy_body_limit_bytes: Option<usize>,
    flow_dispatcher: FlowDispatcher,
    proxy_mode: ProxyMode,
    ua_db: Arc<UserAgentDatabase>,
}

impl Debug for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State")
            .field("mitm_tls_service_data", &"...")
            .field("exec", &self.exec)
            .field("proxy_body_limit_bytes", &self.proxy_body_limit_bytes)
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
    proxy_mode: ProxyMode,
    upstream_handshake_timeout_ms: u64,
    upstream_request_timeout_sec: u64,
    body_save_limit_bytes: Option<usize>,
    body_omit_content_types: Vec<String>,
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

    let upstream_proxy = match upstream_proxy {
        None => None,
        Some(a) => {
            let ip = a.split(':').next().unwrap();
            let port = a.split(':').next_back().unwrap();

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
    let upstream_client = new_upstream_client(
        exec.clone(),
        proxy_mode,
        ua_profile,
        connect_ua_profile,
        Duration::from_millis(upstream_handshake_timeout_ms),
        Duration::from_secs(upstream_request_timeout_sec),
    );

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

    let proxy_body_limit_bytes = body_save_limit_bytes
        .map(|limit| limit.max(PROXY_BODY_LIMIT_BYTES));

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
            filters_enabled: proxy_mode == ProxyMode::Observe,
            filter_state_enabled: proxy_mode == ProxyMode::Observe && filter_state.enabled,
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
        exec: exec.clone(),
        proxy_body_limit_bytes,
        flow_dispatcher,
        proxy_mode,
        ua_db: Arc::new(UserAgentDatabase::try_embedded()?),
    };

    let dbstate = store_dbstate.clone();
    info!(
        ?proxy_mode,
        filters_enabled = proxy_mode == ProxyMode::Observe,
        request_ua_profile = ?ua_profile,
        connect_ua_profile = ?connect_ua_profile,
        "Starting mitm proxy with upstream proxy"
    );

    let handle = graceful.spawn_task(async {
        info!("starting tcp proxy on {service_port}");

        let tcp_service = TcpListener::build(exec.clone())
            .bind_address(service_port)
            .await
            .expect("bind tcp proxy");

        let http_mitm_service = new_http_mitm_proxy(&state);
        let http_service = HttpServer::auto(exec.clone()).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                UpgradeLayer::new(
                    exec,
                    MethodMatcher::CONNECT,
                    DefaultHttpProxyConnectReplyService::new(),
                    service_fn(http_connect_proxy),
                ),
            )
                .into_layer(http_mitm_service),
        ));

        if let Some(proxy_body_limit_bytes) = state.proxy_body_limit_bytes {
            tcp_service
                .serve(
                    (
                        AddInputExtensionLayer::new(state),
                        BodyLimitLayer::symmetric(proxy_body_limit_bytes),
                    )
                        .into_layer(http_service),
                )
                .await;
        } else {
            tcp_service
                .serve(AddInputExtensionLayer::new(state).into_layer(http_service))
                .await;
        }
    });

    let _ = shutdown_rx.changed().await;
    dbstate.flush_sqlite_wal_on_exit().await?;
    handle.abort();
    Ok(())
}

async fn http_connect_proxy(upgraded: Upgraded) -> Result<(), Infallible> {
    let span = info_span!("https_conn");

    async move {
        let state = upgraded
            .extensions()
            .get_ref::<State>()
            .expect("proxy state must be present");

        let http_service = new_http_mitm_proxy(state);
        let executor = state.exec.clone();

        let mut http_transport = HttpServer::auto(executor);
        http_transport.h2_mut().set_enable_connect_protocol();

        let http_transport_service = http_transport.service(http_service);

        let https_service = TlsAcceptorLayer::new(state.mitm_tls_service_data.clone())
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
            CompressionLayer::new(),
            AddRequiredRequestHeadersLayer::new(),
            EmulateTlsProfileLayer::new(),
        )
            .into_layer(service_fn(http_mitm_proxy)),
    )
}

async fn http_mitm_proxy(req: Request) -> Result<Response, Infallible> {
    let state = req
        .extensions()
        .get_ref::<State>()
        .expect("proxy state must be present")
        .clone();

    if WebSocketMatcher::new().matches(None, &req) {
        return Ok(
            dispatch_websocket_handshake(&state.flow_dispatcher, req).await,
        );
    }

    state.flow_dispatcher.dispatch(req).await
}


// NOTE: for a production service you ideally use
// an issued TLS cert (if possible via ACME). Or at the very least
// load it in from memory/file, so that your clients can install the certificate for trust.
fn new_mitm_tls_service_data() -> Result<TlsServerConfig, BoxError> {
    let dynamic_issuer = DynamicIssuer::default();

    Ok(TlsServerConfig::new()
        .with_alpn_http_auto()
        .with_cert_issuer(ServerCertIssuerData {
            kind: dynamic_issuer.into(),
            cache_kind: CacheKind::Disabled,
        }))
}
