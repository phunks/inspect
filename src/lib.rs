
use rama::{
    error::{BoxError, ErrorContext, OpaqueError}, extensions::{ExtensionsMut, ExtensionsRef},
    http::{
        client::EasyHttpWebClient, layer::{
            compression::CompressionLayer,
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        }, matcher::MethodMatcher, server::HttpServer, service::web::response::IntoResponse,
        Body,
        Request,
        Response,
        StatusCode,
        Version,
    },
    layer::{AddInputExtensionLayer, ConsumeErrLayer},
    net::{
        http::RequestContext, proxy::ProxyTarget, stream::layer::http::BodyLimitLayer,
        tls::SecureTransport,
    },
    rt::Executor,
    service::service_fn,
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter},
    },
    tls::rustls::{
        client::TlsConnectorDataBuilder,
        server::{TlsAcceptorData, TlsAcceptorDataBuilder, TlsAcceptorLayer},
    },
    Layer,
    Service,
};
use std::{convert::Infallible, io, time::Duration};
use std::fmt::{Debug, Formatter};
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};
use base64::Engine;
use bytes::Bytes;
use rama::net::address::{Host, HostWithPort, ProxyAddress};
use rustls::{ServerConfig, ALL_VERSIONS};
use flate2::read;
use http::{HeaderName, HeaderValue};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use uuid::Uuid;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use chrono::{DateTime, Utc};
use rama::http::layer::traffic_writer;
use rama::http::layer::traffic_writer::RequestWriterLayer;
use rama::ua::layer::classifier::UserAgentClassifierLayer;
use tracing::{info, info_span};
use tracing_futures::Instrument;
use mitm::store_metadata::{DbState, RequestMetadata, RequestResponseEvent, ResponseMetadata};
use mitm::dynamic_ca::DynamicIssuer;
use tokio::sync::{mpsc, watch};


pub mod mitm;
pub mod tui;
pub mod option;

const BODY_SAVE_LIMIT_BYTES: usize = 3 * 1024;
const PROXY_BODY_LIMIT_BYTES: usize = 16 * 1024 * 1024;

pub type AnyError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type AnyResult<T> = Result<T, AnyError>;

#[derive(Clone, Debug)]
pub struct CapturePaths {
    pub root: PathBuf,
    pub db_path: PathBuf,
    pub flows_dir: PathBuf,
}
static CAPTURE_PATHS: OnceLock<CapturePaths> = OnceLock::new();
impl CapturePaths {
    fn build() -> std::io::Result<Self> {
        let base_dir = std::env::var("INSPECT_CAPTURE_DIR")
            .unwrap_or_else(|_| "./capture".to_string());
        let session = Utc::now().format("%Y%m%d%H%M%SZ").to_string();

        let root = PathBuf::from(base_dir).join(session);
        let db_path = root.join("index.sqlite");
        let flows_dir = root.join("flows");

        std::fs::create_dir_all(&flows_dir)?;
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&db_path)?;

        Ok(Self { root, db_path, flows_dir })
    }

    pub fn initialize_for_process() -> std::io::Result<&'static Self> {
        if let Some(existing) = CAPTURE_PATHS.get() {
            return Ok(existing);
        }

        let built = Self::build()?;
        let _ = CAPTURE_PATHS.set(built);
        Ok(CAPTURE_PATHS.get().expect("capture paths must be initialized"))
    }

    pub fn new() -> Self {
        CAPTURE_PATHS
            .get_or_init(|| {
                Self::build().expect("failed to initialize capture paths")
            })
            .clone()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketSummary {
    pub id: String,
    pub time: String,
    pub epoch_ms: i64,
    pub method: String,
    pub protocol: String,
    pub host: String,
    pub uri: String,
    pub query_str: String,
    pub status: u16,
    pub version: String,
    // pub elapsed:
}

#[derive(Clone)]
struct UiBridge {
    tx: mpsc::Sender<PacketSummary>,
}

#[derive(Clone)]
struct State {
    mitm_tls_service_data: TlsAcceptorData,
    upstream_proxy: Option<ProxyAddress>,
    exec: Executor,
    dbstate: DbState,
    capture_paths: CapturePaths,
    seq: Arc<AtomicU64>,
    tui_callback: Option<Arc<dyn Fn(PacketSummary) + Send + Sync>>,
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
                &self.tui_callback.as_ref().map(|_| "Fn(PacketSummary)"),
            )
            .finish()
    }
}

pub async fn mitm_proxy_main(
    upstream_proxy: Option<String>,
    service_port: String,
    packet_callback: Option<Arc<dyn Fn(PacketSummary) + Send + Sync>>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> AnyResult<()> {
    let mitm_tls_service_data =
        new_mitm_tls_service_data().await.context("generate self-signed mitm tls cert")?;

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
        seq: Arc::new(AtomicU64::new(0)),
        tui_callback: packet_callback,
    };
    let dbstate = state.dbstate.clone();
    info!("Starting mitm proxy with upstream proxy");
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
                (
                    AddInputExtensionLayer::new(state),
                    // protect the http proxy from too large bodies,
                    // both from request and response end
                    BodyLimitLayer::symmetric(PROXY_BODY_LIMIT_BYTES),
                )
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
        let http_service = new_http_mitm_proxy(&state);
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

        if let Err(err) = https_service.serve(upgraded).await {
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
        // UserAgentEmulateLayer::new(state.ua_db.clone())
        //     .with_try_auto_detect_user_agent(true)
        //     .with_is_optional(true),
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        CompressionLayer::new(),
        // AddRequiredRequestHeadersLayer::new(),
    )
        .into_layer(service_fn(http_mitm_proxy))

}

fn decode_reader(header_value: &HeaderValue, bytes: &[u8]) -> io::Result<Bytes> {
    let mut buf = Vec::new();
    info!("compression method: {:?}", header_value);
    let res = match header_value.as_bytes() {
        b"gzip" => read::GzDecoder::new(bytes).read_to_end(&mut buf),
        b"deflate" => read::DeflateDecoder::new(bytes).read_to_end(&mut buf),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid encoding",
        )),
    };

    match res {
        Ok(_) => Ok(Bytes::from(buf)),
        Err(e) => {
            tracing::error!("decode error: {:?}", e);
            Ok(Bytes::copy_from_slice(bytes))
        }
    }
}

async fn http_mitm_proxy(
    req: Request
) -> Result<Response, Infallible> {
    // This function will receive all requests going through this proxy,
    // be it sent via HTTP or HTTPS, both are equally visible. Hence... MITM

    let (mut parts, body) = req.into_parts();

    let state = parts.extensions().get::<State>().cloned().unwrap();
    let dbstate = state.dbstate.clone();
    let tui_callback = state.tui_callback.clone();
    let capture_paths = state.capture_paths.clone();
    let seq = state.seq.fetch_add(1, Ordering::Relaxed) + 1;

    let req_ctx = RequestContext::try_from(&parts)
                                .expect("extract request context");
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

    let req_head_text = build_request_head_text(&parts);
    let _ = tokio::fs::write(&req_head_path, req_head_text).await;

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
        headers: headers_to_json(&parts.headers),
    })).unwrap_or_else(|e|
        tracing::error!("error sending request event: {e:?}"));

    let user_agent = parts.headers.get(http::header::USER_AGENT).cloned();
    let req_method = parts.method.to_string().clone();

    let req_body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!("failed to collect request body: {e}");
            Bytes::new()
        }
    };
    let _ = write_body_limited(&req_body_path,
                               &req_body_bytes,
                               BODY_SAVE_LIMIT_BYTES
    ).await;
    let mut req = Request::from_parts(parts, Body::from(req_body_bytes));

    if let Some(user_agent) = user_agent {
        req.headers_mut().insert(http::header::USER_AGENT, user_agent);
    }

    // NOTE: use a custom connector (layers) in case you wish to add custom features,
    // such as upstream proxies or other configurations
    let tls_config = TlsConnectorDataBuilder::new()
        .with_alpn_protocols_http_auto()
        .try_with_env_key_logger()
        .expect("with env keylogger")
        // .with_no_cert_verifier()
        .build();

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_rustls()
        .with_proxy_support()
        .with_tls_support_using_rustls_and_default_http_version(Some(tls_config), Version::HTTP_11)
        // .with_custom_connector(UserAgentClassifierLayer::new().with_overwrite_header(HeaderName::from_static("xxxxx-user-agent")))
        .with_default_http_connector()
        .build_client();

        // .with_jit_layer(
        //     // UserAgentClassifierLayer::new().with_overwrite_header(HeaderName::from_static("xxxxx-user-agent")),
        //     RequestWriterLayer::stdout_unbounded(
        //         &executor,
        //         Some(traffic_writer::WriterMode::Headers)
        //     )
        // );
    let started_at = std::time::Instant::now();

    let (res, upstream_err): (Response, Option<String>) = match client.serve(req).await {
        Ok(res) => (res, None),
        Err(err) => {
            let res = err.into_response();
            let msg = format!("upstream error: {res:?}");
            (res, Some(msg))
        }
    };

    let elapsed_ms = started_at.elapsed().as_millis() as i64;

    let (parts, body) = res.into_parts();

    let res_head_text = build_response_head_text(&parts);
    let _ = tokio::fs::write(&res_head_path, res_head_text).await;

    let res_body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!("failed to collect response body: {e}");
            Bytes::new()
        }
    };

    if let Some(msg) = upstream_err.as_deref() {
        let _ = write_body_limited(&res_body_path, msg.as_bytes(), BODY_SAVE_LIMIT_BYTES).await;
    } else {
        let _ = write_body_limited(&res_body_path, &res_body_bytes, BODY_SAVE_LIMIT_BYTES).await;
    }

    dbstate.event_sender.send(RequestResponseEvent::Response(ResponseMetadata {
        id: id.to_string(),
        seq: seq as i64,
        flow_key: flow_key.clone(),
        flow_dir: flow_dir.to_string_lossy().to_string(),
        response_head_path: res_head_path.to_string_lossy().to_string(),
        response_body_path: res_body_path.to_string_lossy().to_string(),
        elapsed: elapsed_ms.to_string(),
        status: parts.status.as_u16(),
        version: version_to_string(parts.version),
        headers: headers_to_json(&parts.headers),
    })).unwrap_or_else(|e| tracing::error!("error sending response event: {e:?}"));

    if let Some(cb) = tui_callback {
        cb(PacketSummary {
            id: id.into(),
            time: rfc3999z(&time),
            epoch_ms: time.timestamp_millis(),
            method: req_method,
            protocol: req_protocol,
            host: req_host,
            uri: uri.path().to_string(),
            query_str: uri.query().unwrap_or_default().into(),
            status: parts.status.as_u16(),
            version: version_to_string(parts.version),
        });
    }

    Ok(Response::from_parts(parts, Body::from(res_body_bytes)))
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

fn build_request_head_text(parts: &rama::http::request::Parts) -> String {
    let mut out = String::new();
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
    let dynamic_issuer = Arc::new(DynamicIssuer::default());
    let config = ServerConfig::builder_with_protocol_versions(ALL_VERSIONS)
        .with_no_client_auth()
        .with_cert_resolver(dynamic_issuer);
    let data = TlsAcceptorDataBuilder::from(config)
        .with_alpn_protocols_http_auto()
        .try_with_env_key_logger()
        .context("with env key logger")?
        .build();

    Ok(data)
}
