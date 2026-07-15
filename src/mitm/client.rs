use rama::{
    http::{
        client::EasyHttpWebClient,
        service::web::response::IntoResponse,
        Request,
        Response,
        StatusCode,
    },
    layer::timeout::TimeoutLayer as ServiceTimeoutLayer,
    tls::boring::client::TlsConnectorDataBuilder,
    ua::layer::emulate::{
        UserAgentEmulateHttpConnectModifierLayer,
        UserAgentEmulateHttpRequestModifierLayer,
    },
    Layer,
    Service,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use http::header::USER_AGENT;
use http::HeaderValue;
use rama::extensions::{ExtensionsRef, InputExtensions};
use rama::http::client::proxy::layer::HttpProxyConnector;
use rama::http::layer::timeout::TimeoutLayer;
use rama::net::stream::ClientSocketInfo;
use rama::net::tls::client::ServerVerifyMode;
use crate::options::{ProxyMode, UaProfile};
use crate::mitm::websocket::mitm_websocket;

#[derive(Debug)]
pub(crate) struct UpstreamResult {
    pub response: Response,
    pub upstream_err: Option<String>,
    pub upstream_status: Option<u16>,
    pub upstream_remote_addr: Option<String>,
}

type UpstreamCall = Arc<
    dyn Fn(Request) -> Pin<Box<dyn Future<Output = UpstreamResult> + Send>>
    + Send
    + Sync,
>;

type UpstreamWebSocketCall = Arc<
    dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>>
    + Send
    + Sync,
>;

#[derive(Clone)]
pub struct UpstreamClient {
    call: UpstreamCall,
    websocket_call: UpstreamWebSocketCall,
}

impl UpstreamClient {
    pub(crate) async fn serve(&self, req: Request) -> UpstreamResult {
        (self.call)(req).await
    }

    pub(crate) async fn serve_websocket(&self, req: Request) -> Response {
        (self.websocket_call)(req).await
    }

    fn new(call: UpstreamCall, websocket_call: UpstreamWebSocketCall) -> Self {
        Self {
            call,
            websocket_call,
        }
    }
}

fn upstream_remote_addr_from_response(res: &Response) -> Option<String> {
    let socket_info = res.extensions()
        .get()
        .and_then(|InputExtensions(egress)| egress.get::<ClientSocketInfo>())?;

    let peer = socket_info.peer_addr();

    let ip = peer.ip();
    let port = peer.port();

    Some(format!("{ip}:{port}"))
}

#[derive(Clone)]
struct CustomProxyUaLayer {
    ua_value: Option<HeaderValue>,
}

impl<S> Layer<HttpProxyConnector<S>> for CustomProxyUaLayer {
    type Service = HttpProxyConnector<S>;

    fn layer(&self, mut connector: HttpProxyConnector<S>) -> Self::Service {
        if let Some(ua) = &self.ua_value {
            connector.set_custom_header(USER_AGENT, ua.clone());
        }
        connector
    }
}

const CHROME_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36";
const FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0";

fn ua_header_for_profile(profile: UaProfile) -> Option<HeaderValue> {
    match profile {
        UaProfile::Auto => None,
        UaProfile::Chrome => Some(HeaderValue::from_static(CHROME_UA)),
        UaProfile::Firefox => Some(HeaderValue::from_static(FIREFOX_UA)),
    }
}

pub fn new_upstream_client(
    proxy_mode: ProxyMode,
    request_ua_profile: UaProfile,
    connect_ua_profile: Option<UaProfile>,
    connect_ua: Option<String>,
    handshake_timeout: Duration,
    request_timeout: Duration,
) -> UpstreamClient {
    let base_tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .with_store_server_certificate_chain(true)
        .into_shared_builder();

    let request_ua = ua_header_for_profile(request_ua_profile);
    let connect_ua_from_profile = connect_ua_profile.and_then(ua_header_for_profile);
    let connect_ua_raw = connect_ua
        .as_deref()
        .and_then(|value| HeaderValue::from_str(value).ok());

    let static_proxy_ua = match proxy_mode {
        ProxyMode::Observe => connect_ua_raw
            .clone()
            .or_else(|| connect_ua_from_profile.clone())
            .or_else(|| request_ua.clone()),
        ProxyMode::Emulate => connect_ua_raw
            .clone()
            .or_else(|| connect_ua_from_profile.clone())
            .or_else(|| request_ua.clone())
            .or_else(|| Some(HeaderValue::from_static(CHROME_UA))),
    };

    match proxy_mode {
        ProxyMode::Observe => {
            let static_client = Arc::new(
                EasyHttpWebClient::connector_builder()
                    .with_default_transport_connector()
                    .with_tls_proxy_support_using_boringssl()
                    .with_proxy_support()
                    .with_custom_connector(CustomProxyUaLayer { ua_value: static_proxy_ua.clone() })
                    .with_tls_support_using_boringssl(Some(base_tls_config.clone()))
                    .with_default_http_connector()
                    .with_custom_connector(ServiceTimeoutLayer::new(handshake_timeout))
                    .build_client()
                    .with_jit_layer(
                        TimeoutLayer::with_status_code(StatusCode::GATEWAY_TIMEOUT, request_timeout)
                    ),
            );

            let request_ua = request_ua.clone();
            let http_client = static_client.clone();

            let call: UpstreamCall = Arc::new(move |req: Request| {
                let client = static_client.clone();
                let request_ua = request_ua.clone();

                Box::pin(async move {
                    let mut req = req;

                    if let Some(ua) = request_ua {
                        req.headers_mut().insert(USER_AGENT, ua);
                    }

                    match client.serve(req).await {
                        Ok(res) => {
                            let status = Some(res.status().as_u16());
                            let upstream_remote_addr = upstream_remote_addr_from_response(&res);
                            UpstreamResult {
                                response: res,
                                upstream_err: None,
                                upstream_status: status,
                                upstream_remote_addr,
                            }
                        }
                        Err(err) => {
                            let err_text = format!("{err:#}");
                            let upstream_status = extract_http_status_from_error_text(&err_text);

                            let res = err.into_response();
                            let fallback_status = Some(res.status().as_u16());

                            let msg = format!("upstream error: {err_text}");
                            UpstreamResult {
                                response: res,
                                upstream_err: Some(msg),
                                upstream_status: upstream_status.or(fallback_status),
                                upstream_remote_addr: None,
                            }
                        }
                    }
                })
            });

            let websocket_call: UpstreamWebSocketCall = Arc::new(move |req: Request| {
                let client = http_client.clone();

                Box::pin(async move {
                    mitm_websocket(client.as_ref(), req).await
                })
            });

            UpstreamClient::new(call, websocket_call)
        }
        ProxyMode::Emulate => {
            let client = Arc::new(
                EasyHttpWebClient::connector_builder()
                    .with_default_transport_connector()
                    .with_tls_proxy_support_using_boringssl()
                    .with_proxy_support()
                    .with_custom_connector(CustomProxyUaLayer { ua_value: static_proxy_ua })
                    .with_tls_support_using_boringssl(Some(base_tls_config))
                    .with_custom_connector(UserAgentEmulateHttpConnectModifierLayer::default())
                    .with_default_http_connector()
                    .with_custom_connector(ServiceTimeoutLayer::new(handshake_timeout))
                    .build_client()
                    .with_jit_layer((
                        UserAgentEmulateHttpRequestModifierLayer::default(),
                        TimeoutLayer::with_status_code(StatusCode::GATEWAY_TIMEOUT, request_timeout),
                    )),
            );

            let request_ua = request_ua.clone();
            let http_client = client.clone();

            let call: UpstreamCall = Arc::new(move |req: Request| {
                let client = client.clone();
                let request_ua = request_ua.clone();

                Box::pin(async move {
                    let mut req = req;

                    if let Some(ua) = request_ua {
                        req.headers_mut().insert(USER_AGENT, ua);
                    }

                    match client.serve(req).await {
                        Ok(res) => {
                            let status = Some(res.status().as_u16());

                            UpstreamResult {
                                response: res,
                                upstream_err: None,
                                upstream_status: status,
                                upstream_remote_addr: None,
                            }
                        }
                        Err(err) => {
                            let err_text = format!("{err:#}");
                            let upstream_status = extract_http_status_from_error_text(&err_text);

                            let res = err.into_response();
                            let fallback_status = Some(res.status().as_u16());

                            let msg = format!("upstream error: {err_text}");

                            UpstreamResult {
                                response: res,
                                upstream_err: Some(msg),
                                upstream_status: upstream_status.or(fallback_status),
                                upstream_remote_addr: None,
                            }
                        }
                    }
                })
            });

            let websocket_call: UpstreamWebSocketCall = Arc::new(move |req: Request| {
                let client = http_client.clone();

                Box::pin(async move {
                    mitm_websocket(client.as_ref(), req).await
                })
            });

            UpstreamClient::new(call, websocket_call)
        }
    }
}

pub fn extract_http_status_from_error_text(s: &str) -> Option<u16> {
    let bytes = s.as_bytes();
    if bytes.len() < 3 {
        return None;
    }

    for i in 0..=bytes.len() - 3 {
        let a = bytes[i];
        let b = bytes[i + 1];
        let c = bytes[i + 2];

        let is_digit3 = a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit();
        if !is_digit3 {
            continue;
        }

        let left_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
        let right_ok = i + 3 >= bytes.len() || !bytes[i + 3].is_ascii_digit();
        if !(left_ok && right_ok) {
            continue;
        }

        let code = ((a - b'0') as u16) * 100 + ((b - b'0') as u16) * 10 + (c - b'0') as u16;
        if (100..=599).contains(&code) {
            return Some(code);
        }
    }

    None
}
