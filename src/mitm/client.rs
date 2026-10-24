use rama::extensions::ExtensionsRef;
use rama::http::HeaderValue;
use rama::http::client::proxy::layer::HttpProxyConnector;
use rama::http::header::USER_AGENT;
use rama::http::layer::timeout::TimeoutLayer;
use rama::net::stream::SocketInfo;
use rama::{
    Layer, Service,
    http::{
        Request, Response, StatusCode, client::EasyHttpWebClient,
        service::web::response::IntoResponse,
    },
    layer::timeout::TimeoutLayer as ServiceTimeoutLayer,
    rt::Executor,
    tls::client::{ServerVerifyMode, TlsClientConfig},
    ua::layer::emulate::{
        UserAgentEmulateHttpConnectModifierLayer, UserAgentEmulateHttpRequestModifierLayer,
    },
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::mitm::flow::tls_metadata::ExtendedTlsParameters;
use crate::mitm::websocket::mitm_websocket;
use crate::options::{ProxyMode, UaProfile};
use rama::net::client::{ConnectorService, EstablishedClientConnection};
use rama::tls::boring::client::AutoTlsStream;
use rama::tls::client::NegotiatedTlsParameters;

/// Capture while the concrete TLS stream is still available, before HTTP erases it.
#[derive(Debug, Clone)]
struct CaptureTlsLayer;

impl<S> Layer<S> for CaptureTlsLayer {
    type Service = CaptureTls<S>;
    fn layer(&self, inner: S) -> Self::Service {
        CaptureTls(inner)
    }
}

#[derive(Debug, Clone)]
struct CaptureTls<S>(S);

impl<S, Input, Io> Service<Input> for CaptureTls<S>
where
    S: ConnectorService<Input, Connection = AutoTlsStream<Io>>,
    Input: Send + 'static,
    Io: rama::io::Io + Unpin + ExtensionsRef,
{
    type Output = EstablishedClientConnection<AutoTlsStream<Io>, Input>;
    type Error = rama::net::client::ConnectionError;
    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let established = self.0.connect(input).await?;
        if let Some(ssl) = established.conn.ssl_ref()
            && let Some(negotiated) = established
                .conn
                .extensions()
                .get_ref::<NegotiatedTlsParameters>()
        {
            established
                .conn
                .extensions()
                .insert(ExtendedTlsParameters::capture(ssl, negotiated.clone()));
        }
        Ok(established)
    }
}

/// Only carry connection metadata forward, not arbitrary request extensions.
#[derive(Debug, Clone)]
struct CarryConnectionInfoLayer;

impl<S> Layer<S> for CarryConnectionInfoLayer {
    type Service = CarryConnectionInfo<S>;
    fn layer(&self, inner: S) -> Self::Service {
        CarryConnectionInfo(inner)
    }
}

#[derive(Debug, Clone)]
struct CarryConnectionInfo<S>(S);

impl<S, B> Service<Request> for CarryConnectionInfo<S>
where
    S: Service<Request, Output = Response<B>>,
    B: rama::http::StreamingBody<Data = bytes::Bytes, Error: Into<rama::error::BoxError>>
        + Send
        + Sync
        + 'static,
{
    type Output = Response;
    type Error = S::Error;
    async fn serve(&self, req: Request) -> Result<Response, Self::Error> {
        let tls = req.extensions().get_ref::<ExtendedTlsParameters>().cloned();
        let socket = req.extensions().get_ref::<SocketInfo>().cloned();
        let response = self.0.serve(req).await?;
        if let Some(tls) = tls {
            response.extensions().insert(tls);
        }
        if let Some(socket) = socket {
            response.extensions().insert(socket);
        }
        Ok(response.map(rama::http::Body::new))
    }
}

#[derive(Debug)]
pub(crate) struct UpstreamResult {
    pub response: Response,
    pub upstream_err: Option<String>,
    pub upstream_status: Option<u16>,
    pub upstream_remote_addr: Option<String>,
}

type UpstreamCall =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = UpstreamResult> + Send>> + Send + Sync>;

type UpstreamWebSocketCall =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

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
    let socket_info = res.extensions().get_ref::<SocketInfo>()?;

    Some(socket_info.peer_addr().to_string())
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

const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36";
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
    let base_tls_config = TlsClientConfig::default_http()
        .with_server_verify(ServerVerifyMode::Disable)
        .with_store_server_cert_chain(true);

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
                    .with_default_dns_connector()
                    .with_tls_proxy_support_using_boringssl()
                    .with_proxy_support()
                    .with_custom_connector(CustomProxyUaLayer { ua_value: static_proxy_ua.clone() })
                    .with_tls_support_using_boringssl_and_default_http_version(base_tls_config.clone(), rama::http::Version::HTTP_11)
                    .with_custom_connector(CaptureTlsLayer)
                    .with_default_http_connector(Executor::default())
                    .with_custom_connector(ServiceTimeoutLayer::new(handshake_timeout))
                    .without_connection_pool()
                    .build_client()
                    .with_jit_layer((rama::http::layer::map_response_body::MapResponseBodyLayer::new_boxed_streaming_body(), CarryConnectionInfoLayer,
                        TimeoutLayer::with_status_code(StatusCode::GATEWAY_TIMEOUT, request_timeout)
                    )),
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

                            let res = StatusCode::BAD_GATEWAY.into_response();
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

                Box::pin(async move { mitm_websocket(client.as_ref(), req).await })
            });

            UpstreamClient::new(call, websocket_call)
        }
        ProxyMode::Emulate => {
            let client = Arc::new(
                EasyHttpWebClient::connector_builder()
                    .with_default_transport_connector()
                    .with_default_dns_connector()
                    .with_tls_proxy_support_using_boringssl()
                    .with_proxy_support()
                    .with_custom_connector(CustomProxyUaLayer { ua_value: static_proxy_ua })
                    .with_tls_support_using_boringssl_and_default_http_version(base_tls_config, rama::http::Version::HTTP_11)
                    .with_custom_connector(UserAgentEmulateHttpConnectModifierLayer::default())
                    .with_custom_connector(CaptureTlsLayer)
                    .with_default_http_connector(Executor::default())
                    .with_custom_connector(ServiceTimeoutLayer::new(handshake_timeout))
                    .without_connection_pool()
                    .build_client()
                    .with_jit_layer((
                        rama::http::layer::map_response_body::MapResponseBodyLayer::new_boxed_streaming_body(),
                        CarryConnectionInfoLayer,
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

                            let res = StatusCode::BAD_GATEWAY.into_response();
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

                Box::pin(async move { mitm_websocket(client.as_ref(), req).await })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::flow::tls_metadata::upstream_tls_info_from_extensions;
    use rama::extensions::{Egress, Extension, Extensions};
    use rama::http::Body;
    use rama::service::service_fn;
    use rama::tls::ProtocolVersion;
    use std::convert::Infallible;

    fn metadata() -> ExtendedTlsParameters {
        ExtendedTlsParameters {
            negotiated: NegotiatedTlsParameters {
                protocol_version: ProtocolVersion::TLSv1_3,
                application_layer_protocol: None,
                peer_certificate_chain: None,
            },
            protocol_version: Some("TLSv1.3".into()),
            cipher: Some("test-cipher".into()),
            cipher_standard_name: None,
            cipher_description: None,
            bits: Some(256),
            algorithm_bits: Some(256),
            curve_name: None,
            client_random: vec![0xAB; 32],
            server_random: vec![0xCD; 32],
        }
    }

    #[derive(Debug, Clone, Extension)]
    struct RequestOnly;

    #[tokio::test]
    async fn carries_egress_tls_and_socket_metadata_without_leaking_request_state() {
        let egress = Extensions::new();
        egress.insert(metadata());
        egress.insert(SocketInfo::new(None, "127.0.0.1:443".parse().unwrap()));
        let request = Request::new(Body::empty());
        request.extensions().insert(Egress(egress));
        request.extensions().insert(RequestOnly);
        let service = CarryConnectionInfo(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
        let response = service.serve(request).await.unwrap();
        let info = upstream_tls_info_from_extensions(response.extensions()).unwrap();
        assert_eq!(info["cipher"], "test-cipher");
        assert_eq!(info["client_random"], "AB".repeat(32));
        assert_eq!(
            upstream_remote_addr_from_response(&response).as_deref(),
            Some("127.0.0.1:443")
        );
        assert!(response.extensions().get_ref::<RequestOnly>().is_none());
    }

    #[tokio::test]
    async fn plain_http_has_no_tls_metadata() {
        let service = CarryConnectionInfo(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
        let response = service.serve(Request::new(Body::empty())).await.unwrap();
        assert!(upstream_tls_info_from_extensions(response.extensions()).is_none());
    }

    // The deeply composed connector futures need extra stack in unoptimized tests.
    #[test]
    fn captures_real_tls_for_http1_http2_and_reused_connections() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(real_tls_roundtrips());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn real_tls_roundtrips() {
        use rama::http::{BodyExtractExt, Version};
        use rama::tcp::server::TcpListener;
        use rama::tls::boring::server::TlsAcceptorLayer;
        use rama::tls::server::TlsServerConfig;
        use std::convert::Infallible;

        let listener = TcpListener::bind_address("127.0.0.1:0", Executor::default())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = TlsAcceptorLayer::new(TlsServerConfig::generated_http_auto().unwrap())
            .into_layer(
                rama::http::server::HttpServer::auto(Executor::default()).service(service_fn(
                    async |_: Request| Ok::<_, Infallible>(Response::new(Body::from("ok"))),
                )),
            );
        let task = tokio::spawn(listener.serve(server));

        for version in [Version::HTTP_11, Version::HTTP_2] {
            let config = TlsClientConfig::default_http()
                .with_server_verify(ServerVerifyMode::Disable)
                .with_store_server_cert_chain(true);
            let client = EasyHttpWebClient::connector_builder()
                .with_default_transport_connector()
                .with_default_dns_connector()
                .without_tls_proxy_support()
                .without_proxy_support()
                .with_tls_support_using_boringssl(config)
                .with_custom_connector(CaptureTlsLayer)
                .with_default_http_connector(Executor::default())
                .with_default_connection_pool()
                .build_client()
                .with_jit_layer(CarryConnectionInfoLayer);
            let mut previous_random = None;
            for _ in 0..2 {
                let request = Request::builder()
                    .uri(format!("https://localhost:{}/", address.port()))
                    .version(version)
                    .body(Body::empty())
                    .unwrap();
                request
                    .extensions()
                    .insert(rama::net::http::TargetHttpVersion(version));
                let response =
                    tokio::time::timeout(Duration::from_secs(10), Box::pin(client.serve(request)))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(response.version(), version);
                let info = upstream_tls_info_from_extensions(response.extensions()).unwrap();
                assert!(info["cipher"].as_str().is_some_and(|s| !s.is_empty()));
                assert_eq!(info["client_random"].as_str().unwrap().len(), 64);
                assert_eq!(info["server_random"].as_str().unwrap().len(), 64);
                assert!(!info["certificate_chain"].as_array().unwrap().is_empty());
                assert!(upstream_remote_addr_from_response(&response).is_some());
                if let Some(previous) = previous_random.as_ref() {
                    assert_eq!(
                        previous, &info["client_random"],
                        "expected pooled TLS connection reuse"
                    );
                }
                previous_random = Some(info["client_random"].clone());
                assert_eq!(response.into_body().try_into_string().await.unwrap(), "ok");
            }
        }
        for mode in [ProxyMode::Observe, ProxyMode::Emulate] {
            let client = new_upstream_client(
                mode,
                UaProfile::Auto,
                None,
                None,
                Duration::from_secs(5),
                Duration::from_secs(5),
            );
            let request = Request::builder()
                .uri(format!("https://localhost:{}/", address.port()))
                .body(Body::empty())
                .unwrap();
            let result = Box::pin(client.serve(request)).await;
            assert!(result.upstream_err.is_none(), "{:?}", result.upstream_err);
            assert!(upstream_tls_info_from_extensions(result.response.extensions()).is_some());
            if mode == ProxyMode::Observe {
                assert!(result.upstream_remote_addr.is_some());
            }
            assert_eq!(
                result.response.into_body().try_into_string().await.unwrap(),
                "ok"
            );
        }
        task.abort();
    }

    #[test]
    fn websocket_upgrade_and_message_relay() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(websocket_roundtrip());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn websocket_roundtrip() {
        use rama::http::ws::{
            Message,
            handshake::{client::HttpClientWebSocketExt, server::WebSocketAcceptor},
        };
        use rama::tcp::server::TcpListener;
        let listener = TcpListener::bind_address("127.0.0.1:0", Executor::default())
            .await
            .unwrap();
        let origin_address = listener.local_addr().unwrap();
        let origin = rama::http::server::HttpServer::auto(Executor::default()).service(
            rama::layer::ConsumeErrLayer::default()
                .into_layer(WebSocketAcceptor::new().into_echo_service()),
        );
        let origin_task = tokio::spawn(listener.serve(origin));
        let upstream = new_upstream_client(
            ProxyMode::Observe,
            UaProfile::Auto,
            None,
            None,
            Duration::from_secs(5),
            Duration::from_secs(5),
        );
        let listener = TcpListener::bind_address("127.0.0.1:0", Executor::default())
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = rama::http::server::HttpServer::auto(Executor::default()).service(service_fn(
            move |req: Request| {
                let upstream = upstream.clone();
                async move { Ok::<_, Infallible>(upstream.serve_websocket(req).await) }
            },
        ));
        let proxy_task = tokio::spawn(listener.serve(proxy));
        let request = Request::builder()
            .uri(format!("http://{origin_address}/"))
            .header("host", origin_address.to_string())
            .body(Body::empty())
            .unwrap();
        // The outer HTTP proxy route retains the echo origin as request target.
        let client = EasyHttpWebClient::connector_builder()
            .with_default_transport_connector()
            .with_default_dns_connector()
            .without_tls_proxy_support()
            .with_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .without_connection_pool()
            .build_client();
        request
            .extensions()
            .insert(rama::net::client::ProxyRoutes::from(
                format!("http://{address}")
                    .parse::<rama::net::address::ProxyAddress>()
                    .unwrap(),
            ));
        let mut socket = tokio::time::timeout(
            Duration::from_secs(10),
            Box::pin(
                client
                    .websocket_with_request(request)
                    .initiate_handshake(Extensions::new()),
            ),
        )
        .await
        .unwrap()
        .unwrap()
        .complete()
        .await
        .unwrap();
        socket
            .send_message(Message::text("rama04-ws"))
            .await
            .unwrap();
        let message = tokio::time::timeout(Duration::from_secs(5), socket.recv_message())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(message, Message::text("rama04-ws"));
        proxy_task.abort();
        origin_task.abort();
    }
}
