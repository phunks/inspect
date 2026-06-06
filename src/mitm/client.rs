use rama::{http::{
    client::EasyHttpWebClient,
    service::web::response::IntoResponse,
    Request,
    Response}, tls::boring::client::TlsConnectorDataBuilder, ua::layer::emulate::{
    UserAgentEmulateHttpConnectModifierLayer,
    UserAgentEmulateHttpRequestModifierLayer,
}, Layer, Service};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use http::header::USER_AGENT;
use http::HeaderValue;
use rama::http::client::proxy::layer::{HttpProxyConnector, HttpProxyConnectorLayer};
use rama::net::tls::client::ServerVerifyMode;
use crate::options::{ProxyMode, UaProfile};

type UpstreamCall = Arc<
    dyn Fn(Request) -> Pin<Box<dyn Future<Output = (Response, Option<String>, Option<u16>)> + Send>>
    + Send
    + Sync,
>;

#[derive(Clone)]
pub enum UpstreamClient {
    Observe(UpstreamCall),
    Emulate(UpstreamCall),
}

impl UpstreamClient {
    pub(crate) async fn serve(&self, req: Request) -> (Response, Option<String>, Option<u16>) {
        match self {
            Self::Observe(call) | Self::Emulate(call) => (call)(req).await,
        }
    }
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
) -> UpstreamClient {
    let base_tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .with_store_server_certificate_chain(true)
        .into_shared_builder();

    let request_ua = ua_header_for_profile(request_ua_profile);
    let connect_ua_from_profile = connect_ua_profile.and_then(ua_header_for_profile);

    let static_proxy_ua = match proxy_mode {
        ProxyMode::Observe => connect_ua_from_profile.clone().or_else(|| request_ua.clone()),
        ProxyMode::Emulate => connect_ua_from_profile
            .clone()
            .or_else(|| request_ua.clone())
            .or_else(|| Some(HeaderValue::from_static(CHROME_UA))),
    };

    let dynamic_connect_ua_from_request =
        proxy_mode == ProxyMode::Observe && static_proxy_ua.is_none();

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
                    .build_client(),
            );

            let request_ua = request_ua.clone();
            let call: UpstreamCall = Arc::new(move |req: Request| {
                let static_client = static_client.clone();
                let request_ua = request_ua.clone();
                let base_tls_config = base_tls_config.clone();

                Box::pin(async move {
                    let mut req = req;

                    if let Some(ua) = request_ua {
                        req.headers_mut().insert(USER_AGENT, ua);
                    }

                    let client = if dynamic_connect_ua_from_request {
                        let connect_ua_from_client = req.headers().get(USER_AGENT).cloned();
                        Arc::new(
                            EasyHttpWebClient::connector_builder()
                                .with_default_transport_connector()
                                .with_tls_proxy_support_using_boringssl()
                                .with_proxy_support()
                                .with_custom_connector(CustomProxyUaLayer { ua_value: connect_ua_from_client })
                                .with_tls_support_using_boringssl(Some(base_tls_config))
                                .with_default_http_connector()
                                .build_client(),
                        )
                    } else {
                        static_client
                    };

                    match client.serve(req).await {
                        Ok(res) => {
                            let status = Some(res.status().as_u16());
                            (res, None, status)
                        }
                        Err(err) => {
                            let err_text = format!("{err:#}");
                            let upstream_status = extract_http_status_from_error_text(&err_text);

                            let res = err.into_response();
                            let fallback_status = Some(res.status().as_u16());

                            let msg = format!("upstream error: {err_text}");
                            (res, Some(msg), upstream_status.or(fallback_status))
                        }
                    }
                })
            });

            UpstreamClient::Observe(call)
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
                    .build_client()
                    .with_jit_layer((UserAgentEmulateHttpRequestModifierLayer::default(),)),
            );

            let request_ua = request_ua.clone();
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
                            (res, None, status)
                        }
                        Err(err) => {
                            let err_text = format!("{err:#}");
                            let upstream_status = extract_http_status_from_error_text(&err_text);

                            let res = err.into_response();
                            let fallback_status = Some(res.status().as_u16());

                            let msg = format!("upstream error: {err_text}");
                            (res, Some(msg), upstream_status.or(fallback_status))
                        }
                    }
                })
            });

            UpstreamClient::Emulate(call)
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