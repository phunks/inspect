use rama::{
    http::{
        client::EasyHttpWebClient,
        service::web::response::IntoResponse,
        Request,
        Response },
    tls::boring::client::TlsConnectorDataBuilder,
    ua::layer::emulate::{
        UserAgentEmulateHttpConnectModifierLayer,
        UserAgentEmulateHttpRequestModifierLayer,
    }, Service,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use rama::net::tls::client::ServerVerifyMode;
use crate::options::ProxyMode;

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

pub fn new_upstream_client(proxy_mode: ProxyMode) -> UpstreamClient {
    let base_tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(ServerVerifyMode::Disable)
        .with_store_server_certificate_chain(true)
        .into_shared_builder();

    match proxy_mode {
        ProxyMode::Observe => {
            let client = Arc::new(
                EasyHttpWebClient::connector_builder()
                    .with_default_transport_connector()
                    .with_tls_proxy_support_using_boringssl()
                    .with_proxy_support()
                    .with_tls_support_using_boringssl(Some(base_tls_config))
                    .with_default_http_connector()
                    .build_client(),
            );

            let call: UpstreamCall = Arc::new(move |req: Request| {
                let client = client.clone();
                Box::pin(async move {
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
                    .with_tls_support_using_boringssl(Some(base_tls_config))
                    .with_custom_connector(UserAgentEmulateHttpConnectModifierLayer::default())
                    .with_default_http_connector()
                    .build_client()
                    .with_jit_layer((UserAgentEmulateHttpRequestModifierLayer::default(),)),
            );

            let call: UpstreamCall = Arc::new(move |req: Request| {
                let client = client.clone();
                Box::pin(async move {
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