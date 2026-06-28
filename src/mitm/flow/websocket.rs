use std::sync::atomic::Ordering;

use chrono::{DateTime, Utc};
use rama::{
    http::{
        service::web::response::IntoResponse,
        Request,
        Response,
        StatusCode,
    },
    net::http::RequestContext,
};
use rama::extensions::ExtensionsRef;
use serde_json::json;
use uuid::Uuid;

use crate::mitm::flow::{
    FlowDispatcher,
    FlowEvent,
    RequestCommitted,
    ResponseCommitted,
};
use crate::mitm::flow::capture_service::{
    build_request_head_text,
    build_response_head_text,
    headers_to_json,
    version_to_string,
};
use crate::mitm::flow::tls_metadata::tls_sni_from_extensions;
use crate::mitm::store_metadata::{
    RequestMetadata,
    RequestResponseEvent,
    ResponseMetadata,
};

const WEBSOCKET_NOT_CAPTURED_MESSAGE: &str =
    "<WebSocket upgraded; payload is not captured by inspect. Use tcpdump + SSLKEYLOGFILE + Wireshark.>\n";

pub(crate) async fn dispatch_websocket_handshake(
    dispatcher: &FlowDispatcher,
    req: Request,
) -> Response {
    let dbstate = dispatcher.capture().dbstate().clone();
    let capture_paths = dispatcher.capture().paths().clone();
    let seq = dispatcher.seq().fetch_add(1, Ordering::Relaxed) + 1;

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

    if let Err(err) = tokio::fs::create_dir_all(&flow_dir).await {
        tracing::error!(
            path = %flow_dir.display(),
            error = ?err,
            "failed to create websocket flow dir"
        );
    }

    let req_head_path = flow_dir.join("request.head");
    let req_body_path = flow_dir.join("request.body");
    let res_head_path = flow_dir.join("response.head");
    let res_body_path = flow_dir.join("response.body");
    let ssl_tls_path = flow_dir.join("ssl_tls.json");

    let (parts, body) = req.into_parts();
    let req_method = parts.method.to_string();

    let req_head_text = build_request_head_text(
        parts.method.as_str(),
        &parts.uri,
        parts.version,
        &parts.headers,
        tls_sni.as_deref(),
    );

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

    dbstate
        .event_sender
        .send(RequestResponseEvent::Request(RequestMetadata {
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
            body_save_limit: dispatcher
                .config()
                .body_save_limit_bytes
                .map(|limit| limit as i64),
        }))
        .unwrap_or_else(|err| {
            tracing::error!("error sending websocket request event: {err:?}");
        });

    dispatcher
        .events()
        .publish(FlowEvent::RequestCommitted(RequestCommitted {
            id: id.to_string(),
            seq,
            flow_key: flow_key.clone(),
            time: rfc3999z(&time),
            epoch_ms: time.timestamp_millis(),
            method: "WS".to_string(),
            protocol: req_protocol.clone(),
            host: req_host.clone(),
            uri: uri.path().to_string(),
            query_str: uri.query().unwrap_or_default().to_string(),
            version: version_to_string(parts.version),
            marks: Vec::new(),
        }));

    let req = Request::from_parts(parts, body);
    let started_at = std::time::Instant::now();

    let res = dispatcher.upstream_client().serve_websocket(req).await;

    let elapsed_ms = started_at.elapsed().as_millis() as i64;
    let (parts, body) = res.into_parts();
    let proxy_status = parts.status.as_u16();

    let res_head_text = build_response_head_text(
        parts.version,
        parts.status,
        &parts.headers,
    );

    let _ = tokio::fs::write(&res_head_path, res_head_text).await;
    let _ = tokio::fs::write(&res_body_path, WEBSOCKET_NOT_CAPTURED_MESSAGE).await;

    dbstate
        .event_sender
        .send(RequestResponseEvent::Response(ResponseMetadata {
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
            body_save_limit: dispatcher
                .config()
                .body_save_limit_bytes
                .map(|limit| limit as i64),
        }))
        .unwrap_or_else(|err| {
            tracing::error!("error sending websocket response event: {err:?}");
        });

    dispatcher
        .events()
        .publish(FlowEvent::ResponseCommitted(ResponseCommitted {
            id: id.to_string(),
            flow_key,
            status: proxy_status,
            elapsed_ms,
            version: version_to_string(parts.version),
            marks: Vec::new(),
        }));

    Response::from_parts(parts, body)
}

fn websocket_scheme_from_http_scheme(scheme: &str) -> String {
    match scheme {
        "https" => "wss".to_string(),
        "http" => "ws".to_string(),
        other => other.to_string(),
    }
}

fn rfc3999z(time: &DateTime<Utc>) -> String {
    time.to_rfc3339_opts(chrono::format::SecondsFormat::Millis, true)
}