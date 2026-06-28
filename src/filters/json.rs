
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use crate::filters::{FilterHeader, FilterRequest};
use crate::mitm::flow::filter_bridge::normalized_content_type;
use crate::mitm::flow::http_types::ResponseDispatchInput;

pub fn json_filter_request_bytes(req: &FilterRequest) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": req.id,
        "seq": req.seq,
        "flow_key": req.flow_key,
        "method": req.method,
        "scheme": req.scheme,
        "host": req.host,
        "path": req.path,
        "query": req.query,
        "version": req.version,
        "tls_sni": req.tls_sni,
        "headers": json_filter_headers(&req.headers),
        "body": json_body(
            req.body.content_type.as_deref(),
            req.body.encoding.as_deref(),
            req.body.truncated,
            &req.body.bytes,
        ),
    }))
        .unwrap_or_else(|err| {
            tracing::warn!(error = ?err, "failed to serialize captured request json");
            b"{}".to_vec()
        })
}

pub fn json_filter_response_bytes(
    res_parts: &rama::http::response::Parts,
    res_body_bytes: &Bytes,
    upstream_status: Option<u16>,
    elapsed_ms: i64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "status": res_parts.status.as_u16(),
        "version": crate::mitm::flow::capture_service::version_to_string(res_parts.version),
        "upstream_status": upstream_status,
        "elapsed_ms": elapsed_ms,
        "headers": json_header_map(&res_parts.headers),
        "body": json_body(
            normalized_content_type(&res_parts.headers).as_deref(),
            res_parts
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            false,
            res_body_bytes,
        ),
    }))
        .unwrap_or_else(|err| {
            tracing::warn!(error = ?err, "failed to serialize captured response json");
            b"{}".to_vec()
        })
}

pub(crate) fn json_filter_flow_bytes(
    input: &ResponseDispatchInput,
    res_parts: &rama::http::response::Parts,
    res_body_bytes: &Bytes,
    elapsed_ms: i64,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": input.id.to_string(),
        "seq": input.seq,
        "flow_key": input.flow_key,
        "request": serde_json::from_slice::<serde_json::Value>(
            &json_filter_request_bytes(&input.filter_request),
        ).unwrap_or_else(|_| serde_json::json!({})),
        "response": serde_json::from_slice::<serde_json::Value>(
            &json_filter_response_bytes(
                res_parts,
                res_body_bytes,
                input.upstream_status,
                elapsed_ms,
            ),
        ).unwrap_or_else(|_| serde_json::json!({})),
    }))
        .unwrap_or_else(|err| {
            tracing::warn!(error = ?err, "failed to serialize captured flow json");
            b"{}".to_vec()
        })
}

fn json_filter_headers(headers: &[FilterHeader]) -> serde_json::Value {
    serde_json::Value::Array(
        headers
            .iter()
            .map(|header| {
                serde_json::json!({
                    "name": header.name,
                    "value": header.value,
                })
            })
            .collect(),
    )
}

fn json_header_map(headers: &http::HeaderMap) -> serde_json::Value {
    serde_json::Value::Array(
        headers
            .iter()
            .map(|(name, value)| {
                serde_json::json!({
                    "name": name.as_str(),
                    "value": value
                        .to_str()
                        .map(str::to_string)
                        .unwrap_or_else(|_| STANDARD.encode(value.as_bytes())),
                })
            })
            .collect(),
    )
}

fn json_body(
    content_type: Option<&str>,
    encoding: Option<&str>,
    truncated: bool,
    bytes: &[u8],
) -> serde_json::Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => serde_json::json!({
            "content_type": content_type,
            "encoding": encoding,
            "truncated": truncated,
            "text": text,
            "base64": null,
        }),
        Err(_) => serde_json::json!({
            "content_type": content_type,
            "encoding": encoding,
            "truncated": truncated,
            "text": null,
            "base64": STANDARD.encode(bytes),
        }),
    }
}