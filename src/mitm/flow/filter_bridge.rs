use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::HeaderValue;
use rama::http::StatusCode;
use uuid::Uuid;

use crate::filters::{
    FilterBody,
    FilterHeader,
    FilterRequest,
    FilterRequestPatch,
    FilterResponse,
    FilterResponsePatch,
    RequestAction,
    ResponseAction,
};
use crate::mitm::flow::FlowMark;
use crate::mitm::flow::capture_service::version_to_string;
use crate::mitm::flow::body_encoding::decoded_body_or_raw;


pub(crate) fn flow_marks_from_request_action(action: &RequestAction) -> Vec<FlowMark> {
    let mut marks = Vec::new();

    marks.extend(action.marks.iter().map(|mark| FlowMark {
        label: mark.label.clone(),
        color: mark.color.clone(),
    }));

    marks.extend(action.tags.iter().map(|tag| FlowMark {
        label: tag.clone(),
        color: Some("green".to_string()),
    }));

    marks.extend(action.notes.iter().map(|note| FlowMark {
        label: note.clone(),
        color: Some("blue".to_string()),
    }));

    marks
}

pub(crate) fn flow_marks_from_response_action(action: &ResponseAction) -> Vec<FlowMark> {
    let mut marks = Vec::new();

    marks.extend(action.marks.iter().map(|mark| FlowMark {
        label: mark.label.clone(),
        color: mark.color.clone(),
    }));

    marks.extend(action.tags.iter().map(|tag| FlowMark {
        label: tag.clone(),
        color: Some("green".to_string()),
    }));

    marks.extend(action.notes.iter().map(|note| FlowMark {
        label: note.clone(),
        color: Some("blue".to_string()),
    }));

    marks
}

pub(crate) fn merge_request_action(dst: &mut RequestAction, src: RequestAction) {
    if src.request.is_some() {
        dst.request = src.request;
    }

    if src.synthetic_response.is_some() {
        dst.synthetic_response = src.synthetic_response;
        dst.continue_filters = false;
    } else {
        dst.continue_filters = src.continue_filters;
    }

    dst.drop_client_response = dst.drop_client_response || src.drop_client_response;

    dst.marks.extend(src.marks);
    dst.tags.extend(src.tags);
    dst.notes.extend(src.notes);
    dst.outbound_http.extend(src.outbound_http);
}

pub(crate) fn merge_response_action(dst: &mut ResponseAction, src: ResponseAction) {
    if src.response.is_some() {
        dst.response = src.response;
    }

    dst.marks.extend(src.marks);
    dst.tags.extend(src.tags);
    dst.notes.extend(src.notes);
    dst.outbound_http.extend(src.outbound_http);
    dst.continue_filters = src.continue_filters;
    dst.drop_client_response = dst.drop_client_response || src.drop_client_response;
}

fn filter_headers_from_header_map(headers: &http::HeaderMap) -> Vec<FilterHeader> {
    headers
        .iter()
        .map(|(name, value)| FilterHeader {
            name: name.as_str().to_string(),
            value: value
                .to_str()
                .map(str::to_string)
                .unwrap_or_else(|_| STANDARD.encode(value.as_bytes())),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_filter_request(
    id: &Uuid,
    seq: u64,
    flow_key: &str,
    parts: &rama::http::request::Parts,
    req_protocol: &str,
    req_host: &str,
    req_body_bytes: &Bytes,
    tls_sni: Option<String>,
) -> FilterRequest {
    let body_text_bytes = decoded_body_or_raw(&parts.headers, req_body_bytes);

    FilterRequest {
        id: id.to_string(),
        seq,
        flow_key: flow_key.to_string(),
        method: parts.method.as_str().to_string(),
        scheme: req_protocol.to_string(),
        host: req_host.to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or_default().to_string(),
        version: version_to_string(parts.version),
        headers: filter_headers_from_header_map(&parts.headers),
        body: FilterBody {
            bytes: req_body_bytes.to_vec(),
            text: std::str::from_utf8(body_text_bytes.as_ref()).ok().map(str::to_string),
            content_type: normalized_content_type(&parts.headers),
            encoding: parts
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            truncated: false,
        },
        tls_sni,
    }
}

pub(crate) fn build_filter_response(
    parts: &rama::http::response::Parts,
    res_body_bytes: &Bytes,
    upstream_status: Option<u16>,
    elapsed_ms: i64,
) -> FilterResponse {
    let body_text_bytes = decoded_body_or_raw(&parts.headers, res_body_bytes);

    FilterResponse {
        status: parts.status.as_u16(),
        version: version_to_string(parts.version),
        headers: filter_headers_from_header_map(&parts.headers),
        body: FilterBody {
            bytes: res_body_bytes.to_vec(),
            text: std::str::from_utf8(body_text_bytes.as_ref()).ok().map(str::to_string),
            content_type: normalized_content_type(&parts.headers),
            encoding: parts
                .headers
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            truncated: false,
        },
        upstream_status,
        elapsed_ms: Some(elapsed_ms),
    }
}

pub(crate) fn normalized_content_type(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

pub(crate) fn apply_request_patch(
    parts: &mut rama::http::request::Parts,
    body: &mut Bytes,
    patch: FilterRequestPatch,
) {
    if let Some(method) = patch.method {
        match method.parse() {
            Ok(method) => {
                parts.method = method;
            }
            Err(err) => {
                tracing::warn!(
                    method,
                    error = ?err,
                    "ignored invalid request method from filter patch"
                );
            }
        }
    }

    if patch.path.is_some() || patch.query.is_some() {
        let current_path = parts.uri.path().to_string();
        let current_query = parts.uri.query().map(str::to_string);

        let next_path = patch.path.unwrap_or(current_path);
        let next_query = patch.query.or(current_query);

        let path_and_query = match next_query {
            Some(query) if !query.is_empty() => format!("{next_path}?{query}"),
            _ => next_path,
        };

        match path_and_query.parse() {
            Ok(path_and_query) => {
                let mut uri_parts = parts.uri.clone().into_parts();
                uri_parts.path_and_query = Some(path_and_query);

                match http::Uri::from_parts(uri_parts) {
                    Ok(uri) => {
                        parts.uri = uri;
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = ?err,
                            "ignored invalid request uri from filter patch"
                        );
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    path_and_query,
                    error = ?err,
                    "ignored invalid request path/query from filter patch"
                );
            }
        }
    }

    apply_header_patch(
        &mut parts.headers,
        patch.set_headers,
        patch.remove_headers,
    );

    if let Some(body_patch) = patch.body {
        *body = Bytes::from(body_patch.bytes);

        remove_body_integrity_headers(&mut parts.headers);

        if let Some(content_type) = body_patch.content_type {
            match HeaderValue::from_str(&content_type) {
                Ok(value) => {
                    parts.headers.insert(http::header::CONTENT_TYPE, value);
                }
                Err(err) => {
                    tracing::warn!(
                        content_type,
                        error = ?err,
                        "ignored invalid request content-type from filter patch"
                    );
                }
            }
        }
    }
}

pub(crate) fn apply_response_patch(
    parts: &mut rama::http::response::Parts,
    body: &mut Bytes,
    patch: FilterResponsePatch,
) {
    if let Some(status) = patch.status {
        match StatusCode::from_u16(status) {
            Ok(status) => {
                parts.status = status;
            }
            Err(err) => {
                tracing::warn!(
                    status,
                    error = ?err,
                    "ignored invalid response status from filter patch"
                );
            }
        }
    }

    apply_header_patch(
        &mut parts.headers,
        patch.set_headers,
        patch.remove_headers,
    );

    if let Some(body_patch) = patch.body {
        *body = Bytes::from(body_patch.bytes);

        remove_body_integrity_headers(&mut parts.headers);

        if let Some(content_type) = body_patch.content_type {
            match HeaderValue::from_str(&content_type) {
                Ok(value) => {
                    parts.headers.insert(http::header::CONTENT_TYPE, value);
                }
                Err(err) => {
                    tracing::warn!(
                        content_type,
                        error = ?err,
                        "ignored invalid response content-type from filter patch"
                    );
                }
            }
        }
    }
}

fn apply_header_patch(
    headers: &mut http::HeaderMap,
    set_headers: Vec<FilterHeader>,
    remove_headers: Vec<String>,
) {
    for name in remove_headers {
        match http::HeaderName::from_bytes(name.as_bytes()) {
            Ok(name) => {
                headers.remove(name);
            }
            Err(err) => {
                tracing::warn!(
                    header = name,
                    error = ?err,
                    "ignored invalid header name from filter remove patch"
                );
            }
        }
    }

    for header in set_headers {
        let name = match http::HeaderName::from_bytes(header.name.as_bytes()) {
            Ok(name) => name,
            Err(err) => {
                tracing::warn!(
                    header = header.name,
                    error = ?err,
                    "ignored invalid header name from filter set patch"
                );
                continue;
            }
        };

        let value = match HeaderValue::from_str(&header.value) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    header = header.name,
                    error = ?err,
                    "ignored invalid header value from filter set patch"
                );
                continue;
            }
        };

        headers.insert(name, value);
    }
}

fn remove_body_integrity_headers(headers: &mut http::HeaderMap) {
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::CONTENT_ENCODING);
    headers.remove(http::header::ETAG);
    headers.remove("content-md5");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::{RequestAction, ResponseAction};

    #[test]
    fn merge_request_action_or_drop_flag_when_src_true() {
        let mut dst = RequestAction::pass();
        dst.drop_client_response = false;

        let mut src = RequestAction::pass();
        src.drop_client_response = true;

        merge_request_action(&mut dst, src);

        assert!(dst.drop_client_response);
    }

    #[test]
    fn merge_request_action_keeps_drop_true_when_dst_already_true() {
        let mut dst = RequestAction::pass();
        dst.drop_client_response = true;

        let mut src = RequestAction::pass();
        src.drop_client_response = false;

        merge_request_action(&mut dst, src);

        assert!(dst.drop_client_response);
    }

    #[test]
    fn merge_response_action_or_drop_flag() {
        let mut dst = ResponseAction::pass();
        dst.drop_client_response = false;

        let mut src = ResponseAction::pass();
        src.drop_client_response = true;

        merge_response_action(&mut dst, src);

        assert!(dst.drop_client_response);
    }
}