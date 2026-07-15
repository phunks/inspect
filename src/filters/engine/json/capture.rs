use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use sqlx::types::JsonValue;
use crate::filters::{DiffEvent, DiffNode, DiffPath, DiffPathSegment, DiffSource, FilterHeader, FilterRequest, GeneratedJsonPatchOperation};
use crate::filters::engine::diff::BodyDiffSource::Json;
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


pub fn push_json_body_diff_events(
    events: &mut Vec<DiffEvent>,
    original: &str,
    edited: &str,
    content_type: Option<&str>,
) -> bool {
    if !looks_like_json(content_type, original) && !looks_like_json(content_type, edited) {
        return false;
    }

    let Ok(original_json) = serde_json::from_str::<JsonValue>(original) else {
        return false;
    };

    let Ok(edited_json) = serde_json::from_str::<JsonValue>(edited) else {
        return false;
    };

    diff_json_value(
        events,
        Vec::new(),
        &original_json,
        &edited_json,
    );

    true
}

pub fn push_json_body_insert_event(
    events: &mut Vec<DiffEvent>,
    text: &str,
    content_type: Option<&str>,
) -> bool {
    if !looks_like_json(content_type, text) {
        return false;
    }

    let Ok(json) = serde_json::from_str::<JsonValue>(text) else {
        return false;
    };

    events.push(DiffEvent::Insert {
        path: DiffPath::body(),
        node: json_value_to_diff_node(&json),
        source: DiffSource::Body(Json),
    });

    true
}

pub fn push_json_body_delete_event(
    events: &mut Vec<DiffEvent>,
    text: &str,
    content_type: Option<&str>,
) -> bool {
    if !looks_like_json(content_type, text) {
        return false;
    }

    let Ok(json) = serde_json::from_str::<JsonValue>(text) else {
        return false;
    };

    events.push(DiffEvent::Delete {
        path: DiffPath::body(),
        old: json_value_to_diff_node(&json),
        source: DiffSource::Body(Json),
    });

    true
}

fn diff_json_value(
    events: &mut Vec<DiffEvent>,
    path: Vec<DiffPathSegment>,
    original: &JsonValue,
    edited: &JsonValue,
) {
    if original == edited {
        return;
    }

    match (original, edited) {
        (JsonValue::Object(original_map), JsonValue::Object(edited_map)) => {
            for (key, original_value) in original_map {
                let mut next_path = path.clone();
                next_path.push(DiffPathSegment::JsonKey(key.clone()));

                match edited_map.get(key) {
                    Some(edited_value) => {
                        diff_json_value(events, next_path, original_value, edited_value);
                    }
                    None => {
                        events.push(DiffEvent::Delete {
                            path: DiffPath::body_json(next_path),
                            old: json_value_to_diff_node(original_value),
                            source: DiffSource::Body(Json),
                        });
                    }
                }
            }

            for (key, edited_value) in edited_map {
                if original_map.contains_key(key) {
                    continue;
                }

                let mut next_path = path.clone();
                next_path.push(DiffPathSegment::JsonKey(key.clone()));

                events.push(DiffEvent::Insert {
                    path: DiffPath::body_json(next_path),
                    node: json_value_to_diff_node(edited_value),
                    source: DiffSource::Body(Json),
                });
            }
        }
        (JsonValue::Array(original_items), JsonValue::Array(edited_items)) => {
            let common_len = original_items.len().min(edited_items.len());

            for idx in 0..common_len {
                let mut next_path = path.clone();
                next_path.push(DiffPathSegment::JsonIndex(idx));

                diff_json_value(
                    events,
                    next_path,
                    &original_items[idx],
                    &edited_items[idx],
                );
            }

            for (idx, item) in original_items.iter().enumerate().skip(common_len) {
                let mut next_path = path.clone();
                next_path.push(DiffPathSegment::JsonIndex(idx));

                events.push(DiffEvent::Delete {
                    path: DiffPath::body_json(next_path),
                    old: json_value_to_diff_node(item),
                    source: DiffSource::Body(Json),
                });
            }

            for (idx, item) in edited_items.iter().enumerate().skip(common_len) {
                let mut next_path = path.clone();
                next_path.push(DiffPathSegment::JsonIndex(idx));

                events.push(DiffEvent::Insert {
                    path: DiffPath::body_json(next_path),
                    node: json_value_to_diff_node(item),
                    source: DiffSource::Body(Json),
                });
            }
        }
        _ => {
            events.push(DiffEvent::Replace {
                path: DiffPath::body_json(path),
                old: json_value_to_diff_node(original),
                new: json_value_to_diff_node(edited),
                source: DiffSource::Body(Json),
            });
        }
    }
}

fn json_value_to_diff_node(value: &JsonValue) -> DiffNode {
    match value {
        JsonValue::Null => DiffNode::Null,
        JsonValue::Bool(value) => DiffNode::Bool(*value),
        JsonValue::Number(value) => DiffNode::Number(value.to_string()),
        JsonValue::String(value) => DiffNode::String(value.clone()),
        JsonValue::Array(_) | JsonValue::Object(_) => DiffNode::Json {
            raw: value.to_string(),
        },
    }
}

fn looks_like_json(content_type: Option<&str>, text: &str) -> bool {
    if content_type
        .is_some_and(|content_type| {
            let content_type = content_type
                .split(';')
                .next()
                .unwrap_or(content_type)
                .trim()
                .to_ascii_lowercase();

            content_type == "application/json"
                || content_type.ends_with("+json")
                || content_type == "text/json"
        })
    {
        return true;
    }

    let text = text.trim_start();

    text.starts_with('{') || text.starts_with('[')
}

pub fn json_patch_operations_from_diff_events(
    events: &[DiffEvent],
) -> Vec<GeneratedJsonPatchOperation> {
    events
        .iter()
        .filter_map(json_patch_operation_from_diff_event)
        .collect()
}

fn json_patch_operation_from_diff_event(
    event: &DiffEvent,
) -> Option<GeneratedJsonPatchOperation> {
    if event.source() != DiffSource::Body(Json) {
        return None;
    }

    match event {
        DiffEvent::Insert { path, node, .. } => Some(GeneratedJsonPatchOperation::Add {
            path: json_pointer_from_diff_path(path)?,
            value: diff_node_to_json_patch_value(node),
        }),
        DiffEvent::Delete { path, .. } => Some(GeneratedJsonPatchOperation::Remove {
            path: json_pointer_from_diff_path(path)?,
        }),
        DiffEvent::Replace { path, new, .. } => Some(GeneratedJsonPatchOperation::Replace {
            path: json_pointer_from_diff_path(path)?,
            value: diff_node_to_json_patch_value(new),
        }),
        DiffEvent::Move { from, to, .. } => Some(GeneratedJsonPatchOperation::Move {
            from: json_pointer_from_diff_path(from)?,
            path: json_pointer_from_diff_path(to)?,
        }),
    }
}

pub fn json_pointer_from_diff_path(path: &DiffPath) -> Option<String> {
    let mut out = String::new();
    let mut seen_body = false;

    for segment in &path.segments {
        match segment {
            DiffPathSegment::Body => {
                seen_body = true;
            }
            DiffPathSegment::JsonKey(key) if seen_body => {
                out.push('/');
                out.push_str(&escape_json_pointer_segment(key));
            }
            DiffPathSegment::JsonIndex(index) if seen_body => {
                out.push('/');
                out.push_str(&index.to_string());
            }
            _ => {}
        }
    }

    if seen_body {
        Some(out)
    } else {
        None
    }
}

fn escape_json_pointer_segment(segment: &str) -> String {
    segment
        .replace('~', "~0")
        .replace('/', "~1")
}

fn diff_node_to_json_patch_value(node: &DiffNode) -> String {
    match node {
        DiffNode::Null => "null".to_string(),
        DiffNode::Bool(value) => value.to_string(),
        DiffNode::Number(value) => value.clone(),
        DiffNode::String(value) | DiffNode::Text(value) => {
            serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
        }
        DiffNode::Json { raw } => {
            serde_json::from_str::<JsonValue>(raw)
                .map(|value| value.to_string())
                .unwrap_or_else(|_| serde_json::to_string(raw).unwrap_or_else(|_| "null".to_string()))
        }
        DiffNode::Xml { name, text } => serde_json::json!({
            "name": name,
            "text": text,
        })
            .to_string(),
        DiffNode::Html { tag, text } => serde_json::json!({
            "tag": tag,
            "text": text,
        })
            .to_string(),
        DiffNode::Ast { kind, text } => serde_json::json!({
            "kind": kind,
            "text": text,
        })
            .to_string(),
        DiffNode::BytesLen(value) => value.to_string(),
        DiffNode::Header { name, value } => serde_json::json!({
            "name": name,
            "value": value,
        })
            .to_string(),
        DiffNode::Cookie { name, value } => serde_json::json!({
            "name": name,
            "value": value,
        })
            .to_string(),
        DiffNode::Binary {
            bytes_len,
            content_type,
        } => serde_json::json!({
            "bytes_len": bytes_len,
            "content_type": content_type,
        })
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use crate::filters::{
        extract_response_filter_from_edit,
        json_patch_operations_to_rfc6902_json,
        EditableHttpBody,
        EditableHttpHeader,
        EditableHttpMessage,
        EditableHttpMessageKind
    };

    use super::*;

    #[test]
    fn generated_json_patch_operations_emit_rfc6902_json() {
        let operations = vec![
            GeneratedJsonPatchOperation::Replace {
                path: "/user/name".to_string(),
                value: "\"bob\"".to_string(),
            },
            GeneratedJsonPatchOperation::Add {
                path: "/user/enabled".to_string(),
                value: "true".to_string(),
            },
            GeneratedJsonPatchOperation::Remove {
                path: "/user/old".to_string(),
            },
        ];

        let json = json_patch_operations_to_rfc6902_json(&operations);
        let value = serde_json::from_str::<JsonValue>(&json)
            .expect("generated patch should be valid JSON");

        assert_eq!(value[0]["op"], "replace");
        assert_eq!(value[0]["path"], "/user/name");
        assert_eq!(value[0]["value"], "bob");
        assert_eq!(value[1]["op"], "add");
        assert_eq!(value[1]["path"], "/user/enabled");
        assert_eq!(value[1]["value"], true);
        assert_eq!(value[2]["op"], "remove");
        assert_eq!(value[2]["path"], "/user/old");
    }

    #[test]
    fn response_json_edit_generates_json_patch_action_comment_and_body_rewrite() {
        let request = EditableHttpMessage {
            kind: EditableHttpMessageKind::Request,
            method: Some("GET".to_string()),
            scheme: Some("https".to_string()),
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: None,
            headers: Vec::new(),
            body: EditableHttpBody::Empty,
        };

        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: None,
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: Some(200),
            headers: vec![EditableHttpHeader {
                name: "content-type".to_string(),
                value: "application/json; charset=utf-8".to_string(),
            }],
            body: EditableHttpBody::Text {
                text: r#"{"user":{"name":"alice","role":"user"}}"#.to_string(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
        };

        let edited = EditableHttpMessage {
            body: EditableHttpBody::Text {
                text: r#"{"user":{"name":"bob","role":"admin"}}"#.to_string(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
            ..original.clone()
        };

        let filter = extract_response_filter_from_edit(
            "json patch response",
            &request,
            &original,
            &edited,
        )
            .expect("json edit should produce generated filter");

        let source = filter.to_roto_source();

        assert!(source.contains("JSON patch operations:"));
        assert!(source.contains("// - replace /user/name = \"bob\""));
        assert!(source.contains("// - replace /user/role = \"admin\""));
        assert!(source.contains(".apply_json_patch("));
        assert!(source.contains("\"op\": \"replace\""));
        assert!(source.contains("\"path\": \"/user/name\""));
        assert!(source.contains("\"value\": \"bob\""));
        assert!(source.contains("\"path\": \"/user/role\""));
        assert!(source.contains("\"value\": \"admin\""));
    }

    #[test]
    fn json_pointer_escapes_special_segments() {
        let path = DiffPath::body_json(vec![
            DiffPathSegment::JsonKey("a/b".to_string()),
            DiffPathSegment::JsonKey("c~d".to_string()),
        ]);

        assert_eq!(
            json_pointer_from_diff_path(&path),
            Some("/a~1b/c~0d".to_string()),
        );
    }

    #[test]
    fn semantic_diff_detects_json_body_replace_insert_delete() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: None,
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: Some(200),
            headers: vec![EditableHttpHeader {
                name: "content-type".to_string(),
                value: "application/json; charset=utf-8".to_string(),
            }],
            body: EditableHttpBody::Text {
                text: r#"{"error":"not found","id":123,"keep":true}"#.to_string(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
        };

        let edited = EditableHttpMessage {
            body: EditableHttpBody::Text {
                text: r#"{"ok":true,"id":456,"keep":true}"#.to_string(),
                content_type: Some("application/json; charset=utf-8".to_string()),
            },
            ..original.clone()
        };

        let events = original.semantic_diff(&edited);
        let summaries = events
            .iter()
            .map(DiffEvent::summary)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(summaries.contains("delete /body/error"));
        assert!(summaries.contains("insert /body/ok"));
        assert!(summaries.contains("replace /body/id: 123 -> 456"));
        assert!(!summaries.contains("/body/keep"));
    }

    #[test]
    fn semantic_diff_detects_json_nested_replace() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: None,
            host: "api.example.com".to_string(),
            path: "/v1/users/123".to_string(),
            query: String::new(),
            status: Some(200),
            headers: vec![EditableHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: EditableHttpBody::Text {
                text: r#"{"user":{"name":"alice","roles":["user"]}}"#.to_string(),
                content_type: Some("application/json".to_string()),
            },
        };

        let edited = EditableHttpMessage {
            body: EditableHttpBody::Text {
                text: r#"{"user":{"name":"bob","roles":["user","admin"]}}"#.to_string(),
                content_type: Some("application/json".to_string()),
            },
            ..original.clone()
        };

        let events = original.semantic_diff(&edited);
        let summaries = events
            .iter()
            .map(DiffEvent::summary)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(summaries.contains("replace /body/user/name"));
        assert!(summaries.contains("insert /body/user/roles/1"));
    }

    #[test]
    fn semantic_diff_falls_back_to_text_for_invalid_json() {
        let original = EditableHttpMessage {
            kind: EditableHttpMessageKind::Response,
            method: None,
            scheme: None,
            host: "api.example.com".to_string(),
            path: "/broken".to_string(),
            query: String::new(),
            status: Some(200),
            headers: vec![EditableHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            }],
            body: EditableHttpBody::Text {
                text: r#"{"broken":"#.to_string(),
                content_type: Some("application/json".to_string()),
            },
        };

        let edited = EditableHttpMessage {
            body: EditableHttpBody::Text {
                text: r#"{"ok":true}"#.to_string(),
                content_type: Some("application/json".to_string()),
            },
            ..original.clone()
        };

        let events = original.semantic_diff(&edited);
        let summaries = events
            .iter()
            .map(DiffEvent::summary)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(summaries.contains("replace /body"));
    }
}