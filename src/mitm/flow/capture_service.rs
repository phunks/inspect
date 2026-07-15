use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{HeaderMap, StatusCode, Version};
use serde_json::{json, Value};
use std::io;
use std::path::PathBuf;
use uuid::Uuid;

use crate::mitm::capture::CapturePaths;
use crate::mitm::flow::body_encoding::decoded_body_or_raw;
use crate::mitm::flow::filter_bridge::normalized_content_type;
use crate::mitm::store_metadata::{DbState, FilterExecStatMetadata, RequestMetadata, RequestResponseEvent, ResponseMetadata};

#[derive(Clone, Debug)]
pub struct TunnelFailureCapture {
    pub id: String,
    pub seq: u64,
    pub flow_key: String,
    pub flow_dir: PathBuf,
    pub time: DateTime<Utc>,
    pub host: String,
    pub port: u16,
    pub stage: String,
    pub error: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FilterResourceStats {
    pub state_read_bytes: i64,
    pub state_write_bytes: i64,
    pub state_items: i64,
    pub evicted_items: i64,
    pub limit_hit: bool,
}

impl FilterResourceStats {
    pub fn merge(self, rhs: Self) -> Self {
        Self {
            state_read_bytes: self.state_read_bytes + rhs.state_read_bytes,
            state_write_bytes: self.state_write_bytes + rhs.state_write_bytes,
            state_items: rhs.state_items,
            evicted_items: self.evicted_items + rhs.evicted_items,
            limit_hit: self.limit_hit || rhs.limit_hit,
        }
    }
}

#[derive(Clone)]
pub struct CaptureService {
    dbstate: DbState,
    paths: CapturePaths,
    body_save_limit_bytes: Option<usize>,
    body_omit_content_types: Vec<String>,
}

impl CaptureService {
    pub fn new(
        dbstate: DbState,
        paths: CapturePaths,
        body_save_limit_bytes: Option<usize>,
        body_omit_content_types: Vec<String>,
    ) -> Self {
        Self {
            dbstate,
            paths,
            body_save_limit_bytes,
            body_omit_content_types: body_omit_content_types
                .into_iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
        }
    }

    pub async fn commit_tunnel_failure(
        &self,
        capture: TunnelFailureCapture,
    ) -> anyhow::Result<()> {
        tokio::fs::create_dir_all(&capture.flow_dir)
            .await
            .with_context(|| format!("create tunnel failure dir {}", capture.flow_dir.display()))?;

        let ssl_tls_path = capture.flow_dir.join("ssl_tls.json");

        let failure = json!({
            "kind": "tls_tunnel_failure",
            "method": "CONNECT",
            "target": format!("{}:{}", capture.host, capture.port),
            "host": capture.host,
            "port": capture.port,
            "time": rfc3999z(&capture.time),
            "epoch_ms": capture.time.timestamp_millis(),
            "stage": capture.stage,
            "result": "failed",
            "error": capture.error,
        });

        let failure_json = serde_json::to_vec_pretty(&failure)
            .context("serialize TLS tunnel failure metadata")?;

        tokio::fs::write(&ssl_tls_path, &failure_json)
            .await
            .with_context(|| format!("write {}", ssl_tls_path.display()))?;

        let time = rfc3999z(&capture.time);

        self.dbstate
            .event_sender
            .send(RequestResponseEvent::Request(RequestMetadata {
                id: capture.id,
                seq: capture.seq as i64,
                flow_key: capture.flow_key,
                flow_dir: capture.flow_dir.to_string_lossy().to_string(),
                request_head_path: String::new(),
                request_body_path: String::new(),
                time,
                epoch_ms: capture.time.timestamp_millis(),
                method: "CONNECT".to_string(),
                protocol: "https".to_string(),
                host: capture.host,
                uri: String::new(),
                query_str: String::new(),
                version: String::new(),
                tls_sni: None,
                headers: json!({}),
                body_size: 0,
                body_saved_size: 0,
                body_truncated: false,
                body_save_limit: None,
            }))
            .map_err(|err| anyhow::anyhow!("queue tunnel failure request metadata: {err}"))?;

        Ok(())
    }

    pub fn paths(&self) -> &CapturePaths {
        &self.paths
    }

    pub fn dbstate(&self) -> &DbState {
        &self.dbstate
    }

    pub async fn commit_request(
        &self,
        capture: EffectiveRequestCapture,
    ) -> anyhow::Result<RequestCommit> {
        tokio::fs::create_dir_all(&capture.flow_dir)
            .await
            .with_context(|| {
                format!("create flow dir {}", capture.flow_dir.display())
            })?;

        let request_head_path = capture.flow_dir.join("request.head");
        let request_body_path = capture
            .flow_dir
            .join(body_file_name("request.body", &capture.headers));

        let request_head_text = build_request_head_text(
            &capture.method,
            &capture.uri,
            capture.version,
            &capture.headers,
            capture.tls_sni.as_deref(),
        );

        tokio::fs::write(&request_head_path, request_head_text)
            .await
            .with_context(|| {
                format!("write request head {}", request_head_path.display())
            })?;

        let omit_reason = body_omit_reason_by_content_type(
            &capture.headers,
            &self.body_omit_content_types,
        );

        let stored_body_bytes = if let Some(reason) = omit_reason.as_deref() {
            Bytes::from(format!("<body omitted by inspect: {reason}>\n"))
        } else if self.body_save_limit_bytes.is_none() {
            capture.body_bytes.clone()
        } else {
            request_body_for_storage(&capture.headers, &capture.body_bytes)
        };

        let storage_info = if omit_reason.is_some() {
            BodyStorageInfo {
                saved_size: stored_body_bytes.len(),
                truncated: true,
            }
        } else {
            body_storage_info(stored_body_bytes.len(), self.body_save_limit_bytes)
        };

        let body_save_limit = if omit_reason.is_some() {
            Some(0)
        } else {
            self.body_save_limit_bytes.map(|limit| limit as i64)
        };

        write_body_for_storage(
            &request_body_path,
            &stored_body_bytes,
            if omit_reason.is_some() {
                None
            } else {
                self.body_save_limit_bytes
            },
        )
            .await
            .with_context(|| {
                format!("write request body {}", request_body_path.display())
            })?;

        let time = rfc3999z(&capture.time);
        let epoch_ms = capture.time.timestamp_millis();
        let uri = capture.uri.path().to_string();
        let query_str = capture.uri.query().unwrap_or_default().to_string();
        let version = version_to_string(capture.version);

        self.dbstate
            .event_sender
            .send(RequestResponseEvent::Request(RequestMetadata {
                id: capture.id.to_string(),
                seq: capture.seq as i64,
                flow_key: capture.flow_key.clone(),
                flow_dir: capture.flow_dir.to_string_lossy().to_string(),
                request_head_path: request_head_path.to_string_lossy().to_string(),
                request_body_path: request_body_path.to_string_lossy().to_string(),
                time: time.clone(),
                epoch_ms,
                method: capture.method.clone(),
                protocol: capture.protocol.clone(),
                host: capture.host.clone(),
                uri: uri.clone(),
                query_str: query_str.clone(),
                version: version.clone(),
                tls_sni: capture.tls_sni.clone(),
                headers: headers_to_json(&capture.headers),
                body_size: capture.body_bytes.len() as i64,
                body_saved_size: storage_info.saved_size as i64,
                body_truncated: storage_info.truncated,
                body_save_limit,
            }))
            .unwrap_or_else(|err| {
                tracing::error!("error sending request event: {err:?}");
            });

        Ok(RequestCommit {
            id: capture.id.to_string(),
            seq: capture.seq,
            flow_key: capture.flow_key,
            flow_dir: capture.flow_dir,
            request_head_path,
            request_body_path,
            time,
            epoch_ms,
            method: capture.method,
            protocol: capture.protocol,
            host: capture.host,
            uri,
            query_str,
            version,
        })
    }

    pub async fn commit_response(
        &self,
        capture: EffectiveResponseCapture,
    ) -> anyhow::Result<ResponseCommit> {
        tokio::fs::create_dir_all(&capture.flow_dir)
            .await
            .with_context(|| {
                format!("create flow dir {}", capture.flow_dir.display())
            })?;

        let response_head_path = capture.flow_dir.join("response.head");
        let response_body_path = capture
            .flow_dir
            .join(body_file_name("response.body", &capture.headers));
        let ssl_tls_path = capture.flow_dir.join("ssl_tls.json");

        let ssl_tls_json = json!({
            "request": {
                "tls_sni": capture.tls_sni,
            },
            "response": {
                "upstream_tls": capture.tls_upstream,
                "origin": capture.origin.as_str(),
            }
        });

        let ssl_tls_text = serde_json::to_string_pretty(&ssl_tls_json)
            .unwrap_or_else(|_| ssl_tls_json.to_string());

        tokio::fs::write(&ssl_tls_path, ssl_tls_text)
            .await
            .with_context(|| {
                format!("write ssl tls info {}", ssl_tls_path.display())
            })?;

        let response_head_text = build_response_head_text(
            capture.version,
            capture.status,
            &capture.headers,
        );

        tokio::fs::write(&response_head_path, response_head_text)
            .await
            .with_context(|| {
                format!("write response head {}", response_head_path.display())
            })?;

        let body_size = capture.body_bytes.len() as i64;
        let body_saved_size;
        let body_truncated;
        let body_save_limit;

        if let Some(msg) = capture.upstream_error_message.as_deref() {
            let storage_info = body_storage_info(msg.len(), self.body_save_limit_bytes);
            body_saved_size = storage_info.saved_size as i64;
            body_truncated = storage_info.truncated;
            body_save_limit = self.body_save_limit_bytes.map(|limit| limit as i64);

            write_body_for_storage(
                &response_body_path,
                msg.as_bytes(),
                self.body_save_limit_bytes,
            )
                .await
                .with_context(|| {
                    format!("write response error body {}", response_body_path.display())
                })?;
        } else {
            let omit_reason = body_omit_reason_by_content_type(
                &capture.headers,
                &self.body_omit_content_types,
            );

            let stored_body_bytes = if let Some(reason) = omit_reason.as_deref() {
                Bytes::from(format!("<body omitted by inspect: {reason}>\n"))
            } else if self.body_save_limit_bytes.is_none() {
                capture.body_bytes.clone()
            } else {
                body_for_storage(&capture.headers, &capture.body_bytes)
            };

            let storage_info = if omit_reason.is_some() {
                BodyStorageInfo {
                    saved_size: stored_body_bytes.len(),
                    truncated: true,
                }
            } else {
                body_storage_info(stored_body_bytes.len(), self.body_save_limit_bytes)
            };

            body_saved_size = storage_info.saved_size as i64;
            body_truncated = storage_info.truncated;
            body_save_limit = if omit_reason.is_some() {
                Some(0)
            } else {
                self.body_save_limit_bytes.map(|limit| limit as i64)
            };

            write_body_for_storage(
                &response_body_path,
                &stored_body_bytes,
                if omit_reason.is_some() {
                    None
                } else {
                    self.body_save_limit_bytes
                },
            )
                .await
                .with_context(|| {
                    format!("write response body {}", response_body_path.display())
                })?;
        }

        let status = capture.status.as_u16();
        let display_status = capture.upstream_status.unwrap_or(status);
        let version = version_to_string(capture.version);

        self.dbstate
            .event_sender
            .send(RequestResponseEvent::Response(ResponseMetadata {
                id: capture.id.to_string(),
                seq: capture.seq as i64,
                flow_key: capture.flow_key.clone(),
                flow_dir: capture.flow_dir.to_string_lossy().to_string(),
                response_head_path: response_head_path.to_string_lossy().to_string(),
                response_body_path: response_body_path.to_string_lossy().to_string(),
                elapsed: capture.elapsed_ms,
                status,
                upstream_status: capture.upstream_status,
                version: version.clone(),
                tls_upstream: capture.tls_upstream.clone(),
                upstream_remote_addr: capture.upstream_remote_addr.clone(),
                headers: headers_to_json(&capture.headers),
                body_size,
                body_saved_size,
                body_truncated,
                body_save_limit,
            }))
            .unwrap_or_else(|err| {
                tracing::error!("error sending response event: {err:?}");
            });

        Ok(ResponseCommit {
            id: capture.id.to_string(),
            seq: capture.seq,
            flow_key: capture.flow_key,
            flow_dir: capture.flow_dir,
            response_head_path,
            response_body_path,
            elapsed_ms: capture.elapsed_ms,
            status,
            display_status,
            version,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_filter_exec_stat(
        &self,
        id: &str,
        seq: u64,
        flow_key: &str,
        phase: &str,
        filter_id: Option<&str>,
        filter_name: &str,
        elapsed_us: i64,
        result_code: i64,
        resource_stats: FilterResourceStats,
    ) {
        self.dbstate
            .event_sender
            .send(RequestResponseEvent::FilterExecStat(FilterExecStatMetadata {
                id: id.to_string(),
                seq: seq as i64,
                flow_key: flow_key.to_string(),
                phase: phase.to_string(),
                filter_id: filter_id.map(str::to_string),
                filter_name: filter_name.to_string(),
                elapsed_us,
                result_code,
                state_read_bytes: resource_stats.state_read_bytes,
                state_write_bytes: resource_stats.state_write_bytes,
                state_items: resource_stats.state_items,
                evicted_items: resource_stats.evicted_items,
                limit_hit: i64::from(resource_stats.limit_hit),
            }))
            .unwrap_or_else(|err| {
                tracing::error!("error sending filter exec stat event: {err:?}");
            });
    }
}

pub struct EffectiveRequestCapture {
    pub id: Uuid,
    pub seq: u64,
    pub flow_key: String,
    pub time: DateTime<Utc>,
    pub flow_dir: PathBuf,
    pub method: String,
    pub uri: http::Uri,
    pub version: Version,
    pub headers: HeaderMap,
    pub body_bytes: Bytes,
    pub protocol: String,
    pub host: String,
    pub tls_sni: Option<String>,
}

pub struct EffectiveResponseCapture {
    pub id: Uuid,
    pub seq: u64,
    pub flow_key: String,
    pub flow_dir: PathBuf,
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    pub body_bytes: Bytes,
    pub elapsed_ms: i64,
    pub origin: ResponseOrigin,
    pub upstream_status: Option<u16>,
    pub upstream_remote_addr: Option<String>,
    pub tls_sni: Option<String>,
    pub tls_upstream: Option<Value>,
    pub upstream_error_message: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ResponseOrigin {
    Upstream,
    Synthetic,
    ProxyError,
    WebSocketUpgrade,
}

impl ResponseOrigin {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Synthetic => "synthetic",
            Self::ProxyError => "proxy_error",
            Self::WebSocketUpgrade => "websocket_upgrade",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RequestCommit {
    pub id: String,
    pub seq: u64,
    pub flow_key: String,
    pub flow_dir: PathBuf,
    pub request_head_path: PathBuf,
    pub request_body_path: PathBuf,
    pub time: String,
    pub epoch_ms: i64,
    pub method: String,
    pub protocol: String,
    pub host: String,
    pub uri: String,
    pub query_str: String,
    pub version: String,
}

#[derive(Clone, Debug)]
pub struct ResponseCommit {
    pub id: String,
    pub seq: u64,
    pub flow_key: String,
    pub flow_dir: PathBuf,
    pub response_head_path: PathBuf,
    pub response_body_path: PathBuf,
    pub elapsed_ms: i64,
    pub status: u16,
    pub display_status: u16,
    pub version: String,
}

fn body_for_storage(headers: &HeaderMap, body_bytes: &Bytes) -> Bytes {
    body_for_storage_by_headers(headers, body_bytes)
}

fn request_body_for_storage(headers: &HeaderMap, body_bytes: &Bytes) -> Bytes {
    body_for_storage_by_headers(headers, body_bytes)
}

fn body_for_storage_by_headers(headers: &HeaderMap, body_bytes: &Bytes) -> Bytes {
    decoded_body_or_raw(headers, body_bytes)
}

fn body_file_name(base: &str, headers: &HeaderMap) -> String {
    let Some(content_encoding) = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
    else {
        return base.to_string();
    };

    let suffixes = content_encoding
        .split(',')
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter_map(|encoding| match encoding.as_str() {
            "gzip" | "x-gzip" => Some("gz"),
            "br" => Some("br"),
            "zstd" => Some("zst"),
            "deflate" => Some("deflate"),
            "identity" => None,
            _ => None,
        })
        .collect::<Vec<_>>();

    if suffixes.is_empty() {
        base.to_string()
    } else {
        format!("{base}.{}", suffixes.join("."))
    }
}

fn body_omit_reason_by_content_type(
    headers: &HeaderMap,
    omit_content_types: &[String],
) -> Option<String> {
    let content_type = normalized_content_type(headers)?;

    omit_content_types
        .iter()
        .find(|pattern| content_type.starts_with(pattern.as_str()))
        .map(|pattern| {
            format!("content-type {content_type} matched omit rule {pattern}")
        })
}

async fn write_body_limited(
    path: &std::path::Path,
    bytes: &[u8],
    max_len: usize,
) -> io::Result<()> {
    let take_len = bytes.len().min(max_len);
    let mut out = Vec::with_capacity(take_len + 64);
    out.extend_from_slice(&bytes[..take_len]);

    if bytes.len() > max_len {
        out.extend_from_slice(format!(
            "\n<< mitm truncated: max_len={} bytes, total={} bytes >>",
            max_len,
            bytes.len()
        ).as_bytes());
    }

    tokio::fs::write(path, out).await
}

struct BodyStorageInfo {
    saved_size: usize,
    truncated: bool,
}

fn body_storage_info(body_len: usize, max_len: Option<usize>) -> BodyStorageInfo {
    match max_len {
        Some(max_len) => BodyStorageInfo {
            saved_size: body_len.min(max_len),
            truncated: body_len > max_len,
        },
        None => BodyStorageInfo {
            saved_size: body_len,
            truncated: false,
        },
    }
}

async fn write_body_for_storage(
    path: &std::path::Path,
    bytes: &[u8],
    max_len: Option<usize>,
) -> io::Result<()> {
    match max_len {
        Some(max_len) => write_body_limited(path, bytes, max_len).await,
        None => tokio::fs::write(path, bytes).await,
    }
}

fn rfc3999z(time: &DateTime<Utc>) -> String {
    time.to_rfc3339_opts(chrono::format::SecondsFormat::Millis, true)
}

pub(crate) fn version_to_string(v: Version) -> String {
    match v {
        Version::HTTP_09 => "HTTP/0.9".into(),
        Version::HTTP_10 => "HTTP/1.0".into(),
        Version::HTTP_11 => "HTTP/1.1".into(),
        Version::HTTP_2 => "HTTP/2".into(),
        Version::HTTP_3 => "HTTP/3".into(),
        other => format!("{other:?}"),
    }
}

pub(crate) fn headers_to_json(headers: &HeaderMap) -> Value {
    let mut map = serde_json::Map::new();

    for (name, value) in headers {
        let key = name.as_str();
        let val = value
            .to_str()
            .map(|value| json!(value))
            .unwrap_or_else(|_| json!(STANDARD.encode(value.as_bytes())));

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

pub(crate) fn build_request_head_text(
    method: &str,
    uri: &http::Uri,
    version: Version,
    headers: &HeaderMap,
    tls_sni: Option<&str>,
) -> String {
    let mut out = String::new();

    if let Some(tls_sni) = tls_sni {
        out.push_str(&format!("X-Inspect-TLS-SNI: {tls_sni}\r\n"));
    }

    out.push_str(&format!(
        "{} {} {}\r\n",
        method,
        uri,
        version_to_string(version)
    ));

    for (name, value) in headers {
        let value = value.to_str().unwrap_or("<binary>");
        out.push_str(&format!("{name}: {value}\r\n"));
    }

    out.push_str("\r\n");
    out
}

pub(crate) fn build_response_head_text(
    version: Version,
    status: StatusCode,
    headers: &HeaderMap,
) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{} {}\r\n",
        version_to_string(version),
        status
    ));

    for (name, value) in headers {
        let value = value.to_str().unwrap_or("<binary>");
        out.push_str(&format!("{name}: {value}\r\n"));
    }

    out.push_str("\r\n");
    out
}