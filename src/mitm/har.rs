use std::net::SocketAddr;
use anyhow::{Context, Result};
use rama::http::StatusCode;
use serde_json::{json, Map, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::Row;
use std::time::Duration;

use crate::mitm::capture::CapturePaths;
use crate::tui::body::format_body_for_har;

#[derive(Debug)]
struct HarRow {
    #[allow(unused)]
    id: String,
    started_date_time: Option<String>,
    method: Option<String>,
    protocol: Option<String>,
    host: Option<String>,
    uri: Option<String>,
    query_str: Option<String>,
    request_version: Option<String>,
    request_headers: Option<String>,
    request_head_path: Option<String>,
    request_body_path: Option<String>,
    request_body_size: Option<i64>,
    request_body_saved_size: Option<i64>,
    request_body_truncated: Option<i64>,
    request_body_save_limit: Option<i64>,
    request_body_save_unlimited: Option<i64>,
    elapsed: Option<i64>,
    status: Option<i64>,
    response_version: Option<String>,
    response_headers: Option<String>,
    response_head_path: Option<String>,
    response_body_path: Option<String>,
    response_body_size: Option<i64>,
    response_body_saved_size: Option<i64>,
    response_body_truncated: Option<i64>,
    response_body_save_limit: Option<i64>,
    response_body_save_unlimited: Option<i64>,
    upstream_remote_addr: Option<String>,
}

/// Exports the current capture as a HAR v1.2 file.
///
/// Initial HAR export intentionally omits body text. It exports headers and
/// basic timings only, while keeping body sizes and truncation comments.
pub async fn export_current_capture_har() -> Result<std::path::PathBuf> {
    let paths = CapturePaths::new();
    let output_path = paths.root.join("inspect.har");

    let conn_opts = SqliteConnectOptions::new()
        .filename(&paths.db_path)
        .read_only(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_millis(5000));

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(conn_opts)
        .await
        .with_context(|| format!("Failed to open SQLite: {}", paths.db_path.display()))?;

    let rows = select_har_rows(&pool).await?;
    let har = build_har(rows).await;
    let text = serde_json::to_string_pretty(&har).context("Failed to serialize HAR")?;

    tokio::fs::write(&output_path, text)
        .await
        .with_context(|| format!("Failed to write HAR: {}", output_path.display()))?;

    Ok(output_path)
}

async fn select_har_rows(pool: &sqlx::SqlitePool) -> Result<Vec<HarRow>> {
    let rows = sqlx::query(
        r#"
        SELECT
            requests.id AS id,
            requests.time AS started_date_time,
            requests.method AS method,
            requests.protocol AS protocol,
            requests.host AS host,
            requests.uri AS uri,
            requests.query_str AS query_str,
            requests.version AS request_version,
            requests.headers AS request_headers,
            requests.request_head_path AS request_head_path,
            requests.request_body_path AS request_body_path,
            requests.body_size AS request_body_size,
            requests.body_saved_size AS request_body_saved_size,
            requests.body_truncated AS request_body_truncated,
            requests.body_save_limit AS request_body_save_limit,
            requests.body_save_limit IS NULL AS request_body_save_unlimited,
            responses.elapsed AS elapsed,
            COALESCE(responses.upstream_status, responses.status) AS status,
            responses.version AS response_version,
            responses.headers AS response_headers,
            responses.response_head_path AS response_head_path,
            responses.response_body_path AS response_body_path,
            responses.body_size AS response_body_size,
            responses.body_saved_size AS response_body_saved_size,
            responses.body_truncated AS response_body_truncated,
            responses.body_save_limit AS response_body_save_limit,
            responses.body_save_limit IS NULL AS response_body_save_unlimited,
            responses.upstream_remote_addr AS upstream_remote_addr
        FROM requests
        LEFT JOIN responses ON responses.id = requests.id
        ORDER BY requests.seq ASC
        "#,
    )
        .fetch_all(pool)
        .await
        .context("Failed to select HAR rows")?;

    Ok(rows
        .into_iter()
        .map(|row| HarRow {
            id: row.get("id"),
            started_date_time: row.try_get("started_date_time").ok(),
            method: row.try_get("method").ok(),
            protocol: row.try_get("protocol").ok(),
            host: row.try_get("host").ok(),
            uri: row.try_get("uri").ok(),
            query_str: row.try_get("query_str").ok(),
            request_version: row.try_get("request_version").ok(),
            request_headers: row.try_get("request_headers").ok(),
            request_head_path: row.try_get("request_head_path").ok(),
            request_body_path: row.try_get("request_body_path").ok(),
            request_body_size: row.try_get("request_body_size").ok(),
            request_body_saved_size: row.try_get("request_body_saved_size").ok(),
            request_body_truncated: row.try_get("request_body_truncated").ok(),
            request_body_save_limit: row.try_get("request_body_save_limit").ok(),
            request_body_save_unlimited: row.try_get("request_body_save_unlimited").ok(),
            elapsed: row.try_get("elapsed").ok(),
            status: row.try_get("status").ok(),
            response_version: row.try_get("response_version").ok(),
            response_headers: row.try_get("response_headers").ok(),
            response_head_path: row.try_get("response_head_path").ok(),
            response_body_path: row.try_get("response_body_path").ok(),
            response_body_size: row.try_get("response_body_size").ok(),
            response_body_saved_size: row.try_get("response_body_saved_size").ok(),
            response_body_truncated: row.try_get("response_body_truncated").ok(),
            response_body_save_limit: row.try_get("response_body_save_limit").ok(),
            response_body_save_unlimited: row.try_get("response_body_save_unlimited").ok(),
            upstream_remote_addr: row.try_get("upstream_remote_addr").ok(),
        })
        .collect())
}

async fn build_har(rows: Vec<HarRow>) -> Value {
    let mut entries = Vec::with_capacity(rows.len());

    for row in rows {
        entries.push(build_entry(row).await);
    }

    json!({
        "log": {
            "version": "1.2",
            "creator": {
                "name": "inspect",
                "version": env!("CARGO_PKG_VERSION")
            },
            "entries": entries
        }
    })
}

async fn build_entry(row: HarRow) -> Value {
    let elapsed = row.elapsed.unwrap_or(0).max(0);
    let status = row.status.unwrap_or(0);
    let response_body_size = row.response_body_size.unwrap_or(-1);
    let request_headers = parse_headers(row.request_headers.as_deref());
    let response_headers = parse_headers(row.response_headers.as_deref());

    let request_headers_size = file_size(row.request_head_path.as_deref()).await.unwrap_or(-1);
    let response_headers_size = file_size(row.response_head_path.as_deref()).await.unwrap_or(-1);

    let mut request = json!({
        "method": row.method.as_deref().unwrap_or("GET"),
        "url": build_url(
            row.protocol.as_deref(),
            row.host.as_deref(),
            row.uri.as_deref(),
            row.query_str.as_deref(),
        ),
        "httpVersion": row.request_version.as_deref().unwrap_or("HTTP/1.1"),
        "cookies": [],
        "headers": headers_to_har_array(row.request_headers.as_deref()),
        "queryString": query_to_har_array(row.query_str.as_deref()),
        "headersSize": request_headers_size,
        "bodySize": row.request_body_size.unwrap_or(-1)
    });

    if should_include_body(
        row.request_body_save_unlimited,
        row.request_body_truncated,
    ) && let Some(body) = read_file(row.request_body_path.as_deref()).await {
        let content = format_body_for_har(&request_headers, &body);

        let mut post_data = json!({
            "mimeType": content
                .get("mimeType")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "text": content
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        });

        if let Some(encoding) = content.get("encoding").cloned() {
            post_data["encoding"] = encoding;
        }

        request["postData"] = post_data;
    }

    let mut response_content = json!({
        "size": response_body_size,
        "mimeType": content_type(row.response_headers.as_deref()).unwrap_or_default()
    });

    if should_include_body(
        row.response_body_save_unlimited,
        row.response_body_truncated,
    ) && let Some(body) = read_file(row.response_body_path.as_deref()).await {
        response_content = format_body_for_har(&response_headers, &body);
    }

    let mut entry = json!({
        "startedDateTime": row.started_date_time.as_deref().unwrap_or("1970-01-01T00:00:00.000Z"),
        "time": elapsed,
        "request": request,
        "response": {
            "status": status,
            "statusText": status_text(status),
            "httpVersion": row.response_version.as_deref().unwrap_or("HTTP/1.1"),
            "cookies": [],
            "headers": headers_to_har_array(row.response_headers.as_deref()),
            "content": response_content,
            "redirectURL": redirect_url(row.response_headers.as_deref()).unwrap_or_default(),
            "headersSize": response_headers_size,
            "bodySize": response_body_size
        },
        "cache": {},
        "timings": {
            "blocked": -1,
            "dns": -1,
            "connect": -1,
            "ssl": -1,
            "send": 0,
            "wait": elapsed,
            "receive": 0
        }
    });

    if let Some((ip, port)) = split_remote_addr(row.upstream_remote_addr.as_deref())
        && let Some(obj) = entry.as_object_mut() {
        obj.insert("serverIPAddress".to_string(), Value::String(ip));
        obj.insert("connection".to_string(), Value::String(port));
    }

    let comments = truncation_comments(&row);
    if !comments.is_empty()
        && let Some(obj) = entry.as_object_mut() {
        obj.insert("comment".to_string(), Value::String(comments.join("; ")));
    }

    entry
}

fn should_include_body(
    body_save_unlimited: Option<i64>,
    body_truncated: Option<i64>,
) -> bool {
    body_save_unlimited == Some(1) && body_truncated != Some(1)
}

async fn read_file(path: Option<&str>) -> Option<Vec<u8>> {
    let path = path?;
    tokio::fs::read(path).await.ok()
}

async fn file_size(path: Option<&str>) -> Option<i64> {
    let path = path?;
    tokio::fs::metadata(path)
        .await
        .ok()
        .map(|metadata| metadata.len() as i64)
}

fn parse_headers(headers: Option<&str>) -> Value {
    let Some(headers) = headers else {
        return Value::Null;
    };

    let parsed = serde_json::from_str::<Value>(headers).unwrap_or(Value::Null);
    match parsed {
        Value::String(s) => serde_json::from_str::<Value>(&s).unwrap_or(Value::Null),
        other => other,
    }
}

fn split_remote_addr(addr: Option<&str>) -> Option<(String, String)> {
    let addr = addr?;
    let addr = addr.parse::<SocketAddr>().ok()?;
    Some((addr.ip().to_string(), addr.port().to_string()))
}

fn build_url(
    protocol: Option<&str>,
    host: Option<&str>,
    uri: Option<&str>,
    query_str: Option<&str>,
) -> String {
    let protocol = protocol.unwrap_or("http");
    let host = host.unwrap_or_default();
    let uri = uri.unwrap_or("/");

    match query_str {
        Some(query) if !query.is_empty() => format!("{protocol}://{host}{uri}?{query}"),
        _ => format!("{protocol}://{host}{uri}"),
    }
}

fn headers_to_har_array(headers: Option<&str>) -> Value {
    let Some(headers) = headers else {
        return Value::Array(Vec::new());
    };

    let parsed = serde_json::from_str::<Value>(headers).unwrap_or(Value::Null);
    let parsed = match parsed {
        Value::String(s) => serde_json::from_str::<Value>(&s).unwrap_or(Value::Null),
        other => other,
    };

    let Value::Object(map) = parsed else {
        return Value::Array(Vec::new());
    };

    let mut out = Vec::new();

    for (name, value) in map {
        match value {
            Value::Array(values) => {
                for value in values {
                    out.push(json!({
                        "name": name,
                        "value": header_value_to_string(value),
                    }));
                }
            }
            value => {
                out.push(json!({
                    "name": name,
                    "value": header_value_to_string(value),
                }));
            }
        }
    }

    Value::Array(out)
}

fn header_value_to_string(value: Value) -> String {
    match value {
        Value::String(s) => s,
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn query_to_har_array(query: Option<&str>) -> Value {
    let Some(query) = query else {
        return Value::Array(Vec::new());
    };

    if query.is_empty() {
        return Value::Array(Vec::new());
    }

    Value::Array(
        query
            .split('&')
            .filter(|part| !part.is_empty())
            .map(|part| {
                let mut split = part.splitn(2, '=');
                let name = split.next().unwrap_or_default();
                let value = split.next().unwrap_or_default();

                json!({
                    "name": name,
                    "value": value
                })
            })
            .collect(),
    )
}

fn header_lookup(headers: Option<&str>, name: &str) -> Option<String> {
    let headers = headers_to_map(headers)?;
    headers
        .get(&name.to_ascii_lowercase())
        .and_then(|value| match value {
            Value::String(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        })
}

fn headers_to_map(headers: Option<&str>) -> Option<Map<String, Value>> {
    let headers = headers?;
    let parsed = serde_json::from_str::<Value>(headers).ok()?;
    let parsed = match parsed {
        Value::String(s) => serde_json::from_str::<Value>(&s).ok()?,
        other => other,
    };

    let Value::Object(map) = parsed else {
        return None;
    };

    let normalized = map
        .into_iter()
        .map(|(key, value)| {
            let value = match value {
                Value::Array(values) => values
                    .into_iter()
                    .map(header_value_to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                value => header_value_to_string(value),
            };

            (key.to_ascii_lowercase(), Value::String(value))
        })
        .collect::<Map<_, _>>();

    Some(normalized)
}

fn content_type(headers: Option<&str>) -> Option<String> {
    header_lookup(headers, "content-type")
        .and_then(|value| value.split(';').next().map(str::trim).map(str::to_string))
        .filter(|value| !value.is_empty())
}

fn redirect_url(headers: Option<&str>) -> Option<String> {
    header_lookup(headers, "location")
}

fn status_text(status: i64) -> String {
    let Ok(status) = u16::try_from(status) else {
        return String::new();
    };

    StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason().map(str::to_string))
        .unwrap_or_default()
}

fn truncation_comments(row: &HarRow) -> Vec<String> {
    let mut comments = Vec::new();

    if !should_include_body(row.request_body_save_unlimited, row.request_body_truncated)
        && row.request_body_size.unwrap_or(0) > 0 {
        comments.push("Request body text is omitted because body_save_unlimited was not enabled or body was truncated".to_string());
    }

    if !should_include_body(row.response_body_save_unlimited, row.response_body_truncated)
        && row.response_body_size.unwrap_or(0) > 0 {
        comments.push("Response body text is omitted because body_save_unlimited was not enabled or body was truncated".to_string());
    }

    if row.request_body_truncated == Some(1) {
        comments.push(format!(
            "Request body was truncated on disk: bodySize={}, saved={}, limit={}",
            size_text(row.request_body_size),
            size_text(row.request_body_saved_size),
            size_text(row.request_body_save_limit),
        ));
    }

    if row.response_body_truncated == Some(1) {
        comments.push(format!(
            "Response body was truncated on disk: bodySize={}, saved={}, limit={}",
            size_text(row.response_body_size),
            size_text(row.response_body_saved_size),
            size_text(row.response_body_save_limit),
        ));
    }

    comments
}

fn size_text(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}