use std::fmt;
use std::fmt::Formatter;
use anyhow::{Context, Result};
use std::time::Duration;
use http::StatusCode;
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use sqlx::{Executor, FromRow, Sqlite};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use rama::telemetry::tracing;
use serde_json::Value;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::mitm::capture::CapturePaths;

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum DbCommand {
    SelectRequest {
        id: String,
        reply: oneshot::Sender<Result<RequestMetadata>>,
    },
    SelectResponse {
        id: String,
        reply: oneshot::Sender<Result<ResponseMetadata>>,
    },
    SelectPacketSummaries {
        reply: oneshot::Sender<Result<Vec<PacketSummary>>>,
    },
}

#[derive(Clone, Debug)]
pub struct DbState {
    _db_pool: SqlitePool,
    pub event_sender: UnboundedSender<DbCommand>,
}

#[derive(Clone, Debug, FromRow)]
pub struct PacketSummary {
    pub id: String,
    pub seq: i64,
    pub flow_key: String,
    pub time: Option<String>,
    pub epoch_ms: Option<i64>,
    pub method: Option<String>,
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub query_str: Option<String>,
    pub status: Option<i64>,
    pub elapsed: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RequestMetadata {
    pub id: Option<String>,
    pub seq: Option<i64>,
    pub flow_key: Option<String>,
    pub flow_dir: Option<String>,
    pub request_head_path: Option<String>,
    pub request_body_path: Option<String>,
    pub time: Option<String>,
    pub epoch_ms: Option<i64>,
    pub method: Option<String>,
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub query_str: Option<String>,
    pub version: Option<String>,
    pub tls_sni: Option<String>,
    pub headers: Value,
    pub body_size: Option<i64>,
    pub body_saved_size: Option<i64>,
    pub body_truncated: Option<i64>,
    pub body_save_limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct RequestMetadataLegacy {
    pub id: Option<String>,
    pub seq: Option<i64>,
    pub flow_key: Option<String>,
    pub flow_dir: Option<String>,
    pub request_head_path: Option<String>,
    pub request_body_path: Option<String>,
    pub time: Option<String>,
    pub epoch_ms: Option<i64>,
    pub method: Option<String>,
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub query_str: Option<String>,
    pub version: Option<String>,
    pub headers: Value,
}

impl From<RequestMetadataLegacy> for RequestMetadata {
    fn from(value: RequestMetadataLegacy) -> Self {
        Self {
            id: value.id,
            seq: value.seq,
            flow_key: value.flow_key,
            flow_dir: value.flow_dir,
            request_head_path: value.request_head_path,
            request_body_path: value.request_body_path,
            time: value.time,
            epoch_ms: value.epoch_ms,
            method: value.method,
            protocol: value.protocol,
            host: value.host,
            uri: value.uri,
            query_str: value.query_str,
            version: value.version,
            headers: value.headers,
            tls_sni: None,
            body_size: None,
            body_saved_size: None,
            body_truncated: None,
            body_save_limit: None,
        }
    }
}

impl fmt::Display for RequestMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let headers = normalize_headers_for_display(self.headers.clone());
        let headers_pretty = serde_json::to_string_pretty(&headers)
            .unwrap_or_else(|_| headers.to_string());
        let width = 10;
        writeln!(f, "{:<width$}: {}", "time", opt_str(self.time.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "method", opt_str(self.method.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "scheme", opt_str(self.protocol.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "host", opt_str(self.host.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "path", opt_str(self.uri.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "query", opt_str(self.query_str.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "version", opt_str(self.version.as_deref()))?;
        // writeln!(f, "{:<width$}: {}", "tls_sni", opt_str(self.tls_sni.as_deref()))?;
        writeln!(f, "{:<width$}:", "headers")?;
        write!(f, "{}", indent_lines(&headers_pretty, "  "))
    }
}

impl RequestMetadata {
    pub fn body_size_line(&self) -> String {
        format_body_size_line(
            self.body_size,
            self.body_saved_size,
            self.body_truncated,
            self.body_save_limit,
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ResponseMetadata {
    pub id: Option<String>,
    pub seq: Option<i64>,
    pub flow_key: Option<String>,
    pub flow_dir: Option<String>,
    pub response_head_path: Option<String>,
    pub response_body_path: Option<String>,
    pub elapsed: Option<i64>,
    pub status: Option<i64>,
    pub upstream_status: Option<i64>,
    pub version: Option<String>,
    pub tls_upstream: Option<String>,
    pub headers: Value,
    pub body_size: Option<i64>,
    pub body_saved_size: Option<i64>,
    pub body_truncated: Option<i64>,
    pub body_save_limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct ResponseMetadataLegacy {
    pub id: Option<String>,
    pub seq: Option<i64>,
    pub flow_key: Option<String>,
    pub flow_dir: Option<String>,
    pub response_head_path: Option<String>,
    pub response_body_path: Option<String>,
    pub elapsed: Option<i64>,
    pub status: Option<i64>,
    pub upstream_status: Option<i64>,
    pub version: Option<String>,
    pub headers: Value,
}

impl From<ResponseMetadataLegacy> for ResponseMetadata {
    fn from(value: ResponseMetadataLegacy) -> Self {
        Self {
            id: value.id,
            seq: value.seq,
            flow_key: value.flow_key,
            flow_dir: value.flow_dir,
            response_head_path: value.response_head_path,
            response_body_path: value.response_body_path,
            elapsed: value.elapsed,
            status: value.status,
            upstream_status: value.upstream_status,
            version: value.version,
            tls_upstream: None,
            headers: value.headers,
            body_size: None,
            body_saved_size: None,
            body_truncated: None,
            body_save_limit: None,
        }
    }
}

impl fmt::Display for ResponseMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let headers = normalize_headers_for_display(self.headers.clone());
        let headers_pretty = serde_json::to_string_pretty(&headers)
            .unwrap_or_else(|_| headers.to_string());
        let width = 10;
        let status = self.upstream_status.or(self.status);
        writeln!(
            f,
            "{:<width$}: {}",
            "status",
            format_status_for_display(status)
        )?;
        writeln!(f, "{:<width$}: {} ms", "elapsed", self.elapsed.map_or("-".into(), |d| d.to_string()))?;
        writeln!(f, "{:<width$}: {}", "protocol", opt_str(self.version.as_deref()))?;

        // if let Some(tls_upstream) = self.tls_upstream.as_deref() {
        //     writeln!(f, "{:<width$}:", "upstream tls")?;
        //     let tls_value = serde_json::from_str::<Value>(tls_upstream)
        //         .unwrap_or_else(|_| Value::String(tls_upstream.to_string()));
        //     let tls_pretty = serde_json::to_string_pretty(&tls_value)
        //         .unwrap_or_else(|_| tls_upstream.to_string());
        //     writeln!(f, "{}", indent_lines(&tls_pretty, "  "))?;
        // }

        writeln!(f, "{:<width$}:", "headers")?;
        write!(f, "{}", indent_lines(&headers_pretty, "  "))
    }
}

impl ResponseMetadata {
    pub fn body_size_line(&self) -> String {
        format_body_size_line(
            self.body_size,
            self.body_saved_size,
            self.body_truncated,
            self.body_save_limit,
        )
    }
}

fn format_status_for_display(status: Option<i64>) -> String {
    let Some(status) = status else {
        return "-".to_string();
    };

    let Ok(status_u16) = u16::try_from(status) else {
        return status.to_string();
    };

    match StatusCode::from_u16(status_u16)
        .ok()
        .and_then(|status| status.canonical_reason())
    {
        Some(reason) => format!("{status_u16} {reason}"),
        None => status_u16.to_string(),
    }
}

fn format_body_size_line(
    body_size: Option<i64>,
    body_saved_size: Option<i64>,
    body_truncated: Option<i64>,
    body_save_limit: Option<i64>,
) -> String {
    let Some(body_size) = body_size else {
        return "-".to_string();
    };

    let body_size_text = format_number(body_size);

    if body_truncated == Some(1) {
        let saved = body_saved_size.map(format_number).unwrap_or_else(|| "-".to_string());
        let limit = body_save_limit.map(format_number).unwrap_or_else(|| "-".to_string());
        return format!("{body_size_text} bytes (saved {saved} bytes, truncated limit {limit} bytes)");
    }

    if let Some(saved) = body_saved_size
        && saved != body_size {
        return format!("{body_size_text} bytes (saved {} bytes)", format_number(saved));
    }

    format!("{body_size_text} bytes")
}

fn format_number(n: i64) -> String {
    let s = n.abs().to_string();
    let mut out = String::new();

    for (idx, ch) in s.chars().rev().enumerate() {
        if idx > 0 && idx % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }

    let mut out = out.chars().rev().collect::<String>();
    if n < 0 {
        out.insert(0, '-');
    }
    out
}

fn opt_str(v: Option<&str>) -> &str {
    v.unwrap_or("-")
}

fn normalize_headers_for_display(v: Value) -> Value {
    match v {
        Value::String(s) => serde_json::from_str::<Value>(&s).unwrap_or(Value::String(s)),
        other => other,
    }
}

fn indent_lines(s: &str, prefix: &str) -> String {
    s.lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

impl DbState {
    pub async fn new() -> Result<Self> {
        let paths = CapturePaths::new();

        let conn_opts = SqliteConnectOptions::new()
            .filename(&paths.db_path)
            .read_only(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_millis(5000));

        let db_pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(conn_opts)
            .await
            .context("Failed to connect to SQLite")?;


        let (event_sender, mut receiver): (
            UnboundedSender<DbCommand>,
            UnboundedReceiver<DbCommand>
        ) = mpsc::unbounded_channel();

        let pool_clone = db_pool.clone();
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                match event {
                    DbCommand::SelectRequest { id, reply } => {
                        let result = select_request(&pool_clone, &id).await;
                        let _ = reply.send(result);
                    }
                    DbCommand::SelectResponse { id, reply } => {
                        let result = select_response(&pool_clone, &id).await;
                        let _ = reply.send(result);
                    }
                    DbCommand::SelectPacketSummaries { reply } => {
                        let result = select_packet_summaries(&pool_clone).await;
                        let _ = reply.send(result);
                    }
                }
            }
            tracing::info!("read DB pool shutting down");
        });

        Ok(Self {
            _db_pool: db_pool,
            event_sender,
        })
    }

    pub async fn select_request_by_id(&self, id: impl Into<String>) -> Result<RequestMetadata> {
        let (tx, rx) = oneshot::channel();
        self.event_sender
            .send(DbCommand::SelectRequest {
                id: id.into(),
                reply: tx,
            })
            .context("Failed to send SelectRequest command")?;

        rx.await.context("DB worker dropped SelectRequest response")?
    }

    pub async fn select_response_by_id(&self, id: impl Into<String>) -> Result<ResponseMetadata> {
        let (tx, rx) = oneshot::channel();
        self.event_sender
            .send(DbCommand::SelectResponse {
                id: id.into(),
                reply: tx,
            })
            .context("Failed to send SelectResponse command")?;

        rx.await.context("DB worker dropped SelectResponse response")?
    }

    pub async fn select_packet_summaries(&self) -> Result<Vec<PacketSummary>> {
        let (tx, rx) = oneshot::channel();
        self.event_sender
            .send(DbCommand::SelectPacketSummaries {
                reply: tx,
            })
            .context("Failed to send SelectPacketSummaries command")?;

        rx.await.context("DB worker dropped SelectPacketSummaries response")?
    }
}

async fn select_packet_summaries<'e, E>(exec: E) -> Result<Vec<PacketSummary>>
where
    E: Executor<'e, Database = Sqlite>,
{
    let rows = sqlx::query_as::<_, PacketSummary>(
        r#"
        SELECT
            requests.id AS id,
            requests.seq AS seq,
            requests.flow_key AS flow_key,
            requests.time AS time,
            requests.epoch_ms AS epoch_ms,
            requests.method AS method,
            requests.protocol AS protocol,
            requests.host AS host,
            requests.uri AS uri,
            requests.query_str AS query_str,
            COALESCE(responses.upstream_status, responses.status) AS status,
            responses.elapsed AS elapsed
        FROM requests
        LEFT JOIN responses ON responses.id = requests.id
        ORDER BY requests.seq ASC
        "#
    )
        .fetch_all(exec)
        .await
        .context("Failed to select packet summaries")?;

    Ok(rows)
}

async fn select_request(exec: &SqlitePool, id: &str) -> Result<RequestMetadata> {
    let with_body_columns = sqlx::query_as!(
        RequestMetadata,
        r#"SELECT id,
                seq,
                flow_key,
                flow_dir,
                request_head_path,
                request_body_path,
                time,
                epoch_ms,
                method,
                protocol,
                host,
                uri,
                query_str,
                version,
                tls_sni,
                headers,
                body_size,
                body_saved_size,
                body_truncated,
                body_save_limit
            FROM requests WHERE id = ?"#,
        id
    )
        .fetch_one(exec)
        .await;

    match with_body_columns {
        Ok(request) => Ok(request),
        Err(new_schema_error) => {
            let legacy = sqlx::query_as!(
                RequestMetadataLegacy,
                r#"SELECT id,
                        seq,
                        flow_key,
                        flow_dir,
                        request_head_path,
                        request_body_path,
                        time,
                        epoch_ms,
                        method,
                        protocol,
                        host,
                        uri,
                        query_str,
                        version,
                        headers
                    FROM requests WHERE id = ?"#,
                id,
            )
                .fetch_one(exec)
                .await
                .with_context(|| {
                    format!("Failed to select request; new schema error: {new_schema_error}")
                })?;

            Ok(legacy.into())
        }
    }
}

async fn select_response<'e, E>(exec: E, id: &str) -> Result<ResponseMetadata>
where
    E: Executor<'e, Database = Sqlite> + Copy,
{
    let with_body_columns = sqlx::query_as!(
        ResponseMetadata,
        r#"SELECT id,
                seq,
                flow_key,
                flow_dir,
                response_head_path,
                response_body_path,
                elapsed,
                status,
                upstream_status,
                version,
                tls_upstream,
                headers,
                body_size,
                body_saved_size,
                body_truncated,
                body_save_limit
            FROM responses WHERE id = ?"#,
        id
    )
        .fetch_one(exec)
        .await;

    match with_body_columns {
        Ok(response) => Ok(response),
        Err(new_schema_error) => {
            let legacy = sqlx::query_as!(
                ResponseMetadataLegacy,
                r#"SELECT id,
                        seq,
                        flow_key,
                        flow_dir,
                        response_head_path,
                        response_body_path,
                        elapsed,
                        status,
                        upstream_status,
                        version,
                        headers
                    FROM responses WHERE id = ?"#,
                id
            )
                .fetch_one(exec)
                .await
                .with_context(|| {
                    format!("Failed to select response; new schema error: {new_schema_error}")
                })?;

            Ok(legacy.into())
        }
    }
}

