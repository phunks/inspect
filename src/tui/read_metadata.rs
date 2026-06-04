use std::fmt;
use std::fmt::Formatter;
use anyhow::{Context, Result};
use std::time::Duration;
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqliteSynchronous};
use sqlx::{Executor, Sqlite};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use rama::http::{Request, Body};
use rama::telemetry::tracing;
use serde_json::Value;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::CapturePaths;

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
}

#[derive(Clone, Debug)]
pub struct DbState {
    pub db_pool: SqlitePool,
    pub event_sender: UnboundedSender<DbCommand>,
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
    pub headers: Value,
}

impl fmt::Display for RequestMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let headers = normalize_headers_for_display(self.headers.clone());
        let headers_pretty = serde_json::to_string_pretty(&headers)
            .unwrap_or_else(|_| headers.to_string());
        let width = 8;
        writeln!(f, "{:<width$}: {}", "time", opt_str(self.time.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "method", opt_str(self.method.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "scheme", opt_str(self.protocol.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "host", opt_str(self.host.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "path", opt_str(self.uri.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "query", opt_str(self.query_str.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "version", opt_str(self.version.as_deref()))?;
        writeln!(f, "{:<width$}:", "headers")?;
        write!(f, "{}", indent_lines(&headers_pretty, "  "))
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
    pub elapsed: Option<String>,
    pub status: Option<i64>,
    pub version: Option<String>,
    pub headers: Value,
}

impl fmt::Display for ResponseMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let headers = normalize_headers_for_display(self.headers.clone());
        let headers_pretty = serde_json::to_string_pretty(&headers)
            .unwrap_or_else(|_| headers.to_string());
        let width = 9;
        writeln!(f, "{:<width$}: {} ms", "elapsed", opt_str(self.elapsed.as_deref()))?;
        writeln!(f, "{:<width$}: {}", "status", self.status.map_or("-".into(), |s| s.to_string()))?;
        writeln!(f, "{:<width$}: {}", "protocol", opt_str(self.version.as_deref()))?;
        writeln!(f, "{:<width$}:", "headers")?;
        write!(f, "{}", indent_lines(&headers_pretty, "  "))
    }
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
                }
            }
            tracing::info!("DB shutting down");
        });

        Ok(Self {
            db_pool,
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
}

fn sqlite_readonly_url_for_path(path: &std::path::Path) -> String {
    format!("sqlite:{}?mode=ro", path.display())
}

async fn select_request<'e, E>(exec: E, id: &str) -> Result<RequestMetadata>
where
    E: Executor<'e, Database = Sqlite>,
{
    let r = sqlx::query_as!(
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
                headers
            FROM requests WHERE id = ?"#,
        id,
    )
        .fetch_one(exec)
        .await
        .context("Failed to select request")?;

    Ok(r)
}

async fn select_response<'e, E>(exec: E, id: &str) -> Result<ResponseMetadata>
where
    E: Executor<'e, Database = Sqlite>,
{
    let r = sqlx::query_as!(
        ResponseMetadata,
        r#"SELECT id,
                seq,
                flow_key,
                flow_dir,
                response_head_path,
                response_body_path,
                elapsed,
                status,
                version,
                headers
            FROM responses WHERE id = ?"#,
        id
    )
        .fetch_one(exec)
        .await
        .context("Failed to select response")?;

    Ok(r)
}

