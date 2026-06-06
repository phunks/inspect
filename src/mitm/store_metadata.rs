
use anyhow::{Context, Result};
use std::time::Duration;
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqliteSynchronous};
use sqlx::{Executor, Sqlite};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::mpsc;
use rama::http::{Request, Body};
use rama::telemetry::tracing;
use serde_json::Value;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::CapturePaths;

#[derive(Clone, Debug, Serialize)]
pub struct RequestMetadata {
    pub id: String,
    pub seq: i64,
    pub flow_key: String,
    pub flow_dir: String,
    pub request_head_path: String,
    pub request_body_path: String,
    pub time: String,
    pub epoch_ms: i64,
    pub method: String,
    pub protocol: String,
    pub host: String,
    pub uri: String,
    pub query_str: String,
    pub version: String,
    pub headers: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResponseMetadata {
    pub id: String,
    pub seq: i64,
    pub flow_key: String,
    pub flow_dir: String,
    pub response_head_path: String,
    pub response_body_path: String,
    pub elapsed: String,
    pub status: u16,
    pub upstream_status: Option<u16>,
    pub version: String,
    pub headers: Value,
}

#[derive(Debug)]
pub enum RequestResponseEvent {
    Request(RequestMetadata),
    Response(ResponseMetadata),
}

#[derive(Clone, Debug)]
pub struct DbState {
    pub db_pool: SqlitePool,
    pub event_sender: UnboundedSender<RequestResponseEvent>,
}

type DbResult<T> = Result<T, sqlx::Error>;
impl DbState {
    pub async fn new() -> Result<Self> {
        let paths = CapturePaths::new();

        tracing::info!("Using database url: {:?}", &paths.db_path);
        tracing::info!("Using current dir: {:?}", std::env::current_dir());

        let conn_opts = SqliteConnectOptions::new()
            .filename(&paths.db_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_millis(5000));

        let db_pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(conn_opts)
            .await
            .context("Failed to connect to SQLite")?;

        sqlx::query!(
            "CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                seq INTEGER NOT NULL,
                flow_key TEXT NOT NULL,
                flow_dir TEXT NOT NULL,
                request_head_path TEXT,
                request_body_path TEXT,
                time TEXT,
                epoch_ms INTEGER,
                method TEXT,
                protocol TEXT,
                host TEXT,
                uri TEXT,
                query_str TEXT,
                version TEXT,
                headers TEXT
            )"
        )
            .execute(&db_pool)
            .await?;
        sqlx::query!(
            "CREATE TABLE IF NOT EXISTS responses (
                id TEXT PRIMARY KEY,
                seq INTEGER NOT NULL,
                flow_key TEXT NOT NULL,
                flow_dir TEXT NOT NULL,
                response_head_path TEXT,
                response_body_path TEXT,
                elapsed TEXT,
                status INTEGER,
                upstream_status INTEGER,
                version TEXT,
                headers TEXT
            )"
        )
            .execute(&db_pool)
            .await?;

        let (event_sender, mut receiver): (
            UnboundedSender<RequestResponseEvent>,
            UnboundedReceiver<RequestResponseEvent>
        ) = mpsc::unbounded_channel();

        let pool_clone = db_pool.clone();
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                match event {
                    RequestResponseEvent::Request(metadata) => {
                        if let Err(e) = insert_request(&pool_clone, &metadata).await {
                            tracing::error!("Failed to insert request: {:?}", e);
                        }
                    }
                    RequestResponseEvent::Response(metadata) => {
                        if let Err(e) = insert_response(&pool_clone, &metadata).await {
                            tracing::error!("Failed to insert response: {:?}", e);
                        }
                    }
                }
            }
            tracing::info!("store DB pool shutting down");
        });

        Ok(Self {
            db_pool,
            event_sender,
        })
    }

    pub async fn flush_sqlite_wal_on_exit(&self) -> Result<(), sqlx::Error>
    {
        self.db_pool.execute("PRAGMA wal_checkpoint(TRUNCATE);").await?;
        self.db_pool.execute("PRAGMA optimize;").await?;
        self.db_pool.close().await;
        Ok(())
    }
}

fn sqlite_url_for_path(path: &std::path::Path) -> String {
    format!("sqlite:{}", path.display())
}

async fn insert_request<'e, E>(exec: E, metadata: &RequestMetadata) -> Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO requests (
            id, seq, flow_key, flow_dir, request_head_path, request_body_path,
            time, epoch_ms, method, protocol, host, uri, query_str, version, headers
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(&metadata.id)
        .bind(metadata.seq)
        .bind(&metadata.flow_key)
        .bind(&metadata.flow_dir)
        .bind(&metadata.request_head_path)
        .bind(&metadata.request_body_path)
        .bind(&metadata.time)
        .bind(metadata.epoch_ms)
        .bind(&metadata.method)
        .bind(&metadata.protocol)
        .bind(&metadata.host)
        .bind(&metadata.uri)
        .bind(&metadata.query_str)
        .bind(&metadata.version)
        .bind(metadata.headers.to_string())
        .execute(exec)
        .await?;

    Ok(())
}

async fn insert_response<'e, E>(exec: E, metadata: &ResponseMetadata) -> Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO responses (
            id, seq, flow_key, flow_dir, response_head_path, response_body_path,
            elapsed, status, upstream_status, version, headers
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(&metadata.id)
        .bind(metadata.seq)
        .bind(&metadata.flow_key)
        .bind(&metadata.flow_dir)
        .bind(&metadata.response_head_path)
        .bind(&metadata.response_body_path)
        .bind(&metadata.elapsed)
        .bind(metadata.status as i64)
        .bind(metadata.upstream_status.map(|s| s as i64))
        .bind(&metadata.version)
        .bind(metadata.headers.to_string())
        .execute(exec)
        .await?;

    Ok(())
}

