
use anyhow::{Context, Result};
use std::time::Duration;
use serde::Serialize;
use sqlx::sqlite::{
    SqliteConnectOptions,
    SqliteJournalMode,
    SqlitePool,
    SqliteSynchronous
};
use sqlx::{Acquire, Executor, Sqlite};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::mpsc;
use rama::telemetry::tracing;
use serde_json::Value;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use crate::mitm::capture::CapturePaths;

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
    pub tls_sni: Option<String>,
    pub headers: Value,
    pub body_size: i64,
    pub body_saved_size: i64,
    pub body_truncated: bool,
    pub body_save_limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResponseMetadata {
    pub id: String,
    pub seq: i64,
    pub flow_key: String,
    pub flow_dir: String,
    pub response_head_path: String,
    pub response_body_path: String,
    pub elapsed: i64,
    pub status: u16,
    pub upstream_status: Option<u16>,
    pub version: String,
    pub tls_upstream: Option<Value>,
    pub upstream_remote_addr: Option<String>,
    pub headers: Value,
    pub body_size: i64,
    pub body_saved_size: i64,
    pub body_truncated: bool,
    pub body_save_limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FilterExecStatMetadata {
    pub id: String,
    pub seq: i64,
    pub flow_key: String,
    pub phase: String,
    pub filter_id: Option<String>,
    pub filter_name: String,
    pub elapsed_us: i64,
    pub result_code: i64,
    pub state_read_bytes: i64,
    pub state_write_bytes: i64,
    pub state_items: i64,
    pub evicted_items: i64,
    pub limit_hit: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FilterStatusMetadata {
    pub filter_id: String,
    pub source_kind: String,
    pub file_name: String,
    pub path: String,
    pub explicit_id: Option<String>,
    pub name: String,
    pub enabled: bool,
    pub valid: bool,
    pub priority: Option<i32>,
    pub script_hash: String,
    pub script_len: i64,
    pub program_kind: Option<String>,
    pub last_error: Option<String>,
    pub loaded_at: String,
}

#[derive(Debug)]
pub enum RequestResponseEvent {
    Request(RequestMetadata),
    Response(ResponseMetadata),
    FilterExecStat(FilterExecStatMetadata),
    FilterStatus(FilterStatusMetadata),
    FilterStatusPrune {
        file_names: Vec<String>,
    },
}

#[derive(Clone, Debug)]
pub struct DbState {
    pub db_pool: SqlitePool,
    pub event_sender: UnboundedSender<RequestResponseEvent>,
}

impl DbState {
    pub async fn new() -> Result<Self> {
        let paths = CapturePaths::new();
        Self::new_for_paths(&paths).await
    }

    pub async fn new_for_paths(paths: &CapturePaths)  -> Result<Self> {
        tracing::info!("Using database url: {:?}", &paths.db_path);
        tracing::info!("Using current dir: {:?}", std::env::current_dir());

        let conn_opts = SqliteConnectOptions::new()
            .filename(&paths.db_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_millis(5000));

        let db_pool: SqlitePool = SqlitePoolOptions::new()
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
                tls_sni TEXT,
                headers TEXT,
                body_size INTEGER,
                body_saved_size INTEGER,
                body_truncated INTEGER,
                body_save_limit INTEGER
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
                elapsed INTEGER,
                status INTEGER,
                upstream_status INTEGER,
                version TEXT,
                tls_upstream TEXT,
                upstream_remote_addr TEXT,
                headers TEXT,
                body_size INTEGER,
                body_saved_size INTEGER,
                body_truncated INTEGER,
                body_save_limit INTEGER
            )"
        )
            .execute(&db_pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS filters (
                filter_id TEXT PRIMARY KEY,
                source_kind TEXT NOT NULL,
                file_name TEXT NOT NULL,
                path TEXT NOT NULL,
                explicit_id TEXT,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                valid INTEGER NOT NULL,
                priority INTEGER,
                script_hash TEXT NOT NULL,
                script_len INTEGER NOT NULL,
                program_kind TEXT,
                last_error TEXT,
                loaded_at TEXT
            )"
        )
            .execute(&db_pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS filter_exec_stats (
                id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                flow_key TEXT NOT NULL,
                phase TEXT NOT NULL,
                filter_id TEXT,
                filter_name TEXT NOT NULL,
                elapsed_us INTEGER NOT NULL,
                result_code INTEGER NOT NULL,
                state_read_bytes INTEGER NOT NULL DEFAULT 0,
                state_write_bytes INTEGER NOT NULL DEFAULT 0,
                state_items INTEGER NOT NULL DEFAULT 0,
                evicted_items INTEGER NOT NULL DEFAULT 0,
                limit_hit INTEGER NOT NULL DEFAULT 0
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
                    RequestResponseEvent::FilterExecStat(metadata) => {
                        if let Err(e) = insert_filter_exec_stat(&pool_clone, &metadata).await {
                            tracing::error!("Failed to insert filter_exec_stat: {:?}", e);
                        }
                    }
                    RequestResponseEvent::FilterStatus(metadata) => {
                        if let Err(e) = insert_filter_status(&pool_clone, &metadata).await {
                            tracing::error!("Failed to insert filter status: {:?}", e);
                        }
                    }
                    RequestResponseEvent::FilterStatusPrune { file_names } => {
                        if let Err(e) = prune_filter_statuses(&pool_clone, &file_names).await {
                            tracing::error!("Failed to prune filter statuses: {:?}", e);
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

async fn prune_filter_statuses<'e, E>(exec: E, file_names: &[String]) -> Result<()>
where
    E: Acquire<'e, Database = Sqlite>,
{
    let mut tx = exec.begin().await?;

    if file_names.is_empty() {
        sqlx::query("DELETE FROM filters")
            .execute(&mut *tx)
            .await?;
    } else {
        let placeholders = std::iter::repeat_n("?", file_names.len())
            .collect::<Vec<_>>()
            .join(", ");

        let mut query = sqlx::query(
            "DELETE FROM filters WHERE file_name NOT IN ({placeholders})"
        );
        
        for file_name in file_names {
            query = query.bind(file_name);
        }

        query.execute(&mut *tx).await?;
    }

    tx.commit().await?;

    Ok(())
}

async fn insert_request<'e, E>(exec: E, metadata: &RequestMetadata) -> Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO requests (
            id, seq, flow_key, flow_dir, request_head_path, request_body_path,
            time, epoch_ms, method, protocol, host, uri, query_str, version, tls_sni, headers,
            body_size, body_saved_size, body_truncated, body_save_limit
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
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
        .bind(&metadata.tls_sni)
        .bind(metadata.headers.to_string())
        .bind(metadata.body_size)
        .bind(metadata.body_saved_size)
        .bind(metadata.body_truncated as i64)
        .bind(metadata.body_save_limit)
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
            elapsed, status, upstream_status, version, tls_upstream, upstream_remote_addr, headers,
            body_size, body_saved_size, body_truncated, body_save_limit
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(&metadata.id)
        .bind(metadata.seq)
        .bind(&metadata.flow_key)
        .bind(&metadata.flow_dir)
        .bind(&metadata.response_head_path)
        .bind(&metadata.response_body_path)
        .bind(metadata.elapsed)
        .bind(metadata.status as i64)
        .bind(metadata.upstream_status.map(|s| s as i64))
        .bind(&metadata.version)
        .bind(metadata.tls_upstream.as_ref().map(|v| v.to_string()))
        .bind(&metadata.upstream_remote_addr)
        .bind(metadata.headers.to_string())
        .bind(metadata.body_size)
        .bind(metadata.body_saved_size)
        .bind(metadata.body_truncated as i64)
        .bind(metadata.body_save_limit)
        .execute(exec)
        .await?;

    Ok(())
}

async fn insert_filter_exec_stat<'e, E>(exec: E, metadata: &FilterExecStatMetadata) -> Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT INTO filter_exec_stats (
            id, seq, flow_key, phase, filter_id, filter_name, elapsed_us, result_code,
            state_read_bytes, state_write_bytes, state_items, evicted_items, limit_hit
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(&metadata.id)
        .bind(metadata.seq)
        .bind(&metadata.flow_key)
        .bind(&metadata.phase)
        .bind(&metadata.filter_id)
        .bind(&metadata.filter_name)
        .bind(metadata.elapsed_us)
        .bind(metadata.result_code)
        .bind(metadata.state_read_bytes)
        .bind(metadata.state_write_bytes)
        .bind(metadata.state_items)
        .bind(metadata.evicted_items)
        .bind(metadata.limit_hit)
        .execute(exec)
        .await?;

    Ok(())
}

async fn insert_filter_status<'e, E>(exec: E, metadata: &FilterStatusMetadata) -> Result<()>
where
    E: Acquire<'e, Database = Sqlite>,
{
    let mut tx = exec.begin().await?;

    sqlx::query(
        "DELETE FROM filters
         WHERE file_name = ?
           AND filter_id != ?"
    )
        .bind(&metadata.file_name)
        .bind(&metadata.filter_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO filters (
            filter_id, source_kind, file_name, path, explicit_id, name, enabled, valid,
            priority, script_hash, script_len, program_kind, last_error, loaded_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(filter_id) DO UPDATE SET
            source_kind = excluded.source_kind,
            file_name = excluded.file_name,
            path = excluded.path,
            explicit_id = excluded.explicit_id,
            name = excluded.name,
            enabled = excluded.enabled,
            valid = excluded.valid,
            priority = excluded.priority,
            script_hash = excluded.script_hash,
            script_len = excluded.script_len,
            program_kind = excluded.program_kind,
            last_error = excluded.last_error,
            loaded_at = excluded.loaded_at"
    )
        .bind(&metadata.filter_id)
        .bind(&metadata.source_kind)
        .bind(&metadata.file_name)
        .bind(&metadata.path)
        .bind(&metadata.explicit_id)
        .bind(&metadata.name)
        .bind(metadata.enabled as i64)
        .bind(metadata.valid as i64)
        .bind(metadata.priority.map(i64::from))
        .bind(&metadata.script_hash)
        .bind(metadata.script_len)
        .bind(&metadata.program_kind)
        .bind(&metadata.last_error)
        .bind(&metadata.loaded_at)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(())
}