CREATE TABLE IF NOT EXISTS requests (
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
);

CREATE TABLE IF NOT EXISTS responses (
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
);

CREATE TABLE IF NOT EXISTS filter_phase_stats (
    id TEXT NOT NULL,              -- flow/request id
    seq INTEGER NOT NULL,
    flow_key TEXT NOT NULL,
    phase TEXT NOT NULL,           -- request|response|completed
    total_elapsed_us INTEGER NOT NULL,
    loaded_filters INTEGER NOT NULL,
    matched_filters INTEGER NOT NULL,
    executed_filters INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_filter_phase_stats_id_phase
    ON filter_phase_stats(id, phase);

CREATE TABLE IF NOT EXISTS filter_exec_stats (
    id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    flow_key TEXT NOT NULL,
    phase TEXT NOT NULL,
    filter_name TEXT NOT NULL,     -- path全部よりname優先で軽量化
    elapsed_us INTEGER NOT NULL,
    result_code INTEGER NOT NULL,  -- 0=ok,1=error,2=quarantined
    continue_filters INTEGER,      -- 0/1/null
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_filter_exec_stats_id_phase
    ON filter_exec_stats(id, phase);

CREATE INDEX IF NOT EXISTS idx_filter_exec_stats_filter_phase
    ON filter_exec_stats(filter_name, phase);

