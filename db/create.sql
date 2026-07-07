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


-- CREATE INDEX IF NOT EXISTS idx_filter_phase_stats_id_phase
--     ON filter_phase_stats(id, phase);
--
-- CREATE INDEX IF NOT EXISTS idx_filter_exec_stats_id_phase
--     ON filter_exec_stats(id, phase);
--
-- CREATE INDEX IF NOT EXISTS idx_filter_exec_stats_filter_phase
--     ON filter_exec_stats(filter_name, phase);

CREATE TABLE IF NOT EXISTS filters (
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
);


CREATE TABLE IF NOT EXISTS filter_exec_stats (
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
);