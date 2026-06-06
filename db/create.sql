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
    headers TEXT
);

CREATE TABLE IF NOT EXISTS responses (
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
);