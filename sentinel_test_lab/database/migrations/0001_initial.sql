CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    base_url TEXT NOT NULL UNIQUE,
    scheme TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    environment TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    authorization_statement TEXT NOT NULL,
    authorized_at TEXT NOT NULL,
    allowed_paths TEXT NOT NULL,
    allowed_methods TEXT NOT NULL,
    pinned_ips TEXT NOT NULL,
    allow_private INTEGER NOT NULL DEFAULT 0,
    network_class TEXT NOT NULL DEFAULT 'public',
    ownership_verified INTEGER NOT NULL DEFAULT 0,
    verify_token TEXT NOT NULL DEFAULT '',
    verify_tls INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    test_type TEXT NOT NULL,
    target_id INTEGER,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL,
    backend TEXT NOT NULL DEFAULT 'internal',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    stop_reason TEXT NOT NULL DEFAULT '',
    config TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '{}',
    details TEXT NOT NULL DEFAULT '{}',
    series TEXT NOT NULL DEFAULT '[]',
    findings TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX idx_runs_started ON runs (started_at DESC);
CREATE INDEX idx_runs_type ON runs (test_type);

CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    run_id INTEGER,
    data TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_ts ON audit (ts DESC);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
