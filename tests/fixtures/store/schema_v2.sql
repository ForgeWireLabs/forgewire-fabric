-- ForgeWire hub schema — v2 snapshot (oracle/v2.7.0-baseline)
-- Captured: 2026-05-31
-- Source: python/forgewire_fabric/hub/schema.sql + additive migrations in server.py
--
-- The Rust REMOVED-M2.7.3 implementation MUST consume this schema without
-- changes to existing column names, types, or constraints. New columns are
-- additive-only. No column may be removed or renamed during the migration window.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

-- v1 and v2 both inserted at first start (idempotent INSERT OR IGNORE).
-- schema_version rows: (1, <ts>), (2, <ts>)

CREATE TABLE IF NOT EXISTS tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    todo_id         TEXT,
    title           TEXT NOT NULL,
    prompt          TEXT NOT NULL,
    scope_globs     TEXT NOT NULL,          -- JSON array
    base_commit     TEXT NOT NULL,
    branch          TEXT NOT NULL,
    timeout_minutes INTEGER NOT NULL DEFAULT 60,
    priority        INTEGER NOT NULL DEFAULT 100,
    kind            TEXT NOT NULL DEFAULT 'agent',  -- 'agent' | 'command'
    status          TEXT NOT NULL DEFAULT 'queued',
    worker_id       TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    claimed_at      TEXT,
    started_at      TEXT,
    completed_at    TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}',     -- JSON
    -- Additive columns (v2 migration, applied at runtime via ALTER TABLE ADD COLUMN):
    required_tools  TEXT,                           -- JSON array | NULL
    required_tags   TEXT,                           -- JSON array | NULL
    tenant          TEXT,
    workspace_root  TEXT,
    require_base_commit INTEGER NOT NULL DEFAULT 0,
    -- M2.5.4: structured capability predicates
    required_capabilities TEXT,                     -- JSON array | NULL
    -- M2.5.5a: declared secret names
    secrets_needed  TEXT,                           -- JSON array | NULL
    -- M2.5.5b: per-task egress policy
    network_egress  TEXT,                           -- JSON object | NULL
    -- dispatcher_id: which dispatcher created this task
    dispatcher_id   TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_status_priority
    ON tasks (status, priority DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_tasks_branch ON tasks (branch);
CREATE INDEX IF NOT EXISTS idx_tasks_todo_id ON tasks (todo_id);

CREATE TABLE IF NOT EXISTS results (
    task_id         INTEGER PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    status          TEXT NOT NULL,
    branch          TEXT NOT NULL,
    head_commit     TEXT,
    commits_json    TEXT NOT NULL DEFAULT '[]',
    files_touched   TEXT NOT NULL DEFAULT '[]',
    test_summary    TEXT,
    log_tail        TEXT,
    error           TEXT,
    reported_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS progress (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    message         TEXT NOT NULL,
    files_touched   TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_progress_task_seq ON progress (task_id, seq);

CREATE TABLE IF NOT EXISTS notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    author          TEXT NOT NULL,
    body            TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_notes_task ON notes (task_id, id);

CREATE TABLE IF NOT EXISTS workers (
    worker_id       TEXT PRIMARY KEY,
    hostname        TEXT,
    capabilities    TEXT NOT NULL DEFAULT '{}',
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    current_task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS runners (
    runner_id        TEXT PRIMARY KEY,
    public_key       TEXT NOT NULL,
    hostname         TEXT NOT NULL,
    os               TEXT NOT NULL,
    arch             TEXT NOT NULL,
    cpu_model        TEXT,
    cpu_count        INTEGER,
    ram_mb           INTEGER,
    gpu              TEXT,
    tools            TEXT NOT NULL DEFAULT '[]',
    tags             TEXT NOT NULL DEFAULT '[]',
    scope_prefixes   TEXT NOT NULL DEFAULT '[]',
    tenant           TEXT,
    workspace_root   TEXT,
    runner_version   TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    max_concurrent   INTEGER NOT NULL DEFAULT 1,
    state            TEXT NOT NULL DEFAULT 'online',
    drain_requested  INTEGER NOT NULL DEFAULT 0,
    cpu_load_pct     REAL,
    ram_free_mb      INTEGER,
    battery_pct      INTEGER,
    on_battery       INTEGER NOT NULL DEFAULT 0,
    last_known_commit TEXT,
    metadata         TEXT NOT NULL DEFAULT '{}',
    first_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    last_heartbeat   TEXT NOT NULL DEFAULT (datetime('now')),
    last_nonce       TEXT,
    -- Additive columns (v2 migration):
    capabilities     TEXT NOT NULL DEFAULT '{}'  -- JSON object for M2.5.4 capability matching
);
CREATE INDEX IF NOT EXISTS idx_runners_state    ON runners (state);
CREATE INDEX IF NOT EXISTS idx_runners_tenant   ON runners (tenant);
CREATE INDEX IF NOT EXISTS idx_runners_hostname ON runners (hostname);

CREATE TABLE IF NOT EXISTS task_streams (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    channel         TEXT NOT NULL,      -- 'stdout' | 'stderr' | 'info'
    line            TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_task_streams_task_seq ON task_streams (task_id, seq);

CREATE TABLE IF NOT EXISTS dispatchers (
    dispatcher_id   TEXT PRIMARY KEY,
    public_key      TEXT NOT NULL,
    label           TEXT NOT NULL,
    hostname        TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dispatcher_nonces (
    dispatcher_id   TEXT NOT NULL REFERENCES dispatchers(dispatcher_id) ON DELETE CASCADE,
    nonce           TEXT NOT NULL,
    used_at         TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (dispatcher_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_dispatcher_nonces_used_at ON dispatcher_nonces (used_at);

CREATE TABLE IF NOT EXISTS runner_nonces (
    runner_id       TEXT NOT NULL REFERENCES runners(runner_id) ON DELETE CASCADE,
    nonce           TEXT NOT NULL,
    used_at         TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (runner_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_runner_nonces_used_at ON runner_nonces (used_at);

CREATE TABLE IF NOT EXISTS audit_event (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id_hash   TEXT NOT NULL UNIQUE,
    prev_event_id_hash TEXT NOT NULL,
    kind            TEXT NOT NULL,       -- 'dispatch' | 'claim' | 'result'
    task_id         INTEGER,
    payload_json    TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_event (task_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_day  ON audit_event (created_at);

CREATE TABLE IF NOT EXISTS host_roles (
    hostname        TEXT NOT NULL,
    role            TEXT NOT NULL,       -- 'hub_head' | 'control' | 'dispatch' | 'command_runner' | 'agent_runner'
    enabled         INTEGER NOT NULL DEFAULT 1,
    status          TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}',
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (hostname, role)
);

CREATE TABLE IF NOT EXISTS labels (
    key             TEXT PRIMARY KEY,
    value_json      TEXT NOT NULL,
    updated_by      TEXT,
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id     TEXT PRIMARY KEY,
    envelope_hash   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',  -- 'pending' | 'approved' | 'denied' | 'consumed'
    decision_json   TEXT NOT NULL DEFAULT '{}',
    task_label      TEXT,
    branch          TEXT,
    scope_globs_json TEXT NOT NULL DEFAULT '[]',
    dispatcher_id   TEXT,
    approver        TEXT,
    reason          TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals (status);
CREATE INDEX IF NOT EXISTS idx_approvals_envelope ON approvals (envelope_hash);

CREATE TABLE IF NOT EXISTS secrets (
    name            TEXT PRIMARY KEY,
    encrypted_value TEXT NOT NULL,      -- AES-256-GCM encrypted, base64
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_rotated_at TEXT
);
