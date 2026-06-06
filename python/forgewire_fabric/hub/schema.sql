-- ForgeWire hub schema (v1).
-- Designed so a future modules/remote_subagent/ can absorb this file in
-- place without migration.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_version (version, applied_at)
VALUES (1, datetime('now'));
INSERT OR IGNORE INTO schema_version (version, applied_at)
VALUES (2, datetime('now'));

-- ----------------------------------------------------------------------
-- tasks: sealed task records dispatched from main agent to remote runner
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    todo_id         TEXT,                       -- optional human ref (e.g. "109-jobs")
    title           TEXT NOT NULL,
    prompt          TEXT NOT NULL,              -- sealed brief shipped to runner
    scope_globs     TEXT NOT NULL,              -- json array of glob strings
    base_commit     TEXT NOT NULL,              -- commit sha task is based on
    branch          TEXT NOT NULL,              -- e.g. agent/optiplex/109-jobs
    timeout_minutes INTEGER NOT NULL DEFAULT 60,
    priority        INTEGER NOT NULL DEFAULT 100,
    -- kind: routing class for the task.
    --   'agent'   = sealed brief for a Copilot-Chat agent runner (default).
    --   'command' = shell/script payload for a non-agent (cmd) runner.
    -- Hub uses this to keep agent runners and command runners on disjoint queues.
    kind            TEXT NOT NULL DEFAULT 'agent',
    status          TEXT NOT NULL DEFAULT 'queued',
                    -- queued | claimed | running | reporting | done |
                    -- failed | cancelled | timed_out
    worker_id       TEXT,                       -- runner that claimed it
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    claimed_at      TEXT,
    started_at      TEXT,
    completed_at    TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    metadata        TEXT NOT NULL DEFAULT '{}', -- json for forward-compat
    -- v2 columns (defined at creation so no ALTER TABLE needed)
    required_tools        TEXT NOT NULL DEFAULT '[]',
    required_tags         TEXT NOT NULL DEFAULT '[]',
    tenant                TEXT,
    workspace_root        TEXT,
    require_base_commit   INTEGER NOT NULL DEFAULT 0,
    dispatcher_id         TEXT,
    required_capabilities TEXT NOT NULL DEFAULT '[]',
    secrets_needed        TEXT NOT NULL DEFAULT '[]',
    network_egress        TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_status_priority
    ON tasks (status, priority DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_tasks_branch ON tasks (branch);
CREATE INDEX IF NOT EXISTS idx_tasks_todo_id ON tasks (todo_id);

-- ----------------------------------------------------------------------
-- results: terminal report from the runner
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS results (
    task_id         INTEGER PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    status          TEXT NOT NULL,              -- mirrors final tasks.status
    branch          TEXT NOT NULL,
    head_commit     TEXT,
    commits_json    TEXT NOT NULL DEFAULT '[]',
    files_touched   TEXT NOT NULL DEFAULT '[]',
    test_summary    TEXT,                       -- short string e.g. "12 pass / 0 fail"
    log_tail        TEXT,                       -- last N lines of runner log
    error           TEXT,                       -- present iff status in (failed, timed_out)
    reported_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ----------------------------------------------------------------------
-- progress: streaming progress beats from runner -> blackboard -> dispatcher
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS progress (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    message         TEXT NOT NULL,
    files_touched   TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_progress_task_seq
    ON progress (task_id, seq);

-- ----------------------------------------------------------------------
-- notes: bidirectional free-form back-channel
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    author          TEXT NOT NULL,              -- 'dispatcher' | 'runner' | <freeform>
    body            TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_notes_task ON notes (task_id, id);

-- ----------------------------------------------------------------------
-- workers: heartbeat/registry for runners
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS workers (
    worker_id       TEXT PRIMARY KEY,
    hostname        TEXT,
    capabilities    TEXT NOT NULL DEFAULT '{}', -- json
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    current_task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL
);

-- ----------------------------------------------------------------------
-- runners (v2): rich registry with capabilities, identity, scope affinity,
-- heartbeat-driven state machine, and authenticated registration.
--
-- A runner row is the durable identity (UUID + public_key). The legacy
-- ``workers`` table is still maintained for backward compat with the
-- ``claim_next_task`` code path; new code reads from ``runners``.
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS runners (
    runner_id        TEXT PRIMARY KEY,           -- UUID4 generated once per host
    public_key       TEXT NOT NULL,              -- ed25519 hex (32 bytes)
    hostname         TEXT NOT NULL,
    os               TEXT NOT NULL,              -- e.g. "Windows-10-10.0.19045"
    arch             TEXT NOT NULL,              -- e.g. "AMD64"
    cpu_model        TEXT,
    cpu_count        INTEGER,
    ram_mb           INTEGER,
    gpu              TEXT,                       -- short label or null
    tools            TEXT NOT NULL DEFAULT '[]', -- json array of tool names
    tags             TEXT NOT NULL DEFAULT '[]', -- json array of tag strings
    scope_prefixes   TEXT NOT NULL DEFAULT '[]', -- json array of allowed path prefixes
    tenant           TEXT,                       -- optional tenant/workspace key
    workspace_root   TEXT,                       -- absolute path on the runner
    runner_version   TEXT NOT NULL,              -- runner code version string
    protocol_version INTEGER NOT NULL,           -- handshake major version
    max_concurrent   INTEGER NOT NULL DEFAULT 1,
    state            TEXT NOT NULL DEFAULT 'online',
                     -- online | degraded | offline | draining
    drain_requested  INTEGER NOT NULL DEFAULT 0,
    cpu_load_pct     REAL,
    ram_free_mb      INTEGER,
    battery_pct      INTEGER,                    -- null on AC/desktop
    on_battery       INTEGER NOT NULL DEFAULT 0,
    last_known_commit TEXT,                      -- HEAD on the runner's clone
    metadata         TEXT NOT NULL DEFAULT '{}',
    first_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    last_heartbeat   TEXT NOT NULL DEFAULT (datetime('now')),
    last_nonce       TEXT,                       -- replay protection
    -- v2 reliability counters
    claim_failures_total        INTEGER NOT NULL DEFAULT 0,
    claim_failures_consecutive  INTEGER NOT NULL DEFAULT 0,
    last_claim_error            TEXT,
    last_claim_error_at         TEXT,
    heartbeat_failures_total    INTEGER NOT NULL DEFAULT 0,
    capabilities                TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_runners_state    ON runners (state);
CREATE INDEX IF NOT EXISTS idx_runners_tenant   ON runners (tenant);
CREATE INDEX IF NOT EXISTS idx_runners_hostname ON runners (hostname);

-- ----------------------------------------------------------------------
-- task_streams (v2): structured stdout/stderr lines from runner -> hub.
-- Separate from ``progress`` so high-volume process output doesn't drown
-- the human-readable progress beat stream.
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS task_streams (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id         INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    seq             INTEGER NOT NULL,
    channel         TEXT NOT NULL,              -- 'stdout' | 'stderr' | 'info'
    line            TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_task_streams_task_seq
    ON task_streams (task_id, seq);

-- ----------------------------------------------------------------------
-- dispatchers (M2.4): mirror of runners for the dispatcher side
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dispatchers (
    dispatcher_id  TEXT PRIMARY KEY,
    public_key     TEXT NOT NULL,
    label          TEXT NOT NULL,
    hostname       TEXT,
    metadata       TEXT NOT NULL DEFAULT '{}',
    first_seen     TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_nonce     TEXT
);

-- ----------------------------------------------------------------------
-- labels: fabric-wide cosmetic labels (hub name, runner aliases)
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS labels (
    key         TEXT PRIMARY KEY,
    value_json  TEXT NOT NULL,
    updated_by  TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ----------------------------------------------------------------------
-- host_roles: installer-reported role facts per hostname
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS host_roles (
    hostname    TEXT NOT NULL,
    role        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    status      TEXT,
    metadata    TEXT NOT NULL DEFAULT '{}',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (hostname, role)
);

-- ----------------------------------------------------------------------
-- approvals (M2.5.1): human-approval queue for REQUIRE_APPROVAL holds
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approvals (
    approval_id      TEXT PRIMARY KEY,
    envelope_hash    TEXT NOT NULL,
    decision_json    TEXT NOT NULL,
    task_label       TEXT NOT NULL,
    branch           TEXT,
    scope_globs_json TEXT NOT NULL,
    dispatcher_id    TEXT,
    status           TEXT NOT NULL DEFAULT 'pending',
    approver         TEXT,
    reason           TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at      TEXT,
    consumed_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_approvals_status   ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_envelope ON approvals(envelope_hash, status);

-- ----------------------------------------------------------------------
-- audit_event (M2.5.3): append-only, hash-chained audit log
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_event (
    seq                  INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id_hash        TEXT NOT NULL UNIQUE,
    prev_event_id_hash   TEXT NOT NULL,
    kind                 TEXT NOT NULL,
    task_id              INTEGER,
    payload_json         TEXT NOT NULL,
    created_at           TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_task    ON audit_event(task_id, seq);
CREATE INDEX IF NOT EXISTS idx_audit_kind    ON audit_event(kind, seq);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_event(created_at);

-- ----------------------------------------------------------------------
-- secrets (M2.5.5a): sealed secret broker
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS secrets (
    name            TEXT PRIMARY KEY,
    ciphertext      TEXT NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_rotated_at TEXT
);

-- ----------------------------------------------------------------------
-- cost_ledger (M2.5.2): per-task cost actuals
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cost_ledger (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id             TEXT NOT NULL,
    dispatcher_id       TEXT,
    runner_id           TEXT,
    model_id            TEXT NOT NULL DEFAULT '',
    prompt_tokens       INTEGER NOT NULL DEFAULT 0,
    completion_tokens   INTEGER NOT NULL DEFAULT 0,
    cost_usd            REAL NOT NULL DEFAULT 0.0,
    wall_seconds        REAL NOT NULL DEFAULT 0.0,
    runner_cpu_seconds  REAL NOT NULL DEFAULT 0.0,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cost_task    ON cost_ledger(task_id);
CREATE INDEX IF NOT EXISTS idx_cost_created ON cost_ledger(created_at);
CREATE INDEX IF NOT EXISTS idx_cost_model   ON cost_ledger(model_id, created_at);
