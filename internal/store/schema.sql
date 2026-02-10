CREATE TABLE IF NOT EXISTS messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT    NOT NULL,
    session_id    TEXT    NOT NULL,
    direction     TEXT    NOT NULL,
    kind          TEXT    NOT NULL,
    method        TEXT,
    msg_id        TEXT,
    payload       TEXT    NOT NULL,
    size_bytes    INTEGER NOT NULL,
    blocked       INTEGER NOT NULL DEFAULT 0,
    audit         INTEGER NOT NULL DEFAULT 0,
    scrub_count   INTEGER NOT NULL DEFAULT 0,
    matched_rules TEXT,
    tool_name     TEXT,
    policy_action TEXT
);

CREATE INDEX IF NOT EXISTS idx_messages_session   ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_method    ON messages(method);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    ended_at   TEXT,
    command    TEXT NOT NULL,
    args       TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    id         TEXT PRIMARY KEY,
    timestamp  TEXT NOT NULL,
    session_id TEXT NOT NULL,
    direction  TEXT NOT NULL,
    method     TEXT,
    tool_name  TEXT,
    rule_name  TEXT NOT NULL,
    payload    TEXT NOT NULL,
    decision   TEXT NOT NULL,
    decided_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id);

CREATE TABLE IF NOT EXISTS tool_registry (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL,
    tool_name   TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    first_seen  TEXT    NOT NULL,
    UNIQUE(session_id, tool_name)
);
CREATE INDEX IF NOT EXISTS idx_tool_registry_session ON tool_registry(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_registry_tool    ON tool_registry(tool_name);
