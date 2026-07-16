-- glc_v1 audit log. Append-only; the application layer never issues
-- UPDATE or DELETE against this table.

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL    NOT NULL,
    session_id      TEXT,
    channel         TEXT    NOT NULL,
    channel_user_id TEXT    NOT NULL,
    trust_level     TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    tool            TEXT,
    policy_verdict  TEXT,
    params_json     TEXT,
    result_json     TEXT,
    prev_hash       TEXT,
    hash            TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_channel ON audit_log(channel, ts DESC);

-- Schema version table: any change to the columns above requires a
-- documented version bump. Migrations are not automatic.
CREATE TABLE IF NOT EXISTS audit_schema (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (1, strftime('%s','now'));

-- v2: prev_hash/hash columns above. store.py's init_store() ALTERs
-- existing v1 tables to add these columns (CREATE TABLE IF NOT EXISTS
-- alone won't add columns to an already-existing table).
INSERT OR IGNORE INTO audit_schema (version, applied_at) VALUES (2, strftime('%s','now'));
