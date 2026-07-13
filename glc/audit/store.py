"""Append-only SQLite audit log.

Every channel message, agent decision, policy verdict, and tool dispatch
lands here. Append-only is enforced at the application layer: only
`append()` is exposed; there is no update or delete function. The schema
is at `audit_schema` version 2 (see schema.sql); bumping it requires a
documented migration step.

Each append commits immediately so writes survive a hard kill.

Hash chaining (L2/L3 defense-in-depth): every row's `hash` column is
sha256(prev_hash + canonical_json(row)), chained off the previous row's
hash. This does not *prevent* an in-process caller with direct sqlite
access from tampering (that requires the process/container separation
of Move B) — but it makes tampering *detectable*: `verify_chain()`
walks the table and reports the first row where the recorded hash no
longer matches its content, or where the chain linkage breaks (e.g. a
DELETEd row leaves a gap the next row's prev_hash can't explain). This
assumes a single writer, same assumption as the A6 fix (max_containers=1)
— concurrent writers could each read the same "previous" hash and fork
the chain rather than extend it linearly.

Known limitation, inherent to hash-chaining without an external
checkpoint: `verify_chain()` can only detect tampering with a row that
some *later, still-present* row's `prev_hash` still references. Deleting
the most recent row(s) — or every row — leaves no later row to contradict
the deletion, so `verify_chain()` reports the (now-shorter) chain as
intact. Only mid-chain edits/deletes are caught. Closing this fully needs
an external, append-only checkpoint of the latest hash (e.g. published
somewhere the same attacker can't also reach) — out of scope for this
Part-1 mitigation, which targets the more common "quietly edit or remove
one record" tamper case.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.path.expanduser("~/.glc"))


def _resolve_path() -> str:
    """Resolve at call time, not import time, so tests that swap the env
    var see the change."""
    return os.getenv("GLC_AUDIT_DB", str(DEFAULT_DIR / "audit.sqlite"))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)  # autocommit; each insert flushes
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_store() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA_PATH.read_text())
        # v1 -> v2 migration: CREATE TABLE IF NOT EXISTS in schema.sql
        # won't add columns to an already-existing table.
        cols = {row["name"] for row in c.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "prev_hash" not in cols:
            c.execute("ALTER TABLE audit_log ADD COLUMN prev_hash TEXT")
        if "hash" not in cols:
            c.execute("ALTER TABLE audit_log ADD COLUMN hash TEXT")


def _jsonify(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, default=str)
    except Exception:
        return json.dumps({"_repr": repr(v)})


def _canonical_row(
    *,
    ts: float,
    session_id: str | None,
    channel: str,
    channel_user_id: str,
    trust_level: str,
    event_type: str,
    tool: str | None,
    policy_verdict: str | None,
    params_json: str | None,
    result_json: str | None,
) -> str:
    return json.dumps(
        {
            "ts": ts,
            "session_id": session_id,
            "channel": channel,
            "channel_user_id": channel_user_id,
            "trust_level": trust_level,
            "event_type": event_type,
            "tool": tool,
            "policy_verdict": policy_verdict,
            "params_json": params_json,
            "result_json": result_json,
        },
        sort_keys=True,
        default=str,
    )


def _last_hash(c: sqlite3.Connection) -> str:
    row = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return row["hash"] if row and row["hash"] else ""


class AuditStore:
    """Application-layer write-once store. The class deliberately exposes
    no update or delete methods. Reads (for the replay viewer) live in
    query() which is read-only."""

    def append(
        self,
        *,
        channel: str,
        channel_user_id: str,
        trust_level: str,
        event_type: str,
        session_id: str | None = None,
        tool: str | None = None,
        policy_verdict: str | None = None,
        params: Any = None,
        result: Any = None,
    ) -> int:
        ts = time.time()
        params_json = _jsonify(params)
        result_json = _jsonify(result)
        with _conn() as c:
            prev_hash = _last_hash(c)
            row_repr = _canonical_row(
                ts=ts,
                session_id=session_id,
                channel=channel,
                channel_user_id=channel_user_id,
                trust_level=trust_level,
                event_type=event_type,
                tool=tool,
                policy_verdict=policy_verdict,
                params_json=params_json,
                result_json=result_json,
            )
            row_hash = hashlib.sha256((prev_hash + row_repr).encode()).hexdigest()
            cur = c.execute(
                """INSERT INTO audit_log
                   (ts, session_id, channel, channel_user_id, trust_level,
                    event_type, tool, policy_verdict, params_json, result_json,
                    prev_hash, hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ts,
                    session_id,
                    channel,
                    channel_user_id,
                    trust_level,
                    event_type,
                    tool,
                    policy_verdict,
                    params_json,
                    result_json,
                    prev_hash,
                    row_hash,
                ),
            )
            return int(cur.lastrowid or 0)


_singleton: AuditStore | None = None


def get_store() -> AuditStore:
    global _singleton
    if _singleton is None:
        init_store()
        _singleton = AuditStore()
    return _singleton


def append(**kwargs: Any) -> int:
    return get_store().append(**kwargs)


def query(limit: int = 100, session_id: str | None = None, channel: str | None = None) -> list[dict]:
    q = "SELECT * FROM audit_log"
    where, args = [], []
    if session_id:
        where.append("session_id=?")
        args.append(session_id)
    if channel:
        where.append("channel=?")
        args.append(channel)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args).fetchall()]


def verify_chain() -> tuple[bool, int | None]:
    """Walk the audit log in id order and confirm the hash chain is
    unbroken. Returns (ok, first_broken_id) — first_broken_id is None
    when ok is True. Rows written before the hash-chaining migration
    (hash IS NULL) are legacy and skipped rather than treated as
    tampered; the chain is only verified from the first hashed row
    onward."""
    with _conn() as c:
        rows = c.execute(
            "SELECT id, ts, session_id, channel, channel_user_id, trust_level, "
            "event_type, tool, policy_verdict, params_json, result_json, prev_hash, hash "
            "FROM audit_log ORDER BY id ASC"
        ).fetchall()
    prev_hash_seen: str | None = None
    for row in rows:
        if row["hash"] is None:
            continue
        row_repr = _canonical_row(
            ts=row["ts"],
            session_id=row["session_id"],
            channel=row["channel"],
            channel_user_id=row["channel_user_id"],
            trust_level=row["trust_level"],
            event_type=row["event_type"],
            tool=row["tool"],
            policy_verdict=row["policy_verdict"],
            params_json=row["params_json"],
            result_json=row["result_json"],
        )
        expected_hash = hashlib.sha256(((row["prev_hash"] or "") + row_repr).encode()).hexdigest()
        if row["hash"] != expected_hash:
            return False, int(row["id"])
        if prev_hash_seen is not None and row["prev_hash"] != prev_hash_seen:
            return False, int(row["id"])
        prev_hash_seen = row["hash"]
    return True, None


def schema_version() -> int:
    with _conn() as c:
        row = c.execute("SELECT MAX(version) AS v FROM audit_schema").fetchone()
        return int(row["v"] or 0)
