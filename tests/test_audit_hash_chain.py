"""L2/L3 — hash-chained audit log (defense-in-depth).

Before this, the audit log was an ordinary SQLite file: any in-process
code could open it directly and DELETE/UPDATE rows with no trace (L2),
and there was no way to detect a rewritten history. Full prevention
needs Move B (process/container separation); this makes tampering
*detectable* in the meantime — the chain breaks the moment a row is
altered or removed.
"""

from __future__ import annotations

import sqlite3

from glc.audit import store
from glc.audit.store import append, init_store, verify_chain


def test_clean_chain_verifies_ok():
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="a")
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="b")
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="c")
    ok, broken_at = verify_chain()
    assert ok is True
    assert broken_at is None


def test_rows_are_actually_chained(monkeypatch, tmp_path):
    db_path = tmp_path / "audit.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(db_path))
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="a")
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="b")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT id, prev_hash, hash FROM audit_log ORDER BY id").fetchall()
    conn.close()

    assert rows[0]["prev_hash"] == ""
    assert rows[0]["hash"]
    assert rows[1]["prev_hash"] == rows[0]["hash"]
    assert rows[1]["hash"] != rows[0]["hash"]


def test_deleting_a_row_breaks_the_chain(monkeypatch, tmp_path):
    db_path = tmp_path / "audit.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(db_path))
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="a")
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="b")
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="c")

    ok, _ = verify_chain()
    assert ok is True

    # An in-process attacker with raw sqlite access — this is exactly
    # what L2 says any in-process code can already do.
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM audit_log WHERE event_type='b'")
    conn.commit()
    conn.close()

    ok, broken_at = verify_chain()
    assert ok is False
    assert broken_at is not None


def test_known_limitation_deleting_the_tail_is_not_detected(monkeypatch, tmp_path):
    """Documented, honest limitation: hash-chaining without an external
    checkpoint can only catch tampering that some later, still-present
    row's prev_hash still references. Deleting the most recent row(s) —
    or the whole table — leaves nothing to contradict the deletion, so
    verify_chain() reports the (now-shorter) chain as intact. This is
    why L2 is 'mitigated', not 'closed', in FINDINGS.md."""
    db_path = tmp_path / "audit.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(db_path))
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="a")
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="b")

    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM audit_log WHERE event_type='b'")  # the tail
    conn.commit()
    conn.close()

    ok, broken_at = verify_chain()
    assert ok is True
    assert broken_at is None


def test_editing_a_row_in_place_breaks_the_chain(monkeypatch, tmp_path):
    db_path = tmp_path / "audit.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(db_path))
    init_store()
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="a")

    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE audit_log SET event_type='tampered' WHERE event_type='a'")
    conn.commit()
    conn.close()

    ok, broken_at = verify_chain()
    assert ok is False
    assert broken_at is not None


def test_legacy_unhashed_rows_do_not_count_as_tampered(monkeypatch, tmp_path):
    """Rows written before this migration have hash IS NULL — they must
    not make an otherwise-clean post-migration chain report as broken."""
    db_path = tmp_path / "audit.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(db_path))
    init_store()

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO audit_log (ts, channel, channel_user_id, trust_level, event_type) "
        "VALUES (0, 'legacy', '1', 'owner_paired', 'pre_migration')"
    )
    conn.commit()
    conn.close()

    store._singleton = None
    append(channel="x", channel_user_id="1", trust_level="owner_paired", event_type="post_migration")

    ok, broken_at = verify_chain()
    assert ok is True
    assert broken_at is None


def test_init_store_migrates_existing_v1_table(monkeypatch, tmp_path):
    """A DB created before this fix has no prev_hash/hash columns at
    all — init_store() must ALTER TABLE to add them, not just no-op."""
    db_path = tmp_path / "audit.sqlite"
    monkeypatch.setenv("GLC_AUDIT_DB", str(db_path))

    conn = sqlite3.connect(db_path)
    conn.execute(
        """CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            session_id TEXT,
            channel TEXT NOT NULL,
            channel_user_id TEXT NOT NULL,
            trust_level TEXT NOT NULL,
            event_type TEXT NOT NULL,
            tool TEXT,
            policy_verdict TEXT,
            params_json TEXT,
            result_json TEXT
        )"""
    )
    conn.commit()
    conn.close()

    init_store()

    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    conn.close()
    assert "prev_hash" in cols
    assert "hash" in cols
