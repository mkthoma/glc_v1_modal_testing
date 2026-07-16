"""Append-only SQLite log of every check run.

Deliberately mirrors glc/audit/store.py's shape (only an insert is
exposed, autocommit, no update/delete) — the same append-only pattern
the assignment is teaching, applied to your own testing tool.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from tools.findings_console.models import ATTACKER_ROLES, Check, CheckResult, Verdict, describe_invariant
from tools.findings_console.sections import build_sections

DEFAULT_DB = Path(__file__).resolve().parent.parent.parent / ".findings_console" / "console.sqlite"


def _resolve_path() -> str:
    return os.getenv("FINDINGS_CONSOLE_DB", str(DEFAULT_DB))


@contextmanager
def _conn():
    p = _resolve_path()
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(p, isolation_level=None)
    c.row_factory = sqlite3.Row
    try:
        yield c
    finally:
        c.close()


def _ensure_column(c: sqlite3.Connection, table: str, column: str, coltype: str) -> None:
    """Additive schema migration for DBs created before this column
    existed — CREATE TABLE IF NOT EXISTS alone doesn't add columns to
    an already-existing table."""
    cols = [row["name"] for row in c.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def init_db() -> None:
    with _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                check_id TEXT NOT NULL,
                target_name TEXT NOT NULL,
                kind TEXT NOT NULL,
                verdict TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence TEXT NOT NULL,
                error TEXT,
                git_commit TEXT
            )"""
        )
        _ensure_column(c, "runs", "git_commit", "TEXT")
        c.execute("CREATE INDEX IF NOT EXISTS idx_check_ts ON runs(check_id, ts DESC)")


def record(result: CheckResult) -> int:
    with _conn() as c:
        cur = c.execute(
            """INSERT INTO runs (ts, check_id, target_name, kind, verdict, summary, evidence, error, git_commit)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                time.time(),
                result.check_id,
                result.target_name,
                result.kind.value,
                result.verdict.value,
                result.summary,
                result.evidence,
                result.error,
                result.git_commit,
            ),
        )
        return int(cur.lastrowid or 0)


def _row_to_dict(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "ts": r["ts"],
        "check_id": r["check_id"],
        "target_name": r["target_name"],
        "kind": r["kind"],
        "verdict": r["verdict"],
        "summary": r["summary"],
        "evidence": r["evidence"],
        "error": r["error"],
        "git_commit": r["git_commit"],
    }


def history(check_id: str, limit: int = 50) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM runs WHERE check_id=? ORDER BY ts DESC LIMIT ?",
            (check_id, limit),
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def earliest(check_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM runs WHERE check_id=? ORDER BY ts ASC LIMIT 1", (check_id,)).fetchone()
        return _row_to_dict(row) if row else None


def latest(check_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM runs WHERE check_id=? ORDER BY ts DESC LIMIT 1", (check_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def latest_for_target(check_id: str, target_name: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM runs WHERE check_id=? AND target_name=? ORDER BY ts DESC LIMIT 1",
            (check_id, target_name),
        ).fetchone()
        return _row_to_dict(row) if row else None


def clear_all() -> None:
    """Deletes every run, for every check and every target. Irreversible —
    the UI confirms before calling this."""
    with _conn() as c:
        c.execute("DELETE FROM runs")


def clear_for_check(check_id: str) -> None:
    """Deletes history for one check, across all targets."""
    with _conn() as c:
        c.execute("DELETE FROM runs WHERE check_id=?", (check_id,))


def latest_per_check() -> dict[str, dict]:
    """Returns {check_id: latest_run_dict} for every check that has at least one run."""
    with _conn() as c:
        rows = c.execute(
            """SELECT r.* FROM runs r
               INNER JOIN (SELECT check_id, MAX(ts) AS max_ts FROM runs GROUP BY check_id) m
               ON r.check_id = m.check_id AND r.ts = m.max_ts"""
        ).fetchall()
        return {r["check_id"]: _row_to_dict(r) for r in rows}


def _finding_lines(label: str, check: Check) -> list[str]:
    """The lines for one finding: the invariant/attacker-role sentence
    ASSIGNMENT.md asks for, then whatever's been run so far. Spells out
    what each code actually means rather than leaving a bare "INV-2" —
    a code with no description next to it isn't the "clear description"
    ASSIGNMENT.md's own wording asks for."""
    role_desc = ATTACKER_ROLES.get(check.attacker_role)
    if check.attacker_role and role_desc:
        role_line = f"{check.attacker_role} ({role_desc})"
    else:
        role_line = "(not classified)"
    inv_desc = describe_invariant(check.invariant)
    inv_line = f"{check.invariant} ({inv_desc})" if inv_desc else check.invariant

    lines = [f"### {label} — {check.title}", ""]
    lines.append(
        f"Breaks **{inv_line}** and is reachable by **{role_line}**."
        if check.attacker_role
        else f"Breaks **{inv_line}**. Attacker role not classified for this check."
    )
    lines.append("")

    last = latest(check.id)
    first = earliest(check.id)
    if last is None:
        lines.append("_Not yet run — no verdict recorded._")
    else:
        lines.append(f"- **Latest verdict:** `{last['verdict']}` ({last['target_name']}, {last['kind']})")
        lines.append(f"- **Latest summary:** {last['summary']}")
        if Verdict(last["verdict"]) in (Verdict.CLOSED, Verdict.MITIGATED) and last.get("git_commit"):
            lines.append(f"- **Fixed in commit:** `{last['git_commit']}`")
        if first and first["id"] != last["id"]:
            lines.append(f"- **Earliest recorded verdict:** `{first['verdict']}` — {first['summary']}")
    lines.append("")
    return lines


def export_markdown() -> str:
    """Grouped the way Session 12 §6/§7 group findings, not by
    PLAN.md's flat ground-truth order — a starting draft for the
    FINDINGS.md deliverable. ASSIGNMENT.md's own words: "For each
    finding, say in one sentence which invariant from Section 4 it
    breaks and which attacker role reaches it." — every finding leads
    with exactly that sentence, pulled from the check registry, not
    just the run log. Includes every registered check, not only ones
    you've run yet, so it doubles as a checklist."""
    from tools.findings_console.registry import REGISTRY  # local import: registry pulls in every
    # checks_*.py module (httpx, websockets, subprocess-spawning logic) — more than this
    # module's own append/query API needs, so it's kept lazy rather than a module-level import

    lines = ["# Findings console export", "", "Draft for `FINDINGS.md` — grouped as Session 12 §6/§7 do.", ""]
    for section in build_sections(REGISTRY):
        lines.append(f"## {section.title}")
        lines.append("")
        for item in section.items:
            lines.extend(_finding_lines(item.label, item.check))
    return "\n".join(lines)
