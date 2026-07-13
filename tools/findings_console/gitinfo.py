"""Best-effort capture of the local checkout's git commit, attached to
every run so a `closed`/`mitigated` verdict can show which commit
actually fixed the finding — without you having to remember it or
copy-paste a SHA in by hand."""

from __future__ import annotations

import subprocess
from pathlib import Path


def current_commit(repo_root: Path, timeout: float = 5.0) -> str | None:
    """Short commit hash, with a suffix if the working tree has
    uncommitted changes (a "closed" verdict against a dirty tree means
    the fix isn't actually committed yet — worth flagging, not hiding).
    Returns None if this isn't a git checkout or git isn't on PATH."""
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if sha.returncode != 0:
        return None
    commit = sha.stdout.strip()
    if not commit:
        return None

    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return commit
    if status.returncode == 0 and status.stdout.strip():
        return f"{commit} (uncommitted changes present)"
    return commit
