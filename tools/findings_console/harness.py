"""Runs an in-process check as an isolated subprocess.

Why a subprocess, not an import in this process: some in-process checks
(L8 in particular) call `os.kill(os.getpid(), SIGTERM)` — that must
terminate a disposable child, never the console server itself. Running
every in-process check this way, even the ones that don't self-terminate,
keeps the pattern uniform and keeps a check's monkey-patching (L5) or
singleton mutation (L3, L4) from bleeding into the console's own process
or into later checks.

Every run gets a fresh scratch GLC_CONFIG_DIR — this must never point at
your real ~/.glc, since L2's check genuinely deletes audit rows and L3's
genuinely writes a pairing record.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WITH_FIXES_ROOT = REPO_ROOT / "with_fixes"
WITHOUT_FIXES_ROOT = REPO_ROOT / "without_fixes"

# The line-oriented protocol every snippet must follow: print exactly one
# line starting with this prefix, containing the verdict token, so the
# harness can parse it out of whatever other stdout the snippet produces.
RESULT_PREFIX = "FINDINGS_CONSOLE_RESULT:"


@dataclass(frozen=True)
class HarnessRun:
    returncode: int
    stdout: str
    stderr: str
    result_line: str | None  # the parsed RESULT_PREFIX line, if the snippet printed one
    timed_out: bool


def run_snippet(
    snippet: str,
    timeout: float = 15.0,
    extra_env: dict[str, str] | None = None,
    glc_root: Path = WITH_FIXES_ROOT,
) -> HarnessRun:
    """Runs `snippet` in a subprocess that imports `glc` from `glc_root`
    (its parent directory goes on PYTHONPATH ahead of anything else, so
    it shadows the editable-installed with_fixes/glc when glc_root is
    without_fixes/ — the "before" baseline has no in-process mitigation
    at all, so these checks show the original vulnerable behavior
    against it, same snippet, no code duplicated per variant)."""
    scratch = Path(tempfile.mkdtemp(prefix="glc-findings-console-"))
    env = dict(os.environ)
    env["GLC_CONFIG_DIR"] = str(scratch)
    env["GLC_AUDIT_DB"] = str(scratch / "audit.sqlite")
    env["GLC_PAIRING_DB"] = str(scratch / "pairings.sqlite")
    env["GLC_GATEWAY_DB"] = str(scratch / "gateway.sqlite")
    env["GEMINI_API_KEY"] = env.get("GEMINI_API_KEY", "mock-key-findings-console")
    env["PYTHONPATH"] = str(glc_root) + os.pathsep + env.get("PYTHONPATH", "")
    if extra_env:
        env.update(extra_env)

    script_path = scratch / "snippet.py"
    script_path.write_text(snippet, encoding="utf-8")

    try:
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(REPO_ROOT),
            env=env,
        )
        timed_out = False
        returncode, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        timed_out = True
        returncode = -1
        stdout = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = (e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or "")

    result_line = next(
        (line for line in stdout.splitlines() if line.startswith(RESULT_PREFIX)),
        None,
    )
    return HarnessRun(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        result_line=result_line,
        timed_out=timed_out,
    )
