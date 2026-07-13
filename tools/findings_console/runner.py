"""Executes a Check against a Target and records the result.

Always normalizes `result.check_id` to the id actually invoked — this
matters for the L9 alias in registry.py, whose underlying function
hardcodes "C2" as its result id internally. Also stamps every result
with the local checkout's current git commit (gitinfo.py), so a later
`closed` verdict can show which commit actually fixed the finding.
"""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path

from tools.findings_console import gitinfo, store
from tools.findings_console.models import Check, CheckKind, CheckResult, Target, Verdict

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def run_check(check: Check, target: Target) -> CheckResult:
    t0 = time.time()
    try:
        result = check.run(target)
    except Exception as e:  # a check itself blowing up is data, not a crash
        result = CheckResult(
            check_id=check.id,
            target_name=target.name,
            kind=check.kind,
            verdict=Verdict.ERROR,
            summary=f"check raised {type(e).__name__}: {e}",
            evidence=f"elapsed={time.time() - t0:.2f}s",
            error=str(e),
        )
    result = dataclasses.replace(
        result,
        check_id=check.id,
        git_commit=gitinfo.current_commit(REPO_ROOT),
    )
    store.record(result)
    return result


def run_all(checks: list[Check], target: Target, kinds: set[CheckKind] | None = None) -> list[CheckResult]:
    out = []
    for c in checks:
        if kinds is not None and c.kind not in kinds:
            continue
        out.append(run_check(c, target))
    return out
