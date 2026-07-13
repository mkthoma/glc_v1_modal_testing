"""Static checks: inspect local repo source rather than a running target.

These cover findings that are really deployment/config facts (A3-A6) or
a source-level pattern (L7) — not observable via a single HTTP call.
They always read the *local checkout*, never the deployed Modal app, so
if you've made the fix but haven't redeployed yet, these will already
show fixed while your live HTTP checks won't (that's expected — use
both).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from tools.findings_console.models import Check, CheckKind, CheckResult, Target, Verdict

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MODAL_APP = REPO_ROOT / "modal_app.py"
WHISPER_WRAPPER = REPO_ROOT / "glc" / "voice" / "stt" / "providers" / "whisper_cpp" / "wrapper.py"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        return f"__READ_ERROR__ {e}"


def _egress_wall_check(check_id: str) -> Callable[[Target], CheckResult]:
    def _run(_: Target) -> CheckResult:
        src = _read(MODAL_APP)
        if src.startswith("__READ_ERROR__"):
            return CheckResult(check_id, "local checkout", CheckKind.STATIC, Verdict.ERROR, src, src)
        has_sandbox = "modal.Sandbox" in src
        has_allowlist = bool(re.search(r"outbound_domain_allowlist|block_network", src))
        if has_sandbox and has_allowlist:
            verdict, summary = (
                Verdict.MITIGATED,
                "modal_app.py references Sandbox + an egress-allowlist-shaped kwarg — verify the allowlist is actually scoped per adapter, not just present",
            )
        elif has_sandbox:
            verdict, summary = (
                Verdict.VULNERABLE,
                "modal_app.py uses modal.Sandbox but no egress-allowlist kwarg was found",
            )
        else:
            verdict, summary = (
                Verdict.VULNERABLE,
                "modal_app.py defines no modal.Sandbox at all — every Function has unrestricted egress",
            )
        return CheckResult(check_id, "local checkout", CheckKind.STATIC, verdict, summary, src)

    return _run


CHECKS: list[Check] = [
    Check(
        id="A3",
        title="Single Function, no egress wall",
        invariant="INV-2",
        kind=CheckKind.STATIC,
        description="modal_app.py ships every component as one modal.Function with no outbound network control.",
        run=_egress_wall_check("A3"),
        plan_task="T1.13",
        attacker_role="AR3",
    ),
    Check(
        id="L6",
        title="Unbounded egress (same root cause as A3)",
        invariant="INV-2",
        kind=CheckKind.STATIC,
        description="Structural — no egress control anywhere in the deployment, so an adapter can reach any host.",
        run=_egress_wall_check("L6"),
        plan_task="T1.13",
        notes="Same underlying gap as A3; fixing one fixes both.",
        attacker_role="AR3",
    ),
    Check(
        id="A4",
        title="One Secret for the whole Function",
        invariant="INV-1",
        kind=CheckKind.STATIC,
        description="A single Secret is mounted to a single Function covering every route and every adapter.",
        run=lambda _: _check_a4(),
        plan_task="T1.11/T1.12",
        attacker_role="AR3",
    ),
    Check(
        id="A5",
        title="Non-reproducible image",
        invariant="supply chain",
        kind=CheckKind.STATIC,
        description="Image build hand-duplicates dependency ranges instead of consuming uv.lock, and the base image isn't pinned by digest.",
        run=lambda _: _check_a5(),
        plan_task="T1.9",
        notes="Supply-chain drift is a path to AR4 (arbitrary code execution in the gateway process "
        "via a poisoned dependency or a shifted base image), not a directly-triggered exploit.",
        attacker_role="AR4",
    ),
    Check(
        id="A6",
        title="Audit volume assumes one writer",
        invariant="INV-7",
        kind=CheckKind.STATIC,
        description="No max_containers=1 (or equivalent single-writer guarantee) on the Function that writes the SQLite audit/gateway DBs on a shared Volume.",
        run=lambda _: _check_a6(),
        plan_task="T1.10",
        notes="Not attacker-triggered in the usual sense — corruption risk grows with concurrent load, "
        "which any high-volume caller (AR1) can induce by hammering the data plane.",
        attacker_role="AR1",
    ),
    Check(
        id="L7",
        title="Subprocess / PATH injection in whisper_cpp",
        invariant="INV-1",
        kind=CheckKind.STATIC,
        description="whisper_cpp/wrapper.py resolves the whisper-cli binary via shutil.which() (PATH-dependent) instead of a fixed, configured path.",
        run=lambda _: _check_l7(),
        plan_task="T1.16",
        attacker_role="AR3",
    ),
]


def _check_a4() -> CheckResult:
    src = _read(MODAL_APP)
    function_defs = re.findall(r"@app\.function\(", src)
    sandbox_defs = re.findall(r"modal\.Sandbox\.create\(|make_adapter_function\(", src)
    total_components = len(function_defs) + len(sandbox_defs)
    if total_components <= 1:
        verdict, summary = (
            Verdict.VULNERABLE,
            f"only {total_components} Function/Sandbox definition found in modal_app.py — every "
            f"route and every adapter still shares the one Secret mounted to it",
        )
    else:
        verdict, summary = (
            Verdict.MITIGATED,
            f"{total_components} Function/Sandbox definitions found — verify each adapter's Secret "
            f"is actually scoped to only that adapter's own credential, not the shared LLM key Secret",
        )
    return CheckResult("A4", "local checkout", CheckKind.STATIC, verdict, summary, src)


def _check_a5() -> CheckResult:
    src = _read(MODAL_APP)
    uses_lockfile = bool(re.search(r"pip_install_from_pyproject|uv_sync|from_dockerfile", src))
    hand_listed = bool(re.search(r"\.pip_install\(\s*\n?\s*\"", src))
    pinned_digest = bool(re.search(r"@sha256:[0-9a-f]{64}", src))
    problems = []
    if hand_listed and not uses_lockfile:
        problems.append("dependencies are hand-listed with pip_install(...) instead of building from uv.lock")
    if not pinned_digest:
        problems.append("base image is not pinned by digest (no @sha256:... reference found)")
    if problems:
        verdict, summary = Verdict.VULNERABLE, "; ".join(problems)
    else:
        verdict, summary = (
            Verdict.CLOSED,
            "image build consumes the lockfile and the base image is digest-pinned",
        )
    return CheckResult("A5", "local checkout", CheckKind.STATIC, verdict, summary, src)


def _check_a6() -> CheckResult:
    src = _read(MODAL_APP)
    has_single_writer = bool(re.search(r"max_containers\s*=\s*1\b", src))
    if has_single_writer:
        verdict, summary = (
            Verdict.MITIGATED,
            "max_containers=1 found — trades scalability for a single audit-log writer (the Part-1-scoped mitigation; a real fix needs a dedicated writer process or managed DB)",
        )
    else:
        verdict, summary = (
            Verdict.VULNERABLE,
            "no max_containers=1 (or equivalent) found — the Function writing to the SQLite Volume can scale beyond one concurrent writer",
        )
    return CheckResult("A6", "local checkout", CheckKind.STATIC, verdict, summary, src)


def _check_l7() -> CheckResult:
    src = _read(WHISPER_WRAPPER)
    if src.startswith("__READ_ERROR__"):
        return CheckResult("L7", "local checkout", CheckKind.STATIC, Verdict.ERROR, src, src)
    uses_which = "shutil.which(" in src
    uses_fixed_path = bool(re.search(r"GLC_WHISPER_CLI_PATH|WHISPER_CLI_PATH\s*=", src))
    if uses_which and not uses_fixed_path:
        verdict, summary = (
            Verdict.VULNERABLE,
            "shutil.which('whisper-cli') resolves the binary via PATH — exploitable if an earlier PATH entry is attacker-writable",
        )
    elif uses_fixed_path and not uses_which:
        verdict, summary = (
            Verdict.MITIGATED,
            "resolves via a fixed/configured path, not PATH search — full closure still needs Move B (container isolation) since a Python process can still execute other installed binaries",
        )
    else:
        verdict, summary = Verdict.ERROR, "could not determine resolution strategy from source"
    return CheckResult("L7", "local checkout", CheckKind.STATIC, verdict, summary, src)
