"""Static checks: inspect local repo source rather than a running target.

These cover findings that are really deployment/config facts (A3-A6) or
a source-level pattern (L7) — not observable via a single HTTP call.
They always read a *local checkout* — with_fixes/ (hardened) by
default, or without_fixes/ (baseline) when run against the "before"
target — never the deployed Modal app itself, so if you've made a fix
but haven't redeployed yet, these will already show fixed while your
live HTTP checks won't (that's expected — use both).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from tools.findings_console.models import Check, CheckKind, CheckResult, Target, Verdict

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WITH_FIXES_ROOT = REPO_ROOT / "with_fixes"
WITHOUT_FIXES_ROOT = REPO_ROOT / "without_fixes"


def _variant_root(target: Target) -> Path:
    """ "before" reads the frozen pre-hardening snapshot; every other
    target name (including the default "after"/"modal") reads the
    hardened checkout — the only two variants that exist."""
    return WITHOUT_FIXES_ROOT if target.name == "before" else WITH_FIXES_ROOT


def _modal_app_path(target: Target) -> Path:
    return _variant_root(target) / "modal_app.py"


def _whisper_wrapper_path(target: Target) -> Path:
    return _variant_root(target) / "glc" / "voice" / "stt" / "providers" / "whisper_cpp" / "wrapper.py"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        return f"__READ_ERROR__ {e}"


def _egress_wall_check(check_id: str) -> Callable[[Target], CheckResult]:
    def _run(target: Target) -> CheckResult:
        src = _read(_modal_app_path(target))
        if src.startswith("__READ_ERROR__"):
            return CheckResult(check_id, target.name, CheckKind.STATIC, Verdict.ERROR, src, src)
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
        return CheckResult(check_id, target.name, CheckKind.STATIC, verdict, summary, src)

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
        command='grep -nE "modal\\.Sandbox|outbound_domain_allowlist|block_network" with_fixes/modal_app.py',
        fix_summary=(
            "with_fixes/modal_app.py's verify_telegram_egress_allowlist() local_entrypoint uses "
            "modal.Sandbox.create(..., outbound_domain_allowlist=TELEGRAM_EGRESS_ALLOWLIST) for telegram. "
            "Container separation (Move B/C) is done for all 15 adapters; the egress allowlist itself is "
            "only demonstrated for telegram, not wired into every adapter's live webhook dispatch path — "
            "stays mitigated, not closed, until it is."
        ),
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
        command='grep -nE "modal\\.Sandbox|outbound_domain_allowlist|block_network" with_fixes/modal_app.py',
        fix_summary="Same fix as A3 above — same root cause, same commit.",
    ),
    Check(
        id="A4",
        title="One Secret for the whole Function",
        invariant="INV-1",
        kind=CheckKind.STATIC,
        description="A single Secret is mounted to a single Function covering every route and every adapter.",
        run=lambda t: _check_a4(t),
        plan_task="T1.11/T1.12",
        attacker_role="AR3",
        command="grep -n 'ADAPTER_SECRETS' -A 20 with_fixes/modal_app.py",
        fix_summary=(
            "with_fixes/modal_app.py's ADAPTER_SECRETS dict maps every one of the 15 catalogue adapters "
            "to its own Secret name (or None for local_mic/webui, which need no external credential) — "
            "never glc-llm-keys, the Secret the core gateway mounts for provider keys. This check parses "
            "that dict directly and reports CLOSED only if every non-null entry is distinct and none "
            "collides with glc-llm-keys."
        ),
    ),
    Check(
        id="A5",
        title="Non-reproducible image",
        invariant="supply chain",
        kind=CheckKind.STATIC,
        description="Image build hand-duplicates dependency ranges instead of consuming uv.lock, and the base image isn't pinned by digest.",
        run=lambda t: _check_a5(t),
        plan_task="T1.9",
        notes="Supply-chain drift is a path to AR4 (arbitrary code execution in the gateway process "
        "via a poisoned dependency or a shifted base image), not a directly-triggered exploit.",
        attacker_role="AR4",
        command='grep -nE "uv_sync|from_registry|@sha256:" with_fixes/modal_app.py',
        fix_summary=(
            "with_fixes/modal_app.py builds from modal.Image.from_registry('python:3.11-slim@sha256:...') "
            "(a digest-pinned base) piped into .uv_sync(extra_options='--no-dev'), which runs `uv sync "
            "--frozen` against this repo's own uv.lock instead of hand-listed pip_install(...) ranges."
        ),
    ),
    Check(
        id="A6",
        title="Audit volume assumes one writer",
        invariant="INV-7",
        kind=CheckKind.STATIC,
        description="No max_containers=1 (or equivalent single-writer guarantee) on the Function that writes the SQLite audit/gateway DBs on a shared Volume.",
        run=lambda t: _check_a6(t),
        plan_task="T1.10",
        notes="Not attacker-triggered in the usual sense — corruption risk grows with concurrent load, "
        "which any high-volume caller (AR1) can induce by hammering the data plane.",
        attacker_role="AR1",
        command="grep -n 'max_containers' with_fixes/modal_app.py",
        fix_summary=(
            "with_fixes/modal_app.py pins max_containers=1 on the core gateway Function. Mitigated, not "
            "closed: this trades away horizontal scalability to guarantee a single writer rather than "
            "adding real coordination — a dedicated writer process or a managed DB would close it properly."
        ),
    ),
    Check(
        id="L7",
        title="Subprocess / PATH injection in whisper_cpp",
        invariant="INV-1",
        kind=CheckKind.STATIC,
        description="whisper_cpp/wrapper.py resolves the whisper-cli binary via shutil.which() (PATH-dependent) instead of a fixed, configured path.",
        run=lambda t: _check_l7(t),
        plan_task="T1.16",
        attacker_role="AR3",
        command="grep -n 'shutil.which\\|WHISPER_CLI_PATH' with_fixes/glc/voice/stt/providers/whisper_cpp/wrapper.py",
        fix_summary=(
            "with_fixes/glc/voice/stt/providers/whisper_cpp/wrapper.py resolves WHISPER_CLI_PATH from "
            "GLC_WHISPER_CLI_PATH (default /usr/local/bin/whisper-cli), an absolute path checked with "
            ".is_file() before use — no PATH search, no shutil import at all. Closed for the "
            "PATH-injection vector itself; running inside a container with no other writable-then-"
            "executable path ahead of it is the separate, already-covered Move B guarantee (see L1/L3/"
            "L4/L8), not something this specific fix has to redo."
        ),
    ),
]


_LLM_SECRET_NAME = "glc-llm-keys"


def _check_a4(target: Target) -> CheckResult:
    src = _read(_modal_app_path(target))
    if src.startswith("__READ_ERROR__"):
        return CheckResult("A4", target.name, CheckKind.STATIC, Verdict.ERROR, src, src)
    dict_match = re.search(r"ADAPTER_SECRETS\s*:\s*dict\[[^\]]*\]\s*=\s*\{(.*?)\n\}", src, re.DOTALL)
    if not dict_match:
        return CheckResult(
            "A4",
            target.name,
            CheckKind.STATIC,
            Verdict.VULNERABLE,
            "no ADAPTER_SECRETS mapping found in modal_app.py — adapters likely still share one Secret",
            src,
        )
    entries = re.findall(r'"([^"]+)"\s*:\s*(None|"([^"]+)")', dict_match.group(1))
    if not entries:
        return CheckResult(
            "A4",
            target.name,
            CheckKind.STATIC,
            Verdict.ERROR,
            "ADAPTER_SECRETS was found but no adapter:secret entries could be parsed from it",
            src,
        )
    secret_names = [sec for (_name, raw, sec) in entries if raw != "None"]
    duplicates = {s for s in secret_names if secret_names.count(s) > 1}
    shares_llm_secret = _LLM_SECRET_NAME in secret_names
    if duplicates:
        verdict, summary = (
            Verdict.VULNERABLE,
            f"ADAPTER_SECRETS reuses the same Secret name across more than one adapter: {sorted(duplicates)}",
        )
    elif shares_llm_secret:
        verdict, summary = (
            Verdict.VULNERABLE,
            f"an adapter is scoped to {_LLM_SECRET_NAME!r}, the same Secret the core gateway uses for provider keys",
        )
    else:
        verdict, summary = (
            Verdict.CLOSED,
            f"{len(entries)} adapters mapped in ADAPTER_SECRETS, {len(secret_names)} distinct non-null "
            f"Secret name(s), none overlapping {_LLM_SECRET_NAME!r}",
        )
    return CheckResult("A4", target.name, CheckKind.STATIC, verdict, summary, src)


def _check_a5(target: Target) -> CheckResult:
    src = _read(_modal_app_path(target))
    if src.startswith("__READ_ERROR__"):
        return CheckResult("A5", target.name, CheckKind.STATIC, Verdict.ERROR, src, src)
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
    return CheckResult("A5", target.name, CheckKind.STATIC, verdict, summary, src)


def _check_a6(target: Target) -> CheckResult:
    src = _read(_modal_app_path(target))
    if src.startswith("__READ_ERROR__"):
        return CheckResult("A6", target.name, CheckKind.STATIC, Verdict.ERROR, src, src)
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
    return CheckResult("A6", target.name, CheckKind.STATIC, verdict, summary, src)


def _check_l7(target: Target) -> CheckResult:
    src = _read(_whisper_wrapper_path(target))
    if src.startswith("__READ_ERROR__"):
        return CheckResult("L7", target.name, CheckKind.STATIC, Verdict.ERROR, src, src)
    uses_which = "shutil.which(" in src
    uses_fixed_path = bool(re.search(r"GLC_WHISPER_CLI_PATH|WHISPER_CLI_PATH\s*=", src))
    if uses_which and not uses_fixed_path:
        verdict, summary = (
            Verdict.VULNERABLE,
            "shutil.which('whisper-cli') resolves the binary via PATH — exploitable if an earlier PATH entry is attacker-writable",
        )
    elif uses_fixed_path and not uses_which:
        verdict, summary = (
            Verdict.CLOSED,
            "resolves via a fixed/configured absolute path, not a PATH search — the PATH-injection "
            "vector this finding names is closed; a compromised container executing other installed "
            "binaries entirely is the separate, already-covered Move B guarantee (see L1/L3/L4/L8)",
        )
    else:
        verdict, summary = Verdict.ERROR, "could not determine resolution strategy from source"
    return CheckResult("L7", target.name, CheckKind.STATIC, verdict, summary, src)
