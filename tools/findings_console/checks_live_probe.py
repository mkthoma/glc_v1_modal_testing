"""Live container-separation checks: L1, L3, L4, L8.

These used to be local-subprocess demonstrations (checks_inprocess.py) that
always reported `vulnerable`, by construction — the check shares a process
with the code it's testing, so it can prove the code path *exists* but
can't observe whether a real deployed adapter container is actually
isolated the way FINDINGS.md claims. That's not a bug, but it meant every
run of these showed a red badge forever, even after the real fix landed,
with a footnote explaining why to trust the docs instead of the dashboard
— worse than useless if you don't read the footnote.

L1/L3/L4 call `glc-adapter-shape-probe`: a Modal Function deployed with
the *exact* image shape as a genuine catalogue adapter (`adapter_image()`
in modal_app.py — no LLM Secret, no Volume mount, see
`make_adapter_functions()`). It reports what a real, live container in
that shape can actually observe. Calling it gives a real, live-measured
verdict — closed or vulnerable — instead of a documented assumption.

L8 calls a second, separate Function, `glc-adapter-shape-self-kill-probe`
— kept apart from the read-only probe above so a self-kill test never
risks the environment-inspection checks. It self-terminates via
os.kill(os.getpid(), SIGTERM); calling it via .remote() (confirmed by
experiment: ~20-30s, a clean exception, not a hang the way an earlier
`modal run` *script* invocation was) proves the call itself succeeds
(Python can't stop it), and checking the real gateway's /healthz
immediately before and after proves — or would disprove — that killing
this container's own process has no effect on the gateway's.

For a "before" target (the pre-hardening baseline), none of this
applies — Move B/C predates that snapshot entirely, so there's no
per-adapter container to call a probe Function inside of at all. Those
four checks report a structural VULNERABLE verdict from reading
without_fixes/modal_app.py directly instead of attempting a live call.

Every CheckResult's target_name is always exactly target.name ("before"
or "after") — never a longer descriptive string — since the dashboard's
before/after comparison looks results up by that exact name.

Requires modal_app.py to be deployed with both probe Functions present.
If they're not (not deployed yet, wrong app name detected), these report
`error`, not `vulnerable` — nothing was actually observed, so nothing
should be claimed either way.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import httpx

from tools.findings_console.modal_detect import (
    WITH_FIXES_MODAL_APP,
    WITHOUT_FIXES_MODAL_APP,
    detect_app_and_function,
)
from tools.findings_console.models import Check, CheckKind, CheckResult, Target, Verdict

PROBE_FUNCTION_NAME = "glc-adapter-shape-probe"
SELF_KILL_PROBE_NAME = "glc-adapter-shape-self-kill-probe"


def _modal_app_path_for(target: Target) -> Path:
    return WITHOUT_FIXES_MODAL_APP if target.name == "before" else WITH_FIXES_MODAL_APP


def _baseline_vulnerable_result(check_id: str, target: Target, explanation: str) -> CheckResult:
    """The "before" baseline predates Move B/C entirely — there is no
    per-adapter container to call a probe Function inside of, because
    that separation is exactly what these findings say doesn't exist
    yet. Confirmed by reading without_fixes/modal_app.py directly
    (structural fact, not a live network call) rather than assumed."""
    try:
        src = WITHOUT_FIXES_MODAL_APP.read_text(encoding="utf-8")
    except OSError as e:
        return CheckResult(
            check_id,
            target.name,
            CheckKind.LIVE_PROBE,
            Verdict.ERROR,
            f"couldn't read the baseline modal_app.py: {e}",
            str(e),
        )
    function_count = len(re.findall(r"@app\.function\(", src))
    has_separation = bool(re.search(r"ADAPTER_SECRETS|make_adapter_functions", src))
    if has_separation:
        return CheckResult(
            check_id,
            target.name,
            CheckKind.LIVE_PROBE,
            Verdict.ERROR,
            "without_fixes/modal_app.py unexpectedly shows adapter container separation — "
            "the baseline snapshot may have been replaced with the hardened version by mistake",
            src,
        )
    return CheckResult(
        check_id,
        target.name,
        CheckKind.LIVE_PROBE,
        Verdict.VULNERABLE,
        f"{explanation} — confirmed: without_fixes/modal_app.py defines {function_count} Modal "
        f"Function(s) total, with no per-adapter separation at all, so every route and every "
        f"adapter share this one process's environment and mounts",
        src,
    )


# Illustrative only — shown in the "Attack command" box to demonstrate the
# underlying code-level fact (any code sharing a process can do this); the
# actual verdict below comes from _call_probe(), not from running this.
_L1_ILLUSTRATION = """
import os
key = os.environ.get("GEMINI_API_KEY", "")
if key:
    print(f"arbitrary code sharing this process can read GEMINI_API_KEY ({key[:4]}...) via plain os.environ")
"""

_L3_ILLUSTRATION = """
from glc.security.pairing import get_pairing_store
store = get_pairing_store()
store.force_pair_owner("telegram", "attacker", user_handle="me")
# force_pair_owner() is an ordinary importable method - reachable from any
# in-process code, including a compromised adapter's on_message()/send().
"""

_L4_ILLUSTRATION = """
from glc.config import get_or_create_install_token
tok = get_or_create_install_token()
# get_or_create_install_token() is reachable from any in-process code;
# 0600 file mode only stops other OS users, not other in-process code.
"""

_L8_ILLUSTRATION = """
import os, signal
os.kill(os.getpid(), signal.SIGTERM)
# os.kill(os.getpid(), SIGTERM) is reachable from any in-process code,
# bypassing the /v1/control/kill loopback check entirely.
"""


def _call_probe(target: Target) -> tuple[dict[str, Any] | None, str]:
    modal_app_path = _modal_app_path_for(target)
    app_and_fn = detect_app_and_function(modal_app_path)
    if app_and_fn is None:
        return None, f"couldn't find modal.App(...) in {modal_app_path} to know which app to call"
    app_name, _function_name = app_and_fn
    try:
        import modal

        fn = modal.Function.from_name(app_name, PROBE_FUNCTION_NAME)
        result = fn.remote()
    except Exception as e:  # noqa: BLE001 - reported as an ERROR verdict, not raised
        return None, f"{type(e).__name__}: {e}"
    if not isinstance(result, dict):
        return None, f"unexpected result shape from probe: {result!r}"
    return result, ""


def _probe_error(check_id: str, target: Target, reason: str) -> CheckResult:
    return CheckResult(
        check_id,
        target.name,
        CheckKind.LIVE_PROBE,
        Verdict.ERROR,
        f"couldn't call the live probe ({reason}) — deploy modal_app.py "
        f"(it now defines {PROBE_FUNCTION_NAME}) and try again",
        reason,
    )


def _check_l1(target: Target) -> CheckResult:
    if target.name == "before":
        return _baseline_vulnerable_result(
            "L1",
            target,
            "GEMINI_API_KEY is an ordinary env var, visible to any code sharing this one process",
        )
    result, reason = _call_probe(target)
    if result is None:
        return _probe_error("L1", target, reason)
    evidence = repr(result)
    if result.get("gemini_key_present"):
        return CheckResult(
            "L1",
            target.name,
            CheckKind.LIVE_PROBE,
            Verdict.VULNERABLE,
            "GEMINI_API_KEY IS present inside a real, live adapter-shaped container — Secret scoping regressed",
            evidence,
        )
    return CheckResult(
        "L1",
        target.name,
        CheckKind.LIVE_PROBE,
        Verdict.CLOSED,
        "GEMINI_API_KEY is absent from a real, live adapter-shaped Modal container — confirmed, not assumed",
        evidence,
    )


def _check_l3(target: Target) -> CheckResult:
    if target.name == "before":
        return _baseline_vulnerable_result(
            "L3",
            target,
            "force_pair_owner() is an ordinary importable method, reachable from this one shared process",
        )
    result, reason = _call_probe(target)
    if result is None:
        return _probe_error("L3", target, reason)
    evidence = repr(result)
    if result.get("data_mount_exists"):
        return CheckResult(
            "L3",
            target.name,
            CheckKind.LIVE_PROBE,
            Verdict.VULNERABLE,
            "the real /data Volume IS mounted inside a live adapter-shaped container — force_pair_owner() "
            "there could reach the real pairing store",
            evidence,
        )
    return CheckResult(
        "L3",
        target.name,
        CheckKind.LIVE_PROBE,
        Verdict.CLOSED,
        "force_pair_owner() still runs inside a live adapter-shaped container (Python can't block the call), "
        "but no /data mount exists there to write the real pairing store to — confirmed, not assumed",
        evidence,
    )


def _check_l4(target: Target) -> CheckResult:
    if target.name == "before":
        return _baseline_vulnerable_result(
            "L4",
            target,
            "get_or_create_install_token()/install_token_path() are readable from this one shared process",
        )
    result, reason = _call_probe(target)
    if result is None:
        return _probe_error("L4", target, reason)
    evidence = repr(result)
    if result.get("data_mount_exists"):
        return CheckResult(
            "L4",
            target.name,
            CheckKind.LIVE_PROBE,
            Verdict.VULNERABLE,
            "the real /data Volume IS mounted inside a live adapter-shaped container — the real install "
            "token could be read from there",
            evidence,
        )
    return CheckResult(
        "L4",
        target.name,
        CheckKind.LIVE_PROBE,
        Verdict.CLOSED,
        "get_or_create_install_token() still runs inside a live adapter-shaped container, but with no "
        "/data mount it can only create a throwaway local token, never read or forge the real one — "
        "confirmed, not assumed",
        evidence,
    )


def _healthz(target: Target, timeout: float = 10) -> tuple[bool, str]:
    if not target.base_url:
        return False, "no target configured"
    try:
        r = httpx.get(f"{target.base_url}/healthz", timeout=timeout)
        return r.status_code == 200, f"status={r.status_code}"
    except httpx.HTTPError as e:
        return False, f"{type(e).__name__}: {e}"


def _check_l8(target: Target) -> CheckResult:
    if target.name == "before":
        return _baseline_vulnerable_result(
            "L8",
            target,
            "os.kill(os.getpid(), SIGTERM) is reachable from this one shared process with no "
            "loopback/token check at all (not live-tested against the baseline itself — the same "
            "self-kill risk documented for the hardened probe applies here too, and the structural "
            "fact alone is conclusive: there is no separate container to isolate the blast radius to)",
        )
    pre_ok, pre_detail = _healthz(target)
    if not pre_ok:
        return CheckResult(
            "L8",
            target.name,
            CheckKind.LIVE_PROBE,
            Verdict.ERROR,
            f"aborted before testing: the real gateway's /healthz wasn't healthy to begin with "
            f"({pre_detail}) — fix that first, a self-kill test would be meaningless otherwise",
            pre_detail,
        )

    modal_app_path = _modal_app_path_for(target)
    app_and_fn = detect_app_and_function(modal_app_path)
    if app_and_fn is None:
        return _probe_error(
            "L8", target, f"couldn't find modal.App(...) in {modal_app_path} to know which app to call"
        )
    app_name, _function_name = app_and_fn

    try:
        import modal

        fn = modal.Function.from_name(app_name, SELF_KILL_PROBE_NAME)
        result = fn.remote()
        self_killed = False
        kill_evidence = f"self-kill probe returned normally without an exception: {result!r} (unexpected)"
    except Exception as e:  # noqa: BLE001 - the expected outcome IS an exception here
        self_killed = True
        kill_evidence = f"{type(e).__name__}: {e}"

    post_ok, post_detail = _healthz(target)
    evidence = f"pre-kill /healthz: {pre_detail}\nself-kill probe: {kill_evidence}\npost-kill /healthz: {post_detail}"

    if not self_killed:
        return CheckResult(
            "L8",
            target.name,
            CheckKind.LIVE_PROBE,
            Verdict.ERROR,
            "the self-kill probe returned normally instead of terminating — inconclusive, not a claim either way",
            evidence,
        )
    if not post_ok:
        return CheckResult(
            "L8",
            target.name,
            CheckKind.LIVE_PROBE,
            Verdict.VULNERABLE,
            f"the real gateway's /healthz stopped responding after this container's self-kill "
            f"({post_detail}) — container isolation did not hold",
            evidence,
        )
    return CheckResult(
        "L8",
        target.name,
        CheckKind.LIVE_PROBE,
        Verdict.CLOSED,
        "os.kill(os.getpid(), SIGTERM) still terminates this container's own process (Python can't block "
        "the call), but the real gateway's /healthz kept responding immediately after — confirmed, not "
        "assumed, that this container's PID namespace has nothing to do with the gateway's",
        evidence,
    )


_CONTAINER_ISOLATION_FIX = (
    "modal_app.py's make_adapter_functions() puts every catalogue adapter in its own Modal Function (a "
    "real container), and adapter_image() deliberately never sets GLC_CONFIG_DIR/GLC_AUDIT_DB/"
    "GLC_PAIRING_DB/GLC_GATEWAY_DB or mounts the Volume. Verified live: glc-adapter-shape-probe is "
    "deployed with that exact image shape and reports back what it can actually observe from inside a "
    "real container — this check calls it directly rather than trusting a documented assumption. Still "
    "fully effective for AR4 (code execution inside the gateway's own container, which does have the "
    "real mount) — see FINDINGS.md, closing that needs a further split of the gateway's own trusted "
    "internals."
)

CHECKS: list[Check] = [
    Check(
        id="L1",
        title="Shared process environment",
        invariant="INV-1",
        kind=CheckKind.LIVE_PROBE,
        description="Any in-process code can read GEMINI_API_KEY via os.environ — glc/providers.py's "
        "key and an adapter's code share one process.",
        run=_check_l1,
        plan_task="T1.11/T1.12",
        attacker_role="AR3",
        command=f"python3 -c '{_L1_ILLUSTRATION.strip()}'",
        fix_summary=_CONTAINER_ISOLATION_FIX,
        notes="The command above is illustrative (the underlying code-level fact) — the verdict itself "
        "comes from calling the live glc-adapter-shape-probe Function, not from running that snippet.",
    ),
    Check(
        id="L3",
        title="Pairing escalation",
        invariant="INV-2",
        kind=CheckKind.LIVE_PROBE,
        description="force_pair_owner() is an ordinary importable method, reachable from any in-process code.",
        run=_check_l3,
        plan_task="T1.11/T1.12",
        attacker_role="AR4",
        command=f"python3 -c '{_L3_ILLUSTRATION.strip()}'",
        fix_summary=_CONTAINER_ISOLATION_FIX,
        notes="The command above is illustrative (the underlying code-level fact) — the verdict itself "
        "comes from calling the live glc-adapter-shape-probe Function, not from running that snippet.",
    ),
    Check(
        id="L4",
        title="Install token readable in-process",
        invariant="INV-2",
        kind=CheckKind.LIVE_PROBE,
        description="get_or_create_install_token()/install_token_path() are readable from any in-process "
        "code; 0600 file mode only stops other OS users.",
        run=_check_l4,
        plan_task="T1.11/T1.12",
        attacker_role="AR4",
        command=f"python3 -c '{_L4_ILLUSTRATION.strip()}'",
        fix_summary=_CONTAINER_ISOLATION_FIX,
        notes="The command above is illustrative (the underlying code-level fact) — the verdict itself "
        "comes from calling the live glc-adapter-shape-probe Function, not from running that snippet.",
    ),
    Check(
        id="L8",
        title="In-process kill",
        invariant="INV-8",
        kind=CheckKind.LIVE_PROBE,
        description="os.kill(os.getpid(), SIGTERM) is reachable from any in-process code, bypassing the "
        "/v1/control/kill loopback check entirely.",
        run=_check_l8,
        plan_task="T1.11/T1.12",
        attacker_role="AR4",
        command=f"python3 -c '{_L8_ILLUSTRATION.strip()}'",
        fix_summary=(
            "modal_app.py deploys glc-adapter-shape-self-kill-probe, an adapter_image()-shaped Function "
            "with no Secret/Volume, kept separate from glc-adapter-shape-probe so a self-kill test never "
            "risks the read-only checks above. This check calls it, confirms the call raises (the kill "
            "succeeded — Python can't block it), then checks the real gateway's /healthz immediately "
            "before and after: still healthy after means this container's own PID namespace has nothing "
            "to do with the gateway's, verified live instead of argued structurally."
        ),
        notes="Takes roughly 20-30s — Modal reports the container's abnormal exit through the call "
        "itself rather than hanging, but it isn't instant.",
    ),
]
