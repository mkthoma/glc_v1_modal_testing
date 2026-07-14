"""In-process leak checks: L1, L2, L3, L4, L5, L8, L10.

Honesty note baked into the design, not just the copy: L1, L3, L4, L5,
and L8 are structural — they exist because Python has no in-process ACL
on `os.environ` or on importable functions. A local subprocess harness
can only ever demonstrate that the attack surface exists in
shared-process code; it cannot observe whether your *deployed* adapter
containers (Move B, T1.11) are actually separated, because that would
require running this same snippet from inside a live adapter container,
not from this console. So these five always report VULNERABLE — that's
correct, not a bug in the check. Mark them CLOSED in FINDINGS.md
manually once T1.11/T1.12 are deployed and you've confirmed (by trying
this exact snippet from inside an adapter's own container) that it no
longer has the access it demonstrates here.

L2 and L10 are different: input validation (T1.15) and hash-chaining
(T1.14) are real, checkable, code-level mitigations independent of
container separation, so those two can genuinely report MITIGATED.
"""

from __future__ import annotations

from tools.findings_console.harness import HarnessRun, run_snippet
from tools.findings_console.models import Check, CheckKind, CheckResult, Target, Verdict

_VERDICT_TOKENS = {v.value: v for v in Verdict}


def _parse(run: HarnessRun) -> tuple[Verdict, str]:
    if run.timed_out:
        return Verdict.ERROR, "harness snippet timed out"
    if run.result_line is None:
        # No result line at all: on some platforms a SIGTERM-style kill can
        # still tear down the process before the pipe flush is observed.
        # A nonzero/negative returncode with no output is itself evidence
        # the process was terminated out from under it.
        if run.returncode != 0:
            return (
                Verdict.VULNERABLE,
                f"process exited abnormally (code {run.returncode}) with no result line — "
                "consistent with an unhandled in-process kill",
            )
        return Verdict.ERROR, f"no result line printed; stderr: {run.stderr[:500]}"
    body = run.result_line[len("FINDINGS_CONSOLE_RESULT:") :].strip()
    token, _, summary = body.partition("|")
    verdict = _VERDICT_TOKENS.get(token.strip(), Verdict.ERROR)
    return verdict, summary.strip() or body


def _run(snippet: str, target: Target, check_id: str) -> CheckResult:
    run = run_snippet(snippet)
    verdict, summary = _parse(run)
    evidence = f"--- stdout ---\n{run.stdout}\n--- stderr ---\n{run.stderr}"
    return CheckResult(
        check_id=check_id,
        target_name="local checkout (in-process checks always run locally)",
        kind=CheckKind.INPROCESS,
        verdict=verdict,
        summary=summary,
        evidence=evidence,
    )


_L1_SNIPPET = """
import os
key = os.environ.get("GEMINI_API_KEY", "")
if key:
    print(f"FINDINGS_CONSOLE_RESULT: vulnerable|arbitrary code sharing this process read "
          f"GEMINI_API_KEY ({key[:4]}...) via plain os.environ; Python has no in-process ACL "
          f"on environment variables")
else:
    print("FINDINGS_CONSOLE_RESULT: error|GEMINI_API_KEY was not present (harness misconfigured)")
"""

_L2_SNIPPET = """
import sqlite3, os
from glc.audit import store as audit_store

audit_store.init_store()
audit_store.append(channel="probe", channel_user_id="u1", trust_level="untrusted", event_type="a")
audit_store.append(channel="probe", channel_user_id="u1", trust_level="untrusted", event_type="b")
audit_store.append(channel="probe", channel_user_id="u1", trust_level="untrusted", event_type="c")
before = len(audit_store.query(limit=1000))

# Delete a *mid-chain* row (a later row, "c", is still present and still
# references it) — a direct sqlite3 DELETE, exactly what L2 says any
# in-process code can already do.
path = os.environ["GLC_AUDIT_DB"]
conn = sqlite3.connect(path)
conn.execute("DELETE FROM audit_log WHERE event_type='b'")
conn.commit()
conn.close()

after = len(audit_store.query(limit=1000))
deleted = before - after
verify_chain = getattr(audit_store, "verify_chain", None)

if deleted <= 0:
    print(f"FINDINGS_CONSOLE_RESULT: error|delete did not remove rows (before={before}, after={after})")
elif verify_chain is not None:
    try:
        result = verify_chain()
        ok = bool(result[0]) if isinstance(result, tuple) else bool(result)
    except Exception:
        ok = True
    if not ok:
        print(f"FINDINGS_CONSOLE_RESULT: mitigated|direct DELETE of a mid-chain row still succeeded "
              f"(removed {deleted} row(s)), but verify_chain() detected the tamper. Known limitation, "
              f"not tested here: deleting the *tail* (most recent row(s), or the whole table) is NOT "
              f"detected -- there's no later row left to contradict it. See FINDINGS.md.")
    else:
        print(f"FINDINGS_CONSOLE_RESULT: vulnerable|direct DELETE of a mid-chain row succeeded "
              f"(removed {deleted} row(s)) and verify_chain() did not detect it")
else:
    print(f"FINDINGS_CONSOLE_RESULT: vulnerable|direct DELETE succeeded (removed {deleted} row(s)); "
          f"no verify_chain() exists yet (T1.14 not applied)")
"""

_L3_SNIPPET = """
from glc.security.pairing import get_pairing_store
store = get_pairing_store()
store.force_pair_owner("telegram", "findings-console-attacker", user_handle="me")
check = store.lookup("telegram", "findings-console-attacker")
if check is not None and check.trust_level == "owner_paired":
    print("FINDINGS_CONSOLE_RESULT: vulnerable|force_pair_owner() is reachable from arbitrary "
          "in-process code and granted owner_paired trust to a fabricated identity")
else:
    print("FINDINGS_CONSOLE_RESULT: error|force_pair_owner() did not produce the expected record")
"""

_L4_SNIPPET = """
from glc.config import get_or_create_install_token, install_token_path
tok = get_or_create_install_token()
read_back = install_token_path().read_text().strip()
if read_back == tok and tok:
    print(f"FINDINGS_CONSOLE_RESULT: vulnerable|install token ({tok[:4]}...) is readable by any "
          f"in-process code via install_token_path(); file mode 0600 only stops other OS users, "
          f"not other in-process code")
else:
    print("FINDINGS_CONSOLE_RESULT: error|could not read back the install token")
"""

_L5_SNIPPET = """
import sys
import glc.policy.engine as engine
from glc.policy.schemas import PolicyVerdict

before = engine.evaluate({"name": "dangerous.tool", "arguments": {}}, {"channel": "x", "trust_level": "untrusted"})

try:
    engine.evaluate = lambda *a, **k: PolicyVerdict(action="allow", reason="findings-console-pwned")
    after = engine.evaluate({"name": "dangerous.tool", "arguments": {}}, {"channel": "x", "trust_level": "untrusted"})
    if before.action == "deny" and after.action == "allow":
        print("FINDINGS_CONSOLE_RESULT: vulnerable|glc.policy.engine.evaluate is an ordinary rebindable "
              "attribute; default-deny for untrusted was silently replaced with always-allow")
    else:
        print(f"FINDINGS_CONSOLE_RESULT: error|unexpected before={before.action} after={after.action}")
except AttributeError as e:
    # The exact one-liner the finding names is now rejected. Still
    # "mitigated," not "closed": the identical outcome is one line away
    # via a direct __dict__ write, which bypasses __setattr__ entirely
    # and is exactly as easy for an attacker who already has code
    # execution in this process. Same class of residual gap as L2's
    # hash-chain tail-deletion limitation.
    sys.modules["glc.policy.engine"].__dict__["evaluate"] = lambda *a, **k: PolicyVerdict(
        action="allow", reason="findings-console-pwned-via-dict-write"
    )
    after = engine.evaluate({"name": "dangerous.tool", "arguments": {}}, {"channel": "x", "trust_level": "untrusted"})
    if after.action == "allow":
        print(f"FINDINGS_CONSOLE_RESULT: mitigated|direct reassignment now raises ({e}), but writing "
              f"straight to glc.policy.engine.__dict__['evaluate'] bypasses that check and produces the "
              f"identical outcome (default-deny replaced with always-allow) for the same AR4 attacker. "
              f"The separated glc-policy-engine Function (evaluate_remote()) is immune to both "
              f"techniques, but nothing calls it yet — see FINDINGS.md.")
    else:
        print(f"FINDINGS_CONSOLE_RESULT: error|__dict__ write did not take effect (after={after.action})")
"""

_L8_SNIPPET = """
import os, signal, sys
print("FINDINGS_CONSOLE_RESULT: vulnerable|about to call os.kill(os.getpid(), SIGTERM) from "
      "arbitrary in-process code with no loopback/token check (this is an isolated subprocess "
      "spawned by the console, not your real dev server or deployed gateway)")
sys.stdout.flush()
os.kill(os.getpid(), signal.SIGTERM)
print("FINDINGS_CONSOLE_RESULT: error|os.kill did not terminate the process")
"""

_L10_SNIPPET = """
import glc.db as db
db.init()
raised = False
reason = ""
try:
    db.log_call(provider="findings-console-probe", model="x", input_tokens=999_999_999, output_tokens=0)
except ValueError as e:
    raised = True
    reason = str(e)

if raised:
    print(f"FINDINGS_CONSOLE_RESULT: mitigated|log_call rejected an absurd token count: {reason}")
else:
    rows = db.recent(limit=1, provider="findings-console-probe")
    if rows:
        print("FINDINGS_CONSOLE_RESULT: vulnerable|log_call accepted an absurd token count with no validation")
    else:
        print("FINDINGS_CONSOLE_RESULT: error|log_call neither raised nor produced a queryable row")
"""


def _make(
    check_id: str,
    title: str,
    invariant: str,
    description: str,
    snippet: str,
    plan_task: str,
    attacker_role: str,
    fix_summary: str = "",
    notes: str = "",
) -> Check:
    def _runner(target: Target, _snippet: str = snippet, _id: str = check_id) -> CheckResult:
        return _run(_snippet, target, _id)

    default_notes = "Runs in an isolated scratch subprocess — never touches your real ~/.glc state."
    return Check(
        id=check_id,
        title=title,
        invariant=invariant,
        kind=CheckKind.INPROCESS,
        description=description,
        run=_runner,
        plan_task=plan_task,
        notes=f"{default_notes} {notes}".strip() if notes else default_notes,
        attacker_role=attacker_role,
        command=f"python3 -c '{snippet.strip()}'",
        fix_summary=fix_summary,
    )


_CONTAINER_ISOLATION_FIX = (
    "modal_app.py's make_adapter_functions() puts every catalogue adapter in its own Modal Function "
    "(a real container), and adapter_image() deliberately never sets GLC_CONFIG_DIR/GLC_AUDIT_DB/"
    "GLC_PAIRING_DB/GLC_GATEWAY_DB or mounts the Volume. This check always reports 'vulnerable' because "
    "it runs as a plain local subprocess importing glc directly — the same process as the code it's "
    "attacking, by construction. It cannot observe an adapter container from outside it. Verified "
    "instead with a throwaway probe Function sharing the adapter image's exact shape: no /data mount "
    "exists there at all, so this call has nothing real to reach for AR3. Still fully effective for "
    "AR4 (code execution inside the gateway's own container, which does have the real mount) — see "
    "FINDINGS.md, closing that needs a further split of the gateway's own trusted internals."
)

CHECKS: list[Check] = [
    _make(
        "L1",
        "Shared process environment",
        "INV-1",
        "Any in-process code can read GEMINI_API_KEY via os.environ — glc/providers.py's key "
        "and an adapter's code share one process.",
        _L1_SNIPPET,
        "T1.11/T1.12",
        "AR3",
        fix_summary=_CONTAINER_ISOLATION_FIX,
        notes="Known tool limitation: this always reports vulnerable when run from this console (see fix_summary above) — closed for AR3, verified via a separate live probe, not by this check.",
    ),
    _make(
        "L2",
        "Audit log writable",
        "INV-7",
        "In-process code can open the audit SQLite file directly and DELETE rows.",
        _L2_SNIPPET,
        "T1.14",
        "AR4",
        fix_summary=(
            "glc/audit/store.py adds hash-chaining: every row stores hash = sha256(prev_hash + "
            "canonical_json(row)), and verify_chain() walks the table to report the first row where "
            "content or chain linkage no longer matches. A direct SQLite DELETE/UPDATE is now detected "
            "— but not prevented, and deleting the tail (or the whole table) isn't detected either, "
            "since there's no later row left to contradict it. Mitigated, not closed."
        ),
    ),
    _make(
        "L3",
        "Pairing escalation",
        "INV-2",
        "force_pair_owner() is an ordinary importable method, reachable from any in-process code.",
        _L3_SNIPPET,
        "T1.11/T1.12",
        "AR4",
        fix_summary=_CONTAINER_ISOLATION_FIX,
        notes="Known tool limitation: this always reports vulnerable when run from this console (see fix_summary above) — closed for AR3, verified via a separate live probe, not by this check.",
    ),
    _make(
        "L4",
        "Install token readable in-process",
        "INV-2",
        "get_or_create_install_token()/install_token_path() are readable from any in-process code; "
        "0600 file mode only stops other OS users.",
        _L4_SNIPPET,
        "T1.11/T1.12",
        "AR4",
        fix_summary=_CONTAINER_ISOLATION_FIX,
        notes="Known tool limitation: this always reports vulnerable when run from this console (see fix_summary above) — closed for AR3, verified via a separate live probe, not by this check.",
    ),
    _make(
        "L5",
        "Policy engine monkey-patchable",
        "INV-2",
        "glc.policy.engine.evaluate is an ordinary rebindable module attribute.",
        _L5_SNIPPET,
        "T1.11/T1.12",
        "AR4",
        fix_summary=(
            "glc/policy/engine.py now blocks the exact one-liner this finding names: PolicyEngine gets "
            "__slots__ (blocks instance-level `some_engine.evaluate = ...`), and the module's __class__ "
            "is swapped to a types.ModuleType subclass whose __setattr__ rejects external reassignment "
            "of evaluate/get_engine/reload_engine. Mitigated, not closed: the identical outcome is one "
            "line away via sys.modules['glc.policy.engine'].__dict__['evaluate'] = ..., which bypasses "
            "__setattr__ entirely and is exactly as easy for the same AR4 attacker. The separated "
            "glc-policy-engine Modal Function (glc/policy/remote.py's evaluate_remote()) is immune to "
            "both techniques and verified live, but nothing calls it yet."
        ),
    ),
    _make(
        "L8",
        "In-process kill",
        "INV-8",
        "os.kill(os.getpid(), SIGTERM) is reachable from any in-process code, bypassing the "
        "/v1/control/kill loopback check entirely.",
        _L8_SNIPPET,
        "T1.11/T1.12",
        "AR4",
        fix_summary=_CONTAINER_ISOLATION_FIX
        + " Each adapter container also has its own private PID namespace, so os.kill(os.getpid(), "
        "SIGTERM) inside it can only ever kill that container's own process, never the gateway's.",
        notes="Known tool limitation: this always reports vulnerable when run from this console (see fix_summary above) — closed for AR3 by construction (separate PID namespace), not by this check.",
    ),
    _make(
        "L10",
        "Cost-ledger poisoning",
        "INV-8",
        "glc.db.log_call() accepts unvalidated token counts from any in-process caller.",
        _L10_SNIPPET,
        "T1.15",
        "AR4",
        fix_summary=(
            "glc/db.py adds MAX_TOKENS_PER_CALL=2_000_000 and log_call() now raises ValueError for "
            "negative values or values above that ceiling, before the INSERT runs. Mitigated, not "
            "closed: the fix bounds the values accepted, but any in-process caller (not just the "
            "trusted core) can still call log_call() at all — full closure needs Move B (only the "
            "trusted core process should ever call it)."
        ),
    ),
]
