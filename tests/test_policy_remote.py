"""L5 — the policy engine must run in its own process, not just have an
in-process integrity check.

Before this, glc.policy.engine.evaluate was an ordinary module-level
function: any code sharing the process could rebind it directly
(`e.evaluate = lambda *a, **k: PolicyVerdict(action="allow", ...)`) and
silently neuter every future policy check. glc/policy/engine.py now
blocks that literal one-liner (a types.ModuleType subclass rejects
external reassignment of `evaluate`/`get_engine`/`reload_engine`, and
PolicyEngine's __slots__ blocks the equally common instance-level
`some_engine.evaluate = ...` variant) — see test_direct_monkeypatch_*
below. But an attacker with genuine code execution in the process
(AR4) isn't limited to that one syntax: writing straight to the
module's __dict__ bypasses __setattr__ entirely and is just as easy.
No pure-Python in-process trick can close that gap — the only thing
that actually does is a caller that never holds a reference to the
local function and calls the separated Function instead.

evaluate_remote() dispatches to a separate glc-policy-engine Modal
Function instead. This test proves the point directly: tamper with
the LOCAL glc.policy.engine.evaluate via the __dict__-write technique
that still works, then call evaluate_remote() (with the remote call
itself mocked to return a canned deny verdict, standing in for the
untouched separate container) and confirm the local tampering had
zero effect on the result — because evaluate_remote() never calls the
local function at all.
"""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, patch

import pytest

import glc.policy.engine as engine
from glc.policy.remote import evaluate_remote, is_remote
from glc.policy.schemas import PolicyVerdict


def test_is_remote_reads_env_var(monkeypatch):
    monkeypatch.delenv("GLC_POLICY_ENGINE_REMOTE", raising=False)
    assert is_remote() is False

    monkeypatch.setenv("GLC_POLICY_ENGINE_REMOTE", "1")
    assert is_remote() is True


def test_direct_monkeypatch_of_module_function_is_rejected():
    """The exact exploit line the finding names now raises instead of
    silently succeeding."""
    with pytest.raises(AttributeError):
        engine.evaluate = lambda *a, **k: PolicyVerdict(action="allow", reason="pwned")


def test_direct_monkeypatch_of_instance_method_is_rejected():
    """The equally common `some_engine.evaluate = ...` variant, blocked
    by PolicyEngine's __slots__ (evaluate isn't an instance attribute,
    so instances have no __dict__ slot to shadow it with)."""
    eng = engine.get_engine()
    with pytest.raises(AttributeError):
        eng.evaluate = lambda *a, **k: PolicyVerdict(action="allow", reason="pwned")


def test_dict_write_bypass_still_works_documented_residual_gap():
    """Honest limitation, same class as L2's hash-chain tail-deletion
    gap: __setattr__ interception doesn't stop a direct write to the
    module's own __dict__, which is exactly as easy for an attacker who
    already has code execution in the process (AR4). This is why L5 is
    "mitigated," not "closed" — see FINDINGS.md."""
    original = engine.evaluate
    try:
        sys.modules["glc.policy.engine"].__dict__["evaluate"] = lambda *a, **k: PolicyVerdict(
            action="allow", reason="dict-write-bypass"
        )
        assert engine.evaluate({}, {}).reason == "dict-write-bypass"
    finally:
        sys.modules["glc.policy.engine"].__dict__["evaluate"] = original


@pytest.mark.asyncio
async def test_local_monkeypatch_does_not_affect_remote_decision(monkeypatch):
    # Simulate an attacker with code execution in the gateway's own
    # process — the exact exploit named in the finding, using the
    # __dict__-write technique since the direct-assignment form is now
    # blocked (see test_direct_monkeypatch_of_module_function_is_rejected).
    original_evaluate = engine.evaluate
    sys.modules["glc.policy.engine"].__dict__["evaluate"] = lambda *a, **k: PolicyVerdict(
        action="allow", reason="pwned"
    )
    try:
        # The "separate container" is mocked here (no live Modal call in
        # a unit test), but the whole point is: evaluate_remote() never
        # touches engine.evaluate at all, tampered or not — it calls out
        # to a Modal Function object instead.
        fake_remote = AsyncMock(return_value={"action": "deny", "reason": "real policy, untouched"})
        fake_fn = type("FakeFn", (), {"remote": type("R", (), {"aio": fake_remote})()})()

        with patch("modal.Function.from_name", return_value=fake_fn):
            verdict = await evaluate_remote(
                {"name": "shell.exec", "arguments": {"command": "sudo rm -rf /"}},
                {"channel": "telegram", "trust_level": "untrusted"},
            )

        assert verdict.action == "deny"
        assert verdict.reason == "real policy, untouched"
        # The tampered local function was never even called.
        assert engine.evaluate({}, {}).reason == "pwned"  # confirms the tamper is still in place locally
    finally:
        sys.modules["glc.policy.engine"].__dict__["evaluate"] = original_evaluate
