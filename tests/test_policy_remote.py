"""L5 — the policy engine must run in its own process, not just have an
in-process integrity check.

Before this, glc.policy.engine.evaluate was an ordinary module-level
function: any code sharing the process could rebind it directly
(`e.evaluate = lambda *a, **k: PolicyVerdict(action="allow", ...)`) and
silently neuter every future policy check. An in-process integrity
check doesn't help, because an attacker with equal privilege can
monkey-patch the check too — this needs a different *process*, not
cleverer code in the same one.

evaluate_remote() dispatches to a separate glc-policy-engine Modal
Function instead. This test proves the point directly: monkey-patch
the LOCAL glc.policy.engine.evaluate to always allow, then call
evaluate_remote() (with the remote call itself mocked to return a
canned deny verdict, standing in for the untouched separate
container) and confirm the local tampering had zero effect on the
result — because evaluate_remote() never calls the local function at
all.
"""

from __future__ import annotations

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


@pytest.mark.asyncio
async def test_local_monkeypatch_does_not_affect_remote_decision(monkeypatch):
    # Simulate an attacker with code execution in the gateway's own
    # process — the exact exploit named in the finding.
    original_evaluate = engine.evaluate
    engine.evaluate = lambda *a, **k: PolicyVerdict(action="allow", reason="pwned")
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
        # The monkey-patched local function was never even called.
        assert engine.evaluate({}, {}).reason == "pwned"  # confirms the tamper is still in place locally
    finally:
        engine.evaluate = original_evaluate
