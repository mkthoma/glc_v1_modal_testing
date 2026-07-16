"""L5 fix — run the policy decision in its own Modal Function.

`glc.policy.engine.evaluate` is a module-level function; any code
sharing this process can monkey-patch it directly —

    import glc.policy.engine as e
    e.evaluate = lambda *a, **k: PolicyVerdict(action="allow", reason="pwned")

— and silently neuter every future policy check. Python has no
in-process ACL to stop this, and an integrity check added *around*
`evaluate()` doesn't help either: an attacker with equal in-process
privilege can monkey-patch the integrity check too. Self-checking code
cannot certify its own integrity against an attacker at the same
privilege level — that needs an external verifier, i.e. a different
process, the same boundary Move B/C already builds for adapters.

`evaluate_remote()` calls a dedicated `glc-policy-engine` Modal
Function instead of the local `glc.policy.engine.evaluate`. Rebinding
the *local* reference in this process has no effect on the decision
made inside that separate container — there is nothing here to
monkey-patch that reaches it.

Nothing in the current route handlers calls the policy engine yet (the
agent runtime is a stub that just echoes messages — see
routes/channels.py); this module exists so the separated architecture
is in place and provably closes L5 once policy enforcement is wired
into a real decision path, not left as a "fix it later" TODO.

Local dev (`uv run glc serve`) never sets GLC_POLICY_ENGINE_REMOTE, so
importing this module is always safe even without a deployed Function
— it only touches Modal's client when GLC_POLICY_ENGINE_REMOTE=1 and
evaluate_remote() is actually called.
"""

from __future__ import annotations

import os
from typing import Any

from glc.policy.schemas import PolicyVerdict

MODAL_APP_NAME = "glc-v1-gateway"
MODAL_FUNCTION_NAME = "glc-policy-engine"


def is_remote() -> bool:
    return os.getenv("GLC_POLICY_ENGINE_REMOTE", "0") == "1"


async def evaluate_remote(tool_call: dict[str, Any], context: dict[str, Any]) -> PolicyVerdict:
    import modal

    fn = modal.Function.from_name(MODAL_APP_NAME, MODAL_FUNCTION_NAME)
    result = await fn.remote.aio(tool_call, context)
    return PolicyVerdict.model_validate(result)
