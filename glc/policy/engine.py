"""Declarative policy engine.

evaluate(tool_call, context) -> PolicyVerdict
  - first matching rule wins
  - ties resolve to deny
  - default allow when trust_level == 'owner_paired' and no rule matches
  - default deny otherwise

Hot reload on SIGHUP (process-level handler installed by main.py). Malformed
yaml is rejected: the engine falls back to a deny-everything safe-default
config and logs a warning so the gateway boots in a known-safe state.
"""

from __future__ import annotations

import fnmatch
import re
import sys
import threading
import types as _types
from pathlib import Path
from typing import Any

import yaml

from glc.policy.schemas import PolicyConfig, PolicyRule, PolicyVerdict

_SAFE_DEFAULT = PolicyConfig(
    rules=[
        PolicyRule(
            tool="*",
            trust_level="*",
            action="deny",
            reason="policy.yaml unreadable — falling back to deny-everything",
        )
    ]
)


def _matches_glob(value: Any, pattern: str) -> bool:
    if not isinstance(value, str):
        return False
    # fnmatch's ** support is weak; substitute ** for a regex-ish pattern.
    if "**" in pattern:
        regex = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        return bool(re.match(regex + "$", value))
    return fnmatch.fnmatch(value, pattern)


def _matches_condition(condition: dict[str, Any], params: dict[str, Any]) -> bool:
    for key, expected in condition.items():
        if key.endswith("_glob"):
            target = key[: -len("_glob")]
            if not _matches_glob(params.get(target), expected):
                return False
        elif key.endswith("_regex"):
            target = key[: -len("_regex")]
            val = params.get(target)
            if not isinstance(val, str) or not re.search(expected, val):
                return False
        elif key.endswith("_in"):
            target = key[: -len("_in")]
            if params.get(target) not in (expected or []):
                return False
        elif key == "command_matches":
            cmd = params.get("command", "")
            if not isinstance(cmd, str):
                return False
            patterns = expected if isinstance(expected, list) else [expected]
            if not any(p in cmd for p in patterns):
                return False
        elif key == "recipient_type":
            if params.get("recipient_type") != expected:
                return False
        elif isinstance(expected, list):
            if params.get(key) not in expected:
                return False
        else:
            if params.get(key) != expected:
                return False
    return True


class PolicyEngine:
    # L5 fix, layer 1: __slots__ blocks instance-level monkey-patching of
    # evaluate — `some_engine.evaluate = lambda *a, **k: ...` normally
    # shadows the class method with an instance attribute; with __slots__
    # restricted to the two real instance attributes, that assignment
    # raises AttributeError instead of silently succeeding, since
    # instances no longer have a __dict__ to hold arbitrary attributes.
    __slots__ = ("config", "_lock")

    def __init__(self, config: PolicyConfig):
        self.config = config
        self._lock = threading.Lock()

    @classmethod
    def from_yaml(cls, path: Path | str) -> PolicyEngine:
        p = Path(path)
        if not p.exists():
            return cls(_SAFE_DEFAULT)
        try:
            raw = yaml.safe_load(p.read_text()) or {}
            cfg = PolicyConfig.model_validate(raw)
        except Exception as e:  # pragma: no cover
            print(f"[glc.policy] malformed {p}: {e!r} — using deny-everything safe default")
            cfg = _SAFE_DEFAULT
        return cls(cfg)

    def evaluate(self, tool_call: dict[str, Any], context: dict[str, Any]) -> PolicyVerdict:
        """tool_call = {'name': 'email.send', 'arguments': {...}}
        context   = {'channel': 'telegram', 'trust_level': 'owner_paired',
                     'channel_user_id': '...'}"""
        tool = tool_call.get("name", "")
        params = tool_call.get("arguments") or {}
        channel = context.get("channel", "")
        trust_level = context.get("trust_level", "untrusted")

        with self._lock:
            rules = list(self.config.rules)

        deny_match: tuple[int, PolicyRule] | None = None
        first_match: tuple[int, PolicyRule] | None = None
        for i, rule in enumerate(rules):
            if rule.tool != "*" and rule.tool != tool:
                continue
            if rule.channel != "*" and rule.channel != channel:
                continue
            if rule.trust_level != "*" and rule.trust_level != trust_level:
                continue
            if rule.condition and not _matches_condition(rule.condition, params):
                continue
            if first_match is None:
                first_match = (i, rule)
            if rule.action == "deny" and deny_match is None:
                deny_match = (i, rule)

        if deny_match is not None:
            i, r = deny_match
            return PolicyVerdict(action="deny", reason=r.reason or "denied by policy", matched_rule_index=i)
        if first_match is not None:
            i, r = first_match
            return PolicyVerdict(
                action=r.action, reason=r.reason or f"matched rule #{i}", matched_rule_index=i
            )
        if trust_level == "owner_paired":
            return PolicyVerdict(action="allow", reason="default-allow for owner_paired")
        return PolicyVerdict(action="deny", reason=f"default-deny for trust_level={trust_level}")

    def reload(self, path: Path | str) -> None:
        new = PolicyEngine.from_yaml(path)
        with self._lock:
            self.config = new.config


# Module-level singleton, lazily constructed from config.policy_yaml_path().
_engine: PolicyEngine | None = None
_engine_lock = threading.Lock()


def get_engine() -> PolicyEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            from glc.config import policy_yaml_path

            _engine = PolicyEngine.from_yaml(policy_yaml_path())
    return _engine


def reload_engine() -> None:
    from glc.config import policy_yaml_path

    eng = get_engine()
    eng.reload(policy_yaml_path())


def evaluate(tool_call: dict[str, Any], context: dict[str, Any]) -> PolicyVerdict:
    return get_engine().evaluate(tool_call, context)


# L5 fix, layer 2: block `glc.policy.engine.evaluate = lambda *a, **k: ...`
# style monkey-patching of the module itself, not just the class.
#
# A plain module object stores its attributes in a regular __dict__, and
# external code assigning `module.name = x` calls object.__setattr__ on the
# module — nothing stops it. Swapping the module's __class__ for a
# types.ModuleType subclass lets us intercept that path: __setattr__ raises
# for a frozen set of names once they're already defined.
#
# This does NOT stop every possible rebind. Internal `global x; x = value`
# statements compile to a direct write on the frame's globals dict (the
# module's __dict__), bypassing __setattr__ entirely — that's how
# get_engine()'s `global _engine` still works, and it's also why _engine
# itself is deliberately left out of the frozen set (tests reset it via
# `eng_mod._engine = None`, an external assignment style that would defeat
# a naive "freeze everything" approach and offers no real security value
# for that particular name). A sufficiently privileged attacker with
# __dict__ or ctypes-level access could still force the change; this closes
# the naive, direct monkey-patch shown in the finding and used by
# tools/findings_console's L5 check, not every conceivable in-process
# tamper technique. See L2's hash-chain tail-deletion limitation in
# FINDINGS.md for the same caveat applied elsewhere.
_FROZEN_NAMES = frozenset({"evaluate", "get_engine", "reload_engine"})


class _FrozenPolicyModule(_types.ModuleType):
    def __setattr__(self, name: str, value: Any) -> None:
        if name in _FROZEN_NAMES and name in self.__dict__:
            raise AttributeError(
                f"glc.policy.engine.{name} is frozen after import and cannot be reassigned "
                "(L5 hardening — see FINDINGS.md)"
            )
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _FrozenPolicyModule
