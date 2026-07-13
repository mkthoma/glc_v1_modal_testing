"""Shared types for the findings console.

A `Check` mirrors one row of PLAN.md's ground-truth table (id A1-A6,
C1-C6, L1-L10). Running a check against a `Target` produces a
`CheckResult`, which the store logs append-only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum


class Verdict(StrEnum):
    VULNERABLE = "vulnerable"
    MITIGATED = "mitigated"  # defense-in-depth applied, root cause not fully closed
    CLOSED = "closed"  # fully fixed
    MANUAL = "manual"  # requires human judgement; not auto-checkable
    ERROR = "error"  # the check itself failed to run


class CheckKind(StrEnum):
    HTTP = "http"
    WS = "ws"
    INPROCESS = "inprocess"
    STATIC = "static"  # inspects local repo source, not a running target


KIND_LABELS: dict[str, str] = {
    "http": "HTTP request",
    "ws": "WebSocket connection",
    "inprocess": "Isolated subprocess",
    "static": "Source code inspection",
}

KIND_DESCRIPTIONS: dict[str, str] = {
    "http": "Sends a single HTTP request to the target's address, the same as running curl against it.",
    "ws": (
        "Opens a WebSocket connection to the target's address and exchanges messages over it. "
        "A WebSocket is a two-way connection that, unlike a normal HTTP request, stays open so "
        "both sides can keep sending messages. This is how a channel adapter (Telegram, WhatsApp, "
        "and so on) talks to the gateway."
    ),
    "inprocess": (
        "Runs in a throwaway subprocess on your own machine that imports the glc package directly. "
        "It never contacts the target you configured, because it is demonstrating code that would "
        "run inside the gateway's own process."
    ),
    "static": "Reads source files in your local checkout directly and never runs anything or contacts a target.",
}


# PLAN.md's attacker-role ladder, weakest to strongest (Session 12 §3).
ATTACKER_ROLES: dict[str, str] = {
    "AR1": "an outsider on the public internet with no credentials",
    "AR2": "a normal channel user who controls only the text they type",
    "AR3": "an attacker who has taken over a single adapter container",
    "AR4": "an attacker who has achieved code execution inside the gateway process",
}

# The eight security invariants, verbatim from Session 12 §4.
INVARIANT_DESCRIPTIONS: dict[str, str] = {
    "INV-1": "Adapters must never see provider API keys.",
    "INV-2": "Every action must be checked against the actual user, tenant, and final arguments.",
    "INV-3": "External content must always be treated as data, never as instructions.",
    "INV-4": "A credential must work only for one specific tool call.",
    "INV-5": "Each tenant must have separate memory, and every stored fact must record its source.",
    "INV-6": "Dangerous or high-impact actions must be approved with their final parameters.",
    "INV-7": "Components must not be able to edit or delete their own audit logs.",
    "INV-8": "Every run must have hard limits on time, tokens, tool calls, and cost.",
}


def describe_invariant(code: str) -> str:
    """Human-readable description(s) for an invariant code. Handles a
    single code ("INV-2"), a compound one (C1's "INV-2/INV-3"), and a
    label outside the numbered eight (A5's "supply chain" — PLAN.md's
    own ground-truth table doesn't force every finding into one of the
    eight, and neither does this)."""
    parts = [p.strip() for p in code.split("/") if p.strip()]
    if not parts:
        return ""
    described = []
    for p in parts:
        desc = INVARIANT_DESCRIPTIONS.get(p)
        described.append(desc if desc else "not one of the eight numbered invariants")
    return " / ".join(described)


@dataclass(frozen=True)
class Target:
    """Where to run HTTP/WS checks. In-process and static checks ignore
    base_url and always run against the local checkout."""

    name: str
    base_url: str  # e.g. http://localhost:8111 or your Modal URL
    install_token: str | None = None  # required for token-gated checks


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    target_name: str
    kind: CheckKind
    verdict: Verdict
    summary: str
    evidence: str  # request/response transcript, harness stdout, or grep output
    error: str | None = None
    git_commit: str | None = None  # local checkout's commit at the moment this ran; set by runner.py


@dataclass(frozen=True)
class Check:
    id: str  # A1, C2, L9, ...
    title: str
    invariant: str  # INV-2, etc.
    kind: CheckKind
    description: str
    run: Callable[[Target], CheckResult]
    plan_task: str = ""  # e.g. "T1.1" — the PLAN.md fix task
    notes: str = field(default="")
    attacker_role: str = ""  # AR1-AR4, see ATTACKER_ROLES — which rung of the ladder reaches this finding
