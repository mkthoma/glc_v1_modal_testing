"""Aggregates every Check from the four check-kind modules into one
id-keyed registry, ordered to match PLAN.md's ground-truth table."""

from __future__ import annotations

import dataclasses

from tools.findings_console import (
    checks_http,
    checks_inprocess,
    checks_live_probe,
    checks_static,
    checks_ws,
)
from tools.findings_console.models import Check

_ORDER = [
    "A1",
    "A2",
    "A3",
    "A4",
    "A5",
    "A6",
    "C1",
    "C2",
    "C3",
    "C4",
    "C5",
    "C6",
    "L1",
    "L2",
    "L3",
    "L4",
    "L5",
    "L6",
    "L7",
    "L8",
    "L9",
    "L10",
]

_ALL: list[Check] = [
    *checks_http.CHECKS,
    *checks_ws.CHECKS,
    *checks_static.CHECKS,
    *checks_inprocess.CHECKS,
    *checks_live_probe.CHECKS,
]

REGISTRY: dict[str, Check] = {c.id: c for c in _ALL}

# C2 and L9 are the same bug (cross-channel spoof); checks_ws.py implements
# it once under "C2" and we alias "L9" to the same Check object so both ids
# from the ground-truth table are independently visible in the dashboard.
# dataclasses.replace() carries every field forward automatically — a
# manual field-by-field copy silently drops new fields (attacker_role
# was added later and missed the first version of this alias).
if "L9" not in REGISTRY and "C2" in REGISTRY:
    REGISTRY["L9"] = dataclasses.replace(
        REGISTRY["C2"],
        id="L9",
        title="Cross-channel envelope spoofing (= C2)",
        notes="Alias of C2 — literally the same bug, named twice in the assignment.",
    )


def ordered_checks() -> list[Check]:
    known = [REGISTRY[i] for i in _ORDER if i in REGISTRY]
    rest = [c for cid, c in REGISTRY.items() if cid not in _ORDER]
    return known + rest
