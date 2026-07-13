"""Groups checks the way Session 12 itself groups them — by what the
Modal migration did to each finding — not by the technical `kind`
(http/ws/inprocess/static) checks_*.py organizes around internally.

Mirrors two passes from the lecture: §6's "introduced / inherited-open
/ inherited-reachable" A/B/C summary, and §7's full ten-leaks catalog.
Group B is deliberately a *condensed* 8-of-10 subset of the ten leaks
(skipping L6 and L9, which §6 already covers under A3 and C2) — the
same duplication the source document itself has, not a bug.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.findings_console.models import Check

GROUP_A_TITLE = "A. Introduced or elevated by the migration (the highest-value class here)"
GROUP_B_TITLE = "B. Inherited in-process leaks the migration did NOT close (all still live)"
GROUP_C_TITLE = "C. Inherited endpoint/logic issues, now internet-reachable"
TEN_LEAKS_TITLE = "The ten code leaks the migration leaves open"

GROUP_A_IDS = ["A1", "A2", "A3", "A4", "A5", "A6"]

# B1-B8, in the order §6 lists them: 8 of the 10 leaks from §7, skipping
# L6 (= A3, already in Group A) and L9 (= C2, already in Group C).
GROUP_B_ORDER = ["L1", "L2", "L3", "L4", "L5", "L8", "L10", "L7"]
B_LABELS = {
    "L1": "B1",
    "L2": "B2",
    "L3": "B3",
    "L4": "B4",
    "L5": "B5",
    "L8": "B6",
    "L10": "B7",
    "L7": "B8",
}

GROUP_C_IDS = ["C1", "C2", "C3", "C4", "C5", "C6"]

TEN_LEAKS_ORDER = ["L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9", "L10"]


@dataclass(frozen=True)
class SectionItem:
    label: str  # what to display in place of the raw id — "A1", "B3", "L7", ...
    check: Check


@dataclass(frozen=True)
class Section:
    title: str
    items: list[SectionItem]


def build_sections(registry: dict[str, Check]) -> list[Section]:
    def _items(ids: list[str], labels: dict[str, str] | None = None) -> list[SectionItem]:
        out = []
        for cid in ids:
            check = registry.get(cid)
            if check is None:
                continue
            out.append(SectionItem(label=(labels or {}).get(cid, cid), check=check))
        return out

    return [
        Section(GROUP_A_TITLE, _items(GROUP_A_IDS)),
        Section(GROUP_B_TITLE, _items(GROUP_B_ORDER, B_LABELS)),
        Section(GROUP_C_TITLE, _items(GROUP_C_IDS)),
        Section(TEN_LEAKS_TITLE, _items(TEN_LEAKS_ORDER)),
    ]
