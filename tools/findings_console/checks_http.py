"""HTTP checks: A1, A2, C1, C4, C5, C6.

Each check is a synchronous function (the server runs these off the
event loop via a thread pool) that hits `target.base_url` directly —
your local `uv run glc serve` instance or your deployed Modal URL.
"""

from __future__ import annotations

import re

import httpx

from tools.findings_console.models import Check, CheckKind, CheckResult, Target, Verdict

_PROVIDER_HOST_PATTERNS = re.compile(
    r"generativelanguage\.googleapis\.com|api\.openai\.com|api\.groq\.com|"
    r"api\.cerebras\.ai|openrouter\.ai|models\.github\.ai|Traceback \(most recent",
    re.IGNORECASE,
)

_INFO_ENDPOINTS = ["/v1/status", "/v1/providers", "/v1/capabilities", "/v1/cost/by_agent", "/v1/calls"]


def _headers(target: Target) -> dict[str, str]:
    return {"Authorization": f"Bearer {target.install_token}"} if target.install_token else {}


def _err(check_id: str, target: Target, e: Exception) -> CheckResult:
    return CheckResult(
        check_id, target.name, CheckKind.HTTP, Verdict.ERROR, f"request failed: {e}", str(e), error=str(e)
    )


def _check_a1(target: Target) -> CheckResult:
    body = {"messages": [{"role": "user", "content": "findings-console probe"}]}
    try:
        r = httpx.post(f"{target.base_url}/v1/chat", json=body, timeout=15)
    except httpx.HTTPError as e:
        return _err("A1", target, e)
    evidence = f"POST /v1/chat (no auth)\nstatus={r.status_code}\nbody={r.text[:800]}"
    if r.status_code in (401, 403):
        return CheckResult(
            "A1",
            target.name,
            CheckKind.HTTP,
            Verdict.CLOSED,
            f"unauthenticated call rejected ({r.status_code})",
            evidence,
        )
    return CheckResult(
        "A1",
        target.name,
        CheckKind.HTTP,
        Verdict.VULNERABLE,
        f"unauthenticated call was NOT rejected (status={r.status_code}) — it reached the provider dispatch logic",
        evidence,
    )


def _check_a2(target: Target) -> CheckResult:
    lines = []
    any_open = False
    try:
        for path in _INFO_ENDPOINTS:
            r = httpx.get(f"{target.base_url}{path}", timeout=10)
            open_ = r.status_code not in (401, 403)
            any_open = any_open or open_
            lines.append(f"GET {path} -> {r.status_code} ({'OPEN' if open_ else 'gated'})")
        docs = httpx.get(f"{target.base_url}/openapi.json", timeout=10)
        lines.append(
            f"GET /openapi.json -> {docs.status_code} ({'reachable' if docs.status_code == 200 else 'disabled/gated'}) "
            f"[informational only — env-conditional per T1.2, not gated on this alone]"
        )
    except httpx.HTTPError as e:
        return _err("A2", target, e)
    evidence = "\n".join(lines)
    if any_open:
        return CheckResult(
            "A2",
            target.name,
            CheckKind.HTTP,
            Verdict.VULNERABLE,
            "at least one info-disclosure endpoint is reachable without auth",
            evidence,
        )
    return CheckResult(
        "A2", target.name, CheckKind.HTTP, Verdict.CLOSED, "all probed info endpoints require auth", evidence
    )


def _check_c1(target: Target) -> CheckResult:
    payload = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "probe"},
                    {"type": "image_url", "image_url": {"url": "http://169.254.169.254/latest/meta-data/"}},
                ],
            }
        ]
    }
    try:
        # The gateway's own _resolve_image_urls fetch uses a 30s timeout
        # internally (chat.py); stay above that so we observe its actual
        # response instead of our own client timing out first.
        r = httpx.post(f"{target.base_url}/v1/chat", json=payload, headers=_headers(target), timeout=35)
    except httpx.HTTPError as e:
        return _err("C1", target, e)
    evidence = f"POST /v1/chat with image_url=http://169.254.169.254/... \nstatus={r.status_code}\nbody={r.text[:800]}"
    blocked = r.status_code == 400 and "block" in r.text.lower()
    if blocked:
        return CheckResult(
            "C1",
            target.name,
            CheckKind.HTTP,
            Verdict.CLOSED,
            "request to a link-local address was proactively rejected",
            evidence,
        )
    return CheckResult(
        "C1",
        target.name,
        CheckKind.HTTP,
        Verdict.VULNERABLE,
        f"no proactive block detected (status={r.status_code}) — heuristic only, inspect evidence; "
        "make your T1.5 fix's rejection message include the word 'block' so this check can detect it",
        evidence,
    )


def _check_c4(target: Target) -> CheckResult:
    body = {"messages": [{"role": "user", "content": "probe"}], "model": "findings-console-invalid-model"}
    try:
        r = httpx.post(f"{target.base_url}/v1/chat", json=body, headers=_headers(target), timeout=20)
    except httpx.HTTPError as e:
        return _err("C4", target, e)
    evidence = f"POST /v1/chat\nstatus={r.status_code}\nbody={r.text[:800]}"
    if r.status_code in (401, 403):
        return CheckResult(
            "C4",
            target.name,
            CheckKind.HTTP,
            Verdict.MANUAL,
            "call was auth-gated (A1 fix active) before reaching provider dispatch — supply target.install_token to actually exercise this check",
            evidence,
        )
    leaks = _PROVIDER_HOST_PATTERNS.search(r.text)
    if leaks:
        return CheckResult(
            "C4",
            target.name,
            CheckKind.HTTP,
            Verdict.VULNERABLE,
            f"response body leaks upstream detail: {leaks.group(0)!r}",
            evidence,
        )
    return CheckResult(
        "C4",
        target.name,
        CheckKind.HTTP,
        Verdict.CLOSED,
        "no provider hostname or raw traceback text found in the error body",
        evidence,
    )


def _check_c5(target: Target) -> CheckResult:
    body = {"messages": [{"role": "user", "content": "probe"}]}
    statuses: list[int] = []
    try:
        with httpx.Client(timeout=10) as client:
            for _ in range(15):
                r = client.post(f"{target.base_url}/v1/chat", json=body, headers=_headers(target))
                statuses.append(r.status_code)
                if 429 in statuses:
                    break
    except httpx.HTTPError as e:
        return _err("C5", target, e)
    evidence = f"fired {len(statuses)} rapid POST /v1/chat, statuses={statuses}"
    if 429 in statuses:
        return CheckResult(
            "C5",
            target.name,
            CheckKind.HTTP,
            Verdict.CLOSED,
            f"got a 429 after {statuses.index(429) + 1} requests",
            evidence,
        )
    return CheckResult(
        "C5",
        target.name,
        CheckKind.HTTP,
        Verdict.VULNERABLE,
        f"no 429 after {len(statuses)} rapid requests",
        evidence,
    )


def _check_c6(target: Target) -> CheckResult:
    if not target.install_token:
        return CheckResult(
            "C6",
            target.name,
            CheckKind.HTTP,
            Verdict.MANUAL,
            "requires target.install_token (control plane is token-gated) — supply it to run this check",
            "",
        )
    h = _headers(target)
    try:
        pair = httpx.post(
            f"{target.base_url}/v1/control/pair",
            headers=h,
            json={"channel": "findings-console", "channel_user_id": "probe"},
            timeout=10,
        )
        if pair.status_code != 200:
            return CheckResult(
                "C6",
                target.name,
                CheckKind.HTTP,
                Verdict.ERROR,
                f"pair request failed ({pair.status_code})",
                pair.text,
            )
        statuses = []
        with httpx.Client(timeout=10) as client:
            for i in range(20):
                bogus_code = f"{i:06d}"
                r = client.post(
                    f"{target.base_url}/v1/control/pair/confirm", headers=h, json={"code": bogus_code}
                )
                statuses.append(r.status_code)
                if r.status_code not in (404, 200):
                    break
    except httpx.HTTPError as e:
        return _err("C6", target, e)
    evidence = f"20 confirm attempts with wrong codes, statuses={statuses}"
    locked_out = any(s not in (404, 200) for s in statuses)
    if locked_out:
        return CheckResult(
            "C6",
            target.name,
            CheckKind.HTTP,
            Verdict.CLOSED,
            "confirm attempts were eventually rate-limited/locked out",
            evidence,
        )
    return CheckResult(
        "C6",
        target.name,
        CheckKind.HTTP,
        Verdict.VULNERABLE,
        "20 wrong-code attempts, all just 404 — no attempt limiter",
        evidence,
    )


CHECKS: list[Check] = [
    Check(
        "A1",
        "Public data plane, no auth",
        "INV-2",
        CheckKind.HTTP,
        "POST /v1/chat with no Authorization header.",
        _check_a1,
        "T1.1",
        attacker_role="AR1",
    ),
    Check(
        "A2",
        "Unauthenticated info disclosure",
        "INV-2",
        CheckKind.HTTP,
        "GET /v1/status, /v1/providers, /v1/capabilities, /v1/cost/by_agent, /v1/calls with no auth.",
        _check_a2,
        "T1.2",
        attacker_role="AR1",
    ),
    Check(
        "C1",
        "SSRF via image resolver",
        "INV-2/INV-3",
        CheckKind.HTTP,
        "POST /v1/chat with an image_url pointing at a link-local address. Heuristic — match your fix's error wording to 'block' for this check to detect it.",
        _check_c1,
        "T1.5",
        notes="Heuristic, not a network-level oracle — read the evidence yourself too.",
        attacker_role="AR1",
    ),
    Check(
        "C4",
        "Verbose upstream errors",
        "INV-2",
        CheckKind.HTTP,
        "Trigger a provider failure and check whether the response leaks upstream hostnames/tracebacks. Needs target.install_token once A1 is fixed.",
        _check_c4,
        "T1.3",
        notes="Under-reports as CLOSED if the target has zero provider keys configured — no provider "
        "is even attempted, so there's nothing to leak. Set at least one mock provider key "
        "(e.g. GEMINI_API_KEY=mock-not-real) on the target so a real upstream attempt happens.",
        attacker_role="AR1",
    ),
    Check(
        "C5",
        "No rate limits on data plane",
        "INV-8",
        CheckKind.HTTP,
        "Fire 15 rapid POST /v1/chat and check for a 429.",
        _check_c5,
        "T1.4",
        notes="Against a live remote target this actually invokes /v1/chat up to 15 times — prefer running this one against your local dev server.",
        attacker_role="AR1",
    ),
    Check(
        "C6",
        "Pairing-code brute force",
        "INV-2",
        CheckKind.HTTP,
        "Issue a pairing code, then hammer /confirm with wrong codes. Needs target.install_token.",
        _check_c6,
        "T1.8",
        notes="Currently token-gated end-to-end in this codebase, so the realistic actor is someone who "
        "already holds the install token, not an anonymous outsider — see PLAN.md T1.8.",
        attacker_role="AR4",
    ),
]
