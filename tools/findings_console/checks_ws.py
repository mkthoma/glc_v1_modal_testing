"""WebSocket checks: C2/L9 (cross-channel envelope spoof) and C3 (WS
token accepted via query string).

Both require `target.install_token` — the WS route is token-gated
regardless of the bug being tested, so without a token these report
MANUAL rather than a false VULNERABLE.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import httpx
import websockets
from websockets.exceptions import WebSocketException

from tools.findings_console.models import Check, CheckKind, CheckResult, Target, Verdict

_PROBE_USER_ID = "findings-console-probe"

# channels.yaml ships telegram/discord disabled by default; whatsapp and
# webui are enabled out of the box. Using a disabled channel as either the
# route or the spoof target trips the *disabled-channel* gate in
# glc.security.allowlists.allowed() before the spoof-vulnerable code path
# (channel_ws never checking env.channel == route name) is even reached —
# that would mask the bug this check exists to demonstrate.
_ROUTE_CHANNEL = "webui"
_SPOOF_CHANNEL = "whatsapp"


class _PairingSetupBlocked(Exception):
    """Raised when _ensure_paired_owner can't complete because of an
    expected side effect of a *different* check (C6's pairing-confirm
    lockout is global, not scoped per caller/identity — see
    checks_http.py's C6), not a bug in C2/L9 itself."""


def _is_already_paired_owner(target: Target, channel: str) -> bool:
    """/v1/control/presence lists every currently-paired identity — if
    the probe is already owner_paired on `channel` from an earlier run
    of this same check, there's no reason to pair again. Best-effort:
    any failure here just means "assume not paired yet" and fall
    through to the normal pair/confirm flow, so a presence-check hiccup
    never blocks the check outright."""
    h = {"Authorization": f"Bearer {target.install_token}"}
    try:
        r = httpx.get(f"{target.base_url}/v1/control/presence", headers=h, timeout=10)
        r.raise_for_status()
    except httpx.HTTPError:
        return False
    return any(
        p.get("channel") == channel
        and p.get("channel_user_id") == _PROBE_USER_ID
        and p.get("trust_level") == "owner_paired"
        for p in r.json().get("paired_users", [])
    )


def _ensure_paired_owner(target: Target, channel: str) -> None:
    """The allowlist drops messages from unknown senders before the
    spoof-vulnerable code ever runs — that's a *different* control, not
    the one this check tests. Pair the probe identity as an owner on
    `channel` first so the envelope actually reaches channel_ws's
    channel-vs-route comparison (or lack of it).

    Skips the pair/confirm dance entirely once the probe is already
    paired from an earlier run — pairings persist (they're written to
    the real pairing store), so after the first successful run this
    check never touches /v1/control/pair/confirm again, which also
    means it stops being exposed to C6's pairing-confirm lockout on
    every re-run after the first."""
    if _is_already_paired_owner(target, channel):
        return
    h = {"Authorization": f"Bearer {target.install_token}"}
    pair = httpx.post(
        f"{target.base_url}/v1/control/pair",
        headers=h,
        json={"channel": channel, "channel_user_id": _PROBE_USER_ID, "trust_level": "owner_paired"},
        timeout=10,
    )
    pair.raise_for_status()
    code = pair.json()["code"]
    confirm = httpx.post(
        f"{target.base_url}/v1/control/pair/confirm", headers=h, json={"code": code}, timeout=10
    )
    if confirm.status_code == 429:
        # C6's own fix (glc/security/pairing.py's CONFIRM_ATTEMPT_LIMIT) is a
        # single global counter on the confirm endpoint, not scoped per
        # channel_user_id or caller — deliberately, since scoping a
        # brute-force lockout per identity lets an attacker just rotate
        # identities to reset it. That correctly-designed global lockout
        # has a real, documented side effect: if C6 tripped it recently,
        # this check's OWN legitimate confirm (the right code, first try)
        # gets blocked by the same window. Not a bug in either check.
        raise _PairingSetupBlocked(
            "the gateway's pairing-confirm lockout is still active, most likely tripped by a recent "
            "C6 run in this same 5-minute window (glc/security/pairing.py's CONFIRM_ATTEMPT_LIMIT is a "
            "single global counter, deliberately not scoped per identity — see C6's fix_summary). This "
            "check's own setup step needs one legitimate confirm and got blocked by that same lockout. "
            "Not a bug in C2/L9 or C6 — wait for the 5-minute window to pass and re-run, or run this "
            "check before C6 in a fresh pass."
        )
    confirm.raise_for_status()


def _ws_url(target: Target, path: str) -> str:
    base = target.base_url.rstrip("/")
    if base.startswith("https://"):
        return "wss://" + base[len("https://") :] + path
    if base.startswith("http://"):
        return "ws://" + base[len("http://") :] + path
    return base + path


def _envelope(channel: str) -> str:
    return json.dumps(
        {
            "channel": channel,
            "channel_user_id": _PROBE_USER_ID,
            "user_handle": "probe",
            "trust_level": "untrusted",
            "arrived_at": datetime.now(UTC).isoformat(),
        }
    )


async def _run_c2(target: Target) -> CheckResult:
    url = _ws_url(target, f"/v1/channels/{_ROUTE_CHANNEL}")
    headers = {"Authorization": f"Bearer {target.install_token}"}
    try:
        async with websockets.connect(url, additional_headers=headers, open_timeout=10) as ws:
            await ws.send(_envelope(_SPOOF_CHANNEL))  # spoofed: connected to the webui route
            try:
                reply = await asyncio.wait_for(ws.recv(), timeout=8)
            except (WebSocketException, TimeoutError) as e:
                return CheckResult(
                    "C2",
                    target.name,
                    CheckKind.WS,
                    Verdict.CLOSED,
                    f"connection was closed/no reply after sending a mismatched-channel envelope ({e})",
                    f"url={url}\nsent channel={_SPOOF_CHANNEL} over the {_ROUTE_CHANNEL} route\n{e}",
                )
    except WebSocketException as e:
        return CheckResult(
            "C2",
            target.name,
            CheckKind.WS,
            Verdict.CLOSED,
            f"handshake or connection rejected: {e}",
            f"url={url}\n{e}",
        )
    reply_text = reply if isinstance(reply, str) else reply.decode("utf-8", errors="replace")
    evidence = f"url={url}\nsent channel={_SPOOF_CHANNEL} over the {_ROUTE_CHANNEL} route\nreceived: {reply_text[:500]}"
    if "[glc echo]" in reply_text:
        return CheckResult(
            "C2",
            target.name,
            CheckKind.WS,
            Verdict.VULNERABLE,
            "the gateway processed and echoed a message whose envelope.channel did not match the WS route",
            evidence,
        )
    if "does not match route" in reply_text:
        # The fix's actual shape: an explicit rejection message, THEN
        # close — not a silent close, which _run_c2's earlier branches
        # already treat as CLOSED. A same-content explicit rejection is
        # just as unambiguous; don't fall through to MANUAL for it.
        return CheckResult(
            "C2",
            target.name,
            CheckKind.WS,
            Verdict.CLOSED,
            "the gateway sent an explicit channel-mismatch rejection instead of processing the message",
            evidence,
        )
    return CheckResult(
        "C2", target.name, CheckKind.WS, Verdict.MANUAL, "unexpected reply shape — inspect evidence", evidence
    )


async def _run_c3(target: Target) -> CheckResult:
    url = _ws_url(target, "/v1/channels/telegram") + f"?token={target.install_token}"
    try:
        async with websockets.connect(url, open_timeout=10) as ws:
            await ws.send(_envelope("telegram"))
            try:
                reply = await asyncio.wait_for(ws.recv(), timeout=8)
            except (WebSocketException, TimeoutError) as e:
                return CheckResult(
                    "C3",
                    target.name,
                    CheckKind.WS,
                    Verdict.CLOSED,
                    f"query-string-only auth was not accepted ({e})",
                    f"url={url}\n{e}",
                )
    except WebSocketException as e:
        return CheckResult(
            "C3",
            target.name,
            CheckKind.WS,
            Verdict.CLOSED,
            f"handshake rejected with query-string-only auth: {e}",
            f"url={url}\n{e}",
        )
    reply_text = reply if isinstance(reply, str) else reply.decode("utf-8", errors="replace")
    evidence = (
        f"url={url}\nconnected with ?token=... only, no Authorization header\nreceived: {reply_text[:500]}"
    )
    return CheckResult(
        "C3",
        target.name,
        CheckKind.WS,
        Verdict.VULNERABLE,
        "connection was accepted using only the query-string token",
        evidence,
    )


def _check_c2(target: Target) -> CheckResult:
    if not target.install_token:
        return CheckResult(
            "C2", target.name, CheckKind.WS, Verdict.MANUAL, "requires target.install_token", ""
        )
    try:
        _ensure_paired_owner(target, _ROUTE_CHANNEL)
    except _PairingSetupBlocked as e:
        return CheckResult("C2", target.name, CheckKind.WS, Verdict.ERROR, str(e), str(e), error=str(e))
    except httpx.HTTPError as e:
        return CheckResult(
            "C2",
            target.name,
            CheckKind.WS,
            Verdict.ERROR,
            f"could not pair the probe identity as an owner on {_ROUTE_CHANNEL!r} first: {e}",
            str(e),
            error=str(e),
        )
    return asyncio.run(_run_c2(target))


def _check_c3(target: Target) -> CheckResult:
    if not target.install_token:
        return CheckResult(
            "C3", target.name, CheckKind.WS, Verdict.MANUAL, "requires target.install_token", ""
        )
    return asyncio.run(_run_c3(target))


_C2_COMMAND = """python3 - <<'PY'
import asyncio, json, websockets

url = "__BASE_URL__".replace("https://", "wss://").replace("http://", "ws://") + "/v1/channels/webui"
headers = {"Authorization": "Bearer __TOKEN__"}

async def main():
    async with websockets.connect(url, additional_headers=headers) as ws:
        # connected to the webui route, but claim to be a whatsapp message
        await ws.send(json.dumps({
            "channel": "whatsapp", "channel_user_id": "attacker", "user_handle": "probe",
            "trust_level": "untrusted", "arrived_at": "2026-01-01T00:00:00Z",
        }))
        print(await ws.recv())

asyncio.run(main())
PY"""

_C3_COMMAND = """python3 - <<'PY'
import asyncio, json, websockets

# token only in the query string, no Authorization header at all
url = "__BASE_URL__".replace("https://", "wss://").replace("http://", "ws://") + "/v1/channels/telegram?token=__TOKEN__"

async def main():
    async with websockets.connect(url) as ws:
        await ws.send(json.dumps({
            "channel": "telegram", "channel_user_id": "attacker", "user_handle": "probe",
            "trust_level": "untrusted", "arrived_at": "2026-01-01T00:00:00Z",
        }))
        print(await ws.recv())

asyncio.run(main())
PY"""

CHECKS: list[Check] = [
    Check(
        "C2",
        "Cross-channel envelope spoofing (= L9)",
        "INV-2",
        CheckKind.WS,
        "Connect to WS /v1/channels/webui, send an envelope with channel='whatsapp'; the "
        "gateway should reject the mismatch, not process it.",
        _check_c2,
        "T1.6",
        notes="Same underlying bug as L9 in the ground-truth table. Uses webui/whatsapp (not "
        "telegram/discord) because those are the channels enabled by default in channels.yaml. Only "
        "pairs the probe identity once — checks /v1/control/presence first and skips pair/confirm "
        "entirely on every re-run after the first, so this stops being exposed to C6's global "
        "confirm-attempt lockout after the first successful run. If it still reports error mentioning "
        "a pairing lockout, that means the very first pair attempt landed in an active C6 lockout — "
        "wait ~5 minutes and re-run once; every run after that is immune.",
        attacker_role="AR3",
        command=_C2_COMMAND,
        fix_summary=(
            "glc/routes/channels.py's channel_ws now checks `if env.channel != name:` and closes the "
            "socket with WS_1008_POLICY_VIOLATION plus an explicit rejection message, instead of "
            "processing (and echoing) an envelope whose channel doesn't match the WS route it arrived on."
        ),
    ),
    Check(
        "C3",
        "WS token accepted via query string",
        "INV-4",
        CheckKind.WS,
        "Connect using only ?token=... (no Authorization header); should be rejected once T1.7 lands.",
        _check_c3,
        "T1.7",
        attacker_role="AR1",
        command=_C3_COMMAND,
        fix_summary=(
            "glc/routes/channels.py removes the `token: str | None = Query(...)` fallback entirely — "
            "channel_ws now only accepts the token from the Authorization header, so a URL-only token "
            "(which leaks into proxy/access logs) is rejected at handshake."
        ),
    ),
]
