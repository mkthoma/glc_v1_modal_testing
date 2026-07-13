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


def _ensure_paired_owner(target: Target, channel: str) -> None:
    """The allowlist drops messages from unknown senders before the
    spoof-vulnerable code ever runs — that's a *different* control, not
    the one this check tests. Pair the probe identity as an owner on
    `channel` first so the envelope actually reaches channel_ws's
    channel-vs-route comparison (or lack of it)."""
    h = {"Authorization": f"Bearer {target.install_token}"}
    pair = httpx.post(
        f"{target.base_url}/v1/control/pair",
        headers=h,
        json={"channel": channel, "channel_user_id": _PROBE_USER_ID, "trust_level": "owner_paired"},
        timeout=10,
    )
    pair.raise_for_status()
    code = pair.json()["code"]
    httpx.post(
        f"{target.base_url}/v1/control/pair/confirm", headers=h, json={"code": code}, timeout=10
    ).raise_for_status()


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
        "telegram/discord) because those are the channels enabled by default in channels.yaml.",
        attacker_role="AR3",
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
    ),
]
