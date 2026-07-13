"""C2 / L9 — cross-channel envelope spoofing.

Before the fix, channel_ws trusted whatever `channel` field a caller
put in the envelope body over the channel identity implied by the
WebSocket route it connected to (e.g. connect to /v1/channels/webui,
but claim channel="whatsapp" in the payload). The gateway now rejects
any message where the two disagree, checked on every message — not
just at connect time.

webui and whatsapp are both enabled: true in the packaged
channels.yaml, matching the findings console's default check pair.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from starlette.websockets import WebSocketDisconnect

from glc.security.pairing import get_pairing_store


def _envelope(channel: str, text: str = "hello", sender: str = "attacker") -> dict:
    return {
        "channel": channel,
        "channel_user_id": sender,
        "user_handle": sender,
        "text": text,
        "trust_level": "untrusted",
        "arrived_at": datetime.now(UTC).isoformat(),
        "metadata": {},
    }


def test_spoofed_channel_is_rejected_and_closed(app_client, auth_headers):
    with app_client.websocket_connect("/v1/channels/webui", headers=auth_headers) as ws:
        ws.send_text(json.dumps(_envelope("whatsapp")))
        # The gateway must close the socket, not just error-and-continue.
        try:
            msg = ws.receive_text()
            assert "does not match route" in json.loads(msg)["error"]
        except WebSocketDisconnect:
            pass
        try:
            ws.receive_text()
            raise AssertionError("connection should have been closed after the spoof attempt")
        except WebSocketDisconnect as exc:
            assert exc.code == 1008


def test_matching_channel_is_accepted(app_client, auth_headers):
    get_pairing_store().force_pair_owner("webui", "owner1")
    with app_client.websocket_connect("/v1/channels/webui", headers=auth_headers) as ws:
        ws.send_text(json.dumps(_envelope("webui", sender="owner1")))
        reply = json.loads(ws.receive_text())
        assert reply["channel"] == "webui"
        assert "hello" in reply["text"]


def test_spoof_check_runs_on_every_message_not_just_first(app_client, auth_headers):
    """A connection can send a legitimate envelope first, then a
    spoofed one on message #2 — the check must not be connect-time only."""
    get_pairing_store().force_pair_owner("webui", "owner1")
    with app_client.websocket_connect("/v1/channels/webui", headers=auth_headers) as ws:
        ws.send_text(json.dumps(_envelope("webui", text="first, legit", sender="owner1")))
        ws.receive_text()  # the echo reply for the legit message

        ws.send_text(json.dumps(_envelope("whatsapp", text="second, spoofed", sender="owner1")))
        try:
            ws.receive_text()
        except WebSocketDisconnect:
            pass
        try:
            ws.receive_text()
            raise AssertionError("connection should have been closed after the spoof attempt")
        except WebSocketDisconnect as exc:
            assert exc.code == 1008
