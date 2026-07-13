"""C3 — WS channel auth must be header-only, no query-string fallback.

Before the fix, channel_ws accepted the install token via ?token=...
as well as the Authorization header. URLs land in access logs, browser
history, and Referrer headers — a bearer token is a bit that should
never be reflected in the URL.
"""

from __future__ import annotations

from starlette.websockets import WebSocketDisconnect


def test_query_string_token_is_rejected(app_client, install_token):
    """The old ?token=... fallback must no longer authenticate."""
    try:
        with app_client.websocket_connect(f"/v1/channels/webui?token={install_token}"):
            raise AssertionError("connection should have been rejected — no query-string fallback")
    except WebSocketDisconnect as exc:
        assert exc.code == 1008


def test_header_token_still_works(app_client, auth_headers):
    # Connection accepted — proven by not raising on entry.
    with app_client.websocket_connect("/v1/channels/webui", headers=auth_headers):
        pass
