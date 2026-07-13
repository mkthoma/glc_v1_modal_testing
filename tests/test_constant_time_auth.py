"""Constant-time token comparisons.

control.py's _require_token and channels.py's channel_ws both compared
the install token with plain `!=` instead of hmac.compare_digest —
inconsistent with the webhook verify-token check next door
(channels.py's channel_webhook_verify), which already did it
correctly. A network attacker who can measure response timing can, in
principle, recover the token byte-by-byte (CWE-208).

Timing itself isn't practical to assert in a unit test, so this
verifies the fix at the source level (no naive comparison left) plus
the unchanged behavioral contract (right token passes, wrong token is
still rejected).
"""

from __future__ import annotations

import ast
from pathlib import Path

import glc.routes.channels as channels_mod
import glc.routes.control as control_mod


def _uses_naive_token_compare(module) -> bool:
    """True if the module's source contains `presented != expected` or
    `presented == expected` — the naive, non-constant-time pattern."""
    src = Path(module.__file__).read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            op = node.ops[0]
            if isinstance(op, (ast.NotEq, ast.Eq)):
                names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                if {"presented", "expected"} <= names:
                    return True
    return False


def test_control_plane_does_not_use_naive_comparison():
    assert _uses_naive_token_compare(control_mod) is False


def test_channels_ws_does_not_use_naive_comparison():
    assert _uses_naive_token_compare(channels_mod) is False


def test_control_plane_still_rejects_wrong_token(app_client):
    r = app_client.post(
        "/v1/control/pair",
        headers={"Authorization": "Bearer wrong"},
        json={"channel": "telegram", "channel_user_id": "1"},
    )
    assert r.status_code == 403


def test_control_plane_still_accepts_right_token(app_client, auth_headers):
    r = app_client.post(
        "/v1/control/pair",
        headers=auth_headers,
        json={"channel": "telegram", "channel_user_id": "1"},
    )
    assert r.status_code == 200
