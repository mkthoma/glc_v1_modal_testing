"""C5 — rate limits and a hard daily budget cap on the data plane.

Before the fix, chat.py had zero references to
glc.security.rate_limits — the limiter was wired only into WS/webhook
traffic, never /v1/chat and friends. A single credential (T1.1 issues
one shared install token to every caller) could otherwise burn the
whole deployment's budget in one loop.

Caveat, documented honestly here and in the README: since every
caller shares one install token, this is a single global rate limit /
budget cap on the whole gateway, not per-caller throttling.
"""

from __future__ import annotations

from glc.security.rate_limits import get_rate_limiter


def test_chat_is_rate_limited_after_default_budget(app_client, auth_headers):
    limiter = get_rate_limiter()
    mpm, _ = limiter.limits_for("http_data_plane")
    for _ in range(mpm):
        app_client.post("/v1/chat", headers=auth_headers, json={"prompt": "hi"})

    r = app_client.post("/v1/chat", headers=auth_headers, json={"prompt": "hi"})
    assert r.status_code == 429


def test_embed_is_rate_limited_after_default_budget(app_client, auth_headers):
    limiter = get_rate_limiter()
    mpm, _ = limiter.limits_for("http_data_plane")
    for _ in range(mpm):
        app_client.post("/v1/embed", headers=auth_headers, json={"text": "hi"})

    r = app_client.post("/v1/embed", headers=auth_headers, json={"text": "hi"})
    assert r.status_code == 429


def test_daily_budget_cap_blocks_further_calls(app_client, auth_headers, monkeypatch):
    monkeypatch.setenv("GLC_DAILY_BUDGET_USD", "0.01")

    from glc import db

    db.log_call(provider="groq", model="x", input_tokens=1_000_000, output_tokens=1_000_000, status="ok")

    r = app_client.post("/v1/chat", headers=auth_headers, json={"prompt": "hi"})
    assert r.status_code == 429
    assert "budget" in r.json()["detail"].lower()


def test_no_budget_cap_when_unset(app_client, auth_headers, monkeypatch):
    monkeypatch.delenv("GLC_DAILY_BUDGET_USD", raising=False)
    r = app_client.post("/v1/chat", headers=auth_headers, json={"prompt": "hi"})
    # No providers configured in the test env, so this is a routing
    # failure, not a rate-limit/budget 429.
    assert r.status_code != 429
