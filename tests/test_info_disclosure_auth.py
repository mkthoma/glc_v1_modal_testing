"""A2 — info-disclosure endpoints must not be reachable anonymously.

Before the fix, /v1/status, /v1/providers, /v1/capabilities,
/v1/cost/by_agent, /v1/calls, /v1/routers, and /v1/embedders handed an
attacker a full map of provider order, rate limits, and usage before
any authentication — free reconnaissance for AR1. /docs and
/openapi.json were also FastAPI defaults, never disabled.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize(
    "path",
    [
        "/v1/status",
        "/v1/providers",
        "/v1/capabilities",
        "/v1/cost/by_agent",
        "/v1/calls",
        "/v1/routers",
        "/v1/embedders",
    ],
)
def test_info_endpoint_without_token_is_401(app_client, path):
    r = app_client.get(path)
    assert r.status_code == 401


@pytest.mark.parametrize(
    "path",
    [
        "/v1/status",
        "/v1/providers",
        "/v1/capabilities",
        "/v1/cost/by_agent",
        "/v1/calls",
        "/v1/routers",
        "/v1/embedders",
    ],
)
def test_info_endpoint_with_valid_token_succeeds(app_client, auth_headers, path):
    r = app_client.get(path, headers=auth_headers)
    assert r.status_code == 200


def test_docs_disabled_in_production(monkeypatch):
    monkeypatch.setenv("GLC_ENV", "production")
    import glc.main as m

    importlib.reload(m)
    try:
        assert m.app.docs_url is None
        assert m.app.redoc_url is None
        assert m.app.openapi_url is None
    finally:
        monkeypatch.delenv("GLC_ENV", raising=False)
        importlib.reload(m)


def test_docs_enabled_outside_production(app_client):
    r = app_client.get("/docs")
    assert r.status_code == 200
