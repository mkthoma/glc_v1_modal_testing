"""A1 — the data plane must reject unauthenticated callers.

Before the fix, /v1/chat and friends had no auth dependency at all: an
anonymous internet caller (AR1) could drive LLM spend with zero
credentials. Each of these must now 401 before reaching any provider
dispatch logic.
"""

from __future__ import annotations


def test_chat_without_token_is_401(app_client):
    r = app_client.post("/v1/chat", json={"prompt": "hi"})
    assert r.status_code == 401


def test_chat_batch_without_token_is_401(app_client):
    r = app_client.post("/v1/chat/batch", json={"calls": [{"prompt": "hi"}]})
    assert r.status_code == 401


def test_vision_without_token_is_401(app_client):
    r = app_client.post("/v1/vision", json={"prompt": "describe", "image": "http://example.com/x.png"})
    assert r.status_code == 401


def test_embed_without_token_is_401(app_client):
    r = app_client.post("/v1/embed", json={"text": "hi"})
    assert r.status_code == 401


def test_transcribe_without_token_is_401(app_client):
    r = app_client.post("/v1/transcribe", json={"audio_b64": "AA==", "mime": "audio/wav"})
    assert r.status_code == 401


def test_speak_without_token_is_401(app_client):
    r = app_client.post("/v1/speak", json={"text": "hi"})
    assert r.status_code == 401


def test_chat_with_bad_token_is_403(app_client, install_token):
    r = app_client.post("/v1/chat", headers={"Authorization": "Bearer wrong"}, json={"prompt": "hi"})
    assert r.status_code == 403


def test_chat_with_valid_token_passes_auth(app_client, auth_headers):
    r = app_client.post("/v1/chat", headers=auth_headers, json={"prompt": "hi"})
    # No providers configured in the test env, so this won't be 401/403 —
    # it proves auth was cleared, not that a provider call succeeded.
    assert r.status_code not in (401, 403)
