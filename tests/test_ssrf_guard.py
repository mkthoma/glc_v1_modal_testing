"""C1 — SSRF guard on the chat image-URL resolver.

Before the fix, _resolve_image_urls fetched any http(s) URL handed to
it, following redirects, with no host restriction — turning the
gateway into an attacker's SSRF proxy with the server's own network
identity and position. The fix blocks private/loopback/link-local
targets on the initial request AND on every redirect hop.
"""

from __future__ import annotations

import httpx
import pytest

from glc.routes import chat as chat_route


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "169.254.169.254",  # cloud metadata endpoint
        "10.0.0.5",
        "192.168.1.1",
        "::1",
    ],
)
def test_blocked_hosts_are_rejected(host):
    assert chat_route._is_blocked_image_host(host) is True


def test_unresolvable_host_fails_closed():
    assert chat_route._is_blocked_image_host("this-does-not-resolve.invalid") is True


def test_vision_request_to_private_ip_is_blocked(app_client, auth_headers):
    r = app_client.post(
        "/v1/chat",
        headers=auth_headers,
        json={
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "describe"},
                        {
                            "type": "image_url",
                            "image_url": {"url": "http://169.254.169.254/latest/meta-data/"},
                        },
                    ],
                }
            ]
        },
    )
    assert r.status_code == 400
    assert "blocked" in r.json()["detail"].lower()


def test_redirect_to_private_ip_is_blocked(app_client, auth_headers, monkeypatch):
    """The first hop resolves to a public host and is allowed through;
    the redirect Location then points at a private IP and must be
    re-validated, not blindly followed."""
    monkeypatch.setattr(
        chat_route,
        "_is_blocked_image_host",
        lambda host: host not in ("public.example.com",),
    )

    calls = {"n": 0}

    async def _fake_get(self, url, *args, **kwargs):
        calls["n"] += 1
        req = httpx.Request("GET", url)
        if "public.example.com" in str(url):
            return httpx.Response(302, headers={"location": "http://10.0.0.5/steal"}, request=req)
        raise AssertionError("redirect target should have been blocked before a second fetch")

    monkeypatch.setattr(httpx.AsyncClient, "get", _fake_get)

    r = app_client.post(
        "/v1/chat",
        headers=auth_headers,
        json={
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "describe"},
                        {"type": "image_url", "image_url": {"url": "http://public.example.com/x.png"}},
                    ],
                }
            ]
        },
    )
    assert r.status_code == 400
    assert "blocked" in r.json()["detail"].lower()
    assert calls["n"] == 1
