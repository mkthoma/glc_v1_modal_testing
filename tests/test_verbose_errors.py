"""C4 — upstream provider errors must not leak to the client.

Before the fix, chat.py put str(e) (provider hostnames, raw upstream
error bodies) directly into HTTPException details returned to the
caller. Now the detailed error is logged server-side only; the client
gets a generic message.
"""

from __future__ import annotations

from glc import providers as P


class _FailingProvider:
    model = "fake-model"
    capabilities: dict = {}

    async def chat(self, *args, **kwargs):
        raise P.ProviderError(
            "secret upstream detail: connection to 10.0.0.5:1521 refused",
            status=500,
            retryable=False,
        )


def test_chat_provider_failure_returns_generic_error(app_client, auth_headers):
    app_client.app.state.router.providers["gemini"] = _FailingProvider()
    r = app_client.post(
        "/v1/chat",
        headers=auth_headers,
        json={"prompt": "hi", "provider": "gemini"},
    )
    assert r.status_code == 502
    body = r.json()["detail"]
    assert body == "upstream provider error"
    assert "10.0.0.5" not in body
    assert "gemini" not in body


def test_image_fetch_failure_returns_generic_error(app_client, auth_headers):
    r = app_client.post(
        "/v1/chat",
        headers=auth_headers,
        json={
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "describe"},
                        {"type": "image_url", "image_url": {"url": "http://127.0.0.1:1/nope.png"}},
                    ],
                }
            ]
        },
    )
    assert r.status_code == 400
    body = r.json()["detail"]
    assert body == "failed to fetch image url"
