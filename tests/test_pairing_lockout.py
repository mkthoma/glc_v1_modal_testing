"""C6 — pairing-code confirmation must not be brute-forceable.

Before the fix, confirm_code had no attempt counter or lockout at all
— an install-token holder (or, if a future feature ever lets a channel
user submit a code directly, a plain channel user) could try all
1,000,000 six-digit codes with zero friction. This is a global lockout
(no per-caller identity is available at this layer until a code
actually resolves), so it throttles "anyone guessing codes."
"""

from __future__ import annotations

from glc.security.pairing import CONFIRM_ATTEMPT_LIMIT


def test_repeated_wrong_codes_eventually_locked_out(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    for _ in range(CONFIRM_ATTEMPT_LIMIT):
        r = app_client.post("/v1/control/pair/confirm", headers=h, json={"code": "000000"})
        assert r.status_code == 404

    # One more attempt, past the limit — locked out regardless of guess.
    r = app_client.post("/v1/control/pair/confirm", headers=h, json={"code": "000000"})
    assert r.status_code == 429


def test_valid_confirm_does_not_count_as_a_failure(app_client, install_token):
    h = {"Authorization": f"Bearer {install_token}"}
    p = app_client.post(
        "/v1/control/pair",
        headers=h,
        json={"channel": "telegram", "channel_user_id": "1", "user_handle": "me"},
    ).json()
    r = app_client.post("/v1/control/pair/confirm", headers=h, json={"code": p["code"]})
    assert r.status_code == 200

    # A single successful confirm shouldn't move the failure counter at
    # all — plenty of headroom left before lockout.
    r2 = app_client.post("/v1/control/pair/confirm", headers=h, json={"code": "000000"})
    assert r2.status_code == 404
