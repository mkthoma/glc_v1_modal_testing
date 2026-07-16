"""tools/findings_console/checks_ws.py's C2/L9 check calls
/v1/control/pair then /v1/control/pair/confirm as its own setup step.
glc/security/pairing.py's CONFIRM_ATTEMPT_LIMIT is a single global
counter (deliberately not scoped per identity, so an attacker can't
just rotate identities to reset it) — which means C6's check (20 wrong
codes) can trip a lockout that then blocks C2/L9's own legitimate,
first-try confirm for up to 5 minutes. That's an expected interaction
between two real, correctly-designed checks, not a bug in either one.

Two layers of defense, tested here: (1) _ensure_paired_owner now checks
/v1/control/presence first and skips pair/confirm entirely once the
probe is already paired from an earlier run, so repeat runs of C2/L9
stop being exposed to C6's lockout at all; (2) on the rare occasion the
very first pairing attempt does land in an active lockout, the console
reports a clear, distinguishing message instead of a bare exception."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from tools.findings_console import checks_ws
from tools.findings_console.models import Target, Verdict

_TARGET = Target(name="modal", base_url="https://example.modal.run", install_token="tok")


def _mock_response(status_code: int, json_body: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}

    def _raise_for_status():
        if status_code >= 400:
            raise httpx.HTTPStatusError("error", request=MagicMock(), response=resp)

    resp.raise_for_status.side_effect = _raise_for_status
    return resp


def _presence_response(paired_users: list[dict] | None = None) -> MagicMock:
    return _mock_response(200, {"paired_users": paired_users or []})


def test_ensure_paired_owner_skips_pair_confirm_when_already_paired():
    """The core fix: once presence shows the probe already owner_paired,
    pair/confirm is never called again — immune to C6's lockout from
    the second run onward."""
    already_paired = _presence_response(
        [{"channel": "webui", "channel_user_id": checks_ws._PROBE_USER_ID, "trust_level": "owner_paired"}]
    )
    with patch("httpx.get", return_value=already_paired), patch("httpx.post") as post:
        checks_ws._ensure_paired_owner(_TARGET, "webui")
    post.assert_not_called()


def test_ensure_paired_owner_pairs_normally_when_presence_shows_not_paired():
    not_paired_yet = _presence_response([])
    pair_resp = _mock_response(200, {"code": "123456"})
    confirm_resp = _mock_response(200)
    with (
        patch("httpx.get", return_value=not_paired_yet),
        patch("httpx.post", side_effect=[pair_resp, confirm_resp]) as post,
    ):
        checks_ws._ensure_paired_owner(_TARGET, "webui")
    assert post.call_count == 2


def test_is_already_paired_owner_returns_false_when_presence_check_fails():
    """Best-effort: a presence-check hiccup falls through to the normal
    pair/confirm flow rather than blocking the check outright."""
    with patch("httpx.get", side_effect=httpx.ConnectError("down")):
        assert checks_ws._is_already_paired_owner(_TARGET, "webui") is False


def test_ensure_paired_owner_raises_setup_blocked_on_429_from_confirm():
    not_paired_yet = _presence_response([])
    pair_resp = _mock_response(200, {"code": "123456"})
    confirm_resp = _mock_response(429)
    with (
        patch("httpx.get", return_value=not_paired_yet),
        patch("httpx.post", side_effect=[pair_resp, confirm_resp]),
    ):
        try:
            checks_ws._ensure_paired_owner(_TARGET, "webui")
            raised = False
        except checks_ws._PairingSetupBlocked:
            raised = True
    assert raised


def test_check_c2_reports_clear_error_not_a_bare_exception_on_lockout_collision():
    not_paired_yet = _presence_response([])
    pair_resp = _mock_response(200, {"code": "123456"})
    confirm_resp = _mock_response(429)
    with (
        patch("httpx.get", return_value=not_paired_yet),
        patch("httpx.post", side_effect=[pair_resp, confirm_resp]),
    ):
        result = checks_ws._check_c2(_TARGET)
    assert result.verdict == Verdict.ERROR
    assert "C6" in result.summary
    assert "lockout" in result.summary
    assert "not a bug" in result.summary.lower()


def test_ensure_paired_owner_succeeds_normally_when_confirm_is_200():
    not_paired_yet = _presence_response([])
    pair_resp = _mock_response(200, {"code": "123456"})
    confirm_resp = _mock_response(200)
    with (
        patch("httpx.get", return_value=not_paired_yet),
        patch("httpx.post", side_effect=[pair_resp, confirm_resp]),
    ):
        checks_ws._ensure_paired_owner(_TARGET, "webui")  # must not raise
