"""tools/findings_console/checks_ws.py's C2/L9 check calls
/v1/control/pair then /v1/control/pair/confirm as its own setup step.
glc/security/pairing.py's CONFIRM_ATTEMPT_LIMIT is a single global
counter (deliberately not scoped per identity, so an attacker can't
just rotate identities to reset it) — which means C6's check (20 wrong
codes) can trip a lockout that then blocks C2/L9's own legitimate,
first-try confirm for up to 5 minutes. That's an expected interaction
between two real, correctly-designed checks, not a bug in either one -
these tests confirm the console reports it clearly instead of a bare
exception string."""

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


def test_ensure_paired_owner_raises_setup_blocked_on_429_from_confirm():
    pair_resp = _mock_response(200, {"code": "123456"})
    confirm_resp = _mock_response(429)
    with patch("httpx.post", side_effect=[pair_resp, confirm_resp]):
        try:
            checks_ws._ensure_paired_owner(_TARGET, "webui")
            raised = False
        except checks_ws._PairingSetupBlocked:
            raised = True
    assert raised


def test_check_c2_reports_clear_error_not_a_bare_exception_on_lockout_collision():
    pair_resp = _mock_response(200, {"code": "123456"})
    confirm_resp = _mock_response(429)
    with patch("httpx.post", side_effect=[pair_resp, confirm_resp]):
        result = checks_ws._check_c2(_TARGET)
    assert result.verdict == Verdict.ERROR
    assert "C6" in result.summary
    assert "lockout" in result.summary
    assert "not a bug" in result.summary.lower()


def test_ensure_paired_owner_succeeds_normally_when_confirm_is_200():
    pair_resp = _mock_response(200, {"code": "123456"})
    confirm_resp = _mock_response(200)
    with patch("httpx.post", side_effect=[pair_resp, confirm_resp]):
        checks_ws._ensure_paired_owner(_TARGET, "webui")  # must not raise
