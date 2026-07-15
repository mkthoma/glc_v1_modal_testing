"""tools/findings_console/checks_live_probe.py — L1/L3/L4 now call a real
deployed Modal Function (glc-adapter-shape-probe) instead of running a
local subprocess that always says "vulnerable" by construction. These
tests mock modal.Function.from_name(...).remote() so they run without
any real Modal deployment or network access, the same way
test_policy_remote.py mocks the equivalent call for L5."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tools.findings_console import checks_live_probe as live_probe
from tools.findings_console.models import Verdict


def _patch_app_detection():
    return patch.object(live_probe, "detect_app_and_function", return_value=("glc-v1-gateway", "fastapi_app"))


def test_l1_closed_when_probe_reports_no_gemini_key():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": False}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l1(None)
    assert result.verdict == Verdict.CLOSED
    assert "absent" in result.summary


def test_l1_vulnerable_when_probe_reports_gemini_key_present():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": True, "data_mount_exists": False}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l1(None)
    assert result.verdict == Verdict.VULNERABLE


def test_l3_closed_when_no_data_mount():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": False}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l3(None)
    assert result.verdict == Verdict.CLOSED


def test_l3_vulnerable_when_data_mount_present():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": True}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l3(None)
    assert result.verdict == Verdict.VULNERABLE


def test_l4_closed_when_no_data_mount():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": False}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l4(None)
    assert result.verdict == Verdict.CLOSED


def test_l4_vulnerable_when_data_mount_present():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": True}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l4(None)
    assert result.verdict == Verdict.VULNERABLE


def test_reports_error_not_vulnerable_when_app_not_detected():
    """Nothing was actually observed if the app can't even be identified
    — must not silently default to a claim either way."""
    with patch.object(live_probe, "detect_app_and_function", return_value=None):
        result = live_probe._check_l1(None)
    assert result.verdict == Verdict.ERROR


def test_reports_error_not_vulnerable_when_modal_call_raises():
    """A not-yet-deployed probe Function, missing auth, or a transient
    API error must land as ERROR, never as a silent VULNERABLE/CLOSED
    claim about something that was never actually observed."""
    with _patch_app_detection(), patch("modal.Function.from_name", side_effect=RuntimeError("not found")):
        result = live_probe._check_l1(None)
    assert result.verdict == Verdict.ERROR
    assert "not found" in result.evidence


def test_all_three_checks_registered_with_live_probe_kind():
    from tools.findings_console.models import CheckKind

    ids_and_kinds = {c.id: c.kind for c in live_probe.CHECKS}
    assert ids_and_kinds == {
        "L1": CheckKind.LIVE_PROBE,
        "L3": CheckKind.LIVE_PROBE,
        "L4": CheckKind.LIVE_PROBE,
    }
