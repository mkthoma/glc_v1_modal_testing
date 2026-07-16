"""tools/findings_console/checks_live_probe.py — L1/L3/L4/L8 now call real
deployed Modal Functions (glc-adapter-shape-probe,
glc-adapter-shape-self-kill-probe) instead of running a local subprocess
that always says "vulnerable" by construction. These tests mock
modal.Function.from_name(...).remote() and httpx so they run without any
real Modal deployment or network access, the same way test_policy_remote.py
mocks the equivalent call for L5.

A target named "before" is special-cased: the pre-hardening baseline has
no per-adapter container to call a probe Function inside of at all (that
separation is exactly what these findings say doesn't exist yet there),
so those four checks report a structural VULNERABLE verdict from reading
without_fixes/modal_app.py directly instead of attempting a live call."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tools.findings_console import checks_live_probe as live_probe
from tools.findings_console.models import Target, Verdict

_AFTER_TARGET = Target(name="modal", base_url="https://example.modal.run", install_token=None)
_BEFORE_TARGET = Target(name="before", base_url="https://baseline.example.modal.run", install_token=None)


def _patch_app_detection():
    return patch.object(live_probe, "detect_app_and_function", return_value=("glc-v1-gateway", "fastapi_app"))


def _healthz_response(status_code: int) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    return resp


def test_l1_closed_when_probe_reports_no_gemini_key():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": False}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l1(_AFTER_TARGET)
    assert result.verdict == Verdict.CLOSED
    assert "absent" in result.summary


def test_l1_vulnerable_when_probe_reports_gemini_key_present():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": True, "data_mount_exists": False}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l1(_AFTER_TARGET)
    assert result.verdict == Verdict.VULNERABLE


def test_l3_closed_when_no_data_mount():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": False}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l3(_AFTER_TARGET)
    assert result.verdict == Verdict.CLOSED


def test_l3_vulnerable_when_data_mount_present():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": True}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l3(_AFTER_TARGET)
    assert result.verdict == Verdict.VULNERABLE


def test_l4_closed_when_no_data_mount():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": False}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l4(_AFTER_TARGET)
    assert result.verdict == Verdict.CLOSED


def test_l4_vulnerable_when_data_mount_present():
    fake_fn = MagicMock()
    fake_fn.remote.return_value = {"gemini_key_present": False, "data_mount_exists": True}
    with _patch_app_detection(), patch("modal.Function.from_name", return_value=fake_fn):
        result = live_probe._check_l4(_AFTER_TARGET)
    assert result.verdict == Verdict.VULNERABLE


def test_reports_error_not_vulnerable_when_app_not_detected():
    """Nothing was actually observed if the app can't even be identified
    — must not silently default to a claim either way."""
    with patch.object(live_probe, "detect_app_and_function", return_value=None):
        result = live_probe._check_l1(_AFTER_TARGET)
    assert result.verdict == Verdict.ERROR


def test_reports_error_not_vulnerable_when_modal_call_raises():
    """A not-yet-deployed probe Function, missing auth, or a transient
    API error must land as ERROR, never as a silent VULNERABLE/CLOSED
    claim about something that was never actually observed."""
    with _patch_app_detection(), patch("modal.Function.from_name", side_effect=RuntimeError("not found")):
        result = live_probe._check_l1(_AFTER_TARGET)
    assert result.verdict == Verdict.ERROR
    assert "not found" in result.evidence


def test_all_four_checks_registered_with_live_probe_kind():
    from tools.findings_console.models import CheckKind

    ids_and_kinds = {c.id: c.kind for c in live_probe.CHECKS}
    assert ids_and_kinds == {
        "L1": CheckKind.LIVE_PROBE,
        "L3": CheckKind.LIVE_PROBE,
        "L4": CheckKind.LIVE_PROBE,
        "L8": CheckKind.LIVE_PROBE,
    }


def test_l8_closed_when_self_kill_raises_and_gateway_stays_healthy():
    with (
        _patch_app_detection(),
        patch("httpx.get", side_effect=[_healthz_response(200), _healthz_response(200)]),
        patch(
            "modal.Function.from_name",
            return_value=MagicMock(remote=MagicMock(side_effect=RuntimeError("killed"))),
        ),
    ):
        result = live_probe._check_l8(_AFTER_TARGET)
    assert result.verdict == Verdict.CLOSED


def test_l8_vulnerable_when_gateway_unhealthy_after_self_kill():
    with (
        _patch_app_detection(),
        patch("httpx.get", side_effect=[_healthz_response(200), _healthz_response(500)]),
        patch(
            "modal.Function.from_name",
            return_value=MagicMock(remote=MagicMock(side_effect=RuntimeError("killed"))),
        ),
    ):
        result = live_probe._check_l8(_AFTER_TARGET)
    assert result.verdict == Verdict.VULNERABLE


def test_l8_error_when_gateway_unhealthy_before_testing():
    """Never risk the self-kill test at all if the gateway isn't even
    healthy to begin with — a post-kill failure would be meaningless."""
    with patch("httpx.get", return_value=_healthz_response(500)):
        result = live_probe._check_l8(_AFTER_TARGET)
    assert result.verdict == Verdict.ERROR


def test_l8_error_when_self_kill_probe_returns_normally():
    """If the self-kill probe somehow doesn't terminate, that's
    inconclusive test mechanics, not a security claim either way."""
    with (
        _patch_app_detection(),
        patch("httpx.get", side_effect=[_healthz_response(200), _healthz_response(200)]),
        patch(
            "modal.Function.from_name", return_value=MagicMock(remote=MagicMock(return_value="still alive"))
        ),
    ):
        result = live_probe._check_l8(_AFTER_TARGET)
    assert result.verdict == Verdict.ERROR


def _baseline_source_without_separation() -> str:
    return """
app = modal.App("glc-v1-gateway-baseline")
@app.function(secrets=[llm_secret])
@modal.asgi_app()
def fastapi_app():
    pass
"""


def _baseline_source_with_separation() -> str:
    return """
app = modal.App("glc-v1-gateway-baseline")
ADAPTER_SECRETS = {"telegram": "glc-telegram-secret"}
def make_adapter_functions(name, secret_name):
    pass
"""


def test_l1_before_target_reports_vulnerable_from_baseline_source(monkeypatch, tmp_path):
    fake_modal_app = tmp_path / "modal_app.py"
    fake_modal_app.write_text(_baseline_source_without_separation())
    monkeypatch.setattr(live_probe, "WITHOUT_FIXES_MODAL_APP", fake_modal_app)
    result = live_probe._check_l1(_BEFORE_TARGET)
    assert result.verdict == Verdict.VULNERABLE
    assert result.target_name == "before"


def test_l3_before_target_reports_vulnerable_from_baseline_source(monkeypatch, tmp_path):
    fake_modal_app = tmp_path / "modal_app.py"
    fake_modal_app.write_text(_baseline_source_without_separation())
    monkeypatch.setattr(live_probe, "WITHOUT_FIXES_MODAL_APP", fake_modal_app)
    result = live_probe._check_l3(_BEFORE_TARGET)
    assert result.verdict == Verdict.VULNERABLE


def test_l4_before_target_reports_vulnerable_from_baseline_source(monkeypatch, tmp_path):
    fake_modal_app = tmp_path / "modal_app.py"
    fake_modal_app.write_text(_baseline_source_without_separation())
    monkeypatch.setattr(live_probe, "WITHOUT_FIXES_MODAL_APP", fake_modal_app)
    result = live_probe._check_l4(_BEFORE_TARGET)
    assert result.verdict == Verdict.VULNERABLE


def test_l8_before_target_reports_vulnerable_from_baseline_source_without_calling_modal(
    monkeypatch, tmp_path
):
    """The whole point of special-casing "before": never risk a live
    self-kill call against the baseline at all."""
    fake_modal_app = tmp_path / "modal_app.py"
    fake_modal_app.write_text(_baseline_source_without_separation())
    monkeypatch.setattr(live_probe, "WITHOUT_FIXES_MODAL_APP", fake_modal_app)
    with patch("modal.Function.from_name") as from_name:
        result = live_probe._check_l8(_BEFORE_TARGET)
    from_name.assert_not_called()
    assert result.verdict == Verdict.VULNERABLE


def test_before_target_reports_error_if_baseline_unexpectedly_has_separation(monkeypatch, tmp_path):
    """If without_fixes/modal_app.py was accidentally replaced with the
    hardened shape, don't silently claim vulnerable — that would be a
    false positive baked into the tool itself."""
    fake_modal_app = tmp_path / "modal_app.py"
    fake_modal_app.write_text(_baseline_source_with_separation())
    monkeypatch.setattr(live_probe, "WITHOUT_FIXES_MODAL_APP", fake_modal_app)
    result = live_probe._check_l1(_BEFORE_TARGET)
    assert result.verdict == Verdict.ERROR
