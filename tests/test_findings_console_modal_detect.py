"""tools/findings_console/modal_detect.py parses a modal_app.py so the
console can find a deployed gateway without pasting a URL/token by
hand. These tests cover the pure regex-parsing half (no network, no
Modal auth needed) against both the real with_fixes/modal_app.py and
synthetic source strings, so a future edit to modal_app.py's shape is
caught here rather than silently breaking auto-detection.

Every detect_* function takes an explicit modal_app_path now, since the
console tracks two deployments (before/baseline and after/hardened)
side by side - these tests patch _read_modal_app_source to accept
whatever path argument it's called with and ignore it, since the tests
care about the parsing logic, not which file is passed."""

from __future__ import annotations

from tools.findings_console import modal_detect


def test_detects_app_and_function_from_real_with_fixes_modal_app_py():
    result = modal_detect.detect_app_and_function(modal_detect.WITH_FIXES_MODAL_APP)
    assert result == ("glc-v1-gateway", "fastapi_app")


def test_detects_volume_and_token_path_from_real_with_fixes_modal_app_py():
    result = modal_detect.detect_volume_and_token_path(modal_detect.WITH_FIXES_MODAL_APP)
    assert result == ("glc-data", "glc/install_token")


def test_default_path_is_with_fixes():
    """Calling with no argument at all should behave identically to
    passing WITH_FIXES_MODAL_APP explicitly — the hardened deployment
    is the sensible default for any caller that doesn't care about the
    before/after distinction."""
    assert modal_detect.detect_app_and_function() == modal_detect.detect_app_and_function(
        modal_detect.WITH_FIXES_MODAL_APP
    )


def test_detect_app_and_function_returns_none_on_unrecognized_source(monkeypatch):
    monkeypatch.setattr(modal_detect, "_read_modal_app_source", lambda _path: "print('no modal app here')")
    assert modal_detect.detect_app_and_function(modal_detect.WITH_FIXES_MODAL_APP) is None


def test_detect_app_and_function_returns_none_when_file_missing(monkeypatch):
    monkeypatch.setattr(modal_detect, "_read_modal_app_source", lambda _path: None)
    assert modal_detect.detect_app_and_function(modal_detect.WITH_FIXES_MODAL_APP) is None
    assert modal_detect.detect_volume_and_token_path(modal_detect.WITH_FIXES_MODAL_APP) is None


def test_detect_volume_and_token_path_handles_nested_config_dir(monkeypatch):
    src = """
app = modal.App("some-other-app")
data_volume = modal.Volume.from_name("some-volume", create_if_missing=True)
GLC_DATA_ENV = {
    "GLC_CONFIG_DIR": "/mnt/data/nested/glc",
}
@app.function(volumes={"/mnt/data": data_volume})
@modal.asgi_app()
def serve_app():
    pass
"""
    monkeypatch.setattr(modal_detect, "_read_modal_app_source", lambda _path: src)
    fake_path = modal_detect.WITH_FIXES_MODAL_APP
    assert modal_detect.detect_app_and_function(fake_path) == ("some-other-app", "serve_app")
    assert modal_detect.detect_volume_and_token_path(fake_path) == ("some-volume", "nested/glc/install_token")


def test_detect_volume_and_token_path_returns_none_when_config_dir_outside_mount(monkeypatch):
    src = """
data_volume = modal.Volume.from_name("some-volume")
GLC_DATA_ENV = {"GLC_CONFIG_DIR": "/elsewhere/glc"}
@app.function(volumes={"/data": data_volume})
"""
    monkeypatch.setattr(modal_detect, "_read_modal_app_source", lambda _path: src)
    assert modal_detect.detect_volume_and_token_path(modal_detect.WITH_FIXES_MODAL_APP) is None


def test_without_fixes_path_constant_points_at_baseline_folder():
    assert modal_detect.WITHOUT_FIXES_MODAL_APP.parts[-2:] == ("without_fixes", "modal_app.py")


def test_with_fixes_path_constant_points_at_hardened_folder():
    assert modal_detect.WITH_FIXES_MODAL_APP.parts[-2:] == ("with_fixes", "modal_app.py")
