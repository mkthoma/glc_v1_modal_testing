"""tools/findings_console/modal_detect.py parses modal_app.py so the
console can find your deployed gateway without pasting a URL/token by
hand. These tests cover the pure regex-parsing half (no network, no
Modal auth needed) against both the real modal_app.py and synthetic
source strings, so a future edit to modal_app.py's shape is caught
here rather than silently breaking auto-detection."""

from __future__ import annotations

from tools.findings_console import modal_detect


def test_detects_app_and_function_from_real_modal_app_py():
    result = modal_detect.detect_app_and_function()
    assert result == ("glc-v1-gateway", "fastapi_app")


def test_detects_volume_and_token_path_from_real_modal_app_py():
    result = modal_detect.detect_volume_and_token_path()
    assert result == ("glc-data", "glc/install_token")


def test_detect_app_and_function_returns_none_on_unrecognized_source(monkeypatch):
    monkeypatch.setattr(modal_detect, "_read_modal_app_source", lambda: "print('no modal app here')")
    assert modal_detect.detect_app_and_function() is None


def test_detect_app_and_function_returns_none_when_file_missing(monkeypatch):
    monkeypatch.setattr(modal_detect, "_read_modal_app_source", lambda: None)
    assert modal_detect.detect_app_and_function() is None
    assert modal_detect.detect_volume_and_token_path() is None


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
    monkeypatch.setattr(modal_detect, "_read_modal_app_source", lambda: src)
    assert modal_detect.detect_app_and_function() == ("some-other-app", "serve_app")
    assert modal_detect.detect_volume_and_token_path() == ("some-volume", "nested/glc/install_token")


def test_detect_volume_and_token_path_returns_none_when_config_dir_outside_mount(monkeypatch):
    src = """
data_volume = modal.Volume.from_name("some-volume")
GLC_DATA_ENV = {"GLC_CONFIG_DIR": "/elsewhere/glc"}
@app.function(volumes={"/data": data_volume})
"""
    monkeypatch.setattr(modal_detect, "_read_modal_app_source", lambda: src)
    assert modal_detect.detect_volume_and_token_path() is None
