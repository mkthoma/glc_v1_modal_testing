"""L7 — the whisper_cpp subprocess call must not resolve its binary via PATH.

Before the fix, run_whisper_cpp() used shutil.which("whisper-cli"),
which resolves via the PATH environment variable — exploitable if any
earlier-loaded, less-trusted code can write to a directory ahead of
the real binary's location in PATH. The fix requires an absolute,
explicitly-configured path (GLC_WHISPER_CLI_PATH).
"""

from __future__ import annotations

import importlib

import pytest

from glc.voice.stt.providers.whisper_cpp import wrapper


def test_module_does_not_import_shutil():
    assert not hasattr(wrapper, "shutil")


def test_missing_binary_raises_clear_error(monkeypatch, tmp_path):
    monkeypatch.setenv("GLC_WHISPER_CLI_PATH", str(tmp_path / "does-not-exist"))
    importlib.reload(wrapper)
    try:
        with pytest.raises(RuntimeError, match="GLC_WHISPER_CLI_PATH"):
            wrapper.run_whisper_cpp(b"\x00" * 100, "audio/wav")
    finally:
        monkeypatch.delenv("GLC_WHISPER_CLI_PATH", raising=False)
        importlib.reload(wrapper)


def test_configured_path_is_absolute_and_used(monkeypatch, tmp_path):
    fake_cli = tmp_path / "whisper-cli"
    fake_cli.write_text("")
    monkeypatch.setenv("GLC_WHISPER_CLI_PATH", str(fake_cli))
    importlib.reload(wrapper)
    try:
        assert wrapper.WHISPER_CLI_PATH == fake_cli
        assert wrapper.WHISPER_CLI_PATH.is_absolute()
    finally:
        monkeypatch.delenv("GLC_WHISPER_CLI_PATH", raising=False)
        importlib.reload(wrapper)
