"""A5 — the Modal image build must be reproducible.

Before the fix, modal_app.py hand-duplicated a pip_install(...) list
that could silently drift from what's actually tested locally
(pyproject.toml / uv.lock), and the base image
(modal.Image.debian_slim(python_version="3.11")) was not pinned by
digest, so it could shift under us between deploys.
"""

from __future__ import annotations

import re
from pathlib import Path

MODAL_APP = Path(__file__).parent.parent / "modal_app.py"


def _source() -> str:
    return MODAL_APP.read_text()


def test_image_build_consumes_the_lockfile():
    src = _source()
    assert re.search(r"pip_install_from_pyproject|uv_sync|from_dockerfile", src)
    # The old hand-duplicated dependency list must be gone.
    assert not re.search(r"\.pip_install\(\s*\n?\s*\"", src)


def test_base_image_is_pinned_by_digest():
    src = _source()
    assert re.search(r"@sha256:[0-9a-f]{64}", src)


def test_gateway_function_is_single_writer():
    """A6 — the Volume-backed audit/gateway sqlite dbs have no
    cross-container write coordination; max_containers=1 is the
    Part-1-scoped mitigation (a real fix needs a dedicated writer
    process or managed DB, which is Move B/C territory)."""
    src = _source()
    assert re.search(r"max_containers\s*=\s*1\b", src)
