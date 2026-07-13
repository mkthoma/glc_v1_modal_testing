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


ALL_CATALOGUE_ADAPTERS = [
    p.name
    for p in (Path(__file__).parent.parent / "glc" / "channels" / "catalogue").iterdir()
    if p.is_dir() and p.name != "__pycache__"
]

# Every adapter under glc/channels/catalogue/ has a real, non-stub
# implementation (verified by grepping each adapter.py for
# "raise NotImplementedError" and finding none) — an earlier version of
# modal_app.py migrated only telegram on the mistaken assumption that
# the other 14 were still stubs. There's no adapter left that
# legitimately needs to share the core gateway's LLM provider Secret.
ADAPTERS_NEEDING_NO_SECRET = {"local_mic", "webui"}


def test_every_catalogue_adapter_is_registered_in_modal_app():
    """Move B/C — every real adapter must have its own Modal Function
    registration, not just a demonstrated subset."""
    src = _source()
    m = re.search(r"ADAPTER_SECRETS[^{]*=\s*\{(.*?)\n\}", src, re.DOTALL)
    assert m, "could not locate the ADAPTER_SECRETS mapping in modal_app.py"
    mapping_src = m.group(1)
    for name in ALL_CATALOGUE_ADAPTERS:
        assert f'"{name}"' in mapping_src, f"{name} is missing from ADAPTER_SECRETS"


def test_adapters_needing_credentials_get_their_own_secret():
    src = _source()
    m = re.search(r"ADAPTER_SECRETS[^{]*=\s*\{(.*?)\n\}", src, re.DOTALL)
    assert m
    mapping_src = m.group(1)
    for name in ALL_CATALOGUE_ADAPTERS:
        if name in ADAPTERS_NEEDING_NO_SECRET:
            assert re.search(rf'"{name}"\s*:\s*None', mapping_src), f"{name} should map to None"
        else:
            assert re.search(rf'"{name}"\s*:\s*"glc-[\w-]+-secret"', mapping_src), (
                f"{name} should map to its own glc-<name>-secret"
            )


def test_no_two_adapters_share_the_same_secret_name():
    """Each adapter's Secret must be its own — sharing one Secret across
    multiple adapters would undo the whole point of scoped credentials
    (INV-1/INV-4), even if it happened to be less code to write."""
    src = _source()
    m = re.search(r"ADAPTER_SECRETS[^{]*=\s*\{(.*?)\n\}", src, re.DOTALL)
    assert m
    secret_names = re.findall(r':\s*"(glc-[\w-]+-secret)"', m.group(1))
    assert len(secret_names) == len(set(secret_names)), f"duplicate secret names: {secret_names}"


def test_core_gateway_function_does_not_import_adapter_secrets():
    """The core gateway Function's own secrets list must stay scoped to
    glm_secret only — no per-adapter secret must ever be attached there,
    or the whole point of the separation is undone."""
    src = _source()
    m = re.search(r"@app\.function\(\s*image=image,.*?\n\)", src, re.DOTALL)
    assert m, "could not locate the core gateway Function's decorator"
    core_fn_block = m.group(0)
    assert "secrets=[llm_secret]" in core_fn_block
    for name in ALL_CATALOGUE_ADAPTERS:
        assert f"glc-{name}-secret" not in core_fn_block
    assert "GLC_SEPARATED_ADAPTERS" in core_fn_block


def test_telegram_egress_allowlist_is_configured():
    """Move D — telegram's Sandbox egress control must be an allowlist
    (specific domains), not the coarse all-or-nothing block_network flag
    that's all modal.Function supports in this Modal version."""
    src = _source()
    assert re.search(r"outbound_domain_allowlist", src)
    assert "api.telegram.org" in src
