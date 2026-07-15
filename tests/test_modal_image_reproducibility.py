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


def test_all_four_stores_point_at_the_volume():
    """A6 correction, found by checking rather than assuming: only
    glc.config.CONFIG_DIR derives from GLC_CONFIG_DIR. glc/audit/store.py,
    glc/security/pairing.py, and glc/db.py each hardcode their own
    "~/.glc" default and only honor their own specific env var
    (GLC_AUDIT_DB, GLC_PAIRING_DB, GLC_GATEWAY_DB). Setting only
    GLC_CONFIG_DIR (as an earlier version of this file did) means
    audit.sqlite/pairings.sqlite/gateway.sqlite silently fall back to the
    ephemeral container filesystem and never reach the Volume — verified
    live: `modal volume ls glc-data glc` showed only `install_token`
    despite real traffic. All four must be set explicitly."""
    src = _source()
    for env_var in ("GLC_CONFIG_DIR", "GLC_AUDIT_DB", "GLC_PAIRING_DB", "GLC_GATEWAY_DB"):
        assert re.search(rf'"{env_var}"\s*:\s*"/data/', src), f"{env_var} is not pointed at the Volume"


def test_adapter_image_does_not_set_any_data_store_env_var():
    """L3/L4 — adapter_image() must NOT set GLC_CONFIG_DIR/GLC_AUDIT_DB/
    GLC_PAIRING_DB/GLC_GATEWAY_DB, or an adapter's in-process call to
    force_pair_owner()/install_token_path() would resolve to the same
    paths the real gateway trusts instead of a disconnected local file."""
    src = _source()
    m = re.search(r"def adapter_image\(.*?\n\ndef ", src, re.DOTALL)
    assert m, "could not locate adapter_image()'s body"
    body = m.group(0)
    for env_var in ("GLC_CONFIG_DIR", "GLC_AUDIT_DB", "GLC_PAIRING_DB", "GLC_GATEWAY_DB"):
        assert env_var not in body, f"{env_var} must not appear in adapter_image()"


def test_adapter_functions_never_mount_the_volume():
    """L3/L4 — make_adapter_functions() must never pass volumes=, or an
    adapter container could read/write the real pairing/audit/gateway
    data on the shared Volume even without a matching env var."""
    src = _source()
    m = re.search(r"def make_adapter_functions\(.*?\n\n\n", src, re.DOTALL)
    assert m, "could not locate make_adapter_functions()'s body"
    assert "volumes=" not in m.group(0)


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


def test_policy_engine_runs_as_its_own_function():
    """L5 — the policy engine must be its own Modal Function, not an
    in-process call, or monkey-patching glc.policy.engine.evaluate in
    the gateway's own process would still neuter every decision."""
    src = _source()
    assert re.search(r'name="glc-policy-engine"', src)
    assert "from glc.policy.engine import evaluate" in src


def test_policy_engine_function_has_no_secrets_or_volume():
    """The policy Function's only inputs are the tool_call/context dicts
    passed in on each call — no Secret, no Volume mount. Mounting the
    Volume here would let a compromised policy container read the real
    pairing/audit/install-token data, re-opening what Move B/C closed
    for adapters."""
    src = _source()
    m = re.search(r"@app\.function\(image=policy_image[^\n]*\)", src)
    assert m, "could not locate the policy engine Function's decorator"
    block = m.group(0)
    assert "secrets=" not in block
    assert "volumes=" not in block


def test_core_gateway_routes_policy_checks_through_the_separated_function():
    src = _source()
    m = re.search(r"@app\.function\(\s*image=image,.*?\n\)", src, re.DOTALL)
    assert m, "could not locate the core gateway Function's decorator"
    assert "GLC_POLICY_ENGINE_REMOTE" in m.group(0)


def test_adapter_shape_probe_function_exists():
    """The findings console's L1/L3/L4 checks call this Function directly
    to get a live-measured verdict instead of a documented assumption —
    it has to actually exist in the deployed app for that to work."""
    src = _source()
    assert re.search(r'name="glc-adapter-shape-probe"', src)
    assert "def adapter_shape_probe" in src


def test_adapter_shape_probe_has_no_secret_and_uses_adapter_image():
    """The whole point is proving nothing sensitive is reachable from an
    adapter-shaped container — it must be built from adapter_image() (no
    GLC_DATA_ENV) and carry no Secret, exactly like a real adapter."""
    src = _source()
    m = re.search(r"@app\.function\(image=adapter_image\([^\n]*?\)[^\n]*\)", src)
    assert m, "could not locate the adapter-shape probe Function's decorator"
    block = m.group(0)
    assert "secrets=" not in block
    assert "volumes=" not in block


def test_telegram_egress_allowlist_is_configured():
    """Move D — telegram's Sandbox egress control must be an allowlist
    (specific domains), not the coarse all-or-nothing block_network flag
    that's all modal.Function supports in this Modal version."""
    src = _source()
    assert re.search(r"outbound_domain_allowlist", src)
    assert "api.telegram.org" in src
