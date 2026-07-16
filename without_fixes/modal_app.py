"""
Modal deployment wrapper for the PRE-HARDENING baseline of glc_v1.

This is the findings console's "before" target: the exact code and
deployment shape from the original migration commit (before any Part 1
security work), so every check's "before" value is a real, live
measurement against a real deployed app - not a local assumption or a
hand-written description of what used to be true.

Deliberately UNCHANGED from the original wrapper except for two things,
both just to let this coexist with the hardened ("after") deployment
without colliding:
  - a distinct App name (glc-v1-gateway-baseline, not glc-v1-gateway)
  - a distinct Volume name (glc-data-baseline, not glc-data) so this
    deployment's install token / pairing store / audit log never touch
    the hardened deployment's persistent state
The provider-key Secret (glc-llm-keys) is intentionally the SAME one
the hardened deployment uses - it's just mock environment variables,
and reusing it means one secret to manage instead of two.

No application code changes here at all - see FINDINGS.md and
without_fixes/glc/ for what's genuinely absent: no data-plane auth, no
per-adapter container separation, no egress control, no hash-chained
audit log, no policy-engine hardening, no pairing lockout, hand-listed
(non-reproducible) image dependencies, no single-writer guarantee.

Deploy with:   uv run modal deploy without_fixes/modal_app.py
(run from the repo root, same as the hardened deployment - this file
has no pyproject.toml/uv.lock of its own to build from)
"""

from pathlib import Path

import modal

# The Modal "app" is just a namespace for everything we deploy under this name.
app = modal.App("glc-v1-gateway-baseline")

# Path to the glc package next to this file. We copy the whole package (not just
# .py files) so its data files travel too: policy.yaml, channels.yaml,
# audit/schema.sql, and the channel catalogue.
LOCAL_GLC = Path(__file__).parent / "glc"

# The image = a Linux box with Python 3.11, the same dependencies as
# pyproject.toml, the glc package copied in, and GLC_CONFIG_DIR pointed at the
# Volume mount so all databases land on persistent storage instead of the
# throwaway container filesystem.
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "fastapi>=0.110",
        "uvicorn[standard]>=0.27",
        "httpx>=0.27",
        "python-dotenv>=1.0",
        "pydantic>=2.6",
        "jsonschema>=4.21",
        "pyyaml>=6.0",
        "websockets>=12.0",
        "twilio>=9.0",
    )
    .env({"GLC_CONFIG_DIR": "/data/glc"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

# A persistent Volume. The audit db, pairing db, and install token live here and
# survive restarts and redeploys. Without this, every restart wipes them.
# Named distinctly from the hardened deployment's "glc-data" Volume so the two
# deployments' install tokens / pairing stores / audit logs never mix.
data_volume = modal.Volume.from_name("glc-data-baseline", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Same
# Secret the hardened deployment uses (mock values) - just env vars, no
# reason to duplicate it for a second deployment.
llm_secret = modal.Secret.from_name("glc-llm-keys")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
)
@modal.asgi_app()
def fastapi_app():
    """Serve the unchanged glc_v1 FastAPI app."""
    import os

    # The gateway writes its databases and install token here on startup, so the
    # folder must exist on the mounted Volume before the app's lifespan runs.
    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web  # the real glc_v1 app, imported as-is
    return web
