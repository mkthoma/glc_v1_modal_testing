"""
Modal deployment wrapper for glc_v1  (Session 12, Move 1: wrap the gateway).

This file changes NO application code. It only describes, for Modal:
  1. the container image to build,
  2. a persistent Volume for the ~/.glc config/db folder,
  3. a Secret that supplies the provider keys as environment variables,
  4. which object to serve  ->  the existing FastAPI app, glc.main:app.

Deploy with:   uv run modal deploy modal_app.py
"""

from pathlib import Path

import modal

# The Modal "app" is just a namespace for everything we deploy under this name.
app = modal.App("glc-v1-gateway")

# Path to the glc package next to this file. We copy the whole package (not just
# .py files) so its data files travel too: policy.yaml, channels.yaml,
# audit/schema.sql, and the channel catalogue.
LOCAL_GLC = Path(__file__).parent / "glc"

# A5 fix: build from uv.lock instead of a hand-duplicated pip_install
# list that could silently drift from what's actually tested locally,
# and pin the base image by digest so it can't shift under us between
# deploys. Digest resolved via the Docker Hub registry API for
# python:3.11-slim (the same value `docker pull` + `docker inspect
# --format='{{index .RepoDigests 0}}'` would produce) — re-resolve and
# update this if you intentionally want to move to a newer base.
#
# The image = a pinned Linux box with Python 3.11, dependencies installed
# by `uv sync --frozen` against this repo's own uv.lock (so the deployed
# image can't drift from what's tested locally), the glc package copied
# in, and GLC_CONFIG_DIR pointed at the Volume mount so all databases
# land on persistent storage instead of the throwaway container filesystem.
image = (
    modal.Image.from_registry(
        "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
    )
    .uv_sync(extra_options="--no-dev")  # --no-dev: skip pytest/ruff/mypy, the lock is honored either way
    .env({"GLC_CONFIG_DIR": "/data/glc", "GLC_ENV": "production"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

# A persistent Volume. The audit db, pairing db, and install token live here and
# survive restarts and redeploys. Without this, every restart wipes them.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Created
# separately with `modal secret create glc-llm-keys ...` (mock values for now).
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
