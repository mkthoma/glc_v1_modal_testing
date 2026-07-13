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


# ---------------------------------------------------------------------------
# Move B/C: per-adapter container + scoped Secret, demonstrated on telegram
# ---------------------------------------------------------------------------
# L1-L5/L7/L8/L10 all exist because every adapter and every route share one
# Python process with the core gateway's LLM provider keys — Python has no
# in-process ACL on os.environ or on importable functions, so no amount of
# code-level permission checking closes this. The only real wall is a
# process/container boundary the kernel enforces (namespaces + cgroups).
#
# This factory builds that boundary generically; telegram (the one
# catalogue adapter confirmed to have a real, non-stub on_message/send
# implementation — glc/channels/catalogue/telegram/adapter.py) demonstrates
# it end-to-end with working code, not a stub. The core gateway Function
# stops importing/calling telegram's adapter code in-process; it calls
# these two Functions via glc/channels/remote.py instead, communicating
# only through the typed ChannelMessage/ChannelReply envelopes that already
# exist (glc/channels/envelope.py) — the "typed contract, no shared memory"
# boundary docs/ARCHITECTURE.md describes as the intended design. The
# remaining stub adapters inherit the same factory once implemented; the
# architecture is fixed even though not every adapter has been migrated.


def adapter_image(adapter_name: str) -> modal.Image:
    # `adapter_name` is unused today (every adapter shares the same base
    # image) but kept in the signature for per-adapter image tuning later
    # (e.g. an adapter needing extra system packages).
    return (
        modal.Image.from_registry(
            "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
        )
        .uv_sync(extra_options="--no-dev")
        .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
    )


def make_adapter_functions(name: str, secret_name: str | None) -> None:
    """Registers glc-adapter-<name> (on_message) and glc-adapter-<name>-send
    (send) as their own Modal Functions, each with only `secret_name`'s
    credential attached — never glm_secret, the core gateway's LLM
    provider Secret.

    serialized=True: these functions are defined dynamically (nested in
    this factory, one call per adapter) rather than as one hardcoded
    global per adapter, so Modal must ship them via cloudpickle instead
    of resolving them by module-level name — required by this Modal
    version for any @app.function not at true module scope.
    """
    secrets = [modal.Secret.from_name(secret_name)] if secret_name else []
    img = adapter_image(name)

    @app.function(image=img, secrets=secrets, name=f"glc-adapter-{name}", serialized=True)
    def on_message(raw: dict) -> dict | None:
        import asyncio

        from glc.channels.registry import instantiate

        adapter = instantiate(name)
        msg = asyncio.run(adapter.on_message(raw))
        return msg.model_dump(mode="json") if msg is not None else None

    @app.function(image=img, secrets=secrets, name=f"glc-adapter-{name}-send", serialized=True)
    def send(reply: dict) -> dict:
        import asyncio

        from glc.channels.envelope import ChannelReply
        from glc.channels.registry import instantiate

        adapter = instantiate(name)
        result = asyncio.run(adapter.send(ChannelReply.model_validate(reply)))
        return result if isinstance(result, dict) else {"result": result}


# The Telegram bot token lives in its own Secret, created separately with
# `modal secret create glc-telegram-secret TELEGRAM_BOT_TOKEN=telegram-mock-not-real`
# — mock value, same rule as glc-llm-keys.
make_adapter_functions("telegram", "glc-telegram-secret")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret],
    # Move B/C: telegram's on_message/send now run in their own Function
    # (above), so this core Function never imports its adapter code and
    # never has TELEGRAM_BOT_TOKEN in its environment.
    env={"GLC_SEPARATED_ADAPTERS": "telegram"},
    min_containers=0,  # scale to zero when idle -> protects the free tier
    # A6 fix: the audit log and gateway db are plain sqlite3.connect()
    # calls on the shared Volume with no cross-container coordination —
    # more than one concurrent writer risks a corrupted or split audit
    # trail. max_containers=1 trades away horizontal scaling for a
    # single writer, the right trade for a security-critical, low-QPS
    # audit path. The "real" fix (a dedicated managed database, or a
    # single append-only writer process separate from request-handling
    # containers) is Move B/C territory.
    max_containers=1,
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
