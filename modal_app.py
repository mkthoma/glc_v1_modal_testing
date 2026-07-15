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
# Correction, found by checking rather than assuming: glc.config.CONFIG_DIR
# is the only one of the four store paths that actually derives from
# GLC_CONFIG_DIR. glc/audit/store.py, glc/security/pairing.py, and glc/db.py
# each hardcode their OWN "~/.glc" default and only honor their own specific
# env var (GLC_AUDIT_DB, GLC_PAIRING_DB, GLC_GATEWAY_DB respectively) — none
# of which this file used to set. Only setting GLC_CONFIG_DIR (as the
# original wrapper did) means install_token lands on the Volume correctly,
# but audit.sqlite/pairings.sqlite/gateway.sqlite silently fall back to the
# container's own ephemeral "~/.glc" and are wiped on every cold start —
# verified directly: `modal volume ls glc-data glc` showed only
# `glc/install_token`, never the other three files, despite the deployment
# handling real traffic. All four stores now explicitly point at the Volume.
GLC_DATA_ENV = {
    "GLC_CONFIG_DIR": "/data/glc",
    "GLC_AUDIT_DB": "/data/glc/audit.sqlite",
    "GLC_PAIRING_DB": "/data/glc/pairings.sqlite",
    "GLC_GATEWAY_DB": "/data/glc/gateway.sqlite",
    "GLC_ENV": "production",
}

# The image = a pinned Linux box with Python 3.11, dependencies installed
# by `uv sync --frozen` against this repo's own uv.lock (so the deployed
# image can't drift from what's tested locally), the glc package copied
# in, and every store's path pointed at the Volume mount so all databases
# land on persistent storage instead of the throwaway container filesystem.
image = (
    modal.Image.from_registry(
        "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
    )
    .uv_sync(extra_options="--no-dev")  # --no-dev: skip pytest/ruff/mypy, the lock is honored either way
    .env(GLC_DATA_ENV)
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

# A persistent Volume. The audit db, pairing db, and install token live here and
# survive restarts and redeploys. Without this, every restart wipes them.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Created
# separately with `modal secret create glc-llm-keys ...` (mock values for now).
llm_secret = modal.Secret.from_name("glc-llm-keys")


# ---------------------------------------------------------------------------
# Move B/C: per-adapter container + scoped Secret — every adapter
# ---------------------------------------------------------------------------
# L1-L5/L7/L8/L10 all exist because every adapter and every route share one
# Python process with the core gateway's LLM provider keys — Python has no
# in-process ACL on os.environ or on importable functions, so no amount of
# code-level permission checking closes this. The only real wall is a
# process/container boundary the kernel enforces (namespaces + cgroups).
#
# An earlier version of this file migrated only telegram, on the belief
# (inherited from the lecture's own framing, never independently checked)
# that the other 14 catalogue adapters were still NotImplementedError
# stubs not worth containerizing yet. That belief was wrong: every adapter
# under glc/channels/catalogue/ has a real, non-stub on_message/send
# implementation (confirmed by grepping each adapter.py for
# "raise NotImplementedError" and finding none). Once that was checked,
# there was no remaining reason to leave 14 of them sharing the core
# gateway's LLM provider Secret — so all 15 are migrated here.
#
# The core gateway Function never imports any adapter's code in-process;
# it calls each one's own Function via glc/channels/remote.py instead,
# communicating only through the typed ChannelMessage/ChannelReply
# envelopes that already exist (glc/channels/envelope.py) — the "typed
# contract, no shared memory" boundary docs/ARCHITECTURE.md describes as
# the intended design.
#
# local_mic and webui need no external credential (local audio device /
# local WS respectively) and get secret_name=None — no Secret attached,
# nothing to scope.
#
# This also closes L3/L4 for an adapter-container-level attacker (AR3),
# not just L1/A4: adapter_image() below deliberately does NOT set
# GLC_CONFIG_DIR/GLC_AUDIT_DB/GLC_PAIRING_DB/GLC_GATEWAY_DB, and
# make_adapter_functions() never mounts data_volume. So every module each
# adapter's on_message()/send() imports (glc.security.pairing,
# glc.config, glc.db) falls back to its own local, empty, throwaway
# "~/.glc" inside that adapter's own container — completely disconnected
# from the real pairings.sqlite/install_token/gateway.sqlite the core
# gateway reads and writes on the Volume. force_pair_owner() called from
# inside an adapter's container still runs (Python has no way to block
# the call itself), but it only pollutes that adapter's own throwaway
# file; it can never touch — and has no way to discover — the real
# pairing data the gateway actually trusts. Likewise, install_token_path()
# called from inside an adapter never resolves to the real token. This
# doesn't close L3/L4 for AR4 (code execution inside the gateway process
# itself, which does have the real files) — only for AR3, which is the
# rung Move B/C's container boundary is meant to hold.


def adapter_image(adapter_name: str) -> modal.Image:
    # `adapter_name` is unused today (every adapter shares the same base
    # image) but kept in the signature for per-adapter image tuning later
    # (e.g. an adapter needing extra system packages).
    #
    # Deliberately no .env(GLC_DATA_ENV) here — see the comment above.
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


# Each entry's Secret was created separately with
# `modal secret create glc-<name>-secret <FIELD>=<name>-mock-not-real ...`
# — mock values only, same rule as glc-llm-keys. secret_name=None means
# the adapter needs no external credential at all.
ADAPTER_SECRETS: dict[str, str | None] = {
    "discord": "glc-discord-secret",
    "gmail": "glc-gmail-secret",
    "imap": "glc-imap-secret",
    "line": "glc-line-secret",
    "local_mic": None,
    "matrix": "glc-matrix-secret",
    "signal": "glc-signal-secret",
    "slack": "glc-slack-secret",
    "teams": "glc-teams-secret",
    "telegram": "glc-telegram-secret",
    "twilio_sms": "glc-twilio-sms-secret",
    "twilio_voice": "glc-twilio-voice-secret",
    "webhook": "glc-webhook-secret",
    "webui": None,
    "whatsapp": "glc-whatsapp-secret",
}

for _adapter_name, _secret_name in ADAPTER_SECRETS.items():
    make_adapter_functions(_adapter_name, _secret_name)


# ---------------------------------------------------------------------------
# L1/L3/L4 live verification probe
# ---------------------------------------------------------------------------
# The findings console's local L1/L3/L4 checks run a subprocess on the
# operator's own machine, sharing a process with the code they're testing
# by construction — that can prove the code path exists, but can't observe
# whether a real deployed adapter container is actually isolated the way
# the comment above claims. This closes that gap for real: a Function
# deployed with the exact same image shape as a genuine adapter (built from
# adapter_image(), no Secret, no Volume mount — see make_adapter_functions()
# above) that reports what it can actually observe from inside a live
# container, so the console gets a real measurement instead of a documented
# assumption. It carries no Secret at all, since the whole point is to
# confirm nothing sensitive is reachable here — there's nothing to scope.
@app.function(image=adapter_image("shape-probe"), name="glc-adapter-shape-probe", serialized=True)
def adapter_shape_probe() -> dict:
    import os

    result: dict = {
        "gemini_key_present": bool(os.environ.get("GEMINI_API_KEY", "")),
        "data_mount_exists": os.path.isdir("/data"),
    }

    try:
        from glc.security.pairing import get_pairing_store

        store = get_pairing_store()
        store.force_pair_owner("telegram", "console-shape-probe", user_handle="probe")
        check = store.lookup("telegram", "console-shape-probe")
        result["pairing_write_landed"] = check is not None and check.trust_level == "owner_paired"
    except Exception as e:  # noqa: BLE001 - diagnostic probe, report the failure as data
        result["pairing_error"] = f"{type(e).__name__}: {e}"

    try:
        from glc.config import get_or_create_install_token

        result["install_token_created"] = bool(get_or_create_install_token())
    except Exception as e:  # noqa: BLE001 - diagnostic probe, report the failure as data
        result["install_token_error"] = f"{type(e).__name__}: {e}"

    return result


# ---------------------------------------------------------------------------
# L5 fix: run the policy engine in its own process
# ---------------------------------------------------------------------------
# glc.policy.engine.evaluate is a module-level function; any code sharing a
# process can monkey-patch it directly and silently neuter every future
# policy check. Unlike L3/L4/L8, an in-process integrity check around
# evaluate() doesn't help here — an attacker with equal in-process privilege
# can monkey-patch the check too. Self-checking code cannot certify its own
# integrity against an attacker at the same privilege level; that needs an
# external verifier, i.e. a different process — the exact boundary Move B/C
# already builds for adapters, applied here to the policy engine instead.
#
# This Function gets no Secret and no Volume mount — its only inputs are the
# tool_call/context dicts passed in on each call, and its policy rules come
# from the packaged glc/policy/policy.yaml baked into the image, not the
# shared Volume (mounting the Volume here would let a compromised policy
# container read the real pairing/audit/install-token data, re-opening
# exactly what Move B/C just closed for adapters). A custom policy.yaml
# override via the Volume is a legitimate future enhancement; it isn't
# built here because it would need its own, separately-scoped read path.
policy_image = (
    modal.Image.from_registry(
        "python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3"
    )
    .uv_sync(extra_options="--no-dev")
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)


@app.function(image=policy_image, name="glc-policy-engine", serialized=True)
def evaluate_policy(tool_call: dict, context: dict) -> dict:
    from glc.policy.engine import evaluate

    return evaluate(tool_call, context).model_dump(mode="json")


# ---------------------------------------------------------------------------
# Move D: egress allowlist via Modal Sandboxes, demonstrated on telegram
# ---------------------------------------------------------------------------
# A3/L6: the core gateway Function has no network egress control at all —
# and needs open egress, since it has to reach every LLM provider. But an
# adapter doesn't need arbitrary egress: telegram only ever needs
# api.telegram.org. Restricting that at the container's network boundary
# is the control that would have stopped the attack chain the SSRF finding
# (C1) enables — an SSRF response can't be exfiltrated to an
# attacker-controlled host if the fetching container's egress is
# allowlisted. This is *one* necessary layer, not sufficient alone (data
# can still leave through an *allowed* channel, like the adapter's own
# reply) — not oversold as full closure here or in FINDINGS.md.
#
# modal.Function (used by make_adapter_functions above) only exposes an
# all-or-nothing block_network flag in this Modal version — no domain-level
# allowlist. Only modal.Sandbox exposes outbound_domain_allowlist. Wiring
# every real-time webhook call through a freshly-spawned Sandbox would add
# real per-request latency and complexity that hasn't been justified for
# this assignment's scope; verify_telegram_egress_allowlist() below proves
# the mechanism itself actually enforces the allowlist (documented
# separately from, not silently folded into, the live webhook dispatch
# path in glc/channels/remote.py).
# api.telegram.org's TLS connections are actually served from
# core.telegram.org at the network layer — both need to be listed, or
# the allowlist blocks Telegram's own API alongside everything else.
TELEGRAM_EGRESS_ALLOWLIST = ["api.telegram.org", "core.telegram.org"]


@app.local_entrypoint()
def verify_telegram_egress_allowlist():
    """Run with: uv run modal run modal_app.py::verify_telegram_egress_allowlist

    Spawns a Sandbox scoped to TELEGRAM_EGRESS_ALLOWLIST and proves the
    allowlist is enforced, not just configured: a request to the allowed
    domain succeeds, a request to an arbitrary disallowed domain fails.
    """
    probe_script = (
        "import sys, urllib.request\n"
        "url = sys.argv[1]\n"
        "try:\n"
        "    urllib.request.urlopen(url, timeout=8)\n"
        "    print('REACHED')\n"
        "except Exception as e:\n"
        "    print(f'BLOCKED: {e!r}')\n"
    )
    sb = modal.Sandbox.create(
        app=app,
        image=adapter_image("telegram"),
        outbound_domain_allowlist=TELEGRAM_EGRESS_ALLOWLIST,
        timeout=60,
    )
    try:
        sb.filesystem.write_text(probe_script, "/probe.py")

        allowed_proc = sb.exec("python", "/probe.py", "https://api.telegram.org")
        allowed_out = allowed_proc.stdout.read()
        allowed_proc.wait()

        blocked_proc = sb.exec("python", "/probe.py", "https://example.com")
        blocked_out = blocked_proc.stdout.read()
        blocked_proc.wait()
    finally:
        sb.terminate()

    print(f"allowed domain (api.telegram.org): {allowed_out.strip()}")
    print(f"disallowed domain (example.com):   {blocked_out.strip()}")
    assert "REACHED" in allowed_out, "allowlisted domain should be reachable"
    assert "REACHED" not in blocked_out, "non-allowlisted domain should be blocked"
    print("egress allowlist verified: allowed domain reachable, disallowed domain blocked")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret],
    # Move B/C: every adapter's on_message/send now runs in its own
    # Function (above), so this core Function never imports adapter code
    # in-process and never has any channel credential in its environment
    # — only glc-llm-keys.
    # L5 fix: GLC_POLICY_ENGINE_REMOTE=1 routes any future policy check
    # through the separated glc-policy-engine Function above instead of
    # the in-process glc.policy.engine.evaluate, so monkey-patching the
    # local reference can't neuter the actual decision.
    env={
        "GLC_SEPARATED_ADAPTERS": ",".join(ADAPTER_SECRETS),
        "GLC_POLICY_ENGINE_REMOTE": "1",
    },
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
