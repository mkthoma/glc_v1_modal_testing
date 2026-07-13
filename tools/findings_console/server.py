"""Local-only FastAPI dashboard for the findings console.

Run with:
    uv run python -m tools.findings_console.server

Detects (or spawns) a gateway on 127.0.0.1:8111 and resolves its
install token so the target form opens pre-filled — then serves the
dashboard on 127.0.0.1:8811. Nothing runs until you click Run or Run
all checks yourself; there is no automatic run-on-startup.

Serves on 127.0.0.1:8811 by default (distinct from glc's own 8111) so
it never collides with a locally running gateway. Never deploy this —
it has no auth of its own and isn't meant to be reachable by anyone
but you, on your own machine.

Environment variables:
    FINDINGS_CONSOLE_AUTOSTART_GATEWAY=0   don't detect/spawn a gateway at all
    FINDINGS_CONSOLE_DB=<path>             override the SQLite log location
    FINDINGS_CONSOLE_FORCE_PORTS=0         don't force-kill stale processes on 8111/8811
"""

from __future__ import annotations

import asyncio
import os
import platform
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from tools.findings_console import render, runner, store
from tools.findings_console.models import Target
from tools.findings_console.registry import ordered_checks

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
GATEWAY_URL = "http://127.0.0.1:8111"
SCRATCH_GLC_DIR = REPO_ROOT / ".findings_console" / "glc-scratch"


def _pids_listening_on(port: int) -> list[int]:
    """Best-effort discovery of PIDs with a LISTENING socket on `port`.

    Shells out to netstat (Windows) or lsof (macOS/Linux) — there's no
    portable stdlib way to do this without adding a psutil dependency.
    Any failure here just means "found nothing"; never raises.
    """
    try:
        if platform.system() == "Windows":
            out = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True, timeout=5, check=False
            ).stdout
            pids: set[int] = set()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "TCP" and parts[3] == "LISTENING":
                    if parts[1].rsplit(":", 1)[-1] == str(port) and parts[-1].isdigit():
                        pids.add(int(parts[-1]))
            return sorted(pids)
        else:
            out = subprocess.run(
                ["lsof", "-ti", f":{port}"], capture_output=True, text=True, timeout=5, check=False
            ).stdout
            return sorted({int(p) for p in out.split() if p.strip().isdigit()})
    except (OSError, subprocess.SubprocessError):
        return []


def _free_port(port: int) -> list[int]:
    """Force-kill any process currently listening on `port` (except us).

    Used so a prior session's console or scratch gateway that wasn't
    stopped with Ctrl+C (leaving 8111/8811 bound to a dead-but-lingering
    process) doesn't block this run with a bind error. Opt out with
    FINDINGS_CONSOLE_FORCE_PORTS=0.
    """
    if os.getenv("FINDINGS_CONSOLE_FORCE_PORTS", "1") == "0":
        return []
    my_pid = os.getpid()
    killed: list[int] = []
    for pid in _pids_listening_on(port):
        if pid == my_pid:
            continue
        try:
            if platform.system() == "Windows":
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=5, check=False
                )
            else:
                import signal

                os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except (OSError, subprocess.SubprocessError):
            pass
    if killed:
        print(f"[findings-console] freed port {port} — killed stale process(es): {killed}")
        time.sleep(0.5)  # give the OS a moment to release the socket
    return killed

_state: dict[str, object] = {
    "target": Target(name="local", base_url=GATEWAY_URL, install_token=None),
    "gateway_note": "",
}
_owned_gateway_proc: subprocess.Popen | None = None


def _current_target() -> Target:
    target = _state["target"]
    assert isinstance(target, Target)
    return target


async def _gateway_healthy(client: httpx.AsyncClient) -> bool:
    try:
        r = await client.get(f"{GATEWAY_URL}/healthz", timeout=2)
        return r.status_code == 200
    except httpx.HTTPError:
        return False


async def _wait_for_gateway(client: httpx.AsyncClient, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if await _gateway_healthy(client):
            return True
        await asyncio.sleep(1)
    return False


def _resolve_token(config_dir: Path) -> str | None:
    p = config_dir / "install_token"
    if p.exists():
        return p.read_text().strip() or None
    return None


async def _ensure_gateway_and_token() -> None:
    """Detect an already-running gateway and reuse it, or spawn a
    disposable scratch instance. Either way, populate _state['target']
    with a working install_token so the dashboard opens ready to go."""
    global _owned_gateway_proc

    if os.getenv("FINDINGS_CONSOLE_AUTOSTART_GATEWAY", "1") == "0":
        _state["gateway_note"] = (
            "auto-start disabled (FINDINGS_CONSOLE_AUTOSTART_GATEWAY=0) — set a target yourself"
        )
        return

    async with httpx.AsyncClient() as client:
        if await _gateway_healthy(client):
            # Something is already listening on 8111 — almost certainly a
            # `uv run glc serve` the operator started themselves, testing
            # their own fixes. Reuse it; don't spawn a second one, and
            # don't touch its state beyond reading its token.
            config_dir = Path(os.getenv("GLC_CONFIG_DIR", os.path.expanduser("~/.glc")))
            token = _resolve_token(config_dir)
            _state["gateway_note"] = (
                f"found an existing gateway already running at {GATEWAY_URL} — reusing it"
                + (
                    ""
                    if token
                    else f" (no install_token found at {config_dir}/install_token — set one manually)"
                )
            )
        else:
            print(f"[findings-console] no gateway at {GATEWAY_URL} — starting a scratch instance...")
            _free_port(8111)  # clear out any stale, unresponsive process squatting the port
            SCRATCH_GLC_DIR.mkdir(parents=True, exist_ok=True)
            env = dict(os.environ)
            env["GLC_CONFIG_DIR"] = str(SCRATCH_GLC_DIR)
            env.setdefault("GEMINI_API_KEY", "mock-not-real")
            _owned_gateway_proc = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import uvicorn; uvicorn.run('glc.main:app', host='127.0.0.1', port=8111)",
                ],
                cwd=str(REPO_ROOT),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            healthy = await _wait_for_gateway(client, timeout_s=30)
            if not healthy:
                _state["gateway_note"] = (
                    "tried to start a scratch gateway but it never became healthy — check the console's own stdout"
                )
                return
            token = _resolve_token(SCRATCH_GLC_DIR)
            _state["gateway_note"] = f"started a disposable scratch gateway at {GATEWAY_URL}"

    _state["target"] = Target(name="local", base_url=GATEWAY_URL, install_token=token)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    await _ensure_gateway_and_token()
    yield
    if _owned_gateway_proc is not None:
        _owned_gateway_proc.terminate()


app = FastAPI(title="GLC v2 Findings Console", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    checks = ordered_checks()
    latest = store.latest_per_check()
    return render.dashboard(
        checks,
        latest,
        _current_target(),
        gateway_note=str(_state["gateway_note"]),
    )


@app.post("/api/target")
async def set_target(
    name: str = Form(...),
    base_url: str = Form(...),
    install_token: str = Form(""),
) -> RedirectResponse:
    _state["target"] = Target(
        name=name.strip() or "target",
        base_url=base_url.rstrip("/"),
        install_token=install_token.strip() or None,
    )
    return RedirectResponse(url="/", status_code=303)


@app.get("/check/{check_id}", response_class=HTMLResponse)
async def check_detail(check_id: str) -> HTMLResponse:
    checks = {c.id: c for c in ordered_checks()}
    check = checks.get(check_id)
    if check is None:
        return HTMLResponse(f"unknown check id {check_id!r}", status_code=404)
    hist = store.history(check_id)
    per_target = [
        (
            name,
            store.baseline_for_target(check_id, name),
            store.latest_for_target(check_id, name),
            store.get_pin(check_id, name),
        )
        for name in store.targets_for_check(check_id)
    ]
    return HTMLResponse(render.check_detail(check, hist, per_target))


@app.post("/api/pin/{check_id}")
async def pin_run(
    check_id: str,
    target_name: str = Form(...),
    run_id: int = Form(...),
) -> RedirectResponse:
    store.set_pin(check_id, target_name, run_id)
    return RedirectResponse(url=f"/check/{check_id}", status_code=303)


@app.post("/api/unpin/{check_id}")
async def unpin_run(
    check_id: str,
    target_name: str = Form(...),
) -> RedirectResponse:
    store.clear_pin(check_id, target_name)
    return RedirectResponse(url=f"/check/{check_id}", status_code=303)


@app.post("/api/clear")
async def clear_all_history() -> RedirectResponse:
    store.clear_all()
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/clear/{check_id}")
async def clear_check_history(check_id: str) -> RedirectResponse:
    store.clear_for_check(check_id)
    return RedirectResponse(url=f"/check/{check_id}", status_code=303)


@app.post("/api/run/{check_id}")
async def run_one(check_id: str) -> RedirectResponse:
    checks = {c.id: c for c in ordered_checks()}
    check = checks.get(check_id)
    if check is not None:
        await run_in_threadpool(runner.run_check, check, _current_target())
    return RedirectResponse(url=f"/check/{check_id}", status_code=303)


@app.post("/api/run_all")
async def run_all() -> RedirectResponse:
    checks = ordered_checks()
    target = _current_target()
    for c in checks:
        await run_in_threadpool(runner.run_check, c, target)
    return RedirectResponse(url="/", status_code=303)


@app.get("/api/export.md", response_class=PlainTextResponse)
async def export_markdown() -> str:
    return store.export_markdown()


def main() -> None:
    import uvicorn

    store.init_db()
    _free_port(8811)  # clear out any stale console instance left over from a prior session
    uvicorn.run(app, host="127.0.0.1", port=8811)


if __name__ == "__main__":
    main()
