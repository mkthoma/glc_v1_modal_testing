"""Local-only FastAPI dashboard for the findings console.

Run with:
    uv run python -m tools.findings_console.server

Serves the dashboard on 127.0.0.1:8811. Nothing runs until you click
Run or Run all checks yourself; there is no automatic run-on-startup.

Only your deployed Modal gateway is a valid target for the HTTP/WS
checks — this assignment is about the deployed app, not a local `uv
run glc serve` stand-in, so there is no local-gateway autostart or
"local" target option here. On startup, the console auto-detects your
deployed gateway's URL and install token directly from `modal_app.py`
(app name, ASGI function name, Volume name, config path) and a live
lookup against the Modal SDK — no pasting required, as long as you've
already run `modal deploy modal_app.py` and are logged into the same
Modal account this console runs under. If that lookup fails (app not
deployed yet, no local Modal auth), the target form starts empty with
an explanation, and a **Re-detect from modal_app.py** button is always
available once you have deployed. In-process and static checks never
use the target at all; they always run a local subprocess / read this
local checkout, by design (see the "Check kinds" legend on the
dashboard).

Never deploy this console itself — it has no auth of its own and
isn't meant to be reachable by anyone but you, on your own machine.

Environment variables:
    GLC_MODAL_URL=<url>             pre-fill the target's base_url with your deployed *.modal.run URL
    GLC_MODAL_INSTALL_TOKEN=<token> pre-fill the target's install_token
    FINDINGS_CONSOLE_DB=<path>      override the SQLite log location
    FINDINGS_CONSOLE_FORCE_PORTS=0  don't force-kill a stale console process on 8811
"""

from __future__ import annotations

import os
import platform
import subprocess
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from tools.findings_console import modal_detect, render, runner, store
from tools.findings_console.models import Target
from tools.findings_console.registry import ordered_checks

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


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


def _initial_target() -> Target:
    """Prefer whatever the operator already told us about their deployed
    Modal gateway (env vars set once in the shell, or in .env); otherwise
    start empty and let the target form's own warning prompt for it."""
    base_url = os.getenv("GLC_MODAL_URL", "")
    token = os.getenv("GLC_MODAL_INSTALL_TOKEN") or None
    return Target(name="modal", base_url=base_url, install_token=token)


_state: dict[str, object] = {
    "target": _initial_target(),
    "gateway_note": "",
}


def _current_target() -> Target:
    target = _state["target"]
    assert isinstance(target, Target)
    return target


async def _try_autodetect(*, force: bool = False) -> None:
    """Fill in whichever of base_url/install_token are still missing by
    asking Modal directly (see modal_detect.py) — parses modal_app.py
    for the app/function/Volume names, then looks up the deployed
    Function's web URL and reads the install token out of the Volume.
    Never overwrites a value the operator already set unless `force` is
    passed (the manual "Re-detect" button uses force=True to refresh
    after a redeploy)."""
    current = _current_target()
    need_url = force or not current.base_url
    need_token = force or not current.install_token
    if not need_url and not need_token:
        _state["gateway_note"] = "target already fully configured — nothing to auto-detect"
        return
    url, token, note = await modal_detect.autodetect_target()
    final_url = url if (need_url and url) else current.base_url
    final_token = token if (need_token and token) else current.install_token
    _state["target"] = Target(name=current.name or "modal", base_url=final_url, install_token=final_token)
    _state["gateway_note"] = note


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    await _try_autodetect()
    yield


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


@app.post("/api/target/autodetect")
async def autodetect_target() -> RedirectResponse:
    await _try_autodetect(force=True)
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
    return HTMLResponse(render.check_detail(check, hist, per_target, _current_target()))


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
