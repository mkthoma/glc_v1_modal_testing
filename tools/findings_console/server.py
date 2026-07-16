"""Local-only FastAPI dashboard for the findings console.

Run with:
    uv run python -m tools.findings_console.server

Serves the dashboard on 127.0.0.1:8811. Nothing runs until you click
Run or Run all checks yourself; there is no automatic run-on-startup.

Tracks exactly two fixed, named Modal targets, both auto-detected —
never a local `uv run glc serve` stand-in, since this assignment is
about the deployed app:

  - "before"  — without_fixes/modal_app.py, the pre-hardening baseline
  - "after"   — with_fixes/modal_app.py, the hardened gateway

On startup, the console auto-detects each target's URL and install
token directly from its own modal_app.py (app name, ASGI function
name, Volume name, config path) and a live lookup against the Modal
SDK — no pasting required, as long as you've deployed both
(`modal deploy without_fixes/modal_app.py` and
`modal deploy with_fixes/modal_app.py`) and are logged into the same
Modal account this console runs under. If a lookup fails (that app
isn't deployed yet, no local Modal auth), that target's form starts
empty with an explanation, and its own **Re-detect** button is always
available once you have deployed. In-process and static checks never
use `target.base_url` for their HTTP calls, but they DO pick which
local checkout / which glc package to read or import based on which
target ("before" vs "after") they're running for — see the "Check
kinds" legend on the dashboard.

Never deploy this console itself — it has no auth of its own and
isn't meant to be reachable by anyone but you, on your own machine.

Environment variables:
    GLC_MODAL_URL=<url>                      pre-fill the "after" target's base_url
    GLC_MODAL_INSTALL_TOKEN=<token>           pre-fill the "after" target's install_token
    GLC_MODAL_BASELINE_URL=<url>              pre-fill the "before" target's base_url
    GLC_MODAL_BASELINE_INSTALL_TOKEN=<token>  pre-fill the "before" target's install_token
    FINDINGS_CONSOLE_DB=<path>                override the SQLite log location
    FINDINGS_CONSOLE_FORCE_PORTS=0            don't force-kill a stale console process on 8811
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


def _initial_after_target() -> Target:
    """Prefer whatever the operator already told us about the hardened
    deployment (env vars set once in the shell, or in .env); otherwise
    start empty and let the target form's own warning prompt for it."""
    base_url = os.getenv("GLC_MODAL_URL", "")
    token = os.getenv("GLC_MODAL_INSTALL_TOKEN") or None
    return Target(name="after", base_url=base_url, install_token=token)


def _initial_before_target() -> Target:
    base_url = os.getenv("GLC_MODAL_BASELINE_URL", "")
    token = os.getenv("GLC_MODAL_BASELINE_INSTALL_TOKEN") or None
    return Target(name="before", base_url=base_url, install_token=token)


_state: dict[str, object] = {
    "after_target": _initial_after_target(),
    "before_target": _initial_before_target(),
    "after_note": "",
    "before_note": "",
}


def _after_target() -> Target:
    target = _state["after_target"]
    assert isinstance(target, Target)
    return target


def _before_target() -> Target:
    target = _state["before_target"]
    assert isinstance(target, Target)
    return target


# Back-compat alias — most of the console (single-check runs, export,
# the generic per-target history view) still means "the hardened
# deployment" whenever it says "the current target."
_current_target = _after_target


async def _try_autodetect_after(*, force: bool = False) -> None:
    """Fill in whichever of base_url/install_token are still missing for
    the "after" (hardened) target by asking Modal directly (see
    modal_detect.py) — parses with_fixes/modal_app.py for the
    app/function/Volume names, then looks up the deployed Function's web
    URL and reads the install token out of the Volume. Never overwrites
    a value the operator already set unless `force` is passed (the
    manual "Re-detect" button uses force=True to refresh after a
    redeploy)."""
    current = _after_target()
    need_url = force or not current.base_url
    need_token = force or not current.install_token
    if not need_url and not need_token:
        _state["after_note"] = "target already fully configured — nothing to auto-detect"
        return
    url, token, note = await modal_detect.autodetect_target(modal_detect.WITH_FIXES_MODAL_APP)
    final_url = url if (need_url and url) else current.base_url
    final_token = token if (need_token and token) else current.install_token
    _state["after_target"] = Target(name="after", base_url=final_url, install_token=final_token)
    _state["after_note"] = note


async def _try_autodetect_before(*, force: bool = False) -> None:
    """Same as _try_autodetect_after, but for the "before" (baseline)
    target — reads without_fixes/modal_app.py instead."""
    current = _before_target()
    need_url = force or not current.base_url
    need_token = force or not current.install_token
    if not need_url and not need_token:
        _state["before_note"] = "target already fully configured — nothing to auto-detect"
        return
    url, token, note = await modal_detect.autodetect_target(modal_detect.WITHOUT_FIXES_MODAL_APP)
    final_url = url if (need_url and url) else current.base_url
    final_token = token if (need_token and token) else current.install_token
    _state["before_target"] = Target(name="before", base_url=final_url, install_token=final_token)
    _state["before_note"] = note


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    await _try_autodetect_after()
    await _try_autodetect_before()
    yield


app = FastAPI(title="GLC v2 Findings Console", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    checks = ordered_checks()
    before_latest = {c.id: r for c in checks if (r := store.latest_for_target(c.id, "before")) is not None}
    after_latest = {c.id: r for c in checks if (r := store.latest_for_target(c.id, "after")) is not None}
    return render.dashboard(
        checks,
        before_latest,
        after_latest,
        _before_target(),
        _after_target(),
        before_note=str(_state["before_note"]),
        after_note=str(_state["after_note"]),
    )


@app.post("/api/target/after")
async def set_after_target(base_url: str = Form(...), install_token: str = Form("")) -> RedirectResponse:
    _state["after_target"] = Target(
        name="after", base_url=base_url.rstrip("/"), install_token=install_token.strip() or None
    )
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/target/before")
async def set_before_target(base_url: str = Form(...), install_token: str = Form("")) -> RedirectResponse:
    _state["before_target"] = Target(
        name="before", base_url=base_url.rstrip("/"), install_token=install_token.strip() or None
    )
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/target/after/autodetect")
async def autodetect_after_target() -> RedirectResponse:
    await _try_autodetect_after(force=True)
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/target/before/autodetect")
async def autodetect_before_target() -> RedirectResponse:
    await _try_autodetect_before(force=True)
    return RedirectResponse(url="/", status_code=303)


@app.get("/check/{check_id}", response_class=HTMLResponse)
async def check_detail(check_id: str) -> HTMLResponse:
    checks = {c.id: c for c in ordered_checks()}
    check = checks.get(check_id)
    if check is None:
        return HTMLResponse(f"unknown check id {check_id!r}", status_code=404)
    hist = store.history(check_id)
    before_run = store.latest_for_target(check_id, "before")
    after_run = store.latest_for_target(check_id, "after")
    return HTMLResponse(render.check_detail(check, hist, _after_target(), before_run, after_run))


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
        await run_in_threadpool(runner.run_check, check, _after_target())
    return RedirectResponse(url=f"/check/{check_id}", status_code=303)


@app.post("/api/run_before/{check_id}")
async def run_one_before(check_id: str) -> RedirectResponse:
    checks = {c.id: c for c in ordered_checks()}
    check = checks.get(check_id)
    if check is not None:
        await run_in_threadpool(runner.run_check, check, _before_target())
    return RedirectResponse(url=f"/check/{check_id}", status_code=303)


@app.post("/api/run_all")
async def run_all() -> RedirectResponse:
    checks = ordered_checks()
    target = _after_target()
    for c in checks:
        await run_in_threadpool(runner.run_check, c, target)
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/run_all_before")
async def run_all_before() -> RedirectResponse:
    checks = ordered_checks()
    target = _before_target()
    for c in checks:
        await run_in_threadpool(runner.run_check, c, target)
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/run_all_both")
async def run_all_both() -> RedirectResponse:
    checks = ordered_checks()
    before, after = _before_target(), _after_target()
    for c in checks:
        await run_in_threadpool(runner.run_check, c, before)
        await run_in_threadpool(runner.run_check, c, after)
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
