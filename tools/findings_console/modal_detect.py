"""Auto-detect a deployed Modal gateway's URL and install token.

The console used to require pasting a `*.modal.run` URL and an install
token into the target form by hand. Both are actually derivable: the
app name, the ASGI function name, the Volume name, and the config path
are all literal strings in a modal_app.py, and the Modal SDK can look
up a deployed Function's web URL and read a file out of a Volume
directly - no `modal` CLI subprocess, no copy-pasting.

Every function here takes an explicit `modal_app_path` because this
console now tracks *two* deployments side by side - the "before"
baseline (without_fixes/modal_app.py) and the "after" hardened gateway
(with_fixes/modal_app.py) - and each has to be resolved independently,
never assumed to be "the" modal_app.py.

This only ever *reads* already-deployed state (a Function's metadata,
a file from a Volume) - it never deploys, modifies, or creates
anything.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WITH_FIXES_MODAL_APP = REPO_ROOT / "with_fixes" / "modal_app.py"
WITHOUT_FIXES_MODAL_APP = REPO_ROOT / "without_fixes" / "modal_app.py"


def _read_modal_app_source(modal_app_path: Path) -> str | None:
    try:
        return modal_app_path.read_text(encoding="utf-8")
    except OSError:
        return None


def detect_app_and_function(modal_app_path: Path = WITH_FIXES_MODAL_APP) -> tuple[str, str] | None:
    """Parse a modal_app.py for the App name and the name of the function
    serving the ASGI app (the one decorated with @modal.asgi_app()).
    Returns None if either can't be found - the file may not exist yet
    (not deployed) or have been restructured since this was written."""
    src = _read_modal_app_source(modal_app_path)
    if src is None:
        return None
    app_match = re.search(r"""modal\.App\(\s*["']([^"']+)["']""", src)
    fn_match = re.search(r"@modal\.asgi_app\(\)\s*\n\s*(?:async\s+)?def\s+(\w+)\s*\(", src)
    if not app_match or not fn_match:
        return None
    return app_match.group(1), fn_match.group(1)


def detect_volume_and_token_path(modal_app_path: Path = WITH_FIXES_MODAL_APP) -> tuple[str, str] | None:
    """Parse a modal_app.py for the Volume name and derive the install
    token's path relative to that Volume's root, from whatever mount
    point and GLC_CONFIG_DIR are actually configured - not hardcoded,
    since either could change if the file is edited."""
    src = _read_modal_app_source(modal_app_path)
    if src is None:
        return None
    vol_match = re.search(r"""modal\.Volume\.from_name\(\s*["']([^"']+)["']""", src)
    mount_match = re.search(r"""volumes\s*=\s*\{\s*["']([^"']+)["']""", src)
    config_dir_match = re.search(r"""["']GLC_CONFIG_DIR["']\s*:\s*["']([^"']+)["']""", src)
    if not vol_match or not mount_match or not config_dir_match:
        return None
    volume_name = vol_match.group(1)
    mount_point = mount_match.group(1).rstrip("/")
    config_dir = config_dir_match.group(1)
    if not config_dir.startswith(mount_point + "/"):
        return None
    relative_config_dir = config_dir[len(mount_point) + 1 :]
    token_path = f"{relative_config_dir}/install_token" if relative_config_dir else "install_token"
    return volume_name, token_path


async def fetch_deployed_url(app_name: str, function_name: str) -> tuple[str | None, str]:
    """Look up the web URL of an already-deployed Function. Returns
    (url, "") on success or (None, "<reason>") on any failure - a
    not-yet-deployed app, no local Modal auth, the modal package
    missing, or a transient API error all land here rather than
    raising, since this runs at console startup and a failure here
    just means "fall back to the manual form," not a crash."""
    try:
        import modal
    except ImportError:
        return None, "the modal package isn't installed in this environment"
    try:
        fn = modal.Function.from_name(app_name, function_name)
        url = await fn.get_web_url.aio()
    except Exception as e:  # noqa: BLE001 - deliberately broad, see docstring
        return None, f"{type(e).__name__}: {e}"
    if not url:
        return None, f"Function {app_name}/{function_name} exists but has no web URL (not an ASGI app?)"
    return url, ""


async def fetch_install_token(volume_name: str, token_path: str) -> tuple[str | None, str]:
    """Read the install token directly out of the deployed Volume.
    Same failure contract as fetch_deployed_url: never raises, always
    returns a (value, reason) pair."""
    try:
        import modal
    except ImportError:
        return None, "the modal package isn't installed in this environment"
    try:
        vol = modal.Volume.from_name(volume_name)
        chunks = [chunk async for chunk in vol.read_file.aio(token_path)]
    except Exception as e:  # noqa: BLE001 - deliberately broad, see docstring
        return None, f"{type(e).__name__}: {e}"
    token = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not token:
        return None, f"{token_path!r} on Volume {volume_name!r} was empty"
    return token, ""


async def autodetect_target(
    modal_app_path: Path = WITH_FIXES_MODAL_APP,
) -> tuple[str | None, str | None, str]:
    """Best-effort end-to-end autodetect against a specific modal_app.py:
    (base_url, install_token, note). Either value can be None if that
    piece couldn't be determined; note explains what happened, for
    display in the dashboard's status panel."""
    app_and_fn = detect_app_and_function(modal_app_path)
    if app_and_fn is None:
        return (
            None,
            None,
            f"couldn't find `modal.App(...)` and an @modal.asgi_app() function in {modal_app_path}",
        )
    app_name, function_name = app_and_fn

    url, url_reason = await fetch_deployed_url(app_name, function_name)

    token = None
    token_reason = ""
    vol_and_path = detect_volume_and_token_path(modal_app_path)
    if vol_and_path is not None:
        volume_name, token_path = vol_and_path
        token, token_reason = await fetch_install_token(volume_name, token_path)

    if url and token:
        return url, token, f"auto-detected from {modal_app_path.name}: {app_name}/{function_name}"
    if url:
        reason = token_reason or f"no Volume/token path found in {modal_app_path}"
        return (
            url,
            None,
            f"auto-detected the URL, but not the install token ({reason}) - paste it in yourself",
        )
    return (
        None,
        None,
        f"couldn't reach the deployed app ({url_reason}) - deploy it or set the target yourself",
    )
