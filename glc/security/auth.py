"""Bearer-token dependency for the data plane.

Reuses the same per-installation token `glc.routes.control` already
gates `/v1/control/*` with (`glc.config.get_or_create_install_token`)
instead of inventing a second auth mechanism. Comparison is constant-time
(`hmac.compare_digest`) so a network attacker can't recover the token
byte-by-byte via response-timing (CWE-208).
"""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException

from glc.config import get_or_create_install_token


async def require_data_plane_token(authorization: str | None = Header(default=None)) -> None:
    expected = get_or_create_install_token()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token (Authorization: Bearer <install_token>)")
    presented = authorization.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(presented, expected):
        raise HTTPException(403, "token mismatch")
