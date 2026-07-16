"""Move B/C — optional out-of-process adapter dispatch.

L1 (shared process env) and A4 (one Secret for the whole Function)
exist because every adapter and every route shares one Python process
— any code running in it can read `os.environ["GEMINI_API_KEY"]`, and
Python has no in-process ACL to stop it. The only real fix is a
process/container boundary the kernel enforces, not a code-level
permission check.

For channels listed in GLC_SEPARATED_ADAPTERS, on_message()/send() run
inside a dedicated Modal Function instead — its own container, with
only that channel's own credential in its Secret, never the LLM
provider keys. The core gateway process communicates with it only
through the typed ChannelMessage/ChannelReply envelopes (channels/envelope.py),
matching the "typed contract, no shared memory" boundary
docs/ARCHITECTURE.md describes as the intended design.

Local dev (`uv run glc serve`) never sets GLC_SEPARATED_ADAPTERS, so
the default path is unchanged: adapters run in-process exactly as
before. This module only touches Modal's client when a channel is
actually configured as separated — importing it is always safe, even
without Modal installed reachably, as long as no channel is listed.
"""

from __future__ import annotations

import os
from typing import Any

from glc.channels.envelope import ChannelMessage, ChannelReply

MODAL_APP_NAME = "glc-v1-gateway"


def _separated_channels() -> set[str]:
    return {c.strip() for c in os.getenv("GLC_SEPARATED_ADAPTERS", "").split(",") if c.strip()}


def is_separated(channel: str) -> bool:
    return channel in _separated_channels()


async def remote_on_message(channel: str, raw: Any) -> ChannelMessage | None:
    import modal

    fn = modal.Function.from_name(MODAL_APP_NAME, f"glc-adapter-{channel}")
    result = await fn.remote.aio(raw)
    return ChannelMessage.model_validate(result) if result is not None else None


async def remote_send(channel: str, reply: ChannelReply) -> Any:
    import modal

    fn = modal.Function.from_name(MODAL_APP_NAME, f"glc-adapter-{channel}-send")
    return await fn.remote.aio(reply.model_dump(mode="json"))
