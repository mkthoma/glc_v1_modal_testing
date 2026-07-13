"""Move B/C — per-adapter container + scoped credential, every adapter.

L1 (shared process env) and A4 (one Secret for the whole Function)
exist because every adapter shares one Python process with the core
gateway's LLM provider keys — no in-process ACL can stop a channel
adapter's code from reading os.environ["GEMINI_API_KEY"]. For channels
listed in GLC_SEPARATED_ADAPTERS, on_message()/send() dispatch to a
dedicated Modal Function (glc/channels/remote.py) instead of running
in-process; this test proves the gateway's webhook route actually
takes that path and never touches the in-process adapter code for a
separated channel, without needing a live Modal connection (the
remote dispatch functions are monkeypatched).

An earlier version of this test only covered telegram, which is how a
scoping mistake (migrating only telegram in modal_app.py, on the wrong
assumption the other 14 adapters were still stubs) went unnoticed for
a while. Parametrized over two real adapters now so a regression in
the *dispatch logic itself* (as opposed to modal_app.py's static
config) can't hide behind "well, it worked for telegram."
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from glc.channels import remote as adapter_remote
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.pairing import get_pairing_store

ALL_CATALOGUE_ADAPTERS = [
    p.name
    for p in (Path(__file__).parent.parent / "glc" / "channels" / "catalogue").iterdir()
    if p.is_dir() and p.name != "__pycache__"
]


def test_is_separated_reads_env_var(monkeypatch):
    monkeypatch.delenv("GLC_SEPARATED_ADAPTERS", raising=False)
    assert adapter_remote.is_separated("telegram") is False

    monkeypatch.setenv("GLC_SEPARATED_ADAPTERS", "telegram,whatsapp")
    assert adapter_remote.is_separated("telegram") is True
    assert adapter_remote.is_separated("whatsapp") is True
    assert adapter_remote.is_separated("webui") is False


def test_all_15_catalogue_adapters_can_be_marked_separated(monkeypatch):
    """modal_app.py sets GLC_SEPARATED_ADAPTERS to all 15 channel names —
    is_separated() must recognize every one of them, not just telegram."""
    monkeypatch.setenv("GLC_SEPARATED_ADAPTERS", ",".join(ALL_CATALOGUE_ADAPTERS))
    for name in ALL_CATALOGUE_ADAPTERS:
        assert adapter_remote.is_separated(name) is True


@pytest.mark.parametrize("channel", ["telegram", "whatsapp"])
def test_separated_channel_webhook_never_touches_in_process_adapter(app_client, monkeypatch, channel):
    """The whole point of Move B: for a separated channel, the process
    holding the LLM provider Secret must never import/instantiate that
    channel's adapter code at all."""
    monkeypatch.setenv("GLC_SEPARATED_ADAPTERS", channel)
    get_pairing_store().force_pair_owner(channel, "owner1")

    # telegram is disabled: true by default in the packaged channels.yaml;
    # whatsapp is enabled by default. Force-enable whichever one is under
    # test in this test's isolated config dir, so the message reaches
    # send() instead of being dropped at the allowlist gate.
    from glc.config import CONFIG_DIR

    (CONFIG_DIR / "channels.yaml").write_text(f"channels:\n  {channel}: {{enabled: true}}\n")

    canned_msg = ChannelMessage(
        channel=channel,
        channel_user_id="owner1",
        user_handle="owner1",
        text=f"hi from {channel}",
        trust_level="untrusted",
        arrived_at=datetime.now(UTC),
        metadata={},
    )

    remote_on_message = AsyncMock(return_value=canned_msg)
    remote_send = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(adapter_remote, "remote_on_message", remote_on_message)
    monkeypatch.setattr(adapter_remote, "remote_send", remote_send)

    # If the webhook route touched the in-process adapter, this would
    # raise (no mock configured / real credential unset) or at least
    # diverge from the canned remote response.
    from glc.routes import channels as channels_route

    called_instantiate = {"n": 0}
    original_instantiate = channels_route.registry.instantiate

    def _spy_instantiate(name, config=None):
        called_instantiate["n"] += 1
        return original_instantiate(name, config)

    monkeypatch.setattr(channels_route.registry, "instantiate", _spy_instantiate)

    r = app_client.post(f"/v1/channels/{channel}/webhook", json={"update_id": 1})
    assert r.status_code == 200
    assert called_instantiate["n"] == 0
    remote_on_message.assert_awaited_once()
    remote_send.assert_awaited_once()

    sent_reply = remote_send.await_args.args[1]
    assert isinstance(sent_reply, ChannelReply)
    assert f"hi from {channel}" in (sent_reply.text or "")


def test_non_separated_channel_still_uses_in_process_adapter(app_client, monkeypatch):
    """Default behavior (no GLC_SEPARATED_ADAPTERS) must be unchanged —
    local dev never sets this env var."""
    monkeypatch.delenv("GLC_SEPARATED_ADAPTERS", raising=False)
    # webhook channel is enabled in the packaged channels.yaml and has a
    # real (non-stub) adapter with its own HMAC verification, so an
    # unsigned POST is rejected by the adapter itself — proving we're on
    # the in-process path, not the remote one (which we haven't mocked).
    r = app_client.post("/v1/channels/webhook/webhook", json={"x": 1})
    assert r.status_code == 200
