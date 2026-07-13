"""Move B/C — per-adapter container + scoped credential (telegram).

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
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

from glc.channels import remote as adapter_remote
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.security.pairing import get_pairing_store


def test_is_separated_reads_env_var(monkeypatch):
    monkeypatch.delenv("GLC_SEPARATED_ADAPTERS", raising=False)
    assert adapter_remote.is_separated("telegram") is False

    monkeypatch.setenv("GLC_SEPARATED_ADAPTERS", "telegram,whatsapp")
    assert adapter_remote.is_separated("telegram") is True
    assert adapter_remote.is_separated("whatsapp") is True
    assert adapter_remote.is_separated("webui") is False


def test_separated_channel_webhook_never_touches_in_process_adapter(app_client, monkeypatch):
    """The whole point of Move B: for a separated channel, the process
    holding the LLM provider Secret must never import/instantiate that
    channel's adapter code at all."""
    monkeypatch.setenv("GLC_SEPARATED_ADAPTERS", "telegram")
    get_pairing_store().force_pair_owner("telegram", "owner1")

    # telegram is disabled: true by default in the packaged channels.yaml
    # — enable it in this test's isolated config dir so the message
    # reaches send() instead of being dropped at the allowlist gate.
    from glc.config import CONFIG_DIR

    (CONFIG_DIR / "channels.yaml").write_text("channels:\n  telegram: {enabled: true}\n")

    canned_msg = ChannelMessage(
        channel="telegram",
        channel_user_id="owner1",
        user_handle="owner1",
        text="hi from telegram",
        trust_level="untrusted",
        arrived_at=datetime.now(UTC),
        metadata={},
    )

    remote_on_message = AsyncMock(return_value=canned_msg)
    remote_send = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(adapter_remote, "remote_on_message", remote_on_message)
    monkeypatch.setattr(adapter_remote, "remote_send", remote_send)

    # If the webhook route touched the in-process telegram adapter, this
    # would raise (no mock configured / TELEGRAM_BOT_TOKEN unset) or at
    # least diverge from the canned remote response.
    from glc.routes import channels as channels_route

    called_instantiate = {"n": 0}
    original_instantiate = channels_route.registry.instantiate

    def _spy_instantiate(name, config=None):
        called_instantiate["n"] += 1
        return original_instantiate(name, config)

    monkeypatch.setattr(channels_route.registry, "instantiate", _spy_instantiate)

    r = app_client.post("/v1/channels/telegram/webhook", json={"update_id": 1})
    assert r.status_code == 200
    assert called_instantiate["n"] == 0
    remote_on_message.assert_awaited_once()
    remote_send.assert_awaited_once()

    sent_reply = remote_send.await_args.args[1]
    assert isinstance(sent_reply, ChannelReply)
    assert "hi from telegram" in (sent_reply.text or "")


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
