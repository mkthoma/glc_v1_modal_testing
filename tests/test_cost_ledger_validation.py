"""L10 — cost-ledger writes must be validated.

Before the fix, log_call() took input_tokens/output_tokens as
unchecked ints with no range or sanity validation and no caller
identity binding — any in-process code could fabricate a call record
attributing arbitrary cost to an arbitrary agent. Full closure needs
Move B (only the trusted core process should be able to call
log_call); this is the Part-1-scoped mitigation: reject wildly
out-of-range values before they ever reach the ledger.
"""

from __future__ import annotations

import pytest

from glc import db


def test_negative_input_tokens_rejected():
    with pytest.raises(ValueError):
        db.log_call(provider="groq", model="x", input_tokens=-1, output_tokens=0)


def test_negative_output_tokens_rejected():
    with pytest.raises(ValueError):
        db.log_call(provider="groq", model="x", input_tokens=0, output_tokens=-1)


def test_absurdly_large_token_count_rejected():
    with pytest.raises(ValueError):
        db.log_call(provider="groq", model="x", input_tokens=10**9, output_tokens=0)


def test_reasonable_token_counts_still_accepted():
    db.log_call(provider="groq", model="x", input_tokens=100, output_tokens=200)
    rows = db.recent(limit=1)
    assert rows[0]["input_tokens"] == 100
    assert rows[0]["output_tokens"] == 200


def test_rejected_call_never_reaches_the_ledger():
    before = len(db.recent(limit=1000))
    with pytest.raises(ValueError):
        db.log_call(provider="groq", model="x", input_tokens=-5, output_tokens=0)
    after = len(db.recent(limit=1000))
    assert after == before
