# FINDINGS — Part 1 hardening

This is the required note: for each finding, the invariant it broke and the fix that closed or mitigated it. Findings are grouped the same way the local testing dashboard (`tools/findings_console/`) groups them — by what the Modal migration did to each one. Every fix below has its own commit; commit subjects are quoted so you can `git show <subject>` for the exact diff.

Two things worth being upfront about, since they shape how "closed" is used below:

- Only **C2/L9** (cross-channel envelope spoofing) is closable with a pure application-layer code change. **L1–L5, L7, L8, L10 fundamentally require process/container separation to be fully closed** — Python has no in-process ACL on `os.environ` or on importable functions, so the only real wall is a kernel-enforced process boundary. Of these, **L1, L2, L7, L10 got a real Part-1-scope mitigation** (per-adapter separation for telegram, hash-chaining, an absolute binary path, input validation, respectively); **L3, L4, L5, L8 got none** — no code-level fix closes them at all without Move B, and they're marked **open**, not mitigated, below. Don't take "mitigated" to mean every leak in this range has a corresponding fix; check each entry's own Status line.
- **A4 and L1 are the same underlying gap** (one shared Secret), described at the deployment-config level and the code-consequence level. **C2 and L9 are the literal same bug**, named twice.

## Section A — Introduced or elevated by the Modal migration

### A1 — Public data plane, no auth

**Location:** `glc/routes/chat.py` (`/v1/chat`, `/chat/batch`, `/vision`, `/embed`), `glc/routes/transcribe.py`, `glc/routes/speak.py`
**Invariant broken:** INV-2 (every action must be checked against the actual user)
**Attacker role reached:** AR1
**Status:** fully closed

**Before:** none of the six data-plane routes had an auth dependency — an anonymous internet caller could drive LLM spend and abuse the pipeline with zero credentials.
**Fix:** `glc/security/auth.py`'s `require_data_plane_token` (constant-time `hmac.compare_digest` from the start), wired via `dependencies=[Depends(...)]` on all six routes. Commit: `harden: require bearer-token auth on the data plane (A1)`.
**Re-verified:** `curl -X POST <url>/v1/chat -d '{"prompt":"hi"}'` now returns `401` instead of reaching provider dispatch — confirmed against the live Modal deployment.

### A2 — Unauthenticated info disclosure

**Location:** `glc/routes/chat.py` (`/cost/by_agent`, `/providers`, `/capabilities`, `/status`, `/routers`, `/embedders`, `/calls`); `glc/main.py` (`/docs`, `/openapi.json`, `/redoc`)
**Invariant broken:** INV-2
**Attacker role reached:** AR1
**Status:** fully closed

**Before:** all seven read endpoints were open with no auth — free reconnaissance of provider order, rate limits, and usage. `/docs`/`/openapi.json` were FastAPI defaults, never disabled.
**Fix:** same `require_data_plane_token` dependency applied to all seven endpoints; `main.py` sets `docs_url`/`redoc_url`/`openapi_url` to `None` when `GLC_ENV=production` (set in the Modal image). Commits: `harden: gate info-disclosure endpoints, disable docs in prod (A2)`, `harden: set GLC_ENV=production in the Modal image (A2 follow-up)`.
**Re-verified:** live deployment — `/v1/status` returns `401` unauthenticated; `/docs` returns `404`.

### A3 — Single Function, no egress wall

**Location:** `modal_app.py`
**Invariant broken:** INV-2/INV-3
**Attacker role reached:** AR1/AR3
**Status:** mitigated (full closure requires every adapter migrated)

**Before:** one `@app.function`, no `modal.Sandbox`, no egress control at all.
**Fix:** the telegram adapter now runs in its own Function (Move B/C) and its egress is demonstrably allowlist-able via `modal.Sandbox` (Move D). Commits: `harden: per-adapter container + scoped Secret, telegram (Move B/C)`, `harden: egress allowlist via Modal Sandbox, telegram (Move D)`.
**Re-verified:** `uv run modal run modal_app.py::verify_telegram_egress_allowlist` — a request to `api.telegram.org` succeeds, a request to `example.com` is blocked. Not wired into the live per-request webhook dispatch path (see Move D note below) and not yet applied to any adapter besides telegram — the core gateway Function itself still has open egress, which it needs to reach LLM providers.

### A4 — One Secret for the whole Function

**Location:** `modal_app.py`
**Invariant broken:** INV-1
**Attacker role reached:** AR3
**Status:** mitigated for telegram, open for the other 12 adapters

**Before:** `llm_secret` mounted to the entire `fastapi_app` Function — every route and every adapter could read every provider key.
**Fix:** same as A3/L1 — `make_adapter_functions("telegram", "glc-telegram-secret")` gives telegram its own Secret containing only `TELEGRAM_BOT_TOKEN`, never `glc-llm-keys`. Commit: `harden: per-adapter container + scoped Secret, telegram (Move B/C)`.
**Re-verified:** a throwaway probe Function sharing the exact telegram image + Secret configuration read its own `os.environ` live on Modal: `TELEGRAM_BOT_TOKEN` present, all six LLM provider keys (`GEMINI_API_KEY`, `GITHUB_ACCESS_TOKEN`, `GROQ_API_KEY`, `NVIDIA_API_KEY`, `CEREBRAS_API_KEY`, `OPEN_ROUTER_API_KEY`) absent.

### A5 — Non-reproducible image

**Location:** `modal_app.py`
**Invariant broken:** supply chain
**Attacker role reached:** AR4 (arbitrary code execution via a poisoned dependency or shifted base image)
**Status:** fully closed

**Before:** `pip_install([...])` hand-duplicated from `pyproject.toml`, ignoring `uv.lock`; base image `debian_slim(python_version="3.11")` unpinned.
**Fix:** `modal.Image.from_registry("python:3.11-slim@sha256:e031123e...")` (digest resolved via the Docker Hub registry API) piped into `.uv_sync(extra_options="--no-dev")`, which runs `uv sync --frozen` against this repo's own lock file. Commit: `harden: reproducible image build from uv.lock, pin base digest (A5)`.
**Re-verified:** redeployed to the live account — image builds clean from the pinned digest + `uv sync`, `/healthz` still returns `{"ok": true}`.

### A6 — Audit volume assumes one writer

**Location:** `modal_app.py`; `glc/audit/store.py`
**Invariant broken:** INV-7
**Attacker role reached:** not directly attacker-triggered — corruption risk grows with concurrent load, which any high-volume caller (AR1) can induce
**Status:** mitigated (full closure needs a dedicated writer process or managed DB — Move B/C territory)

**Before:** `min_containers=0`, no `max_containers` limit; `audit.sqlite`/`gateway.sqlite` opened via bare `sqlite3.connect()` per call with no cross-container coordination.
**Fix:** `max_containers=1` pinned on the core gateway Function. Commit: `harden: single-writer audit path (A6)`.
**Re-verified:** redeployed live, `/healthz` still returns `{"ok": true}`.

## Section B/L — The ten in-process code leaks

`L9` is a UI-only alias of `C2` (see Section C). `L6` is the same root cause as `A3`.

### L1 — Shared process env

**Location:** structural — any code in `fastapi_app` can read every provider key
**Invariant broken:** INV-1
**Status:** mitigated for telegram (Move B/C), open for the other 12 adapters

Same fix and verification as A4 above — this is A4's code-level consequence, closed in the same commit.

### L2 — Audit log writable

**Location:** `glc/audit/store.py`
**Invariant broken:** INV-7
**Status:** mitigated (detectable, not yet preventable — full closure needs Move B)

**Before:** `AuditStore` exposed only `append()`, but the underlying SQLite file is directly `DELETE`-able by any in-process code with a `sqlite3` handle.
**Fix:** every row now carries `hash = sha256(prev_hash + canonical_json(row))`, chained off the previous row. `verify_chain()` walks the table and reports the first row where content or chain linkage no longer matches. Commit: `harden: hash-chained audit log (L2/L3 defense-in-depth)`.
**Re-verified:** a direct `DELETE FROM audit_log WHERE ...` (deleting a *mid-chain* row, with later rows still present) or an in-place `UPDATE` against a live-populated `audit.sqlite` is now caught by `verify_chain()` returning `(False, <first broken row id>)`.
**Known limitation, found while re-verifying:** deleting the **tail** (the most recent row(s), or the entire table) is *not* detected — there's no later row left whose `prev_hash` would contradict the deletion, so `verify_chain()` reports the shorter chain as intact. This is an inherent property of hash-chaining without an external checkpoint (a periodically-published "latest hash" the same attacker can't also reach), which is out of scope for this Part-1 mitigation. Documented in `glc/audit/store.py`'s module docstring and covered by `tests/test_audit_hash_chain.py::test_known_limitation_deleting_the_tail_is_not_detected` so it stays an explicit, known gap rather than an implicit one.

### L3 — Pairing escalation

**Location:** `glc/security/pairing.py`'s `force_pair_owner()`
**Invariant broken:** INV-2
**Status:** open — requires Move B

**Correction from an earlier draft of this file:** `force_pair_owner()` writes directly to `pairings.sqlite`, a completely separate SQLite file from `audit.sqlite` — it is never routed through `glc.audit.append()`, so the L2 hash-chain fix gives it **no** protection at all, tamper-evident or otherwise. There is no Part-1-scope code fix here: the call is an ordinary importable function with no access control, and no amount of code-level permission checking closes that without a process boundary (Move B). Verified directly: `grep -n "audit_append\|from glc.audit" glc/security/pairing.py` returns nothing.

### L4 — Install token readable in-process

**Location:** `glc/config.py`
**Invariant broken:** INV-4
**Status:** open — requires Move B (not fixed this round; `0o600` file permission stops other OS users, not other in-process code, and no Part-1-scope mitigation closes this without full separation)

### L5 — Policy engine monkey-patchable

**Location:** `glc/policy/engine.py`
**Invariant broken:** INV-6
**Status:** open — requires Move B (the module-level `evaluate()` and the singleton are ordinary rebindable Python attributes; no code-level fix closes this without a process boundary)

### L6 — Unbounded egress

**Location:** `modal_app.py` (same root as A3)
**Invariant broken:** INV-3
**Status:** mitigated for telegram — see A3/Move D above

### L7 — Subprocess / PATH injection

**Location:** `glc/voice/stt/providers/whisper_cpp/wrapper.py`
**Invariant broken:** INV-1-adjacent (least privilege / supply chain)
**Attacker role reached:** AR3
**Status:** fully closed (for the PATH-injection vector itself; running in a container with no other writable-then-executable paths ahead of it is Move B territory)

**Before:** `shutil.which("whisper-cli")` resolved the binary via `PATH` — exploitable if an earlier-loaded, less-trusted directory in `PATH` contained a file named `whisper-cli`.
**Fix:** `WHISPER_CLI_PATH` now resolves from `GLC_WHISPER_CLI_PATH` (default `/usr/local/bin/whisper-cli`), an absolute path checked with `.is_file()` before use — no `PATH` search at all. Commit: `harden: whisper_cpp binary via configured path, not PATH (L7)`.
**Re-verified:** pointing `GLC_WHISPER_CLI_PATH` at a nonexistent path raises a clear `RuntimeError` before any subprocess is spawned; the module no longer imports `shutil`.

### L8 — In-process kill

**Location:** `glc/routes/control.py:114` — `os.kill(os.getpid(), signal.SIGTERM)`
**Invariant broken:** INV-6
**Status:** open — requires Move B (the call itself is legitimately used by the loopback-gated kill endpoint; any other in-process code can call it directly, bypassing the loopback check entirely — no code-level fix closes this without a process boundary)

### L9 — Cross-channel envelope spoofing

Literal same bug as C2 — see Section C.

### L10 — Cost-ledger poisoning

**Location:** `glc/db.py`'s `log_call()`
**Invariant broken:** INV-8
**Attacker role reached:** any in-process code
**Status:** mitigated (full closure needs Move B — only the trusted core process should call `log_call`)

**Before:** `input_tokens`/`output_tokens` were unchecked ints with no range validation and no caller-identity binding.
**Fix:** `log_call()` now rejects negative values and values above a 2,000,000-per-call ceiling (`MAX_TOKENS_PER_CALL`) with `ValueError`, before the `INSERT` runs. Commit: `harden: validate cost-ledger writes (L10)`.
**Re-verified:** `db.log_call(input_tokens=-1, ...)` and `db.log_call(input_tokens=10**9, ...)` both now raise instead of landing a poisoned row.

## Section C — Inherited endpoint/logic issues, now internet-reachable

### C1 — SSRF via image resolver

**Location:** `glc/routes/chat.py`'s `_resolve_image_urls`
**Invariant broken:** INV-2/INV-3
**Attacker role reached:** AR1
**Status:** fully closed

**Before:** fetched any `http(s)` URL handed to it, following redirects, with no host restriction — the single most "textbook OWASP" finding in the assignment.
**Fix:** `_is_blocked_image_host()` resolves the hostname and rejects loopback/private/link-local ranges, failing closed on an unresolvable host. `follow_redirects=True` replaced with a manual redirect walk (max 5 hops) that re-validates the host on every hop, not just the initial URL. Commit: `harden: SSRF allowlist on the chat image-url resolver (C1)`.
**Re-verified:** `image_url: "http://169.254.169.254/..."` now returns `400 blocked: private/loopback address not allowed` instead of fetching the cloud metadata endpoint; a crafted redirect from an allowed host to a private IP is blocked before the second fetch.

### C2 / L9 — Cross-channel envelope spoofing

**Location:** `glc/routes/channels.py`'s `channel_ws`
**Invariant broken:** INV-2
**Attacker role reached:** AR2
**Status:** fully closed — the one finding closable by a pure application-layer change

**Before:** the WS handler trusted whatever `channel` field a caller put in the envelope body over the channel identity implied by the route it connected to.
**Fix:** immediately after envelope validation, reject and close (`WS_1008_POLICY_VIOLATION`) any message where `env.channel != name`, checked on every message inside the `while True` loop, not just at connect time; the attempt is audit-logged as `channel_spoof_attempt`. Commit: `harden: reject cross-channel envelope spoofing over WS (C2/L9)`.
**Re-verified:** connect to `/v1/channels/webui`, send an envelope with `channel="whatsapp"` — connection now closes with code 1008 instead of being processed as whatsapp traffic; verified the check also fires on message #2 of a connection that sent a legitimate envelope first.

### C3 — WS token in query string

**Location:** `glc/routes/channels.py`'s `channel_ws`
**Invariant broken:** INV-4-adjacent
**Attacker role reached:** AR1
**Status:** fully closed

**Before:** accepted the install token via `?token=...` as well as the `Authorization` header.
**Fix:** removed the `token` query param and its fallback branch entirely; header-only bearer auth. The two dev bridge scripts that built `?token=` URLs were updated to use `additional_headers` instead. Commit: `harden: WS channel auth via header only (C3)`.
**Re-verified:** connecting with `?token=<valid>` and no `Authorization` header now closes with code 1008.

### C4 — Verbose upstream errors

**Location:** `glc/routes/chat.py`
**Invariant broken:** INV-2
**Attacker role reached:** AR1
**Status:** fully closed (scoped to `chat.py`, per the ground-truth citation — `transcribe.py`/`speak.py`'s error wrapping is a separate, unnamed surface, not fixed here)

**Before:** `str(e)` — raw upstream exception text and provider hostnames — went directly into `HTTPException` details returned to the caller.
**Fix:** every site logs the full detail server-side (`logger.error(..., exc_info=True)`) and raises a generic client-facing message instead — the image-fetch failure, both provider-call failure sites, and the embed error paths (429/400/502/503). Commit: `harden: generic client errors, detailed server-side logs (C4)`.
**Re-verified:** a forced provider failure now returns `502 upstream provider error` with no provider name or exception text in the response body.

### C5 — No rate limits on the data plane

**Location:** `glc/routes/chat.py`, `glc/routes/transcribe.py`, `glc/routes/speak.py`
**Invariant broken:** INV-8
**Attacker role reached:** AR1
**Status:** fully closed, with a documented caveat

**Before:** zero references to `glc.security.rate_limits` in the data plane — the limiter was wired only into WS/webhook traffic.
**Fix:** `check_data_plane_rate_limit()` (shared identity) wired into `chat()`/`embed()` (vision and batch dispatch through `chat()`, so they're covered transitively), `transcribe_route()`, `speak_route()`. `chat.py` also gained a hard daily spend cap via `GLC_DAILY_BUDGET_USD`. Commit: `harden: rate limits + daily budget cap on the data plane (C5)`.
**Caveat:** T1.1's auth model issues one shared install token to every caller, so this is a **global** rate limit / budget cap on the whole gateway, not per-caller throttling — there is no finer-grained identity signal available at this layer yet.
**Re-verified:** the default `messages_per_minute` (30) worth of requests now returns `429` instead of routing to a provider; setting `GLC_DAILY_BUDGET_USD` below the day's logged spend also returns `429`.

### C6 — Pairing-code brute force

**Location:** `glc/security/pairing.py`'s `confirm_code`
**Invariant broken:** INV-2
**Attacker role reached:** AR4-adjacent (currently token-gated, so not directly reachable by AR1 today)
**Status:** fully closed for the attempt-limiter itself; defense-in-depth against a plausible future feature

**Before:** no attempt counter or lockout — an install-token holder could try all 1,000,000 six-digit codes with zero friction.
**Fix:** `PairingStore` tracks confirm failures in a sliding window (10 per 5 minutes); once hit, `confirm_code` raises `PairingLockedOut` and the route returns `429`. This is a global lockout, not per-identity — a wrong guess doesn't reveal whose pairing it was meant for. Commit: `harden: pairing-code attempt limiter (C6)`.
**Re-verified:** 10 wrong codes in a row return `404` each as before; the 11th attempt (correct or not) returns `429`.

## Bonus hardening: constant-time token comparisons

**Location:** `glc/routes/control.py`'s `_require_token`, `glc/routes/channels.py`'s `channel_ws`
**Invariant broken:** INV-2
**Attacker role reached:** AR1 (timing side-channel, CWE-208)
**Status:** fully closed

**Before:** both compared the install token with plain `!=`, inconsistent with the webhook verify-token check right next door in the same file, which already used `hmac.compare_digest` correctly.
**Fix:** both call sites now use `hmac.compare_digest`. Commit: `harden: constant-time token comparisons (control.py, channels.py)`.
**Re-verified:** behavior unchanged (right token passes, wrong token still rejected) — this is a non-functional timing fix, verified via source-level inspection that no `presented != expected`/`presented == expected` pattern remains.

## Not fixed this round (honest gaps)

- **L3, L4, L5, L8** — no Part-1-scope code fix closes these; they require Move B (process/container separation) applied gateway-wide, not just to telegram. (L3 was incorrectly marked "mitigated" in an earlier draft of this file — corrected above: `force_pair_owner()` writes to a separate SQLite file the L2 hash-chain fix never touches.)
- **A3/A4/L1/L6 full closure** — only telegram has been migrated behind Move B/C/D. The remaining 12 catalogue adapters (11 stubs + non-migrated real ones) still run in-process with full access to the LLM provider Secret. The factory (`adapter_image()`/`make_adapter_functions()` in `modal_app.py`) is generic and ready to apply to each one as it's implemented.
- **Move D (egress allowlist)** is demonstrated as a working mechanism (`verify_telegram_egress_allowlist`), not wired into the live per-request webhook dispatch path — spawning a fresh Sandbox per webhook call would add real per-request latency and complexity not justified for this assignment's scope.
- **C5's rate limit/budget cap is global, not per-caller** — a consequence of A1's single shared install token. Finer-grained throttling would need a second identity signal (per-client API keys, or source IP as a coarse proxy).
