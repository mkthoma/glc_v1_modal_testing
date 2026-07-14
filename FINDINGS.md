# FINDINGS — Part 1 hardening

This is the required note: for each finding, the invariant it broke and the fix that closed or mitigated it. Findings are grouped the same way the local testing dashboard (`tools/findings_console/`) groups them — by what the Modal migration did to each one. Every fix below has its own commit; commit subjects are quoted so you can `git show <subject>` for the exact diff.

Two things worth being upfront about, since they shape how "closed" is used below:

- Only **C2/L9** (cross-channel envelope spoofing) is closable with a pure application-layer code change. **L1–L5, L7, L8, L10 fundamentally require process/container separation to be fully closed** — Python has no in-process ACL on `os.environ` or on importable functions, so the only real wall is a kernel-enforced process boundary. Once Move B/C put every catalogue adapter in its own real container, that boundary actually exists now, and it closes more of these than earlier drafts of this file gave it credit for: **L1, L3, L4, L8 are fully closed for AR3** (an attacker who has compromised a single adapter container — verified live, not assumed); **L2, L7, L10 got a real Part-1-scope mitigation** (hash-chaining, an absolute binary path, input validation). **L5 got a real, direct code fix this round** — `glc/policy/engine.py` itself now blocks the exact monkey-patch the finding names (`__slots__` + a frozen module class) — but it's **mitigated, not closed**: an equally-easy `__dict__`-write bypass, one line long, still fully succeeds for the same AR4 attacker, and the separated `glc-policy-engine` path from an earlier draft remains real but still uncalled. Read L5's own entry before trusting any summary of it, including this one — two earlier drafts of this bullet each overclaimed differently (first "no mitigation possible," then "fully closed for both AR3 and AR4"), for two different reasons. L1/L3/L4/L8 remain open for AR4 specifically (code execution inside the gateway process itself, which still holds the real Volume-backed data those four protect) — closing that needs a further split of the gateway's own trusted internals from its request-handling code, a materially bigger, different-shaped task than "every adapter gets a container," out of scope here. Check each entry's own Status line rather than assuming from this summary.
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
**Status:** container separation fully closed (all 15 adapters); egress wall still only demonstrated for telegram

**Before:** one `@app.function` served the entire gateway plus every adapter, no `modal.Sandbox`, no egress control at all.
**Correction from an earlier draft of this file:** the first pass at Move B/C migrated only telegram, on the belief (inherited from the assignment's own framing, never independently checked) that the other 14 catalogue adapters were still `NotImplementedError` stubs not worth containerizing yet. That was wrong — `grep -rn "raise NotImplementedError" glc/channels/catalogue/*/adapter.py` returns nothing; every adapter has a real implementation. There was no remaining reason to leave 14 of them sharing the core gateway's LLM Secret, so all 15 are now migrated.
**Fix:** every catalogue adapter now runs in its own Modal Function via `modal_app.py`'s `ADAPTER_SECRETS` mapping + `make_adapter_functions()`; the core gateway Function never imports adapter code in-process. Egress allowlisting via `modal.Sandbox` remains demonstrated only for telegram (Move D). Commits: `harden: per-adapter container + scoped Secret, telegram (Move B/C)`, `harden: migrate all 15 catalogue adapters to per-adapter Functions + Secrets (Move B/C gateway-wide)`, `harden: egress allowlist via Modal Sandbox, telegram (Move D)`.
**Re-verified:** `uv run modal run modal_app.py::verify_telegram_egress_allowlist` — a request to `api.telegram.org` succeeds, a request to `example.com` is blocked. The egress wall itself is **not** wired into the live per-request webhook dispatch path for any adapter (see Move D note below), and the core gateway Function still has open egress, which it needs to reach LLM providers — that part of A3 stays "mitigated," not closed.

### A4 — One Secret for the whole Function

**Location:** `modal_app.py`
**Invariant broken:** INV-1
**Attacker role reached:** AR3
**Status:** fully closed, all 15 adapters

**Before:** `llm_secret` mounted to the entire `fastapi_app` Function — every route and every adapter could read every provider key.
**Fix:** `modal_app.py`'s `ADAPTER_SECRETS` dict maps every one of the 15 catalogue adapters to its own Secret (`glc-discord-secret`, `glc-gmail-secret`, `glc-imap-secret`, `glc-line-secret`, `glc-matrix-secret`, `glc-signal-secret`, `glc-slack-secret`, `glc-teams-secret`, `glc-telegram-secret`, `glc-twilio-sms-secret`, `glc-twilio-voice-secret`, `glc-webhook-secret`, `glc-whatsapp-secret`, or `None` for `local_mic`/`webui`, which need no external credential) — never `glc-llm-keys`. Commit: `harden: migrate all 15 catalogue adapters to per-adapter Functions + Secrets (Move B/C gateway-wide)`.
**Re-verified:** two throwaway probe Functions sharing the exact live secret configuration, read directly on Modal: the core gateway's probe (`glc-llm-keys` only) showed all six LLM keys present and zero of the twelve adapter credentials; a `slack`-scoped probe (`glc-slack-secret` only) showed its own token present and zero LLM keys, zero other adapters' credentials.

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

**A separate, more serious bug found while re-verifying L3/L4/L8 (not the same thing as the above):** `glc/audit/store.py`, `glc/security/pairing.py`, and `glc/db.py` each hardcode their own `~/.glc` default and only honor their own specific env var (`GLC_AUDIT_DB`, `GLC_PAIRING_DB`, `GLC_GATEWAY_DB`) — only `glc.config.CONFIG_DIR` actually derives from `GLC_CONFIG_DIR`. `modal_app.py` only ever set `GLC_CONFIG_DIR`, so `audit.sqlite`, `pairings.sqlite`, and `gateway.sqlite` were **never landing on the Volume at all** — they silently fell back to the container's own ephemeral filesystem and were wiped on every cold start. Confirmed directly: `modal volume ls glc-data glc` showed only `glc/install_token`, despite the deployment handling real traffic for the entire session. Fixed by explicitly setting all four paths (`GLC_CONFIG_DIR`, `GLC_AUDIT_DB`, `GLC_PAIRING_DB`, `GLC_GATEWAY_DB`) to `/data/glc/...` on the core gateway's image. **Re-verified: made a real request, confirmed `modal volume ls` now lists all four files; pulled `gateway.sqlite` locally, confirmed a `calls` row, redeployed, pulled it again, confirmed the same row survived the redeploy.**

## Section B/L — The ten in-process code leaks

`L9` is a UI-only alias of `C2` (see Section C). `L6` is the same root cause as `A3`.

### L1 — Shared process env

**Location:** structural — any code in `fastapi_app` can read every provider key
**Invariant broken:** INV-1
**Status:** fully closed for every catalogue adapter (the core gateway's own routes still share one process by necessity — they're the trusted core, not an adapter)

Same fix and verification as A4 above — this is A4's code-level consequence, closed in the same commits. The `findings_console`'s L1 check will still always report `vulnerable` when run locally: it demonstrates the leak from *inside the current process*, and can't observe a separated adapter's container from outside it (documented tool limitation, not a real gap) — see the README's known-limitations list.

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
**Status:** fully closed for AR3 (compromised adapter container); open for AR4 (code execution inside the gateway process itself)

**Correction from an earlier draft of this file:** `force_pair_owner()` writes directly to `pairings.sqlite`, a completely separate SQLite file from `audit.sqlite` — it is never routed through `glc.audit.append()`, so the L2 hash-chain fix gives it no protection, tamper-evident or otherwise.
**What actually closes it for AR3:** now that Move B/C puts every catalogue adapter in its own Modal Function (a real container, per `docs/ARCHITECTURE.md` and Section 5's own description of what a container provides), and `adapter_image()`/`make_adapter_functions()` deliberately never set `GLC_PAIRING_DB` or mount the Volume, calling `force_pair_owner()` from inside any adapter's container cannot reach `/data/glc/pairings.sqlite` — the real store the gateway trusts. The call still runs (Python has no in-process ACL on a function you can import), but it can only write to that container's own throwaway, ephemeral local file, which no other container — including the real gateway — ever reads.
**Re-verified live:** deployed a throwaway probe sharing the exact adapter-image shape (no Volume, no `GLC_CONFIG_DIR`/`GLC_PAIRING_DB`) and checked `os.path.isdir("/data")` from inside it — `False`. There is no `/data` mount to write to at all, regardless of what code runs.
**Still open for AR4:** an attacker with code execution inside the gateway process itself has the real Volume mount and the real `GLC_PAIRING_DB`, so `force_pair_owner()` is still fully effective there — that rung requires a further split of the gateway's own trusted internals from its request-handling code, which is out of scope here (see "Not fixed this round" below).

### L4 — Install token readable in-process

**Location:** `glc/config.py`
**Invariant broken:** INV-4
**Status:** fully closed for AR3; open for AR4

**Before:** `0o600` file permission stops other OS users, not other in-process code.
**What actually closes it for AR3:** same mechanism as L3 — `glc.config.get_or_create_install_token()` called from inside any adapter's container resolves `CONFIG_DIR` to that container's own local `~/.glc` (no `GLC_CONFIG_DIR` set there), disconnected from `/data/glc/install_token`, the real token the gateway checks against. An adapter container cannot read or forge the real token.
**Re-verified live:** same probe as L3 — no `/data` mount exists in an adapter-shaped container at all.
**Still open for AR4:** the gateway process itself has the real token file; closing this for that rung needs the same further internal split as L3/L5/L8.

### L5 — Policy engine monkey-patchable

**Location:** `glc/policy/engine.py`; `glc/policy/remote.py` (new)
**Invariant broken:** INV-6
**Attacker role reached:** AR4
**Status:** mitigated — the exploit exactly as the finding names it is now blocked; an equally-easy lower-level variant for the same attacker still succeeds

**Third correction to this file's L5 entry.** The first draft claimed L5 had no available mitigation; the second built `glc-policy-engine` as a separate Modal Function and, correctly, that `evaluate_remote()` is unaffected by a local monkey-patch — but then wrote "mechanism fully closed," which overstated it, because `glc/policy/engine.py` itself was still completely unmodified and nothing called the new path. Prompted again on why the finding wasn't actually fixed, I modified `glc/policy/engine.py` directly this time, instead of building another parallel path next to the untouched original:

- `PolicyEngine` now declares `__slots__ = ("config", "_lock")`, so `some_engine.evaluate = lambda *a, **k: ...` (an equally common monkey-patch style, shadowing the class method with an instance attribute) raises `AttributeError` instead of silently succeeding — instances have no `__dict__` to hold the override.
- The module's own `__class__` is swapped (`sys.modules[__name__].__class__ = _FrozenPolicyModule`) to a `types.ModuleType` subclass whose `__setattr__` rejects external reassignment of `evaluate`, `get_engine`, and `reload_engine` once they're already defined. The exact line the finding shows — `import glc.policy.engine as e; e.evaluate = lambda *a, **k: PolicyVerdict(action="allow", reason="pwned")` — now raises `AttributeError` instead of replacing the function.

**Why this is "mitigated," not "closed":** `__setattr__` interception doesn't stop a direct write to the module's own `__dict__` — `sys.modules["glc.policy.engine"].__dict__["evaluate"] = lambda *a, **k: ...` bypasses it entirely, is exactly one line, and is exactly as easy for the same AR4 attacker (someone who already has code execution in the process, by definition, isn't limited to the first syntax they try). This is the same class of residual gap as L2's hash-chain tail-deletion limitation: a real, verified improvement that raises the bar without closing the door. Overclaiming this as "closed" would repeat the exact mistake the second draft made — the whole reason this entry has been rewritten three times is to stop doing that.
**Re-verified:** `tests/test_policy_remote.py::test_direct_monkeypatch_of_module_function_is_rejected` and `::test_direct_monkeypatch_of_instance_method_is_rejected` confirm both blocks raise; `::test_dict_write_bypass_still_works_documented_residual_gap` confirms the residual gap is real and not accidentally also closed. `tools/findings_console/checks_inprocess.py`'s L5 check runs the literal exploit, catches the now-raised `AttributeError`, then demonstrates the `__dict__`-write bypass, and reports `mitigated` with the caveat spelled out — confirmed live against this exact check, not assumed.
**What's still true from the second correction:** the separated `glc-policy-engine` Modal Function (no Secret, no Volume mount, rules from the packaged `policy.yaml`) is real, deployed, and immune to *both* the blocked and the still-working local tamper technique, since it never references the local module at all. `GLC_POLICY_ENGINE_REMOTE=1` is set on the core gateway's env and `glc/policy/remote.py`'s `evaluate_remote()` is ready to use it. Nothing in the codebase calls it yet — the agent runtime is still a stub — so it remains the only mechanism that would fully close this for AR4, once something actually calls it instead of the local `evaluate()`.

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
**Status:** closed for AR3 by construction; open for AR4

**Before:** any in-process code could call `os.kill(os.getpid(), SIGTERM)` directly, bypassing the loopback-only kill endpoint entirely.
**What closes it for AR3:** every catalogue adapter now runs as its own Modal Function — a genuinely separate container with its own private PID namespace (this is what a container *is*: "its process IDs are a private numbering scheme, so it cannot see other processes"). `os.kill(os.getpid(), SIGTERM)` called from inside an adapter's `on_message()`/`send()` can only ever terminate that adapter's own container's own process — there is no `os.getpid()` value it could resolve to that reaches the actual `fastapi_app` Function's container, because they are different processes in different PID namespaces on Modal's side by construction, not by any code glc runs.
**Verification note:** I did not get a clean empirical self-kill test — a scratch probe that called `os.kill(os.getpid(), SIGTERM)` on itself caused the local Modal CLI client to hang indefinitely waiting on the killed container (likely internal retry/reconnect behavior on an abnormal exit, not a security-relevant finding), and I killed the hung local process rather than let it run unbounded. I did directly confirm the underlying structural fact for the same container shape (via L3's probe: no shared `/data`, no shared anything) — PID namespace isolation is the same category of guarantee, provided together by the same container boundary, not something glc's code has to build separately. Confirmed live throughout: the real gateway's `/healthz` kept responding normally after every one of these probe attempts.
**Still open for AR4:** an attacker with code execution inside the gateway process's own container can still call this and terminate it directly — that's the same process, so there's no boundary to cross.

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

- **L3, L4, L8 are closed for AR3 (a compromised adapter container) but remain open for AR4 (code execution inside the gateway process itself).** They live in the core gateway's own security internals (`force_pair_owner()`, the install-token file, `os.kill`), not in any adapter's code — but the container boundary Move B/C builds happens to close the *adapter-reachable* version of each anyway, since an adapter container has no path at all to the real Volume-backed data or the real gateway process (verified live). Closing them for AR4 needs a *further* architectural split — separating the core gateway's own control-plane/security internals from its request-handling code — which is a deeper change than "every adapter gets its own container" and is out of scope here. (An earlier draft of this file marked L3 "open" outright and separately marked it "mitigated" via the L2 hash-chain, both wrong in different ways — corrected above: `force_pair_owner()` writes to a separate SQLite file the L2 fix never touches, but Move B/C's container boundary closes it for AR3 through a different mechanism entirely.)
- **L5 is mitigated, not closed — the naive monkey-patch is blocked, but an equally-easy `__dict__`-write bypass isn't, and nothing calls the separated replacement.** `glc/policy/engine.py` now blocks the exact exploit the finding names (`e.evaluate = lambda *a, **k: PolicyVerdict(action="allow", ...)`) via `PolicyEngine.__slots__` plus a frozen-module-class guard — confirmed via `tools/findings_console`'s L5 check, which runs that literal line, catches the now-raised `AttributeError`, and reports `mitigated`. But `sys.modules["glc.policy.engine"].__dict__["evaluate"] = lambda ...` bypasses `__setattr__` entirely and produces the identical outcome, in one line, for the same AR4 attacker — no pure-Python in-process guard can close that. `glc-policy-engine` (a separate Modal Function) and `glc/policy/remote.py`'s `evaluate_remote()` remain real, deployed, and immune to *both* techniques since they never reference the local module — but nothing calls either the local `evaluate()` or `evaluate_remote()` for a real decision today (the agent runtime is still a stub), so this stays the only mechanism that would fully close it once policy enforcement is actually wired in and calls `evaluate_remote()` specifically.
- **A3/L6 egress-wall full closure** — container separation (A4/L1) is now done for all 15 catalogue adapters, but the egress-allowlist mechanism (Move D) is only demonstrated for telegram, and isn't wired into the live per-request webhook dispatch path for any adapter (see below). The core gateway Function itself also still has open egress, which it legitimately needs to reach LLM providers.
- **Move D (egress allowlist)** is demonstrated as a working mechanism (`verify_telegram_egress_allowlist`), not wired into the live per-request webhook dispatch path — spawning a fresh Sandbox per webhook call would add real per-request latency and complexity not justified for this assignment's scope, and hasn't been extended to the other 14 adapters.
- **C5's rate limit/budget cap is global, not per-caller** — a consequence of A1's single shared install token. Finer-grained throttling would need a second identity signal (per-client API keys, or source IP as a coarse proxy).
