# GLC v1 — Modal Pen-Testing Deployment

GLC v1 is a gateway that sits between agent clients and LLM providers, plus
channel adapters (Telegram, WhatsApp, webhooks, a web UI, ...) and voice
providers (STT/TTS). This repo is a clone of that gateway wrapped for
deployment on [Modal](https://modal.com) and treated as a live, attackable
target for a security assignment: reproduce every known finding against a
real deployment, harden the gateway against them, then hunt for new bugs.

Everything below documents what's actually been done in **this** clone —
what surfaces exist, what's been broken and fixed, how the eight invariants
and four attacker roles are used to reason about severity, and how to run
the local testing dashboard that automates every repro.

## Attacker model

Findings are rated by which of four attacker roles can reach them — weakest
to strongest:

| Role | Who they are |
|---|---|
| `AR1` | An outsider on the public internet with no credentials |
| `AR2` | A normal channel user who controls only the text they type |
| `AR3` | An attacker who has taken over a single adapter container |
| `AR4` | An attacker who has achieved code execution inside the gateway process |

A finding reachable by `AR1` is worse than an identical finding that
requires `AR4`, because `AR1` needs nothing but a network connection.

## Invariants

Every finding is also tied to which of eight security invariants it
violates:

| Code | Invariant |
|---|---|
| `INV-1` | Adapters must never see provider API keys. |
| `INV-2` | Every action must be checked against the actual user, tenant, and final arguments. |
| `INV-3` | External content must always be treated as data, never as instructions. |
| `INV-4` | A credential must work only for one specific tool call. |
| `INV-5` | Each tenant must have separate memory, and every stored fact must record its source. |
| `INV-6` | Dangerous or high-impact actions must be approved with their final parameters. |
| `INV-7` | Components must not be able to edit or delete their own audit logs. |
| `INV-8` | Every run must have hard limits on time, tokens, tool calls, and cost. |

## Attack surface: the 22 known findings

Findings are grouped by *what the Modal migration did to each one* — this
is the same grouping the local testing dashboard and its export use.

**A. Introduced or elevated by the Modal migration** (deployment-level gaps
that didn't exist, or didn't matter, before the gateway was put on the
public internet):

| ID | Finding | Invariant | Attacker |
|---|---|---|---|
| A1 | Public data plane, no auth — `/v1/chat`, `/chat/batch`, `/vision`, `/embed`, `/v1/transcribe`, `/v1/speak` accept requests from anyone | INV-2 | AR1 |
| A2 | Unauthenticated info disclosure — `/cost/by_agent`, `/providers`, `/capabilities`, `/status`, `/routers`, `/embedders`, `/calls`, plus `/docs`/`/openapi.json` left on | INV-2 | AR1 |
| A3 | Single Modal Function serving everything, no egress wall | INV-2/INV-3 | AR1/AR3 |
| A4 | One Modal Secret mounted to the entire Function — every route and every adapter can read every provider key | INV-1 | AR3 |
| A5 | Non-reproducible container image — hand-duplicated `pip_install` list instead of `uv.lock`, unpinned base image | supply chain | — |
| A6 | Audit volume assumes a single writer — no `max_containers=1`, plain `sqlite3.connect()` with no cross-container coordination | INV-7 | — |

**B. Inherited in-process leaks the migration did not close** — a
condensed view of the ten code leaks below (skips L6/L9, already covered
under A3/C2).

**C. Inherited endpoint/logic issues, now internet-reachable** (bugs that
existed in the code before Modal, but only became attacker-reachable once
the gateway got a public URL):

| ID | Finding | Invariant | Attacker |
|---|---|---|---|
| C1 | SSRF via the chat image-URL resolver — fetches any URL, follows redirects, no private/loopback IP block | INV-2/INV-3 | AR1 |
| C2 (= L9) | Cross-channel envelope spoofing — the WS channel handler trusts the `channel` field in the message body over the route it connected to | INV-2 | AR2 |
| C3 | WebSocket auth token accepted via `?token=` query string (lands in logs/history), not just the header | INV-4-adjacent | AR1 |
| C4 | Verbose upstream errors — raw provider exception text and hostnames returned to the client | INV-2 | AR1 |
| C5 | No rate limits or budget caps on the data plane | INV-8 | AR1 |
| C6 | Pairing-code confirmation has no attempt counter/lockout (currently token-gated, so not directly reachable by AR1 today, but worth closing) | INV-2 | AR4-adjacent |

**The ten in-process code leaks** (require running code *inside* the same
process as the gateway to demonstrate — not curl-able):

| ID | Finding | Invariant |
|---|---|---|
| L1 | Every adapter/route shares one process `os.environ` — any code can read `GEMINI_API_KEY` and friends | INV-1 |
| L2 | The audit log is an ordinary SQLite file — any in-process code can `DELETE FROM audit_log` directly | INV-7 |
| L3 | `force_pair_owner()` lets any in-process code escalate a pairing without going through HTTP | INV-2 |
| L4 | The install token file is only OS-permission protected (`0o600`) — not protected from other in-process code | INV-4 |
| L5 | The policy engine's `evaluate()` and singleton are ordinary rebindable Python attributes — monkey-patchable | INV-6 |
| L6 | No egress control at all — same root cause as A3 | INV-3 |
| L7 | The whisper_cpp subprocess call resolves its binary via `PATH` (`shutil.which`), not an absolute path — PATH injection | INV-1-adjacent |
| L8 | Any in-process code can call `os.kill(os.getpid(), SIGTERM)` directly, bypassing the loopback-only kill endpoint | INV-6 |
| L9 | Same bug as C2 — cross-channel envelope spoofing | INV-2 |
| L10 | `log_call()` accepts unchecked token counts and caller identity — the cost ledger can be poisoned by any in-process caller | INV-8 |

Two things worth being upfront about, because they shape how fixes are
scoped and reported:

- Only **C2/L9** (cross-channel envelope spoofing) is closable with a pure
  application-layer code change. **L1–L5, L7, L8, L10 fundamentally
  require process/container separation to be fully closed** — Python has
  no in-process ACL on `os.environ` or on importable functions, so the
  only real wall is a kernel-enforced process boundary. Each of these gets
  a defense-in-depth mitigation first (input validation, hash-chaining,
  pinning a binary path) and is marked *mitigated, not closed* until
  containers are actually separated.
- **A4 and L1 are the same underlying gap** (one shared Secret) described
  at the deployment-config level and the code-consequence level.
  **C2 and L9 are the literal same bug**, named twice.

## What's been done

Every fix below has its own commit and its own regression test; the
detailed per-finding write-up (location, invariant, attacker role,
before/after, exact commit) is in [`FINDINGS.md`](FINDINGS.md) — this
section is the summary.

1. **Deployed the gateway to a real, live Modal account** — [modal_app.py](modal_app.py)
   wraps the unmodified `glc.main:app` in a Modal Function, attaches a
   persistent Modal Volume so the audit log, pairing store, and install
   token survive container restarts, and mounts a Modal Secret so provider
   keys arrive as environment variables rather than being baked into the
   image. Scale-to-zero (`min_containers=0`) keeps it on the free tier;
   `max_containers=1` pins it to a single writer for the audit path.
2. **Confirmed every finding above reproduces against the live
   deployment before any fix landed** — each `curl`/WebSocket/in-process
   repro was run against the fresh, unmodified deployment and the actual
   response recorded, rather than assuming the lecture's own output
   applies unchanged to this codebase.
3. **Hardened the app-layer and endpoint-level findings** (Move A —
   no architecture change required):
   - Bearer-token auth in front of every data-plane route (`/v1/chat`,
     `/chat/batch`, `/vision`, `/embed`, `/v1/transcribe`, `/v1/speak`),
     reusing the existing install-token pattern, compared with
     `hmac.compare_digest` for constant-time safety.
   - The same token dependency gates every info-disclosure endpoint
     (`/status`, `/providers`, `/capabilities`, `/cost/by_agent`,
     `/calls`, `/routers`, `/embedders`); `/docs`, `/redoc`, and
     `/openapi.json` are disabled outside local dev.
   - Provider errors are logged in full server-side and returned to
     clients as a generic `502 upstream provider error`, no more raw
     exception text or provider hostnames leaking out.
   - Rate limiting and a hard daily-spend budget cap wired into the data
     plane, matching the pattern `routes/channels.py` already used for
     WS/webhook traffic.
   - An IP-allowlist check (blocking loopback/private/link-local ranges)
     added to the chat image-URL resolver, re-validated on every redirect
     hop, not just the initial fetch.
   - The WebSocket channel handler now rejects any message whose envelope
     `channel` field doesn't match the route it connected on — checked on
     every message, not just at connect time — closing the cross-channel
     spoofing bug in one place.
   - The `?token=` query-string fallback removed from the channel
     WebSocket; header-only bearer auth.
   - A pairing-code confirmation attempt limiter (10 failures per 5
     minutes, then locked out).
   - Constant-time (`hmac.compare_digest`) token comparisons everywhere
     the install token is checked.
   - The container image now builds from `uv.lock` via `uv sync --frozen`
     instead of a hand-duplicated dependency list, with the base image
     pinned by digest.
4. **Architectural separation** (Move B/C — the moves that fully close
   the in-process credential leaks, not just mitigate them), applied to
   **every one of the 15 catalogue adapters**, not just a demonstration
   subset:
   - An earlier pass migrated only telegram, on the assumption
     (inherited, never checked) that the other 14 adapters were still
     unimplemented stubs. They aren't — every adapter under
     `glc/channels/catalogue/` has a real `on_message`/`send`
     implementation, so there was no reason to leave them sharing the
     LLM provider Secret. All 15 now run in their own Modal Function
     with their own scoped Secret (`glc-discord-secret`,
     `glc-slack-secret`, ... — or no Secret at all for `local_mic`/`webui`,
     which need no external credential).
   - Verified live: a throwaway probe sharing the core gateway's exact
     Secret configuration shows all six LLM keys present and zero
     adapter credentials; a probe sharing `slack`'s configuration shows
     only its own token, zero LLM keys, zero other adapters' credentials.
   - A pluggable dispatch layer (`glc/channels/remote.py`) so the core
     gateway calls every separated adapter through typed
     `ChannelMessage`/`ChannelReply` envelopes instead of importing any
     adapter's code in-process; local dev is unaffected.
   - **Egress allowlisting (Move D)** via `modal.Sandbox`
     (`outbound_domain_allowlist`) remains a demonstration on telegram
     only, verified live to let `api.telegram.org` through while
     blocking an arbitrary other domain — not wired into the live
     per-request dispatch path or extended to the other 14 adapters (see
     `FINDINGS.md` for why).
5. **Built a separated, un-monkey-patchable path for the policy engine
   (L5) — but this does NOT close the finding as named.** `glc-policy-engine`
   runs a decision in its own Modal Function with no Secret and no
   Volume mount; `glc/policy/remote.py`'s `evaluate_remote()` dispatches
   to it. Verified live: monkey-patched `glc.policy.engine.evaluate` to
   always return `allow`, then called the *real deployed Function* with
   a request the packaged `policy.yaml` denies — it returned `deny`,
   unaffected by the local tamper. **But `glc/policy/engine.py` itself
   was never modified**, and nothing calls `evaluate_remote()` yet — the
   exact exploit the finding names still succeeds completely against
   the original function, deployed or not, because monkey-patching
   replaces the whole function object; no internal redesign of a
   directly-callable function can stop that. This is genuinely different
   from the L1/L3/L4/L8 fixes above, where the deployed reality actually
   changed — for L5, a safer alternative now exists, unused, next to an
   unmodified vulnerable original. See `FINDINGS.md` for the full
   correction (an earlier draft of this section overclaimed "fully
   closed").
6. **Added defense-in-depth mitigations** for the leaks that can't be
   fully closed without full container separation: hash-chaining on the
   audit log (so tampering is *detectable* even before it's
   *preventable* — verified by directly `DELETE`/`UPDATE`-ing a live
   audit.sqlite and confirming `verify_chain()` catches it), input-range
   validation on cost-ledger writes, and an absolute configured path for
   the whisper_cpp binary instead of `PATH`-based resolution.
7. **Regression-tested every fix** (365+ tests, ~89% coverage on
   `with_fixes/glc/`, well above the CI gate) and **redeployed after
   every hardening commit**, re-confirming `/healthz` and the fix itself
   against the live Modal deployment each time — not just locally.
8. **Built a local testing dashboard** (`tools/findings_console/`) that
   automates the manual repro steps for all 22 findings against any
   target — see below.

## Setting up Modal

1. Install the CLI (already a project dependency) and sync:

   ```bash
   uv sync
   ```

2. Authenticate the CLI against your own Modal account — this opens a
   browser to sign up or log in and writes an API token to your machine:

   ```bash
   uv run modal setup
   ```

3. Create the provider-key Secret. **Use mock values only — never put real
   provider keys here.** Each mock value follows
   `<PROVIDER>-mock-not-real` so it's obvious at a glance which key a
   given entry stands in for:

   ```bash
   uv run modal secret create glc-llm-keys \
     GEMINI_API_KEY=gemini-mock-not-real \
     GITHUB_ACCESS_TOKEN=github-mock-not-real \
     GROQ_API_KEY=groq-mock-not-real \
     NVIDIA_API_KEY=nvidia-mock-not-real \
     CEREBRAS_API_KEY=cerebras-mock-not-real \
     OPEN_ROUTER_API_KEY=openrouter-mock-not-real
   ```

## Deploying the app

The repo ships **two** deployable variants, so the findings console below
can compare a real pre-hardening baseline against the real hardened
gateway — not a description of what used to be true:

- **`with_fixes/`** — the hardened gateway, every Part 1 fix applied.
  This is the one you're actually working on.
- **`without_fixes/`** — a frozen, untouched snapshot of the code exactly
  as it was before Session 12's Modal migration and any of this
  hardening. Never edit this — it exists only to give the findings
  console something real to test findings *against* on the "before" side.

```bash
uv run modal deploy with_fixes/modal_app.py
uv run modal deploy without_fixes/modal_app.py
```

Modal prints a public `*.modal.run` URL for each. Confirm both booted:

```bash
curl <with_fixes-url>/healthz
curl <without_fixes-url>/healthz
# {"ok": true, "port": 8111}
```

Open `<with_fixes-url>/docs` in a browser to see the interactive API surface
(when docs are enabled — see the A2 fix above for when they're disabled).
`without_fixes` never gates `/docs`, since A2's fix doesn't exist there.

Redeploy `with_fixes/modal_app.py` any time after a code change with the
same command — its Volume (audit log, pairing store, install token)
survives redeploys; only the container image and code are refreshed.
`without_fixes/modal_app.py` should never need redeploying, since its
code never changes.

To fetch either app's install token by hand (e.g. to `curl` a deployed
gateway directly) — each is stored on that app's own Volume, not on your
machine. The findings console below auto-detects both for you; this is
only for manual use:

```bash
uv run modal volume get glc-data glc/install_token ./modal-install-token.txt              # with_fixes
uv run modal volume get glc-data-baseline glc/install_token ./baseline-install-token.txt   # without_fixes
```

## Running the tests

### Unit / regression test suite

```bash
uv run pytest tests/ -m "not requires_live_api and not requires_models" \
  --cov=with_fixes/glc --cov-report=term-missing --cov-fail-under=80
uv run ruff check . && uv run ruff format --check .
uv run python scripts/validate_envelope.py
uv run python scripts/validate_policy.py
```

(`without_fixes/` is a frozen pre-hardening snapshot, excluded from lint/coverage on purpose — see its own note in `pyproject.toml`.)

### The findings console (pen-test dashboard)

`tools/findings_console/` is a local-only web dashboard that automates
the manual curl/WebSocket/in-process repro for all 22 findings above. It
is never deployed to Modal, has no auth of its own, and should only ever
be reached at `127.0.0.1`.

**Two real, separately deployed Modal apps, tested side by side —
before and after.** `without_fixes/` (pre-hardening baseline) and
`with_fixes/` (hardened gateway) are each deployed independently (see
[Deploying the app](#deploying-the-app) above); the console tracks both
as fixed, auto-detected targets named "before" and "after." There is no
local-gateway option — this assignment hardens the *deployed* app, and
most of these findings (A3–A4, L1, L3–L5, L8) are specifically about
container/Secret separation a local `uv run glc serve` process can't
exercise at all.

**Start it** from the repo root, after you've deployed both apps:

```bash
uv run python -m tools.findings_console.server
```

Serves the dashboard at `http://127.0.0.1:8811`. **No copy-pasting a URL
or token, for either target** — on startup the console parses each
`modal_app.py` for its App name, ASGI function name, Volume name, and
config path, then asks the Modal SDK for that Function's live
`*.modal.run` URL and reads its install token straight out of its own
Volume. If an app isn't deployed yet, that target's form explains what's
missing; click its own **Re-detect** button to retry once it is.

**Using it:**

- Every check starts as `no runs` — nothing runs on its own. Click
  **▶ before** / **▶ after** on a row to fire one check against one
  target, or **Run all checks (before + after)** to fire every check
  against both (roughly two minutes total — C1's SSRF probe and L8's
  self-kill probe are the slow ones, per target).
- Every check's **before** column should read `vulnerable` and **after**
  should read `closed`/`mitigated` — that agreement across two
  independently deployed apps *is* the proof the fixes work, verified
  live, not just documentation saying so.
- Click into any check to see a **Before vs. after** block: the before
  target's most recent run next to the after target's, with each side's
  actual evidence. Every check's own page also has an **Attack command**
  box (the literal `curl`/Python that reproduces it) and a **How this is
  fixed** box naming the actual file and mechanism.
- `GET /api/export.md` dumps the whole log as a Markdown starting point
  for a findings report, organized the same way this README groups
  findings (A/B/C/ten-leaks).

**Verdict codes** — `vulnerable` (attack succeeded), `mitigated` (real
progress verified, but the attack or an equally-easy alternate route
still works, or the check is a heuristic that can't fully confirm
closure alone), `closed` (the check directly confirmed the attack now
fails, unconditionally, for the attacker role it names — a *stronger*
role it doesn't exercise may still have a route), `manual` (needs
something the tool can't supply, usually a token), `error` (the check
itself failed to run — not a verdict on the finding).

Full detail — exactly what each check kind does for "before" vs.
"after" (HTTP/WS checks just hit a different deployed URL; `inprocess`
checks import `with_fixes/glc` or `without_fixes/glc`; `static`/
`live_probe` checks read or call the matching variant's `modal_app.py`),
every known limitation, and the full package layout — lives in
[`tools/findings_console/README.md`](tools/findings_console/README.md).

Stop the console with **Ctrl+C** — a force-kill just leaves port 8811
bound until the next startup's port-guard clears it.

## Repository layout

```
with_fixes/                  the hardened gateway — this is the one you work on
  glc/                         the gateway itself (routes, policy, audit, channels, voice, security)
  modal_app.py                 Modal deployment wrapper — image, Volume, Secret, the served ASGI app
without_fixes/                frozen pre-hardening snapshot — deployed as the findings console's "before"
  glc/                         byte-identical to the code before Session 12's Modal migration; never edit
  modal_app.py                 same original simple wrapper, distinct App/Volume names so it coexists
FINDINGS.md                  per-finding write-up: invariant, attacker role, before/after, commit
tools/findings_console/      the local pen-test dashboard described above
tests/                       regression test suite (targets with_fixes/glc)
scripts/                     CI-parity validation scripts (envelope shape, policy load)
daemon/                      local daemonisation helpers (launchd/systemd/NSSM)
docs/                        architecture and adapter/voice guides
```

## License

MIT — see [`LICENSE`](LICENSE).
