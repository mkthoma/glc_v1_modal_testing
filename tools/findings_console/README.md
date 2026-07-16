# Findings console

A local-only web dashboard that automates the manual `curl`/harness repro steps in [`PLAN.md`](../../PLAN.md) for every Part 1 finding (A1–A6, C1–C6, L1–L10). Run a check, see pass/fail, and compare the state of any finding **before and after hardening, side by side** — using two real, separately deployed Modal apps, not a local guess about what used to be true. Every check's own page also shows the exact command that reproduces the attack and a plain-English summary of the fix.

It is a testing tool, not part of the graded gateway. It is never deployed to Modal, has no authentication of its own, and should only ever be reached at `127.0.0.1`.

**Two fixed, named Modal targets — "before" and "after" — both auto-detected, neither a local `uv run glc serve` stand-in.** This assignment is about hardening the *deployed* app, and most of these findings (A3–A4, L1, L3–L5, L8) are specifically about container/Secret separation a local process can't exercise:

| Target | Source | Deployed app |
|---|---|---|
| **before** | [`without_fixes/`](../../without_fixes/) — the pre-hardening baseline, byte-identical to the code before Session 12's Modal migration | `glc-v1-gateway-baseline` |
| **after** | [`with_fixes/`](../../with_fixes/) — the hardened gateway with every Part 1 fix applied | `glc-v1-gateway` |

## Quick start

**Run this from the repository root** (the directory containing `pyproject.toml`, `with_fixes/`, `without_fixes/`, `tools/`):

1. Deploy both apps if you haven't (see the main [README](../../README.md)'s Modal setup section):
   ```bash
   modal deploy without_fixes/modal_app.py
   modal deploy with_fixes/modal_app.py
   ```
2. Start the console:
   ```bash
   uv run python -m tools.findings_console.server
   ```
3. Open `http://127.0.0.1:8811`.

That's it — **no copy-pasting a URL or token, for either target.** On startup, the console reads each `modal_app.py` for its App name, ASGI function name, Volume name, and configured data path, then asks the Modal SDK for that Function's live `*.modal.run` URL and reads the install token straight out of its Volume. This needs no `modal` CLI subprocess, just the same Modal auth (`modal token new` / `modal setup`) you already used to deploy. Each target's own form shows whether auto-detection worked; if an app isn't deployed yet, that target's form explains what's missing and its own **Re-detect** button is always there to retry. Setting `GLC_MODAL_URL`/`GLC_MODAL_INSTALL_TOKEN` (for "after") or `GLC_MODAL_BASELINE_URL`/`GLC_MODAL_BASELINE_INSTALL_TOKEN` (for "before") — or pasting into either form — overrides auto-detection.

Every check starts as `no runs` — **nothing runs on its own.** Click **▶ before** / **▶ after** on a row to fire one check against one target, or use one of the three "Run all" buttons (before only, after only, or both) — this blocks the request until every check finishes (C1's SSRF probe, L8's self-kill probe, and C5/C6's request bursts are the slow ones; running **both** for all 22 checks takes roughly two minutes).

No setup beyond the repo's normal `uv sync` — every dependency it needs (`fastapi`, `httpx`, `websockets`, `python-multipart`) is already in `pyproject.toml`.

### Stopping it cleanly

Use **`Ctrl+C`** in the terminal it's running in.

If you started it in the background and have to force-kill it (`taskkill /F`, `kill -9`), the console itself leaves nothing else running (it manages no other process) — just make sure port 8811 is actually free before starting it again:

```bash
netstat -ano | grep ":8811 "   # Windows/Git Bash
lsof -i :8811                   # macOS/Linux
```

By default, every startup already force-kills whatever's listening on `8811` for you — see `FINDINGS_CONSOLE_FORCE_PORTS` below.

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `GLC_MODAL_URL` | unset | Overrides auto-detection for the **after** (hardened) target's `base_url`. |
| `GLC_MODAL_INSTALL_TOKEN` | unset | Same, for the **after** target's `install_token`. |
| `GLC_MODAL_BASELINE_URL` | unset | Overrides auto-detection for the **before** (baseline) target's `base_url`. |
| `GLC_MODAL_BASELINE_INSTALL_TOKEN` | unset | Same, for the **before** target's `install_token`. |
| `FINDINGS_CONSOLE_DB` | `.findings_console/console.sqlite` | Override the SQLite log location. |
| `FINDINGS_CONSOLE_FORCE_PORTS` | `1` | Set to `0` to stop the console from force-killing whatever's listening on `8811` before it binds (by default it shells out to `netstat`/`taskkill` or `lsof`/`kill` to clear a stale instance from a prior session that wasn't stopped with Ctrl+C). |

## What it does

1. **Dual target auto-detection** — on startup, the console parses both `without_fixes/modal_app.py` and `with_fixes/modal_app.py` for each App's name, ASGI function name, Volume name, and configured data path, then asks the Modal SDK for each deployed Function's `*.modal.run` URL and reads each install token out of its own Volume directly (`tools/findings_console/modal_detect.py`). No `modal` CLI subprocess, no copy-pasting — it needs only the same Modal auth you used to deploy. Click either target's **Re-detect** button any time (e.g. after a fresh `modal deploy`) to refresh it.
2. **Run checks** — click **▶ before** or **▶ after** on any row to fire just that one check against just that one target, or use **Run all checks (before + after)** to fire every check against both in one pass. Nothing runs on its own; every run is something you clicked.
3. **Hover an invariant or attacker code for what it actually means** — `INV-2`, `AR1`, and the check's `kind` (`http`/`ws`/`live_probe`/`inprocess`/`static`) are all shorthand. Every place one appears (the dashboard table, the check detail page) it's a native `<abbr title="...">` — hover it and the browser shows the full sentence, no JS needed. A **legend** at the bottom of the dashboard spells out every invariant, attacker role, verdict code, and check kind in one place if you'd rather not hover row by row.
4. **Read the verdict** — each run is classified as:

   | Verdict | Meaning |
   |---|---|
   | `vulnerable` | the check ran the attack and it succeeded — no fix in effect yet |
   | `mitigated` | either the attack (or an equally-easy alternate route to the same outcome, for the same attacker role) still succeeds but the check confirmed real, verified progress — reduced impact, or the tamper is now detected — **or** the check is a heuristic that can't fully confirm closure on its own; read the evidence |
   | `closed` | the check directly confirmed the demonstrated attack now fails, unconditionally, for the attacker role it names — a *stronger* attacker role this check doesn't exercise may still have a different route (check FINDINGS.md) |
   | `manual` | this check needs something the tool can't supply on its own (usually an `install_token`) — go verify it yourself |
   | `error` | the check itself failed to run (network error, timeout, unexpected response shape) — not a verdict on the finding |

   The dashboard's own **Reference → Verdict codes** legend spells this out in full — it's the single source of truth `models.py`'s `VERDICT_DESCRIPTIONS` and every check's actual verdict logic is written against, so it never drifts out of sync with what the checks actually do. In practice, every check's **before** column should read `vulnerable` (the baseline has none of the fixes) and **after** should read `closed` or `mitigated`, matching `FINDINGS.md` exactly — that agreement across two independently deployed apps *is* the proof the fixes work, not just documentation saying so.
5. **Compare before vs. after, per check** — click into any check (`/check/<id>`) to see a **Before vs. after** block: the before target's most recent run next to the after target's most recent run, using the exact evidence each run actually produced. A plain **Full run history** table further down lists every run ever recorded for that check, most recent first, across both targets.
6. **Read the attack command and the fix** — every check's own page has an **Attack command** box (the literal `curl`/Python you'd run by hand to reproduce it, with the **after** target's URL and token already substituted in) and a **How this is fixed** box (which file changed and the actual mechanism, not just "see the commit").
7. **Clear history** — **Clear all history** on the dashboard wipes every run, for every check and every target (confirmation required — this is irreversible). **Clear history for this check**, on a check's detail page, does the same but scoped to just that one check.
8. **Export** — `Export FINDINGS.md draft` (`GET /api/export.md`) dumps every finding, grouped exactly like the dashboard (see [The 22 checks](#the-22-checks) below), each one leading with the invariant and attacker-role sentence `ASSIGNMENT.md` asks for — spelled out in full, not left as a bare code — plus whatever's been run so far.
9. **See which commit actually fixed something** — every run is stamped with the local checkout's current git commit (short SHA) at the moment it ran. Once a check's verdict reaches `closed` or `mitigated`, that run's panel shows `Fixed in commit: <sha>`.

Every run is logged **append-only** to a local SQLite file while it exists — deliberately mirroring `glc/audit/store.py`'s own append-only pattern, applied to your own testing tool: nothing is ever *edited*, and normal use never deletes anything either. The **Clear** actions are the one deliberate exception, and they're explicit, confirmed, user-triggered resets.

## The 22 checks

One check per row of `PLAN.md`'s ground-truth table. `L9` is a UI-only alias of `C2` — they're the literal same bug (cross-channel envelope spoofing), named twice in the assignment.

### How they're grouped in the dashboard and the export

Both the dashboard and `Export FINDINGS.md draft` organize findings the way **Session 12 §6/§7 themselves** group them — by what the Modal migration did to each one — not by the technical `kind` below. Four sections, in this order (`tools/findings_console/sections.py`):

| Section | Contents |
|---|---|
| **A. Introduced or elevated by the migration (the highest-value class here)** | A1–A6 |
| **B. Inherited in-process leaks (closed/mitigated status varies by attacker role)** | B1–B8 — a *condensed* 8-of-10 subset of the ten leaks below, labeled `B1 (=L1)` through `B8 (=L7)`. Skips L6 and L9, since those are already covered under A3 and C2 respectively — matching §6's own text exactly. |
| **C. Inherited endpoint/logic issues, now internet-reachable** | C1–C6 |
| **The ten code leaks the migration leaves open** | L1–L10, all ten, in full — the complete §7 catalog, including L6 and L9 again (deliberately — §7 gives them their own full write-up even though §6 already cross-referenced them under A/C) |

Every entry is still the same underlying `Check` regardless of which section(s) it appears in — clicking a row's Run buttons under `B1` and under `L1` later run and log the identical check, just displayed twice, exactly like the lecture text itself mentions leak 6 and leak 9 twice (once as a cross-reference, once as a full write-up).

### What each check actually does when it runs

Every check kind is **target-aware** now — the same `Check.run(target)` call picks which real thing to test (which deployed URL to hit, which Modal Function to call, which local `glc` package to import, which `modal_app.py`/source tree to read) based on whether `target.name` is `"before"` or `"after"`.

| Kind | Runs against | Checks | What "target" changes |
|---|---|---|---|
| `http` | `target.base_url` | A1, A2, C1, C4, C5, C6 | which deployed `*.modal.run` gateway gets the request |
| `ws` | `target.base_url` | C2 (=L9), C3 | same, over a WebSocket |
| `live_probe` | calls a deployed Function via the Modal SDK | L1, L3, L4, L8 | **after**: calls `glc-adapter-shape-probe`/`glc-adapter-shape-self-kill-probe`, deployed only in `with_fixes/modal_app.py`. **before**: there's no per-adapter container to call at all yet (that separation is exactly what these findings say doesn't exist) — reports a structural `vulnerable` from reading `without_fixes/modal_app.py`'s source directly instead. |
| `inprocess` | ignores `base_url` — imports `glc` from a local checkout | L2, L5, L10 | **after**: imports from `with_fixes/glc` (the hardened package). **before**: imports from `without_fixes/glc` (the frozen pre-hardening snapshot) — same snippet, genuinely different behavior, since the mitigation code itself isn't there yet. |
| `static` | ignores `base_url` — reads a local `modal_app.py`/source tree | A3, A4, A5, A6, L6, L7 | **after**: reads `with_fixes/modal_app.py` / `with_fixes/glc/...`. **before**: reads `without_fixes/modal_app.py` / `without_fixes/glc/...`. |

**Why `inprocess`, `static`, and (partly) `live_probe` checks don't need a live HTTP request to tell "before" from "after":** the fix itself lives in the source tree or the deployed Function landscape, not just in request/response behavior — reading or importing the *right* variant's code is the check. `http`/`ws` checks, by contrast, only need `target.base_url` pointed at the right deployed app; the code difference shows up naturally in how that live app responds.

## Known limitations (found by actually running this against both live deployments, not assumed)

- **L5 reports `mitigated`, not `vulnerable` or `closed`, against "after."** The exact one-liner the finding names now raises `AttributeError`, but the check itself then demonstrates the documented residual gap (a direct `__dict__` write bypasses that check) — see its "How this is fixed" box. Against "before" it correctly reports `vulnerable` (no hardening exists there at all).
- **C4 (verbose upstream errors) under-reports as `closed` if a target has zero provider keys configured.** No provider is even attempted, so there's nothing to leak. Both deployed apps share the same `glc-llm-keys` Secret (mock values), so this should behave consistently across before/after — set at least one real-shaped mock key if it doesn't.
- **C1 (SSRF) is a text-matching heuristic, not a network-level oracle.** It looks for the word "block" in a `400` response body. Read the evidence panel yourself too.
- **C2/L9 requires both the route channel and the spoofed channel to be `enabled: true`** in `channels.yaml` for the probe to reach the actual vulnerable code path. The check uses `webui`→`whatsapp` by default, since those are enabled out of the box in this repo's packaged `channels.yaml`.
- **C5 (rate limiting) fires up to 35 rapid requests, and C6 (pairing brute force) fires up to 20 — against whichever real deployed gateway you're testing.** That's intentional: only a deployed gateway is what's actually meaningful here. Expect this to briefly drive real (if tiny) usage on both apps when you run "both."
- **C6's pairing-confirm lockout is global** (`glc/security/pairing.py`'s `CONFIRM_ATTEMPT_LIMIT`, deliberately not scoped per identity). Running C6 against "after" can transiently block C2/L9's own setup step against "after" too, if C2/L9 hasn't already paired its probe identity in an earlier run — the check now checks `/v1/control/presence` first and skips re-pairing once already paired, so this can only happen on a fresh console/cleared history. If it does happen, C2/L9 reports a clear `error` naming C6 and the 5-minute window, not a bare exception.

## Data storage

Every run is logged to `.findings_console/console.sqlite` at the repo root (gitignored — see `.gitignore`). Override the path with `FINDINGS_CONSOLE_DB=/path/to/file.sqlite` if you want a separate log per branch or experiment. In-process checks never touch this file or your real `~/.glc` — each one gets a fresh scratch `GLC_CONFIG_DIR` in a temp directory, so `L2`'s check (which genuinely runs `DELETE FROM audit_log`) and `L3`'s (which genuinely writes a pairing record) can never corrupt your actual local gateway state — and they run against whichever of `with_fixes/glc` or `without_fixes/glc` the target calls for, never your own dev environment's package.

## Package layout

```
tools/findings_console/
  models.py            Check, CheckResult, Verdict, Target, and the INV/AR/kind description tables
  sections.py           groups checks into A/B/C/ten-leaks, matching Session 12 §6/§7
  store.py               append-only SQLite log (record/history/earliest/latest, per-target latest)
  gitinfo.py              captures the local checkout's current commit for every run
  harness.py               spawns an isolated subprocess for in-process checks; glc_root picks with_fixes/ or without_fixes/
  modal_detect.py           parses a modal_app.py + calls the Modal SDK to auto-detect a target's URL/token
  checks_http.py            A1, A2, C1, C4, C5, C6
  checks_ws.py               C2/L9, C3
  checks_inprocess.py        L2, L5, L10
  checks_live_probe.py       L1, L3, L4, L8 — calls the live probe Functions, or the "before" structural check
  checks_static.py           A3, A4, A5, A6, L6, L7 — reads with_fixes/ or without_fixes/ source by target
  registry.py                aggregates all Check objects into one id-keyed registry (+ the L9 alias)
  runner.py                  executes a Check against a Target, stamps the git commit, records the result
  render.py                  plain-Python HTML rendering (no template engine dependency)
  server.py                  FastAPI app + routes + `main()` entry point — tracks before_target/after_target
```

No new runtime dependency was needed beyond `python-multipart` (added as a **dev** dependency — required by FastAPI's `Form(...)` for the plain HTML `<form>` posts the dashboard uses; it never ships with the actual `glc` gateway).

## Troubleshooting

**`only one usage of each socket address ... 8811`** — self-healing as of the port-guard: every startup force-kills whatever's already listening on `8811` before it tries to bind (see `FINDINGS_CONSOLE_FORCE_PORTS` above), so simply re-running `uv run python -m tools.findings_console.server` clears a stale instance from a prior session automatically. If you still see this, either that env var is set to `0`, or the process holding the port isn't a leftover console instance — check what's actually bound (`netstat -ano | findstr :8811` / `lsof -i :8811`) before assuming.

**Every check shows `no runs`, even after starting the console** — expected. Nothing runs automatically; click a **▶ before**/**▶ after** button on a row, or one of the "Run all" buttons.

**The browser looks stuck/loading after clicking "Run all checks (before + after)"** — expected, not stuck. The request blocks until every check finishes against both targets (roughly two minutes total: C1's SSRF probe alone can take up to 35s per target, L8's self-kill probe ~25-30s per target, C5/C6 each fire multiple sequential requests per target). A single **▶** on one row is near-instant except for those same checks.

**Either target shows `manual` for every check** — that target's `install_token` is empty or wrong. Click its **Re-detect** button to re-read it from its Volume; if that still comes up empty, the Volume's `install_token` file probably doesn't exist yet — make one real request to that deployed gateway first, since it's written on first boot.

**All checks come back `error` immediately for a target** — that target isn't reachable at all (wrong `base_url`, or that Modal deployment is asleep/misconfigured). Confirm with `curl <base_url>/healthz` yourself first.
