# Findings console

A local-only web dashboard that automates the manual `curl`/harness repro steps in [`PLAN.md`](../../PLAN.md) for every Part 1 finding (A1–A6, C1–C6, L1–L10). Run a check, see pass/fail, and compare the state of any finding **before and after your fix, side by side** — and on every check's own page, see the exact command that reproduces the attack and a plain-English summary of the fix.

It is a testing tool, not part of the graded gateway. It is never deployed to Modal, has no authentication of its own, and should only ever be reached at `127.0.0.1`.

**Only your deployed Modal gateway is a meaningful target.** This assignment is about hardening the *deployed* app — a local `uv run glc serve` stand-in doesn't exercise the container/Secret separation most of these findings are actually about (A3–A4, L1, L3–L5, L8). There is no local-gateway option or auto-start in this console; every HTTP/WS check fires at the `*.modal.run` URL you configure.

## Quick start

**Run this from the repository root** (the directory containing `pyproject.toml`, `modal_app.py`, `glc/`, `tools/`):

1. Deploy first if you haven't (see the main [README](../../README.md)'s Modal setup section):
   ```bash
   modal deploy modal_app.py
   ```
2. Start the console:
   ```bash
   uv run python -m tools.findings_console.server
   ```
3. Open `http://127.0.0.1:8811`.

That's it — **no copy-pasting a URL or token.** On startup, the console reads `modal_app.py` for the App name, the ASGI function name, the Volume name, and the configured data path, then asks the Modal SDK for that Function's live `*.modal.run` URL and reads the install token straight out of the Volume. This needs no `modal` CLI subprocess, just the same Modal auth (`modal token new` / `modal setup`) you already used to deploy. The dashboard's status panel says whether it worked; if the app isn't deployed yet or your local Modal auth isn't set up, the target form explains what's missing and a **Re-detect from modal_app.py** button is always there to retry once it is. Setting `GLC_MODAL_URL`/`GLC_MODAL_INSTALL_TOKEN` (or pasting into the form) overrides auto-detection, if you specifically want to point at something else.

Every check starts as `no runs` — **nothing runs on its own.** Click **Run** on a row to fire one check, or **Run all checks** to fire every check against the current target in one pass (this one blocks the request until every check finishes — C1's SSRF probe and C5/C6's request bursts are the slow ones, so expect it to take up to a minute).

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
| `GLC_MODAL_URL` | unset | Overrides auto-detection — set this if you specifically want the target's `base_url` to be something other than what `modal_app.py` + the Modal SDK resolve to. |
| `GLC_MODAL_INSTALL_TOKEN` | unset | Same, for `install_token`. |
| `FINDINGS_CONSOLE_DB` | `.findings_console/console.sqlite` | Override the SQLite log location. |
| `FINDINGS_CONSOLE_FORCE_PORTS` | `1` | Set to `0` to stop the console from force-killing whatever's listening on `8811` before it binds (by default it shells out to `netstat`/`taskkill` or `lsof`/`kill` to clear a stale instance from a prior session that wasn't stopped with Ctrl+C). |

## What it does

1. **Target auto-detection** — on startup, the console parses `modal_app.py` for the App name, ASGI function name, Volume name, and configured data path, then asks the Modal SDK for the deployed Function's `*.modal.run` URL and reads the install token out of the Volume directly (`tools/findings_console/modal_detect.py`). No `modal` CLI subprocess, no copy-pasting — it needs only the same Modal auth you used to deploy. Click **Re-detect from modal_app.py** any time (e.g. after a fresh `modal deploy`) to refresh both fields; `GLC_MODAL_URL`/`GLC_MODAL_INSTALL_TOKEN` or typing into the form overrides it.
2. **Run checks** — click **Run** on any row to fire just that one check, or **Run all checks** to fire every check against the current target in one pass. Nothing runs on its own; every run is something you clicked.
3. **Hover an invariant or attacker code for what it actually means** — `INV-2`, `AR1`, and the check's `kind` (`http`/`ws`/`inprocess`/`static`) are all shorthand. Every place one appears (the dashboard table, the check detail page) it's a native `<abbr title="...">` — hover it and the browser shows the full sentence, no JS needed. The dashboard table has a dedicated **Attacker** column for this. Compound invariant codes (`INV-2/INV-3`) and the one non-numbered label (`supply chain`, on A5) are handled too. A **legend** at the bottom of the dashboard spells out every invariant, attacker role, and check kind in one place if you'd rather not hover row by row — `ws` in particular ("WebSocket connection") is easy to misread as an abbreviation for something else at a glance, so it's shown as a full label everywhere, not just the raw code.
4. **Read the verdict** — each run is classified as:

   | Verdict | Meaning |
   |---|---|
   | `vulnerable` | the check ran the attack and it succeeded — no fix in effect yet |
   | `mitigated` | either the attack (or an equally-easy alternate route to the same outcome, for the same attacker role) still succeeds but the check confirmed real, verified progress — reduced impact, or the tamper is now detected — **or** the check is a heuristic that can't fully confirm closure on its own; read the evidence |
   | `closed` | the check directly confirmed the demonstrated attack now fails, unconditionally, for the attacker role it names — a *stronger* attacker role this check doesn't exercise may still have a different route (check FINDINGS.md) |
   | `manual` | this check needs something the tool can't supply on its own (usually an `install_token`) — go verify it yourself |
   | `error` | the check itself failed to run (network error, timeout, unexpected response shape) — not a verdict on the finding |

   The dashboard's own **Reference → Verdict codes** legend spells this out in full — it's the single source of truth `models.py`'s `VERDICT_DESCRIPTIONS` and every check's actual verdict logic is written against, so it never drifts out of sync with what the checks actually do.

5. **Compare before/after** — click into any check (`/check/<id>`) to see, **for each target you've ever run it against**, the "before" run next to the latest one, in one pane. Redeploy a fix and re-run to see it flip from `vulnerable` to `closed`/`mitigated` against the same deployed URL.
6. **Read the attack command and the fix** — every check's own page has an **Attack command** box (the literal `curl`/Python you'd run by hand to reproduce it, with your current target's URL and token already substituted in) and a **How this is fixed** box (which file changed and the actual mechanism, not just "see the commit").
7. **Pin a specific run as the baseline** — by default, "before" is just the *earliest* recorded run for that target, which breaks the moment your first attempt was a flaky `error` rather than a genuine `vulnerable`, or you've retried a check enough times that "earliest" no longer means "the real starting point." Every row in a check's **Full history** table has a **Pin as before** button — click it on whichever run actually shows the vulnerability wide open, and that exact run becomes "before" for every future comparison, regardless of how many more times you re-run the check. The pinned panel is labeled `Before (pinned baseline)` with a `PINNED BASELINE` badge; click **Unpin** to go back to the automatic earliest-run behavior.
8. **Clear history** — **Clear all history** on the dashboard wipes every run and every pin, for every check and every target (confirmation required — this is irreversible). **Clear history for this check**, on a check's detail page, does the same but scoped to just that one check. Use these between test cycles (e.g. after a big refactor where old evidence is no longer meaningful) rather than accumulating runs forever.
9. **Export** — `Export FINDINGS.md draft` (`GET /api/export.md`) dumps every finding, grouped exactly like the dashboard (see [The 22 checks](#the-22-checks) below), each one leading with the invariant and attacker-role sentence `ASSIGNMENT.md` asks for — spelled out in full (e.g. `INV-2 (Every action must be checked against the actual user, tenant, and final arguments.)`), not left as a bare code — plus whatever's been run so far. A real starting point for the `FINDINGS.md` deliverable, not just a data dump.
10. **See which commit actually fixed something** — every run is stamped with the local checkout's current git commit (short SHA) at the moment it ran, captured automatically; no typing a commit hash in by hand. Once a check's verdict reaches `closed` or `mitigated`, that run's panel and its row in **Full history** both show `Fixed in commit: <sha>` — including in the `Export` output. If your working tree has uncommitted changes when a check passes, the commit is suffixed `(uncommitted changes present)`, since a "fix" sitting in an uncommitted diff isn't really pinned to that commit yet.

Every run is logged **append-only** to a local SQLite file while it exists — deliberately mirroring `glc/audit/store.py`'s own append-only pattern, applied to your own testing tool: nothing is ever *edited*, and normal use never deletes anything either. The **Clear** actions are the one deliberate exception, and they're explicit, confirmed, user-triggered resets — a check itself can never delete or edit history, only add to it.

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

Every entry is still the same underlying `Check` regardless of which section(s) it appears in — clicking **Run** on `B1` and clicking **Run** on `L1` later run and log the identical check, just displayed twice, exactly like the lecture text itself mentions leak 6 and leak 9 twice (once as a cross-reference, once as a full write-up).

### What each check actually does when it runs

| Kind | Runs against | Checks | What "target" means for this kind |
|---|---|---|---|
| `http` | `target.base_url` | A1, A2, C1, C4, C5, C6 | your deployed `*.modal.run` gateway |
| `ws` | `target.base_url` | C2 (=L9), C3 | same, over a WebSocket |
| `live_probe` | **calls a deployed Function directly via the Modal SDK** | L1, L3, L4, L8 | ignores `target.base_url` — calls a Modal Function by name (detected from `modal_app.py`, see `modal_detect.py`), not an HTTP endpoint. L1/L3/L4 call `glc-adapter-shape-probe`; L8 calls the separate `glc-adapter-shape-self-kill-probe` and also checks `target.base_url`'s `/healthz` before and after. Requires the app to be deployed with these Functions present. |
| `inprocess` | **your local checkout only** | L2, L5, L10 | ignores `base_url` — spawns an isolated subprocess importing the local `glc` package |
| `static` | **your local checkout only** | A3, A4, A5, A6, L6, L7 | ignores `base_url` — reads `modal_app.py` / source files directly |

**Why in-process and static checks can't test a deployed target:** there is no way to inject code into, or read the source of, a live Modal container from outside it. These always report on the code in your working directory, not on whatever's actually running on Modal. If you've fixed the code but haven't redeployed yet, these will show `closed`/`mitigated` while your `http`/`ws` checks against the stale deployment still show `vulnerable` — that's correct, not a bug; redeploy and re-run the `http`/`ws` checks to confirm the live gateway matches. `live_probe` checks split the difference: they don't touch `target.base_url`, but they do require a real deployment, since they call a Function that only exists once you've deployed.

## Known limitations (found by actually running this against a live deployment, not assumed)

- **L1, L3, L4, L8 now report `closed` for real, verified against your actual deployment — not a documented assumption.** `modal_app.py` deploys `glc-adapter-shape-probe` (env/pairing/token checks) and `glc-adapter-shape-self-kill-probe` (kept separate so a self-kill test never risks the read-only ones), both built with the exact same container shape as a real catalogue adapter (no LLM Secret, no Volume mount), and these four checks call them directly and report what they actually observe. L8 additionally confirms `target.base_url`'s `/healthz` stays healthy immediately before and after the self-kill — takes ~25-30s, not instant, since Modal reports the container's abnormal exit through the call itself rather than instantly. If the app isn't deployed with these Functions yet, they report `error`, not a guess either way — deploy (`modal deploy modal_app.py`) and re-run.
- **L5 reports `mitigated`, not `vulnerable` or `closed`, once `glc/policy/engine.py`'s hardening is deployed.** The exact one-liner the finding names now raises `AttributeError`, but the check itself then demonstrates the documented residual gap (a direct `__dict__` write bypasses that check) — see its "How this is fixed" box.
- **C4 (verbose upstream errors) under-reports as `closed` if the target has zero provider keys configured.** No provider is even attempted, so there's nothing to leak. Set at least one mock key (e.g. `GEMINI_API_KEY=mock-not-real`) on the target so a real upstream attempt happens before trusting this check's verdict.
- **C1 (SSRF) is a text-matching heuristic, not a network-level oracle.** It looks for the word "block" in a `400` response body. Make your fix's rejection message say something like `"blocked: private/loopback address"` so this check can detect it — and read the evidence panel yourself either way.
- **C2/L9 requires both the route channel and the spoofed channel to be `enabled: true`** in `channels.yaml` for the probe to reach the actual vulnerable code path (rather than being dropped earlier by the unrelated "channel disabled" gate). The check uses `webui`→`whatsapp` by default, since those are enabled out of the box in this repo's packaged `channels.yaml`; if you change that config, update the check.
- **C5 (rate limiting) fires up to 35 rapid requests, and C6 (pairing brute force) fires up to 20 — against your real deployed gateway.** That's intentional: only the deployed gateway is what's actually graded, so there's no local substitute to redirect these at. Expect this to briefly drive real (if tiny) usage.

## Data storage

Every run is logged to `.findings_console/console.sqlite` at the repo root (gitignored — see `.gitignore`). Override the path with `FINDINGS_CONSOLE_DB=/path/to/file.sqlite` if you want a separate log per branch or experiment. In-process checks never touch this file or your real `~/.glc` — each one gets a fresh scratch `GLC_CONFIG_DIR` in a temp directory, so `L2`'s check (which genuinely runs `DELETE FROM audit_log`) and `L3`'s (which genuinely writes a pairing record) can never corrupt your actual local gateway state.

## Package layout

```
tools/findings_console/
  models.py            Check, CheckResult, Verdict, Target, and the INV/AR/kind description tables
  sections.py           groups checks into A/B/C/ten-leaks, matching Session 12 §6/§7
  store.py               append-only SQLite log (record/history/earliest/latest, pins, per-target variants)
  gitinfo.py              captures the local checkout's current commit for every run
  harness.py               spawns an isolated subprocess for in-process checks, scratch config dir
  modal_detect.py           parses modal_app.py + calls the Modal SDK to auto-detect the target and app name
  checks_http.py            A1, A2, C1, C4, C5, C6
  checks_ws.py               C2/L9, C3
  checks_inprocess.py        L2, L5, L10
  checks_live_probe.py       L1, L3, L4, L8 — calls the two live probe Functions for a real, live-measured verdict
  checks_static.py           A3, A4, A5, A6, L6, L7
  registry.py                aggregates all Check objects into one id-keyed registry (+ the L9 alias)
  runner.py                  executes a Check against a Target, stamps the git commit, records the result
  render.py                  plain-Python HTML rendering (no template engine dependency)
  server.py                  FastAPI app + routes + `main()` entry point
```

No new runtime dependency was needed beyond `python-multipart` (added as a **dev** dependency — required by FastAPI's `Form(...)` for the plain HTML `<form>` posts the dashboard uses; it never ships with the actual `glc` gateway).

## Troubleshooting

**`only one usage of each socket address ... 8811`** — self-healing as of the port-guard: every startup force-kills whatever's already listening on `8811` before it tries to bind (see `FINDINGS_CONSOLE_FORCE_PORTS` above), so simply re-running `uv run python -m tools.findings_console.server` clears a stale instance from a prior session automatically. If you still see this, either that env var is set to `0`, or the process holding the port isn't a leftover console instance — check what's actually bound (`netstat -ano | findstr :8811` / `lsof -i :8811`) before assuming.

**Every check shows `no runs`, even after starting the console** — expected. Nothing runs automatically; click **Run** on a row or **Run all checks**.

**The browser looks stuck/loading after clicking "Run all checks"** — expected, not stuck. The request blocks until every check finishes (C1's SSRF probe alone can take up to 35s, waiting past the gateway's own 30s internal fetch timeout; C5/C6 each fire multiple sequential requests). Give it up to a minute before assuming something's wrong; a single **Run** on one row is near-instant except for those same three checks.

**Every check shows `manual`** — the target's `install_token` is empty or wrong. Click **Re-detect from modal_app.py** to re-read it from the Volume; if that still comes up empty, check the dashboard's status panel for why (e.g. the Volume's `install_token` file doesn't exist yet — make one real request to the deployed gateway first, since it's written on first boot).

**All 22 checks come back `error` immediately** — the target isn't reachable at all (wrong `base_url`, or the Modal deployment is asleep/misconfigured). Confirm with `curl <base_url>/healthz` yourself first.
