# Findings console

A local-only web dashboard that automates the manual `curl`/harness repro steps in [`PLAN.md`](../../PLAN.md) for every Part 1 finding (A1–A6, C1–C6, L1–L10). Run a check, see pass/fail, and compare the state of any finding **before and after your fix, side by side**, per target (local dev, your Modal deployment, whatever you point it at).

It is a testing tool, not part of the graded gateway. It is never deployed to Modal, has no authentication of its own, and should only ever be reached at `127.0.0.1`.

## Quick start

**Run this from the repository root** (the directory containing `pyproject.toml`, `modal_app.py`, `glc/`, `tools/`):

```bash
uv run python -m tools.findings_console.server
```

That command:

1. Looks for a gateway already running at `http://127.0.0.1:8111`.
2. **If it finds one**, reuses it — this is what happens if you already have your own `uv run glc serve` running while you work on Part 1 fixes.
3. **If it doesn't find one**, starts a disposable scratch gateway itself (config isolated under `.findings_console/glc-scratch/`, separate from your real `~/.glc`, with a mock `GEMINI_API_KEY` set so the verbose-errors check has something to observe).
4. Either way, resolves that gateway's install token and sets it as the default target automatically — no copy-pasting.
5. Serves the dashboard on **http://127.0.0.1:8811**.

Open `http://127.0.0.1:8811` in a browser. Every check starts as `no runs` — **nothing runs on its own.** Click **Run** on a row to fire one check, or **Run all checks** to fire every check against the current target in one pass (this one blocks the request until every check finishes — C1's SSRF probe and C5/C6's request bursts are the slow ones, so expect it to take up to a minute).

No setup beyond the repo's normal `uv sync` — every dependency it needs (`fastapi`, `httpx`, `websockets`, `python-multipart`) is already in `pyproject.toml`.

### Stopping it cleanly

Use **`Ctrl+C`** in the terminal it's running in — that lets it run its shutdown hook, which also terminates the scratch gateway it spawned (if it spawned one).

If you started it in the background and have to force-kill it (`taskkill /F`, `kill -9`), that shutdown hook never runs, and the scratch gateway is left orphaned on port 8111. Find and stop both:

```bash
netstat -ano | grep -E ":8111 |:8811 "   # Windows/Git Bash — note both PIDs
lsof -i :8111 -i :8811                    # macOS/Linux
taskkill //F //PID <pid>                  # repeat for both PIDs, Windows
kill <pid>                                # repeat for both PIDs, macOS/Linux
```

### Turning off gateway auto-start

Checks never run on their own — that part is always manual, by design (there is no "auto-run" toggle because there is no auto-run). The only automatic piece is detecting/spawning the local gateway on startup, and that's controlled by one environment variable:

| Variable | Default | Effect when set to `0` |
|---|---|---|
| `FINDINGS_CONSOLE_AUTOSTART_GATEWAY` | `1` | Don't detect or spawn a gateway at all — the target starts with an empty `base_url`/`install_token`. Use this if you specifically want to point at a URL other than `127.0.0.1:8111` (e.g. going straight to a Modal deployment) without the console trying to manage a local gateway. |
| `FINDINGS_CONSOLE_FORCE_PORTS` | `1` | Don't force-kill whatever's listening on `8111`/`8811` before binding. By default, on every startup the console shells out to `netstat`/`taskkill` (Windows) or `lsof`/`kill` (macOS/Linux) to clear a stale, unresponsive process left over from a prior session that wasn't stopped with Ctrl+C — this is what fixes the `only one usage of each socket address` bind error without you having to hunt PIDs by hand. It only ever kills the process actually bound to those two ports, never anything else. Set to `0` if something *other* than an old console/scratch-gateway instance is intentionally using those ports and you don't want it touched. |

```bash
FINDINGS_CONSOLE_AUTOSTART_GATEWAY=0 uv run python -m tools.findings_console.server
```

### Testing against Modal

The auto-start logic only ever looks at `127.0.0.1:8111` — it can't spawn or detect a Modal deployment for you. Once you've deployed (`PLAN.md` T0.2/T1.20), add it as a **second target** through the dashboard's target form:

1. **Getting the token for your Modal deployment**: it lives on the `glc-data` Volume, not on your machine. Download it with the Modal CLI:
   ```bash
   uv run modal volume get glc-data glc/install_token ./modal-install-token.txt
   cat ./modal-install-token.txt
   ```
   (Adjust the volume name if you renamed it in `modal_app.py`. Run `uv run modal volume --help` if this exact subcommand syntax has changed for your installed `modal` version — this is a fast-moving CLI.)
2. In the dashboard's target form: `name=modal-prod`, `base_url=<your *.modal.run URL>`, `install_token=<from the volume, above>` → **Set target**.
3. Click **Run all checks** again. This target's history — and its before/after view on each check's detail page — stays completely independent of your `local` target's.

## What it does

1. **Set a target** at the top of the dashboard — a name, a `base_url` (e.g. `http://localhost:8111` for a local `uv run glc serve`, or your `*.modal.run` URL once deployed), and an `install_token` if you want to exercise the token-gated checks (C2, C3, C6). By default this is filled in for you automatically on startup (see [Quick start](#quick-start)) — you only need to touch this form to add a second target, like your Modal deployment.
2. **Run checks** — click **Run** on any row to fire just that one check, or **Run all checks** to fire every check against the current target in one pass. Nothing runs on its own; every run is something you clicked.
3. **Hover an invariant or attacker code for what it actually means** — `INV-2`, `AR1`, and the check's `kind` (`http`/`ws`/`inprocess`/`static`) are all shorthand. Every place one appears (the dashboard table, the check detail page) it's a native `<abbr title="...">` — hover it and the browser shows the full sentence, no JS needed. The dashboard table has a dedicated **Attacker** column for this. Compound invariant codes (`INV-2/INV-3`) and the one non-numbered label (`supply chain`, on A5) are handled too. A **legend** at the bottom of the dashboard spells out every invariant, attacker role, and check kind in one place if you'd rather not hover row by row — `ws` in particular ("WebSocket connection") is easy to misread as an abbreviation for something else at a glance, so it's shown as a full label everywhere, not just the raw code.
4. **Read the verdict** — each run is classified as:

   | Verdict | Meaning |
   |---|---|
   | `vulnerable` | the attack still works |
   | `mitigated` | a defense-in-depth fix is in place, but the root cause isn't fully closed (see `PLAN.md`'s "closed vs. mitigated" distinction) |
   | `closed` | fully fixed |
   | `manual` | this check needs something the tool can't supply on its own (usually an `install_token`) — go verify it yourself |
   | `error` | the check itself failed to run (network error, timeout, unexpected response shape) — not a verdict on the finding |

5. **Compare before/after** — click into any check (`/check/<id>`) to see, **for each target you've ever run it against**, the "before" run next to the latest one, in one pane. Test locally while iterating, then point the target at your live Modal URL — each target gets its own independent before/after, so a fix you verified locally can never make a still-vulnerable Modal deployment look fixed.
6. **Pin a specific run as the baseline** — by default, "before" is just the *earliest* recorded run for that target, which breaks the moment your first attempt was a flaky `error` rather than a genuine `vulnerable`, or you've retried a check enough times that "earliest" no longer means "the real starting point." Every row in a check's **Full history** table has a **Pin as before** button — click it on whichever run actually shows the vulnerability wide open, and that exact run becomes "before" for every future comparison, regardless of how many more times you re-run the check. The pinned panel is labeled `Before (pinned baseline)` with a `PINNED BASELINE` badge; click **Unpin** to go back to the automatic earliest-run behavior. Pins are per `(check, target)` — pinning `A1`'s baseline for `local` has no effect on `A1`'s baseline for `modal-prod`.
7. **Clear history** — **Clear all history** on the dashboard wipes every run and every pin, for every check and every target (confirmation required — this is irreversible). **Clear history for this check**, on a check's detail page, does the same but scoped to just that one check. Use these between test cycles (e.g. after a big refactor where old evidence is no longer meaningful) rather than accumulating runs forever.
8. **Export** — `Export FINDINGS.md draft` (`GET /api/export.md`) dumps every finding, grouped exactly like the dashboard (see [The 22 checks](#the-22-checks) below), each one leading with the invariant and attacker-role sentence `ASSIGNMENT.md` asks for — spelled out in full (e.g. `INV-2 (Every action must be checked against the actual user, tenant, and final arguments.)`), not left as a bare code — plus whatever's been run so far. A real starting point for the `FINDINGS.md` deliverable, not just a data dump.
9. **See which commit actually fixed something** — every run is stamped with the local checkout's current git commit (short SHA) at the moment it ran, captured automatically; no typing a commit hash in by hand. Once a check's verdict reaches `closed` or `mitigated`, that run's panel and its row in **Full history** both show `Fixed in commit: <sha>` — including in the `Export` output. If your working tree has uncommitted changes when a check passes, the commit is suffixed `(uncommitted changes present)`, since a "fix" sitting in an uncommitted diff isn't really pinned to that commit yet.

Every run is logged **append-only** to a local SQLite file while it exists — deliberately mirroring `glc/audit/store.py`'s own append-only pattern, applied to your own testing tool: nothing is ever *edited*, and normal use never deletes anything either. The **Clear** actions are the one deliberate exception, and they're explicit, confirmed, user-triggered resets — a check itself can never delete or edit history, only add to it.

## The 22 checks

One check per row of `PLAN.md`'s ground-truth table. `L9` is a UI-only alias of `C2` — they're the literal same bug (cross-channel envelope spoofing), named twice in the assignment.

### How they're grouped in the dashboard and the export

Both the dashboard and `Export FINDINGS.md draft` organize findings the way **Session 12 §6/§7 themselves** group them — by what the Modal migration did to each one — not by the technical `kind` below. Four sections, in this order (`tools/findings_console/sections.py`):

| Section | Contents |
|---|---|
| **A. Introduced or elevated by the migration (the highest-value class here)** | A1–A6 |
| **B. Inherited in-process leaks the migration did NOT close (all still live)** | B1–B8 — a *condensed* 8-of-10 subset of the ten leaks below, labeled `B1 (=L1)` through `B8 (=L7)`. Skips L6 and L9, since those are already covered under A3 and C2 respectively — matching §6's own text exactly. |
| **C. Inherited endpoint/logic issues, now internet-reachable** | C1–C6 |
| **The ten code leaks the migration leaves open** | L1–L10, all ten, in full — the complete §7 catalog, including L6 and L9 again (deliberately — §7 gives them their own full write-up even though §6 already cross-referenced them under A/C) |

Every entry is still the same underlying `Check` regardless of which section(s) it appears in — clicking **Run** on `B1` and clicking **Run** on `L1` later run and log the identical check, just displayed twice, exactly like the lecture text itself mentions leak 6 and leak 9 twice (once as a cross-reference, once as a full write-up).

### What each check actually does when it runs

| Kind | Runs against | Checks | What "target" means for this kind |
|---|---|---|---|
| `http` | `target.base_url` | A1, A2, C1, C4, C5, C6 | your local dev server or deployed gateway |
| `ws` | `target.base_url` | C2 (=L9), C3 | same, over a WebSocket |
| `inprocess` | **your local checkout only** | L1, L2, L3, L4, L5, L8, L10 | ignores `base_url` — spawns an isolated subprocess importing the local `glc` package |
| `static` | **your local checkout only** | A3, A4, A5, A6, L6, L7 | ignores `base_url` — reads `modal_app.py` / source files directly |

**Why in-process and static checks can't test a deployed target:** there is no way to inject code into, or read the source of, a live Modal container from outside it. These always report on the code in your working directory, not on whatever's actually running on Modal. If you've fixed the code but haven't redeployed yet, these will show `closed` while your `http`/`ws` checks against the stale deployment still show `vulnerable` — that's correct, not a bug; redeploy and re-run the `http`/`ws` checks to confirm the live gateway matches.

## Known limitations (found by actually running this against a live `glc serve`, not assumed)

- **L1, L3, L4, L5, L8 will *always* report `vulnerable` locally, even after you've fixed them.** These are structural leaks that exist because Python has no in-process ACL — the only real fix is process/container separation (`PLAN.md` Move B, task T1.11). A local subprocess can only ever prove the attack surface *exists* in shared-process code; it can't observe whether your deployed adapter containers are actually separated, because that requires running this same snippet from inside a live adapter container, which is outside this tool's reach. Mark these `closed` in `FINDINGS.md` manually once you've verified Move B is deployed.
- **C4 (verbose upstream errors) under-reports as `closed` if the target has zero provider keys configured.** No provider is even attempted, so there's nothing to leak. Set at least one mock key (e.g. `GEMINI_API_KEY=mock-not-real`) on the target so a real upstream attempt happens before trusting this check's verdict.
- **C1 (SSRF) is a text-matching heuristic, not a network-level oracle.** It looks for the word "block" in a `400` response body. Make your fix's rejection message say something like `"blocked: private/loopback address"` so this check can detect it — and read the evidence panel yourself either way.
- **C2/L9 requires both the route channel and the spoofed channel to be `enabled: true`** in `channels.yaml` for the probe to reach the actual vulnerable code path (rather than being dropped earlier by the unrelated "channel disabled" gate). The check uses `webui`→`whatsapp` by default, since those are enabled out of the box in this repo's packaged `channels.yaml`; if you change that config, update the check.
- **C5 (rate limiting) fires up to 15 rapid requests, and C6 (pairing brute force) fires up to 20** — against a real remote Modal deployment these count as real invocations. Prefer running these against your local dev server unless you specifically want to confirm the live deployment's behavior.

## Data storage

Every run is logged to `.findings_console/console.sqlite` at the repo root (gitignored — see `.gitignore`). Override the path with `FINDINGS_CONSOLE_DB=/path/to/file.sqlite` if you want a separate log per branch or experiment. In-process checks never touch this file or your real `~/.glc` — each one gets a fresh scratch `GLC_CONFIG_DIR` in a temp directory, so `L2`'s check (which genuinely runs `DELETE FROM audit_log`) and `L3`'s (which genuinely writes a pairing record) can never corrupt your actual local gateway state.

If the console auto-started a scratch gateway (see [Quick start](#quick-start--one-command-does-everything)), that gateway's own config — its `install_token`, `audit.sqlite`, `pairings.sqlite` — lives at `.findings_console/glc-scratch/` (also gitignored). It persists across restarts of the console, so the same scratch gateway keeps the same install token every time; delete that directory if you want a completely fresh scratch identity.

## Package layout

```
tools/findings_console/
  models.py            Check, CheckResult, Verdict, Target, and the INV/AR/kind description tables
  sections.py           groups checks into A/B/C/ten-leaks, matching Session 12 §6/§7
  store.py               append-only SQLite log (record/history/earliest/latest, pins, per-target variants)
  gitinfo.py              captures the local checkout's current commit for every run
  harness.py               spawns an isolated subprocess for in-process checks, scratch config dir
  checks_http.py            A1, A2, C1, C4, C5, C6
  checks_ws.py               C2/L9, C3
  checks_inprocess.py        L1, L2, L3, L4, L5, L8, L10
  checks_static.py           A3, A4, A5, A6, L6, L7
  registry.py                aggregates all Check objects into one id-keyed registry (+ the L9 alias)
  runner.py                  executes a Check against a Target, stamps the git commit, records the result
  render.py                  plain-Python HTML rendering (no template engine dependency)
  server.py                  FastAPI app + routes + `main()` entry point
```

No new runtime dependency was needed beyond `python-multipart` (added as a **dev** dependency — required by FastAPI's `Form(...)` for the plain HTML `<form>` posts the dashboard uses; it never ships with the actual `glc` gateway).

## Troubleshooting

**`only one usage of each socket address ... 8811` (or `8111`)** — self-healing as of the port-guard: every startup force-kills whatever's already listening on `8111`/`8811` before it tries to bind (see `FINDINGS_CONSOLE_FORCE_PORTS` above), so simply re-running `uv run python -m tools.findings_console.server` clears a stale instance from a prior session automatically. If you still see this, either that env var is set to `0`, or the process holding the port isn't a leftover console/gateway — check what's actually bound (`netstat -ano | findstr :8811` / `lsof -i :8811`) before assuming.

**Every check shows `no runs`, even after starting the console** — expected. Nothing runs automatically; click **Run** on a row or **Run all checks**.

**The browser looks stuck/loading after clicking "Run all checks"** — expected, not stuck. The request blocks until every check finishes (C1's SSRF probe alone can take up to 35s, waiting past the gateway's own 30s internal fetch timeout; C5/C6 each fire multiple sequential requests). Give it up to a minute before assuming something's wrong; a single **Run** on one row is near-instant except for those same three checks.

**Every check shows `manual`** — the target's `install_token` is empty or wrong. If you're on the auto-started scratch gateway this shouldn't happen; if you added your own target (e.g. Modal), double check the token you pasted — see [Testing against Modal](#testing-against-modal) or, for a local gateway you started yourself, `uv run glc token` (same `GLC_CONFIG_DIR` your `glc serve` is using).

**All 22 checks come back `error` immediately** — the gateway target isn't reachable at all (wrong `base_url`, or a Modal deployment that's asleep/misconfigured). Confirm with `curl <base_url>/healthz` yourself first.
