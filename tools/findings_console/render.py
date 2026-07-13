"""Plain-Python HTML rendering — no template engine dependency (Jinja2
isn't in pyproject.toml and this tool shouldn't need to add one).
Every dynamic value is html.escape()'d before interpolation.
"""

from __future__ import annotations

import time
from html import escape as e

from tools.findings_console.models import (
    ATTACKER_ROLES,
    INVARIANT_DESCRIPTIONS,
    KIND_DESCRIPTIONS,
    KIND_LABELS,
    Check,
    Target,
    Verdict,
    describe_invariant,
)
from tools.findings_console.sections import Section, build_sections

_VERDICT_COLOR = {
    Verdict.VULNERABLE: "#ef4444",
    Verdict.MITIGATED: "#f59e0b",
    Verdict.CLOSED: "#22c55e",
    Verdict.MANUAL: "#94a3b8",
    Verdict.ERROR: "#a855f7",
}

_STYLE = """
<style>
  :root {
    color-scheme: dark;
    --bg: #0a0d12;
    --bg-raised: #10151c;
    --bg-sunken: #06080b;
    --border: #1f2937;
    --border-strong: #2d3947;
    --text: #e5eaf1;
    --text-muted: #8b96a8;
    --text-faint: #5b6576;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
    --accent-bg: rgba(59, 130, 246, .12);
    --danger: #ef4444;
    --danger-bg: rgba(239, 68, 68, .10);
    --success: #22c55e;
    --success-bg: rgba(34, 197, 94, .10);
    --radius: 10px;
    --radius-sm: 6px;
    --sp-1: .25rem;
    --sp-2: .5rem;
    --sp-3: .75rem;
    --sp-4: 1rem;
    --sp-5: 1.5rem;
    --sp-6: 2.25rem;
    --sp-7: 3.5rem;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text);
    font-family: ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
    margin: 0; padding: var(--sp-6) var(--sp-5) var(--sp-7);
    line-height: 1.6; font-size: 14px;
  }
  main { max-width: 1180px; margin: 0 auto; }
  h1 { font-size: 1.4rem; margin: 0 0 var(--sp-2); font-weight: 700; letter-spacing: -.01em; }
  h2.section-heading {
    font-size: .78rem; font-weight: 700; text-transform: uppercase; letter-spacing: .07em;
    color: var(--text-muted); margin: var(--sp-6) 0 var(--sp-3);
    padding-bottom: var(--sp-2); border-bottom: 1px solid var(--border);
  }
  h3 { font-size: .85rem; margin: 0 0 var(--sp-2); color: var(--text); font-weight: 600; }
  .lede { color: var(--text-muted); font-size: .88rem; max-width: 72ch; margin-bottom: var(--sp-5); }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  a:focus-visible, button:focus-visible, input:focus-visible {
    outline: 2px solid var(--accent); outline-offset: 2px; border-radius: var(--radius-sm);
  }

  .table-wrap { overflow-x: auto; margin-bottom: var(--sp-5); border: 1px solid var(--border); border-radius: var(--radius); }
  table { border-collapse: collapse; width: 100%; font-size: .84rem; }
  th, td { text-align: left; padding: .55rem .75rem; border-bottom: 1px solid var(--border); white-space: nowrap; }
  td:nth-child(2) { white-space: normal; }
  th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: .68rem;
       letter-spacing: .06em; background: var(--bg-sunken); }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover td { background: var(--bg-raised); }

  .badge { display: inline-block; padding: .2rem .55rem; border-radius: 999px; font-size: .7rem;
           font-weight: 700; color: #08090b; letter-spacing: .01em; }
  .badge.neutral { background: #334155; color: var(--text-muted); }

  .panel { background: var(--bg-raised); border: 1px solid var(--border); border-radius: var(--radius);
           padding: var(--sp-4); margin-bottom: var(--sp-4); }
  .panel.notice { border-color: var(--border-strong); font-size: .82rem; color: var(--text-muted); }

  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-4); }
  @media (max-width: 760px) { .grid2 { grid-template-columns: 1fr; } }

  pre { white-space: pre-wrap; word-break: break-word; background: var(--bg-sunken);
        border: 1px solid var(--border); padding: var(--sp-3); border-radius: var(--radius-sm);
        max-height: 280px; overflow: auto; font-size: .76rem; color: var(--text-muted); margin: var(--sp-3) 0 0; }

  label { display: block; font-size: .68rem; text-transform: uppercase; letter-spacing: .06em;
          color: var(--text-muted); margin-bottom: var(--sp-1); }
  input[type=text] { width: 100%; background: var(--bg-sunken); border: 1px solid var(--border-strong);
                      color: var(--text); padding: .5rem .6rem; border-radius: var(--radius-sm);
                      font-family: inherit; font-size: .84rem; }
  .form-row { display: grid; grid-template-columns: 1fr 2fr 2fr auto; gap: var(--sp-3); align-items: end; }
  @media (max-width: 760px) { .form-row { grid-template-columns: 1fr; } }

  button { background: var(--bg-sunken); border: 1px solid var(--border-strong); color: var(--text);
           padding: .5rem .95rem; border-radius: var(--radius-sm); cursor: pointer;
           font-family: inherit; font-size: .84rem; font-weight: 500; transition: background .15s, border-color .15s; }
  button:hover { background: var(--bg-raised); border-color: var(--text-faint); }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 600; }
  button.primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
  button.danger { background: transparent; border-color: #5c2020; color: #fca5a5; }
  button.danger:hover { background: var(--danger-bg); border-color: var(--danger); }
  button.small { padding: .2rem .6rem; font-size: .72rem; }
  .actions { display: flex; flex-wrap: wrap; gap: var(--sp-2); align-items: center; margin-bottom: var(--sp-5); }
  .actions form, .actions a { display: inline-flex; }

  .meta { color: var(--text-faint); font-size: .72rem; }
  abbr.hint { border-bottom: 1px dotted var(--text-faint); text-decoration: none; cursor: help; color: inherit; }

  .pin-badge { display: inline-block; padding: .12rem .5rem; border-radius: 999px; font-size: .66rem;
               font-weight: 700; background: var(--accent-bg); color: #93c5fd; letter-spacing: .03em; }
  .commit { color: var(--accent); font-size: .78rem; font-family: inherit; }

  /* Definition-list detail block on the check page */
  dl.detail-list { margin: 0 0 var(--sp-4); border: 1px solid var(--border); border-radius: var(--radius);
                    overflow: hidden; background: var(--bg-raised); }
  dl.detail-list > div { display: grid; grid-template-columns: 200px 1fr; gap: var(--sp-4);
                          padding: var(--sp-3) var(--sp-4); border-bottom: 1px solid var(--border); }
  dl.detail-list > div:last-child { border-bottom: none; }
  @media (max-width: 620px) { dl.detail-list > div { grid-template-columns: 1fr; gap: var(--sp-1); } }
  dl.detail-list dt { color: var(--text-muted); font-size: .72rem; font-weight: 700; text-transform: uppercase;
                       letter-spacing: .05em; padding-top: .15rem; }
  dl.detail-list dd { margin: 0; color: var(--text); line-height: 1.65; max-width: 68ch; }
  dl.detail-list dd .term { color: var(--text); font-weight: 700; }

  /* Before / after comparison */
  .compare-wrap { margin-bottom: var(--sp-5); }
  .compare-target { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
                     color: var(--text-muted); margin: var(--sp-4) 0 var(--sp-2); }
  .compare-card { border-radius: var(--radius); padding: var(--sp-4); background: var(--bg-raised);
                   border: 1px solid var(--border); border-top: 3px solid var(--border-strong); }
  .compare-card.before { border-top-color: var(--danger); background: linear-gradient(180deg, var(--danger-bg), var(--bg-raised) 55%); }
  .compare-card.after { border-top-color: var(--success); background: linear-gradient(180deg, var(--success-bg), var(--bg-raised) 55%); }
  .compare-eyebrow { display: inline-flex; align-items: center; gap: .35rem; font-size: .66rem; font-weight: 700;
                      text-transform: uppercase; letter-spacing: .08em; padding: .18rem .6rem; border-radius: 999px;
                      margin-bottom: var(--sp-2); }
  .compare-eyebrow.before { background: rgba(239, 68, 68, .16); color: #fca5a5; }
  .compare-eyebrow.after { background: rgba(34, 197, 94, .16); color: #86efac; }
  .compare-meta { color: var(--text-faint); font-size: .74rem; margin-bottom: var(--sp-2); }
  .compare-summary { color: var(--text); font-size: .86rem; }
  .compare-empty { color: var(--text-faint); font-size: .82rem; font-style: italic; }

  /* Reference legend */
  .legend-group { margin-bottom: var(--sp-5); }
  .legend-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: var(--sp-3); }
  .legend-card { background: var(--bg-raised); border: 1px solid var(--border); border-radius: var(--radius-sm);
                 padding: var(--sp-3) var(--sp-4); }
  .legend-card .code { display: inline-block; font-weight: 700; color: var(--accent); font-size: .78rem;
                        margin-bottom: var(--sp-1); }
  .legend-card p { margin: 0; color: var(--text-muted); font-size: .8rem; line-height: 1.6; }

  @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
"""


def _badge(verdict: Verdict) -> str:
    color = _VERDICT_COLOR.get(verdict, "#94a3b8")
    return f'<span class="badge" style="background:{color}">{e(verdict.value)}</span>'


def _inv_html(code: str) -> str:
    """The raw code (e.g. "INV-2") with its full text as a native
    hover tooltip — an <abbr title="..."> needs no JS and works the
    same in every browser."""
    if not code:
        return ""
    desc = describe_invariant(code)
    return f'<abbr class="hint" title="{e(desc)}">{e(code)}</abbr>' if desc else e(code)


def _ar_html(code: str) -> str:
    """Same treatment as _inv_html, for an attacker-role code."""
    if not code:
        return '<span class="meta">not classified</span>'
    desc = ATTACKER_ROLES.get(code)
    return f'<abbr class="hint" title="{e(desc)}">{e(code)}</abbr>' if desc else e(code)


def _kind_html(kind_value: str) -> str:
    """The raw kind ("ws") is opaque at a glance — show the plain-English
    label instead, with the full explanation as a hover tooltip."""
    label = KIND_LABELS.get(kind_value, kind_value)
    desc = KIND_DESCRIPTIONS.get(kind_value)
    return f'<abbr class="hint" title="{e(desc)}">{e(label)}</abbr>' if desc else e(label)


def _page(title: str, body: str) -> str:
    return f"""<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>{_STYLE}</head>
<body><main>{body}</main></body></html>"""


def target_form(target: Target) -> str:
    return f"""
<form class="panel" method="post" action="/api/target">
  <h3>Target</h3>
  <p class="meta" style="margin:0 0 var(--sp-3)">HTTP and WebSocket checks run against this. In-process and static checks always run locally, regardless of this setting.</p>
  <div class="form-row">
    <div>
      <label for="target-name">Name</label>
      <input id="target-name" type="text" name="name" value="{e(target.name)}">
    </div>
    <div>
      <label for="target-url">Base URL</label>
      <input id="target-url" type="text" name="base_url" value="{e(target.base_url)}">
    </div>
    <div>
      <label for="target-token">Install token</label>
      <input id="target-token" type="text" name="install_token" value="{e(target.install_token or "")}"
             placeholder="needed for C2, C3, C6">
    </div>
    <div><button type="submit" class="primary">Set target</button></div>
  </div>
</form>
"""


def _check_row(label: str, c: Check, latest: dict[str, dict]) -> str:
    run = latest.get(c.id)
    if run:
        badge = _badge(Verdict(run["verdict"]))
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(run["ts"]))
    else:
        badge, when = '<span class="badge neutral">no runs</span>', "-"
    id_cell = (
        f'<a href="/check/{e(c.id)}">{e(label)}</a>'
        if label == c.id
        else f'<a href="/check/{e(c.id)}">{e(label)}</a> <span class="meta">(= {e(c.id)})</span>'
    )
    return f"""<tr>
      <td>{id_cell}</td>
      <td>{e(c.title)}</td>
      <td>{_inv_html(c.invariant)}</td>
      <td>{_ar_html(c.attacker_role)}</td>
      <td>{_kind_html(c.kind.value)}</td>
      <td>{badge}</td>
      <td class="meta">{e(when)}</td>
      <td>
        <form method="post" action="/api/run/{e(c.id)}">
          <button type="submit" class="small">Run</button>
        </form>
      </td>
    </tr>"""


def _section_block(section: Section, latest: dict[str, dict]) -> str:
    rows = "".join(_check_row(item.label, item.check, latest) for item in section.items)
    return f"""
    <h2 class="section-heading">{e(section.title)}</h2>
    <div class="table-wrap"><table>
      <tr><th>id</th><th>title</th><th>invariant</th><th>attacker</th><th>kind</th><th>latest</th><th>last run</th><th></th></tr>
      {rows}
    </table></div>"""


def _legend_group(title: str, rows: list[tuple[str, str]]) -> str:
    cards = "".join(
        f'<div class="legend-card"><span class="code">{e(code)}</span><p>{e(desc)}</p></div>'
        for code, desc in rows
    )
    return f"""<div class="legend-group"><h3>{e(title)}</h3><div class="legend-grid">{cards}</div></div>"""


def _legend_tables() -> str:
    kind_rows = [(KIND_LABELS[k], desc) for k, desc in KIND_DESCRIPTIONS.items()]
    return f"""
    <h2 class="section-heading">Reference</h2>
    {_legend_group("Invariant codes", list(INVARIANT_DESCRIPTIONS.items()))}
    {_legend_group("Attacker role codes", list(ATTACKER_ROLES.items()))}
    {_legend_group("Check kinds", kind_rows)}"""


def dashboard(
    checks: list[Check],
    latest: dict[str, dict],
    target: Target,
    gateway_note: str = "",
) -> str:
    registry = {c.id: c for c in checks}
    sections_html = "".join(_section_block(s, latest) for s in build_sections(registry))
    actions = """
    <form method="post" action="/api/run_all">
      <button type="submit" class="primary">Run all checks</button>
    </form>
    <a href="/api/export.md"><button type="button">Export FINDINGS.md draft</button></a>
    <form method="post" action="/api/clear"
          onsubmit="return confirm('Delete every recorded run and every pinned baseline, for every check and every target? This cannot be undone.')">
      <button type="submit" class="danger">Clear all history</button>
    </form>
    """
    status = f'<div class="panel notice">{e(gateway_note)}</div>' if gateway_note else ""
    body = f"""
    <h1>GLC v2 - Findings Console</h1>
    <p class="lede">This is a local-only testing dashboard. Findings are grouped by what the migration
    did to each one: introduced by the move to Modal, inherited but not yet closed, or inherited and now
    reachable over the internet. Every run is logged and kept. Nothing runs automatically here. Click Run
    on a row, or Run all checks, whenever you are ready.</p>
    {status}
    {target_form(target)}
    <div class="actions">{actions}</div>
    {sections_html}
    {_legend_tables()}
    """
    return _page("Findings console", body)


_FIXED_VERDICTS = {Verdict.CLOSED, Verdict.MITIGATED}


def _fixed_commit_html(run: dict) -> str:
    """The commit the local checkout was on when this run happened,
    shown only when the run actually demonstrates a fix — a vulnerable
    or errored run's commit isn't "the commit that fixed it"."""
    if Verdict(run["verdict"]) not in _FIXED_VERDICTS:
        return ""
    commit = run.get("git_commit")
    if not commit:
        return ""
    return f'<div class="commit">Fixed in commit: {e(commit)}</div>'


def _compare_card(
    position: str, run: dict | None, check_id: str = "", target_name: str = "", pinned: bool = False
) -> str:
    """position is "before" or "after" — drives the color-coded framing
    (rose for before, green for after) so the two sides read apart at a
    glance, independent of whatever verdict badge sits inside."""
    if run is None:
        return f"""<div class="compare-card {position}">
          <span class="compare-eyebrow {position}">{e(position)}</span>
          <div class="compare-empty">no run recorded</div>
        </div>"""
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(run["ts"]))
    badge = _badge(Verdict(run["verdict"]))
    pin_html = ""
    if pinned:
        pin_html = f"""<span class="pin-badge">PINNED</span>
        <form method="post" action="/api/unpin/{e(check_id)}" style="display:inline;margin-left:.4rem">
          <input type="hidden" name="target_name" value="{e(target_name)}">
          <button type="submit" class="small">Unpin</button>
        </form>"""
    return f"""<div class="compare-card {position}">
      <span class="compare-eyebrow {position}">{e(position)}</span>
      <div class="compare-meta">{e(when)} - target: {e(run["target_name"])}</div>
      <div style="margin-bottom:var(--sp-2)">{badge} {pin_html}</div>
      {_fixed_commit_html(run)}
      <div class="compare-summary">{e(run["summary"])}</div>
      <pre>{e(run["evidence"])}</pre>
    </div>"""


def _before_after_block(
    check_id: str, target_name: str, before: dict | None, after: dict | None, pin_run_id: int | None
) -> str:
    same_run = before is not None and after is not None and before["id"] == after["id"]
    note = " (only one run recorded)" if same_run else ""
    before_note = "" if pin_run_id is not None else " - earliest recorded, pin a row below to override"
    return f"""
    <div class="compare-target">target: {e(target_name)}{e(note)}</div>
    <div class="grid2">
      {_compare_card("before", before, check_id, target_name, pinned=pin_run_id is not None)}
      {_compare_card("after", after)}
    </div>
    {f'<div class="meta" style="margin-top:var(--sp-1)">Before{e(before_note)}</div>' if before_note else ""}"""


def _history_row(r: dict, check_id: str, pinned_by_target: dict[str, int]) -> str:
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
    target_name = r["target_name"]
    if pinned_by_target.get(target_name) == r["id"]:
        action = '<span class="pin-badge">PINNED</span>'
    else:
        action = f"""<form method="post" action="/api/pin/{e(check_id)}">
          <input type="hidden" name="target_name" value="{e(target_name)}">
          <input type="hidden" name="run_id" value="{r["id"]}">
          <button type="submit" class="small">Pin as before</button>
        </form>"""
    commit = r.get("git_commit")
    commit_cell = (
        f'<span class="commit">{e(commit)}</span>'
        if Verdict(r["verdict"]) in _FIXED_VERDICTS and commit
        else '<span class="meta">-</span>'
    )
    return f"""<tr><td class="meta">{e(when)}</td><td>{_badge(Verdict(r["verdict"]))}</td>
        <td>{e(target_name)}</td><td>{e(r["summary"])}</td><td>{commit_cell}</td><td>{action}</td></tr>"""


def check_detail(
    check: Check,
    history: list[dict],
    per_target: list[tuple[str, dict | None, dict | None, int | None]],
) -> str:
    if per_target:
        before_after = "".join(
            _before_after_block(check.id, name, before, after, pin_run_id)
            for name, before, after, pin_run_id in per_target
        )
    else:
        before_after = (
            '<div class="panel notice">no runs recorded yet. Run this check against a target first.</div>'
        )

    pinned_by_target = {name: pin_run_id for name, _b, _a, pin_run_id in per_target if pin_run_id is not None}
    hist_rows = "".join(_history_row(r, check.id, pinned_by_target) for r in history)
    hist_table = f"""<div class="table-wrap"><table>
      <tr><th>when</th><th>verdict</th><th>target</th><th>summary</th><th>commit</th><th></th></tr>
      {hist_rows or '<tr><td colspan="6">no runs yet</td></tr>'}</table></div>"""

    inv_desc = describe_invariant(check.invariant)
    ar_desc = ATTACKER_ROLES.get(check.attacker_role)
    kind_label = KIND_LABELS.get(check.kind.value, check.kind.value)
    kind_desc = KIND_DESCRIPTIONS.get(check.kind.value, "")
    detail_list = f"""<dl class="detail-list">
      <div>
        <dt>Invariant broken</dt>
        <dd><span class="term">{e(check.invariant)}.</span> {e(inv_desc) if inv_desc else "Not one of the eight numbered invariants."}</dd>
      </div>
      <div>
        <dt>Attacker role reached</dt>
        <dd>{(f'<span class="term">{e(check.attacker_role)}.</span> {e(ar_desc)}') if check.attacker_role and ar_desc else "Not classified for this check."}</dd>
      </div>
      <div>
        <dt>How this check runs</dt>
        <dd><span class="term">{e(kind_label)}.</span> {e(kind_desc)}</dd>
      </div>
    </dl>"""
    body = f"""
    <p class="meta" style="margin-bottom:var(--sp-2)"><a href="/">&larr; back to dashboard</a></p>
    <h1>{e(check.id)} - {e(check.title)}</h1>
    {detail_list}
    <div class="panel">{e(check.description)}{f"<br><br><i>{e(check.notes)}</i>" if check.notes else ""}</div>
    <div class="actions">
      <form method="post" action="/api/run/{e(check.id)}">
        <button type="submit" class="primary">Run now against current target</button>
      </form>
      <form method="post" action="/api/clear/{e(check.id)}"
            onsubmit="return confirm('Delete all history and any pinned baseline for {e(check.id)}, across every target? This cannot be undone.')">
        <button type="submit" class="danger">Clear history for this check</button>
      </form>
    </div>
    <div class="compare-wrap">{before_after}</div>
    <h2 class="section-heading">Full history ({len(history)} run(s)) - pin any row as the before baseline</h2>
    {hist_table}
    """
    return _page(f"{check.id} — {check.title}", body)
