from __future__ import annotations

import html as _html
from urllib.parse import quote as _quote

from .dashboard import DashboardData, PROVIDER_LABELS, TrialView
from ..judge.render import TOPBAR_CSS, render_topbar

_NONE_DISPLAY = "—"


def _esc(value: object) -> str:
    return _html.escape("" if value is None else str(value))


def _attr(value: object) -> str:
    """Raw stored value for a data-* attribute, or 'none' when absent."""
    return _html.escape("none" if value is None else str(value))


def _kv(label: str, key: str, value: object) -> str:
    return (
        f'<div class="kv"><span class="k">{_esc(label)}</span>'
        f'<span class="v" data-{key}="{_attr(value)}">'
        f"{_esc(_NONE_DISPLAY if value is None else value)}</span></div>"
    )


def _list(text: str, items: tuple[str, ...]) -> str:
    return (
        f'<div class="kv"><span class="k">{_esc(text)}</span>'
        f'<span class="v" data-{text.replace(" ", "-")}="{_attr(",".join(items) if items else None)}">'
        f"{_esc(', '.join(items) if items else _NONE_DISPLAY)}</span></div>"
    )


def _decision_class(status: str) -> str:
    return {
        "allowed": "decision-allow",
        "review": "decision-review",
        "blocked": "decision-block",
        "error": "decision-error",
        "proposed": "decision-proposed",
    }.get(status, "")


def _chain(trial: TrialView | None) -> str:
    steps = [
        ("Attack", True),
        ("SOC Agent", trial is not None and trial.proposed_action is not None),
        ("Blue AI", trial is not None and trial.context_trust is not None),
        ("Risk Engine", trial is not None and trial.risk_score is not None),
        ("Policy Gate", trial is not None and trial.final_decision is not None),
    ]
    parts = []
    for i, (label, has_data) in enumerate(steps):
        parts.append(
            f'<span class="step{" active" if has_data else ""}" '
            f'data-step="{_esc(label)}" data-active="{str(has_data).lower()}">{_esc(label)}</span>'
        )
        if i < len(steps) - 1:
            parts.append('<span class="arrow">→</span>')
    return '<div class="chain">' + "".join(parts) + "</div>"


def _selector(data: DashboardData, selected: str | None) -> str:
    if not data.trials:
        return '<div class="trial-selector-empty">no stored trials</div>'
    chips = []
    for t in data.trials:
        active = " active" if t.trial_id == selected else ""
        chips.append(
            f'<a class="chip{active}" href="/dashboard?trial={_quote(t.trial_id)}">'
            f"{_esc(t.trial_id)}</a>"
        )
    return '<div class="trial-selector">' + "".join(chips) + "</div>"


def _provider_header(data: DashboardData) -> str:
    if data.is_replay_only:
        return (
            '<div class="provider-badge replay" data-replay-mode="true">'
            '<span class="dot"></span>REPLAY MODE — deterministic, not live inference</div>'
        )
    if data.providers:
        labels = []
        for p in data.providers:
            labels.append(f'<span class="prov" data-provider="{_esc(p)}">{_esc(PROVIDER_LABELS.get(p, p))}</span>')
        return '<div class="provider-badge">' + "<span class='dot'></span>" + " · ".join(labels) + "</div>"
    return '<div class="provider-badge" data-provider="none">no provider recorded</div>'


def _metrics_table(data: DashboardData) -> str:
    mv = data.metrics
    rows = []
    for r in mv.rows:
        rows.append(
            f"<tr>"
            f'<td>{_esc(r.mode)}</td>'
            f'<td data-asr="{_attr(r.asr)}">{_esc(_NONE_DISPLAY if r.asr is None else r.asr)}</td>'
            f'<td data-uar="{_attr(r.uar)}">{_esc(_NONE_DISPLAY if r.uar is None else r.uar)}</td>'
            f'<td data-fir="{_attr(r.fir)}">{_esc(_NONE_DISPLAY if r.fir is None else r.fir)}</td>'
            f'<td data-tti-ms="{_attr(r.tti_ms)}">{_esc(_NONE_DISPLAY if r.tti_ms is None else r.tti_ms)}</td>'
            f'<td data-e2e-ms="{_attr(r.e2e_ms)}">{_esc(_NONE_DISPLAY if r.e2e_ms is None else r.e2e_ms)}</td>'
            f'<td data-attempts="{r.attempts}">{r.attempts}</td>'
            f"</tr>"
        )
    rows_html = "".join(rows) if rows else (
        f'<tr><td colspan="7" class="muted">no trials recorded</td></tr>'
    )
    uapr = mv.uapr
    return (
        '<section class="panel metrics-panel" id="metrics">'
        '<h2>Panel 5 — Metrics <small>(computed from stored trials)</small></h2>'
        f'<div class="uapr" data-uapr="{_attr(uapr)}" data-baseline="{_esc(mv.baseline_mode)}" '
        f'data-defended="{_esc(mv.defended_mode)}">'
        f'UAPR ({_esc(mv.baseline_mode)} → {_esc(mv.defended_mode)}): '
        f"<strong>{_esc(_NONE_DISPLAY if uapr is None else uapr)}</strong></div>"
        '<table class="metrics-table"><thead><tr><th>Mode</th><th>ASR</th><th>UAR</th>'
        "<th>FIR</th><th>TTI (ms)</th><th>E2E (ms)</th><th>Attempts</th></tr></thead>"
        f"<tbody>{rows_html}</tbody></table>"
        "</section>"
    )


def _panel(header: str, sub: str, body: str, extra_class: str = "") -> str:
    return (
        f'<section class="panel {extra_class}"><h2>{header} '
        f"<small>{_esc(sub)}</small></h2>{body}</section>"
    )


def _trial_panels(trial: TrialView) -> str:
    # Panel 1 - Red AI
    p1 = (
        _kv("Attack type", "attack-type", trial.attack_type)
        + _kv("Seed", "seed", trial.seed)
        + _kv("Mutation", "mutation", trial.mutation)
        + _kv("Iteration", "iteration", trial.iteration)
        + _kv("Status", "status", trial.status)
    )
    # Panel 2 - SOC Agent
    p2 = (
        _kv("Alert", "alert", trial.alert)
        + _kv("Relevant context", "context", trial.relevant_context)
        + _kv("Proposed action", "proposed-action", trial.proposed_action)
        + _kv("Provider", "provider", trial.provider)
    )
    # Panel 3 - Blue AI / Defense
    p3 = (
        _kv("Context trust", "context-trust", trial.context_trust)
        + _kv("Behavior deviation", "behavior-deviation", trial.behavior_deviation)
        + _kv("Action criticality", "action-criticality", trial.action_criticality)
        + _kv("Privilege impact", "privilege-impact", trial.privilege_impact)
        + _kv("Route", "route", trial.route)
        + _list("Evidence tags", trial.evidence_tags)
    )
    # Panel 4 - Risk / Policy
    margin = trial.decision_margin
    margin_display = _NONE_DISPLAY if margin is None else f"{margin:g} pts"
    p4 = (
        _kv("Risk score", "risk-score", trial.risk_score)
        + f'<div class="kv"><span class="k">Decision margin</span>'
        f'<span class="v" data-decision-margin="{_attr(margin)}">{_esc(margin_display)}</span></div>'
        + _list("Triggered constraints", trial.triggered_constraints)
        + f'<div class="kv"><span class="k">Final decision</span>'
        f'<span class="v decision {_decision_class(trial.status)}" data-decision="{_attr(trial.final_decision)}">'
        f"{_esc(_NONE_DISPLAY if trial.final_decision is None else trial.final_decision)}"
        f'{"" if trial.final_decision is not None else ""}</span></div>'
        + _list("Reason tags", trial.reason_tags)
        + _kv("Executed", "executed", trial.executed)
    )
    return (
        _panel("Panel 1 — Red AI", trial.trial_id, p1)
        + _panel("Panel 2 — SOC Agent", trial.mode, p2)
        + _panel("Panel 3 — Blue AI / Defense", trial.mode, p3)
        + _panel("Panel 4 — Risk / Policy", trial.status, p4)
    )


_CSS = """
:root { --ink:#1c2333; --muted:#6b7280; --line:#e5e7eb; --card:#ffffff; --bg:#f6f7f9; --high:#e7e8e8;
        --allow:#15803d; --review:#b45309; --block:#b91c1c; --error:#6b7280; --replay:#b45309; }
* { box-sizing:border-box; }
body { margin:0; font-family: system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       background:var(--bg); color:var(--ink); font-size:14px; line-height:1.5; }
.wrap { max-width:1180px; margin:0 auto; padding:24px 20px 48px; }
.page-header { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;
         margin-bottom:18px; }
h1 { font-size:20px; margin:0; font-weight:650; }
h1 small, h2 small { color:var(--muted); font-weight:400; font-size:12px; }
.meta { color:var(--muted); font-size:12px; font-family: ui-monospace,SFMono-Regular,Menlo,monospace; }
.provider-badge { display:inline-flex; align-items:center; gap:8px; padding:6px 12px; border:1px solid var(--line);
                  border-radius:999px; background:var(--card); font-size:12px; font-weight:550; }
.provider-badge .dot { width:8px; height:8px; border-radius:50%; background:var(--allow); }
.provider-badge.replay { border-style:dashed; border-color:var(--replay); color:var(--replay); }
.provider-badge.replay .dot { background:var(--replay); }
.chain { display:flex; align-items:center; gap:10px; flex-wrap:wrap; background:var(--card);
         border:1px solid var(--line); border-radius:10px; padding:12px 16px; margin-bottom:16px; }
.step { font-size:12px; font-weight:550; color:var(--muted); padding:4px 10px; border-radius:999px;
        background:#eef0f3; }
.step.active { background:#e0f2fe; color:#0369a1; }
.arrow { color:var(--muted); }
.trial-selector { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:16px; }
.chip { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:11px; color:#374151;
        background:var(--card); border:1px solid var(--line); padding:3px 10px; border-radius:999px;
        text-decoration:none; }
.chip.active { border-color:#0369a1; background:#e0f2fe; color:#0369a1; }
.grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
@media (max-width:860px){ .grid { grid-template-columns:1fr; } }
.panel { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px 18px; }
.panel h2 { margin:0 0 12px; font-size:15px; font-weight:600; }
.metrics-panel { grid-column:1 / -1; }
.kv { display:flex; justify-content:space-between; gap:16px; padding:6px 0; border-bottom:1px dotted #eef0f3; }
.kv:last-child { border-bottom:0; }
.k { color:var(--muted); flex-shrink:0; }
.v { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; text-align:right;
    overflow-wrap:anywhere; }
.decision { font-weight:700; }
.decision-allow { color:var(--allow); }
.decision-review { color:var(--review); }
.decision-block { color:var(--block); }
.decision-error, .decision-proposed { color:var(--error); }
.uapr { font-size:13px; margin-bottom:10px; padding:10px 12px; background:#f0fdf4; border:1px solid #bbf7d0;
        border-radius:8px; }
.uapr strong { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
table.metrics-table { width:100%; border-collapse:collapse; font-size:12.5px; }
.metrics-table th, .metrics-table td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); }
.metrics-table th { color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; }
.metrics-table td:not(:first-child) { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
.muted { color:var(--muted); font-style:italic; }
.notice { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:22px; }
.notice code { background:#eef0f3; border-radius:4px; padding:1px 6px; }
footer { margin-top:18px; color:var(--muted); font-size:11px; }
""" + TOPBAR_CSS


def render_html(data: DashboardData, selected: str | None = None) -> str:
    """Render the dashboard to a self-contained HTML page (server-side, no JS)."""
    trial = data.trials[0] if data.trials else None
    if trial is not None and selected is not None:
        trial = next((t for t in data.trials if t.trial_id == selected), trial)

    seed_html = _esc(data.seed) if data.seed is not None else "—"
    notice_html = (
        ""
        if trial is not None
        else '<div class="notice">No stored experiment data yet. Run an experiment '
        "(e.g. <code>ExperimentRunner</code>) and store its report — the dashboard only "
        "renders stored results.</div>"
    )
    chain_html = _chain(trial)
    selector_html = _selector(data, trial.trial_id if trial else None)
    panels_html = _trial_panels(trial) if trial is not None else ""
    metrics_html = _metrics_table(data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WIENER Dashboard — {_esc(data.experiment_id)}</title>
<style>{_CSS}</style>
</head>
<body>
{render_topbar('dashboard')}
<div class="wrap">
<section class="page-header">
  <h1>WIENER Dashboard <small>live view of stored experiment data</small></h1>
  {_provider_header(data)}
</section>
<div class="meta">experiment: <span data-experiment-id="{_esc(data.experiment_id)}">{_esc(data.experiment_id)}</span>
 · rng seed: <span data-seed="{_attr(data.seed)}">{seed_html}</span></div>
{chain_html}
{selector_html}
{notice_html}
<div class="grid">
{panels_html}
</div>
{metrics_html}
<footer>All values are rendered directly from the stored ExperimentReport; nothing is hardcoded.</footer>
</div>
</body>
</html>"""


def render_trial_html(data: DashboardData, trial_id: str | None = None) -> str:
    """Render a single trial's detail panels (used by tests)."""
    trial = next((t for t in data.trials if t.trial_id == trial_id), None)
    if trial is not None:
        return _trial_panels(trial)
    if data.trials:
        return _trial_panels(data.trials[0])
    return ""