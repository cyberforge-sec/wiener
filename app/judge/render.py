"""Apple-styled, projector-friendly renderer for the interactive Judge Mode.

The renderer only presents the ``JudgeRun`` returned by the live pipeline.  In
particular, it deliberately has no client-side verdict switcher: a verdict is
always supplied by the policy gate and every tool call remains simulated.
"""

from __future__ import annotations

import html as _html

from ..risk_engine.risk_engine import decision_margin
from .judge_mode import (
    ATTACK_SEED_ID,
    LIVE_STAGE_ORDER,
    STAGES,
    AdaptiveStep,
    JudgeRun,
    PROVIDERS,
    SCENARIOS,
    live_display,
    scenario_chip,
    trial_label,
)

_PROVIDER_LABELS = {
    "openai_compatible": "Cloud (configurable adapter)",
    # Legacy alias for the same tier; still selectable, still the same path.
    "opencode": "Cloud (configurable adapter)",
    "local": "Local (Ollama)",
    "replay": "Replay",
}
_SCENARIO_LABELS = {"normal": "Normal", "prompt_injection": "Prompt Injection", "adaptive": "Adaptive Attack"}


def provider_label(name: str) -> str:
    return _PROVIDER_LABELS.get(name, name)


def scenario_label(name: str) -> str:
    return _SCENARIO_LABELS.get(name, name)
_DECISION_LABELS = {
    "ALLOW": "ALLOWED SIMULATED EXECUTION",
    "REVIEW": "REVIEW NOT EXECUTED",
    "BLOCK": "BLOCKED SAFE FROM EXECUTION",
}
_DECISION_NOTES = {
    "ALLOW": "Safe verified dispatch completed inside the sandbox only.",
    "REVIEW": "Execution is held for review; nothing was dispatched.",
    "BLOCK": "The gate intercepted the action before any simulated dispatch.",
}

_STAGE_ICONS = {k: meta["icon"] for k, meta in STAGES.items()}

# Inline SVG icon sprite. The Judge page used to load the Material Symbols
# webfont from fonts.googleapis.com, which (a) breaks the demo offline and
# (b) executes third-party CSS on every page view. Icons are now local,
# inline, and font-independent. Paths are Material Design icons (Apache-2.0).
_ICON_SPRITE: dict[str, str] = {
    "shield": "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5L12,1z",
    "smart_toy": "M20,2H4C2.9,2 2,2.9 2,4v18l4,-4h14c1.1,0 2,-0.9 2,-2V4C22,2.9 21.1,2 20,2zM7,9h10v2H7V9zM7,13h7v2H7V13z",
    "route": "M16,17.01V10h-2v7.01h-3L15,21l4,-3.99h-3zM9,3L5,6.99h3V14h2V6.99h3L9,3z",
    "verified": "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5L12,1zm-2,16l-4,-4 1.41,-1.41L10,14.17l6.59,-6.59L18,9l-8,8z",
    "speed": "M1,21h22L12,2 1,21zm12,-3h-2v-2h2v2zm0,-4h-2v-4h2v4z",
    "gavel": "M12,2l3,3-3,3-3,-3 3,-3zM5,11l3,-3 3,3-3,3-3,-3zM2,20h20v2H2v-2z",
    "terminal": "M9.4,16.6L4.8,12l4.6,-4.6L8,6l-6,6 6,6 1.4,-1.4zm5.2,0l4.6,-4.6 -4.6,-4.6L16,6l6,6 -6,6 -1.4,-1.4z",
    "expand_more": "M16.59,8.59L12,13.17 7.41,8.59 6,10l6,6 6,-6z",
    "play_arrow": "M8,5v14l11,-7z",
    "refresh": "M17.65,6.35C16.2,4.9 14.21,4 12,4c-4.42,0 -7.99,3.58 -8,8s3.57,8 8,8c3.73,0 6.84,-2.55 7.73,-6h-2.08c-0.82,2.33 -3.04,4 -5.65,4 -3.31,0 -6,-2.69 -6,-6s2.69,-6 6,-6c1.66,0 3.14,0.69 4.22,1.78L13,11h7V4l-2.35,2.35z",
    "replay": "M13,3c-4.97,0 -9,4.03 -9,9H1l3.89,3.89 0.07,0.14L9,12H6c0,-3.87 3.13,-7 7,-7s7,3.13 7,7 -3.13,7 -7,7c-1.93,0 -3.68,-0.79 -4.94,-2.06l-1.42,1.42C8.27,19.99 10.51,21 13,21c4.97,0 9,-4.03 9,-9s-4.03,-9 -9,-9z",
}


def _icon(name: str, css_class: str = "ico", title: str = "") -> str:
    """Inline SVG icon from the local sprite (no webfont, no network)."""
    path = _ICON_SPRITE.get(name, _ICON_SPRITE["shield"])
    label = f'<title>{_esc(title)}</title>' if title else ""
    return (
        f'<svg class="{_esc(css_class)}" viewBox="0 0 24 24" aria-hidden="true" '
        f'focusable="false">{label}<path d="{path}"/></svg>'
    )


assert set(STAGES) == set(LIVE_STAGE_ORDER), "STAGES keys must match LIVE_STAGE_ORDER"


def _esc(value: object) -> str:
    return _html.escape("" if value is None else str(value))


def _attr(value: object) -> str:
    value = "none" if value is None else str(value).lower() if isinstance(value, bool) else str(value)
    return _html.escape(value, quote=True)


def _value(value: object) -> str:
    return "-" if value is None or value == "" else str(value)


def _number(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f}".rstrip("0").rstrip(".")


def _decision_class(decision: str | None) -> str:
    return {"ALLOW": "allow", "REVIEW": "review", "BLOCK": "block"}.get(decision or "", "neutral")


def _decision_label(decision: str | None) -> str:
    return _DECISION_LABELS.get(decision or "", decision or "NO DECISION")


def _provider_tier(run: JudgeRun) -> str:
    if run.replay_mode or run.provider_used == "replay":
        return "replay"
    if run.provider_used == "degraded":
        return "degraded"
    if run.provider_used == "local" and run.requested_provider not in ("", "local"):
        return "local_fallback"
    return "live"


def _tier_notice(run: JudgeRun) -> str:
    tier = _provider_tier(run)
    if tier == "replay":
        return '<span class="tier tier--replay" data-tier="replay">REPLAY MODE: deterministic, not live inference</span>'
    if tier == "degraded":
        return '<span class="tier tier--degraded" data-tier="degraded">DEGRADED TIER: not counted as defense evidence</span>'
    if tier == "local_fallback":
        return '<span class="tier tier--fallback" data-tier="local_fallback">LOCAL FALLBACK: cloud tier unavailable</span>'
    return ""


def _stage(
    *,
    key: str,
    chip: str | None = None,
    value: str = "-",
    accent: str = "",
    state: str = "pending",
    active: bool = False,
) -> str:
    meta = STAGES[key]
    icon = meta["icon"]
    chip = chip or meta["chip"]
    title = meta["title"]
    description = meta["description"]
    label = meta["label"]
    state_cls = f" step-card--{state}"
    accent_cls = f" step-card--{accent}" if accent else ""
    status_attr = "done" if state == "completed" else "pending" if state == "pending" else state
    return f'''<div id="stage-{_esc(key)}" data-active="{str(active).lower()}" data-stage-key="{_esc(key)}" data-stage-status="{status_attr}" class="step-card group relative rounded-xl bg-white border border-neutral-200 shadow-[0_1px_3px_rgba(0,0,0,.04)] transition hover:shadow-md{state_cls}{accent_cls}">
  <div class="flex w-full items-center gap-2 border-b border-neutral-200 -mx-4 -mt-4 mb-3 px-4 py-2 bg-neutral-50 rounded-t-xl">
    {_icon(icon, "ico step-icon text-neutral-400")}
    <div class="step-title font-semibold text-[13px] text-neutral-900">{_esc(title)}</div>
  </div>
  <div class="text-[11px] text-neutral-500 uppercase tracking-widest font-medium" data-stage-chip data-idle-chip="{_esc(chip)}">{_esc(chip)}</div>
  <div class="text-xs text-neutral-600 mt-1 leading-relaxed">{_esc(description)}</div>
  <div class="step-meta pt-3 mt-auto">
    <div class="text-[11px] text-neutral-500 uppercase tracking-widest font-medium" data-stage-label>{_esc(label)}</div>
    <code class="text-[13px] font-semibold text-neutral-900 mt-0.5 block break-words" data-stage-value>{_esc(value)}</code>
  </div>
</div>'''


def _adaptive_row(step: AdaptiveStep) -> str:
    decision = step.decision or "\u2014"
    mutation = "baseline" if not step.kind else step.kind.replace("_", " ")
    mutation_note = f"Mutation: {_esc(mutation)}"
    if step.risk is not None:
        mutation_note += f'<span class="text-neutral-300 px-1">&middot;</span>Risk: {step.risk:g} / 100'
    return f'''<div class="flex items-center justify-between gap-3 px-5 py-3" data-iteration="{step.iteration + 1}" data-decision="{_esc(decision)}">
  <div class="flex items-baseline gap-2 min-w-0">
    <span class="text-[12px] font-semibold text-neutral-900 shrink-0">Iteration {step.iteration + 1}</span>
    <span class="text-[11px] text-neutral-500 truncate">{mutation_note}</span>
  </div>
  <strong class="text-[12px] font-semibold decision-{_decision_class(decision)} shrink-0">{_esc(decision)}</strong>
</div>'''


def _adaptive_stop_label(reason: str | None) -> str:
    """Human label for the backend's StopReason — tells the observer WHY the
    loop ended before any explanation of how the defense is scored."""
    if reason == "defense_blocked":
        return "DEFENSE BLOCKED"
    if reason == "max_iterations":
        return "HORIZON REACHED"
    return (reason or "") if reason else "\u2014"


def _adaptive_panel(run: JudgeRun) -> str:
    """Backend-faithful panel listing every mutation the adaptive loop really
    made. Only rendered for adaptive runs; the Execution Trace still shows the
    single final pipeline run, never this history."""
    if run.scenario != "adaptive" or not run.adaptive_trace:
        return ""
    rows = "\n".join(_adaptive_row(step) for step in run.adaptive_trace)
    stop_label = _adaptive_stop_label(run.stopped_reason)
    return f'''<section class="mt-4 rounded-2xl border bg-white p-6 px-7 shadow-[0_1px_3px_rgba(0,0,0,.04)]" data-adaptive-loop="1" data-adaptive-iterations="{len(run.adaptive_trace)}">
  <h2 class="text-[15px] font-semibold tracking-tight text-neutral-900">Adaptive Loop</h2>
  <p class="text-[11px] text-neutral-400 mt-1">Iterations judged by the real policy gate &middot; final run in Execution Trace</p>
  <div class="mt-4 divide-y divide-neutral-100 border border-neutral-100 rounded-xl overflow-hidden">
    {rows}
  </div>
  <div class="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-3">
    <div class="rounded-xl border border-neutral-100 bg-neutral-50 px-4 py-3">
      <div class="text-[11px] text-neutral-500 uppercase tracking-widest font-medium">Stop condition</div>
      <div class="text-[13px] font-semibold text-neutral-900 mt-0.5" data-stop-condition="BLOCK or iteration horizon">BLOCK or iteration horizon</div>
    </div>
    <div class="rounded-xl border border-neutral-100 bg-neutral-50 px-4 py-3">
      <div class="text-[11px] text-neutral-500 uppercase tracking-widest font-medium">Stop reason</div>
      <div class="text-[13px] font-semibold text-neutral-900 mt-0.5" data-stop-reason="{_esc(run.stopped_reason or '')}">{_esc(stop_label)}</div>
    </div>
  </div>
</section>'''


def _main_cards(run: JudgeRun) -> str:
    assert run.result is not None
    result = run.result
    proposal = result.trajectory.proposed_action
    blue = result.assessment
    risk = result.risk
    policy = result.decision
    tool = result.tool_result
    decision = policy.decision.value
    executed = tool.executed if tool else None
    status = tool.status.value if tool else None
    rule_ids = list(risk.triggered_constraints or policy.constraint_ids or [])
    rule_text = rule_ids[0] if rule_ids else "None matched"
    rule_bracket = f" [{_esc(rule_text)}]" if rule_ids else ""
    action = proposal.action.value
    risk_text = _number(risk.risk_score)
    risk_display = "—" if risk.risk_score is None else risk_text
    tool_state = "EXECUTED (SIMULATED)" if executed else "NOT EXECUTED"
    raw = result.trajectory.metadata.get("raw_completion", "") if result.trajectory.metadata else ""
    if executed is True:
        exec_label = "EXECUTED (SIMULATED)"
    elif status in ("refused_block", "refused_review"):
        exec_label = "REFUSED"
    elif status == "unsupported":
        exec_label = "UNSUPPORTED"
    else:
        exec_label = "NOT EXECUTED"
    margin = decision_margin(risk.risk_score) if risk.risk_score is not None else None
    margin_text = "—" if margin is None else f"{_number(margin)} pts"
    raw_block = ""
    if raw:
        raw_block = (
            '<h4 class="text-xs font-semibold text-neutral-400 mt-4 mb-1">Raw model output</h4>'
            f'<pre class="text-[11px] leading-relaxed font-mono text-neutral-400 whitespace-pre-wrap break-words">{_esc(raw)}</pre>'
        )
    row1 = "".join(
        (
            _stage(key="red_ai", chip=scenario_chip(run.scenario), value="Parsed", state="completed", active=True),
            _stage(
                key="soc_agent",
                value=(
                    f"tool: {action}"
                    + (f" → {proposal.target}" if proposal.target else "")
                ),
                state="completed",
                active=True,
            ),
            _stage(key="trajectory", value=trial_label(result.trajectory.trial_id), state="completed", active=True),
            _stage(key="blue_ai", value=f"Delta: {_number(blue.behavior_deviation)}", state="completed", active=True),
        )
    )
    row2 = "".join(
        (
            _stage(key="risk_engine", value=f"Score: {risk_text} / 100", state="completed", active=True),
            _stage(key="policy_gate", value=decision, state="completed", active=True, accent=_decision_class(decision)),
            _stage(key="simulated_tool", chip=tool_state, value=status or tool_state, state="completed", active=tool is not None, accent=_decision_class(decision)),
        )
    )
    return f'''<section class="run-shell" data-run-id="{run.run_id}" data-scenario="{_attr(run.scenario)}" data-requested-provider="{_attr(run.requested_provider)}" data-provider-used="{_attr(run.provider_used)}" data-replay-mode="{str(run.replay_mode).lower()}" data-provider-tier="{_attr(_provider_tier(run))}">
  <section class="rounded-2xl border bg-white p-6 px-7 shadow-[0_1px_3px_rgba(0,0,0,.04)] verdict-section verdict-section--{_decision_class(decision)}" data-final-decision="{_attr(decision)}" data-decision-label="{_attr(_decision_label(decision))}">
    <div class="flex items-start justify-between gap-4">
      <div class="flex items-start gap-3">
        {_icon("gavel", "ico text-[26px] text-neutral-400 mt-1")}
        <div>
          <p class="text-[11px] font-medium tracking-widest uppercase text-neutral-500 mb-1">Live Result</p>
          <h1 id="main-verdict-title" class="text-[28px] font-semibold tracking-tight decision-{_decision_class(decision)}">{_esc(_decision_label(decision).split(" ", 1)[0])}</h1>
          <p class="text-[13px] text-neutral-500 mt-0.5">{_esc(_DECISION_LABELS[decision].split(" ", 1)[1])}</p>
        </div>
      </div>
      {_tier_notice(run)}
    </div>
  </section>
  <div class="pipeline-panel mt-4">
    <h2 class="pipeline-panel__title">Execution Pipeline</h2>
    <div class="interception-grid">{row1}</div>
    <div class="interception-grid interception-grid--row2">{row2}</div>
  </div>
  <section class="mt-4 rounded-2xl border bg-white p-6 px-7 shadow-[0_1px_3px_rgba(0,0,0,.04)]">
    <div class="grid grid-cols-3 divide-x divide-neutral-100 border-b border-neutral-100 pb-5">
      <div class="px-4 first:pl-0">
        <div class="text-[11px] font-medium tracking-widest uppercase text-neutral-500 mb-1">Proposed Action</div>
        <div id="val-proposed-action" class="text-[15px] font-medium text-neutral-900" data-proposed-action="{_attr(action)}">{_esc(action)}</div>
      </div>
      <div class="px-4">
        <div class="text-[11px] font-medium tracking-widest uppercase text-neutral-500 mb-1">Target</div>
        <div class="text-[15px] font-medium text-neutral-900">{_esc(_value(proposal.target))}</div>
      </div>
      <div class="px-4 pr-0">
        <div class="text-[11px] font-medium tracking-widest uppercase text-neutral-500 mb-1">Policy Decision</div>
        <div class="text-[15px] font-semibold decision-{_decision_class(decision)}" data-decision="{_attr(decision)}">{_esc(decision)}</div>
      </div>
    </div>
    <div class="grid grid-cols-2 divide-x divide-neutral-100 border-b border-neutral-100 mt-5 pb-5">
      <div class="px-4 first:pl-0">
        <div class="text-[11px] font-medium tracking-widest uppercase text-neutral-500 mb-1">Execution</div>
        <div class="text-[15px] font-semibold text-neutral-900" data-tool-executed="{_attr(executed)}" data-tool-status="{_attr(status)}">{_esc(exec_label)}</div>
      </div>
      <div class="px-4 pr-0">
        <div class="text-[11px] font-medium tracking-widest uppercase text-neutral-500 mb-1">Risk</div>
        <div class="text-[15px] font-medium text-neutral-900 tabular-nums" id="val-risk-score" data-risk-score="{_attr(risk.risk_score)}">{_esc(risk_display)}</div>
        <p class="text-[10px] text-neutral-400 mt-1" data-triggered-constraints="{_attr(', '.join(risk.triggered_constraints))}">Hard Constraint: {_esc(rule_text)}</p>
      </div>
    </div>
    <details class="group mt-5">
      <summary class="flex cursor-pointer list-none items-center gap-1.5 text-[11px] font-semibold tracking-widest uppercase text-neutral-500 select-none [&::-webkit-details-marker]:hidden">
        {_icon("expand_more", "ico text-[15px] text-neutral-400 transition-transform group-open:rotate-180")}
        Intercepted Model Output
      </summary>
      <div class="grid grid-cols-2 gap-x-8 gap-y-3 text-[12px] font-mono mt-3">
        <div><span class="block text-[10px] uppercase tracking-widest text-neutral-500 mb-0.5">Proposed Action</span><span class="block text-neutral-900">{_esc(action)}</span></div>
        <div><span class="block text-[10px] uppercase tracking-widest text-neutral-500 mb-0.5">Target</span><span class="block text-neutral-900">{_esc(_value(proposal.target))}</span></div>
        <div><span class="block text-[10px] uppercase tracking-widest text-neutral-500 mb-0.5" title="Distance from the nearest policy boundary">Decision Margin</span><span class="block text-neutral-900" data-margin="{_attr(margin)}" title="Distance from the nearest policy boundary">{_esc(margin_text)}</span><span class="block text-[9px] text-neutral-400 mt-0.5">Distance from nearest policy boundary</span></div>
        <div><span class="block text-[10px] uppercase tracking-widest text-neutral-500 mb-0.5">Source</span><span class="block text-neutral-900">{_esc(_PROVIDER_LABELS.get(run.provider_used, run.provider_used) or "-")}</span></div>
        <div><span class="block text-[10px] uppercase tracking-widest text-neutral-500 mb-0.5">Policy Decision</span><strong class="block text-neutral-900">{_esc(decision)}{rule_bracket}</strong></div>
        <div><span class="block text-[10px] uppercase tracking-widest text-neutral-500 mb-0.5">Execution</span><strong class="block text-neutral-900" data-tool-executed="{_attr(executed)}" data-tool-status="{_attr(status)}">{_esc(exec_label)}</strong></div>
      </div>
      {raw_block}
    </details>
    <div class="mt-5 pt-4 border-t border-neutral-100">
      <div class="text-[11px] font-medium tracking-widest uppercase text-neutral-500 mb-1">Verification</div>
      <p class="text-xs text-neutral-500">{_esc(action)} <span class="text-neutral-300">\u00b7</span> <span class="decision-{_decision_class(decision)} font-medium">{_esc(decision)}</span> <span class="text-neutral-300">\u00b7</span> {_esc(exec_label)}</p>
    </div>
  </section>
  {_adaptive_panel(run)}
  <span class="sr-only" data-scenario="{_attr(_SCENARIO_LABELS.get(run.scenario, run.scenario))}" data-seed="{_attr(run.attack.seed_id if run.attack else None)}" data-margin="{_attr(margin)}" data-route="{_attr(blue.route.value)}" data-evidence-tags="{_attr(', '.join(blue.evidence_tags))}" data-executed="{_attr(executed)}" data-tool-simulated="1"></span>
</section>'''


def _pipeline_nodes() -> str:
    """A linear pipeline stepper whose architecture (nodes + order) is authored
    by the server and whose states are advanced ONLY by SSE stage events.

    Node order and the moving connector come from ``LIVE_STAGE_ORDER``, the
    exact sequence the engine reports, so the visual can never drift from the
    real backend lifecycle. Every node is a single execution stage: idle ``○``,
    running ``● RUNNING``, completed ``✓`` or failed ``×``. Only one node may
    ever wear the running state at a time.
    """
    nodes = ""
    for index, key in enumerate(LIVE_STAGE_ORDER):
        meta = live_display(key, {})
        nodes += f'''<li class="pipe pipe--idle" data-stage-key="{_esc(key)}" data-stage-status="idle">
  <div class="pipe-track"><span class="pipe-dot" aria-hidden="true"></span><span class="pipe-line" aria-hidden="true"></span></div>
  <div class="pipe-body">
    <b class="pipe-title">{_esc(meta["title"])}</b>
    <small class="pipe-chip" data-pipe-chip data-idle-chip="{_esc(meta["chip"])}">{_esc(meta["chip"])}</small>
    <em class="pipe-state" data-pipe-state></em>
  </div>
</li>'''
    return nodes


def _live_trace_section() -> str:
    """The permanently-visible animated pipeline trace.

    It is rendered ON PAGE LOAD (never inside the throwaway run skeleton) and
    survives every run: IDLE before the first run, advanced state-by-state by
    SSE lifecycle events while streaming, and left at the completed state
    afterwards; it is never removed from the page.
    """
    return f'''<section class="run-shell live-shell live-trace" id="live-trace" data-live="1" aria-live="polite">
  <details class="group">
    <summary class="flex cursor-pointer list-none items-center justify-between text-[11px] font-semibold tracking-widest uppercase text-neutral-500 select-none [&::-webkit-details-marker]:hidden">
      <span class="flex items-center gap-1.5">{_icon("expand_more", "ico text-[15px] text-neutral-400 transition-transform group-open:rotate-180")}Execution Trace</span>
      <span class="text-[10px] font-medium normal-case tracking-normal text-neutral-400">Real backend event trace</span>
    </summary>
    <div class="pipeline-card bg-white rounded-2xl border border-neutral-200 shadow-[0_1px_3px_rgba(0,0,0,.04)] mt-3 overflow-hidden">
      <div class="run-context">
        <span>Run #<b id="live-run-id" class="tabular-nums text-neutral-900 font-semibold">-</b></span><span>\u00b7</span><span id="live-provider">Provider: -</span><span>\u00b7</span><span id="live-scenario">Scenario: -</span>
      </div>
      <div class="pipeline-wrap">
        <ol id="live-pipeline" class="pipeline" data-stage-order="{','.join(LIVE_STAGE_ORDER)}">
          {_pipeline_nodes()}
        </ol>
      </div>
    </div>
  </details>
  <section class="mt-4" id="live-activity-section">
    <details class="group">
      <summary class="flex cursor-pointer list-none items-center justify-between text-[11px] font-semibold tracking-widest uppercase text-neutral-500 select-none [&::-webkit-details-marker]:hidden">
        <span class="flex items-center gap-1.5">{_icon("expand_more", "ico text-[15px] text-neutral-400 transition-transform group-open:rotate-180")}Live Activity</span>
        <span class="text-[10px] font-medium normal-case tracking-normal text-neutral-400">SSE event log</span>
      </summary>
      <div class="activity-card mt-3">
        <div class="activity-head"><span>Timestamp</span><span>Stage</span><span>Action</span></div>
        <div id="live-activity" class="activity-list" aria-live="polite"></div>
      </div>
    </details>
  </section>
</section>'''


def render_live_skeleton() -> str:
    """Server-authored live detail cards (static architecture).

    The persistent animated pipeline trace (``#live-trace``) lives directly in
    the page and never disappears; only these detail cards are swapped into
    ``#main-view`` during a run. Their values are filled exclusively by
    backend SSE stage events: the skeleton itself decides nothing and drives
    no timers.
    """
    cards1, cards2 = "", ""
    for key in LIVE_STAGE_ORDER[:4]:
        cards1 += _stage(key=key, value="-", state="pending")
    for key in LIVE_STAGE_ORDER[4:]:
        cards2 += _stage(key=key, value="-", state="pending")
    return f'''<section class="run-shell live-shell" data-live="1" aria-live="polite">
  <div class="pipeline-panel">
    <h2 class="pipeline-panel__title">Execution Pipeline</h2>
    <div class="interception-grid">{cards1}</div>
    <div class="interception-grid interception-grid--row2">{cards2}</div>
  </div>
</section>'''


def render_main_view(run: JudgeRun) -> str:
    """Return a complete post-run view for the judge page's AJAX replacement."""
    if run.error or run.result is None:
        return f'<div class="run-error" data-error="1"><b>Run failed</b>: {_esc(run.error or "No pipeline result")}</div>'
    return _main_cards(run)


_JUDGE_CSS_HEAD = r'''
:root{--bg:#f8f9f9;--surface:#fff;--low:#f3f4f4;--high:#e7e8e8;--line:#d7dadb;--ink:#191c1c;--muted:#62666a;--outline:#777b80;--blue:#0057c0;--red:#b42318;--red-bg:#fde7e4;--green:#17663c;--green-bg:#dff5e6;--shadow:0 2px 10px rgba(20,28,29,.045)}
'''

TOPBAR_CSS = r'''
.topbar{height:56px;position:sticky;top:0;z-index:5;background:rgba(255,255,255,.94);backdrop-filter:blur(12px);border-bottom:1px solid rgba(119,123,128,.35)}.topbar-inner{width:100%;height:100%;padding:0 24px 0 12px;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:6px}.brand-logo{width:40px;height:40px;flex:none;border-radius:8px}.brand-text{display:flex;flex-direction:row;align-items:baseline;gap:8px;white-space:nowrap}.brand-text b{font-size:17px;letter-spacing:-.04em}.brand-text em,.brand-text small{font-style:normal;font-size:11px;color:var(--muted);white-space:nowrap}.tagline{color:var(--ink);font-size:15px;font-weight:650;letter-spacing:.01em;white-space:nowrap;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
@media(max-width:840px){.topbar-inner{padding:0 10px 0 8px}.topbar small,.tagline{display:none}}
'''

def render_topbar(active: str = "") -> str:
    """Shared full-width top bar: brand (logo + WIENER wordmark) with the
    tagline. No navigation tabs rendered; pages are reached by URL so every
    served page keeps an identical header."""
    return (
        '<header class="topbar"><div class="topbar-inner"><div class="brand">'
        '<img src="/judge/logo" alt="WIENER logo" class="brand-logo" width="40" height="40" loading="lazy">'
        '<span class="brand-text"><b>WIENER</b><em>Adaptive AI-vs-AI Defense</em>'
        '<small>| HackNusa 2026</small></span></div>'
        '<div class="tagline">DON\'T JUST DETECT GOVERN THE ACTION</div></div></header>'
    )

_CSS = _JUDGE_CSS_HEAD + TOPBAR_CSS + r'''
.ico{display:inline-block;width:1em;height:1em;vertical-align:-.125em;fill:currentColor;flex:none}
@keyframes step-pop{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.run-shell .step-card{display:flex;flex-direction:column;align-items:flex-start;min-height:170px;padding:16px}
.run-shell .step-card .step-icon{font-size:22px;line-height:1}
.run-shell .step-card .step-meta{margin-top:auto}
.run-shell .step-card{opacity:0;animation:step-pop .25s ease forwards}
.run-shell .interception-grid>.step-card:nth-child(1){animation-delay:.05s}
.run-shell .interception-grid>.step-card:nth-child(2){animation-delay:.15s}
.run-shell .interception-grid>.step-card:nth-child(3){animation-delay:.25s}
.run-shell .interception-grid>.step-card:nth-child(4){animation-delay:.35s}
.run-shell .interception-grid--row2>.step-card:nth-child(1){animation-delay:.45s}
.run-shell .interception-grid--row2>.step-card:nth-child(2){animation-delay:.55s}
.run-shell .interception-grid--row2>.step-card:nth-child(3){animation-delay:.65s}
.interception-grid{--igap:12px;display:grid;grid-template-columns:minmax(0,1fr);gap:var(--igap)}
.interception-grid--row2{margin-top:var(--igap)}
@media(min-width:640px){.interception-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(min-width:1200px){.interception-grid{grid-template-columns:repeat(4,minmax(0,1fr))}.interception-grid--row2{grid-template-columns:repeat(3,minmax(0,1fr));width:calc(75% - var(--igap)/4);margin-left:auto;margin-right:auto}}
/* ---- One premium outer container wrapping the 4+3 pipeline grid. The panel
   carries the surface/shadow; inner stage cards stay calm (light surface,
   small radius, minimal shadow, equal height via min-height). The single
   identity color per stage lives on icon + running accent only. ---- */
.pipeline-panel{position:relative;background:var(--surface);border:1px solid rgba(119,123,128,.28);border-radius:20px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.04),0 12px 32px rgba(20,28,29,.05)}
.pipeline-panel__title{font-size:20px;font-weight:600;letter-spacing:-.02em;line-height:1.3;color:var(--ink);margin:0 0 18px}
.pipeline-panel .step-card{background:rgba(252,253,253,.92);border-radius:10px;box-shadow:0 1px 2px rgba(0,0,0,.03)}
.pipeline-panel .step-card:hover{box-shadow:0 2px 8px rgba(20,28,29,.06)}
.pipeline-panel .step-card[data-stage-key="red_ai"] .step-icon{color:#dc2626}
.pipeline-panel .step-card[data-stage-key="soc_agent"] .step-icon{color:#ea580c}
.pipeline-panel .step-card[data-stage-key="trajectory"] .step-icon{color:#d97706}
.pipeline-panel .step-card[data-stage-key="blue_ai"] .step-icon{color:#2563eb}
.pipeline-panel .step-card[data-stage-key="risk_engine"] .step-icon{color:#8b5cf6}
.pipeline-panel .step-card[data-stage-key="policy_gate"] .step-icon{color:#4f46e5}
.pipeline-panel .step-card[data-stage-key="simulated_tool"] .step-icon{color:#16a34a}
.live-shell .pipeline-panel .step-card--active[data-stage-key="red_ai"]{border-color:#fca5a5}
.live-shell .pipeline-panel .step-card--active[data-stage-key="soc_agent"]{border-color:#fdba74}
.live-shell .pipeline-panel .step-card--active[data-stage-key="trajectory"]{border-color:#fcd34d}
.live-shell .pipeline-panel .step-card--active[data-stage-key="blue_ai"]{border-color:#93c5fd}
.live-shell .pipeline-panel .step-card--active[data-stage-key="risk_engine"]{border-color:#c4b5fd}
.live-shell .pipeline-panel .step-card--active[data-stage-key="policy_gate"]{border-color:#a5b4fc}
.live-shell .pipeline-panel .step-card--active[data-stage-key="simulated_tool"]{border-color:#86efac}
.live-shell .pipeline-panel .step-card--active{transition-property:box-shadow}
.step-card--pending{border-color:#e5e7eb}
.step-card--completed{border-color:#d4d4d4}
.step-card--failed{border-color:#fecaca}
.step-card--danger{border-color:#fecaca}.step-card--danger .step-icon{color:#dc2626}
.step-card--allow{border-color:#bbf7d0}.step-card--allow .step-icon{color:#16a34a}
.step-card--review{border-color:#fde68a}.step-card--review .step-icon{color:#d97706}
.step-card--block{border-color:#fecaca}.step-card--block .step-icon{color:#dc2626}
.verdict-section--allow{border-color:#bbf7d0}.verdict-section--review{border-color:#fde68a}.verdict-section--block{border-color:#fecaca}
.decision-allow{color:#16a34a}.decision-review{color:#d97706}.decision-block{color:#dc2626}.decision-neutral{color:#737373}
.tier{display:inline-flex;align-items:center;gap:6px;padding:2px 8px;border-radius:6px;font:500 10px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.075em;text-transform:uppercase}
.tier::before{content:'';height:6px;width:6px;border-radius:50%}
.tier--replay{background:#dbeafe;color:#1e40af}.tier--replay::before{background:#2563eb}
.tier--degraded{background:#fef3c7;color:#92400e}.tier--degraded::before{background:#d97706}
.tier--fallback{background:#fef3c7;color:#92400e}.tier--fallback::before{background:#d97706}
.run-error{padding:24px;background:#fef2f2;border:1px solid #fecaca;border-radius:16px;color:#991b1b}
.step-card--active{border-color:#e5e7eb}
@keyframes live-pulse{0%,100%{box-shadow:0 0 0 0 rgba(63,63,70,.12)}50%{box-shadow:0 0 0 4px rgba(63,63,70,0)}}
.live-shell .step-card{animation:none;opacity:1}
.live-shell .step-card--done{opacity:1}
.live-shell .step-card--active{border-color:#e5e7eb;animation:live-pulse 1.4s ease-in-out infinite}
/* ---- Live pipeline stepper: ONE identity color per stage; state only
   modulates that stage's own color (idle muted / running full + pulse /
   completed solid + SVG check / failed red). States are advanced ONLY by
   SSE stage events. `.pipe-dot` is PURELY VISUAL and carries NO text: the
   earlier `content:'u2713'` was dropped because CSS treats `u` as a hex
   digit, so it rendered the literal text "u2713" inside the dots. ---- */
@keyframes pipe-flow{0%{background-position:200% 0}100%{background-position:-200% 0}}
@keyframes pipe-pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.82)}}
@keyframes pipe-glow{0%,100%{box-shadow:0 0 0 0 var(--glow)}50%{box-shadow:0 0 0 10px var(--glow)}}
@keyframes pipe-pop{0%{transform:scale(.55);opacity:.3}55%{transform:scale(1.16);opacity:1}100%{transform:scale(1);opacity:1}}
.pipeline-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
.pipeline{width:100%;display:flex;align-items:flex-start;min-width:680px;list-style:none;margin:0;padding:22px 20px 18px}
.pipe{flex:1 1 0;min-width:0;display:flex;flex-direction:column;gap:9px;--c:#62666a;--soft:#c2c6ca;--glow:rgba(63,63,70,.22)}
.pipe[data-stage-key="red_ai"]{--c:#dc2626;--soft:#fca5a5;--glow:rgba(220,38,38,.3)}
.pipe[data-stage-key="soc_agent"]{--c:#ea580c;--soft:#fdba74;--glow:rgba(234,88,12,.3)}
.pipe[data-stage-key="trajectory"]{--c:#d97706;--soft:#fcd34d;--glow:rgba(217,119,6,.3)}
.pipe[data-stage-key="blue_ai"]{--c:#2563eb;--soft:#93c5fd;--glow:rgba(37,99,235,.3)}
.pipe[data-stage-key="risk_engine"]{--c:#8b5cf6;--soft:#c4b5fd;--glow:rgba(139,92,246,.3)}
.pipe[data-stage-key="policy_gate"]{--c:#4f46e5;--soft:#a5b4fc;--glow:rgba(79,70,229,.3)}
.pipe[data-stage-key="simulated_tool"]{--c:#16a34a;--soft:#86efac;--glow:rgba(22,163,74,.3)}
.pipe-track{display:flex;align-items:center}
.pipe-dot{position:relative;flex:0 0 30px;width:30px;height:30px;border-radius:50%;border:2px solid #d4d4d8;background-color:#fff;background-size:14px 14px;background-position:center;background-repeat:no-repeat;display:flex;align-items:center;justify-content:center;transition:border-color .2s,background-color .2s,opacity .2s}
.pipe-line{position:relative;flex:1 1 0;height:3px;margin:0 4px;border-radius:3px;background:#e9ebec;overflow:hidden;transition:background-color .25s}
.pipe-line::after{content:'';position:absolute;inset:0;background-image:linear-gradient(90deg,transparent 25%,var(--soft) 52%,var(--c) 56%,var(--soft) 60%,transparent 80%);background-size:200% 100%;animation:pipe-flow 1.5s linear infinite;opacity:0;transition:opacity .2s}
/* The connector flowing OUT of the ONE active stage carries that stage's color */
.pipe--running .pipe-line::after{opacity:1}
.pipe:last-child .pipe-line{display:none}
/* IDLE - muted stage color, low opacity, no animation */
.pipe--idle .pipe-dot{border-color:var(--soft);opacity:.55}
.pipe--idle .pipe-dot::after{content:'';width:8px;height:8px;border-radius:50%;background:var(--soft)}
.pipe--idle .pipe-state::before{content:'IDLE';color:#c2c6ca}
/* RUNNING - the ONE active stage: full stage color, solid pulsing dot + glow */
.pipe--running .pipe-dot{border-color:var(--c)}
.pipe--running .pipe-dot::after{content:'';width:14px;height:14px;border-radius:50%;background:var(--c);animation:pipe-pulse 1.1s ease-in-out infinite}
.pipe--running .pipe-dot{animation:pipe-glow 1.3s ease-in-out infinite}
.pipe--running .pipe-title{color:var(--c)}
.pipe--running .pipe-state::before{content:'RUNNING';color:var(--c)}
.pipe--running .pipe-state{animation:pipe-pulse 1.1s ease-in-out infinite}
/* COMPLETED - stage color stays visible but calmer; SVG check, no text, no pulse */
.pipe--completed .pipe-dot{background-color:var(--c);border-color:var(--c);background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'><path d='M2 6.2 4.9 9.1 10 3.2' fill='none' stroke='white' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/></svg>");animation:pipe-pop .3s ease-out backwards}
.pipe--completed .pipe-dot::after{content:none}
.pipe--completed .pipe-line{background:var(--soft)}
.pipe--completed .pipe-state::before{content:''}
/* FAILED - red error treatment overrides the stage color */
.pipe--failed .pipe-dot{background-color:#b42318;border-color:#b42318;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 10 10'><path d='M1.5 1.5 8.5 8.5M8.5 1.5 1.5 8.5' stroke='white' stroke-width='1.7' stroke-linecap='round'/></svg>")}
.pipe--failed .pipe-dot::after{content:none}
.pipe--failed .pipe-line{background:var(--soft)}
.pipe--failed .pipe-state::before{content:'FAILED';color:#b42318}
.pipe-body{display:flex;flex-direction:column;gap:3px;padding-left:2px}
.run-context{display:flex;align-items:center;gap:10px;padding:13px 18px;border-bottom:1px solid #e7e8ea;font-size:11px;font-weight:500;color:#737373;letter-spacing:.02em;text-transform:none}
.run-context b{color:#191c1c;font-weight:600}
.pipe-title{font-size:14px;font-weight:600;color:#191c1c;letter-spacing:-.01em}
.pipe-chip{font-size:10.5px;font-weight:500;letter-spacing:.08em;text-transform:uppercase;color:#8a8f94}
.pipe-state{font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;min-height:15px}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border-width:0}
.empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:64px 24px;text-align:center;color:#a3a3a3}
.empty-state b{display:block;font-size:15px;font-weight:600;color:#525252;margin-bottom:4px}
#live-activity-section{margin-top:22px}
.activity-card{background:#fff;border:1px solid #e7e8ea;border-radius:14px;box-shadow:0 1px 3px rgba(0,0,0,.04);overflow:hidden;width:100%}
.activity-head{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));column-gap:18px;padding:9px 20px;border-bottom:1px solid #e7e8ea;background:#f5f5f5;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#191c1c;overflow-y:hidden;scrollbar-gutter:stable}
.activity-head span{text-align:center}
.activity-list{width:100%;max-height:230px;overflow-y:auto;scrollbar-gutter:stable}
.activity-list:empty::before{content:'Awaiting run events…';display:block;padding:10px 16px;font-size:11.5px;color:#a3a3a3;letter-spacing:.04em}
.trow{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));align-items:center;column-gap:18px;padding:7px 20px;border-bottom:1px solid #f0f1f2;font-size:12px;transition:background-color .18s}
.trow:last-child{border-bottom:none}
.tms{width:100%;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#191c1c;font-variant-numeric:tabular-nums;text-align:center}
.tlabel{width:100%;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#191c1c;text-align:center}
.taction{min-width:0;width:100%;display:block;color:#191c1c;overflow-wrap:anywhere;text-align:center}
@media (max-width:600px){.activity-head{grid-template-columns:96px minmax(0,1fr);column-gap:12px;padding:8px 12px}.activity-head span:nth-child(3){display:none}.trow{grid-template-columns:96px minmax(0,1fr);row-gap:2px;padding:6px 12px}.tlabel{width:auto;text-align:left}.tms{text-align:left}.taction{grid-column:2;text-align:left}}
.select-wrap{position:relative;display:inline-block;min-width:180px}.select-caret{position:absolute;right:9px;top:50%;transform:translateY(-50%);font-size:16px;color:#71717a;pointer-events:none}
'''


_JS = r'''
function escapeHTML(value){return String(value==null?'':value).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function busy(active){['btn-run','btn-replay','btn-reset'].forEach(function(id){var button=document.getElementById(id);if(button)button.disabled=active})}
async function post(path,body){var response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):null});return{status:response.status,data:await response.json()}}
function show(response){var status=document.getElementById('status'),view=document.getElementById('main-view');if(response.status>=400||!response.data.ok){status.textContent='';view.className='';view.innerHTML='<div class="run-error"><b>Run failed</b>: '+escapeHTML(response.data.detail||response.data.error||'request failed')+'</div>';return}status.textContent='\u2714 Completed \u00b7 Provider: '+response.data.provider_used+' \u00b7 Scenario: '+response.data.scenario+' \u00b7 Verdict: '+response.data.decision_label;view.className='';view.innerHTML=response.data.html;var shell=view.querySelector('.run-shell');var rid=document.getElementById('live-run-id');if(rid&&shell)rid.textContent=shell.getAttribute('data-run-id')||'-';var prov=document.getElementById('live-provider');if(prov)prov.textContent='Provider: '+(response.data.provider_label||response.data.provider_used||response.data.requested_provider||'-');var scen=document.getElementById('live-scenario');if(scen)scen.textContent='Scenario: '+(response.data.scenario_label||response.data.scenario||'-')}
/* --- Live SSE pipeline trace -------------------------------------------------
   The animation is driven ONLY by backend events delivered over the
   `/judge/stream` server-sent-events endpoint: one `{stage}_started`/
   `{stage}_completed` pair per real pipeline stage, then
   `run_completed`/`run_failed` with the authoritative rendered result. No
   timers, no client-side stage list. The trace itself is permanent; it is
   rendered on page load and never removed.

   The stream is read with fetch + ReadableStream instead of a native
   EventSource (`new EventSource(url)` is the drop-in alternative) because
   Chromium's EventSource only dispatches the FIRST frame of a connection's
   opening read: sibling frames in that read (e.g. red_ai_started arriving
   back-to-back with run_started) are parsed but never reach listeners. A
   fetch reader receives every frame as-is, so early stages are never lost.
   Reconnects use rAF backoff; there are no `setInterval`/`setTimeout` calls.
   Events still apply to the render queue (rAF) strictly in arrival order. */
var _handlers={},_activeReader=null,_streaming=false,_acct=0;
function closeLive(){_streaming=false;var r=_activeReader;if(r){try{r.cancel()}catch(e){} _activeReader=null}}
function onSSE(type,fn){(_handlers[type]=_handlers[type]||[]).push(fn)}
function _emitSSE(type,d){var hs=_handlers[type];if(hs){for(var i=0;i<hs.length;i++)hs[i](d)}}
function _onSSEframe(frame){
  var ev=frame.match(/^event: (.+)$/m),da=frame.match(/^data: (.+)$/m);
  if(!ev||!da)return;
  var type=ev[1].trim(),d;
  try{d=JSON.parse(da[1].trim())}catch(e){return}
  _emitSSE(type,d);
}
function _retrLater(url){
  /* rAF backoff: each retry doubles the wait, capped by requestAnimationFrame
     (no timers); only retries the LIVE stream, never after a terminal. */
  var n=++_acct,c=0,wait=Math.min(60,8*n);
  function step(){c++;if(c>=wait){_stream(url);return}requestAnimationFrame(step)}
  requestAnimationFrame(step);
}
async function _stream(url){
  if(_streaming&&_activeReader)return; /* already consuming a stream */
  _streaming=true;
  var resp;
  try{resp=await fetch(url,{headers:{'Accept':'text/event-stream'},cache:'no-store'})}
  catch(e){_streaming=false;_retrLater(url);return}
  if(!resp.ok||!resp.body){_streaming=false;_retrLater(url);return}
  var reader=resp.body.getReader(),dec=new TextDecoder(),buf='';
  _activeReader=reader;
  try{
    while(true){
      var chunk=await reader.read();
      if(chunk.done)break;
      buf+=dec.decode(chunk.value,{stream:true});
      var i;
      while((i=buf.indexOf('\n\n'))!==-1){
        var frame=buf.slice(0,i);buf=buf.slice(i+2);
        _onSSEframe(frame);
      }
    }
  }catch(e){/* aborted or dropped */}
  if(_activeReader===reader)_activeReader=null;
  /* terminal events set _streaming=false via their handlers; if the stream
     ended without a terminal we reconnect (run may still be in flight). */
  if(_streaming){_streaming=false;_retrLater(url)}
}
/* Live-state render queue: applies ONE real backend event per painted frame
   via requestAnimationFrame. This is not a timer and adds no latency: it
   only guarantees each lifecycle transition is committed to its own frame, so
   even sub-16ms deterministic stages (RISK ENG / POLICY / TOOL) visibly flow
   instead of collapsing into the final state. Events apply strictly in
   arrival order; nothing is synthesized, throttled or slowed. */
var _evQueue=[],_evPump=false;
function _evPumpStep(){var job=_evQueue.shift();if(!job){_evPump=false;return}job.apply();if(_evQueue.length){requestAnimationFrame(_evPumpStep)}else{_evPump=false}}
function queueLive(job){_evQueue.push(job);if(!_evPump){_evPump=true;requestAnimationFrame(_evPumpStep)}}
/* --- Live Activity trail ----------------------------------------------------
   Append-only, one row per REAL backend SSE event. The timestamp comes from
   the server's event-emission wall-clock (`ts`), never a frontend clock and
   never synthesized. The newest row stays highlighted until the NEXT real
   event arrives (no timers, no minimum display duration). The trail lives in
   the permanent trace section, so it survives RUN_COMPLETED untouched. */
function _fmtTs(ts){
  var ms=Math.round((Number(ts)||0)*1000),d=new Date(ms);function p(x){return('0'+x).slice(-2)}
  var m=('00'+Math.floor(ms%1000)).slice(-3);
  return p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds())+'.'+m;
}
function _cap(text){return String(text||'').toLowerCase().replace(/\b[a-z]/g,function(c){return c.toUpperCase()})}
function _activityRoot(){return document.getElementById('live-activity')}
function clearActivity(){var list=_activityRoot();if(list)list.innerHTML=''}
function _trailRow(title,action,ts){
  var list=_activityRoot();if(!list)return;
  var prev=list.querySelector('.trow--new');if(prev)prev.classList.remove('trow--new');
  var row=document.createElement('div');row.className='trow trow--new';
  row.innerHTML='<span class="tms">'+_fmtTs(ts)+'</span><span class="tlabel">'+escapeHTML(title)+'</span><span class="taction">'+escapeHTML(action)+'</span>';
  list.appendChild(row);
  if(list.scrollHeight>list.clientHeight)list.scrollTop=list.scrollHeight;
}
function activityRow(ev){
  var d=ev.display||{};
  var title=d.title||String(ev.stage||'ev').replace(/_/g,' ').toUpperCase();
  _trailRow(title,_cap(d.chip||''),ev.ts);
}
var _PIPE_IDLE='idle',_PIPE_RUN='running',_PIPE_DONE='completed',_PIPE_FAIL='failed';
function applyLive(phase,ev,extras){
  var li=document.querySelector('#live-pipeline li[data-stage-key="'+ev.stage+'"]');
  var card=document.getElementById('stage-'+ev.stage);
  var disp=extras&&extras.display||ev.display||{};
  var failed=extras&&extras.failed;
  if(phase==='started'){
    if(li){li.setAttribute('data-stage-status',_PIPE_RUN);li.className='pipe pipe--'+_PIPE_RUN;
      var alien=li.querySelector('[data-pipe-chip]');if(alien&&disp.chip)alien.textContent=disp.chip;}
    if(card){card.setAttribute('data-active','true');card.setAttribute('data-stage-status',_PIPE_RUN);
      card.classList.remove('step-card--done');card.classList.add('step-card--active');}
    var chipEL=card?card.querySelector('[data-stage-chip]'):null;
    if(chipEL&&disp.chip)chipEL.textContent=disp.chip;
    var valEL=card?card.querySelector('[data-stage-value]'):null;
    if(valEL&&disp.value)valEL.textContent=disp.value;
  }else if(failed){
    if(li){li.setAttribute('data-stage-status',_PIPE_FAIL);li.className='pipe pipe--'+_PIPE_FAIL;}
    if(card){card.setAttribute('data-stage-status',_PIPE_FAIL);
      card.classList.remove('step-card--active');card.classList.add('step-card--done');}
  }else{
    if(li){li.setAttribute('data-stage-status',_PIPE_DONE);li.className='pipe pipe--'+_PIPE_DONE;
      var doneChip=li.querySelector('[data-pipe-chip]');if(doneChip&&disp.chip)doneChip.textContent=disp.chip;}
    if(card){
      var chip=card.querySelector('[data-stage-chip]');if(chip&&disp.chip)chip.textContent=disp.chip;
      var label=card.querySelector('[data-stage-label]');if(label&&disp.label)label.textContent=disp.label;
      var value=card.querySelector('[data-stage-value]');if(value&&disp.value)value.textContent=disp.value;
      card.setAttribute('data-active','true');card.setAttribute('data-stage-status',_PIPE_DONE);
      card.classList.remove('step-card--active');card.classList.add('step-card--done');
    }
  }
}
function setPipeIdle(li){li.setAttribute('data-stage-status',_PIPE_IDLE);li.className='pipe pipe--'+_PIPE_IDLE;
  var c=li.querySelector('[data-pipe-chip]');if(c&&c.getAttribute('data-idle-chip'))c.textContent=c.getAttribute('data-idle-chip')}
function wireStages(stages){
  /* Stage listeners come from the server-authored stage list carried by
      `run_started`. Registration is SYNCHRONOUS (before any stage event is
      processed), so a fresh connect/replay can never drop early events; the
     frontend never hardcodes a stage order or index. */
  (stages||[]).forEach(function(stage){
    onSSE(stage+'_started',function(ev){queueLive({apply:function(){applyLive('started',ev);activityRow(ev)}})});
    onSSE(stage+'_completed',function(ev){queueLive({apply:function(){applyLive('completed',ev);activityRow(ev)}})});
  });
}
function initPipeline(stages){
  var orderEl=document.getElementById('live-pipeline');
  if(orderEl){var lis=orderEl.querySelectorAll('li');for(var i=0;i<lis.length;i++)setPipeIdle(lis[i])}
  var cards=document.querySelectorAll('.live-shell .step-card');
  for(var c=0;c<cards.length;c++){
    cards[c].setAttribute('data-active','false');cards[c].setAttribute('data-stage-status',_PIPE_IDLE);
    cards[c].classList.remove('step-card--active','step-card--done');
    var cc=cards[c].querySelector('[data-stage-chip]');if(cc&&cc.getAttribute('data-idle-chip'))cc.textContent=cc.getAttribute('data-idle-chip');
  }
}
function failStageAtRunEnd(){
  /* `run_failed` carries no stage that failed: mark the stage that was
     actually in flight (the only RUNNING one) as FAILED, honestly. */
  var running=document.querySelector('#live-pipeline li[data-stage-status="'+_PIPE_RUN+'"]');
  if(running){var key=running.getAttribute('data-stage-key');applyLive('completed',{stage:key},{failed:true})}
  var activeCard=document.querySelector('#main-view .step-card[data-active="true"]');
  if(activeCard){activeCard.setAttribute('data-stage-status',_PIPE_FAIL);
    activeCard.classList.remove('step-card--active');activeCard.classList.add('step-card--done')}
}
function resetPipeline(){
  /* The trace is permanent: reset it (and the context line) to the idle
     state instead of ever removing it from the page. */
  var orderEl=document.getElementById('live-pipeline');
  if(orderEl){var lis=orderEl.querySelectorAll('li');for(var i=0;i<lis.length;i++)setPipeIdle(lis[i])}
  var cards=document.querySelectorAll('#main-view .step-card');
  for(var c=0;c<cards.length;c++){
    cards[c].setAttribute('data-active','false');cards[c].setAttribute('data-stage-status',_PIPE_IDLE);
    cards[c].classList.remove('step-card--active','step-card--done');
    var cc=cards[c].querySelector('[data-stage-chip]');if(cc&&cc.getAttribute('data-idle-chip'))cc.textContent=cc.getAttribute('data-idle-chip');
  }
  var rid=document.getElementById('live-run-id');if(rid)rid.textContent='-';
  var prov=document.getElementById('live-provider');if(prov)prov.textContent='Provider: -';
  var scen=document.getElementById('live-scenario');if(scen)scen.textContent='Scenario: -';
  clearActivity();
}
function liveFail(view,status,title,message){view.className='';view.innerHTML='<div class="run-error"><b>'+escapeHTML(title)+'</b>: '+escapeHTML(message)+'</div>';status.textContent='Run failed';busy(false)}
async function run(){busy(true);closeLive();clearActivity();var view=document.getElementById('main-view'),status=document.getElementById('status');status.textContent='Starting live run on the authoritative pipeline\u2026';
  var response;
  try{response=await post('/judge/run?stream=1',{provider:document.getElementById('provider').value,scenario:document.getElementById('scenario').value})}
  catch(err){liveFail(view,status,'Run failed',err.message||'request failed');return}
  var data=response.data;
  if(!data.ok||data.status!=='started'){liveFail(view,status,'Run failed',data.detail||data.error||'request failed');return}
  var tpl=document.getElementById('live-skeleton');
  view.className='';view.innerHTML=tpl?tpl.innerHTML:'<div class="empty-state"><b>No run yet.</b></div>';
  var rid=document.getElementById('live-run-id');if(rid)rid.textContent=data.run_id;
  var prov=document.getElementById('live-provider');if(prov)prov.textContent='Provider: '+(data.provider_label||data.requested_provider||'-');
  var scen=document.getElementById('live-scenario');if(scen)scen.textContent='Scenario: '+(data.scenario_label||data.scenario||'-');
  status.textContent='Watching live pipeline\u2026';
  _handlers={};
  onSSE('run_started',function(msg){wireStages(msg.stages||[]);queueLive({apply:function(){initPipeline(msg.stages);var mr=document.getElementById('live-run-id');if(mr&&msg.run_id)mr.textContent=msg.run_id;_trailRow('Judge run','Started',msg.ts)}})});
  onSSE('run_completed',function(msg){_streaming=false;queueLive({apply:function(){closeLive();_trailRow('Result',msg.meta.decision_label||'Completed',msg.ts);status.textContent='\u2714 Completed \u00b7 Provider: '+(msg.meta.provider_used||'')+' \u00b7 Scenario: '+(msg.meta.scenario||'')+' \u00b7 Verdict: '+(msg.meta.decision_label||'');view.className='';view.innerHTML=msg.html;busy(false)}})});
  onSSE('run_failed',function(msg){_streaming=false;queueLive({apply:function(){failStageAtRunEnd();closeLive();_trailRow('Result','Failed'+(msg.error?' \u00b7 '+msg.error:''),msg.ts||0);view.className='';view.innerHTML=msg.html||'<div class="run-error"><b>Run failed</b>: '+escapeHTML(msg.error||'no pipeline result')+'</div>';status.textContent='Run failed';busy(false)}})});
  _stream('/judge/stream?run_id='+data.run_id);
}
async function replay(){busy(true);document.getElementById('status').textContent='Replaying the most recent request\u2026';try{show(await post('/judge/replay'))}finally{busy(false)}}
async function reset(){busy(true);try{var response=await post('/judge/reset');var view=document.getElementById('main-view');document.getElementById('status').textContent=response.data.ok?'Ready. Choose a scenario and press Run Scenario.':'Reset failed.';view.className='';view.innerHTML='<div class="empty-state"><b>No run yet.</b>The live policy result will appear here after Run Scenario.</div>';resetPipeline()}finally{busy(false)}}
/* Restore the last committed run after a reload. The server still holds it, so
   a judge who refreshes (or demos from a fresh tab) must not silently lose the
   result they were looking at. Nothing is re-executed: this only re-renders the
   stored run, and the status line says so, so a restored verdict can never be
   mistaken for a fresh one. */
async function restoreLast(){try{var response=await fetch('/judge/state',{headers:{'Accept':'application/json'}});if(!response.ok)return;var payload=await response.json();var last=payload&&payload.last;if(!last||!last.html)return;var view=document.getElementById('main-view'),status=document.getElementById('status');view.className='';view.innerHTML=last.html;var shell=view.querySelector('.run-shell');var rid=document.getElementById('live-run-id');if(rid&&shell)rid.textContent=shell.getAttribute('data-run-id')||'-';var prov=document.getElementById('live-provider');if(prov)prov.textContent='Provider: '+(last.provider_used||last.requested_provider||'-');var scen=document.getElementById('live-scenario');if(scen)scen.textContent='Scenario: '+(last.scenario||'-');status.textContent='Showing the last completed run (restored, not re-executed) · Provider: '+(last.provider_used||last.requested_provider||'-')+' · Scenario: '+(last.scenario||'-')+' · Verdict: '+(last.decision_label||'no decision')}catch(_e){/* a failed restore must not break the page */}}
document.getElementById('btn-run').addEventListener('click',run);document.getElementById('btn-replay').addEventListener('click',replay);document.getElementById('btn-reset').addEventListener('click',reset);restoreLast();
'''


def render_page() -> str:
    """Standalone interactive judge page; all verdicts come from ``/judge/run``."""
    provider_options = "".join(f'<option value="{_esc(p)}">{_esc(_PROVIDER_LABELS[p])}</option>' for p in PROVIDERS)
    scenario_options = "".join(f'<option value="{_esc(s)}">{_esc(_SCENARIO_LABELS[s])}</option>' for s in SCENARIOS)
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>WIENER: Judge Live Demo</title>
  <!-- Fully local presentation layer: no CDN script, no webfont, no external
       request of any kind, so the Judge UI renders identically offline. -->
  <link rel="stylesheet" href="/judge/tailwind.css">
  <style>{_CSS}</style>
</head>
<body class="bg-[#f5f5f7] text-neutral-900 font-sans antialiased">
  {render_topbar('judge')}
  <main class="max-w-[1152px] mx-auto px-4 py-6 pb-14">
    <section class="bg-white rounded-2xl border border-neutral-200 shadow-[0_1px_3px_rgba(0,0,0,.04)] p-6 mb-4" id="judge-controls">
      <div class="flex items-end justify-between gap-4 mb-5">
        <div>
          <h2 class="text-[20px] font-semibold tracking-[-0.02em] leading-[1.3] text-neutral-900">Judge Controls</h2>
          <p class="text-[11px] text-neutral-400 mt-0.5">Configure the live scenario and inference provider</p>
        </div>
      </div>
      <div id="status" class="inline-flex items-center gap-2 px-3 py-1.5 bg-neutral-100 rounded-lg text-[12px] font-medium text-neutral-600 mb-5">Ready. Choose a scenario and press Run Scenario.</div>
      <div class="flex flex-wrap items-end justify-between gap-4">
        <div class="flex flex-wrap items-end gap-3">
          <div class="grid gap-1.5">
            <label for="scenario" class="text-[10px] font-medium tracking-widest uppercase text-neutral-500">Attack Scenario Vector</label>
            <div class="select-wrap">
              {_icon("expand_more", "ico select-caret")}
              <select id="scenario" class="appearance-none bg-neutral-100 border-0 rounded-lg px-3 py-2 pr-8 text-[13px] text-neutral-900 min-w-[180px]">{scenario_options}</select>
            </div>
          </div>
          <div class="grid gap-1.5">
            <label for="provider" class="text-[10px] font-medium tracking-widest uppercase text-neutral-500">Model</label>
            <div class="select-wrap">
              {_icon("expand_more", "ico select-caret")}
              <select id="provider" class="appearance-none bg-neutral-100 border-0 rounded-lg px-3 py-2 pr-8 text-[13px] text-neutral-900 min-w-[180px]">{provider_options}</select>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <button id="btn-run" type="button" class="inline-flex items-center gap-1.5 px-4 py-2 bg-neutral-900 text-white text-[13px] font-medium rounded-lg hover:bg-neutral-800 transition disabled:opacity-50">
            {_icon("play_arrow", "ico text-sm")} Run Scenario
          </button>
          <button id="btn-reset" type="button" class="inline-flex items-center gap-1.5 px-3 py-2 bg-neutral-100 text-neutral-700 text-[13px] font-medium rounded-lg hover:bg-neutral-200 transition disabled:opacity-50">
            {_icon("refresh", "ico text-sm")} Reset
          </button>
          <button id="btn-replay" type="button" class="inline-flex items-center gap-1.5 px-3 py-2 bg-neutral-100 text-neutral-700 text-[13px] font-medium rounded-lg hover:bg-neutral-200 transition disabled:opacity-50" title="Replay the latest real judge request">
            {_icon("replay", "ico text-sm")} Replay Locked Trial
          </button>
        </div>
      </div>
    </section>
    <section class="mt-4" id="live-result-section">
      <div id="main-view"><div class="empty-state bg-white rounded-2xl border border-neutral-200 shadow-[0_1px_3px_rgba(0,0,0,.04)]"><b>No run yet.</b>The live policy result will appear here after Run Scenario.</div></div>
    </section>
    <div id="live-trace-holder">{_live_trace_section()}</div>
    <template id="live-skeleton">{render_live_skeleton()}</template>
</main>
  <script>{_JS}</script>
</body>
</html>'''


def run_to_meta(run: JudgeRun) -> dict:
    return {"run_id": run.run_id, "requested_provider": run.requested_provider, "provider_used": run.provider_used, "provider_tier": _provider_tier(run), "replay_mode": run.replay_mode, "scenario": run.scenario, "decision": run.decision, "decision_label": _decision_label(run.decision), "proposed_action": run.proposed_action, "error": run.error}
