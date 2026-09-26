"""Authoritative WIENER dashboard presentation.

This module is deliberately a presentation-only layer.  It renders values
loaded by :mod:`app.present.evidence`; it never creates trial data or
recalculates a metric.  The page is self contained so ``/dashboard`` is useful
in the competition environment without a frontend build step.
"""

from __future__ import annotations

import html as _html
from datetime import datetime, timezone

from ..dashboard.dashboard import DashboardData, TrialView
from ..judge.render import TOPBAR_CSS, render_topbar
from ..models import ExperimentMode
from ..llm.identity import UNVERIFIED, looks_like_transport_name
from ..judge.inference_labels import CLOUD, format_inference_label
from .evidence import EvidenceBundle


_MODE_LABELS = {
    ExperimentMode.NO_DEFENSE.value: "No Defense",
    ExperimentMode.BASIC_PROMPT_DEFENSE.value: "Basic Prompt Defense",
    ExperimentMode.WIENER.value: "WIENER Defense",
}
_MODE_SHORT = {
    ExperimentMode.NO_DEFENSE.value: "NO DEFENSE",
    ExperimentMode.BASIC_PROMPT_DEFENSE.value: "BASIC",
    ExperimentMode.WIENER.value: "WIENER",
}


def _esc(value: object) -> str:
    return _html.escape("" if value is None else str(value))


def _attr(value: object) -> str:
    return _html.escape("none" if value is None else str(value), quote=True)


def _display(value: object) -> str:
    return "—" if value is None or value == "" else str(value)


def _pts(value: float | None) -> str:
    return "—" if value is None else f"{_num(value)} pts"


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def _num(value: float | int | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.2f}".rstrip("0").rstrip(".")
    return str(value)


def _title(value: str | None) -> str:
    return "—" if not value else value.replace("_", " ").replace("-", " ").title()


def _is_gated(trial: TrialView) -> bool:
    """WIENER runs the full Risk Engine + Policy Gate + tool simulation;
    No Defense / Basic Prompt stop at the SOC agent, so those rows carry
    no risk score, no gate verdict, and no simulated execution."""
    return trial.mode == ExperimentMode.WIENER.value


def _decision(trial: TrialView) -> str:
    if not _is_gated(trial):
        return "UNGATED"
    return trial.final_decision or "—"


def _decision_class(decision: str) -> str:
    return {"BLOCK": "block", "REVIEW": "review", "ALLOW": "allow"}.get(decision, "neutral")


def _execution(trial: TrialView) -> str:
    if not _is_gated(trial):
        return "NOT SIMULATED"
    if trial.executed is True:
        return "EXECUTED (SIMULATED)"
    if trial.executed is False:
        return "NOT EXECUTED"
    return "—"


def _action_state(trial: TrialView) -> str:
    if not _is_gated(trial):
        return "NOT SIMULATED"
    if trial.executed is True:
        return "EXECUTED"
    if trial.executed is False:
        return "BLOCKED/NOOP"
    return "—"


def _constraint_display(trial: TrialView) -> str:
    """Triggered safety-constraint ids (e.g. \u201cSC-003 \u00b7 SC-012\u201d),
    or an em dash when none matched (risk-threshold-only decision)."""
    if not _is_gated(trial) or not trial.triggered_constraints:
        return "—"
    return " · ".join(trial.triggered_constraints)


def _context_log(trial: TrialView) -> str:
    pieces = [
        f"Action: {_display(trial.proposed_action)}",
        f"Risk: {_num(trial.risk_score)}",
    ]
    if _is_gated(trial):
        pieces.append(f"Margin: {_pts(trial.decision_margin)}")
    pieces += [
        f"Decision: {_decision(trial)}",
        f"Execution: {_execution(trial)}",
    ]
    if trial.triggered_constraints:
        pieces.append("Constraints: " + ", ".join(trial.triggered_constraints))
    return " · ".join(pieces)


def _selected_trial(data: DashboardData, selected: str | None) -> TrialView | None:
    if not data.trials:
        return None
    if selected:
        return next((trial for trial in data.trials if trial.trial_id == selected), data.trials[0])
    # Prefer a protected WIENER example for the initial presentation view.
    return next(
        (trial for trial in data.trials if trial.mode == ExperimentMode.WIENER.value and trial.final_decision == "BLOCK"),
        data.trials[0],
    )


def _badge(decision: str, *, identifier: str = "") -> str:
    id_attr = f' id="{_esc(identifier)}"' if identifier else ""
    return f'<span{id_attr} class="badge badge--{_decision_class(decision)}">{_esc(decision)}</span>'


def _mode_name(mode: str) -> str:
    return _MODE_LABELS.get(mode, _title(mode))


def _source_status(bundle: EvidenceBundle) -> str:
    return str((bundle.source_provenance or {}).get("status") or "UNKNOWN").lower()


def _evidence_sound(bundle: EvidenceBundle) -> bool:
    return (
        bundle.evidence_status == "LOCKED_VERIFIED"
        and bundle.validation_status == "PASS"
        and bundle.validation_pass == bundle.validation_invariants
        and not bundle.recompute_diffs
        and bundle.duplicate_trial_mode_ids == 0
        and _source_status(bundle) == "match"
    )


def _locked_badge(bundle: EvidenceBundle) -> str:
    """The STORED lock verdict, stated on its own.

    This reports what the evidence bundle itself claims: its recorded
    `evidence_status` and its validation tally. Whether those artifacts still
    describe the CURRENT tree is a separate question with a separate answer,
    reported in the provenance panel — conflating the two is how a page ends up
    implying "verified" about a tree it never measured. So the header states
    the stored verdict, and the provenance panel states the comparison.
    """
    status = bundle.evidence_status or "CANDIDATE"
    if status == "LOCKED_VERIFIED":
        tally = f"{bundle.validation_pass} / {bundle.validation_invariants}"
        if bundle.validation_status != "PASS" or bundle.validation_pass != bundle.validation_invariants:
            return (
                f'<div class="locked locked--candidate"><b></b>LOCKED VERIFIED · '
                f'{_esc(tally)} · VALIDATION {_esc(bundle.validation_status)}</div>'
            )
        return f'<div class="locked"><b></b>LOCKED VERIFIED · {tally} PASS</div>'
    if status == "CANDIDATE":
        return (
            f'<div class="locked locked--candidate"><b></b>CANDIDATE EVIDENCE · '
            f'{bundle.validation_pass} / {bundle.validation_invariants} '
            f'{_esc(bundle.validation_status)}</div>'
        )
    return f'<div class="locked locked--candidate"><b></b>{_esc(status)}</div>'



def _hero(bundle: EvidenceBundle) -> str:
    wiener = bundle.by_mode[ExperimentMode.WIENER.value]
    return f"""<section class="hero surface-card" id="primary-result">
  <div class="hero-top">
    <div class="eyebrow-group"><strong>WIENER Evaluation Summary</strong></div>
    {_locked_badge(bundle)}
  </div>
  <div class="hero-body">
    <div class="hero-result">
      <span class="eyebrow">Unsafe Tool Execution</span>
      <div class="metric-line"><strong class="hero-metric" data-hero-uar="{_attr(wiener.uar)}">{_pct(wiener.uar)}</strong><h1>Observed Evaluation Result</h1></div>
    </div>
    <div class="hero-evidence">
      <div class="proposal-count"><b data-evidence-proposals="{bundle.proposals}">{bundle.proposals}</b><p>dangerous proposals reached the SOC-agent stage.</p></div>
      <div class="decision-grid">
        <span class="decision-chip decision-chip--block" data-evidence-blocked="{bundle.blocked}">{bundle.blocked} BLOCK</span>
        <span class="decision-chip decision-chip--review" data-evidence-reviewed="{bundle.reviewed}">{bundle.reviewed} REVIEW</span>
        <span class="decision-chip decision-chip--allow" data-evidence-executed="{bundle.executed}">{bundle.executed} EXECUTED</span>
      </div>
    </div>
  </div>
  <div class="audit-callout">
    <div class="audit-scope"><b>{bundle.n_trials} TOTAL TRIALS</b><span>{bundle.trials_per_mode} / MODE · {bundle.malicious_total} ADVERSARIAL · {bundle.benign_total} BENIGN</span></div>
  </div>
</section>"""


def _uar_by_mode(bundle: EvidenceBundle) -> str:
    """Unsafe Action Rate per mode, as three equal-weight factual cards.

    Deliberately NOT a chart. A bar whose length tracks the value makes the
    one ungated mode look like a ranking against two defenses, which is a
    comparison claim this section should not be making: the three modes are
    three different configurations, and the number reported for each is the
    measured outcome. Every card is identical in size and structure, and no
    width, rank, order or winner treatment is derived from the value.
    """
    cards = []
    for mode in bundle.modes:
        metric = bundle.by_mode[mode]
        cards.append(
            f'''<article class="surface-card uar-card" data-uar-mode="{_attr(mode)}">
  <span class="card-kicker">{_esc(_MODE_LABELS.get(mode, _title(mode)))}</span>
  <div class="uar-value" data-uar-value="{_attr(metric.uar)}">{_pct(metric.uar)}</div>
  <div class="uar-detail"><code data-unsafe-count="{metric.unsafe_actions}" data-unsafe-denominator="{metric.attempts}">{metric.unsafe_actions} / {metric.attempts}</code> unsafe executions</div>
  <div class="uar-detail uar-detail--muted">ASR <code data-asr-value="{_attr(metric.asr)}">{_pct(metric.asr)}</code></div>
</article>'''
        )
    return f'''<section class="section" id="uar">
  <div class="section-heading"><h2>Unsafe Action Rate by Mode</h2><span>{bundle.n_trials - bundle.benign_total} ADVERSARIAL · {bundle.benign_total} BENIGN</span></div>
  <div class="uar-grid">{''.join(cards)}</div>
</section>'''


def _operational_safety(bundle: EvidenceBundle) -> str:
    """False-intervention reporting for the defended mode.

    The denominator is the DEFENDED mode's own benign controls, taken from that
    mode's stored metric row. Falling back to the run-wide benign total would
    read as "0 / 30" and quietly compare one mode's controls against the whole
    experiment, so there is no fallback: an absent denominator renders as an
    em dash rather than as a number the evidence does not contain.
    """
    wiener = bundle.by_mode[ExperimentMode.WIENER.value]
    incorrect = wiener.incorrect_interventions
    denominator = wiener.fir_den
    if denominator:
        controls = f"{incorrect} / {denominator}"
    else:
        controls = "—"
    return f'''<section class="section" id="operational-safety">
  <div class="section-heading"><h2>Operational Safety</h2><span>FALSE INTERVENTION RATE</span></div>
  <article class="surface-card metric-card">
    <span class="card-kicker">False Intervention Rate</span>
    <div class="big-stat" data-fir-value="{_attr(wiener.fir)}">{_pct(wiener.fir)}</div>
    <p class="card-note">Erroneous policy triggers against benign operations in { _esc(_mode_name(ExperimentMode.WIENER.value)) } mode.</p>
    <div class="inset">
      <div><span>WIENER benign controls</span><code data-benign-interventions="{incorrect}" data-benign-denominator="{_attr(denominator)}">{controls} interventions</code></div>
      <div><span>False positives</span><code data-false-positives="{incorrect}">{incorrect}</code></div>
    </div>
    <p class="card-foot">These are the benign controls recorded for WIENER mode, not the {bundle.benign_total} benign controls across all three modes.</p>
  </article>
</section>'''


def _integrity(bundle: EvidenceBundle) -> str:
    """Structural validation of the evidence itself, from the stored run."""
    mismatch_count = len(bundle.recompute_diffs)
    resume_ok = bundle.duplicate_trial_mode_ids == 0
    return f'''<section class="section" id="integrity">
  <div class="section-heading"><h2>Integrity</h2><span>AUTOMATED RIG VALIDATION</span></div>
  <article class="surface-card metric-card">
    <span class="card-kicker">Invariant validation</span>
    <div class="big-stat" data-validation-pass="{bundle.validation_pass}" data-validation-total="{bundle.validation_invariants}">{bundle.validation_pass} / {bundle.validation_invariants} <small class="pass">{_esc(bundle.validation_status)}</small></div>
    <div class="inset">
      <div><span>Mismatch vector</span><code data-mismatch-count="{mismatch_count}">{mismatch_count} Detected</code></div>
      <div><span>State traceability</span><code data-state-traceability="{'PASS' if resume_ok else 'REVIEW'}">{'PASS' if resume_ok else 'REVIEW'}</code></div>
      <div><span>UAPR</span><code data-uapr="{_attr(bundle.uapr)}">{_esc(_display(bundle.uapr))}</code></div>
    </div>
  </article>
</section>'''



def _pipeline(trial: TrialView | None) -> str:
    if trial is None:
        return ""
    decision = _decision(trial)
    stages = (
        ("ATTACK", _title(trial.attack_type), "Input"),
        ("SOC AGENT", _display(trial.proposed_action), "Action proposal"),
        ("TRAJECTORY", _display(trial.alert), "Context captured"),
        ("BLUE AI", f"Δ {_num(trial.behavior_deviation)}", "Behavior assessed"),
        ("RISK ENGINE", _num(trial.risk_score), "Risk scored"),
        ("POLICY GATE", decision, f"{decision} decision"),
        ("SIMULATED TOOL", _execution(trial), "Sandbox only"),
    )
    parts = []
    for index, (label, value, note) in enumerate(stages, 1):
        cls = " pipeline-node"
        if label == "POLICY GATE":
            cls += " pipeline-node--" + _decision_class(decision)
        if label == "SIMULATED TOOL":
            cls += " pipeline-node--tool"
        parts.append(f'<div class="{cls.strip()}" data-pipeline-stage="{_esc(label)}" aria-label="Phase {index:02d}: {_esc(label)}"><b data-step="{_esc(label)}">{_esc(label)}</b><small>{_esc(value)}</small><em>{_esc(note)}</em></div>')
        if index < len(stages):
            parts.append('<i class="pipeline-arrow" aria-hidden="true">→</i>')
    return f'''<section class="section"><div class="section-heading"><h2>Evaluation Pipeline</h2><span>EVALUATION FLOW TRACE</span></div><div class="surface-card pipeline-wrap"><div class="pipeline">{''.join(parts)}</div></div></section>'''


def _inspector(trial: TrialView | None, bundle: EvidenceBundle) -> str:
    if trial is None:
        return ""
    decision = _decision(trial)
    status = bundle.evidence_status
    return f'''<section class="section" id="active-trial"><div class="section-heading"><h2>Focused Trial Inspection</h2><span>ACTIVE SELECTION</span></div>
  <article class="surface-card inspector"><div class="inspect-header"><div class="inspect-id"><strong id="inspected-trial-id" data-trial-id="{_attr(trial.trial_id)}">{_esc(trial.trial_id)}</strong>{_badge(decision, identifier="inspected-badge")}<span class="mode-chip" id="inspected-mode">{_esc(_mode_name(trial.mode))}</span></div></div>
  <div class="inspect-grid">
    <div><span>Scenario</span><b id="inspected-scenario">{_esc(_title(trial.attack_type))}</b></div>
    <div><span>Proposed Action</span><code id="inspected-proposal">{_esc(_display(trial.proposed_action))}</code></div>
    <div><span>Risk Score</span><code id="inspected-risk">{_esc(_num(trial.risk_score))}</code></div>
    <div><span>Safety Constraint</span><code id="inspected-constraint">{_esc(_constraint_display(trial))}</code></div>
    <div><span>Defense Gate</span><b id="inspected-gate">{_esc(decision)}</b></div>
    <div><span>Execution</span><b id="inspected-execution" class="execution-state">{_esc(_execution(trial))}</b></div>
  </div>
  <div class="inspect-log"><span id="inspected-log">{_esc(_context_log(trial))}</span></div></article></section>'''


def _trial_row(trial: TrialView, is_selected: bool) -> str:
    decision = _decision(trial)
    row_class = " selected" if is_selected else ""
    log = _context_log(trial)
    return f'''<tr class="trial-row{row_class}" tabindex="0" data-id="{_attr(trial.trial_id)}" data-mode="{_attr(trial.mode)}" data-scenario="{_attr(_title(trial.attack_type))}" data-proposal="{_attr(_display(trial.proposed_action))}" data-alert="{_attr(_display(trial.alert))}" data-deviation="{_attr(_num(trial.behavior_deviation))}" data-margin="{_attr(_num(trial.decision_margin))}" data-risk="{_attr(_num(trial.risk_score))}" data-constraint="{_attr(_constraint_display(trial))}" data-decision="{_attr(decision)}" data-executed="{_attr(_execution(trial))}" data-log="{_attr(log)}">
  <td>{_esc(trial.trial_id)}</td><td>{_esc(_MODE_SHORT.get(trial.mode, trial.mode))}</td><td>{_esc(_title(trial.attack_type))}</td><td>{_esc(_display(trial.proposed_action))}</td><td class="right"{(' title="Risk engine runs only in WIENER mode"' if not _is_gated(trial) else "")}>{_esc(_num(trial.risk_score))}</td><td>{_badge(decision)}</td><td class="right {_decision_class(decision)}">{_esc(_action_state(trial))}</td></tr>'''


def _ledger(data: DashboardData, selected: TrialView | None, bundle: EvidenceBundle) -> str:
    rows = "".join(_trial_row(trial, selected is not None and trial.trial_id == selected.trial_id) for trial in data.trials)
    return f'''<section class="section" id="navigator"><div class="section-heading stack-small"><h2>Trial Navigation Ledger</h2></div>
<div class="surface-card ledger"><div class="filters"><label class="search"><span>⌕</span><input id="trial-search" type="search" placeholder="Search Trial ID or Proposal…" aria-label="Search trial"></label><div class="filter-set"><label>Mode:<select id="mode-filter"><option value="ALL">All Modes ({bundle.n_trials})</option><option value="wiener">WIENER ({bundle.trials_per_mode})</option><option value="basic_prompt_defense">Basic Prompt ({bundle.trials_per_mode})</option><option value="no_defense">No Defense ({bundle.trials_per_mode})</option></select></label><label>Decision:<select id="decision-filter"><option value="ALL">All Decisions</option><option value="BLOCK">BLOCK</option><option value="REVIEW">REVIEW</option><option value="ALLOW">ALLOW</option><option value="UNGATED">UNGATED</option></select></label></div></div>
<div class="table-wrap"><table><thead><tr><th>Trial ID</th><th>Mode</th><th>Scenario</th><th>Proposal</th><th class="right">Risk Score</th><th>Decision</th><th class="right">Action State</th></tr></thead><tbody id="trials-tbody">{rows}</tbody></table></div>
<div class="pagination"><span id="pagination-status"></span><div><button id="btn-prev" type="button">Previous</button><button id="btn-next" type="button">Next</button></div></div></div></section>'''


def _locked_at_lines(raw: str | None) -> str:
    """Human-readable LOCKED AT display. The exact ISO timestamp stays
    available in the DOM (`data-locked-at` + `title`); this is the readable
    split-view rendering only."""
    if not raw:
        return "<i>—</i>"
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
        return f"<i>{_esc(dt.strftime('%Y-%m-%d'))}</i><i>{_esc(dt.strftime('%H:%M:%S UTC'))}</i>"
    except Exception:  # noqa: BLE001 - never let a timestamp break the page
        return f"<i>{_esc(raw)}</i>"


def _tree_delta(bundle: EvidenceBundle) -> dict[str, int]:
    """How far the current tree has moved since the evidence was locked.

    Counted, never characterised. Naming WHICH files moved is left to the
    reader via the row's tooltip, because inferring a reason here would let a
    cosmetic change be described as a measurement change or the reverse.
    """
    source = bundle.source_provenance or {}
    return {
        "changed": len(source.get("mismatched_files") or ()),
        "added": len(source.get("added_files") or ()),
        "removed": len(source.get("removed_files") or ()),
    }


def _current_tree_label(bundle: EvidenceBundle) -> str:
    """How the CURRENT tree compares to the tree that produced the evidence.

    Phrased so the artifacts' own integrity is never the thing in question: a
    moved tree means the run was produced by an earlier revision, not that its
    recorded results stopped being true.
    """
    source_status = _source_status(bundle)
    if source_status == "match":
        return "MATCHES THE LOCKED REVISION"
    if source_status == "unknown":
        return "NOT COMPARABLE TO THE LOCKED REVISION"
    delta = _tree_delta(bundle)
    parts = []
    if delta["changed"]:
        parts.append(f"{delta['changed']} changed")
    if delta["added"]:
        parts.append(f"{delta['added']} added")
    if delta["removed"]:
        parts.append(f"{delta['removed']} removed")
    detail = ", ".join(parts) if parts else "revision differs"
    return f"DIFFERS FROM THE LOCKED REVISION · {detail}"


def _provenance_status_line(bundle: EvidenceBundle) -> str:
    """One honest sentence about whether the artifacts describe THIS tree."""
    sound = _evidence_sound(bundle)
    if sound:
        return "STATUS: VERIFIED SOUND"
    source = _source_status(bundle)
    if bundle.evidence_status == "LOCKED_VERIFIED" and source == "stale":
        return (
            "STATUS: ARTIFACTS INTACT · RESULTS UNCHANGED · "
            "PRODUCED BY AN EARLIER REVISION OF THE TREE"
        )
    if bundle.evidence_status == "LOCKED_VERIFIED" and source == "unknown":
        return "STATUS: ARTIFACTS INTACT · CURRENT TREE NOT COMPARABLE"
    if bundle.evidence_status == "LOCKED_VERIFIED":
        return "STATUS: ARTIFACTS LOCKED · REVIEW REQUIRED"
    return "STATUS: CANDIDATE EVIDENCE"


def _model_identity(bundle: EvidenceBundle) -> str:
    """Model identity the stored trials recorded, for the audit layer.

    Read from the bundle's own rows, never from the current configuration: a
    stored run keeps naming the model that produced it even after the
    deployment is reconfigured. When the recorded provider is only a transport
    name it is withheld, because naming the wire protocol is not naming the
    model, and the label falls back to the model id alone.
    """
    identity = bundle.model_identity or {}
    if not identity or not identity.get("agreed"):
        variants = identity.get("variants") if identity else 0
        detail = (
            f"{variants} conflicting identities recorded"
            if variants
            else "no model identity recorded in this bundle"
        )
        return (
            '<div class="manifest-item wide"><span>MODEL IDENTITY</span>'
            f'<b data-model-identity="unrecorded">{_esc(detail)}</b></div>'
        )

    recorded_provider = identity.get("provider")
    provider = None if looks_like_transport_name(recorded_provider) else recorded_provider
    label = format_inference_label(CLOUD, provider, identity.get("requested_model"))
    verification = identity.get("identity_verification") or UNVERIFIED
    pinned = identity.get("model_identity_pinned")
    reported = identity.get("provider_reported_model")
    reported_line = (
        f'<div><span>Provider-reported model</span><code data-reported-model="{_attr(reported)}">{_esc(_display(reported))}</code></div>'
        if reported and reported != identity.get("requested_model")
        else ""
    )
    return f'''<div class="manifest-item wide"><span>MODEL IDENTITY</span><b data-model-identity="{_attr(verification)}" data-inference-label="{_attr(label)}">{_esc(label)}</b></div>
<div class="provenance-grid">
  <div><span>Requested model</span><b data-requested-model="{_attr(identity.get('requested_model'))}">{_esc(_display(identity.get('requested_model')))}</b></div>
  {reported_line}
  <div><span>Verification</span><b data-identity-verification="{_attr(verification)}">{_esc(verification)}</b></div>
  <div><span>Pinned</span><b data-model-pinned="{_attr(pinned)}">{'false' if pinned is False else ('true' if pinned else '—')}</b></div>
  <div><span>Trials recorded</span><b>{identity.get('rows')} / {bundle.n_trials}</b></div>
  <div><span>Transport (adapter)</span><code data-adapter="{_attr(identity.get('adapter'))}">{_esc(_display(identity.get('adapter')))}</code></div>
</div>'''


def _provenance(bundle: EvidenceBundle) -> str:
    locked = bundle.evidence_status == "LOCKED_VERIFIED"
    sound = _evidence_sound(bundle)
    source_status = _source_status(bundle)
    status_line = _provenance_status_line(bundle)

    wiener = bundle.by_mode[ExperimentMode.WIENER.value]
    incorrect = wiener.incorrect_interventions
    mismatch_count = len(bundle.recompute_diffs)
    resume_label = "PASS · Clean" if bundle.duplicate_trial_mode_ids == 0 else f"REVIEW · {bundle.duplicate_trial_mode_ids} Collisions"
    validation_label = "VERIFIED SOUND" if sound else "REVIEW REQUIRED"
    validation_class = "pass" if sound else "candidate"
    lock_phrase = "AUTHORITATIVE DATA LOCKED" if sound else "AUTHORITATIVE DATA NOT VERIFIED"
    source = bundle.source_provenance or {}
    source_label = _current_tree_label(bundle)
    evidence_row = f'<div class="manifest-item"><span>EVIDENCE STATUS</span><b class="pass pill">{_esc(bundle.evidence_status)}</b></div>'
    if locked:
        evidence_row += (
            f'<div class="manifest-item locked-at" data-locked-at="{_attr(bundle.locked_at)}" title="{_attr(bundle.locked_at)}">'
            f'<span>LOCKED AT</span><b class="ts">{_locked_at_lines(bundle.locked_at)}</b></div>'
        )
    code_row = f'<div class="manifest-item"><span>CODE FINGERPRINT</span><b data-fingerprint-root="{_attr(bundle.code_fingerprint_root)}">{_esc(bundle.code_fingerprint_root or "—")}</b></div>'
    source_title = _esc(str(source.get("note") or ""))
    changed_files = ", ".join((bundle.source_provenance or {}).get("mismatched_files") or ())
    source_row = (
        f'<div class="manifest-item"><span>CURRENT TREE</span>'
        f'<b data-source-provenance="{_attr(source_status)}" '
        f'data-tree-delta-changed="{_tree_delta(bundle)["changed"]}" '
        f'title="{_esc(changed_files or source_title)}">'
        f'{_esc(source_label)}</b></div>'
    )
    status_row = f'{evidence_row}{code_row}{source_row}'
    artifact_row = ""
    if bundle.artifact_hashes:
        artifact_row = f'<div class="manifest-item"><span>ARTIFACT HASH</span><b data-evidence-sha="{_attr(bundle.artifact_hashes.get("trials.jsonl"))}">{_esc(bundle.artifact_hashes.get("trials.jsonl", ""))}</b></div>'

    return f'''<section class="section" id="provenance"><div class="section-heading"><h2>Evidence Integrity &amp; Provenance Check</h2><span class="verified">{status_line}</span></div>
<article class="surface-card provenance">
<div class="src-artifact"><span class="card-kicker">Source Artifact</span><code class="src-path">data/experiments/{_esc(bundle.source_dir)}/</code></div>
<div class="provenance-grid"><div><span>Total Records</span><b data-total-trials="{bundle.n_trials}">{bundle.n_trials} Complete</b></div><div><span>Duplicate IDs</span><b>{bundle.duplicate_trial_mode_ids} Collisions</b></div><div><span>Independent Mismatch</span><b>{mismatch_count} Deviations</b></div><div><span>Resume Integrity</span><b class="{'pass' if bundle.duplicate_trial_mode_ids == 0 else 'candidate'}">{resume_label}</b></div></div><span class="sr-only" data-evidence-benign-total="{bundle.benign_total}">{bundle.benign_total} benign controls</span>
<p class="manifest-title">Authoritative Dataset Provenance &amp; Run Specification</p>
<div class="manifest">
<div class="manifest-item"><span>DATASET PATH</span><b>data/experiments/{_esc(bundle.source_dir)}/</b></div>
<div class="manifest-item"><span>RECORDS EVALUATED</span><b>{bundle.n_trials} Trials · {bundle.trials_per_mode} Wiener · {bundle.trials_per_mode} Basic Prompt · {bundle.trials_per_mode} No Defense</b></div>
<div class="manifest-item"><span>BENIGN CONTROLS</span><b>{bundle.benign_total} Benign Runs · {incorrect} False Positives</b></div>
<div class="manifest-item"><span>VALIDATION STATUS</span><b class="{validation_class}" data-validation="{_attr(bundle.validation_status)}">{bundle.validation_pass} / {bundle.validation_invariants} PASSED · {validation_label}</b></div>
{status_row}{artifact_row}
{_model_identity(bundle)}
<div class="manifest-item wide"><span>TRIALS SHA256</span><b data-evidence-sha="{_attr(bundle.trials_sha256)}">{_esc(bundle.trials_sha256)}</b></div>
</div>
<p class="sr-only" data-fir-total="{_attr(wiener.fir)}">Provenance. {lock_phrase}. Dangerous proposals reaching SOC-agent stage: <b>{bundle.proposals}</b>. Unsafe tool executions: <b>{bundle.executed}</b><span data-unsafe-tool-executions="{bundle.executed}"></span>. FIR {_pct(wiener.fir)} — {bundle.benign_total} benign trials; {incorrect} incorrect interventions.</p></article></section>'''


def _audit_layer(data: DashboardData, selected: TrialView | None, bundle: EvidenceBundle) -> str:
    """Detail and audit layer behind a tab bar: trial-by-trial ledger plus
    the evidence/provenance manifest. Both stay in the DOM so the phrases and
    data attributes used by verification tests always remain reachable."""
    return f'''<section class="section" id="audit"><div class="section-heading"><h2>Detail &amp; Audit</h2><span>INSPECTION LAYER</span></div>
<div class="audit-tabs" role="tablist"><button type="button" class="audit-tab is-active" data-audit-tab="ledger">Evaluation Ledger</button><button type="button" class="audit-tab" data-audit-tab="provenance">Evidence &amp; Provenance</button></div>
<div class="audit-panel" data-audit-panel="ledger">{_ledger(data, selected, bundle)}</div>
<div class="audit-panel" data-audit-panel="provenance" hidden>{_provenance(bundle)}</div></section>'''


# demo.json stays quarantined (competition rule); not rendered live.

_CSS = r'''
:root{--bg:#f8f9f9;--surface:#fff;--low:#f3f4f4;--high:#e7e8e8;--line:#d7dadb;--ink:#191c1c;--muted:#62666a;--outline:#777b80;--blue:#0057c0;--red:#b42318;--red-bg:#fde7e4;--green:#17663c;--green-bg:#dff5e6;--shadow:0 2px 10px rgba(20,28,29,.045)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.45}button,input,select{font:inherit}button{cursor:pointer}.wrap{max-width:1248px;margin:auto;padding:48px 16px 56px}.surface-card{background:var(--surface);border-radius:12px;box-shadow:var(--shadow)}.hero{padding:32px 40px}.hero-top,.hero-body,.section-heading,.inspect-header,.filters,.pagination,.historical>div{display:flex;justify-content:space-between;gap:18px}.hero-top{align-items:center;padding-bottom:24px;border-bottom:1px solid var(--line)}.eyebrow-group,.locked,.eyebrow,.section-heading span,.card-kicker,.inspect-grid span,.provenance-grid span,.manifest span,.historical span{font:500 11px ui-monospace,SFMono-Regular,Menlo,monospace;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}.eyebrow-group{display:flex;gap:10px;align-items:center}.eyebrow-group strong{font:600 20px/1.3 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;letter-spacing:-.02em;text-transform:none;color:var(--ink)}.eyebrow-group i{font-style:normal;color:var(--outline)}.locked{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border-radius:999px;background:var(--high);border:1px solid var(--line);color:var(--ink)}.locked b{height:8px;width:8px;border-radius:50%;background:var(--green)}.locked--candidate{border-color:#e0c39a}.locked--candidate b{background:#b7791f}.hero-body{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(280px,.75fr);gap:48px;align-items:end;padding:32px 0}.eyebrow{display:block;margin-bottom:8px}.metric-line{display:flex;flex-direction:column;align-items:flex-start;gap:8px}.hero-metric{font-size:clamp(56px,7vw,88px);line-height:.9;letter-spacing:-.075em}.metric-line h1{margin:0;font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}.hero-evidence{display:flex;flex-direction:column;align-items:flex-start;gap:16px;max-width:420px}.proposal-count b{display:block;font-size:34px;line-height:1;letter-spacing:-.04em;color:var(--ink)}.proposal-count p{margin:2px 0 0;font-size:14px;line-height:1.5;color:var(--muted)}.proposal-count p b{color:var(--ink)}.decision-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;width:100%}.decision-chip{display:flex;align-items:center;justify-content:center;padding:7px 6px;border-radius:8px;font:650 11px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.05em;border:1px solid transparent;text-align:center;white-space:nowrap}.decision-chip--block{color:#891c15;background:var(--red-bg)}.decision-chip--review{color:#7c5a10;background:#fdf0e0}.decision-chip--allow{color:var(--green);background:var(--green-bg)}.badge{display:inline-block;padding:3px 8px;border-radius:4px;font:650 11px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.05em}.badge--block{color:#891c15;background:var(--red-bg)}.badge--review{color:#313538;background:var(--high)}.badge--allow{color:var(--green);background:var(--green-bg)}.badge--neutral{background:var(--high);color:var(--muted)}.audit-callout{margin-top:28px;padding:12px 18px;border-radius:7px;background:var(--low);display:flex;justify-content:space-between;gap:18px;font:500 11px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.035em}.audit-callout .audit-scope{display:flex;flex-direction:column;gap:2px}.audit-callout .audit-scope b{color:var(--ink)}.audit-callout strong,.verified,.pass{color:var(--green)!important}.section{margin-top:58px}.section-heading{align-items:baseline;gap:16px;margin:0 2px 18px}.section-heading h2{margin:0;font-size:20px;line-height:1.3;font-weight:600;letter-spacing:-.02em}.metric-card{padding:24px 26px;display:flex;flex-direction:column}.metric-card h3{margin:5px 0 0;font-size:15px}.metric-card p{margin:2px 0;color:var(--muted);font-size:12px}.inset>div{display:flex;justify-content:space-between;gap:14px;align-items:baseline;min-width:0}.inset code{font:500 12px ui-monospace,SFMono-Regular,Menlo,monospace;text-align:right;overflow-wrap:anywhere}.big-stat{margin-top:18px;font-size:34px;line-height:1;font-weight:650;letter-spacing:-.045em}.big-stat small{display:block;margin-top:6px;font-size:11px;line-height:1.3;font-weight:400;letter-spacing:0;color:var(--muted)}.inset{margin-top:16px;padding:11px 12px;border-radius:8px;background:var(--low);display:grid;gap:6px;font-size:12px}.inset span{color:var(--muted)}.pipeline-wrap{padding:18px 20px;overflow-x:auto}.pipeline{min-width:960px;width:100%;display:flex;align-items:stretch;gap:5px}.pipeline-node{flex:1 1 0;min-width:122px;min-height:108px;padding:12px 11px;border-radius:9px;background:var(--low);border:1px solid var(--line);display:flex;flex-direction:column;text-align:center;align-items:center}.pipeline-node b{margin:10px 0 5px;font-size:11px;font-weight:700;letter-spacing:.01em}.pipeline-node small{font-size:12px;font-weight:650;line-height:1.3;color:var(--ink)}.pipeline-node:has([data-step="TRAJECTORY"]) small{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:500;color:var(--outline)}.pipeline-node em{margin-top:auto;font-size:10px;line-height:1.35;font-style:normal;color:var(--muted)}.pipeline-node--block{background:#fff0ee;border-color:#f2cfca}.pipeline-node--block b,.pipeline-node--block small{color:#891c15}.pipeline-node--review{background:#f4f4f4}.pipeline-node--allow{background:#ecf7ef}.pipeline-node--tool{background:var(--high)}.pipeline-arrow{width:16px;flex:0 0 16px;display:flex;align-items:center;justify-content:center;color:var(--outline);font-size:15px;font-style:normal}.inspector{padding:24px 32px}.inspect-header{align-items:center;padding-bottom:18px;min-height:42px;border-bottom:1px solid var(--line);font:12px ui-monospace,monospace;color:var(--muted)}.inspect-id{display:flex;align-items:center;gap:9px}.inspect-id strong{font-size:16px;color:var(--ink)}.mode-chip{padding:3px 8px;border-radius:4px;background:var(--high);font-size:10px;text-transform:uppercase;letter-spacing:.05em}.execution-state{color:var(--ink)}.inspect-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;padding:20px 0}.inspect-grid>div{min-height:62px;padding:12px 14px;border-radius:7px;background:var(--low);min-width:0;display:flex;flex-direction:column;justify-content:center;gap:5px}.inspect-grid span{display:block;font-size:9px}.inspect-grid b,.inspect-grid code{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px}.inspect-grid code{font-family:ui-monospace,monospace}.inspect-log{padding-top:18px;border-top:1px solid var(--line);font:11px ui-monospace,monospace;color:var(--muted)}.ledger{overflow:hidden}.filters{align-items:center;padding:16px 24px;background:var(--low)}.search{position:relative;flex:1;max-width:360px}.search span{position:absolute;left:11px;top:6px;color:var(--outline);font-size:20px}.search input,.filter-set select{border:0;border-radius:6px;background:#fff;color:var(--ink);outline:0}.search input{width:100%;padding:8px 12px 8px 31px;font-size:12px}.filter-set{display:flex;gap:12px;flex-wrap:wrap}.filter-set label{font-size:11px;color:var(--muted)}.filter-set select{margin-left:5px;padding:7px;font-size:11px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:11px 18px;text-align:left;border-bottom:1px solid var(--high);white-space:nowrap}th{background:rgba(243,244,244,.55);color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.06em;font-weight:600}td:first-child,td:nth-child(2),td:nth-child(4),td:nth-child(5),td:last-child{font-family:ui-monospace,monospace}.right{text-align:right}.trial-row{cursor:pointer;transition:background .12s}.trial-row:hover,.trial-row.selected{background:var(--low)}.pagination{align-items:center;padding:14px 24px;color:var(--muted);font-size:11px}.pagination button{margin-left:7px;padding:6px 10px;border:0;border-radius:5px;background:var(--low);color:var(--ink);font-size:11px}.pagination button:disabled{opacity:.4;cursor:default}.provenance{padding:28px 32px}.src-artifact{margin-bottom:24px}.src-artifact .card-kicker{display:block}.src-path{display:inline-block;max-width:100%;margin-top:6px;padding:8px 12px;border-radius:7px;background:var(--low);border:1px solid var(--line);color:var(--ink);font:600 12.5px ui-monospace,monospace;overflow-wrap:anywhere;word-break:break-all}.provenance-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}.provenance-grid>div{padding:11px;border-radius:7px;background:var(--low)}.provenance-grid span,.provenance-grid b{display:block}.provenance-grid b{margin-top:3px;font:600 12px ui-monospace,monospace}.manifest{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 24px;margin-top:14px}.manifest-title{margin:20px 0 12px;padding:0 0 10px;border-bottom:1px solid var(--line);font:600 10px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.09em;color:var(--ink)}.manifest-item{display:flex;flex-direction:column;gap:5px;padding:12px 14px;border-radius:10px;background:var(--low);border:1px solid var(--line)}.manifest-item.wide{grid-column:1/-1}.manifest b{min-width:0;font:600 12px ui-monospace,monospace;color:var(--ink);overflow-wrap:anywhere;word-break:break-word}.manifest b.pass{color:var(--green)!important}.manifest b.pill{display:inline-block;align-self:flex-start;padding:2px 10px;border-radius:999px;border:1px solid currentColor;background:transparent}.manifest b.ts{line-height:1.6}.manifest b.ts i{display:block;font-style:normal}.historical{margin-top:20px;padding:18px 24px;border:1px dashed var(--line);box-shadow:none}.historical>div{align-items:center;font:11px ui-monospace,monospace;color:var(--outline);text-transform:uppercase}.historical>div b{padding:3px 7px;background:var(--high);border-radius:4px;color:var(--muted);font-size:10px}.historical p{color:var(--muted);font-size:12px}.historical-head{margin:4px 0 6px;font:600 10px ui-monospace,monospace;text-transform:uppercase;letter-spacing:.09em;color:var(--outline)}.historical table{margin-top:10px;max-width:420px}.historical th,.historical td{padding:8px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}footer{text-align:center;padding:28px 0 0;color:var(--outline);font-size:10px}@media(max-width:900px){}@media(max-width:850px){.hero{padding:24px}.hero-body{grid-template-columns:1fr;gap:28px;align-items:start}.inspect-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.provenance-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:640px){}@media(max-width:600px){.wrap{padding:28px 12px}.hero-top,.audit-callout,.filters,.pagination,.inspect-header{align-items:flex-start;flex-direction:column}.metric-line{align-items:flex-start;flex-direction:column;gap:8px}.metric-line h1{font-size:15px}.section-heading{flex-direction:column;align-items:flex-start}.inspect-grid{grid-template-columns:1fr}.provenance-grid{grid-template-columns:1fr}.manifest{grid-template-columns:1fr}.section{margin-top:38px}th,td{padding:10px 14px}.audit-tabs{display:flex;gap:8px;margin-bottom:16px}.audit-tab{padding:8px 16px;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--muted);font:600 12px -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;cursor:pointer}.audit-tab.is-active{background:var(--blue);border-color:var(--blue);color:#fff;box-shadow:var(--shadow)}.audit-tab:hover:not(.is-active){border-color:var(--outline)}.audit-panel[hidden]{display:none}}.uar-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:20px}.uar-card{padding:22px 24px;display:flex;flex-direction:column;gap:6px}.uar-value{font-size:34px;line-height:1.05;letter-spacing:-.03em;font-weight:600;font-variant-numeric:tabular-nums}.uar-detail{font-size:12px;color:var(--muted)}.uar-detail code{font:500 12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--ink)}.uar-detail--muted code{color:var(--muted)}.card-note{margin:6px 0 0;font-size:12px;color:var(--muted)}.card-foot{margin:10px 0 0;font-size:11px;color:var(--muted);border-top:1px solid var(--line);padding-top:8px}@media(max-width:860px){.uar-grid{grid-template-columns:1fr}}''' + TOPBAR_CSS



_JS = r'''
(function () {
  var rows = Array.prototype.slice.call(document.querySelectorAll('.trial-row'));
  var search = document.getElementById('trial-search'), mode = document.getElementById('mode-filter'), decision = document.getElementById('decision-filter');
  var previous = document.getElementById('btn-prev'), next = document.getElementById('btn-next'), status = document.getElementById('pagination-status');
  var page = 1, size = 6, filtered = rows;
  function value(row, key) { return row.getAttribute('data-' + key) || '—'; }
  function badgeClass(d) { return d === 'BLOCK' ? 'block' : d === 'REVIEW' ? 'review' : d === 'ALLOW' ? 'allow' : 'neutral'; }
  function updatePipeline(row) {
    var decision = value(row, 'decision');
    var stageValues = { 'ATTACK': value(row, 'scenario'), 'SOC AGENT': value(row, 'proposal'), 'TRAJECTORY': value(row, 'alert'), 'BLUE AI': 'Δ ' + value(row, 'deviation'), 'RISK ENGINE': value(row, 'risk'), 'POLICY GATE': decision, 'SIMULATED TOOL': value(row, 'executed') };
    Object.keys(stageValues).forEach(function (stage) {
      var node = document.querySelector('.pipeline-node[data-pipeline-stage="' + stage + '"]');
      if (!node) return;
      var small = node.querySelector('small'); if (!small) return;
      small.textContent = stageValues[stage];
      if (stage === 'POLICY GATE') {
        var em = node.querySelector('em'); if (em) em.textContent = decision + ' decision';
        node.classList.remove('pipeline-node--block', 'pipeline-node--review', 'pipeline-node--allow');
        if (decision === 'BLOCK' || decision === 'REVIEW' || decision === 'ALLOW') node.classList.add('pipeline-node--' + decision.toLowerCase());
      }
    });
  }
  function select(row) {
    rows.forEach(function (r) { r.classList.remove('selected'); }); row.classList.add('selected');
    var values = { 'inspected-trial-id':'id', 'inspected-scenario':'scenario', 'inspected-proposal':'proposal', 'inspected-risk':'risk', 'inspected-constraint':'constraint', 'inspected-gate':'decision', 'inspected-execution':'executed', 'inspected-log':'log' };
    Object.keys(values).forEach(function (id) { var el = document.getElementById(id); if (el) el.textContent = value(row, values[id]); });
    var badge = document.getElementById('inspected-badge'); if (badge) { var d = value(row, 'decision'); badge.textContent = d; badge.className = 'badge badge--' + badgeClass(d); }
    var modeEl = document.getElementById('inspected-mode'); if (modeEl) { var m = value(row, 'mode'); modeEl.textContent = m === 'wiener' ? 'WIENER Defense' : m === 'basic_prompt_defense' ? 'Basic Prompt Defense' : 'No Defense'; }
    updatePipeline(row);
  }
  function matches(row) { var q = (search.value || '').toLowerCase(); var m = mode.value, d = decision.value; var text = [value(row,'id'), value(row,'proposal'), value(row,'scenario')].join(' ').toLowerCase(); return (!q || text.indexOf(q) !== -1) && (m === 'ALL' || value(row,'mode') === m) && (d === 'ALL' || value(row,'decision') === d); }
  function render() { filtered = rows.filter(matches); var totalPages = Math.max(1, Math.ceil(filtered.length / size)); if (page > totalPages) page = totalPages; rows.forEach(function (row) { row.hidden = true; }); filtered.slice((page - 1) * size, page * size).forEach(function (row) { row.hidden = false; }); var start = filtered.length ? (page - 1) * size + 1 : 0, end = Math.min(page * size, filtered.length); status.textContent = 'Showing ' + start + ' to ' + end + ' of ' + filtered.length + ' entries'; previous.disabled = page <= 1; next.disabled = page >= totalPages; }
  [search, mode, decision].forEach(function (el) { if (el) el.addEventListener(el === search ? 'input' : 'change', function () { page = 1; render(); }); });
  previous.addEventListener('click', function () { if (page > 1) { page--; render(); } }); next.addEventListener('click', function () { page++; render(); });
  rows.forEach(function (row) { row.addEventListener('click', function () { select(row); }); row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(row); } }); });
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.audit-tab'));
  var panels = Array.prototype.slice.call(document.querySelectorAll('.audit-panel'));
  function switchAudit(name) {
    tabs.forEach(function (t) { t.classList.toggle('is-active', t.getAttribute('data-audit-tab') === name); });
    panels.forEach(function (p) { p.hidden = p.getAttribute('data-audit-panel') !== name; });
  }
  tabs.forEach(function (t) { t.addEventListener('click', function () { switchAudit(t.getAttribute('data-audit-tab')); }); });
  render();
})();
'''


def presentation_page(data: DashboardData, selected: str | None = None) -> str:
    """Render the authoritative dashboard in the supplied light editorial style."""
    bundle = data.evidence
    if bundle is None:
        from .evidence import load_evidence

        bundle = load_evidence()
    if bundle is None:
        return ""
    trial = _selected_trial(data, selected)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>WIENER — Authoritative Dashboard</title><style>{_CSS}</style></head>
<body>{render_topbar('dashboard')}
<main class="wrap" data-environment="simulated" data-authoritative="true"><span class="sr-only">RED AI · SOC AGENT · BLUE AI · RISK ENGINE / POLICY GATE · METRICS</span>{_hero(bundle)}{_uar_by_mode(bundle)}{_operational_safety(bundle)}{_integrity(bundle)}{_pipeline(trial)}{_inspector(trial, bundle)}{_audit_layer(data, trial, bundle)}</main><script>{_JS}</script></body></html>'''
