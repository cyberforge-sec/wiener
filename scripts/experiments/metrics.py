"""Part K/L/M: metrics for the authoritative experiment.

REUSES the existing metric definitions verbatim (app.metrics.core: UAR/ASR/FIR/
UAPR, _rate, _mean, attack_succeeded / unsafe_action_taken / is_benign /
incorrect_intervention). The harness TrialRecord rows are lifted into the
ExperimentReport/ExperimentTrial model the existing compute_metrics consumes,
then serialized (with Wilson binomial CIs) to metrics.json. No metric definition
is changed or duplicated.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from math import log
from pathlib import Path

from app.experiment.runner import ExperimentConfig
from app.metrics.core import (
    MetricsError,
    ModeMetrics,
    compute_metrics,
)
from app.models import (
    Decision,
    ExperimentMode,
    ExperimentReport,
    ExperimentTrial,
    PolicyDecision,
    RedAttack,
    RiskResult,
    SOCOutput,
    TrialOutcome,
)
from app.red_ai.mutator import MutationMeta
from app.red_ai.seed_loader import SeedLoader

from .common import ROOT, TrialRecord, now_iso



def _decision(value: str) -> Decision:
    try:
        return Decision(value)
    except ValueError:
        return Decision.BLOCK


def to_experiment_trial(r: TrialRecord) -> ExperimentTrial:
    from app.models import AttackCategory
    cat = AttackCategory.MALICIOUS_ACTION
    intended = None
    if r.seed_id.startswith("BN-"):
        from .common import BENIGN_SEEDS
        for s in BENIGN_SEEDS:
            if s.seed_id == r.seed_id:
                cat = s.category
                intended = s.intended_action
                break
    else:
        for s in SeedLoader().seeds:
            if s.seed_id == r.seed_id:
                cat = s.category
                intended = s.intended_action
                break
    red = RedAttack(
        seed_id=r.seed_id,
        category=cat,
        iteration=r.iteration,
        payload=r.attack_payload or (r.benign_payload_or_context or ""),
        mutation=MutationMeta(kind=r.mutation_type, rng_seed=hash(r.trial_id) % (2**31), note="") if r.mutation_type else None,
        intended_action=intended,
    )

    soc = None
    if r.action:
        try:
            from app.models import Action
            soc = SOCOutput(
                action=Action(r.action),
                target=r.target or "",
                confidence=r.confidence,
                reasoning="",
            )
        except Exception:  # noqa: BLE001
            soc = None

    risk = None
    if r.risk_score is not None:
        risk = RiskResult(
            risk_score=r.risk_score,
            triggered_constraints=list(r.triggered_constraints or []),
            required_decision=_decision(r.required_decision) if r.required_decision else None,
        )

    outcome = None
    if r.final_decision is not None or r.action is not None:
        # Undefended modes run no gate: a dangerous proposal IS the unsafe outcome.
        decision = _decision(r.final_decision) if r.final_decision else Decision.ALLOW
        outcome = TrialOutcome(
            proposed_action=r.action,
            decision=decision,
            executed=r.tool_executed,
            dangerous=False,  # populated below via action_metadata
            summary=f"tool={r.tool_name or '-'}; executed={r.tool_executed}; reason={r.tool_refusal_reason or '-'}",
        )
        if r.action:
            from app.action_metadata import is_dangerous
            outcome.dangerous = bool(is_dangerous(r.action))

    return ExperimentTrial(
        trial_id=r.trial_id,
        seed_id=r.seed_id,
        mode=ExperimentMode(r.mode),
        attack=red,
        soc_output=soc,
        trajectory=None,
        blue_assessment=None,
        risk=risk,
        policy_decision=PolicyDecision(decision=_decision(r.final_decision)) if r.final_decision else None,
        latency_ms=r.duration_ms,
        outcome=outcome,
        error=r.error,
        provider=r.provider_used,
        generated_at_ms=0.0,
        detected_at_ms=r.request_start_ms,
        intervened_at_ms=r.request_end_ms,
    )


def to_experiment_report(experiment_id: str, records: list[TrialRecord], num_malicious_variants: int) -> ExperimentReport:
    cfg = ExperimentConfig(
        experiment_id=experiment_id,
        num_malicious_variants=num_malicious_variants,
    )
    modes = [ExperimentMode(m.value) for m in (ExperimentMode.NO_DEFENSE, ExperimentMode.BASIC_PROMPT_DEFENSE, ExperimentMode.WIENER)]
    cfg.modes = modes
    return ExperimentReport(
        experiment_id=experiment_id,
        config=cfg,
        trials=[to_experiment_trial(r) for r in records],
    )



def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float | None, float | None]:
    """Two-sided 95% Wilson interval. (None, None) when there is no sample."""
    if n <= 0:
        return None, None
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = (z * (p * (1 - p) / n + z2 / (4 * n * n)) ** 0.5) / denom
    return round(max(0.0, centre - half), 6), round(min(1.0, centre + half), 6)


def _metric_row(label: str, num: int, den: int) -> dict:
    lo, hi = wilson_ci(num, den)
    return {
        "metric": label,
        "value": round(num / den, 6) if den else None,
        "n": den,
        "ci95": [lo, hi],
    }


def metrics_summary(report: ExperimentReport) -> dict:
    """Run the existing compute_metrics and serialize to metrics.json shape."""
    metro = compute_metrics(report)
    rows: dict[str, dict] = {}
    for mode in (ExperimentMode.NO_DEFENSE, ExperimentMode.BASIC_PROMPT_DEFENSE, ExperimentMode.WIENER):
        m: ModeMetrics = metro.for_mode(mode)
        benign_den = m.benign_actions + m.incorrect_interventions
        rows[mode.value] = {
            "attempts": m.attempts,
            "successful_attacks": m.successful_attacks,
            "unsafe_actions": m.unsafe_actions,
            "benign_actions": m.benign_actions,
            "incorrect_interventions": m.incorrect_interventions,
            "uar": _metric_row("UAR", m.unsafe_actions, m.attempts),
            "asr": _metric_row("ASR", m.successful_attacks, m.attempts),
            "fir": _metric_row("FIR", m.incorrect_interventions, benign_den),
            "tti_mean_ms": m.tti_mean_ms,
            "e2e_mean_ms": m.e2e_mean_ms,
            "tti_samples": m.tti_samples,
            "e2e_samples": m.e2e_samples,
        }
    uapr = metro.uapr()
    return {
        "computed_at": now_iso(),
        "metric_source": "app.metrics.core.compute_metrics (UNMODIFIED)",
        "by_mode": rows,
        "uapr_baseline_vs_defended": {
            "baseline": "no_defense",
            "defended": "wiener",
            "value": uapr,
            "defined_when_baseline_uar_gt_0": uapr is not None,
        },
    }


def write_metrics(out_dir: Path, records: list[TrialRecord], num_malicious_variants: int, experiment_id: str) -> dict:
    report = to_experiment_report(experiment_id, records, num_malicious_variants)
    summary = metrics_summary(report)
    (out_dir / "metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary