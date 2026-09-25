from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..action_metadata import is_dangerous
from ..metrics import MetricsReport, compute_metrics
from ..models import (
    Decision,
    ExperimentMode,
    ExperimentReport,
    ExperimentTrial,
    TrialOutcome,
)
from ..risk_engine.risk_engine import decision_margin

if TYPE_CHECKING:  # pragma: no cover - annotations only (avoids an import cycle)
    from ..present.evidence import EvidenceBundle

WIENER = ExperimentMode.WIENER

# Friendly labels for known provider tiers. Unknown names stay verbatim.
PROVIDER_LABELS = {
    "opencode": "OpenCode",
    "local": "Qwen Local",
    "replay": "Replay",
}


@dataclass(frozen=True)
class TrialView:
    """Everything the dashboard shows for ONE stored trial, derived only from
    the stored ExperimentTrial; no invented values.
    """

    trial_id: str
    mode: str
    status: str
    attack_type: str | None
    seed: str | None
    mutation: str | None
    iteration: int | None
    payload: str | None
    alert: str | None
    relevant_context: str
    proposed_action: str | None
    provider: str | None
    context_trust: int | None
    behavior_deviation: int | None
    action_criticality: int | None
    privilege_impact: int | None
    route: str | None
    evidence_tags: tuple[str, ...]
    risk_score: float | None
    # Display-only distance to nearest policy boundary; never a gate input.
    decision_margin: float | None
    triggered_constraints: tuple[str, ...]
    final_decision: str | None
    reason_tags: tuple[str, ...]
    executed: bool | None


@dataclass(frozen=True)
class MetricRow:
    mode: str
    attempts: int
    asr: float | None
    uar: float | None
    fir: float | None
    tti_ms: float | None
    e2e_ms: float | None


@dataclass(frozen=True)
class MetricsView:
    baseline_mode: str
    defended_mode: str
    uapr: float | None
    rows: tuple[MetricRow, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DashboardData:
    """Render-ready view of one stored experiment report."""

    experiment_id: str
    seed: int | None
    metrics: MetricsView
    trials: tuple[TrialView, ...]
    providers: tuple[str, ...]
    is_replay_only: bool
    # Locked authoritative presentation evidence, when present.
    evidence: "EvidenceBundle | None" = None

    @classmethod
    def empty(cls, experiment_id: str = "(none)") -> "DashboardData":
        return cls(
            experiment_id=experiment_id,
            seed=None,
            metrics=MetricsView(
                baseline_mode=ExperimentMode.NO_DEFENSE.value,
                defended_mode=WIENER.value,
                uapr=None,
            ),
            trials=(),
            providers=(),
            is_replay_only=False,
        )


# Per-trial derivation: reads ONLY stored fields.
def _status(trial: ExperimentTrial, outcome: TrialOutcome | None) -> str:
    if trial.error:
        return "error"
    if trial.mode != WIENER:
        return "proposed"
    decision = trial.policy_decision.decision if trial.policy_decision else None
    if decision == Decision.BLOCK:
        return "blocked"
    if decision == Decision.REVIEW:
        return "review"
    if decision == Decision.ALLOW:
        return "allowed"
    return "no_outcome"


def _mutation_label(trial: ExperimentTrial) -> str:
    if trial.attack.mutation is None:
        return "baseline"
    return trial.attack.mutation.kind.value


def _context_summary(trial: ExperimentTrial) -> str:
    traj = trial.trajectory
    if traj is None:
        return ""
    parts: list[str] = []
    for event in traj.context.events:
        line = f"[{event.source}/{event.event_type}] sev={event.severity}"
        if event.detail:
            line = f"{line} {event.detail}"
        parts.append(line)
    if traj.context.notes:
        parts.append(f"notes: {traj.context.notes}")
    return " | ".join(parts)


def to_trial_view(trial: ExperimentTrial) -> TrialView:
    traj = trial.trajectory
    blue = trial.blue_assessment
    risk = trial.risk
    policy = trial.policy_decision
    outcome = trial.outcome

    return TrialView(
        trial_id=trial.trial_id,
        mode=trial.mode.value,
        status=_status(trial, outcome),
        attack_type=trial.attack.category.value,
        seed=trial.attack.seed_id,
        mutation=_mutation_label(trial),
        iteration=trial.attack.iteration,
        payload=trial.attack.payload,
        alert=traj.context.alert_id if traj else None,
        relevant_context=_context_summary(trial),
        proposed_action=outcome.proposed_action if outcome else None,
        provider=traj.provider_used if traj and traj.provider_used else trial.provider,
        context_trust=blue.context_trust if blue else None,
        behavior_deviation=blue.behavior_deviation if blue else None,
        action_criticality=blue.action_criticality if blue else None,
        privilege_impact=blue.privilege_impact if blue else None,
        route=blue.route.value if blue else None,
        evidence_tags=tuple(blue.evidence_tags) if blue else (),
        risk_score=risk.risk_score if risk else None,
        decision_margin=decision_margin(risk.risk_score) if risk else None,
        triggered_constraints=tuple(risk.triggered_constraints) if risk else (),
        final_decision=policy.decision.value if policy else None,
        reason_tags=tuple(policy.reason_tags) if policy else (),
        executed=outcome.executed if outcome else None,
    )


def _metric_rows(report: ExperimentReport, mr: MetricsReport) -> tuple[MetricRow, ...]:
    rows = []
    for mode in mr.by_mode:
        m = mr.for_mode(mode)
        rows.append(
            MetricRow(
                mode=mode.value,
                attempts=m.attempts,
                asr=m.asr,
                uar=m.uar,
                fir=m.fir,
                tti_ms=m.tti_mean_ms,
                e2e_ms=m.e2e_mean_ms,
            )
        )
    return tuple(rows)


def build_dashboard(
    report: ExperimentReport,
    baseline: ExperimentMode = ExperimentMode.NO_DEFENSE,
    defended: ExperimentMode = WIENER,
) -> DashboardData:
    """Turn a stored ExperimentReport into a render-ready dashboard view."""
    mr = compute_metrics(report, baseline=baseline, defended=defended)
    views = tuple(to_trial_view(t) for t in report.trials)
    providers = tuple(sorted({t.provider for t in report.trials if t.provider}))
    is_replay_only = bool(report.trials) and providers == ("replay",)
    return DashboardData(
        experiment_id=report.experiment_id,
        seed=report.config.seed if report.config else None,
        metrics=MetricsView(
            baseline_mode=baseline.value,
            defended_mode=defended.value,
            uapr=mr.uapr(),
            rows=_metric_rows(report, mr),
        ),
        trials=views,
        providers=providers,
        is_replay_only=is_replay_only,
    )