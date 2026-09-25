"""Presentation evidence for the competition dashboard (Part E/I/J/K).

Reads ONLY the locked authoritative experiment artifacts
``data/experiments/authoritative_20260910_1808`` and derives every displayed
value directly from stored fields. No metric is recomputed:

  * UAR / ASR / FIR / UAPR / counts come verbatim from the stored
    ``metrics.json`` and ``validation.json``.
  * The defense-path breakdown (12 dangerous proposals -> 10 BLOCK -> 2 REVIEW
    -> 0 executions) is grouped from the stored per-trial ``action`` /
    ``final_decision`` / ``tool_executed`` fields in ``trials.jsonl``.
  * The historical ``demo.json`` block is loaded read-only from the stored
    report and is always labelled HISTORICAL / NON-AUTHORITATIVE.

This module never modifies any artifact and never invokes the Red/Blue/Pipeline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..dashboard.dashboard import DashboardData, MetricRow, MetricsView, to_trial_view
from ..dashboard.store import default_report_root
from ..metrics import compute_metrics
from ..models import (
    Action,
    AttackCategory,
    BlueAssessment,
    Decision,
    ExperimentMode,
    ExperimentTrial,
    MutationKind,
    MutationMeta,
    PolicyDecision,
    RedAttack,
    RiskResult,
    SOCContext,
    SOCOutput,
    Trajectory,
    TrialOutcome,
)

DANGEROUS_ACTIONS = ("block_ip", "isolate_endpoint", "disable_user")

# Legacy locked run used when no manifest declares a LOCKED_VERIFIED run.
AUTHORITATIVE_ID = "authoritative_20260910_1808"

_MODE_ORDER = (
    ExperimentMode.NO_DEFENSE.value,
    ExperimentMode.BASIC_PROMPT_DEFENSE.value,
    ExperimentMode.WIENER.value,
)


def experiments_root() -> Path:
    """The overridable experiment root (WIENER_EXPERIMENT_STORE), matching the
    report store so the locked evidence and the generic reports resolve to the
    same configured location."""
    return default_report_root()


def authoritative_dir() -> Path:
    """Resolve the primary evidence directory.

    A run whose evidence_manifest.json says LOCKED_VERIFIED wins; otherwise the
    legacy AUTHORITATIVE_ID is used so the dashboard keeps working pre-lock."""
    from scripts.experiments.lock import locked_evidence_dir

    return (
        locked_evidence_dir(experiments_root())
        or experiments_root() / AUTHORITATIVE_ID
    )


def _decision(value: str | None) -> Decision | None:
    if not value:
        return None
    try:
        return Decision(value)
    except ValueError:
        return None


def _action(value: str | None) -> Action | None:
    if not value:
        return None
    try:
        return Action(value)
    except ValueError:
        return None


@dataclass(frozen=True)
class ModeEvidence:
    """Stored per-mode metric values (verbatim from metrics.json)."""

    mode: str
    attempts: int
    successful_attacks: int
    unsafe_actions: int
    benign_actions: int
    incorrect_interventions: int
    uar: float | None
    uar_ci: tuple[float | None, float | None]
    asr: float | None
    fir: float | None
    fir_den: int | None
    tti_mean_ms: float | None
    e2e_mean_ms: float | None


@dataclass(frozen=True)
class HistoricalDemo:
    """Non-authoritative demo.json numbers, kept strictly separate."""

    experiment_id: str
    n_trials: int
    uar_by_mode: dict[str, float | None]
    note: str


@dataclass(frozen=True)
class EvidenceBundle:
    """Everything the dashboard shows about the locked authoritative run."""

    experiment_id: str
    source_dir: str
    trials_sha256: str
    n_trials: int
    modes: tuple[str, ...]
    trials_per_mode: int
    malicious_total: int
    benign_total: int
    raw_completion_present: int
    raw_completion_total: int
    duplicate_trial_mode_ids: int
    provider_counts: dict[str, int]
    degraded_count: int
    by_mode: dict[str, ModeEvidence]
    uapr: float | None
    uapr_baseline: str
    uapr_defended: str
    validation_status: str
    validation_invariants: int
    validation_pass: int
    computed_at: str
    metric_source: str
    proposals: int
    blocked: int
    reviewed: int
    executed: int
    is_authoritative: bool = True
    history: HistoricalDemo | None = None
    evidence_status: str = "CANDIDATE"
    locked_at: str | None = None
    code_fingerprint_root: str | None = None
    artifact_hashes: dict[str, str] | None = None
    source_provenance: dict[str, Any] | None = None
    recompute_diffs: tuple[str, ...] = ()


# Stored-row lift: fields copied with resilience, no metric recomputed here.
def _row_to_trial(row: dict[str, Any]) -> ExperimentTrial:
    mode = ExperimentMode(row["mode"])
    cat = AttackCategory(row["category"]) if row.get("category") else AttackCategory.MALICIOUS_ACTION
    payload = row.get("attack_payload") or row.get("benign_payload_or_context") or ""
    mutation_type = row.get("mutation_type")
    mutation = (
        MutationMeta(
            kind=MutationKind(mutation_type),
            rng_seed=hash(row["trial_id"]) % (2**31),
            note="",
        )
        if mutation_type
        else None
    )
    attack = RedAttack(
        seed_id=row["seed_id"],
        category=cat,
        iteration=int(row.get("iteration") or 0),
        payload=payload,
        mutation=mutation,
        intended_action=None,  # measurement semantics only; never used for display/policy
    )

    soc = None
    action = _action(row.get("action"))
    if action is not None:
        soc = SOCOutput(
            action=action,
            target=row.get("target"),
            confidence=float(row.get("confidence") or 0.0),
            reasoning="",
        )

    trajectory = None
    if soc is not None and isinstance(row.get("SOC_context"), dict):
        try:
            trajectory = Trajectory(
                trial_id=row["trial_id"],
                context=SOCContext(**row["SOC_context"]),
                agent_history=[],
                proposed_action=soc,
                provider_used=row.get("provider_used") or "",
                metadata={"authoritative": True},
            )
        except (TypeError, ValueError):
            trajectory = None

    blue = None
    if isinstance(row.get("blue_assessment"), dict):
        try:
            blue = BlueAssessment(**row["blue_assessment"])
        except (TypeError, ValueError):
            blue = None
    elif row.get("blue_route"):
        blue = BlueAssessment(
            context_trust=0,
            behavior_deviation=0,
            action_criticality=0,
            privilege_impact=0,
            evidence_tags=[],
            route=row["blue_route"],
        )

    risk = None
    if row.get("risk_score") is not None:
        risk = RiskResult(
            risk_score=float(row["risk_score"]),
            triggered_constraints=list(row.get("triggered_constraints") or []),
            required_decision=_decision(row.get("required_decision")),
        )

    decision = _decision(row.get("final_decision"))
    policy = PolicyDecision(decision=decision) if decision else None

    outcome = None
    if decision is not None or action is not None:
        outcome = TrialOutcome(
            proposed_action=row.get("action"),
            decision=decision,
            executed=row.get("tool_executed"),
            dangerous=bool(action and action.value in DANGEROUS_ACTIONS),
            summary=(
                f"tool={row.get('tool_name') or '-'}; "
                f"executed={row.get('tool_executed')}; "
                f"reason={row.get('tool_refusal_reason') or '-'}"
            ),
        )

    return ExperimentTrial(
        trial_id=row["trial_id"],
        seed_id=row["seed_id"],
        mode=mode,
        attack=attack,
        soc_output=soc,
        trajectory=trajectory,
        blue_assessment=blue,
        risk=risk,
        policy_decision=policy,
        latency_ms=row.get("duration_ms"),
        outcome=outcome,
        error=row.get("error"),
        provider=row.get("provider_used") or "",
        generated_at_ms=0.0,
        detected_at_ms=row.get("request_start_ms"),
        intervened_at_ms=row.get("request_end_ms"),
    )



def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceUnavailable(
                f"{path.name} line {number} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise EvidenceUnavailable(f"{path.name} line {number} is not an object")
        rows.append(row)
    return rows


def _stored_metrics(path: Path) -> dict[str, Any]:
    if not path.exists():
        # validation.json is optional for pre-lock runs; an absent file simply
        # means "no validation report", not a broken artifact.
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceUnavailable(f"{path.name} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise EvidenceUnavailable(f"{path.name} is not a JSON object")
    return payload


# Reasons the most recent load_evidence() call failed (non-fatal path only).
# The dashboard surfaces these instead of rendering a blank "no data" page.
load_errors: list[str] = []


def _ci(value: Any) -> tuple[float | None, float | None]:
    if not isinstance(value, dict):
        return None, None
    lo, hi = value.get("ci95") or [None, None]
    return lo, hi


def _load_history() -> HistoricalDemo | None:
    """Read demo.json read-only and derive ONLY UAR values for the secondary
    (HISTORICAL / NON-AUTHORITATIVE) block. FIR is never shown for demo."""
    path = experiments_root() / "demo.json"
    if not path.exists():
        return None
    try:
        from ..models import ExperimentReport

        report = ExperimentReport.model_validate_json(path.read_text(encoding="utf-8"))
        mr = compute_metrics(report)
        uar: dict[str, float | None] = {}
        for mode in _MODE_ORDER:
            uar[mode] = mr.for_mode(mode).uar
        return HistoricalDemo(
            experiment_id="demo.json",
            n_trials=len(report.trials),
            uar_by_mode=uar,
            note=(
                "Historic 10-trial artifact (30 rows, single iteration, no per-trial "
                "provenance). The anomalous 0.40 -> 0.70 increase was NOT reproduced "
                "in the authoritative run. Not quantitatively comparable row-to-row; "
                "shown for transparency only. Not counted as evidence."
            ),
        )
    except Exception:  # noqa: BLE001 - historical aux data must never break the dashboard
        return None


class EvidenceUnavailable(RuntimeError):
    """Raised when the evidence layer cannot be trusted to describe the run.

    Callers must surface this instead of silently rendering an empty or
    partial dashboard: a broken artifact directory must never look like a
    clean run with no data.
    """


def load_evidence(
    directory: str | Path | None = None,
    *,
    strict: bool = False,
) -> EvidenceBundle | None:
    """Load the authoritative evidence bundle.

    Returns None when the locked artifacts are simply absent (the dashboard
    then falls back to the generic stored-report view). Any *other* failure -
    unreadable JSON, malformed rows, missing manifest - raises
    :class:`EvidenceUnavailable` in strict mode and is recorded in
    ``load_errors`` otherwise, so a corrupt evidence directory can never be
    mistaken for an empty one.
    """
    target = authoritative_dir() if directory is None else Path(directory)
    if not target.exists():
        # Nothing has been generated yet: a normal state for a fresh clone.
        load_errors.clear()
        return None
    try:
        bundle = _load(target)
    except Exception as exc:  # noqa: BLE001 - classified, then re-raised when strict
        detail = f"{type(exc).__name__}: {exc}"
        load_errors.append(detail)
        if strict:
            raise EvidenceUnavailable(
                f"authoritative evidence could not be loaded: {detail}"
            ) from exc
        return None
    load_errors.clear()
    return bundle


def _derive_status(
    validation_status: str | None,
    n_rows: int,
    unique_pairs: int,
) -> str:
    """Derived (manifest-less) status: strict LOCKED_VERIFIED only when every
    observable lock condition already holds on the stored artifacts."""
    if (
        validation_status == "PASS"
        and n_rows == 135
        and unique_pairs == n_rows
    ):
        return "LOCKED_VERIFIED"
    return "CANDIDATE"


def _current_source_provenance(dir_path: Path, manifest: dict) -> dict[str, Any]:
    """Recompute source provenance for the tree the dashboard is served from.

    Uses the stored code fingerprint, compares it to the current tree, and
    keeps the manifest's value only as the `recorded_*` provenance trail. If
    the comparison cannot be performed (fingerprint file missing, hashing
    unavailable), the status is UNKNOWN rather than a borrowed MATCH.
    """
    stored = manifest.get("source_provenance") or {}
    recorded_status = str(stored.get("status") or "").upper()
    fingerprint_path = dir_path / "code_fingerprint.json"
    try:
        from scripts.experiments.lock import fingerprint_status

        if not fingerprint_path.exists():
            return {
                "status": "UNKNOWN",
                "recorded_status": recorded_status or None,
                "note": (
                    "code_fingerprint.json is absent, so this run cannot be "
                    "compared to the current source tree"
                ),
            }
        result = fingerprint_status(json.loads(fingerprint_path.read_text(encoding="utf-8")))
    except Exception as exc:  # noqa: BLE001 - never let provenance break the page
        return {
            "status": "UNKNOWN",
            "recorded_status": recorded_status or None,
            "note": f"source provenance could not be recomputed: {type(exc).__name__}: {exc}",
        }
    result["recorded_status"] = recorded_status or None
    if result.get("status") == "MATCH":
        result["note"] = "Fingerprint matches the current source tree."
    else:
        changed = len(result.get("mismatched_files") or [])
        added = len(result.get("added_files") or [])
        removed = len(result.get("removed_files") or [])
        result["note"] = (
            "This evidence was produced by an earlier revision of the code "
            f"({changed} file(s) changed, {added} added, {removed} removed "
            "since it was locked). It is retained as historical evidence and "
            "must be re-run before it can be presented as a result of the "
            "current tree."
        )
    return result


# Loader: reads ONLY the locked artifacts.
def _load(dir_path: Path) -> EvidenceBundle:
    required = ("trials.jsonl", "metrics.json")
    missing = [name for name in required if not (dir_path / name).exists()]
    if missing:
        raise EvidenceUnavailable(
            f"evidence directory {dir_path.name} is missing {', '.join(missing)}"
        )
    metrics = _stored_metrics(dir_path / "metrics.json")
    validation = _stored_metrics(dir_path / "validation.json")
    rows = _read_jsonl(dir_path / "trials.jsonl")
    if not rows:
        raise EvidenceUnavailable(f"no trial rows in {dir_path / 'trials.jsonl'}")

    # Locked-status from the manifest when present, else derived from stored artifacts.
    manifest: dict[str, Any] = {}
    manifest_path = dir_path / "evidence_manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - a broken manifest never kills the page
            manifest = {}
    evidence_status = manifest.get("evidence_status") or _derive_status(
        validation.get("validation_status"),
        len(rows),
        len({(r.get("trial_id"), r.get("mode")) for r in rows}),
    )
    locked_at = manifest.get("locked_at")
    code_root = (manifest.get("code_fingerprint") or {}).get("root_hash")
    artifact_hashes = manifest.get("artifact_hashes")

    # Source provenance is RECOMPUTED against the current tree, never read as
    # a historical claim from the manifest. The manifest's own value was true
    # when the run was locked; after any code change it is a historical fact,
    # and presenting it as the current state would be exactly the kind of
    # stale "VERIFIED" claim this layer exists to prevent.
    source_provenance = _current_source_provenance(dir_path, manifest)

    modes: tuple[str, ...] = tuple(_MODE_ORDER)
    by_mode_rows = metrics.get("by_mode", {})

    def stored(mode: str, key: str, default: Any = None) -> Any:
        m = by_mode_rows.get(mode, {})
        return m.get(key, default)

    def stored_rate(mode: str, key: str) -> float | None:
        v = stored(mode, key)
        if isinstance(v, dict):
            return v.get("value")
        return v

    by_mode: dict[str, ModeEvidence] = {}
    for mode in modes:
        uar = stored_rate(mode, "uar")
        asr = stored_rate(mode, "asr")
        fir = stored_rate(mode, "fir")
        attempts = int(stored(mode, "attempts", 0) or 0)
        by_mode[mode] = ModeEvidence(
            mode=mode,
            attempts=attempts,
            successful_attacks=int(stored(mode, "successful_attacks", 0) or 0),
            unsafe_actions=int(stored(mode, "unsafe_actions", 0) or 0),
            benign_actions=int(stored(mode, "benign_actions", 0) or 0),
            incorrect_interventions=int(stored(mode, "incorrect_interventions", 0) or 0),
            uar=uar,
            uar_ci=_ci(stored(mode, "uar") if isinstance(stored(mode, "uar"), dict) else {}),
            asr=asr,
            fir=fir,
            fir_den=stored(mode, "fir")["n"] if isinstance(stored(mode, "fir"), dict) else None,
            tti_mean_ms=stored(mode, "tti_mean_ms"),
            e2e_mean_ms=stored(mode, "e2e_mean_ms"),
        )

    uapr_block = metrics.get("uapr_baseline_vs_defended") or {}
    uapr = uapr_block.get("value")
    uapr_baseline = uapr_block.get("baseline", ExperimentMode.NO_DEFENSE.value)
    uapr_defended = uapr_block.get("defended", ExperimentMode.WIENER.value)

    # Defense path, grouped exclusively from stored decision / tool fields.
    wiener = [r for r in rows if r.get("mode") == ExperimentMode.WIENER.value]
    proposals = [
        r
        for r in wiener
        if r.get("action") in DANGEROUS_ACTIONS
    ]
    blocked = sum(1 for r in proposals if r.get("final_decision") == Decision.BLOCK.value)
    reviewed = sum(1 for r in proposals if r.get("final_decision") == Decision.REVIEW.value)
    executed = sum(1 for r in proposals if r.get("tool_executed") is True)

    provider_counts: dict[str, int] = {}
    raw_present = 0
    degraded = 0
    for r in rows:
        provider = r.get("provider_used") or "unknown"
        provider_counts[provider] = provider_counts.get(provider, 0) + 1
        if r.get("raw_completion"):
            raw_present += 1
        if r.get("fallback_used"):
            degraded += 1

    benign_total = sum(1 for r in rows if r.get("benign_trial"))
    malicious_total = len(rows) - benign_total
    unique = {(r.get("trial_id"), r.get("mode")) for r in rows}
    dup = len(rows) - len(unique)
    trials_per_mode = len(rows) // len(modes) if modes else 0

    invariants = validation.get("invariants") or {}
    pass_count = sum(1 for inv in invariants.values() if inv.get("status") == "PASS")

    sha = hashlib.sha256((dir_path / "trials.jsonl").read_bytes()).hexdigest()

    return EvidenceBundle(
        experiment_id=validation.get("experiment_id") or metrics.get("experiment_id") or dir_path.name,
        source_dir=dir_path.name,
        trials_sha256=sha,
        n_trials=len(rows),
        modes=modes,
        trials_per_mode=trials_per_mode,
        malicious_total=malicious_total,
        benign_total=benign_total,
        raw_completion_present=raw_present,
        raw_completion_total=len(rows),
        duplicate_trial_mode_ids=dup,
        provider_counts=provider_counts,
        degraded_count=degraded,
        by_mode=by_mode,
        uapr=uapr,
        uapr_baseline=uapr_baseline,
        uapr_defended=uapr_defended,
        validation_status=validation.get("validation_status") or "UNKNOWN",
        validation_invariants=len(invariants),
        validation_pass=pass_count,
        computed_at=metrics.get("computed_at") or "",
        metric_source=metrics.get("metric_source") or "",
        proposals=len(proposals),
        blocked=blocked,
        reviewed=reviewed,
        executed=executed,
        history=_load_history(),
        evidence_status=evidence_status,
        locked_at=locked_at,
        code_fingerprint_root=code_root,
        artifact_hashes=artifact_hashes,
        source_provenance=source_provenance,
        recompute_diffs=tuple(manifest.get("recompute_diffs") or ()),
    )



def _load_trials(dir_path: Path) -> list[ExperimentTrial]:
    return [_row_to_trial(r) for r in _read_jsonl(dir_path / "trials.jsonl")]


def build_evidence_dashboard(bundle: EvidenceBundle | None = None) -> DashboardData:
    """Render-ready dashboard whose primary metrics and drill-down come from
    the LOCKED authoritative artifacts (no metric is recomputed)."""
    if bundle is None:
        bundle = load_evidence()
        if bundle is None:
            return DashboardData.empty()

    # The drill-down MUST come from the same directory the metrics came from.
    # Re-resolving the "current best" directory here could pair a caller
    # supplied bundle with a different run's trials.
    trials_dir = experiments_root() / bundle.source_dir if bundle.source_dir else authoritative_dir()
    views = tuple(to_trial_view(t) for t in _load_trials(trials_dir))
    rows = tuple(
        MetricRow(
            mode=bundle.by_mode[mode].mode,
            attempts=bundle.by_mode[mode].attempts,
            asr=bundle.by_mode[mode].asr,
            uar=bundle.by_mode[mode].uar,
            fir=bundle.by_mode[mode].fir,
            tti_ms=bundle.by_mode[mode].tti_mean_ms,
            e2e_ms=bundle.by_mode[mode].e2e_mean_ms,
        )
        for mode in bundle.modes
    )
    return DashboardData(
        experiment_id=bundle.experiment_id,
        seed=None,
        metrics=MetricsView(
            baseline_mode=bundle.uapr_baseline,
            defended_mode=bundle.uapr_defended,
            uapr=bundle.uapr,
            rows=rows,
        ),
        trials=views,
        providers=tuple(sorted(bundle.provider_counts)),
        is_replay_only=False,
        evidence=bundle,
    )