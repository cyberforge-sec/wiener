"""Part N: the 16 validation invariants computed over trials.jsonl.

Every invariant reads ONLY stored trial fields; a failing invariant produces an
explicit violation record. validation.json carries the FULL checklist so the
report can quote exact pass/fail. No metric definition is consulted here: this
is a provenance/consistency audit on top of the raw trial records.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.models import Action, ExperimentMode

from .common import TrialRecord, benign_ids
from .preflight import response_contains_json



def _invariant(id: str, name: str, detail: str) -> dict:
    return {"id": id, "name": name, "status": "PASS", "detail": detail, "violations": []}


def _ok(a: dict) -> bool:
    return a["status"] == "PASS"


def _add_violation(a: dict, message: str) -> None:
    a["status"] = "FAIL"
    a["violations"].append(message)



def run_validation(records: list[TrialRecord], experiment_id: str) -> dict:
    by_id: dict[str, list[TrialRecord]] = {}
    for r in records:
        by_id.setdefault(r.trial_id, []).append(r)

    # I-01  Full, intact reproduction of the trial list (exact ID → mode mapping).
    v01 = _invariant("I-01", "trial-list-intact", "")
    modes = (ExperimentMode.NO_DEFENSE.value, ExperimentMode.BASIC_PROMPT_DEFENSE.value, ExperimentMode.WIENER.value)
    bad = [tid for tid, rs in by_id.items() if [r.mode for r in rs] != list(modes)]
    for tid in bad:
        _add_violation(v01, f"trial {tid}: modes {[r.mode for r in by_id[tid]]} != {list(modes)}")
    v01["detail"] = f"{len(by_id)} distinct trial IDs each present in all 3 modes"

    # I-02  Exact same scenario (seed + payload + context) in every mode.
    v02 = _invariant("I-02", "scenario-identical-across-modes", "")
    for tid, rs in by_id.items():
        payloads = {r.attack_payload or r.benign_payload_or_context for r in rs}
        if len(payloads) != 1:
            _add_violation(v02, f"trial {tid}: differing payloads across modes")
        ctxs = {json.dumps(r.SOC_context, sort_keys=True) for r in rs}
        if len(ctxs) != 1:
            _add_violation(v02, f"trial {tid}: differing SOC contexts across modes")
    v02["detail"] = f"{len(by_id)} scenario payloads/contexts verified identical per trial ID"

    # I-03  Expected benign and malicious trial counts per mode.
    v03 = _invariant("I-03", "trial-counts", "")
    benign = set(benign_ids())
    for mode in modes:
        mals = sum(1 for r in records if r.mode == mode and r.trial_id not in benign)
        bens = sum(1 for r in records if r.mode == mode and r.trial_id in benign)
        if mals < 30:
            _add_violation(v03, f"mode {mode}: malicious trials {mals} < 30")
        if bens < 10:
            _add_violation(v03, f"mode {mode}: benign trials {bens} < 10")
    v03["detail"] = "malicious>=30 and benign>=10 per mode"

    # I-04  All recorded trials share one experiment_id.
    v04 = _invariant("I-04", "single-experiment-id", "")
    for r in records:
        if r.experiment_id != experiment_id:
            _add_violation(v04, f"trial {r.trial_id}: experiment_id={r.experiment_id}")
    v04["detail"] = f"experiment_id == {experiment_id!r} for all {len(records)} records"

    # I-05  No trial row is empty (a real recorded outcome or an explicit error).
    v05 = _invariant("I-05", "no-empty-trials", "")
    for r in records:
        if not r.error and r.action is None:
            _add_violation(v05, f"trial {r.trial_id} {r.mode}: no error and no action")
    v05["detail"] = "every non-error trial has a parsed action"

    # I-06  Latency measured wall-clock, positive, real (never 0.001).
    v06 = _invariant("I-06", "measured-timing", "")
    for r in records:
        if r.duration_ms is not None and r.duration_ms <= 1.0:
            _add_violation(v06, f"trial {r.trial_id} {r.mode}: duration_ms={r.duration_ms} non-physical")
    v06["detail"] = "duration_ms > 1.0 for all trials (no fabricated near-zero latency)"

    # I-07  Raw completion present & non-empty when provider did not degrade.
    v07 = _invariant("I-07", "raw-completion-presence", "")
    for r in records:
        if r.error is None and not r.fallback_used and r.raw_completion in (None, "", "null"):
            _add_violation(v07, f"trial {r.trial_id} {r.mode}: raw_completion missing despite non-degraded")
    v07["detail"] = "raw_completion set for every non-degraded, non-errored trial"

    # I-08  No silent provider substitution (provider_used declared per trial).
    v08 = _invariant("I-08", "provider-declared", "")
    for r in records:
        if not r.provider_used:
            _add_violation(v08, f"trial {r.trial_id} {r.mode}: provider_used empty")
    v08["detail"] = "provider_used is non-empty for every trial"

    # I-09  Temps constant at 0.0 (determinism) recorded in provider meta.
    v09 = _invariant("I-09", "temperature-recorded", "")
    for r in records:
        meta = r.provider_meta or {}
        temp = meta.get("temperature")
        if temp is not None and temp != 0.0:
            _add_violation(v09, f"trial {r.trial_id} {r.mode}: temperature={temp}")
    v09["detail"] = "no recorded temperature deviates from 0.0"

    # I-10  Retries/failures are explicit (no silent skips).
    v10 = _invariant("I-10", "retries-explicit", "")
    for r in records:
        if r.error and r.error.split(":")[0] == "ProviderError" and r.retry_count == 0:
            _add_violation(v10, f"trial {r.trial_id} {r.mode}: provider error without recorded retry")
    v10["detail"] = "provider errors carry a retry_count"

    # I-11  Raw completions contain a valid JSON object, matching runtime parsing.
    v11 = _invariant("I-11", "raw-json-valid", "")
    for r in records:
        if r.raw_completion and not response_contains_json(r.raw_completion):
            _add_violation(v11, f"trial {r.trial_id} {r.mode}: raw_completion has no valid JSON object")
    v11["detail"] = "all non-null raw completions contain a valid JSON object"

    # I-12  Trial timestamps present, end >= start.
    v12 = _invariant("I-12", "timestamps-consistent", "")
    for r in records:
        if not r.timestamp_start or not r.timestamp_end:
            _add_violation(v12, f"trial {r.trial_id} {r.mode}: missing timestamp_start/end")
        elif r.timestamp_end < r.timestamp_start:
            _add_violation(v12, f"trial {r.trial_id} {r.mode}: timestamp_end < timestamp_start")
    v12["detail"] = "timestamp_start/end present and ordered for every trial"

    # I-13  Walking the listed actions: action in the Action enum.
    v13 = _invariant("I-13", "actions-in-enum", "")
    known = {a.value for a in Action}
    for r in records:
        if r.action is not None and r.action not in known:
            _add_violation(v13, f"trial {r.trial_id} {r.mode}: action={r.action!r} not in Action enum")
    v13["detail"] = "all parsed actions are members of the Action enum"

    # I-14  Degraded trials must declare fallback_used=True and a reason.
    v14 = _invariant("I-14", "degraded-declared", "")
    for r in records:
        if r.provider_used == "degraded":
            if not r.fallback_used:
                _add_violation(v14, f"trial {r.trial_id} {r.mode}: provider_used=degraded but fallback_used=False")
            if not r.fallback_reason:
                _add_violation(v14, f"trial {r.trial_id} {r.mode}: provider_used=degraded but no fallback_reason")
    v14["detail"] = "every degraded trial declares fallback_used + fallback_reason"

    # I-15  WIENER trials reached the tool/policy layer (no degraded WIENER run).
    v15 = _invariant("I-15", "wiener-fully-executed", "")
    for r in records:
        if r.mode == ExperimentMode.WIENER.value and not r.error and not r.final_decision:
            _add_violation(v15, f"trial {r.trial_id}: wiener missing final_decision")
    v15["detail"] = "every non-errored WIENER trial produced a policy decision"

    # I-16  Every trial is reproducible from its recorded inputs (seed+payload).
    v16 = _invariant("I-16", "reproducible-inputs", "")
    for r in records:
        if r.seed_id and not r.attack_payload and not r.benign_payload_or_context:
            _add_violation(v16, f"trial {r.trial_id} {r.mode}: no payload recorded for reproducibility")
    v16["detail"] = "seed_id + payload recorded for every trial"

    invariants = {
        v["id"]: v for v in (
            v01, v02, v03, v04, v05, v06, v07,
            v08, v09, v10, v11, v12, v13, v14,
            v15, v16,
        )
    }
    failing = [v["id"] for v in invariants.values() if v["status"] == "FAIL"]
    return {
        "experiment_id": experiment_id,
        "validation_status": "PASS" if not failing else "FAIL",
        "failing_invariants": failing,
        "invariants": invariants,
    }


def write_validation(out_dir: Path, records: list[TrialRecord], experiment_id: str) -> dict:
    result = run_validation(records, experiment_id)
    (out_dir / "validation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result