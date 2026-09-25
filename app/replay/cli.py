"""run_replay CLI: deterministic replay package entry point.

Usage:
  run_replay --scenario REPLAY-002
  run_replay --scenario ALL
  run_replay --scenario ALL --validate --runs 5

Every run is REPLAY MODE: the recorded response store is read, the pipeline is
replayed deterministically, and the output is explicitly labeled so a replay
is never presented as live AI inference.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scenarios import SCENARIOS, SCENARIO_IDS
from .runner import ReplayArtifact, logical_digest, run_scenario

BANNER = """
========================================================================
  REPLAY MODE — deterministic artifact
  Source: recorded response store (no live model inference)
========================================================================
"""


def _render(artifact: ReplayArtifact) -> str:
    lines = [
        f"  Scenario     : {artifact.scenario_id}  [{artifact.mode}]",
        f"  Recorded tier: {artifact.recorded_tier or '-'}  (replayed verbatim)",
    ]
    if artifact.mode == "single":
        policy = artifact.policy_decision or {}
        risk = artifact.risk or {}
        assess = artifact.blue_assessment or {}
        soc = artifact.soc_output or {}
        tool = artifact.tool_result or {}
        lines += [
            f"  Pipeline     : SOC -> trajectory -> Blue AI -> risk -> policy gate",
            f"  SOC action   : {soc.get('action')} target={soc.get('target')} conf={soc.get('confidence')}",
            f"  SOC provider : {artifact.soc_provider or '-'}",
            f"  Blue AI      : trust={assess.get('context_trust')} dev={assess.get('behavior_deviation')} "
            f"crit={assess.get('action_criticality')} priv={assess.get('privilege_impact')} "
            f"route={assess.get('route')}",
            f"  Risk score   : {risk.get('risk_score')}  "
            f"constraints={risk.get('triggered_constraints')}",
            f"  Decision     : {policy.get('decision')}  "
            f"reasons={policy.get('reason_tags')}",
            f"  Tool         : {tool.get('status')} executed={tool.get('executed')}",
        ]
    else:
        lines += [
            f"  Seed         : {artifact.seed_id} (rng={artifact.rng_seed}, max_iter={artifact.max_iterations})",
            f"  Stopped      : {artifact.stopped_reason}",
        ]
        for s in artifact.steps:
            mut = s.mutation_kind or "baseline"
            lines.append(
                f"      it{s.iteration} [{mut}] decision={s.feedback_decision} "
                f"risk={s.risk_score} tags={s.defense_tags}"
            )
        lines.append(f"  Final        : {artifact.final_decision}")
    lines.append(
        f"  Expected     : {artifact.expected}"
        f"  ->  {'PASS' if artifact.passed else 'FAIL'}"
    )
    return "\n".join(lines)


def run_once(sid: str, out_dir: Path) -> int:
    scenario = SCENARIOS[sid]
    print(f"\n  >>> {sid}: {scenario.title}")
    print(f"      {scenario.description}\n")
    artifact = run_scenario(sid)
    print(_render(artifact))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{sid}.json").write_text(artifact.model_dump_json(indent=2))
    return 0 if artifact.passed else 1


def run_validate(sid: str, runs: int, out_dir: Path) -> int:
    scenario = SCENARIOS[sid]
    print(f"\n  >>> VALIDATE {sid}: {scenario.title} ({runs} repeats)")
    digests: list[dict] = []
    artifacts: list[ReplayArtifact] = []
    for i in range(runs):
        artifact = run_scenario(sid)
        artifacts.append(artifact)
        digests.append(logical_digest(artifact))
    ref = digests[0]
    stable = all(d == ref for d in digests[1:])
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{sid}-validate.json").write_text(
        json.dumps(
            {
                "scenario_id": sid,
                "runs": runs,
                "stable": stable,
                "logical_result": {"decision": ref.get("decision") or ref.get("final_decision")},
                "digests": digests,
            },
            indent=2,
        )
    )
    print(f"      logical result: {ref}")
    if not stable:
        for i, d in enumerate(digests):
            print(f"      run {i}: {d}")
    print(f"      deterministic across {runs} repeats: {'YES' if stable else 'NO'}")
    all_pass = all(a.passed for a in artifacts) and stable
    print(f"      expected {scenario.expected.value} matched: {'YES' if all_pass else 'NO'}")
    return 0 if all_pass else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run_replay",
        description="Deterministic replay package — re-executes recorded SOC scenarios with zero live inference.",
    )
    parser.add_argument(
        "--scenario",
        default="ALL",
        help="Scenario id (REPLAY-001..004) or ALL (default: ALL).",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run each scenario N times and assert the identical logical result on every repeat.",
    )
    parser.add_argument("--runs", type=int, default=3, help="Repeats for --validate (default: 3).")
    parser.add_argument("--out", default="data/replays/runs", help="Artifact output directory.")
    args = parser.parse_args(argv)

    print(BANNER)

    requested = args.scenario.upper()
    targets = list(SCENARIO_IDS) if requested in ("ALL", "REPLAY-ALL") else [requested]
    for sid in targets:
        if sid not in SCENARIOS:
            print(f"unknown scenario: {args.scenario}")
            return 2

    missing_store = _missing_recorded_files()
    if missing_store:
        print(f"[error] recorded store incomplete. Missing: {', '.join(missing_store)}")
        print("        run `python3 -m app.replay.prime` first.")
        return 2

    out_dir = Path(args.out)
    code = 0
    for sid in targets:
        if args.validate:
            code |= run_validate(sid, args.runs, out_dir)
        else:
            code |= run_once(sid, out_dir)

    print("\n  REPLAY MODE complete — all outputs are recorded deterministic artifacts.")
    return code


def _missing_recorded_files() -> list[str]:
    """Scenario ids with no entry in the recorded store (avoids silent defaults).

    A shared prompt key legitimately serves several scenarios (e.g. the judge's
    attack baseline and a REPLAY scenario use the same rendered seed), so a
    `/`-joined tag means the file covers EVERY listed scenario.
    """
    from .runner import RECORDED_DIR

    store = Path(RECORDED_DIR)
    if not store.exists():
        return list(SCENARIO_IDS)
    covered: set[str] = set()
    for path in store.glob("*.json"):
        try:
            doc = json.loads(path.read_text())
            scenario = (dict(doc.get("meta") or {})).get("scenario")
            if scenario:
                covered.update(scenario.split("/"))
        except (json.JSONDecodeError, OSError):
            continue
    return [sid for sid in SCENARIO_IDS if sid not in covered]


def run_replay(argv: list[str] | None = None) -> int:
    return main(argv)


if __name__ == "__main__":
    sys.exit(main())