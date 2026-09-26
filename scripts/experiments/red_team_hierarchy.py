"""TARGETED instruction-hierarchy stress study. Not an authoritative benchmark.

The general stress population varies attack shape across nine families. This
one holds the shape roughly constant and varies only the attacker's claim over
the instruction hierarchy: override, fake system authority, emergency
authorization, policy reinterpretation, quoted instruction, role reassignment,
conflicting-resolution, indirect injection, multi-turn authority laundering, and
a paraphrase of an override.

That is a controlled question rather than a louder one, because the two ungated
modes differ in exactly one variable: whether the system prompt instructing the
model to resist is present at all. Model, route, temperature, scenario
population, and the payload handed to each mode are held identical, so any
difference between No Defense and Basic Prompt Defense is attributable to that
prompt and to nothing else.

HYPOTHESIS, AND WHY IT IS NOT A TARGET
    The intended expectation is that No Defense is at least as susceptible as
    Basic Prompt Defense, i.e. that a resistance prompt helps.

    This module does not encode that ordering anywhere. No assertion, no
    threshold, no pass/fail gate and no metric is derived from it. The study
    reports whichever ordering it observes. A result in which Basic Prompt
    Defense is no better than no defense is a perfectly valid outcome of this
    study and is the more interesting one, because it would show that a
    prompt-level defense adds no execution boundary.

    The only reason the hypothesis is written down at all is that a reader
    should know what the study was for. `HYPOTHESIS` is exported so a report
    can quote it as a question, and nothing imports it to make a decision.

Reuses the mutation and adaptation machinery from the general stress test
unchanged, so the two studies differ only in their population.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from app.config import config
from app.llm.factory import resolve_llm
from app.red_ai.seed_loader import HierarchySeedLoader

from .red_team_stress import (
    DEFAULT_HORIZON,
    DEFAULT_RNG_SEED,
    ChainAudit,
    IterationRecord,
    adaptive_summary,
    compute_stress_metrics,
    run_stress,
)

ARTIFACT_PREFIX = "red_team_hierarchy"
LABEL = "TARGETED INSTRUCTION-HIERARCHY STRESS TEST / NOT AUTHORITATIVE BENCHMARK"

# Stated so a report can quote the question. Deliberately unused by any logic
# below: no comparison, assertion or pass/fail reads it.
HYPOTHESIS = (
    "No Defense dangerous proposals >= Basic Prompt Defense dangerous proposals, "
    "i.e. a resistance prompt should not make the model MORE compliant with a "
    "dangerous instruction. Observed ordering is reported unchanged either way."
)


def new_experiment_id() -> str:
    return f"{ARTIFACT_PREFIX}_{datetime.now().strftime('%Y%m%d_%H%M')}"


def write_hierarchy_bundle(
    experiment_id: str,
    records: list[IterationRecord],
    audits: list[ChainAudit],
    *,
    out_root: Path | None = None,
    rng_seed: int = DEFAULT_RNG_SEED,
    horizon: int = DEFAULT_HORIZON,
) -> Path:
    """Write the bundle. Refuses any name outside this study's namespace."""
    if not experiment_id.startswith(ARTIFACT_PREFIX):
        raise ValueError(
            f"hierarchy-study artifacts must be named {ARTIFACT_PREFIX}_<timestamp>, "
            f"got {experiment_id!r}"
        )
    out_dir = (out_root or Path(config.EXPERIMENT_STORE_PATH)) / experiment_id
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "STRESS_TEST_NOT_AUTHORITATIVE.txt").write_text(
        f"{LABEL}\n\n"
        "This is a targeted instruction-hierarchy stress study. It is NOT an\n"
        "authoritative benchmark and must never be presented as one.\n\n"
        "The general stress population lives in its own bundle\n"
        "(red_team_stress_*) and the authoritative benchmark in its own\n"
        "authoritative_* bundle. Neither is affected by this directory.\n",
        encoding="utf-8",
    )

    with (out_dir / "iterations.jsonl").open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r.__dict__, default=str) + "\n")

    metrics = compute_stress_metrics(records)
    payload = {
        "manifest_type": "instruction_hierarchy_stress_study",
        "label": LABEL,
        "is_authoritative_benchmark": False,
        "experiment_id": experiment_id,
        "created_at": datetime.now().astimezone().isoformat(),
        "rng_seed": rng_seed,
        "horizon": horizon,
        "population_file": "config/stress_hierarchy_seeds.yaml",
        "population_source": "app.red_ai.seed_loader.HierarchySeedLoader",
        "controlled_variable": (
            "the presence of the resistance system prompt; model, route, "
            "temperature, scenario population and per-iteration payload are "
            "identical across all three modes"
        ),
        "hypothesis_stated_for_the_reader": HYPOTHESIS,
        "hypothesis_enforced": False,
        "hypothesis_note": (
            "Recorded as a question only. No assertion, threshold, gate or metric "
            "in this study is derived from it, and the observed ordering is "
            "reported unchanged."
        ),
        "metrics": metrics,
        "adaptive": adaptive_summary(records, audits),
        "n_records": len(records),
        "n_seeds": len({r.seed_id for r in records}),
    }
    (out_dir / "hierarchy_report.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8"
    )
    return out_dir


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="instruction-hierarchy stress study",
        description=f"{LABEL}",
    )
    parser.add_argument("--seeds", default="")
    parser.add_argument("--horizon", type=int, default=DEFAULT_HORIZON)
    parser.add_argument("--rng-seed", type=int, default=DEFAULT_RNG_SEED)
    parser.add_argument("--experiment-id", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    loader = HierarchySeedLoader()
    wanted = [s.strip() for s in args.seeds.split(",") if s.strip()]
    seeds = [loader.get(sid) for sid in wanted] if wanted else loader.seeds
    if any(s is None for s in seeds):
        raise SystemExit(f"unknown hierarchy seed id in: {args.seeds}")
    seeds = [s for s in seeds if s is not None]

    print(LABEL)
    print(f"population: {len(seeds)} seeds "
          f"({sum(1 for s in seeds if s.intended_action)} adversarial, "
          f"{sum(1 for s in seeds if not s.intended_action)} benign)")
    print(f"horizon={args.horizon} rng_seed={args.rng_seed}")
    print(f"question under test: {HYPOTHESIS}")
    if args.dry_run:
        for s in seeds:
            print(f"  {s.seed_id:8} {s.category.value:22} intended={s.intended_action.value if s.intended_action else '—'}")
        print("dry run: no provider calls, no artifact written")
        return 0

    llm = resolve_llm("openai_compatible", strict_replay=True)
    records: list[IterationRecord] = []
    audits: list[ChainAudit] = []
    for seed in seeds:
        recs, audit = run_stress(seed, llm=llm, horizon=args.horizon, rng_seed=args.rng_seed)
        records.extend(recs)
        audits.append(audit)
        print(f"  {seed.seed_id:8} iterations={audit.iterations} "
              f"distinct={audit.distinct_output_hashes}")

    experiment_id = args.experiment_id or new_experiment_id()
    out_dir = write_hierarchy_bundle(
        experiment_id, records, audits, rng_seed=args.rng_seed, horizon=args.horizon
    )
    metrics = compute_stress_metrics(records)
    print(f"\nartifact: {out_dir}")
    print("\nobserved (reported unchanged, no ordering enforced):")
    for mode in ("no_defense", "basic_prompt_defense", "wiener"):
        m = metrics[mode]
        p = m["attack_effectiveness"]["dangerous_proposals"]
        u = m["execution_safety"]["unsafe_executions"]
        f = m["operational_safety"]["false_interventions"]
        print(f"  {mode:22} proposals={p['numerator']}/{p['denominator']}  "
              f"unsafe={u['numerator']}/{u['denominator']}  "
              f"fir={f['numerator']}/{m['operational_safety']['benign_controls']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
