"""Part A..T: authoritative experiment driver.

Usage:
    python -m scripts.experiments.main plan <experiment_id>
    python -m scripts.experiments.main run     <experiment_id>
The `run` command refuses (exit 2) unless preflight.json exists and PASSes.
Artifacts are always written under data/experiments/<experiment_id>/, never
under data/experiments/demo.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .common import ROOT, env_snapshot, now_iso, prompt_manifest, repo_manifest, file_sha256, sha256
from .lock import write_code_fingerprint, write_evidence_manifest
from .metrics import write_metrics
from .preflight import Preflight
from .run import build_trial_list, run
from .validation import write_validation

DATA_DIR = ROOT / "data" / "experiments"

RANDOM_SEED = 20260708
NUM_MALICIOUS_VARIANTS = 6  # it0..it6 => 35 malicious trials per mode (>=30)


def _id_timestamp() -> str:
    """Local wall-clock timestamp for the experiment ID: YYYYMMDD_HHMM."""
    return datetime.now().astimezone().strftime("%Y%m%d_%H%M")


def ensure_experiment_id(candidate: str | None) -> str:
    if candidate and candidate.startswith("authoritative_"):
        return candidate
    if candidate:
        raise SystemExit(f"experiment_id must be authoritative_*, got {candidate!r}")
    return "authoritative_" + _id_timestamp()


def plan(experiment_id: str, out_dir: Path) -> dict:
    """Static plan + manifests: everything that CAN be frozen before running."""
    from app.experiment.runner import _BASIC_DEFENSE_PROMPT, basic_prompt_defense_system_prompt
    from app.soc_agent.soc_agent import _SYSTEM_PROMPT

    cfg = {
        "experiment_id": experiment_id,
        "created_at": now_iso(),
        "preflight_required": ["A1.opencode.credentials", "A1.opencode.handshake", "A1.opencode.model-served", "A1.opencode.minimal-completion", "A2.env.recorded", "A3.local.reachable", "A3.local.model-present", "A3.local.minimal-completion", "A4.replay.store", "A4.replay.deterministic", "A5.pipeline.live-smoke"],
        "modes": ["no_defense", "basic_prompt_defense", "wiener"],
        "num_benign_scenarios": 10,
        "num_malicious_variants": NUM_MALICIOUS_VARIANTS,
        "malicious_per_mode": 35,
        "benign_per_mode": 10,
        "total_trials_per_mode": 45,
        "random_seed": RANDOM_SEED,
        "provider": "opencode",
        "model": __import__("app.config", fromlist=["config"]).config.CLOUD_MODEL,
        "endpoint_identifier": __import__("app.config", fromlist=["config"]).config.CLOUD_BASE_URL,
        "timeout_s": __import__("app.config", fromlist=["config"]).config.LLM_TIMEOUT_S,
        "response_format": __import__("app.config", fromlist=["config"]).config.CLOUD_RESPONSE_FORMAT,
        "risk_thresholds": {
            "allow": __import__("app.config", fromlist=["config"]).config.RISK_ALLOW_THRESHOLD,
            "review": __import__("app.config", fromlist=["config"]).config.RISK_REVIEW_THRESHOLD,
        },
        "risk_weights": {
            "trust": __import__("app.config", fromlist=["config"]).config.RISK_WEIGHT_TRUST,
            "deviation": __import__("app.config", fromlist=["config"]).config.RISK_WEIGHT_DEVIATION,
            "criticality": __import__("app.config", fromlist=["config"]).config.RISK_WEIGHT_CRITICALITY,
            "privilege": __import__("app.config", fromlist=["config"]).config.RISK_WEIGHT_PRIVILEGE,
        },
        "system_prompt_ids": ["soc_agent._SYSTEM_PROMPT", "runner._BASIC_DEFENSE_PROMPT", "runner.basic_prompt_defense_system_prompt"],
        "system_prompt_hashes": {
            "soc_agent._SYSTEM_PROMPT": sha256(_SYSTEM_PROMPT.encode()),
            "runner._BASIC_DEFENSE_PROMPT": sha256(_BASIC_DEFENSE_PROMPT.encode()),
            "runner.basic_prompt_defense_system_prompt": sha256(basic_prompt_defense_system_prompt().encode()),
        },
        "metric_version": "app.metrics.core + authoritative Wilson CI serialization v1",
        "provider_policy": {
            "primary": "opencode",
            "secondary": "local/qwen2.5:1.5b",
            "replay": "replay validation only",
            "fallback_recorded_in_provider_meta": True,
        },
        "temperature_policy": "0.0 fixed (determinism)",
        "no_modification": ["data/experiments/demo.json", "config/*.yaml", "app/metrics/core.py"],
        "trial_schema": "scripts.experiments.common.TrialRecord (Part E)",
    }
    write_code_fingerprint(out_dir)
    artifacts = {
        "experiment_config.json": cfg,
        "environment.json": env_snapshot(),
        "prompt_manifest.json": prompt_manifest(),
        "repo_manifest.json": repo_manifest(),
        "seed_manifest.json": seed_manifest(),
    }
    for name, payload in artifacts.items():
        (out_dir / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return cfg


def seed_manifest() -> dict:
    from .common import BENIGN_SEEDS as BN
    from app.red_ai.seed_loader import SeedLoader
    seeds = SeedLoader().seeds
    return {
        "malicious": [
            {"seed_id": s.seed_id, "category": s.category.value, "intended_action": s.intended_action.value if s.intended_action else None}
            for s in seeds
        ],
        "benign": [
            {"seed_id": s.seed_id, "category": s.category.value, "intended_action": s.intended_action.value if s.intended_action else None}
            for s in BN
        ],
    }


def stage1(experiment_id: str, out_dir: Path) -> dict:
    """Phase 1: preflight. Writes preflight.json. Does NOT launch trials."""
    pre = Preflight(experiment_id, out_dir)
    return pre.run_and_write()


def stage2(experiment_id: str, out_dir: Path) -> dict:
    """Phase 2: run the full experiment (only reached when preflight PASSes)."""
    run(experiment_id, out_dir, NUM_MALICIOUS_VARIANTS)
    # Read the FULL trial set back from the store (resume-safe).
    from json import loads as _loads
    from .common import TrialRecord
    path = out_dir / "trials.jsonl"
    rows = [_loads(line) for line in path.open(encoding="utf-8") if line.strip()]
    parsed = [TrialRecord(**r) for r in rows]
    metrics = write_metrics(out_dir, parsed, NUM_MALICIOUS_VARIANTS, experiment_id)
    validation = write_validation(out_dir, parsed, experiment_id)
    evidence_manifest = write_evidence_manifest(out_dir)
    summary = {
        "experiment_id": experiment_id,
        "completed_at": now_iso(),
        "metrics": metrics,
        "validation": validation["validation_status"],
        "evidence_status": evidence_manifest["evidence_status"],
        "n_trials": len(rows),
    }
    (out_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authoritative experiment harness")
    parser.add_argument("command", choices=["plan", "preflight", "run"], help="phase to execute")
    parser.add_argument("experiment_id", nargs="?", default=None, help="authoritative_YYYYMMDD_HHMM (auto if omitted)")
    args = parser.parse_args(argv)

    experiment_id = ensure_experiment_id(args.experiment_id)
    out_dir = DATA_DIR / experiment_id
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.command == "plan":
        cfg = plan(experiment_id, out_dir)
        print(f"experiment_id={experiment_id}")
        print(f"artifacts written to {out_dir}")
        print(json.dumps(cfg, indent=2))
        return 0

    if args.command == "preflight":
        result = stage1(experiment_id, out_dir)
        print(json.dumps(result, indent=2))
        return 0 if result["preflight"] == "PASS" else 2

    if args.command == "run":
        result = stage1(experiment_id, out_dir)
        if result["preflight"] != "PASS":
            print("PREFLIGHT BLOCKED — full experiment refused. See preflight.json.")
            print(json.dumps(result, indent=2))
            return 2
        summary = stage2(experiment_id, out_dir)
        print(json.dumps(summary, indent=2))
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
