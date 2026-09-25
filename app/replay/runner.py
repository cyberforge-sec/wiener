"""Deterministic scenario runner for the replay package.

`run_scenario` re-executes the exact SOC → trajectory → Blue AI → risk →
policy pipeline used at record time, but always through the ReplayProvider
(never a live model). The artifact preserves fixed input, trajectory, SOC
output, BlueAssessment, RiskResult, PolicyDecision, tool result, and the
expected decision, so any run can be validated by hand or by a script.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ..llm.base import LLMProvider
from ..llm.replay_provider import RECORDED_DIR, ReplayProvider
from ..models import SOCContext
from ..orchestration.pipeline import Pipeline
from ..red_ai import RedAttackLogger, RedLoop, SeedLoader, render_attack
from ..red_ai.mutator import baseline
from .scenarios import SCENARIOS, get



class StepArtifact(BaseModel):
    iteration: int
    attack_payload: str
    mutation_kind: str | None = None
    mutation_rng_seed: int | None = None
    feedback_decision: str
    risk_score: float = 0.0
    defense_tags: list[str] = Field(default_factory=list)
    reason_tags: list[str] = Field(default_factory=list)
    soc_provider: str = ""


class ReplayArtifact(BaseModel):
    scenario_id: str
    mode: str = "single"
    replay_mode: bool = True
    recorded_tier: str = ""
    expected: str
    passed: bool

    fixed_input: dict[str, Any] | None = None  # SOCContext (single) or seed/loop params (adaptive)

    trajectory: dict[str, Any] | None = None
    soc_output: dict[str, Any] | None = None
    soc_raw: str | None = None
    soc_provider: str | None = None
    blue_assessment: dict[str, Any] | None = None
    risk: dict[str, Any] | None = None
    policy_decision: dict[str, Any] | None = None
    tool_result: dict[str, Any] | None = None

    seed_id: str | None = None
    rng_seed: int | None = None
    max_iterations: int | None = None
    stopped_reason: str | None = None
    steps: list[StepArtifact] = Field(default_factory=list)

    @property
    def final_decision(self) -> str:
        if self.mode == "single":
            return str((self.policy_decision or {}).get("decision", "?"))
        return self.steps[-1].feedback_decision if self.steps else "?"


class _RecordingProvider:
    """Serves a fixed ordered list of replies while capturing the prompt keys.

    Used only to PRIME the recorded store; the CLI never runs this path.
    """

    name = "recording"

    def __init__(self, replies: list[dict]) -> None:
        self._replies = list(replies)
        self._i = 0
        self.captured: dict[str, dict] = {}

    def complete(self, system: str, user: str) -> Any:
        key = ReplayProvider._key(system, user)
        if self._i >= len(self._replies):
            raise RuntimeError("recording provider exhausted (more LLM calls than planned replies)")
        reply = dict(self._replies[self._i])
        self._i += 1
        self.captured[key] = reply
        return type("LLMResponse", (), {"text": reply["text"], "provider": reply["provider"], "meta": {}})()



def _render_seed_context(seed_id: str) -> SOCContext:
    seed = SeedLoader().get(seed_id)
    if seed is None:
        raise ValueError(f"unknown seed_id: {seed_id}")
    return render_attack(baseline(seed))


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def run_scenario(
    sid: str,
    llm: LLMProvider | None = None,
    recorded_dir: str | None = None,
    adaptive_log_dir: str | None = None,
) -> ReplayArtifact:
    """Deterministically execute scenario `sid`.

    With `llm` None the recorded ReplayProvider store is used; the primer
    passes `_RecordingProvider` for the one-time store build.
    """
    scenario = get(sid)
    provider = llm or ReplayProvider(replay_dir=recorded_dir or str(RECORDED_DIR))

    if scenario.kind == "single":
        context = scenario.context or _render_seed_context(scenario.seed_id)
        result = Pipeline(llm=provider).run(context)
        locked = json.dumps(
            {
                "context": context.model_dump(mode="json"),
                "trajectory": result.trajectory.model_dump(mode="json"),
                "soc_output": result.trajectory.proposed_action.model_dump(mode="json"),
            },
            sort_keys=True,
            default=str,
        )
        return ReplayArtifact(
            scenario_id=scenario.sid,
            mode="single",
            replay_mode=True,
            recorded_tier=scenario.recorded_tier,
            expected=scenario.expected.value,
            passed=result.decision.decision == scenario.expected,
            fixed_input={"context": context.model_dump(mode="json"), "input_digest": _digest(locked)},
            trajectory=result.trajectory.model_dump(mode="json"),
            soc_output=result.trajectory.proposed_action.model_dump(mode="json"),
            soc_provider=result.soc_provider,
            blue_assessment=result.assessment.model_dump(mode="json"),
            risk=result.risk.model_dump(mode="json"),
            policy_decision=result.decision.model_dump(mode="json"),
            tool_result=result.tool_result.model_dump(mode="json") if result.tool_result else None,
        )

    # Adaptive: the defense is the SAME SOC/defense pipeline, driven by the loop.
    if scenario.kind == "adaptive":
        cache: list[Any] = []

        def defense(context: SOCContext) -> Any:
            res = Pipeline(llm=provider).run(context)
            cache.append(res)
            return res

        log_dir = Path(adaptive_log_dir) if adaptive_log_dir else (Path(RECORDED_DIR).parent.parent.parent / "data" / "replays" / "logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        loop = RedLoop(
            defense,
            attack_logger=RedAttackLogger(
                path=str(log_dir / f"{scenario.sid}-attacks.jsonl"),
                feedback_path=str(log_dir / f"{scenario.sid}-feedback.jsonl"),
            ),
            rng_seed=scenario.rng_seed,
            max_iterations=scenario.max_iterations,
        )
        report = loop.run(scenario.seed_id)

        steps: list[StepArtifact] = []
        for i, step in enumerate(report.steps):
            res = cache[i]
            steps.append(
                StepArtifact(
                    iteration=step.attack.iteration,
                    attack_payload=step.attack.payload,
                    mutation_kind=step.attack.mutation.kind.value if step.attack.mutation else None,
                    mutation_rng_seed=step.attack.mutation.rng_seed if step.attack.mutation else None,
                    feedback_decision=step.feedback.decision.value if step.feedback.decision else "?",
                    risk_score=float(step.feedback.risk_score or 0.0),
                    defense_tags=list(step.feedback.defense_tags),
                    reason_tags=list(step.feedback.reason_tags),
                    soc_provider=getattr(res, "soc_provider", "") or "",
                )
            )

        final = report.steps[-1].feedback.decision if report.steps else None
        passed = final == scenario.expected and report.stopped_reason.value == "max_iterations"

        return ReplayArtifact(
            scenario_id=scenario.sid,
            mode="adaptive",
            replay_mode=True,
            recorded_tier=scenario.recorded_tier,
            expected=scenario.expected.value,
            passed=passed,
            fixed_input={
                "seed_id": scenario.seed_id,
                "rng_seed": scenario.rng_seed,
                "max_iterations": scenario.max_iterations,
                "seed_payload": _render_seed_context(scenario.seed_id).events[0].detail,
            },
            seed_id=scenario.seed_id,
            rng_seed=scenario.rng_seed,
            max_iterations=scenario.max_iterations,
            stopped_reason=report.stopped_reason.value,
            steps=steps,
        )


def logical_digest(artifact: ReplayArtifact) -> dict:
    """A stable fingerprint of the LOGICAL result (for repeat validation)."""
    if artifact.mode == "single":
        policy = artifact.policy_decision or {}
        return {
            "decision": policy.get("decision"),
            "risk_score": round(float((artifact.risk or {}).get("risk_score", 0.0)), 4),
            "constraint_ids": tuple(policy.get("constraint_ids") or []),
            "reason_tags": tuple(policy.get("reason_tags") or []),
            "soc_provider": artifact.soc_provider,
            "tool_status": (artifact.tool_result or {}).get("status"),
        }
    return {
        "final_decision": artifact.final_decision,
        "stopped_reason": artifact.stopped_reason,
        "iterations": len(artifact.steps),
        "step_decisions": tuple(s.feedback_decision for s in artifact.steps),
        "step_constraints": tuple(tuple(s.defense_tags) for s in artifact.steps),
    }


def prime_store(replies_override: dict | None = None) -> dict[str, int]:
    """Build the recorded store by running each scenario once in capture mode.

    Calls the CLI path with zero live inference; the fixture replies defined in
    `scenarios.REPLIES` key the store deterministically. Returns the number of
    recorded entries per scenario.
    """
    from ..llm.replay_provider import ReplayProvider as RP

    store = Path(RECORDED_DIR)
    store.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for sid in SCENARIOS:
        replies = (replies_override or {}).get(sid, None)
        if replies is None:
            from .scenarios import REPLIES

            replies = REPLIES[sid]
        rec = _RecordingProvider([dict(r) for r in replies])
        art = run_scenario(sid, llm=rec)
        if not art.passed:
            raise RuntimeError(f"scenario {sid} did not produce its expected result during priming")
        writer = RP(replay_dir=str(store))
        for key, reply in rec.captured.items():
            writer.save_recorded(
                key,
                reply["text"],
                meta={"scenario": sid, "source": reply.get("source", "fixture")},
                provider=reply.get("provider", "replay"),
            )
        counts[sid] = len(rec.captured)
    return counts