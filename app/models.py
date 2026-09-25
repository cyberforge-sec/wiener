from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field



class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class Action(str, Enum):
    GET_LOGS = "get_logs"
    SEARCH_IOC = "search_ioc"
    CHECK_ENDPOINT = "check_endpoint"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_USER = "disable_user"
    BLOCK_IP = "block_ip"


class BlueRoute(str, Enum):
    DETERMINISTIC = "deterministic"
    QWEN = "qwen"
    FALLBACK = "fallback"


# Backward-compatible alias so legacy imports keep working.
Route = BlueRoute



class AgentEvent(BaseModel):
    """A single meaningful event in the agent trajectory.

    Serializable. Preserves event type, source, and relevant content/metadata.
    Deliberately NOT an arbitrary general-purpose event framework.
    """

    event_id: str
    timestamp: str
    source: str  # e.g. "ids", "siem_sim", "user_report"
    event_type: str  # e.g. "alert", "log", "anomaly"
    severity: int = Field(ge=0, le=10, description="0-10 scale")
    detail: str = ""
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class SOCContext(BaseModel):
    """Context for the SOC Agent and Blue AI.

    `provenance` preserves the raw source/provenance of the alert as EVIDENCE.
    It must NOT be treated as a security score; the normalized `context_trust`
    is produced later by Blue AI / feature extraction.
    """

    alert_id: str
    events: list[AgentEvent]
    provenance: str = "unknown"
    environment: str = "simulated"
    notes: str = ""



class SOCOutput(BaseModel):
    """What the SOC agent proposes: NOT a final policy decision.

    MUST NOT contain risk_score, a final decision, or a PolicyDecision.
    """

    action: Action
    target: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""



class Trajectory(BaseModel):
    """Complete context for the blue-side analysis.

    Must preserve enough information for: Blue AI, Logger, Dashboard,
    Metrics, Replay.
    """

    trial_id: str
    context: SOCContext
    agent_history: list[AgentEvent] = Field(default_factory=list)
    proposed_action: SOCOutput
    provider_used: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)



class BlueAssessment(BaseModel):
    """Deterministic + optional LLM-based assessment of the trajectory."""

    context_trust: int = Field(ge=0, le=100)
    behavior_deviation: int = Field(ge=0, le=100)
    action_criticality: int = Field(ge=0, le=100)
    privilege_impact: int = Field(ge=0, le=100)
    evidence_tags: list[str] = Field(default_factory=list)
    route: BlueRoute = BlueRoute.DETERMINISTIC



class RiskResult(BaseModel):
    """Deterministic risk calculation: NOT the final decision.

    `required_decision` is produced ONLY when hard safety constraints match.
    """

    risk_score: float = Field(ge=0.0, le=100.0)
    triggered_constraints: list[str] = Field(default_factory=list)
    required_decision: Decision | None = None



class PolicyDecision(BaseModel):
    """Final deterministic policy decision."""

    decision: Decision
    reason_tags: list[str] = Field(default_factory=list)
    constraint_ids: list[str] = Field(default_factory=list)



class ToolStatus(str, Enum):
    """Why a simulated tool call ended as it did."""

    OK = "ok"
    REFUSED_BLOCK = "refused_block"
    REFUSED_REVIEW = "refused_review"
    UNSUPPORTED = "unsupported"


class ToolResult(BaseModel):
    """Outcome of attempting a SIMULATED security action.

    `executed` is True only when the action was actually simulated (and then it
    always carries an AgentEvent with simulated=true). The Policy Gate is the
    authorization boundary: when the active decision is BLOCK or REVIEW, or the
    action has no simulated tool, nothing is executed and no event is created.
    """

    action: Action
    target: str | None = None
    executed: bool = False
    status: ToolStatus
    event: AgentEvent | None = None
    detail: str = ""



class AttackCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    MALICIOUS_ACTION = "malicious_action"
    CONTEXT_POISONING = "context_poisoning"
    PRIVILEGE_ABUSE = "privilege_abuse"
    SOCIAL_ENGINEERING = "social_engineering"


class AttackSeed(BaseModel):
    """A fixed, reproducible adversarial seed."""

    seed_id: str = Field(min_length=1)
    category: AttackCategory
    payload: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    targets: list[str] = Field(min_length=1)
    # Attack intent (None = benign); measurement only, never risk/policy.
    intended_action: Action | None = None


class MutationKind(str, Enum):
    """Basic mutations: wording/framing/presentation/structure only."""

    SYNONYM_SWAP = "synonym_swap"
    FRAME_SHIFT = "frame_shift"
    STRUCTURE_REORDER = "structure_reorder"
    URGENCY_BOOST = "urgency_boost"


class MutationMeta(BaseModel):
    """Metadata describing a basic mutation applied to a seed payload."""

    kind: MutationKind
    rng_seed: int
    note: str = ""


class RedAttack(BaseModel):
    """A generated adversarial input (baseline at iteration 0, else mutated)."""

    seed_id: str
    category: AttackCategory
    iteration: int = Field(ge=0)
    payload: str
    mutation: MutationMeta | None = None
    # From the seed; measurement only, never risk/policy.
    intended_action: Action | None = None



class RedFeedback(BaseModel):
    """The ONLY feedback the Red AI loop may adapt on.

    Deliberately structured and minimal: previous policy decision, risk
    level/score, triggered defense tags, high-level reason tags, and the
    iteration number. No hidden chain-of-thought, no raw model output.
    """

    iteration: int = Field(ge=0)
    decision: Decision | None = None
    risk_score: float | None = Field(default=None, ge=0.0, le=100.0)
    defense_tags: list[str] = Field(default_factory=list)
    reason_tags: list[str] = Field(default_factory=list)


class StopReason(str, Enum):
    """Explicit stop conditions for the closed loop."""

    MAX_ITERATIONS = "max_iterations"
    ATTACK_SUCCEEDED = "attack_succeeded"
    DEFENSE_BLOCKED = "defense_blocked"
    PROVIDER_FAILURE = "provider_failure"
    MALFORMED_FEEDBACK = "malformed_feedback"


class LoopStep(BaseModel):
    """One completed closed-loop step: a generated attack and its feedback."""

    attack: RedAttack
    feedback: RedFeedback


class LoopReport(BaseModel):
    """Deterministic trace of a closed-loop run.

    `steps` holds only completed (attack, feedback) pairs; failures are
    surfaced through `stopped_reason` + `error` instead of crashing.
    """

    seed_id: str
    rng_seed: int
    max_iterations: int
    steps: list[LoopStep] = Field(default_factory=list)
    stopped_reason: StopReason
    error: str | None = None

    @property
    def iterations(self) -> int:
        return len(self.steps)



class ExperimentMode(str, Enum):
    """Defense conditions compared by the experiment runner."""

    NO_DEFENSE = "no_defense"
    BASIC_PROMPT_DEFENSE = "basic_prompt_defense"
    WIENER = "wiener"


class ExperimentConfig(BaseModel):
    """Configuration for a reproducible comparison experiment.

    Controls, per requirement: seed (fixed RNG), number of trials (attack
    variants per scenario), provider (LLM backend), scenario (seed selection).
    `modes` selects which conditions to run (default: all three).
    """

    experiment_id: str = "experiment"
    seed: int = Field(default=20260708)
    num_trials: int = Field(default=2, ge=1)
    provider: str = "replay"
    scenario: str | list[str] = "all"
    modes: list[ExperimentMode] = Field(
        default_factory=lambda: list(ExperimentMode)
    )

    @property
    def scenario_ids(self) -> list[str]:
        if isinstance(self.scenario, str):
            return [self.scenario]
        return list(self.scenario)


class TrialOutcome(BaseModel):
    """Final per-trial outcome, derived from real outputs: never hand-set.

    `proposed_action` is the agent's unfiltered action everywhere; `decision`
    and `executed` are populated only by the WIENER pipeline.
    """

    proposed_action: str | None = None
    decision: Decision | None = None
    executed: bool | None = None
    dangerous: bool = False
    summary: str = ""


class ExperimentTrial(BaseModel):
    """One complete trial in the experiment.

    Fields are populated "when applicable": NO_DEFENSE / BASIC_PROMPT_DEFENSE
    have no Blue/Risk/Policy stage; failed trials carry `error` and are never
    silently skipped.
    """

    trial_id: str
    seed_id: str
    mode: ExperimentMode
    attack: RedAttack
    soc_output: SOCOutput | None = None
    trajectory: Trajectory | None = None
    blue_assessment: BlueAssessment | None = None
    risk: RiskResult | None = None
    policy_decision: PolicyDecision | None = None
    latency_ms: float | None = None
    outcome: TrialOutcome | None = None
    error: str | None = None
    provider: str = ""
    # Trial timeline instants (ms) for TTI/E2E, each optional per running mode.
    generated_at_ms: float | None = None
    detected_at_ms: float | None = None
    intervened_at_ms: float | None = None


class ExperimentReport(BaseModel):
    """Full result set for one experiment run."""

    experiment_id: str
    config: ExperimentConfig
    trials: list[ExperimentTrial] = Field(default_factory=list)

    def trials_for(self, mode: ExperimentMode) -> list[ExperimentTrial]:
        return [t for t in self.trials if t.mode == mode]