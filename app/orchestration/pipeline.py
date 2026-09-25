from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Callable

from ..blue_ai.blue_ai import BlueAI
from ..llm.base import LLMProvider
from ..llm.factory import get_llm
from ..logger import TrajectoryLogger
from ..models import (
    AgentEvent,
    BlueAssessment,
    PolicyDecision,
    RiskResult,
    SOCContext,
    SOCOutput,
    ToolResult,
    Trajectory,
)
from ..policy_gate.policy_gate import PolicyGate
from ..risk_engine.risk_engine import RiskEngine
from ..soc_agent.soc_agent import SOCAgent
from ..tools.tool_executor import SimulatedToolExecutor


class PipelineResult:
    __slots__ = (
        "trajectory",
        "assessment",
        "risk",
        "decision",
        "soc_provider",
        "tool_result",
    )

    def __init__(
        self,
        trajectory: Trajectory,
        assessment: BlueAssessment,
        risk: RiskResult,
        decision: PolicyDecision,
        soc_provider: str,
        tool_result: ToolResult | None = None,
    ) -> None:
        self.trajectory = trajectory
        self.assessment = assessment
        self.risk = risk
        self.decision = decision
        self.soc_provider = soc_provider
        self.tool_result = tool_result


class Pipeline:
    """The core runtime pipeline:

    Red AI (context) → SOC Agent → Trajectory → Blue AI → Risk Engine
    → Policy Gate → ALLOW / REVIEW / BLOCK
    """

    def __init__(
        self,
        llm: LLMProvider | None = None,
        soc_agent: SOCAgent | None = None,
        blue_ai: BlueAI | None = None,
        risk_engine: RiskEngine | None = None,
        policy_gate: PolicyGate | None = None,
        tool_executor: SimulatedToolExecutor | None = None,
        logger: TrajectoryLogger | None = None,
        listener: Callable[[str, str, dict], None] | None = None,
    ) -> None:
        llm = llm or get_llm()
        self.soc_agent = soc_agent or SOCAgent(llm)
        self.blue_ai = blue_ai or BlueAI(llm)
        self.risk_engine = risk_engine or RiskEngine()
        self.policy_gate = policy_gate or PolicyGate()
        self.tool_executor = tool_executor or SimulatedToolExecutor()
        self.logger = logger
        # Optional SSE stage-event sink; None = inert.
        self._listener = listener

    def _emit(self, stage: str, phase: str, data: dict) -> None:
        if self._listener is not None:
            self._listener(stage, phase, dict(data))

    def run(
        self,
        context: SOCContext,
        history: Sequence[AgentEvent] | None = None,
    ) -> PipelineResult:
        start = time.perf_counter()

        # 0. Red AI: adversarial context prepared.
        red_ai_ctx = {
            "alert_id": context.alert_id,
            "provenance": context.provenance,
            "environment": context.environment,
            "events": len(context.events),
        }
        self._emit("red_ai", "started", red_ai_ctx)
        self._emit("red_ai", "completed", red_ai_ctx)

        # 1. Red AI / SOC Agent.
        self._emit("soc_agent", "started", {})
        soc_output, raw, provider = self.soc_agent.analyze(context)
        self._emit("soc_agent", "completed", {
            "action": soc_output.action.value,
            "target": soc_output.target,
            "confidence": soc_output.confidence,
            "provider": provider,
        })

        # 2. Assemble the trajectory for the blue side.
        self._emit("trajectory", "started", {})
        # `history` = prior alerts from the same attacker, carried so the Blue
        # side assesses this alert against the accumulated campaign. It is
        # never shown to the SOC Agent, so the proposal prompt stays stable.
        agent_history = context.events if history is None else [*history, *context.events]
        trajectory = Trajectory(
            trial_id=context.alert_id,
            context=context,
            agent_history=agent_history,
            proposed_action=soc_output,
            provider_used=provider,
            # Provenance (logging-only): never used by Blue AI / Risk Engine / Policy Gate.
            metadata={"raw_completion": raw},
        )

        # 3. Persist the assembled trajectory exactly once (single store).
        if self.logger is not None:
            self.logger.record(trajectory, provider=provider)

        self._emit("trajectory", "completed", {
            "trial_id": trajectory.trial_id,
            "proposed_action": trajectory.proposed_action.action.value,
            "provider": provider,
        })

        # 4. Blue AI.
        self._emit("blue_ai", "started", {})
        assessment = self.blue_ai.analyze(trajectory)
        self._emit("blue_ai", "completed", {
            "route": assessment.route.value,
            "behavior_deviation": assessment.behavior_deviation,
            "context_trust": assessment.context_trust,
            "action_criticality": assessment.action_criticality,
            "evidence_tags": list(assessment.evidence_tags),
        })

        # 5. Risk Engine (deterministic).
        self._emit("risk_engine", "started", {})
        risk = self.risk_engine.evaluate(soc_output.action, assessment)
        self._emit("risk_engine", "completed", {
            "risk_score": risk.risk_score,
            "triggered_constraints": list(risk.triggered_constraints),
        })

        # 6. Policy Gate (deterministic, no LLM).
        self._emit("policy_gate", "started", {})
        decision = self.policy_gate.decide(risk)
        self._emit("policy_gate", "completed", {
            "decision": decision.decision.value,
            "constraint_ids": list(decision.constraint_ids),
            "reason_tags": list(decision.reason_tags),
        })

        # 7. Simulated tool layer: only after the gate, re-checked; never bypasses it.
        self._emit("simulated_tool", "started", {})
        tool_result = self.tool_executor.execute(decision, soc_output)
        self._emit("simulated_tool", "completed", {
            "executed": tool_result.executed,
            "status": tool_result.status.value,
            "action": tool_result.action.value,
            "detail": tool_result.detail,
        })

        # Append later-stage results onto the same log record.
        if self.logger is not None:
            self.logger.append(
                trajectory.trial_id,
                blue_assessment=assessment,
                risk=risk,
                policy_decision=decision,
                tool_result=tool_result,
            )
            self.logger.append(
                trajectory.trial_id,
                latency_ms=round((time.perf_counter() - start) * 1000, 3),
            )

        return PipelineResult(
            trajectory=trajectory,
            assessment=assessment,
            risk=risk,
            decision=decision,
            soc_provider=provider,
            tool_result=tool_result,
        )
