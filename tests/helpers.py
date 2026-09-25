from __future__ import annotations

import json

from app.models import AgentEvent, Decision, SOCContext, SOCOutput, Trajectory


def make_context(
    alert_id: str = "alert-1",
    severity: int = 5,
    source: str = "ids",
    event_type: str = "alert",
) -> SOCContext:
    return SOCContext(
        alert_id=alert_id,
        events=[
            AgentEvent(
                event_id=f"{alert_id}-e1",
                timestamp="2026-01-01T00:00:00Z",
                source=source,
                event_type=event_type,
                severity=severity,
                detail="simulated event",
            )
        ],
    )


def make_trajectory(
    context: SOCContext | None = None,
    action: str = "check_endpoint",
    target: str = "tgt",
    confidence: float = 0.7,
    provider: str = "test",
    events: list[AgentEvent] | None = None,
) -> Trajectory:
    ctx = context or make_context()
    if events is None:
        events = ctx.events
    return Trajectory(
        trial_id=ctx.alert_id,
        context=ctx,
        agent_history=events,
        proposed_action=SOCOutput(action=action, target=target, confidence=confidence),
        provider_used=provider,
    )


def make_benign_context(
    alert_id: str = "alert-benign",
) -> SOCContext:
    """A high-trust, low-deviation context (benign signals only)."""
    return SOCContext(
        alert_id=alert_id,
        events=[
            AgentEvent(
                event_id=f"{alert_id}-e1",
                timestamp="2026-01-01T00:00:00Z",
                source="user_report",
                event_type="log",
                severity=0,
                detail="routine log",
            )
        ],
    )


def make_suspicious_context(
    alert_id: str = "alert-suspicious",
) -> SOCContext:
    """A low-trust, high-deviation context (hostile signals only)."""
    return SOCContext(
        alert_id=alert_id,
        events=[
            AgentEvent(
                event_id=f"{alert_id}-e1",
                timestamp="2026-01-01T00:00:00Z",
                source="ids",
                event_type="intrusion",
                severity=9,
                detail="lateral movement attempt",
            ),
            AgentEvent(
                event_id=f"{alert_id}-e2",
                timestamp="2026-01-01T00:00:01Z",
                source="siem_sim",
                event_type="anomaly",
                severity=8,
                detail="unusual outbound beacon",
            ),
        ],
    )


def assessment_json(
    trust: int,
    deviation: int,
    criticality: int = 1,
    privilege: int = 1,
    tags: list[str] | None = None,
) -> str:
    """Valid Qwen output under the strict 5-field schema.

    Intrinsic scores default to deliberately wrong values to prove they are
    never adopted over the action_metadata.yaml sources.
    """
    return json.dumps(
        {
            "context_trust": trust,
            "behavior_deviation": deviation,
            "action_criticality": criticality,
            "privilege_impact": privilege,
            "evidence_tags": tags if tags is not None else ["CONFLICTING_EVIDENCE"],
        }
    )
