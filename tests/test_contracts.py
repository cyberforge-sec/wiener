from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models import (
    Action,
    AgentEvent,
    BlueAssessment,
    BlueRoute,
    Decision,
    PolicyDecision,
    RiskResult,
    SOCContext,
    SOCOutput,
    Trajectory,
)


def _event(**overrides) -> dict:
    base = {
        "event_id": "e1",
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "ids",
        "event_type": "alert",
        "severity": 5,
    }
    base.update(overrides)
    return base


def _context(**overrides) -> dict:
    base = {"alert_id": "a1", "events": [_event()]}
    base.update(overrides)
    return base


def _soc_output(**overrides) -> dict:
    base = {"action": "block_ip", "target": "1.2.3.4", "confidence": 0.8}
    base.update(overrides)
    return base


def _trajectory(**overrides) -> dict:
    base = {
        "trial_id": "t1",
        "context": _context(),
        "agent_history": [_event()],
        "proposed_action": _soc_output(),
    }
    base.update(overrides)
    return base



def test_action_values():
    assert [a.value for a in Action] == [
        "get_logs",
        "search_ioc",
        "check_endpoint",
        "isolate_endpoint",
        "disable_user",
        "block_ip",
    ]


def test_decision_values():
    assert [d.value for d in Decision] == ["ALLOW", "REVIEW", "BLOCK"]


def test_blue_route_values():
    assert [r.value for r in BlueRoute] == ["deterministic", "qwen", "fallback"]


def test_route_alias_is_blue_route():
    assert BlueRoute is BlueRoute  # alias kept: Route = BlueRoute
    from app.models import Route

    assert Route is BlueRoute



def test_soccontext_valid():
    ctx = SOCContext(**{**_context(), "provenance": "ids-sensor-7"})
    assert ctx.alert_id == "a1"
    assert ctx.provenance == "ids-sensor-7"
    assert isinstance(ctx.events[0], AgentEvent)


def test_soccontext_missing_required_fields():
    with pytest.raises(ValidationError):
        SOCContext()  # alert_id + events missing
    with pytest.raises(ValidationError):
        SOCContext(alert_id="a1")  # events missing



def test_agentevent_valid_and_serializable():
    ev = AgentEvent(**_event())
    dumped = ev.model_dump()
    assert dumped["event_id"] == "e1"
    restored = AgentEvent.model_validate(dumped)
    assert restored == ev


def test_agentevent_invalid_severity():
    with pytest.raises(ValidationError):
        AgentEvent(**_event(severity=11))
    with pytest.raises(ValidationError):
        AgentEvent(**_event(severity=-1))


def test_agentevent_missing_required():
    with pytest.raises(ValidationError):
        AgentEvent(event_id="x")  # timestamp/source/event_type/severity missing



def test_soc_output_valid_and_action_coerced():
    out = SOCOutput(**_soc_output())
    assert out.action == Action.BLOCK_IP
    assert isinstance(out.action, Action)
    assert out.target == "1.2.3.4"
    assert out.confidence == 0.8


def test_soc_output_invalid_action():
    with pytest.raises(ValidationError):
        SOCOutput(**_soc_output(action="delete_everything"))
    with pytest.raises(ValidationError):
        SOCOutput(**_soc_output(action=123))


def test_soc_output_confidence_bounds():
    with pytest.raises(ValidationError):
        SOCOutput(**_soc_output(confidence=-0.1))
    with pytest.raises(ValidationError):
        SOCOutput(**_soc_output(confidence=1.5))


def test_soc_output_must_not_carry_decision_or_risk():
    out = SOCOutput(**_soc_output())
    assert not hasattr(out, "decision")
    assert not hasattr(out, "risk_score")
    assert not isinstance(out, PolicyDecision)



def test_trajectory_valid():
    traj = Trajectory(**_trajectory())
    assert traj.trial_id == "t1"
    assert isinstance(traj.context, SOCContext)
    assert traj.proposed_action.action is Action.BLOCK_IP
    assert len(traj.agent_history) == 1


def test_trajectory_missing_required_fields():
    with pytest.raises(ValidationError):
        Trajectory()  # all required fields missing
    with pytest.raises(ValidationError):
        Trajectory(**_trajectory(proposed_action=None))


def test_trajectory_serialization_roundtrip():
    traj = Trajectory(**_trajectory())
    assert Trajectory.model_validate_json(traj.model_dump_json()) == traj



def test_blue_assessment_valid_bounds():
    a = BlueAssessment(
        context_trust=50,
        behavior_deviation=50,
        action_criticality=50,
        privilege_impact=50,
    )
    assert a.context_trust == 50


@pytest.mark.parametrize("field", ["context_trust", "behavior_deviation", "action_criticality", "privilege_impact"])
def test_blue_assessment_below_zero_invalid(field):
    kwargs = {
        "context_trust": 50,
        "behavior_deviation": 50,
        "action_criticality": 50,
        "privilege_impact": 50,
    }
    kwargs[field] = -1
    with pytest.raises(ValidationError):
        BlueAssessment(**kwargs)


@pytest.mark.parametrize("field", ["context_trust", "behavior_deviation", "action_criticality", "privilege_impact"])
def test_blue_assessment_above_100_invalid(field):
    kwargs = {
        "context_trust": 50,
        "behavior_deviation": 50,
        "action_criticality": 50,
        "privilege_impact": 50,
    }
    kwargs[field] = 101
    with pytest.raises(ValidationError):
        BlueAssessment(**kwargs)


def test_blue_assessment_invalid_route():
    with pytest.raises(ValidationError):
        BlueAssessment(
            context_trust=10,
            behavior_deviation=10,
            action_criticality=10,
            privilege_impact=10,
            route="definitely-not-a-route",
        )


def test_blue_assessment_missing_fields():
    with pytest.raises(ValidationError):
        BlueAssessment()



def test_risk_result_valid():
    r = RiskResult(risk_score=50, triggered_constraints=["SC-001"], required_decision=Decision.BLOCK)
    assert r.required_decision == Decision.BLOCK


def test_risk_result_required_decision_none_by_default():
    r = RiskResult(risk_score=50)
    assert r.required_decision is None
    assert r.triggered_constraints == []


def test_risk_result_invalid_score():
    with pytest.raises(ValidationError):
        RiskResult(risk_score=150)
    with pytest.raises(ValidationError):
        RiskResult(risk_score=-0.1)


def test_risk_result_invalid_decision():
    with pytest.raises(ValidationError):
        RiskResult(risk_score=50, required_decision="MAYBE")



def test_policy_decision_valid():
    p = PolicyDecision(decision=Decision.REVIEW, reason_tags=["a"], constraint_ids=["SC-010"])
    assert p.decision == Decision.REVIEW


def test_policy_decision_invalid_decision():
    with pytest.raises(ValidationError):
        PolicyDecision(decision="RUN")


def test_policy_decision_missing_decision():
    with pytest.raises(ValidationError):
        PolicyDecision(reason_tags=["a"])



def test_contracts_serialize_to_plain_json():
    """model_dump_json must stay the project's single serialization format."""
    traj = Trajectory(**_trajectory())
    payload = traj.model_dump()
    assert payload["proposed_action"]["action"] == "block_ip"
    assert payload["context"]["alert_id"] == "a1"