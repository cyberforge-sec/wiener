from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models import AgentEvent, SOCContext, SOCOutput, Trajectory
from app.soc_agent.soc_agent import SOCAgent

from .fakes import FakeLLM
from .fixtures import FIXTURES, load_all, load_fixture, load_trajectory
from .helpers import make_context



def test_soc_agent_does_not_own_trajectory_assembly():
    # SOC Agent returns only SOCOutput; it never builds a Trajectory.
    llm = FakeLLM(responses=['{"action": "block_ip", "target": "1.2.3.4", "confidence": 0.8}'])
    agent = SOCAgent(llm)
    ctx = make_context()
    out, _, provider = agent.analyze(ctx)
    assert isinstance(out, SOCOutput)
    assert not isinstance(out, Trajectory)


def test_trajectory_assembly_composes_all_parts():
    ctx = make_context(alert_id="alert-42")
    event = ctx.events[0]
    output = SOCOutput(action="block_ip", target="1.2.3.4", confidence=0.8)

    traj = Trajectory(
        trial_id=ctx.alert_id,
        context=ctx,
        agent_history=[event],
        proposed_action=output,
        provider_used="test",
    )

    assert traj.trial_id == "alert-42"
    assert traj.context is ctx or traj.context == ctx
    assert traj.proposed_action.action == "block_ip"
    assert traj.agent_history == [event]
    # Blue AI critical inputs preserved: provenance + events intact.
    assert traj.context.events == [event]


def test_trajectory_assembly_preserves_provenance():
    ctx = make_context()
    traj = Trajectory(
        trial_id=ctx.alert_id,
        context=ctx,
        agent_history=ctx.events,
        proposed_action=SOCOutput(action="check_endpoint", target="host-a", confidence=0.5),
        provider_used="test",
    )
    assert traj.context.provenance == ctx.provenance
    assert traj.context.environment == ctx.environment


def test_trajectory_supports_zero_event_history():
    ctx = SOCContext(alert_id="a0", events=[])
    traj = Trajectory(
        trial_id="a0",
        context=ctx,
        agent_history=[],
        proposed_action=SOCOutput(action="get_logs", confidence=0.4),
        provider_used="test",
    )
    assert traj.agent_history == []
    assert traj.context.events == []


def test_trajectory_supports_multi_step_history():
    events = [
        AgentEvent(event_id="i1", timestamp="t", source="soc_agent", event_type="investigation", severity=2, detail="get_logs"),
        AgentEvent(event_id="i2", timestamp="t2", source="soc_agent", event_type="investigation", severity=2, detail="search_ioc"),
    ]
    traj = Trajectory(
        trial_id="m",
        context=make_context(),
        agent_history=events,
        proposed_action=SOCOutput(action="disable_user", target="u-1", confidence=0.85),
        provider_used="replay",
    )
    assert [e.event_id for e in traj.agent_history] == ["i1", "i2"]



def test_trajectory_serialization_roundtrip():
    traj = load_trajectory("single_step")
    payload = traj.model_dump_json()
    restored = Trajectory.model_validate_json(payload)
    assert restored == traj
    assert restored.proposed_action.action == "check_endpoint"


def test_trajectory_serialization_plain_json_dict():
    traj = load_trajectory("single_step")
    dumped = traj.model_dump()
    assert dumped["trial_id"] == traj.trial_id
    assert dumped["context"]["alert_id"] == traj.context.alert_id
    assert dumped["proposed_action"]["action"] == "check_endpoint"
    # Full JSON roundtrip through dict.
    assert Trajectory.model_validate(dumped) == traj



def test_all_fixtures_known():
    assert set(FIXTURES) == {
        "single_step",
        "investigation_disable_user",
        "suspicious_context",
        "conflicting_evidence",
        "malformed",
    }


def test_single_step_fixture_loads():
    traj = load_trajectory("single_step")
    assert traj.trial_id == "fixture-single-step"
    assert len(traj.agent_history) == 1
    assert traj.proposed_action.action == "check_endpoint"


def test_investigation_disable_user_fixture():
    traj = load_trajectory("investigation_disable_user")
    assert [e.event_type for e in traj.agent_history] == ["investigation", "investigation"]
    assert traj.proposed_action.action == "disable_user"
    assert traj.proposed_action.target == "user-0412"


def test_suspicious_context_fixture():
    traj = load_trajectory("suspicious_context")
    assert all(e.severity >= 8 for e in traj.context.events)
    assert traj.proposed_action.action == "isolate_endpoint"


def test_conflicting_evidence_fixture():
    traj = load_trajectory("conflicting_evidence")
    # Benign signals + critical action → QWEN disambiguation in Blue AI.
    assert all(e.severity == 0 for e in traj.context.events)
    assert traj.proposed_action.action == "isolate_endpoint"


def test_malformed_fixture_fails_validation():
    with pytest.raises(ValidationError):
        load_trajectory("malformed")


def test_load_all_skips_malformed():
    loaded = load_all()
    assert "malformed" not in loaded
    assert len(loaded) == 4


def test_raw_fixture_preserves_malformed_shape():
    raw = load_fixture("malformed")
    assert raw["proposed_action"] is None