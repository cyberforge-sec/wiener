from __future__ import annotations

import pytest

from app.logger.trajectory_logger import TrajectoryLogger
from app.models import Action, AgentEvent, Decision, PolicyDecision, SOCOutput, ToolStatus
from app.orchestration.pipeline import Pipeline
from app.tools.tool_executor import SimulatedToolExecutor
from tests.fakes import FakeLLM
from tests.helpers import make_benign_context, make_context

_NOW = "2026-09-09T00:00:00Z"


def _allow(action: str, target: str | None) -> PolicyDecision:
    return PolicyDecision(decision=Decision.ALLOW, reason_tags=["threshold_allow"], constraint_ids=[])


def _output(action: str, target: str | None) -> SOCOutput:
    return SOCOutput(action=Action(action), target=target, confidence=0.8)


def _executor() -> SimulatedToolExecutor:
    return SimulatedToolExecutor(now=lambda: _NOW)


SUPPORTED = [
    ("get_logs", None, Action.GET_LOGS),
    ("search_ioc", "185.220.101.44", Action.SEARCH_IOC),
    ("check_endpoint", "host-a", Action.CHECK_ENDPOINT),
    ("block_ip", "1.2.3.4", Action.BLOCK_IP),
    ("disable_user", "alice", Action.DISABLE_USER),
]


def test_block_ip_simulation():
    res = _executor().execute(_allow("block_ip", "1.2.3.4"), _output("block_ip", "1.2.3.4"))
    assert res.executed is True
    assert res.status == ToolStatus.OK
    assert res.action == Action.BLOCK_IP
    assert res.target == "1.2.3.4"
    assert res.event is not None
    assert "DROP" in res.detail


def test_disable_user_simulation():
    res = _executor().execute(_allow("disable_user", "alice"), _output("disable_user", "alice"))
    assert res.executed is True
    assert res.status == ToolStatus.OK
    assert res.action == Action.DISABLE_USER
    assert res.target == "alice"
    assert "disabled" in res.detail


@pytest.mark.parametrize("action,target,expected_enum", SUPPORTED)
def test_supported_tools_create_event(action, target, expected_enum):
    res = _executor().execute(_allow(action, target), _output(action, target))
    assert res.executed is True
    assert res.action == expected_enum
    event = res.event
    assert event is not None
    assert event.event_id
    assert event.timestamp == _NOW
    assert event.source == "simulated_tools"
    assert event.event_type == "simulated_action"
    assert 0 <= event.severity <= 10
    assert event.detail


@pytest.mark.parametrize("action,target,_", SUPPORTED)
def test_simulated_only_flag_on_every_execution(action, target, _):
    res = _executor().execute(_allow(action, target), _output(action, target))
    payload = res.event.raw_payload
    assert payload["simulated"] is True
    assert payload["action"] == action
    assert payload["tool"] == action
    assert payload["target"] == target
    assert payload["status"] == "ok"
    assert "result" in payload and payload["result"]
    assert "simulated" in res.detail


def test_refusal_of_unsupported_action():
    # isolate_endpoint has no simulated tool in the minimum set.
    res = _executor().execute(_allow("isolate_endpoint", "host-a"), _output("isolate_endpoint", "host-a"))
    assert res.executed is False
    assert res.status == ToolStatus.UNSUPPORTED
    assert res.event is None
    assert "no simulated tool" in res.detail


def test_policy_gate_blocks_before_simulated_execution():
    ex = _executor()
    out = _output("block_ip", "9.9.9.9")

    blocked = ex.execute(
        PolicyDecision(decision=Decision.BLOCK, reason_tags=["hard_constraint_block"], constraint_ids=["SC-002"]),
        out,
    )
    assert blocked.executed is False
    assert blocked.status == ToolStatus.REFUSED_BLOCK
    assert blocked.event is None

    review = ex.execute(
        PolicyDecision(decision=Decision.REVIEW, reason_tags=["threshold_review"], constraint_ids=[]),
        out,
    )
    assert review.executed is False
    assert review.status == ToolStatus.REFUSED_REVIEW
    assert review.event is None


def test_pipeline_blocks_tool_when_policy_gate_blocks():
    llm = FakeLLM(responses=['{"action": "block_ip", "target": "5.5.5.5", "confidence": 0.9}'])
    pipeline = Pipeline(llm=llm)
    # Hostile context (sev 9 + sev 8) → deviation 100 → SC-002 hard BLOCK for block_ip.
    ctx = make_context(
        alert_id="alert-block-tool",
        severity=9,
        source="ids",
        event_type="intrusion",
    )
    ctx.events.append(
        AgentEvent(
            event_id="alert-block-tool-e2",
            timestamp="2026-09-09T00:00:01Z",
            source="siem_sim",
            event_type="anomaly",
            severity=8,
            detail="unusual outbound beacon",
        )
    )
    res = pipeline.run(ctx)
    assert res.decision.decision == Decision.BLOCK
    assert res.tool_result.executed is False
    assert res.tool_result.event is None
    assert res.tool_result.status == ToolStatus.REFUSED_BLOCK


def test_pipeline_holds_tool_under_review():
    llm = FakeLLM(responses=['{"action": "search_ioc", "target": "10.0.0.9", "confidence": 0.7}'])
    pipeline = Pipeline(llm=llm)
    ctx = make_context(alert_id="alert-review-tool", severity=5, source="ids", event_type="alert")
    res = pipeline.run(ctx)
    assert res.decision.decision == Decision.REVIEW
    assert res.tool_result.executed is False
    assert res.tool_result.status == ToolStatus.REFUSED_REVIEW


def test_pipeline_executes_tool_only_when_allowed():
    llm = FakeLLM(responses=['{"action": "get_logs", "confidence": 0.6}'])
    pipeline = Pipeline(llm=llm)
    res = pipeline.run(make_benign_context())
    assert res.decision.decision == Decision.ALLOW
    assert res.tool_result.executed is True
    assert res.tool_result.action == Action.GET_LOGS
    assert res.tool_result.event.raw_payload["simulated"] is True


def test_pipeline_logs_tool_result(tmp_path):
    logger = TrajectoryLogger(path=tmp_path / "traj.jsonl")
    llm = FakeLLM(responses=['{"action": "get_logs", "confidence": 0.6}'])
    pipeline = Pipeline(llm=llm, logger=logger)
    res = pipeline.run(make_benign_context())
    entry = logger.load(res.trajectory.trial_id)
    assert entry.tool_result is not None
    assert entry.tool_result.executed is True
    assert entry.tool_result.event.raw_payload["simulated"] is True