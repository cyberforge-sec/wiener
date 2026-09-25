from __future__ import annotations

import json
import tempfile
from pathlib import Path

from app.llm.replay_provider import ReplayProvider
from app.logger import TrajectoryLogger
from app.models import BlueAssessment, Decision, PolicyDecision, RiskResult
from app.orchestration.pipeline import Pipeline

from .fixtures import load_trajectory
from .fakes import FakeLLM
from .helpers import make_context


def _logger() -> tuple[TrajectoryLogger, Path]:
    d = tempfile.mkdtemp()
    path = Path(d) / "trajectory.jsonl"
    return TrajectoryLogger(path), path


def test_logger_records_trajectory():
    logger, path = _logger()
    traj = load_trajectory("single_step")
    logger.record(traj, provider="test")

    assert path.exists()
    text = path.read_text()
    # Single store: exactly one JSON line.
    assert len(text.strip().splitlines()) == 1
    # JSON is valid.
    json.loads(text.strip().splitlines()[0])


def test_logger_persists_required_fields():
    logger, _ = _logger()
    traj = load_trajectory("single_step")
    logger.record(traj, provider="opencode", latency_ms=12.5)

    entry = logger.load(traj.trial_id)
    assert entry is not None
    assert entry.trial_id == "fixture-single-step"
    assert entry.provider == "opencode"
    assert entry.latency_ms == 12.5
    assert entry.context_ref == "alert-single-step"
    assert entry.error is None
    # Trajectory + SOCOutput preserved inside the single record.
    assert entry.trajectory == traj
    assert entry.soc_output is not None
    assert entry.soc_output.action == "check_endpoint"


def test_logger_reads_and_deserializes():
    logger, _ = _logger()
    traj = load_trajectory("suspicious_context")
    logger.record(traj, provider="replay")

    records = logger.read()
    assert len(records) == 1
    restored = records[0]
    assert restored.trial_id == traj.trial_id
    assert restored.trajectory.proposed_action.action == "isolate_endpoint"
    assert isinstance(restored.trajectory.context.events[0].severity, int)


def test_logger_upsert_no_duplicate_trajectories():
    logger, path = _logger()
    traj = load_trajectory("single_step")
    logger.record(traj, provider="replay")
    logger.record(traj, provider="replay")

    records = logger.read()
    assert len(records) == 1


def test_logger_multiple_distinct_trials():
    logger, path = _logger()
    logger.record(load_trajectory("single_step"), provider="replay")
    logger.record(load_trajectory("suspicious_context"), provider="replay")

    assert logger.load("fixture-single-step") is not None
    assert logger.load("fixture-suspicious") is not None
    assert len(logger.read()) == 2


def test_logger_append_stage_fields():
    logger, _ = _logger()
    traj = load_trajectory("single_step")
    logger.record(traj, provider="replay")

    logger.append(
        traj.trial_id,
        blue_assessment=BlueAssessment(
            context_trust=60, behavior_deviation=20, action_criticality=20, privilege_impact=10
        ),
        risk=RiskResult(risk_score=40),
        policy_decision=PolicyDecision(decision=Decision.REVIEW),
    )

    entry = logger.load(traj.trial_id)
    assert entry.blue_assessment.context_trust == 60
    assert entry.risk.risk_score == 40
    assert entry.policy_decision.decision == Decision.REVIEW


def test_logger_append_appends_later_stage_slots():
    logger, _ = _logger()
    traj = load_trajectory("single_step")
    logger.record(traj, provider="replay")
    logger.append(traj.trial_id, attack_seed="seed-1", mutation={"who": "attacker"}, iteration=3)

    entry = logger.load(traj.trial_id)
    assert entry.attack_seed == "seed-1"
    assert entry.mutation == {"who": "attacker"}
    assert entry.iteration == 3


def test_logger_append_persists_latency_ms():
    logger, _ = _logger()
    traj = load_trajectory("single_step")
    logger.record(traj, provider="replay")
    logger.append(traj.trial_id, latency_ms=12.345)

    entry = logger.load(traj.trial_id)
    assert entry.latency_ms == 12.345


def test_logger_append_keeps_single_store():
    logger, path = _logger()
    traj = load_trajectory("single_step")
    logger.record(traj, provider="replay")
    logger.append(traj.trial_id, iteration=2)

    # Appending mutates the record in place; it does NOT add a second line.
    assert len(path.read_text().strip().splitlines()) == 1


def test_logger_malformed_line_is_skipped():
    logger, path = _logger()
    traj = load_trajectory("single_step")
    logger.record(traj, provider="replay")
    # Corrupt one line by appending garbage.
    with path.open("a") as fh:
        fh.write("{this is not valid json\n")

    records = logger.read()
    assert logger.malformed_count == 1
    assert len(records) == 1


def test_logger_clear():
    logger, path = _logger()
    logger.record(load_trajectory("single_step"), provider="replay")
    logger.clear()
    assert logger.read() == []
    assert logger.load("fixture-single-step") is None


def test_logger_append_unknown_trial_is_noop():
    logger, path = _logger()
    logger.append("does-not-exist", iteration=1)
    assert logger.read() == []


def test_logger_missing_trajectory_field_is_rejected():
    logger, path = _logger()
    # A line that validates as JSON but is not a TrajectoryLogEntry.
    with path.open("w") as fh:
        fh.write('{"not": "a valid entry"}\n')
    assert logger.read() == []
    assert logger.malformed_count == 1



def test_pipeline_records_and_appends_trajectory():
    logger, _ = _logger()
    llm = FakeLLM(responses=['{"action": "block_ip", "target": "1.2.3.4", "confidence": 0.8}'])
    pipeline = Pipeline(llm=llm, logger=logger)
    ctx = make_context(alert_id="pipeline-1")

    res = pipeline.run(ctx)

    entry = logger.load("pipeline-1")
    assert entry is not None
    assert entry.trajectory.proposed_action.action == "block_ip"
    assert entry.trajectory.context.alert_id == "pipeline-1"
    assert entry.provider == "fake"
    # Later stages appended onto the same record.
    assert entry.risk is not None
    assert entry.policy_decision is not None
    assert entry.blue_assessment is not None
    # decision from the pipeline result matches the logged decision.
    assert entry.policy_decision.decision == res.decision.decision


def test_pipeline_logs_degraded_trajectory():
    from .fakes import FailingLLM

    logger, _ = _logger()
    pipeline = Pipeline(llm=FailingLLM(), logger=logger)
    ctx = make_context(alert_id="degraded-1")

    pipeline.run(ctx)

    entry = logger.load("degraded-1")
    assert entry.trajectory.proposed_action.action == "check_endpoint"
    assert entry.provider == "degraded"


def test_pipeline_works_without_logger():
    # Default: no logger attached; pipeline still completes.
    pipeline = Pipeline(llm=FakeLLM(responses=['{"action": "block_ip", "target": "1.2.3.4", "confidence": 0.8}']))
    res = pipeline.run(make_context())
    assert res.decision.decision in ("ALLOW", "REVIEW", "BLOCK")