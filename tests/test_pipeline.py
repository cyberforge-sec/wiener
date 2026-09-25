from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.models import AgentEvent, SOCContext
from app.orchestration.pipeline import Pipeline
from tests.fakes import FakeLLM
from tests.helpers import make_context


def test_pipeline_end_to_end():
    llm = FakeLLM(
        responses=['{"action": "block_ip", "target": "1.2.3.4", "confidence": 0.8}']
    )
    pipeline = Pipeline(llm=llm)
    ctx = make_context(severity=8, source="ids", event_type="intrusion")
    res = pipeline.run(ctx)
    assert res.trajectory.context.alert_id == ctx.alert_id
    assert res.trajectory.proposed_action.action == "block_ip"
    assert res.decision.decision in ("ALLOW", "REVIEW", "BLOCK")
    # Blue AI produced an assessment.
    assert res.assessment.route.value in ("deterministic", "qwen", "fallback")


def test_pipeline_never_fails_open_on_bad_llm():
    pipeline = Pipeline(llm=FakeLLM(fail=True))
    ctx = make_context(severity=5)
    res = pipeline.run(ctx)
    # SOC agent degrades to check_endpoint; decision must still be produced.
    assert res.trajectory.proposed_action.action == "check_endpoint"
    assert res.decision.decision in ("ALLOW", "REVIEW", "BLOCK")


def test_provider_agnostic_callers():
    # Callers above the adapter must not know which provider is used.
    for name, llm in [("replay", _replay_llm()), ("fake", FakeLLM())]:
        pipeline = Pipeline(llm=llm)
        ctx = make_context()
        res = pipeline.run(ctx)
        assert res.decision.decision in ("ALLOW", "REVIEW", "BLOCK")


def _replay_llm():
    from app.llm.replay_provider import ReplayProvider
    import tempfile

    return ReplayProvider(replay_dir=tempfile.mkdtemp())
