from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.config import config
from app.llm.replay_provider import ReplayProvider
from app.models import (
    AgentEvent,
    Decision,
    MutationKind,
    RedFeedback,
    SOCContext,
    StopReason,
)
from app.orchestration.pipeline import Pipeline
from app.red_ai import (
    DEFAULT_MAX_ITERATIONS,
    DEFAULT_RNG_SEED,
    RedAttackLogger,
    RedFeedbackError,
    RedLoop,
    SeedLoader,
    adaptive_pool,
    observe,
    render_attack,
)
from app.red_ai.mutator import MUTATION_ORDER, baseline, mutate_adaptive
from tests.fakes import FakeLLM

_TS = "2026-01-01T00:00:00Z"


def _expected_risk(trust: int, deviation: int, crit: int, priv: int) -> float:
    return (
        config.RISK_WEIGHT_TRUST * (100 - trust)
        + config.RISK_WEIGHT_DEVIATION * deviation
        + config.RISK_WEIGHT_CRITICALITY * crit
        + config.RISK_WEIGHT_PRIVILEGE * priv
    )


def _pipeline_defense(responses: list[str] | None = None, replay_dir=None):
    if replay_dir is not None:
        return Pipeline(llm=ReplayProvider(replay_dir=replay_dir)).run
    return Pipeline(llm=FakeLLM(responses)).run


def _block_ip_responses(n: int) -> list[str]:
    return ['{"action": "block_ip", "target": "1.2.3.4", "confidence": 0.9}'] * n


def _benign_render(attack) -> SOCContext:
    """Low-severity context so the gate can ALLOW (used for success-stop)."""
    return SOCContext(
        alert_id=f"red-{attack.seed_id}-b{attack.iteration}",
        provenance="red_ai_test",
        events=[
            AgentEvent(
                event_id=f"b{attack.seed_id}-{attack.iteration}-e1",
                timestamp=_TS,
                source="user_report",
                event_type="log",
                severity=0,
                detail=attack.payload,
            )
        ],
    )


def _loop(defense, **kw):
    return RedLoop(
        defense=defense,
        attack_logger=RedAttackLogger(),
        **kw,
    )



def test_observe_maps_pipeline_result():
    seed = SeedLoader().get("RS-001")
    ctx = render_attack(baseline(seed))
    result = _pipeline_defense(_block_ip_responses(1))(ctx)
    fb = observe(result, iteration=0)
    assert fb.iteration == 0
    assert fb.decision == Decision.REVIEW
    assert fb.risk_score == _expected_risk(35, 45, 60, 40)
    assert fb.reason_tags == ["threshold_review"]
    assert fb.defense_tags == []


def test_observe_accepts_string_decision():
    decision = SimpleNamespace(decision="BLOCK", constraint_ids=["SC-002"], reason_tags=["hard_constraint_block"])
    risk = SimpleNamespace(risk_score=95.0)
    fb = observe(SimpleNamespace(decision=decision, risk=risk), iteration=1)
    assert fb.decision == Decision.BLOCK
    assert fb.defense_tags == ["SC-002"]


def test_observe_missing_decision_raises():
    with pytest.raises(RedFeedbackError, match="missing decision/risk"):
        observe(object(), iteration=0)


def test_observe_missing_risk_raises():
    decision = SimpleNamespace(decision=Decision.ALLOW, constraint_ids=[], reason_tags=[])
    with pytest.raises(RedFeedbackError, match="missing decision/risk"):
        observe(SimpleNamespace(decision=decision, risk=None), iteration=0)


def test_observe_invalid_decision_raises():
    decision = SimpleNamespace(decision="GARBAGE", constraint_ids=[], reason_tags=[])
    risk = SimpleNamespace(risk_score=42.0)
    with pytest.raises(RedFeedbackError, match="malformed feedback"):
        observe(SimpleNamespace(decision=decision, risk=risk), iteration=0)


def test_observe_out_of_range_risk_raises():
    decision = SimpleNamespace(decision=Decision.ALLOW, constraint_ids=[], reason_tags=[])
    risk = SimpleNamespace(risk_score=101.0)
    with pytest.raises(RedFeedbackError, match="malformed feedback"):
        observe(SimpleNamespace(decision=decision, risk=risk), iteration=0)



def test_adaptive_pool_maps_feedback_signal():
    block_fb = RedFeedback(iteration=1, decision=Decision.BLOCK, risk_score=94.5, defense_tags=["SC-002"])
    assert adaptive_pool(block_fb) == (MutationKind.FRAME_SHIFT, MutationKind.SYNONYM_SWAP)

    review_fb = RedFeedback(iteration=1, decision=Decision.REVIEW, risk_score=54.25)
    pool = adaptive_pool(review_fb)
    assert set(pool) == {"structure_reorder", "urgency_boost", "frame_shift"}

    allow_fb = RedFeedback(iteration=1, decision=Decision.ALLOW, risk_score=21.0)
    assert adaptive_pool(allow_fb) == (MutationKind.URGENCY_BOOST, MutationKind.STRUCTURE_REORDER)

    assert adaptive_pool(None) == MUTATION_ORDER


def test_mutate_adaptive_picks_only_from_feedback_pool():
    seed = SeedLoader().get("RS-001")
    for decision in (Decision.BLOCK, Decision.REVIEW, Decision.ALLOW):
        fb = RedFeedback(iteration=1, decision=decision, risk_score=50.0)
        atk = mutate_adaptive(seed, 1, fb, rng_seed=1)
        assert atk.mutation.kind in adaptive_pool(fb)
        assert atk.iteration == 1
        assert atk.payload != seed.payload


def test_mutate_adaptive_reproducible_with_same_feedback():
    seed = SeedLoader().get("RS-001")
    fb = RedFeedback(iteration=1, decision=Decision.BLOCK, risk_score=95.0)
    a1 = mutate_adaptive(seed, 2, fb, rng_seed=77)
    a2 = mutate_adaptive(seed, 2, fb, rng_seed=77)
    assert a1 == a2
    assert a1.mutation.note == a2.mutation.note


def test_mutate_adaptive_rejects_iteration_zero():
    seed = SeedLoader().get("RS-001")
    fb = RedFeedback(iteration=0, decision=Decision.BLOCK, risk_score=95.0)
    with pytest.raises(ValueError):
        mutate_adaptive(seed, 0, fb, rng_seed=1)


def test_mutate_adaptive_compounds_from_previous_attack():
    seed = SeedLoader().get("RS-001")
    fb = RedFeedback(iteration=1, decision=Decision.REVIEW, risk_score=54.25)
    a1 = mutate_adaptive(seed, 1, fb, rng_seed=77)
    a2 = mutate_adaptive(seed, 2, fb, rng_seed=77, base=a1)
    a2_flat = mutate_adaptive(seed, 2, fb, rng_seed=77)  # from seed (one-shot call)
    assert a2.payload != a1.payload
    assert a2.payload != a2_flat.payload  # compounding ≠ rebuilding from the seed
    assert a2.iteration == 2 and a2.seed_id == "RS-001"
    # Deterministic for identical (seed, rng_seed, feedback, base).
    assert mutate_adaptive(seed, 2, fb, rng_seed=77, base=a1) == a2
    # base=baseline reproduces the one-shot mutation1 exactly.
    a1_base = mutate_adaptive(seed, 1, fb, rng_seed=77, base=baseline(seed))
    assert a1_base.payload == a1.payload


def test_loop_compounds_each_mutation_on_previous_attack(tmp_path):
    logger = RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl")
    loop = RedLoop(_pipeline_defense(_block_ip_responses(DEFAULT_MAX_ITERATIONS)), attack_logger=logger)
    report = loop.run("RS-001")
    seed = SeedLoader().get("RS-001")
    s0, s1, s2 = report.steps
    # Step 2 descends from step 1's rendered attack, not from the seed payload.
    expected2 = mutate_adaptive(seed, 2, s1.feedback, DEFAULT_RNG_SEED, base=s1.attack)
    assert s2.attack.payload == expected2.payload
    flat2 = mutate_adaptive(seed, 2, s1.feedback, DEFAULT_RNG_SEED)
    assert s2.attack.payload != flat2.payload
    assert s2.attack.mutation.kind in adaptive_pool(s1.feedback)


def test_redloop_rejects_zero_max_iterations():
    with pytest.raises(ValueError):
        RedLoop(defense=lambda ctx: None, max_iterations=0)



def test_loop_attack1_is_baseline(tmp_path):
    logger = RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl")
    loop = RedLoop(_pipeline_defense(_block_ip_responses(DEFAULT_MAX_ITERATIONS)), attack_logger=logger)
    report = loop.run("RS-001")
    step0 = report.steps[0]
    assert step0.feedback.decision == Decision.REVIEW
    assert step0.attack.iteration == 0
    assert step0.attack.payload == SeedLoader().get("RS-001").payload
    assert step0.attack.mutation is None


def test_loop_mutates_to_attack2_influenced_by_feedback(tmp_path):
    logger = RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl")
    loop = RedLoop(_pipeline_defense(_block_ip_responses(DEFAULT_MAX_ITERATIONS)), attack_logger=logger)
    report = loop.run("RS-001")
    s0, s1 = report.steps[0], report.steps[1]
    assert s0.feedback.decision == Decision.REVIEW
    assert s1.attack.iteration == 1
    assert s1.attack.payload != s0.attack.payload
    assert s1.attack.mutation.kind in adaptive_pool(s0.feedback)


def test_loop_max_iterations_stops(tmp_path):
    logger = RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl")
    loop = RedLoop(
        _pipeline_defense(_block_ip_responses(DEFAULT_MAX_ITERATIONS)),
        attack_logger=logger,
        max_iterations=DEFAULT_MAX_ITERATIONS,
    )
    report = loop.run("RS-001")
    assert report.stopped_reason == StopReason.MAX_ITERATIONS
    assert report.iterations == DEFAULT_MAX_ITERATIONS
    assert [s.attack.iteration for s in report.steps] == [0, 1, 2]


def test_loop_attack_succeeded_stops_early(tmp_path):
    logger = RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl")
    loop = RedLoop(
        _pipeline_defense(['{"action": "get_logs", "confidence": 0.6}']),
        attack_logger=logger,
        render=_benign_render,
    )
    report = loop.run("RS-001")
    assert report.stopped_reason == StopReason.ATTACK_SUCCEEDED
    assert report.iterations == 1
    assert report.steps[0].feedback.decision == Decision.ALLOW


def test_loop_provider_failure_stops_cleanly(tmp_path):
    def broken_defense(ctx):
        raise RuntimeError("provider down")

    logger = RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl")
    loop = RedLoop(broken_defense, attack_logger=logger)
    report = loop.run("RS-001")
    assert report.stopped_reason == StopReason.PROVIDER_FAILURE
    assert report.iterations == 0
    assert "RuntimeError" in (report.error or "")
    assert [a.iteration for a in logger.read()] == [0]  # failed attack still logged


def test_loop_malformed_feedback_stops_cleanly(tmp_path):
    logger = RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl")
    loop = RedLoop(lambda ctx: object(), attack_logger=logger)
    report = loop.run("RS-001")
    assert report.stopped_reason == StopReason.MALFORMED_FEEDBACK
    assert report.iterations == 0
    assert "missing decision/risk" in (report.error or "")
    assert logger.read_feedback() == []


def test_loop_unknown_seed_raises(tmp_path):
    loop = RedLoop(lambda ctx: None, attack_logger=RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl"))
    with pytest.raises(ValueError, match="unknown seed_id"):
        loop.run("RS-999")


def test_loop_logs_every_attack_and_feedback(tmp_path):
    logger = RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl")
    loop = RedLoop(_pipeline_defense(_block_ip_responses(DEFAULT_MAX_ITERATIONS)), attack_logger=logger)
    report = loop.run("RS-001")
    assert [a.iteration for a in logger.read()] == [0, 1, 2]
    assert [f.iteration for f in logger.read_feedback()] == [0, 1, 2]



def test_loop_reproducible_with_scripted_llm(tmp_path):
    def make_defense():
        return _pipeline_defense(_block_ip_responses(DEFAULT_MAX_ITERATIONS))

    r1 = RedLoop(make_defense(), attack_logger=RedAttackLogger(tmp_path / "a.jsonl", tmp_path / "fb.jsonl")).run("RS-001")
    r2 = RedLoop(make_defense(), attack_logger=RedAttackLogger(tmp_path / "b.jsonl", tmp_path / "fb2.jsonl")).run("RS-001")
    assert r1.model_dump_json() == r2.model_dump_json()
    assert [s.attack.payload for s in r1.steps] == [s.attack.payload for s in r2.steps]


def test_loop_deterministic_with_replay_provider(tmp_path):
    def make_defense():
        return _pipeline_defense(replay_dir=tmp_path / "replays")

    def make_loop():
        return RedLoop(make_defense(), attack_logger=RedAttackLogger(tmp_path / "x.jsonl", tmp_path / "y.jsonl"))

    report_a = make_loop().run("RS-001")
    report_b = make_loop().run("RS-001")
    assert report_a.model_dump_json() == report_b.model_dump_json()
    assert report_a.stopped_reason == StopReason.MAX_ITERATIONS


def test_render_attack_is_deterministic():
    seed = SeedLoader().get("RS-001")
    ctx = render_attack(baseline(seed))
    assert ctx.alert_id == "red-RS-001-it0"
    assert ctx.events[0].severity == 8
    assert ctx.events[0].detail == seed.payload
    ctx2 = render_attack(baseline(seed))
    assert ctx.model_dump_json() == ctx2.model_dump_json()