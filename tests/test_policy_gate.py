from __future__ import annotations

from app.config import config
from app.models import Decision, RiskResult
from app.policy_gate.policy_gate import PolicyGate


def test_no_constraint_low_risk_allow():
    gate = PolicyGate()
    result = RiskResult(risk_score=10, triggered_constraints=[], required_decision=None)
    decision = gate.decide(result)
    assert decision.decision == Decision.ALLOW
    assert decision.reason_tags == ["threshold_allow"]
    assert decision.constraint_ids == []


def test_no_constraint_medium_risk_review():
    gate = PolicyGate()
    result = RiskResult(risk_score=45, triggered_constraints=[], required_decision=None)
    decision = gate.decide(result)
    assert decision.decision == Decision.REVIEW
    assert decision.reason_tags == ["threshold_review"]
    assert decision.constraint_ids == []


def test_no_constraint_high_risk_block():
    gate = PolicyGate()
    result = RiskResult(risk_score=85, triggered_constraints=[], required_decision=None)
    decision = gate.decide(result)
    assert decision.decision == Decision.BLOCK
    assert decision.reason_tags == ["threshold_block"]
    assert decision.constraint_ids == []


def test_review_constraint_lower_score_review():
    gate = PolicyGate()
    # Score 20 would map to ALLOW, but the SC-010 hard constraint forces REVIEW.
    result = RiskResult(
        risk_score=20, triggered_constraints=["SC-010"], required_decision=Decision.REVIEW
    )
    decision = gate.decide(result)
    assert decision.decision == Decision.REVIEW
    assert "hard_constraint_review" in decision.reason_tags
    assert "threshold_allow" not in decision.reason_tags
    assert decision.constraint_ids == ["SC-010"]


def test_block_constraint_medium_score_block():
    gate = PolicyGate()
    # Score 45 would map to REVIEW, but the SC-001 hard constraint forces BLOCK.
    result = RiskResult(
        risk_score=45, triggered_constraints=["SC-001"], required_decision=Decision.BLOCK
    )
    decision = gate.decide(result)
    assert decision.decision == Decision.BLOCK
    assert "hard_constraint_block" in decision.reason_tags
    assert "threshold_review" not in decision.reason_tags
    assert decision.constraint_ids == ["SC-001"]


def test_multiple_constraints_preserved_in_output():
    gate = PolicyGate()
    result = RiskResult(
        risk_score=79,
        triggered_constraints=["SC-001", "SC-010"],
        required_decision=Decision.BLOCK,
    )
    decision = gate.decide(result)
    assert decision.decision == Decision.BLOCK
    assert decision.constraint_ids == ["SC-001", "SC-010"]


def test_precedence_hard_constraint_beats_score():
    # BLOCK > REVIEW > ALLOW: a constraint's required_decision beats the score map even at 95.
    gate = PolicyGate()
    for required, expected_tag in (
        (Decision.ALLOW, "hard_constraint_allow"),
        (Decision.REVIEW, "hard_constraint_review"),
        (Decision.BLOCK, "hard_constraint_block"),
    ):
        result = RiskResult(
            risk_score=95, triggered_constraints=["SC-020"], required_decision=required
        )
        decision = gate.decide(result)
        assert decision.decision == required
        assert expected_tag in decision.reason_tags
        assert not any(t.startswith("threshold_") for t in decision.reason_tags)


def test_threshold_boundaries():
    gate = PolicyGate(allow_threshold=30, review_threshold=60)
    same_decision = lambda score: gate.decide(
        RiskResult(risk_score=score, triggered_constraints=[], required_decision=None)
    ).decision

    # Exactly at the block boundary -> BLOCK (>= review).
    assert same_decision(60.0) == Decision.BLOCK
    # Just below it -> REVIEW.
    assert same_decision(59.99) == Decision.REVIEW
    # Exactly at the review boundary -> REVIEW (>= allow).
    assert same_decision(30.0) == Decision.REVIEW
    # Just below it -> ALLOW.
    assert same_decision(29.99) == Decision.ALLOW


def test_policy_gate_is_deterministic_and_pure():
    gate = PolicyGate()
    result = RiskResult(risk_score=70, triggered_constraints=[], required_decision=None)
    first = gate.decide(result)
    second = gate.decide(result)
    assert first == second
    # Thresholds are loaded from configuration.
    assert gate._allow == config.RISK_ALLOW_THRESHOLD
    assert gate._review == config.RISK_REVIEW_THRESHOLD