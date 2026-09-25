from __future__ import annotations

from app.config import config
from app.models import Action, BlueAssessment, Decision
from app.risk_engine.risk_engine import RiskEngine, decision_margin


def _expected_risk(
    trust: int, deviation: int, criticality: int, privilege: int
) -> float:
    """Reference risk score via the documented configurable weights."""
    return (
        config.RISK_WEIGHT_TRUST * (100 - trust)
        + config.RISK_WEIGHT_DEVIATION * deviation
        + config.RISK_WEIGHT_CRITICALITY * criticality
        + config.RISK_WEIGHT_PRIVILEGE * privilege
    )


def test_low_risk_case():
    engine = RiskEngine()
    a = BlueAssessment(context_trust=95, behavior_deviation=5, action_criticality=10, privilege_impact=5)
    result = engine.evaluate(Action.CHECK_ENDPOINT, a)
    assert result.risk_score == _expected_risk(95, 5, 10, 5)
    assert result.risk_score < config.RISK_ALLOW_THRESHOLD
    assert result.triggered_constraints == []
    assert result.required_decision is None


def test_medium_risk_case():
    engine = RiskEngine()
    a = BlueAssessment(context_trust=40, behavior_deviation=50, action_criticality=40, privilege_impact=30)
    result = engine.evaluate(Action.BLOCK_IP, a)
    assert result.risk_score == _expected_risk(40, 50, 40, 30)
    assert config.RISK_ALLOW_THRESHOLD <= result.risk_score < config.RISK_REVIEW_THRESHOLD
    assert result.triggered_constraints == []
    assert result.required_decision is None


def test_high_risk_case_score_only_never_decides():
    engine = RiskEngine()
    # High score on an action with no matching constraint must NOT populate required_decision.
    a = BlueAssessment(context_trust=0, behavior_deviation=100, action_criticality=90, privilege_impact=90)
    result = engine.evaluate(Action.CHECK_ENDPOINT, a)
    assert result.risk_score == _expected_risk(0, 100, 90, 90)
    assert result.risk_score > config.RISK_REVIEW_THRESHOLD
    assert result.triggered_constraints == []
    assert result.required_decision is None


def test_no_constraint_matched():
    engine = RiskEngine()
    a = BlueAssessment(context_trust=50, behavior_deviation=20, action_criticality=10, privilege_impact=0)
    result = engine.evaluate(Action.GET_LOGS, a)
    assert result.risk_score == _expected_risk(50, 20, 10, 0)
    assert result.triggered_constraints == []
    assert result.required_decision is None


def test_review_constraint_matched():
    engine = RiskEngine()
    # SC-010 REVIEW: required_decision comes ONLY from the constraint, never the score.
    a = BlueAssessment(context_trust=40, behavior_deviation=50, action_criticality=80, privilege_impact=90)
    result = engine.evaluate(Action.ISOLATE_ENDPOINT, a)
    assert result.risk_score > config.RISK_REVIEW_THRESHOLD
    assert "SC-010" in result.triggered_constraints
    assert result.required_decision == Decision.REVIEW


def test_block_constraint_matched():
    engine = RiskEngine()
    # isolate_endpoint deviation>=80 -> SC-001 BLOCK.
    a = BlueAssessment(context_trust=0, behavior_deviation=90, action_criticality=80, privilege_impact=90)
    result = engine.evaluate(Action.ISOLATE_ENDPOINT, a)
    assert "SC-001" in result.triggered_constraints
    assert result.required_decision == Decision.BLOCK


def test_multiple_constraints_all_recorded():
    engine = RiskEngine()
    # SC-001 BLOCK AND SC-010 REVIEW both match on isolate_endpoint; BLOCK wins.
    a = BlueAssessment(context_trust=40, behavior_deviation=95, action_criticality=80, privilege_impact=90)
    result = engine.evaluate(Action.ISOLATE_ENDPOINT, a)
    assert {"SC-001", "SC-010"} <= set(result.triggered_constraints)
    assert result.required_decision == Decision.BLOCK


def test_conflicting_constraint_decisions_most_restrictive_wins():
    engine = RiskEngine()
    # SC-002 BLOCK AND SC-011 REVIEW both match on block_ip; BLOCK wins.
    a = BlueAssessment(context_trust=20, behavior_deviation=95, action_criticality=80, privilege_impact=90)
    result = engine.evaluate(Action.BLOCK_IP, a)
    assert "SC-002" in result.triggered_constraints
    assert "SC-011" in result.triggered_constraints
    assert result.required_decision == Decision.BLOCK


def test_score_boundary_exact_threshold_values():
    engine = RiskEngine()
    # Exactly 30.0 (allow/review) boundary.
    a30 = BlueAssessment(context_trust=40, behavior_deviation=30, action_criticality=0, privilege_impact=0)
    r30 = engine.evaluate(Action.CHECK_ENDPOINT, a30)
    assert r30.risk_score == 30.0
    assert r30.required_decision is None

    # Exactly 60.0 (review/block) boundary.
    a60 = BlueAssessment(context_trust=0, behavior_deviation=50, action_criticality=50, privilege_impact=0)
    r60 = engine.evaluate(Action.CHECK_ENDPOINT, a60)
    assert r60.risk_score == 60.0
    assert r60.required_decision is None


def test_float_precision_preserved_no_rounding():
    engine = RiskEngine()
    # 0.35*100 + 0.20*1 + 0.15*3 → raw double ≠ round(..., 4): proves no internal rounding.
    a = BlueAssessment(context_trust=0, behavior_deviation=0, action_criticality=1, privilege_impact=3)
    result = engine.evaluate(Action.CHECK_ENDPOINT, a)
    expected = config.RISK_WEIGHT_TRUST * 100 + config.RISK_WEIGHT_CRITICALITY * 1 + config.RISK_WEIGHT_PRIVILEGE * 3
    assert isinstance(result.risk_score, float)
    assert result.risk_score == expected
    assert result.risk_score != round(expected, 4)


def test_decision_margin_distance_to_nearest_boundary():
    # ALLOW region: closest boundary is RISK_ALLOW_THRESHOLD (30).
    assert decision_margin(21.0) == 9.0
    # In the REVIEW band, nearest boundary is whichever threshold is closer.
    assert decision_margin(45.0) == min(45.0 - config.RISK_ALLOW_THRESHOLD, config.RISK_REVIEW_THRESHOLD - 45.0)
    # BLOCK region: closest boundary is RISK_REVIEW_THRESHOLD (60).
    assert decision_margin(80.0) == 20.0
    # Exactly on a boundary: zero margin.
    assert decision_margin(config.RISK_ALLOW_THRESHOLD) == 0.0
    assert decision_margin(config.RISK_REVIEW_THRESHOLD) == 0.0
    # No risk score -> no margin.
    assert decision_margin(None) is None
    # Custom thresholds are honored (never hardcoded).
    assert decision_margin(35.0, allow_threshold=40, review_threshold=80) == 5.0