from __future__ import annotations

from app.models import Action, BlueAssessment, Decision, RiskResult
from app.policy_gate.policy_gate import PolicyGate
from app.risk_engine.risk_engine import RiskEngine


def test_risk_score_high_for_dangerous_assessment():
    engine = RiskEngine()
    a = BlueAssessment(
        context_trust=0,
        behavior_deviation=100,
        action_criticality=100,
        privilege_impact=100,
    )
    result = engine.evaluate(Action.ISOLATE_ENDPOINT, a)
    assert 0.0 <= result.risk_score <= 100.0
    assert result.risk_score > 70


def test_risk_hard_constraint_block():
    engine = RiskEngine()
    # isolate_endpoint with context_trust=0, deviation>=80 → SC-001 BLOCK
    a = BlueAssessment(
        context_trust=0,
        behavior_deviation=90,
        action_criticality=80,
        privilege_impact=90,
    )
    result = engine.evaluate(Action.ISOLATE_ENDPOINT, a)
    assert result.required_decision == Decision.BLOCK
    assert "SC-001" in result.triggered_constraints


def test_risk_hard_constraint_action_mismatch_no_match():
    engine = RiskEngine()
    a = BlueAssessment(
        context_trust=0,
        behavior_deviation=90,
        action_criticality=80,
        privilege_impact=90,
    )
    # SC-001 requires action == isolate_endpoint; block_ip won't match it.
    result = engine.evaluate(Action.BLOCK_IP, a)
    assert "SC-001" not in result.triggered_constraints


def test_required_decision_none_without_hard_match():
    engine = RiskEngine()
    a = BlueAssessment(
        context_trust=90,
        behavior_deviation=10,
        action_criticality=20,
        privilege_impact=10,
    )
    result = engine.evaluate(Action.CHECK_ENDPOINT, a)
    assert result.required_decision is None
    # check_endpoint would match SC-020 (ALLOW) only at trust>=100; here trust=90.
    assert result.triggered_constraints == []


def test_policy_gate_uses_hard_constraint_precedence():
    gate = PolicyGate()
    result = RiskResult(risk_score=10, triggered_constraints=["SC-001"], required_decision=Decision.BLOCK)
    decision = gate.decide(result)
    assert decision.decision == Decision.BLOCK
    assert "hard_constraint_block" in decision.reason_tags
    assert decision.constraint_ids == ["SC-001"]


def test_policy_gate_threshold_fallback():
    gate = PolicyGate(allow_threshold=30, review_threshold=60)
    result = RiskResult(risk_score=85, triggered_constraints=[], required_decision=None)
    decision = gate.decide(result)
    assert decision.decision == Decision.BLOCK
    assert "threshold_block" in decision.reason_tags


def test_policy_gate_allow_low_score():
    gate = PolicyGate(allow_threshold=30, review_threshold=60)
    result = RiskResult(risk_score=10, triggered_constraints=[], required_decision=None)
    assert gate.decide(result).decision == Decision.ALLOW


def test_policy_gate_no_llm():
    # Structural check: gate has no LLM attribute/dependency.
    gate = PolicyGate()
    assert not hasattr(gate, "llm")
    assert not hasattr(gate, "_llm")
