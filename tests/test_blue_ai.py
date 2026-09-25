from __future__ import annotations

import json

from app.blue_ai.blue_ai import BlueAI
from app.models import BlueRoute, Trajectory

from .fakes import FakeLLM, FailingLLM
from .helpers import assessment_json, make_benign_context, make_suspicious_context, make_trajectory


def test_deterministic_route_benign():
    ai = BlueAI(FakeLLM())
    traj = make_trajectory(action="check_endpoint", confidence=0.9)
    a = ai.analyze(traj)
    assert a.route == BlueRoute.DETERMINISTIC
    assert a.action_criticality == 20  # intrinsic from metadata
    assert a.privilege_impact == 10
    assert "benign_action" in a.evidence_tags


def test_deterministic_route_critical_action():
    ai = BlueAI(FakeLLM())
    traj = make_trajectory(
        action="isolate_endpoint",
        confidence=0.9,
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.DETERMINISTIC
    assert a.action_criticality == 80
    assert a.privilege_impact == 90
    assert "critical_action" in a.evidence_tags


def test_conflict_triggers_qwen_route():
    # High trust + low deviation context proposing a critical action → conflict.
    ai = BlueAI(FakeLLM(responses=[assessment_json(trust=40, deviation=60)]))
    traj = make_trajectory(
        action="isolate_endpoint",
        confidence=0.9,
        context=make_benign_context(),
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.QWEN
    # Qwen is NOT allowed to rewrite intrinsic action properties.
    assert a.action_criticality == 80
    assert a.privilege_impact == 90
    assert "conflicting_evidence" in a.evidence_tags


def test_malformed_trajectory_uses_fallback_no_qwen():
    ai = BlueAI(FakeLLM())
    # A malformed trajectory: proposed_action unset (model_construct bypasses validation).
    traj = make_trajectory()
    malformed = Trajectory.model_construct(
        trial_id=traj.trial_id,
        context=traj.context,
        agent_history=traj.agent_history,
        proposed_action=None,
    )
    a = ai.analyze(malformed)
    assert a.route == BlueRoute.FALLBACK
    assert "malformed_trajectory" in a.evidence_tags
    # LLM should never be called for a malformed trajectory.
    assert len(ai._llm.calls) == 0


def test_qwen_timeout_falls_back_conservatively():
    ai = BlueAI(FailingLLM())
    traj = make_trajectory(
        action="isolate_endpoint",
        confidence=0.9,
        context=make_benign_context(),
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.FALLBACK
    assert "qwen_unavailable" in a.evidence_tags
    # Conservative bias vs the raw deterministic signal (trust=60, deviation=20 baseline).
    assert a.action_criticality == 80  # intrinsic preserved
    assert a.privilege_impact == 90  # intrinsic preserved
    assert a.behavior_deviation > 20
    assert a.context_trust < 60


def test_no_events_is_fallback():
    ai = BlueAI(FakeLLM())
    traj = make_trajectory(events=[])
    a = ai.analyze(traj)
    assert a.route == BlueRoute.FALLBACK
    # Incomplete trajectory → do not call Qwen.
    assert len(ai._llm.calls) == 0


def test_conflicting_evidence_high_pressure_low_stakes():
    # Low-trust + high-deviation proposing a low-stakes action → material conflict → Qwen.
    ai = BlueAI(FakeLLM(responses=[assessment_json(trust=25, deviation=80)]))
    traj = make_trajectory(
        action="get_logs",
        confidence=0.9,
        context=make_suspicious_context(),
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.QWEN
    assert "conflicting_evidence" in a.evidence_tags
    # Intrinsic values fixed to metadata even though Qwen echoed 1/1.
    assert a.action_criticality == 5
    assert a.privilege_impact == 0


def test_qwen_valid_output_adopted():
    ai = BlueAI(FakeLLM(responses=[assessment_json(trust=20, deviation=75)]))
    traj = make_trajectory(
        action="isolate_endpoint",
        confidence=0.9,
        context=make_benign_context(),
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.QWEN
    assert a.context_trust == 20
    assert a.behavior_deviation == 75
    # Intrinsic values pinned to metadata, never rewritten by Qwen.
    assert a.action_criticality == 80
    assert a.privilege_impact == 90
    # Qwen's validated controlled evidence tag is adopted.
    assert "CONFLICTING_EVIDENCE" in a.evidence_tags
    assert "low_context_trust" in a.evidence_tags
    assert "high_deviation" in a.evidence_tags


def test_qwen_invalid_json_falls_back():
    ai = BlueAI(FakeLLM(responses=["this is not json"]))
    traj = make_trajectory(
        action="isolate_endpoint",
        confidence=0.9,
        context=make_benign_context(),
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.FALLBACK
    assert "qwen_invalid_output" in a.evidence_tags
    assert a.action_criticality == 80
    assert a.privilege_impact == 90


def test_qwen_missing_field_falls_back():
    ai = BlueAI(
        FakeLLM(
            responses=[
                json.dumps(
                    {
                        "context_trust": 40,
                        "behavior_deviation": 60,
                        "action_criticality": 80,
                        "privilege_impact": 90,
                    }
                )
            ]
        )
    )
    traj = make_trajectory(
        action="isolate_endpoint",
        confidence=0.9,
        context=make_benign_context(),
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.FALLBACK
    assert "qwen_invalid_output" in a.evidence_tags


def test_qwen_extra_field_falls_back():
    ai = BlueAI(
        FakeLLM(
            responses=[
                json.dumps(
                    {
                        "context_trust": 40,
                        "behavior_deviation": 60,
                        "action_criticality": 80,
                        "privilege_impact": 90,
                        "evidence_tags": ["CONFLICTING_EVIDENCE"],
                        "note": "not allowed",
                    }
                )
            ]
        )
    )
    traj = make_trajectory(
        action="isolate_endpoint",
        confidence=0.9,
        context=make_benign_context(),
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.FALLBACK
    assert "qwen_invalid_output" in a.evidence_tags


def test_qwen_out_of_range_value_falls_back():
    ai = BlueAI(FakeLLM(responses=[assessment_json(trust=150, deviation=50)]))
    traj = make_trajectory(
        action="isolate_endpoint",
        confidence=0.9,
        context=make_benign_context(),
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.FALLBACK
    assert "qwen_invalid_output" in a.evidence_tags


def test_qwen_disallowed_evidence_tag_falls_back():
    ai = BlueAI(
        FakeLLM(
            responses=[
                assessment_json(trust=40, deviation=60, tags=["EXTREME_RISK"])
            ]
        )
    )
    traj = make_trajectory(
        action="isolate_endpoint",
        confidence=0.9,
        context=make_benign_context(),
    )
    a = ai.analyze(traj)
    assert a.route == BlueRoute.FALLBACK
    assert "qwen_invalid_output" in a.evidence_tags
    # Disallowed tag is never adopted into the assessment.
    assert "EXTREME_RISK" not in a.evidence_tags
