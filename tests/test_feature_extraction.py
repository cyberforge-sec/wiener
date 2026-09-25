from __future__ import annotations

import pytest

from app.blue_ai.feature_extraction import ContextualEvidence, FeatureExtractor
from app.models import BlueRoute, SOCContext, SOCOutput, Trajectory

from .fakes import FakeLLM
from .fixtures import load_trajectory
from .helpers import make_trajectory

# Intrinsic properties from config/action_metadata.yaml (source of truth).
EXPECTED_INTRINSIC = {
    "get_logs": (5, 0),
    "search_ioc": (10, 0),
    "check_endpoint": (20, 10),
    "isolate_endpoint": (80, 90),
    "disable_user": (70, 80),
    "block_ip": (60, 40),
}


@pytest.mark.parametrize(
    "action,criticality,privilege",
    [(a, c, p) for a, (c, p) in EXPECTED_INTRINSIC.items()],
    ids=list(EXPECTED_INTRINSIC),
)
def test_known_action_intrinsic_metadata(action, criticality, privilege):
    fe = FeatureExtractor()
    out = fe.extract(make_trajectory(action=action, confidence=0.9))
    assert out.action_criticality == criticality
    assert out.privilege_impact == privilege
    assert fe._meta.action_criticality(action) == criticality
    assert fe._meta.privilege_impact(action) == privilege


def test_benign_action_emits_no_controlled_tags():
    # Default context (sev 5, ids) + get_logs: low stakes, no suspicious signals.
    out = FeatureExtractor().extract(make_trajectory(action="get_logs", confidence=0.9))
    assert out.action == "get_logs"
    assert out.action_criticality == 5
    assert out.history_sufficient is False
    assert out.escalation is False
    assert out.evidence_tags == []


def test_normal_trajectory():
    out = FeatureExtractor().extract(load_trajectory("single_step"))
    assert out.action == "check_endpoint"
    assert out.action_criticality == 20
    assert out.privilege_impact == 10
    assert out.escalation is False
    assert ContextualEvidence.MISSING_CONTEXT.value not in out.evidence_tags


def test_behavior_shift_escalation():
    # get_logs → search_ioc → … → disable_user: escalation over the actual history.
    out = FeatureExtractor().extract(load_trajectory("investigation_disable_user"))
    assert out.history_sufficient is True
    assert out.escalation is True
    assert ContextualEvidence.ACTION_ESCALATION.value in out.evidence_tags
    assert ContextualEvidence.BEHAVIOR_SHIFT.value in out.evidence_tags
    assert ContextualEvidence.HIGH_PRIVILEGE_ACTION.value in out.evidence_tags


def test_missing_history_marks_insufficient():
    # Agent history absent -> never fabricate a trajectory; signal insufficiency.
    traj = make_trajectory(events=[])
    out = FeatureExtractor().extract(traj)
    assert out.history_sufficient is False
    assert out.escalation is False
    assert ContextualEvidence.ACTION_ESCALATION.value not in out.evidence_tags
    assert ContextualEvidence.BEHAVIOR_SHIFT.value not in out.evidence_tags


def test_suspicious_context_untrusted():
    out = FeatureExtractor().extract(load_trajectory("suspicious_context"))
    assert out.context_trust < 35
    assert out.behavior_deviation >= 55
    assert ContextualEvidence.UNTRUSTED_CONTEXT.value in out.evidence_tags
    assert ContextualEvidence.HIGH_PRIVILEGE_ACTION.value in out.evidence_tags


def test_conflicting_context():
    out = FeatureExtractor().extract(load_trajectory("conflicting_evidence"))
    assert ContextualEvidence.CONFLICTING_EVIDENCE.value in out.evidence_tags
    assert out.action_criticality == 80  # intrinsic untouched
    assert out.privilege_impact == 90


def test_no_events_emits_missing_context():
    traj = make_trajectory(
        context=SOCContext(alert_id="alert-empty", events=[]),
        events=[],
    )
    out = FeatureExtractor().extract(traj)
    assert ContextualEvidence.MISSING_CONTEXT.value in out.evidence_tags


def test_unknown_action_defaults_and_tag():
    traj = make_trajectory()
    unknown = Trajectory.model_construct(
        trial_id=traj.trial_id,
        context=traj.context,
        agent_history=traj.agent_history,
        proposed_action=SOCOutput.model_construct(action="purge_all", target="tgt", confidence=0.9),
    )
    out = FeatureExtractor().extract(unknown)
    assert out.action == "purge_all"  # preserved verbatim, never coerced
    assert out.action_criticality == 30  # default, mirrors metadata fallback
    assert out.privilege_impact == 30
    assert ContextualEvidence.UNKNOWN_ACTION.value in out.evidence_tags


def test_none_trajectory_tolerant():
    out = FeatureExtractor().extract(None)
    assert out.action is None
    assert out.action_criticality == 30
    assert out.privilege_impact == 30
    assert out.history_sufficient is False
    assert ContextualEvidence.MISSING_CONTEXT.value in out.evidence_tags


def test_missing_proposed_action_tolerant():
    traj = make_trajectory()
    malformed = Trajectory.model_construct(
        trial_id=traj.trial_id,
        context=traj.context,
        agent_history=traj.agent_history,
        proposed_action=None,
    )
    out = FeatureExtractor().extract(malformed)
    assert out.action is None
    assert out.action_criticality == 30
    assert out.privilege_impact == 30
    # Unset proposed action is absent, not "unknown": tolerant, never invented.
    assert ContextualEvidence.UNKNOWN_ACTION.value not in out.evidence_tags


def test_blue_ai_wiring_emits_controlled_tags():
    from app.blue_ai.blue_ai import BlueAI

    ai = BlueAI(FakeLLM())
    a = ai.analyze(load_trajectory("suspicious_context"))
    assert a.route == BlueRoute.DETERMINISTIC
    assert ContextualEvidence.UNTRUSTED_CONTEXT.value in a.evidence_tags
    assert ContextualEvidence.HIGH_PRIVILEGE_ACTION.value in a.evidence_tags
    # Intrinsic values survive the full BlueAI path.
    assert a.action_criticality == 80
    assert a.privilege_impact == 90