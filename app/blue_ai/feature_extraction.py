from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from ..models import Action, Trajectory
from .metadata import ActionMetadata

_DEFAULT_CRITICALITY = 30
_DEFAULT_PRIVILEGE = 30

# Escalation actions; tuple preserves Action declaration order.
_ACTION_NAMES: tuple[str, ...] = tuple(a.value for a in Action)


class ContextualEvidence(str, Enum):
    """Controlled evidence tags: the only tags FeatureExtractor emits.

    Every tag traces to a rule, an observed event, known metadata, or known
    trajectory state. Tags are never invented when history is insufficient.
    """

    UNTRUSTED_CONTEXT = "UNTRUSTED_CONTEXT"
    ACTION_ESCALATION = "ACTION_ESCALATION"
    HIGH_PRIVILEGE_ACTION = "HIGH_PRIVILEGE_ACTION"
    BEHAVIOR_SHIFT = "BEHAVIOR_SHIFT"
    MISSING_CONTEXT = "MISSING_CONTEXT"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"


class DeterministicFeatures(BaseModel):
    """Deterministic feature snapshot for a trajectory."""

    action: Action | str | None = None
    action_criticality: int
    privilege_impact: int
    context_trust: int
    behavior_deviation: int
    history_sufficient: bool
    escalation: bool
    evidence_tags: list[str]


class FeatureExtractor:
    """Deterministic feature extraction consumed by Blue AI.

    - Intrinsic action properties come from action_metadata.yaml only; the LLM
      is never asked to redefine them.
    - Dynamic signals (context_trust, behavior_deviation, evidence) are derived
      strictly from observable trajectory state.
    - Behavior deviation accounts for actual agent history (e.g. an escalation
      get_logs → search_ioc → … → disable_user).
    - Insufficient history is marked, never fabricated.
    """

    def __init__(self, metadata: ActionMetadata | None = None) -> None:
        self._meta = metadata or ActionMetadata()


    def extract(self, traj: Trajectory | None) -> DeterministicFeatures:
        if traj is None:
            return self._empty()

        proposed = traj.proposed_action
        raw_action = proposed.action if proposed is not None else None
        action = self._coerce_action(raw_action)
        unknown = raw_action is not None and action is None

        if action is not None:
            criticality = self._meta.action_criticality(action)
            privilege = self._meta.privilege_impact(action)
        else:
            criticality = _DEFAULT_CRITICALITY
            privilege = _DEFAULT_PRIVILEGE

        state_events = traj.agent_history if traj.agent_history else (traj.context.events if traj.context else [])
        trust, deviation = self._derive_state(state_events)

        history = traj.agent_history if traj.agent_history is not None else []
        action_refs = self._action_refs(history)
        escalation, history_sufficient = self._detect_escalation(action_refs)
        if escalation:
            deviation = min(100, deviation + 20)
        shifted = self._detect_behavior_shift(action_refs, criticality)

        tags: list[str] = []
        if not state_events:
            tags.append(ContextualEvidence.MISSING_CONTEXT.value)
        if unknown:
            tags.append(ContextualEvidence.UNKNOWN_ACTION.value)
        if trust < 35:
            tags.append(ContextualEvidence.UNTRUSTED_CONTEXT.value)
        if privilege >= 60:
            tags.append(ContextualEvidence.HIGH_PRIVILEGE_ACTION.value)
        if escalation:
            tags.append(ContextualEvidence.ACTION_ESCALATION.value)
        if shifted:
            tags.append(ContextualEvidence.BEHAVIOR_SHIFT.value)
        if self._is_conflicting(trust, deviation, criticality, privilege):
            tags.append(ContextualEvidence.CONFLICTING_EVIDENCE.value)

        tags = self._dedupe(tags)

        return DeterministicFeatures(
            action=action or raw_action,
            action_criticality=criticality,
            privilege_impact=privilege,
            context_trust=trust,
            behavior_deviation=deviation,
            history_sufficient=history_sufficient,
            escalation=escalation,
            evidence_tags=tags,
        )


    def _derive_state(self, events: list) -> tuple[int, int]:
        trust = 60
        deviation = 20

        # Count each event once: a duplicated alert must not amplify penalties.
        seen_event_ids: set[str] = set()
        for ev in events:
            event_id = getattr(ev, "event_id", None)
            if event_id is not None:
                if event_id in seen_event_ids:
                    continue
                seen_event_ids.add(event_id)

            sev = ev.severity
            src = (ev.source or "").lower()
            etype = (ev.event_type or "").lower()

            if sev >= 7:
                trust -= 25
                deviation += 25
            elif sev >= 4:
                trust -= 10
                deviation += 12

            if "ids" in src or "intrusion" in src:
                trust -= 10
                deviation += 15
            if "anomaly" in etype or "anomal" in etype:
                deviation += 20
                trust -= 5
            if "lockout" in etype or "brute" in etype:
                deviation += 25
                trust -= 15
            if "phish" in etype:
                deviation += 20
                trust -= 10

        return max(0, min(100, trust)), max(0, min(100, deviation))


    def _action_refs(self, history: list) -> list[Action]:
        """Extract actual action references from agent history.

        Only explicit action references count. If none are present we do NOT
        invent a trajectory that did not happen.
        """
        refs: list[Action] = []
        for ev in history:
            text = f"{ev.event_type or ''} {ev.detail or ''}".lower()
            found = next((v for v in _ACTION_NAMES if v in text), None)
            if found is not None:
                refs.append(Action(found))
        return refs

    def _detect_escalation(self, refs: list[Action]) -> tuple[bool, bool]:
        if len(refs) < 2:
            return False, len(refs) >= 2
        crits = [self._meta.action_criticality(a) for a in refs]
        return crits[-1] > crits[0], True

    def _detect_behavior_shift(self, refs: list[Action], proposed_criticality: int) -> bool:
        if not refs:
            return False
        max_history = max(self._meta.action_criticality(a) for a in refs)
        return proposed_criticality >= max_history + 40

    def _is_conflicting(
        self,
        trust: int,
        deviation: int,
        action_criticality: int,
        privilege_impact: int,
    ) -> bool:
        low_pressure = trust >= 60 and deviation < 40
        high_stakes = action_criticality >= 60 or privilege_impact >= 60
        if low_pressure and high_stakes:
            return True

        high_pressure = trust < 40 and deviation >= 55
        low_stakes = action_criticality < 30 and privilege_impact < 30
        if high_pressure and low_stakes:
            return True

        return False


    def _coerce_action(self, raw: object) -> Action | None:
        if isinstance(raw, Action):
            return raw
        if isinstance(raw, str) and raw in _ACTION_NAMES:
            return Action(raw)
        return None

    def _empty(self) -> DeterministicFeatures:
        return DeterministicFeatures(
            action=None,
            action_criticality=_DEFAULT_CRITICALITY,
            privilege_impact=_DEFAULT_PRIVILEGE,
            context_trust=0,
            behavior_deviation=0,
            history_sufficient=False,
            escalation=False,
            evidence_tags=[ContextualEvidence.MISSING_CONTEXT.value],
        )

    @staticmethod
    def _dedupe(tags: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for tag in tags:
            if tag not in seen:
                seen.add(tag)
                out.append(tag)
        return out