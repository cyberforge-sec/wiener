from __future__ import annotations

from pathlib import Path

import yaml

from ..config import config
from ..models import Action, BlueAssessment, Decision, RiskResult


class SafetyConstraint:
    __slots__ = (
        "id",
        "action",
        "context_trust",
        "behavior_deviation",
        "action_criticality",
        "privilege_impact",
        "required_decision",
        "reason_tag",
    )

    def __init__(self, data: dict) -> None:
        self.id = data["id"]
        self.action = data.get("action", "")
        self.context_trust = int(data.get("context_trust", 0))
        self.behavior_deviation = int(data.get("behavior_deviation", 0))
        self.action_criticality = int(data.get("action_criticality", 0))
        self.privilege_impact = int(data.get("privilege_impact", 0))
        self.required_decision = Decision(data["required_decision"])
        self.reason_tag = data.get("reason_tag", self.id)

    def matches(self, action: Action, a: BlueAssessment) -> bool:
        """A constraint matches only when its guard conditions are met.

        A guard value of 0 means "no constraint on this axis" (open), unless
        the constraint explicitly requires it via the threshold comparison.
        """
        if self.action and self.action != action.value:
            return False
        # Constraint fires at ≥ threshold on each non-zero axis.
        if self.context_trust > 0 and a.context_trust < self.context_trust:
            return False
        if self.behavior_deviation > 0 and a.behavior_deviation < self.behavior_deviation:
            return False
        if self.action_criticality > 0 and a.action_criticality < self.action_criticality:
            return False
        if self.privilege_impact > 0 and a.privilege_impact < self.privilege_impact:
            return False
        return True

    def __repr__(self) -> str:
        return f"<SafetyConstraint {self.id} {self.required_decision.value}>"


class SafetyConstraints:
    """Loads safety_constraints.yaml into a list of SafetyConstraint objects."""

    def __init__(self, path: str | None = None) -> None:
        path = path or config.SAFETY_CONSTRAINTS_PATH
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self._constraints = [
            SafetyConstraint(c) for c in data.get("constraints", [])
        ]

    @property
    def constraints(self) -> list[SafetyConstraint]:
        return self._constraints


def decision_margin(
    risk_score: float | None,
    allow_threshold: float | None = None,
    review_threshold: float | None = None,
) -> float | None:
    """Distance from a risk score to the nearest Policy Gate boundary.

    Derived DISPLAY metric only: it is never an input to the Policy Gate
    (the gate decides on the raw risk score against its thresholds). It is
    exposed to the UI so a judge can see how much room a verdict still has
    before it would flip (risk engine runs dynamically; thresholds live in
    config). A score exactly on a boundary yields a margin of zero.
    """
    if risk_score is None:
        return None
    allow = config.RISK_ALLOW_THRESHOLD if allow_threshold is None else allow_threshold
    review = config.RISK_REVIEW_THRESHOLD if review_threshold is None else review_threshold
    return min(abs(risk_score - allow), abs(risk_score - review))


class RiskEngine:
    """Deterministic risk calculation.

    Receives BlueAssessment + applicable safety constraints.
    Computes risk_score, identifies triggered constraints, and sets
    required_decision ONLY from matched hard constraints (BLOCK > REVIEW > ALLOW).
    MUST NOT make the final policy decision.

    The score is a weighted sum on the 0-100 scale; weights are documented in
    config (RISK_WEIGHT_*) and sum to 1.0. The result is never rounded so float
    precision is preserved end to end.
    """

    def __init__(self, constraints: SafetyConstraints | None = None) -> None:
        self._constraints = constraints or SafetyConstraints()

    def evaluate(self, action: Action, assessment: BlueAssessment) -> RiskResult:
        # Trust is inverse-risk; weighted sum direct on 0-100, no double rounding.
        score = (
            config.RISK_WEIGHT_TRUST * (100 - assessment.context_trust)
            + config.RISK_WEIGHT_DEVIATION * assessment.behavior_deviation
            + config.RISK_WEIGHT_CRITICALITY * assessment.action_criticality
            + config.RISK_WEIGHT_PRIVILEGE * assessment.privilege_impact
        )
        score = max(0.0, min(100.0, score))

        triggered: list[str] = []
        required: Decision | None = None
        # Precedence: BLOCK > REVIEW > ALLOW; track the strongest matched.
        _weight = {"BLOCK": 3, "REVIEW": 2, "ALLOW": 1}
        for c in self._constraints.constraints:
            if c.matches(action, assessment):
                triggered.append(c.id)
                if _weight[c.required_decision.value] > _weight.get(required.value if required else "", 0):
                    required = c.required_decision

        return RiskResult(
            risk_score=score,
            triggered_constraints=triggered,
            required_decision=required,
        )
