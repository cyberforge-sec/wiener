from __future__ import annotations

from ..config import config
from ..models import Decision, PolicyDecision, RiskResult


class PolicyGate:
    """Deterministic final decision.

    Receives RiskResult and returns the single PolicyDecision.

    CASE 1: hard safety constraints matched (RiskResult.required_decision set):
    emit that decision verbatim. Precedence BLOCK > REVIEW > ALLOW is enforced
    upstream by the RiskEngine, which picks the most restrictive matched
    constraint; the gate never re-derives constraints but preserves their IDs.

    CASE 2: no hard constraint (required_decision is None):
    fall back to configured risk thresholds (0-100 scale):
      LOW    (<  RISK_ALLOW_THRESHOLD)        -> ALLOW
      MEDIUM (>= RISK_ALLOW_THRESHOLD,
              <  RISK_REVIEW_THRESHOLD)       -> REVIEW
      HIGH   (>= RISK_REVIEW_THRESHOLD)       -> BLOCK
    Thresholds are loaded from configuration: never invented here.

    Rules: MUST NOT call any LLM, MUST NOT execute security actions, MUST NOT
    modify external infrastructure. Fully deterministic.
    """

    def __init__(
        self,
        allow_threshold: float | None = None,
        review_threshold: float | None = None,
    ) -> None:
        self._allow = allow_threshold if allow_threshold is not None else config.RISK_ALLOW_THRESHOLD
        self._review = review_threshold if review_threshold is not None else config.RISK_REVIEW_THRESHOLD

    def decide(self, result: RiskResult) -> PolicyDecision:
        reason_tags: list[str] = []
        constraint_ids: list[str] = list(result.triggered_constraints)

        # 1. Hard-constraint precedence (BLOCK > REVIEW > ALLOW).
        if result.required_decision is not None:
            if result.required_decision == Decision.BLOCK:
                reason_tags.append("hard_constraint_block")
            elif result.required_decision == Decision.REVIEW:
                reason_tags.append("hard_constraint_review")
            else:
                reason_tags.append("hard_constraint_allow")
            return PolicyDecision(
                decision=result.required_decision,
                reason_tags=reason_tags,
                constraint_ids=constraint_ids,
            )

        # 2. Fall back to configured thresholds.
        score = result.risk_score
        if score >= self._review:
            reason_tags.append("threshold_block")
            return PolicyDecision(
                decision=Decision.BLOCK,
                reason_tags=reason_tags,
                constraint_ids=constraint_ids,
            )
        if score >= self._allow:
            reason_tags.append("threshold_review")
            return PolicyDecision(
                decision=Decision.REVIEW,
                reason_tags=reason_tags,
                constraint_ids=constraint_ids,
            )
        reason_tags.append("threshold_allow")
        return PolicyDecision(
            decision=Decision.ALLOW,
            reason_tags=reason_tags,
            constraint_ids=constraint_ids,
        )
