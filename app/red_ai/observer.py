from __future__ import annotations

from pydantic import ValidationError

from ..models import RedFeedback


class RedFeedbackError(ValueError):
    """Raised when a defense result cannot be converted to RedFeedback."""


def observe(result: object, iteration: int) -> RedFeedback:
    """Map a defense result (e.g. PipelineResult) to structured RedFeedback.

    Only reads `decision` and `risk` via attribute access, so any object with
    those attributes qualifies. Missing decision/risk or values outside the
    feedback schema raise RedFeedbackError; the loop treats that as a
    malformed-feedback stop, never as a silent all-clear.
    """
    decision = getattr(result, "decision", None)
    risk = getattr(result, "risk", None)
    if decision is None or risk is None:
        raise RedFeedbackError("defense result missing decision/risk")

    try:
        return RedFeedback(
            iteration=iteration,
            decision=getattr(decision, "decision", None),
            risk_score=getattr(risk, "risk_score", None),
            defense_tags=list(getattr(decision, "constraint_ids", None) or []),
            reason_tags=list(getattr(decision, "reason_tags", None) or []),
        )
    except ValidationError as exc:
        raise RedFeedbackError(f"malformed feedback: {exc}") from exc