from __future__ import annotations

import json
import logging

from ..llm.base import LLMProvider, ProviderUnavailable
from ..llm.factory import TRANSIENT_KINDS, fail_provider
from ..llm.parsing import extract_json_object
from ..models import Action, SOCContext, SOCOutput

logger = logging.getLogger("wiener.soc_agent")

_SYSTEM_PROMPT = """You are a SOC analyst AI. You receive alert context and must propose a security
action. You must NOT decide the final ALLOW/REVIEW/BLOCK outcome — that is decided by a separate
deterministic policy layer.

Return ONLY a JSON object with exactly these fields:
{
  "action": "<one of: get_logs, search_ioc, check_endpoint, isolate_endpoint, disable_user, block_ip>",
  "target": "<target identifier>",
  "confidence": <float 0.0-1.0>
}
"""

# Actions that MUST name a specific target to be executable.
_REQUIRES_TARGET = frozenset({
    Action.SEARCH_IOC,
    Action.CHECK_ENDPOINT,
    Action.ISOLATE_ENDPOINT,
    Action.DISABLE_USER,
    Action.BLOCK_IP,
})

# Strict schema (surfaces drift); get_logs may query env-wide (no target).
_ALLOWED_FIELDS = frozenset({"action", "target", "confidence"})


class SOCAgent:
    """Receives SOCContext, reasons about the alert, proposes an action.

    Returns SOCOutput. MUST NOT return the final ALLOW/REVIEW/BLOCK decision.
    """

    def __init__(self, llm: LLMProvider, system_prompt: str | None = None) -> None:
        self._llm = llm
        self._system_prompt = system_prompt or _SYSTEM_PROMPT

    @staticmethod
    def _build_user_prompt(context: SOCContext) -> str:
        lines = [f"Alert: {context.alert_id}", f"Environment: {context.environment}"]
        for ev in context.events:
            lines.append(
                f"- event {ev.event_id} [{ev.source}/{ev.event_type}] "
                f"severity={ev.severity}: {ev.detail}"
            )
        if context.notes:
            lines.append(f"Notes: {context.notes}")
        # Recency bias: restate the hard output constraint at the end.
        lines.append(
            "Output ONLY a single JSON object: "
            '{"action": "<action>", "target": "<target>", "confidence": <0-1>}.'
        )
        return "\n".join(lines)

    @staticmethod
    def _validate_output(data: dict) -> tuple[Action, str | None, float]:
        """Strict validation of the model's JSON object.

        Raises ValueError with a human-readable reason for any deviation:
        unexpected fields, unknown/missing action, missing target when required,
        or confidence outside [0.0, 1.0]. Invalid output must never silently
        become a decision.
        """
        unexpected = set(data) - _ALLOWED_FIELDS
        if unexpected:
            raise ValueError(f"unexpected model fields: {sorted(unexpected)}")

        raw_action = data.get("action")
        normalized_action = raw_action.strip() if isinstance(raw_action, str) else raw_action
        if not isinstance(normalized_action, str) or normalized_action not in Action._value2member_map_:
            raise ValueError(f"unknown or missing action proposed: {raw_action!r}")
        action = Action(normalized_action)

        raw_target = data.get("target")
        target = raw_target.strip() if isinstance(raw_target, str) else raw_target
        if action in _REQUIRES_TARGET and not isinstance(target, str):
            raise ValueError(f"action {action.value} requires a non-empty target")
        if action in _REQUIRES_TARGET and not target:
            raise ValueError(f"action {action.value} requires a non-empty target")

        raw_conf = data.get("confidence")
        if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)):
            raise ValueError(f"confidence must be a number 0.0-1.0, got {raw_conf!r}")
        if not (0.0 <= float(raw_conf) <= 1.0):
            raise ValueError(f"confidence must be in [0.0, 1.0], got {raw_conf!r}")

        return action, target or None, float(raw_conf)

    def _from_llm(self, raw: str) -> SOCOutput:
        data = extract_json_object(raw)
        action, target, confidence = self._validate_output(data)
        return SOCOutput(action=action, target=target, confidence=confidence)

    def analyze(self, context: SOCContext) -> tuple[SOCOutput, str, str]:
        user = self._build_user_prompt(context)
        try:
            resp = self._llm.complete(self._system_prompt, user)
            raw = resp.text
            return self._from_llm(raw), raw, resp.provider
        except (ProviderUnavailable, ValueError, json.JSONDecodeError) as exc:
            # Strict replay refusal fails loud, never degrading into a benign ALLOW.
            if (
                isinstance(exc, ProviderUnavailable)
                and getattr(exc, "kind", "") == "replay_missing"
            ):
                raise
            # Transient tier outage demotes the provider; invalid output is NOT an outage.
            if (
                isinstance(exc, ProviderUnavailable)
                and getattr(exc, "kind", "") in TRANSIENT_KINDS
            ):
                fail_provider(tier=self._llm.name)
            # Degraded path: safe-by-default read-only; invalid output never becomes ALLOW.
            logger.warning(
                "soc_agent: degrading to check_endpoint; provider output invalid/unavailable: %s",
                exc,
            )
            out = SOCOutput(action=Action.CHECK_ENDPOINT, target=context.alert_id, confidence=0.5)
            return out, "", "degraded"
