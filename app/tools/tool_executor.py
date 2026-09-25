from __future__ import annotations

import datetime
from typing import Callable

from ..models import (
    Action,
    AgentEvent,
    Decision,
    PolicyDecision,
    SOCOutput,
    ToolResult,
    ToolStatus,
)


class SimulatedToolExecutor:
    """Simulation-only security tool layer.

    Represents what WOULD happen if an allowed action were executed against the
    simulated environment. It MUST NOT and never does touch real infrastructure:
    no real IP blocks/firewalls, no real account changes, no real endpoint
    isolation, no real exploitation. Every executed action is marked simulated.

    The Policy Gate is the authorization boundary. This executor refuses to run
    anything unless the caller passes a PolicyDecision of ALLOW; it is invoked
    by the Pipeline strictly after the gate AND re-checks the decision itself,
    so a mis-wired caller can never bypass the gate.
    """

    _EVENT_SOURCE = "simulated_tools"
    _EVENT_TYPE = "simulated_action"

    # Severity of the resulting AgentEvent, by tool impact (0-10).
    _SEVERITY = {
        Action.GET_LOGS: 1,
        Action.SEARCH_IOC: 1,
        Action.CHECK_ENDPOINT: 2,
        Action.BLOCK_IP: 4,
        Action.DISABLE_USER: 5,
        Action.ISOLATE_ENDPOINT: 5,
    }

    def __init__(self, now: Callable[[], str] | None = None) -> None:
        self._now = now or (
            lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
        self._seq = 0
        self._handlers: dict[Action, Callable[[str | None], ToolResult]] = {
            Action.GET_LOGS: self._get_logs,
            Action.SEARCH_IOC: self._search_ioc,
            Action.CHECK_ENDPOINT: self._check_endpoint,
            Action.BLOCK_IP: self._block_ip,
            Action.DISABLE_USER: self._disable_user,
            # isolate_endpoint is a first-class dangerous action (seeds target
            # it, safety constraints cover it). Leaving it without a handler
            # meant an ALLOWed proposal silently became UNSUPPORTED, so the
            # vocabulary and the executor disagreed about what can happen.
            Action.ISOLATE_ENDPOINT: self._isolate_endpoint,
        }

    def execute(self, decision: PolicyDecision, output: SOCOutput) -> ToolResult:
        if decision.decision != Decision.ALLOW:
            status = (
                ToolStatus.REFUSED_BLOCK
                if decision.decision == Decision.BLOCK
                else ToolStatus.REFUSED_REVIEW
            )
            return ToolResult(
                action=output.action,
                target=output.target,
                executed=False,
                status=status,
                event=None,
                detail=(
                    f"policy gate returned {decision.decision.value}; "
                    "no simulated execution"
                ),
            )

        handler = self._handlers.get(output.action)
        if handler is None:
            action_name = getattr(output.action, "value", output.action)
            return ToolResult(
                action=output.action,
                target=output.target,
                executed=False,
                status=ToolStatus.UNSUPPORTED,
                event=None,
                detail=(
                    f"no simulated tool for action {action_name!r}; "
                    "refusing to execute"
                ),
            )

        return handler(output.target)


    # Simulated tools (all read-only in effect: no real side effects).
    def _get_logs(self, _target: str | None) -> ToolResult:
        return self._exec(
            Action.GET_LOGS,
            None,
            "collected log lines from the simulated environment",
        )

    def _search_ioc(self, target: str | None) -> ToolResult:
        return self._exec(
            Action.SEARCH_IOC,
            target,
            f"IOC {target or '?'} search completed; 0 matches (simulated)",
        )

    def _check_endpoint(self, target: str | None) -> ToolResult:
        return self._exec(
            Action.CHECK_ENDPOINT,
            target,
            f"endpoint {target or '?'} health check completed; no findings (simulated)",
        )

    def _block_ip(self, target: str | None) -> ToolResult:
        return self._exec(
            Action.BLOCK_IP,
            target,
            f"simulated firewall rule applied: DROP all traffic from {target or '?'}",
        )

    def _disable_user(self, target: str | None) -> ToolResult:
        return self._exec(
            Action.DISABLE_USER,
            target,
            f"simulated account {target or '?'} disabled (active sessions revoked)",
        )

    def _isolate_endpoint(self, target: str | None) -> ToolResult:
        return self._exec(
            Action.ISOLATE_ENDPOINT,
            target,
            f"simulated network isolation applied to {target or '?'} "
            "(management plane detached, simulated)",
        )


    def _exec(
        self,
        action: Action,
        target: str | None,
        result: str,
    ) -> ToolResult:
        return ToolResult(
            action=action,
            target=target,
            executed=True,
            status=ToolStatus.OK,
            event=self._event(action, target, result),
            detail=result,
        )

    def _event(self, action: Action, target: str | None, result: str) -> AgentEvent:
        self._seq += 1
        status = "ok"
        return AgentEvent(
            event_id=f"{action.value}-{self._seq}",
            timestamp=self._now(),
            source=self._EVENT_SOURCE,
            event_type=self._EVENT_TYPE,
            severity=self._SEVERITY.get(action, 0),
            detail=f"simulated {action.value} on {target or '(env)'}: {status}",
            raw_payload={
                "action": action.value,
                "tool": action.value,
                "target": target,
                "simulated": True,
                "status": status,
                "result": result,
            },
        )