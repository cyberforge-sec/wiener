from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ..config import config
from ..models import (
    BlueAssessment,
    PolicyDecision,
    RiskResult,
    SOCOutput,
    ToolResult,
    Trajectory,
)

logger = logging.getLogger("wiener.trajectory_logger")


class TrajectoryLogEntry(BaseModel):
    """One persistent record for a trial.

    Carries the assembled Trajectory exactly once (single store: no duplicate
    trajectory copies). Later pipeline stages append their results onto the same
    record via the optional stage fields.
    """

    version: int = 1
    timestamp: str
    trial_id: str
    provider: str = ""
    context_ref: str = ""
    trajectory: Trajectory | None = None
    latency_ms: float | None = None
    error: str | None = None

    # Stage-append slots filled later by Blue AI / Risk Engine / Policy Gate / harness.
    blue_assessment: BlueAssessment | None = None
    risk: RiskResult | None = None
    policy_decision: PolicyDecision | None = None
    tool_result: ToolResult | None = None
    attack_seed: str | None = None
    mutation: dict[str, Any] | None = None
    iteration: int | None = None

    @property
    def soc_output(self) -> SOCOutput | None:
        return self.trajectory.proposed_action if self.trajectory else None


class TrajectoryLogger:
    """Append-able persistent JSONL store for pipeline trials.

    The trajectory is written once per trial_id; later stages update the record
    in place so a trial never lives in more than one store. Malformed lines are
    skipped, never fatal.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else Path(config.TRAJECTORY_LOG_PATH)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.malformed_count: int = 0

    @staticmethod
    def _now() -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()


    def record(
        self,
        trajectory: Trajectory,
        provider: str = "",
        latency_ms: float | None = None,
        error: str | None = None,
        context_ref: str | None = None,
    ) -> TrajectoryLogEntry:
        entry = TrajectoryLogEntry(
            timestamp=self._now(),
            trial_id=trajectory.trial_id,
            provider=provider,
            context_ref=context_ref if context_ref is not None else self._default_context_ref(trajectory),
            trajectory=trajectory,
            latency_ms=latency_ms,
            error=error,
        )
        records = self.read()
        # Upsert: one record per trial_id, never duplicate the same trajectory.
        records = [r for r in records if r.trial_id != trajectory.trial_id]
        records.append(entry)
        self._write(records)
        return entry

    def append(self, trial_id: str, **stage: Any) -> None:
        """Attach later-stage results (assessment/risk/policy/seed/...) to a record."""
        records = self.read()
        target = next((r for r in records if r.trial_id == trial_id), None)
        if target is None:
            logger.warning("trajectory_logger: append for unknown trial_id=%s", trial_id)
            return
        self._apply_stage(target, **stage)
        self._write(records)


    def read(self) -> list[TrajectoryLogEntry]:
        if not self._path.exists():
            return []
        records: list[TrajectoryLogEntry] = []
        self.malformed_count = 0
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(TrajectoryLogEntry.model_validate_json(line))
            except Exception:  # noqa: BLE001: skip malformed lines, never fatal
                self.malformed_count += 1
        return records

    def load(self, trial_id: str) -> TrajectoryLogEntry | None:
        for r in self.read():
            if r.trial_id == trial_id:
                return r
        return None

    def clear(self) -> None:
        if self._path.exists():
            self._path.unlink()


    def _write(self, records: list[TrajectoryLogEntry]) -> None:
        lines = [r.model_dump_json() for r in records]
        self._path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def _apply_stage(self, entry: TrajectoryLogEntry, **stage: Any) -> None:
        for key, value in stage.items():
            if value is not None and key in {
                "blue_assessment",
                "risk",
                "policy_decision",
                "tool_result",
                "attack_seed",
                "mutation",
                "iteration",
                "latency_ms",
            }:
                setattr(entry, key, value)

    @staticmethod
    def _default_context_ref(trajectory: Trajectory) -> str:
        return trajectory.context.alert_id if trajectory.context else ""