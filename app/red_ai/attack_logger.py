from __future__ import annotations

import json
from pathlib import Path

from ..config import config
from ..models import RedAttack, RedFeedback


class RedAttackLogger:
    """Append-only JSONL store; one line per generated RedAttack.

    The closed loop also writes one RedFeedback line per completed step into a
    sibling feedback log. Malformed lines are skipped, never fatal (consistent
    with TrajectoryLogger).
    """

    def __init__(
        self,
        path: str | Path | None = None,
        feedback_path: str | Path | None = None,
    ) -> None:
        self._path = Path(path) if path else Path(config.RED_AI_LOG_PATH)
        self._feedback_path = (
            Path(feedback_path) if feedback_path else Path(config.RED_FEEDBACK_LOG_PATH)
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._feedback_path.parent.mkdir(parents=True, exist_ok=True)
        self.malformed_count: int = 0

    def log(self, attack: RedAttack) -> None:
        self._path.open("a", encoding="utf-8").write(attack.model_dump_json() + "\n")

    def log_feedback(self, feedback: RedFeedback) -> None:
        self._feedback_path.open("a", encoding="utf-8").write(feedback.model_dump_json() + "\n")

    def read(self) -> list[RedAttack]:
        if not self._path.exists():
            return []
        attacks: list[RedAttack] = []
        self.malformed_count = 0
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                attacks.append(RedAttack.model_validate_json(line))
            except Exception:  # noqa: BLE001 - skip malformed lines, never fatal
                self.malformed_count += 1
        return attacks

    def read_feedback(self) -> list[RedFeedback]:
        if not self._feedback_path.exists():
            return []
        feedbacks: list[RedFeedback] = []
        for line in self._feedback_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                feedbacks.append(RedFeedback.model_validate_json(line))
            except Exception:  # noqa: BLE001 - skip malformed lines, never fatal
                self.malformed_count += 1
        return feedbacks

    def clear(self) -> None:
        if self._path.exists():
            self._path.unlink()
        if self._feedback_path.exists():
            self._feedback_path.unlink()

    def matches(self, seed_id: str, iteration: int) -> RedAttack | None:
        for attack in self.read():
            if attack.seed_id == seed_id and attack.iteration == iteration:
                return attack
        return None

    @property
    def path(self) -> Path:
        return self._path

    @staticmethod
    def from_json(data: str) -> RedAttack:
        return RedAttack.model_validate(json.loads(data))