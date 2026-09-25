from __future__ import annotations

import os
import re
from pathlib import Path

from ..config import config
from ..models import ExperimentReport


class ReportStoreError(ValueError):
    """Raised when a stored experiment report cannot be read."""


def default_report_root() -> Path:
    """Root dir for persisted reports, overridable via WIENER_EXPERIMENT_STORE."""
    return Path(os.getenv("WIENER_EXPERIMENT_STORE", "") or config.EXPERIMENT_STORE_PATH)


def _safe_id(experiment_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "_", experiment_id)
    return cleaned or "experiment"


class ReportStore:
    """Persists and reloads ExperimentReport JSON onto disk.

    The dashboard is a VIEW of these stored reports; it never runs a
    pipeline or fabricates data.
    """

    def __init__(self, root: str | Path | None = None) -> None:
        self._root = Path(root) if root else Path(default_report_root())

    @property
    def root(self) -> Path:
        return self._root

    def save(self, report: ExperimentReport) -> Path:
        self._root.mkdir(parents=True, exist_ok=True)
        path = self._root / f"{_safe_id(report.experiment_id)}.json"
        path.write_text(report.model_dump_json(), encoding="utf-8")
        return path

    def load_latest(self) -> ExperimentReport | None:
        """Newest .json report (mtime, then name for deterministic ties)."""
        if not self._root.exists():
            return None
        files = sorted(
            self._root.glob("*.json"),
            key=lambda p: (p.stat().st_mtime, p.name),
            reverse=True,
        )
        if not files:
            return None
        return self._load(files[0])

    def load(self, path: str | Path) -> ExperimentReport:
        return self._load(Path(path))

    def _load(self, path: Path) -> ExperimentReport:
        try:
            return ExperimentReport.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - surface as a dashboard error
            raise ReportStoreError(f"stored report unreadable: {path}: {exc}") from exc