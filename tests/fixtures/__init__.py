"""JSON test fixtures for trajectories.

Each fixture is a serialized Trajectory dict, loadable via `load_fixture`.
Malformed fixtures are intentionally NOT valid Trajectory documents and should
fail validation, proving malformed data is handled, never silently a decision.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.models import Trajectory

FIXTURE_DIR = Path(__file__).resolve().parent

FIXTURES = {
    "single_step": "single_step.json",
    "investigation_disable_user": "investigation_disable_user.json",
    "suspicious_context": "suspicious_context.json",
    "conflicting_evidence": "conflicting_evidence.json",
    "malformed": "malformed.json",
}


def fixture_path(name: str) -> Path:
    if name not in FIXTURES:
        raise KeyError(f"unknown fixture: {name!r}")
    return FIXTURE_DIR / FIXTURES[name]


def load_fixture(name: str) -> dict:
    return json.loads(fixture_path(name).read_text(encoding="utf-8"))


def load_trajectory(name: str) -> Trajectory:
    """Load and validate a fixture as a Trajectory.

    Raises pydantic ValidationError for malformed fixtures.
    """
    return Trajectory.model_validate(load_fixture(name))


def load_all() -> dict[str, Trajectory]:
    return {
        name: Trajectory.model_validate(load_fixture(name))
        for name in FIXTURES
        if name != "malformed"
    }