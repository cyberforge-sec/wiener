"""Deterministic replay package for the defense pipeline.

`run_replay --scenario REPLAY-00X` re-executes a recorded scenario through the
same SOC → Blue AI → risk → policy pipeline with zero live inference, and
validates the expected decision (REPLAY MODE).
"""

from .cli import main as _main
from .cli import run_replay

__all__ = ["main", "run_replay"]

main = _main