from __future__ import annotations

import threading

from ..llm.base import LLMProvider
from .judge_mode import JudgeRun, run_judge


class JudgeSession:
    """Single interactive demo session.

    Holds only the LAST run plus the request that produced it, so the judge
    controls are minimal: Run / Reset / Replay. Reset fully clears state;
    Replay re-runs the exact same (provider, scenario, slot) request.

    Scenario rotation lives here, not in `run_judge`: every Run advances a
    per-scenario cursor and pins the chosen slot to the committed run, so a
    demo cycle is deterministic (Normal A → B → C → A, attack seeds rotate
    through the catalog) while Replay reproduces the exact same variant.

    A lock guards the shared state: live (SSE) runs commit their result from a
    background thread via `finish`, so concurrent sync reuse is safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: JudgeRun | None = None
        self._last_provider: str | None = None
        self._last_scenario: str | None = None
        self._last_slot: int = 0
        self._cursor: dict[str, int] = {}

    @property
    def last(self) -> JudgeRun | None:
        with self._lock:
            return self._last

    @property
    def last_request(self) -> tuple[str, str] | None:
        with self._lock:
            if self._last_provider is None or self._last_scenario is None:
                return None
            return (self._last_provider, self._last_scenario)

    def next_slot(self, scenario: str) -> int:
        """The next variant slot for `scenario`, then advance the cursor.

        The first run of a fresh session always returns slot 0 (the recorded
        baseline); with the demo cursor still at 0, an all-normal cycle reads
        A → B → C → A.
        """
        with self._lock:
            slot = self._cursor.get(scenario, 0)
            self._cursor[scenario] = slot + 1
            return slot

    def run(self, provider: str, scenario: str, llm: LLMProvider | None = None) -> JudgeRun:
        slot = self.next_slot(scenario)
        run = run_judge(provider, scenario, llm=llm, slot=slot)
        with self._lock:
            self._last = run
            self._last_provider = provider
            self._last_scenario = scenario
            self._last_slot = slot
        return run

    def finish(self, run: JudgeRun, slot: int | None = None) -> None:
        """Commit a run produced off-thread (live SSE path)."""
        with self._lock:
            self._last = run
            self._last_provider = run.requested_provider
            self._last_scenario = run.scenario
            if slot is not None:
                self._last_slot = slot

    def replay(self, llm: LLMProvider | None = None) -> JudgeRun | None:
        """Re-run the last request at its exact slot. None when nothing to replay."""
        req = self.last_request
        if req is None:
            return None
        provider, scenario = req
        run = run_judge(provider, scenario, llm=llm, slot=self._last_slot)
        with self._lock:
            self._last = run
        return run

    def reset(self) -> None:
        with self._lock:
            self._last = None
            self._last_provider = None
            self._last_scenario = None
            self._last_slot = 0
            self._cursor = {}


_session = JudgeSession()


def get_session() -> JudgeSession:
    """Process-wide demo session (matches the single-view main page)."""
    return _session