from __future__ import annotations

import json
import queue
import threading
import time
from typing import Iterator

from ..llm.base import LLMProvider
from .judge_mode import (
    LIVE_STAGE_ORDER,
    live_display,
    live_tier,
    reserve_run_id,
    run_judge,
    validate,
)
from .render import render_main_view, run_to_meta
from .session import get_session

# Real pipeline stage order, so the SSE consumer never has to infer it.
STAGE_ORDER = LIVE_STAGE_ORDER

_TERMINAL = frozenset({"run_completed", "run_failed"})

# Per-consumer SSE backlog. Bounded so an abandoned/slow HTTP client cannot
# grow process memory; the full history stays in ``_LiveRun.log``.
_CONSUMER_QUEUE_MAXSIZE = 512


class _LiveRun:
    """One live run's broadcast state.

    ``log`` is the complete ordered event history (replayed to every new
    consumer so reconnects / multiple viewers never miss a stage), and ``subs``
    holds a per-consumer queue, so events are broadcast, never consumed
    destructively like a single-reader channel.
    """

    def __init__(self, run_id: int) -> None:
        self.run_id = run_id
        self.log: list[dict] = []
        self.subs: set[queue.Queue] = set()
        self.lock = threading.Lock()
        self.done = False
        self.consumers = 0


class LiveRunStore:
    """Registry for live (SSE-streamed) judge runs.

    ``start`` validates and reserves a run id, then executes the REAL judge
    run in a background thread. Every stage is appended to the run's history
    and broadcast to each connected consumer; a terminal
    ``run_completed``/``run_failed`` event ends the stream.
    """

    def __init__(self) -> None:
        self._runs: dict[int, _LiveRun] = {}
        self._lock = threading.Lock()

    def start(
        self,
        provider: str,
        scenario: str,
        llm: LLMProvider | None = None,
        slot: int | None = None,
    ) -> int:
        validate(provider, scenario)  # JudgeInputError → HTTP 400 before any thread
        run_id = reserve_run_id()
        run = _LiveRun(run_id)
        with self._lock:
            self._runs[run_id] = run
        t0 = time.monotonic()

        def emit(stage: str, phase: str, data: dict) -> None:
            payload: dict = {
                "event": f"{stage}_{phase}",
                "run_id": run_id,
                "stage": stage,
                "phase": phase,
                "status": "running" if phase == "started" else "done",
                "ts": time.time(),  # real event-emission wall-clock (activity trail)
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
                "data": data,
                "display": live_display(
                    stage, dict(data), status="running" if phase == "started" else "done"
                ),
            }
            if stage == "soc_agent":
                payload["tier"] = live_tier(str(data.get("provider") or ""), provider)
            self._broadcast(run, payload)

        def work() -> None:
            run_instance = None
            self._broadcast(run, self._run_started_payload(run_id, provider, scenario))
            try:
                run_instance = run_judge(
                    provider,
                    scenario,
                    llm=llm,
                    listener=emit,
                    run_id=run_id,
                    slot=slot,
                )
            except Exception as exc:  # noqa: BLE001 - never leave the stream hanging
                payload = {
                    "event": "run_failed",
                    "run_id": run_id,
                    "ts": time.time(),
                    "error": f"{type(exc).__name__}: {exc}",
                    "html": "",
                    "meta": {
                        "run_id": run_id,
                        "requested_provider": provider,
                        "provider_used": "",
                        "provider_tier": "live",
                        "replay_mode": False,
                        "scenario": scenario,
                        "decision": None,
                        "decision_label": "NO DECISION",
                        "proposed_action": None,
                        "error": str(exc),
                    },
                }
                self._broadcast(run, payload)
                with run.lock:
                    run.done = True
                return
            get_session().finish(run_instance, slot=slot)
            terminal = (
                "run_completed"
                if (run_instance.error is None and run_instance.result is not None)
                else "run_failed"
            )
            payload = {
                "event": terminal,
                "run_id": run_id,
                "ts": time.time(),
                "html": render_main_view(run_instance),
                "meta": run_to_meta(run_instance),
            }
            if terminal == "run_failed":
                payload["error"] = run_instance.error or "run failed without a pipeline result"
            self._broadcast(run, payload)
            with run.lock:
                run.done = True
            # Not purged here: dropped once the last viewer detaches.

        threading.Thread(target=work, name=f"wiener-live-{run_id}", daemon=True).start()
        return run_id

    def _broadcast(self, run: _LiveRun, payload: dict) -> None:
        terminal = payload.get("event") in _TERMINAL
        with run.lock:
            run.log.append(payload)
            subs = list(run.subs)
        for subscriber in subs:
            if terminal:
                # A terminal event is the only thing a client cannot recover
                # from the run log, so it is never dropped. Make room by
                # discarding the oldest intermediate event if the queue is full.
                while True:
                    try:
                        subscriber.put_nowait(payload)
                        break
                    except queue.Full:
                        try:
                            subscriber.get_nowait()
                        except queue.Empty:  # pragma: no cover - racy drain
                            continue
            else:
                try:
                    subscriber.put_nowait(payload)
                except queue.Full:
                    pass  # slow consumer: skip intermediates, terminal still queued

    def _run_started_payload(self, run_id: int, provider: str, scenario: str) -> dict:
        return {
            "event": "run_started",
            "run_id": run_id,
            "ts": time.time(),
            "status": "running",
            "stages": list(STAGE_ORDER),
            "requested_provider": provider,
            "scenario": scenario,
        }

    def _drop_if_idle(self, run: _LiveRun) -> None:
        """Remove a finished run once every attached consumer has detached."""
        with run.lock:
            if not run.done or run.consumers > 0:
                return
        with self._lock:
            if self._runs.get(run.run_id) is run:
                self._runs.pop(run.run_id, None)

    def has(self, run_id: int) -> bool:
        with self._lock:
            return run_id in self._runs

    def get_run(self, run_id: int) -> _LiveRun:
        """Snapshot the live run object (the stream then reads it by reference,
        so an in-flight consumer never breaks when an idle run is dropped)."""
        with self._lock:
            run = self._runs.get(run_id)
        if run is None:
            raise KeyError(run_id)
        return run

    def iter_run(self, run: _LiveRun) -> Iterator[dict]:
        """Walk one run's stream via its queue; refcounted so the entry is only
        dropped once ALL consumers have detached (broadcast, not single-reader)."""
        # Bounded queue: a consumer that stops reading cannot grow server
        # memory. A full queue drops intermediate events; the terminal event is
        # always delivered.
        own = queue.Queue(maxsize=_CONSUMER_QUEUE_MAXSIZE)
        with run.lock:
            # Reconnect-safe: keep the most recent window, since a late client
            # wants current state. The full log stays in ``run.log``.
            history = run.log[-_CONSUMER_QUEUE_MAXSIZE:]
            for event in history:
                own.put_nowait(event)
            if not run.done:
                run.subs.add(own)
            run.consumers += 1
        try:
            while True:
                try:
                    item = own.get(timeout=15)
                except queue.Empty:
                    with run.lock:
                        should_stop = run.done
                    yield {"event": "__keepalive__"}
                    if should_stop:
                        return
                    continue
                yield item
                if item.get("event") in _TERMINAL:
                    return
        finally:
            with run.lock:
                run.consumers -= 1
            self._drop_if_idle(run)

    def iter_events(self, run_id: int) -> Iterator[dict]:
        run = self.get_run(run_id)
        yield from self.iter_run(run)

    def drop(self, run_id: int) -> None:
        with self._lock:
            self._runs.pop(run_id, None)

    def _get(self, run_id: int) -> _LiveRun:
        return self.get_run(run_id)


live_store = LiveRunStore()


def start_live_run(
    provider: str,
    scenario: str,
    llm: LLMProvider | None = None,
    slot: int | None = None,
) -> int:
    """Public helper: begin a live run and return its run id (used by routes)."""
    return live_store.start(provider, scenario, llm=llm, slot=slot)


def sse_lines(item: dict) -> str:
    if item.get("event") == "__keepalive__":
        return ": keepalive\n\n"
    return f"event: {item['event']}\ndata: {json.dumps(item)}\n\n"