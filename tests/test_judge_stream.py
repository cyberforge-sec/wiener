from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient

from app.judge import LIVE_STAGE_ORDER
from app.judge.render import render_page
from app.main import app
from app.llm.base import LLMProvider, LLMResponse, ProviderUnavailable

client = TestClient(app)


class StanceLLM(LLMProvider):
    """Scripted LLM: always proposes a fixed action under a chosen name."""

    def __init__(self, name: str, action: str = "check_endpoint") -> None:
        self.name = name
        self._action = action

    def complete(self, system: str, user: str) -> LLMResponse:
        text = json.dumps({"action": self._action, "target": "host-a", "confidence": 0.9})
        return LLMResponse(text=text, provider=self.name)


def _reset_session() -> None:
    from app.judge.session import get_session

    get_session().reset()


def _api_resolver(stance_by_provider):
    """resolve_llm stub: map requested provider to a scripted stance."""

    def resolver(preferred: str = "", *, strict_replay: bool = False):
        return StanceLLM(stance_by_provider.get(preferred, "replay"))

    return resolver


def _start(monkeypatch, provider: str, scenario: str, resolver=None) -> int:
    _reset_session()
    if resolver is None:
        resolver = _api_resolver({"opencode": "opencode", "local": "local", "replay": "replay"})
    monkeypatch.setattr("app.judge.judge_mode.resolve_llm", resolver)
    resp = client.post(
        "/judge/run?stream=1", json={"provider": provider, "scenario": scenario}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["status"] == "started"
    assert body["run_id"] > 0
    return body["run_id"]


def _drain(run_id: int) -> list[dict]:
    events: list[dict] = []
    with client.stream("GET", f"/judge/stream?run_id={run_id}") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        for raw in resp.iter_lines():
            if not raw or not raw.startswith("data: "):
                continue
            events.append(json.loads(raw[len("data: ") :]))
    assert events, "SSE stream closed without any event"
    return events


def _terminal(events: list[dict]) -> dict:
    return events[-1]


def _stage_events(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("phase")]

def _completed(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("phase") == "completed"]



def test_stream_unknown_run_id_404():
    _reset_session()
    resp = client.get("/judge/stream?run_id=424242")
    assert resp.status_code == 404


def test_stream_invalid_provider_400():
    _reset_session()
    resp = client.post(
        "/judge/run?stream=1", json={"provider": "nonsense", "scenario": "normal"}
    )
    assert resp.status_code == 400
    assert client.get("/judge/state").json()["last"] is None



def test_stream_stage_order_and_terminal(monkeypatch):
    """Full lifecycle arrives in the TRUE engine order: every stage emits a
    *_started event when its real work begins and *_completed when it ends,
    then run_completed terminates the stream."""
    run_id = _start(monkeypatch, "opencode", "normal")
    events = _drain(run_id)
    assert events[0]["event"] == "run_started"
    assert events[0]["stages"] == list(LIVE_STAGE_ORDER)
    expected = [(stage, phase) for stage in LIVE_STAGE_ORDER for phase in ("started", "completed")]
    assert [(e["stage"], e["phase"]) for e in _stage_events(events)] == expected
    completed = [e for e in events if e["event"] == "run_completed"]
    assert len(completed) == 1
    assert _terminal(events)["event"] == "run_completed"
    for ev in _stage_events(events):
        assert ev["event"] == f"{ev['stage']}_{ev['phase']}"
        assert ev["status"] == ("running" if ev["phase"] == "started" else "done")
        assert isinstance(ev["display"], dict) and ev["display"]["value"] != ""
        assert ev["elapsed_ms"] >= 0
        assert ev["run_id"] == run_id


def test_stream_started_precedes_completed_and_values_only_on_completed(monkeypatch):
    """STARTED events fire before their COMPLETED pair, and runtime values are
    delivered on the COMPLETED event, never fabricated at STARTED time."""
    run_id = _start(monkeypatch, "opencode", "normal")
    events = _drain(run_id)
    by_key = {}
    for ev in _stage_events(events):
        by_key.setdefault(ev["stage"], []).append(ev)
    for stage, pair in by_key.items():
        assert [e["phase"] for e in pair] == ["started", "completed"]
    soc_started = by_key["soc_agent"][0]
    assert soc_started["data"] == {}  # the model result does not exist yet
    soc_done = by_key["soc_agent"][1]
    assert soc_done["data"]["action"] and soc_done["data"]["provider"]
    # The chip tracks the phase: progress while running, result once done, never frozen.
    sim = by_key["simulated_tool"]
    assert sim[0]["display"]["chip"] == "EXECUTING"
    assert sim[1]["display"]["chip"] == "EXECUTED (SIMULATED)"
    gate = by_key["policy_gate"]
    assert gate[0]["display"]["chip"] == "EVALUATING"
    assert gate[1]["display"]["chip"] == "DECISION LOCKED"
    risk = by_key["risk_engine"]
    assert risk[0]["display"]["chip"] == "SCORING"
    assert risk[1]["display"]["chip"] == "RISK SCORED"


def test_stream_stage_data_from_backend(monkeypatch):
    """Values shown are the real SOC/policy/tool outputs, never a smoke test map."""
    run_id = _start(monkeypatch, "opencode", "normal")
    events = _drain(run_id)
    done = {e["stage"]: e for e in _completed(events)}
    soc = done["soc_agent"]["data"]
    assert soc["action"] == "check_endpoint"
    assert soc["provider"] == "opencode"
    assert done["policy_gate"]["data"]["decision"] == "ALLOW"
    tool = done["simulated_tool"]["data"]
    assert tool["executed"] is True and tool["status"] == "ok"
    assert done["risk_engine"]["data"]["risk_score"] is not None
    assert done["blue_ai"]["data"]["route"] != ""
    assert done["trajectory"]["data"]["proposed_action"] == "check_endpoint"


def test_stream_final_verdict_from_backend(monkeypatch):
    """The FINAL verdict is produced by the Policy Gate and delivered by the
    stream; the client never derives it."""
    run_id = _start(monkeypatch, "opencode", "normal")
    events = _drain(run_id)
    terminal = _terminal(events)
    assert terminal["meta"]["decision"] == "ALLOW"
    assert 'data-final-decision="ALLOW"' in terminal["html"]
    # the authoritative run was committed to the session state
    state = client.get("/judge/state").json()["last"]
    assert state is not None and state["run_id"] == run_id


def test_stream_tool_result_from_backend(monkeypatch):
    """Tool execution reflects the real SimulatedToolExecutor outcome."""
    run_id = _start(monkeypatch, "opencode", "normal")
    events = _drain(run_id)
    terminal = _terminal(events)
    assert 'data-tool-executed="true"' in terminal["html"]
    assert 'data-tool-status="ok"' in terminal["html"]



def test_stream_replay_labels_truthful(monkeypatch):
    run_id = _start(monkeypatch, "replay", "normal")
    events = _drain(run_id)
    soc = [e for e in _completed(events) if e["stage"] == "soc_agent"][0]
    assert soc["tier"]["tier"] == "replay"
    terminal = _terminal(events)
    assert terminal["meta"]["provider_used"] == "replay"
    assert terminal["meta"]["replay_mode"] is True
    assert terminal["meta"]["provider_tier"] == "replay"
    assert "REPLAY MODE" in terminal["html"]
    assert "not live inference" in terminal["html"]


def test_stream_local_fallback_label_truthful(monkeypatch):
    """Cloud tier down → local resolves; stream must say LOCAL FALLBACK, never
    present it as live cloud inference."""

    def resolver(preferred: str = "", *, strict_replay: bool = False):
        return StanceLLM("local")

    run_id = _start(monkeypatch, "opencode", "normal", resolver=resolver)
    events = _drain(run_id)
    soc = [e for e in _completed(events) if e["stage"] == "soc_agent"][0]
    assert soc["tier"]["tier"] == "local_fallback"
    terminal = _terminal(events)
    assert terminal["meta"]["provider_used"] == "local"
    assert terminal["meta"]["provider_tier"] == "local_fallback"
    assert "LOCAL FALLBACK" in terminal["html"]
    assert "REPLAY MODE" not in terminal["html"]


def test_stream_failed_run_emits_run_failed(monkeypatch):
    """No tier can serve → the stream ends with run_failed (fail-loud, never a
    fabricated verdict)."""

    def boom(preferred: str = "", *, strict_replay: bool = False):
        raise ProviderUnavailable("simulated tier outage", kind="no_provider")

    _reset_session()
    monkeypatch.setattr("app.judge.judge_mode.resolve_llm", boom)
    resp = client.post("/judge/run?stream=1", json={"provider": "opencode", "scenario": "normal"})
    assert resp.status_code == 200
    events = _drain(resp.json()["run_id"])
    terminal = _terminal(events)
    assert terminal["event"] == "run_failed"
    assert "no LLM tier could serve" in terminal["error"]
    assert "Run failed" in terminal["html"]
    assert terminal["meta"]["decision"] is None
    assert terminal["meta"]["error"]



def test_stream_two_consumers_get_full_ordered_history(monkeypatch):
    """Stage events are broadcast: two viewers both observe the SAME full
    ordered stream (history is replayed on attach, never consumed once)."""
    import threading

    from fastapi.testclient import TestClient as TC2

    run_id = _start(monkeypatch, "opencode", "normal")
    results: dict[str, list] = {}

    def consume(name: str) -> None:
        with TC2(app) as tc:  # dedicated client per consumer (httpx not thread-shared)
            results[name] = _drain_client(tc, run_id)

    t1 = threading.Thread(target=consume, args=("a"))
    t2 = threading.Thread(target=consume, args=("b"))
    t1.start(); t2.start()
    t1.join(timeout=20); t2.join(timeout=20)
    assert set(results) == {"a", "b"}
    a, b = results["a"], results["b"]
    expected = [(stage, phase) for stage in LIVE_STAGE_ORDER for phase in ("started", "completed")]
    assert [(e["stage"], e["phase"]) for e in a if e.get("phase")] == expected
    assert [(e["stage"], e["phase"]) for e in b if e.get("phase")] == expected
    assert a[0]["event"] == b[0]["event"] == "run_started"
    assert a[-1]["event"] == b[-1]["event"] == "run_completed"
    assert a[-1]["meta"]["decision"] == b[-1]["meta"]["decision"] == "ALLOW"


def _drain_client(tc, run_id: int) -> list[dict]:
    """Like _drain but against an arbitrary TestClient (thread-local use)."""
    events: list[dict] = []
    with tc.stream("GET", f"/judge/stream?run_id={run_id}") as resp:
        assert resp.status_code == 200
        for raw in resp.iter_lines():
            if not raw or not raw.startswith("data: "):
                continue
            events.append(json.loads(raw[len("data: ") :]))
    assert events
    return events



def test_stream_page_wiring_no_fake_timers():
    html = render_page()
    assert "new EventSource(" in html
    assert "/judge/stream?run_id=" in html
    assert "/judge/run?stream=1" in html
    assert 'id="live-skeleton"' in html
    for key in LIVE_STAGE_ORDER:
        assert f'id="stage-{key}"' in html
    # The animation is SSE-driven only: no client timers, no stage indices.
    for banned in ("setInterval(", "setTimeout(", "stageIndex"):
        assert banned not in html

def test_consumer_queue_is_bounded_and_terminal_event_always_arrives():
    """A slow/abandoned SSE client must not grow server memory without bound,
    and a bounded queue must still deliver the terminal event."""
    import queue as _queue

    from app.judge.stream import _CONSUMER_QUEUE_MAXSIZE, _LiveRun, LiveRunStore

    store = LiveRunStore()
    run = _LiveRun(999)
    store._runs[999] = run

    it = store.iter_run(run)
    next(it)  # registers the consumer queue on first advance

    with run.lock:
        queues = list(run.subs)
    assert len(queues) == 1
    assert queues[0].maxsize == _CONSUMER_QUEUE_MAXSIZE

    # Never read again: flood far past the bound.
    for i in range(_CONSUMER_QUEUE_MAXSIZE * 3):
        store._broadcast(run, {"event": "soc_agent_started", "i": i})
    assert queues[0].qsize() <= _CONSUMER_QUEUE_MAXSIZE

    # A terminal event is never dropped, even on a saturated queue.
    store._broadcast(run, {"event": "run_completed", "run_id": 999})
    drained = []
    while True:
        try:
            drained.append(queues[0].get_nowait())
        except _queue.Empty:
            break
    assert drained[-1]["event"] == "run_completed"
    it.close()


def test_judge_page_has_no_third_party_requests():
    """Regression: the Judge UI must not depend on any external host.

    It used to load cdn.tailwindcss.com (unpinned, unsigned, remote script
    execution) and two Google Fonts stylesheets, so the demo silently broke
    offline and ran third-party code in a security PoC.
    """
    html = render_page()
    for banned in (
        "cdn.tailwindcss.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "material-symbols",
        "<script src=\"http",
    ):
        assert banned not in html, f"Judge page must not reference {banned}"
    assert '<link rel="stylesheet" href="/judge/tailwind.css">' in html
    # Local stylesheet is actually served.
    resp = client.get("/judge/tailwind.css")
    assert resp.status_code == 200
    assert "text/css" in resp.headers["content-type"]
    assert len(resp.content) > 1000
    # Icons are inline SVG, so no webfont is needed for the UI chrome.
    assert "<svg" in html and 'class="ico' in html


def test_state_endpoint_returns_the_rendered_last_run():
    """A reload must not lose the judge's result: the page restores the stored
    run, and it must be labelled as restored rather than freshly executed."""
    _reset_session()
    run = client.post("/judge/run", json={"provider": "replay", "scenario": "normal"})
    assert run.status_code == 200

    state = client.get("/judge/state")
    assert state.status_code == 200
    last = state.json()["last"]
    assert last is not None
    assert last["html"], "state must carry the rendered view, not only summary fields"
    assert "run-shell" in last["html"]
    assert last["decision"] is not None
    assert last["scenario"] == "normal"
    assert last["provider_used"]
    # Risk and tool outcome travel with the restore, not just the verdict.
    assert last["risk_score"] is not None
    assert "tool_executed" in last

    page = render_page()
    assert "/judge/state" in page
    assert "restoreLast" in page
    assert "restored, not re-executed" in page


def test_state_is_empty_after_reset():
    _reset_session()
    client.post("/judge/run", json={"provider": "replay", "scenario": "normal"})
    assert client.get("/judge/state").json()["last"] is not None
    client.post("/judge/reset")
    assert client.get("/judge/state").json()["last"] is None


def test_restore_status_line_has_no_escaped_separator_leakage():
    """Regression: the restored-run status line rendered a literal `00b7`
    because the separator was double-escaped in the Python source."""
    page = render_page()
    line_start = page.index("Showing the last completed run")
    line = page[line_start : line_start + 260]
    assert "\\u00b7" not in line
    assert "00b7" not in line
    assert "\u00b7 Provider: " in line
