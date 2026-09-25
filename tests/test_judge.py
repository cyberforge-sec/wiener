from __future__ import annotations

import json
import shutil
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from app.judge import JudgeSession, run_judge
from app.judge.render import render_main_view, render_page
from app.llm import factory as llm_factory
from app.llm.base import LLMProvider, LLMResponse, ProviderUnavailable
from app.llm.factory import resolve_llm
from app.llm.replay_provider import RECORDED_DIR
from app.main import app

client = TestClient(app)


class StanceLLM(LLMProvider):
    """Scripted LLM: always proposes a fixed action under a chosen name."""

    def __init__(
        self,
        name: str,
        action: str = "check_endpoint",
        target: str = "host-a",
        confidence: float = 0.9,
    ) -> None:
        self.name = name
        self._action = action
        self._target = None if action == "get_logs" else target
        self._confidence = confidence

    def complete(self, system: str, user: str) -> LLMResponse:
        import json

        text = json.dumps(
            {"action": self._action, "target": self._target, "confidence": self._confidence}
        )
        return LLMResponse(text=text, provider=self.name)


def _stance(name: str, action: str = "check_endpoint") -> StanceLLM:
    return StanceLLM(name, action)


def _reset_session() -> None:
    from app.judge.session import get_session

    get_session().reset()



def test_resolve_cloud_first(monkeypatch):
    monkeypatch.setattr(
        llm_factory, "_build",
        lambda name, *, strict_replay=False: _stance("opencode") if name == "opencode" else _stance("local"),
    )
    monkeypatch.setattr(llm_factory, "ollama_reachable", lambda *a, **k: True)
    assert resolve_llm("opencode").name == "opencode"
    assert resolve_llm("").name == "opencode"  # default ladder picks cloud


def test_resolve_cloud_failure_falls_to_local(monkeypatch):
    def build(name, *, strict_replay=False):
        if name == "opencode":
            raise ProviderUnavailable("no key", kind="auth")
        return _stance("local")

    monkeypatch.setattr(llm_factory, "_build", build)
    monkeypatch.setattr(llm_factory, "ollama_reachable", lambda *a, **k: True)
    assert resolve_llm("opencode").name == "local"


def test_resolve_cloud_and_local_failure_falls_to_replay(monkeypatch):
    def build(name, *, strict_replay=False):
        raise ProviderUnavailable(f"simulated {name} failure")

    monkeypatch.setattr(llm_factory, "_build", build)
    monkeypatch.setattr(llm_factory, "ollama_reachable", lambda *a, **k: False)
    resolved = resolve_llm("opencode")
    assert resolved.name == "replay"


def test_resolve_local_failure_falls_to_replay(monkeypatch):
    def build(name, *, strict_replay=False):
        if name == "opencode":
            return _stance("opencode")  # cloud is healthy
        raise ProviderUnavailable("simulated local failure")

    monkeypatch.setattr(llm_factory, "_build", build)
    monkeypatch.setattr(llm_factory, "ollama_reachable", lambda *a, **k: True)
    assert resolve_llm("local").name == "replay"


def test_resolve_replay_direct(monkeypatch):
    # "replay" always maps to a replay-shaped provider; resolve never climbs to a live tier.
    monkeypatch.setattr(llm_factory, "_build", lambda name, *, strict_replay=False: _stance(name))
    monkeypatch.setattr(llm_factory, "ollama_reachable", lambda *a, **k: True)
    assert resolve_llm("replay").name == "replay"


def test_resolve_unknown_provider_defaults_to_ladder(monkeypatch):
    monkeypatch.setattr(
        llm_factory, "_build",
        lambda name, *, strict_replay=False: _stance("opencode") if name == "opencode" else _stance("local"),
    )
    monkeypatch.setattr(llm_factory, "ollama_reachable", lambda *a, **k: True)
    assert resolve_llm("not-a-provider").name == "opencode"



def test_run_normal():
    run = run_judge("opencode", "normal", llm=_stance("opencode", "check_endpoint"))
    assert run.error is None
    assert run.provider_used == "opencode"
    assert run.replay_mode is False
    assert run.scenario == "normal"
    assert run.proposed_action == "check_endpoint"
    assert run.attack is None
    assert run.adaptive_trace == ()
    assert run.decision == "ALLOW"
    assert run.result is not None and run.result.tool_result.executed is True


def test_run_prompt_injection():
    run = run_judge("local", "prompt_injection", llm=_stance("local", "block_ip"))
    assert run.error is None
    assert run.attack is not None and run.attack.seed_id == "RS-001"
    assert run.attack.category.value == "prompt_injection"
    assert run.proposed_action == "block_ip"  # the injected action was adopted
    # Dangerous adopted actions → REVIEW, never executed: the gate never ALLOWs block_ip.
    assert run.decision == "REVIEW"
    assert run.result is not None and run.result.tool_result.executed is False
    assert run.replay_mode is False


def test_run_adaptive():
    # Default slot 0 = ADAPTIVE_CATALOG[0]: RS-011, a moderate recon seed.
    # Two turns, both below the BLOCK boundary: the demo ends REVIEW. The gate
    # decides from the real accumulated risk, never from a hardcoded verdict.
    run = run_judge("replay", "adaptive", llm=None, slot=0)
    assert run.error is None
    assert len(run.adaptive_trace) == 2  # catalog horizon for RS-011
    assert [s.decision for s in run.adaptive_trace] == ["REVIEW", "REVIEW"]
    assert all(
        run.adaptive_trace[i].risk < run.adaptive_trace[i + 1].risk
        for i in range(len(run.adaptive_trace) - 1)
    )
    assert run.stopped_reason == "max_iterations"
    assert run.attack is not None and run.attack.iteration == 1
    assert run.decision == "REVIEW"
    assert run.result is not None and run.result.tool_result.executed is False
    assert run.replay_mode is True


def test_run_adaptive_escalation_arc_ends_block():
    # Catalog slot 1 = RS-001 (block_ip, horizon 4): the first alert is REVIEW,
    # then accumulated history carries the real risk across the boundary. The
    # door closes at BLOCK, so the loop stops there instead of grinding out the
    # full horizon.
    run = run_judge("replay", "adaptive", llm=None, slot=1)
    assert run.error is None
    assert len(run.adaptive_trace) == 2
    assert [s.decision for s in run.adaptive_trace] == ["REVIEW", "BLOCK"]
    assert run.stopped_reason == "defense_blocked"
    assert run.decision == "BLOCK"
    assert run.result is not None and run.result.tool_result.executed is False


def test_adaptive_panel_shows_backend_trace():
    run = run_judge("replay", "adaptive", llm=None, slot=0)
    html = render_main_view(run)
    assert 'data-adaptive-loop="1"' in html
    assert f'data-adaptive-iterations="{len(run.adaptive_trace)}"' in html
    for step in run.adaptive_trace:
        assert f'data-iteration="{step.iteration + 1}"' in html
        assert f'data-decision="{step.decision}"' in html


def test_adaptive_panel_uses_backend_fields():
    run = run_judge("replay", "adaptive", llm=None, slot=0)
    html = render_main_view(run)
    for step in run.adaptive_trace:
        if step.risk is not None:
            assert f"{step.risk:g} / 100" in html
        if step.kind is not None:
            assert step.kind.replace("_", " ") in html


def test_non_adaptive_runs_hide_adaptive_panel():
    normal = run_judge("replay", "normal", llm=None)
    assert "data-adaptive-loop" not in render_main_view(normal)
    injected = run_judge("replay", "prompt_injection", llm=None)
    assert "data-adaptive-loop" not in render_main_view(injected)


def test_adaptive_runs_do_not_inherit_previous_trace():
    first = run_judge("replay", "adaptive", llm=None, slot=0)   # RS-011, horizon 2
    second = run_judge("replay", "adaptive", llm=None, slot=4)  # RS-005, stops at its first BLOCK
    assert len(first.adaptive_trace) == 2
    assert len(second.adaptive_trace) == 2  # never accumulates into a shared pool
    assert first.adaptive_trace != second.adaptive_trace
    assert render_main_view(second).count("data-iteration=") == 2


def test_adaptive_panel_kept_separate_from_execution_trace():
    run = run_judge("replay", "adaptive", llm=None, slot=0)
    html = render_main_view(run)
    assert html.count('data-stage-key=') == 7  # Execution Pipeline stays the final run
    assert 'data-adaptive-iterations="2"' in html
    assert "RS-011-it1" in html  # trajectory shows the final mutation, not the loop history


def test_adaptive_panel_verdict_follows_policy_gate():
    review = run_judge("replay", "adaptive", llm=None, slot=0)    # RS-011: moderate, ends REVIEW
    escalation = run_judge("replay", "adaptive", llm=None, slot=1)  # RS-001: REVIEW then crosses BLOCK
    blocked = run_judge("replay", "adaptive", llm=None, slot=3)   # RS-003: BLOCK from the first alert
    assert [s.decision for s in review.adaptive_trace] == ["REVIEW", "REVIEW"]
    assert [s.decision for s in escalation.adaptive_trace] == ["REVIEW", "BLOCK"]
    assert all(s.decision == "BLOCK" for s in blocked.adaptive_trace)
    review_html = render_main_view(review)
    escalation_html = render_main_view(escalation)
    blocked_html = render_main_view(blocked)
    assert 'data-decision="REVIEW"' in review_html
    assert 'data-decision="REVIEW"' in escalation_html and 'data-decision="BLOCK"' in escalation_html
    assert 'data-decision="REVIEW"' not in blocked_html
    assert blocked_html.count('data-iteration="1"') == 1  # stopped at the door, a single BLOCK


def test_adaptive_panel_explains_stop_without_mechanism():
    review = run_judge("replay", "adaptive", llm=None, slot=0)   # RS-011: door stayed open
    closed = run_judge("replay", "adaptive", llm=None, slot=1)   # RS-001: closed at first BLOCK
    review_html = render_main_view(review)
    closed_html = render_main_view(closed)
    # The condition is static copy; the reason is the backend's real StopReason.
    assert 'data-stop-condition="BLOCK or iteration horizon"' in review_html
    assert 'data-stop-reason="max_iterations"' in review_html
    assert "HORIZON REACHED" in review_html
    assert 'data-stop-reason="defense_blocked"' in closed_html
    assert "DEFENSE BLOCKED" in closed_html


def test_adaptive_panel_verdicts_are_policy_threshold_derived():
    run = run_judge("replay", "adaptive", llm=None, slot=1)
    for step in run.adaptive_trace:
        expected = "ALLOW" if step.risk < 30 else "REVIEW" if step.risk < 60 else "BLOCK"
        assert step.decision == expected  # Panel = policy gate on the real, rising risk.
    assert run.adaptive_trace[0].kind is None  # iteration 1 is the baseline payload
    assert all(s.kind is not None for s in run.adaptive_trace[1:])


def test_adaptive_final_trace_matches_panel_verdict():
    run = run_judge("replay", "adaptive", llm=None, slot=0)
    assert run.decision == run.adaptive_trace[-1].decision  # Execution Trace = last reassessment
    run2 = run_judge("replay", "adaptive", llm=None, slot=1)
    assert run2.decision == run2.adaptive_trace[-1].decision


def test_adaptive_catalog_seeds_configured_and_varied():
    from app.judge.judge_mode import ADAPTIVE_CATALOG
    from app.red_ai.seed_loader import AdaptiveSeedLoader

    loader = AdaptiveSeedLoader()
    horizons = []
    for seed_id, horizon in ADAPTIVE_CATALOG:
        assert loader.get(seed_id) is not None  # catalog references the adaptive pool
        assert 1 <= horizon <= 4
        horizons.append(horizon)
    # The pool must intentionally mix arc lengths so sessions end differently:
    # modular recon horizon 2, the differentiated check_endpoint horizon 3, and
    # escalation/block seeds at the max horizon 4.
    assert 2 in horizons and 3 in horizons and 4 in horizons


def test_adaptive_pool_tiers_are_measured_by_policy_not_hardcoded():
    from app.judge.adaptive_pool import verify_catalog_tiers
    from app.judge.judge_mode import ADAPTIVE_CATALOG
    from app.llm.replay_provider import ReplayProvider

    tiers = verify_catalog_tiers(ADAPTIVE_CATALOG, llm=ReplayProvider(strict=True))
    # Real Policy Gate output, not an asserted claim: the pool must contain
    # BOTH a REVIEW-tier seed (moderate recon) and a BLOCK-tier seed.
    assert "REVIEW" in set(tiers.values())
    assert "BLOCK" in set(tiers.values())
    # Intent per tier, re-verified against the measured outcome.
    assert tiers["RS-011"] == "REVIEW"  # moderate recon pool entry
    assert tiers["RS-001"] == "REVIEW"  # escalation seed starts below the gate
    assert tiers["RS-003"] == "BLOCK"   # high-privilege action is hot from the start


class _RecordingLLM(StanceLLM):
    """Stance that also records each user prompt it saw (for rotation checks)."""

    def __init__(self, name: str, prompts: list[str], **kw) -> None:
        super().__init__(name, **kw)
        self._prompts = prompts

    def complete(self, system: str, user: str) -> LLMResponse:
        self._prompts.append(user)
        return super().complete(system, user)


def test_prompt_injection_rotates_seed_by_slot():
    seed_ids = [
        run_judge("opencode", "prompt_injection", llm=_stance("opencode", "block_ip"), slot=s).attack.seed_id
        for s in range(6)
    ]
    assert seed_ids == ["RS-001", "RS-002", "RS-003", "RS-004", "RS-005", "RS-001"]


def test_adaptive_rotates_seed_by_slot():
    from app.judge.judge_mode import ADAPTIVE_CATALOG

    for slot, (seed_id, horizon) in enumerate(ADAPTIVE_CATALOG):
        run = run_judge("opencode", "adaptive", llm=_stance("opencode", "block_ip"), slot=slot)
        assert run.error is None
        assert run.attack is not None and run.attack.seed_id == seed_id
        # Stance always pushes block_ip, so every slot closes at its first
        # campaign BLOCK: final attack = last closed-loop step, not the horizon.
        assert run.attack.iteration == len(run.adaptive_trace) - 1


def test_normal_rotation_cycles_contexts_including_replay():
    prompts: list[str] = []
    llm = _RecordingLLM("opencode", prompts)

    def at(slot: int) -> None:
        assert run_judge("opencode", "normal", llm=llm, slot=slot).decision == "ALLOW"

    at(0); at(1); at(2); at(3)
    assert len(prompts) == 4
    assert prompts[0] == prompts[3]  # A → B → C → A
    assert len(set(prompts[:3])) == 3  # three distinct benign variants


def test_session_normal_rotation_per_run_and_replay_and_reset():
    prompts: list[str] = []
    s = JudgeSession()
    for _ in range(4):
        s.run("opencode", "normal", llm=_RecordingLLM("opencode", prompts))
    assert prompts[0] == prompts[3] and len(set(prompts[:3])) == 3
    # Replay reproduces the exact same variant (same rotation slot).
    s.replay(llm=_RecordingLLM("opencode", prompts))
    assert prompts[4] == prompts[3]
    # Reset re-arms the cursor back at slot 0 (variant A).
    s.reset()
    s.run("opencode", "normal", llm=_RecordingLLM("opencode", prompts))
    assert prompts[5] == prompts[0]


def test_session_prompt_injection_rotates_seed_per_run():
    s = JudgeSession()
    runs = [s.run("opencode", "prompt_injection", llm=_stance("opencode", "block_ip")) for _ in range(6)]
    assert [r.attack.seed_id for r in runs] == ["RS-001", "RS-002", "RS-003", "RS-004", "RS-005", "RS-001"]


def test_policy_gate_stays_source_of_verdict():
    # The gate blocks a privileged action on its real risk, whether that risk
    # is already above the boundary or climbs there via accumulated history;
    # neither ALLOW nor a forced verdict appears.
    run = run_judge("opencode", "adaptive", llm=_stance("opencode", "disable_user"), slot=3)
    assert run.attack is not None and run.attack.seed_id == "RS-003"
    assert run.decision == "BLOCK"
    assert all(s.decision == "BLOCK" for s in run.adaptive_trace)
    run2 = run_judge("opencode", "prompt_injection", llm=_stance("opencode", "isolate_endpoint"), slot=1)
    assert run2.attack is not None and run2.attack.seed_id == "RS-002"
    assert run2.decision == "BLOCK"
    # Same loop with a block_ip reply: the first isolated alert is REVIEW, then
    # persistence pushes the real risk across the boundary — verdicts track the
    # accumulated campaign, not a hardcoded answer.
    run3 = run_judge("opencode", "adaptive", llm=_stance("opencode", "block_ip"), slot=0)
    assert run3.adaptive_trace[0].decision == "REVIEW"
    assert run3.decision == "BLOCK"


def test_run_replay_provider_is_marked_and_deterministic():
    # Judge replay serves the REAL recorded answer, never the neutral placeholder.
    run_a = run_judge("replay", "normal", llm=None)  # real ReplayProvider fallback
    run_b = run_judge("replay", "normal", llm=None)
    assert run_a.error is None and run_b.error is None
    assert run_a.provider_used == "replay"
    assert run_a.replay_mode and run_b.replay_mode
    assert run_a.proposed_action == run_b.proposed_action
    assert run_a.decision == run_b.decision
    # Guards the pre-fix masking: recorded judge-normal is get_logs → ALLOW.
    assert run_a.proposed_action == "get_logs"
    assert run_a.decision == "ALLOW"


def test_run_unknown_inputs_rejected():
    from app.judge import JudgeInputError

    with pytest.raises(JudgeInputError):
        run_judge("not-a-provider", "normal", llm=_stance("opencode"))
    with pytest.raises(JudgeInputError):
        run_judge("opencode", "not-a-scenario", llm=_stance("opencode"))



def test_session_run_reset_replay():
    s = JudgeSession()
    first = s.run("opencode", "normal", llm=_stance("opencode"))
    assert s.last is first
    assert s.last_request == ("opencode", "normal")

    # Replay re-runs the same request; a NEW run object replaces the old state.
    second = s.replay(llm=_stance("opencode"))
    assert second is not None
    assert second.requested_provider == "opencode"
    assert second.scenario == "normal"
    assert s.last is second

    # Replay over empty state is refused, not silent.
    s.reset()
    assert s.last is None and s.last_request is None
    assert s.replay(llm=_stance("opencode")) is None


def test_session_state_resets_between_runs():
    s = JudgeSession()
    s.run("opencode", "prompt_injection", llm=_stance("opencode", "block_ip"))
    assert s.last.scenario == "prompt_injection"
    s.reset()
    assert s.last is None
    s.run("local", "normal", llm=_stance("local"))
    assert s.last.scenario == "normal"
    assert s.last.requested_provider == "local"



class _AttrCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.attrs: dict[str, str] = {}

    def handle_starttag(self, tag, attrs) -> None:
        for k, v in attrs:
            if k.startswith("data-"):
                self.attrs[k[len("data-"):]] = v


def _attrs(html: str) -> dict[str, str]:
    p = _AttrCollector()
    p.feed(html)
    return p.attrs


def test_main_view_shows_all_stages_and_values():
    run = run_judge("opencode", "prompt_injection", llm=_stance("opencode", "block_ip"))
    html = render_main_view(run)
    for stage in ("RED AI", "SOC AGENT", "TRAJECTORY", "BLUE AI", "RISK ENGINE", "POLICY GATE"):
        assert stage in html
    attrs = _attrs(html)
    assert attrs["scenario"] == "Prompt Injection"
    assert attrs["seed"] == "RS-001"
    assert attrs["proposed-action"] == "block_ip"
    assert attrs["risk-score"] != "none"
    assert attrs["decision"] == "REVIEW"
    assert attrs["executed"] == "false"
    assert attrs["route"] != "none"
    assert attrs["provider-used"] == "opencode"
    assert attrs["replay-mode"] == "false"
    assert "evidence-tags" in attrs


def test_main_view_replay_badge_prominent_when_replay():
    run = run_judge("replay", "normal", llm=None)
    html = render_main_view(run)
    assert 'data-replay-mode="true"' in html
    assert "REPLAY MODE" in html
    assert "not live inference" in html


def test_main_view_error_frame():
    run = run_judge("opencode", "normal", llm=_stance("opencode"))
    run.error = "boom"
    html = render_main_view(run)
    assert "Run failed" in html
    assert "boom" in html


def test_page_minimal_and_no_debug_controls():
    html = render_page()
    for provider in ("opencode", "local", "replay"):
        assert f'value="{provider}"' in html
    for scenario in ("normal", "prompt_injection", "adaptive"):
        assert f'value="{scenario}"' in html
    for btn in ("btn-run", "btn-reset", "btn-replay"):
        assert btn in html
    assert "/judge/run" in html and "/judge/replay" in html



def _api_resolver(stance_by_provider):
    """Resolver stub: map requested provider to a scripted stance (or replay)."""

    def resolver(preferred: str = "", *, strict_replay: bool = False):
        return _stance(stance_by_provider.get(preferred, "replay"))

    return resolver


def test_api_run_normal(monkeypatch):
    _reset_session()
    monkeypatch.setattr(
        "app.judge.judge_mode.resolve_llm",
        _api_resolver({"opencode": "opencode"}),
    )
    resp = client.post("/judge/run", json={"provider": "opencode", "scenario": "normal"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["provider_used"] == "opencode"
    assert body["scenario"] == "normal"
    assert body["replay_mode"] is False
    assert "TRAJECTORY" in body["html"] and "POLICY GATE" in body["html"]


def test_api_run_prompt_injection_via_cloud(monkeypatch):
    _reset_session()
    monkeypatch.setattr(
        "app.judge.judge_mode.resolve_llm",
        _api_resolver({"opencode": "opencode"}),
    )
    resp = client.post(
        "/judge/run", json={"provider": "opencode", "scenario": "prompt_injection"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["scenario"] == "prompt_injection"
    assert body["provider_used"] == "opencode"
    assert "RED AI" in body["html"] and "data-seed=\"RS-001\"" in body["html"]


def test_api_cloud_failure_with_no_recording_fails_loud(monkeypatch):
    """Cloud + local fail AND no recording for the prompt → the judge refuses
    to fabricate a benign-looking decision (fail-loud, never ALLOW)."""
    _reset_session()

    def build(name, *, strict_replay=False):
        if name == "replay":
            from app.llm.replay_provider import ReplayProvider

            return ReplayProvider(replay_dir=tempfile.mkdtemp(), strict=strict_replay)
        raise ProviderUnavailable(f"simulated {name} failure")

    monkeypatch.setattr(llm_factory, "_build", build)
    monkeypatch.setattr(llm_factory, "ollama_reachable", lambda *a, **k: False)

    resp = client.post("/judge/run", json={"provider": "opencode", "scenario": "normal"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body.get("provider_used", "") == ""
    assert body["replay_mode"] is False
    assert body["decision"] is None
    assert "Refusing to fabricate" in body["html"]
    assert "Run failed" in body["html"]


def test_api_cloud_and_local_failure_serve_prerecorded_replay(monkeypatch):
    """Cloud + local fail but the prompt IS recorded → replay serves the real
    recorded answer, still clearly labeled as replay (never live inference)."""
    _reset_session()

    tmp = Path(tempfile.mkdtemp())
    copied = 0
    for path in Path(RECORDED_DIR).glob("*.json"):
        doc = json.loads(path.read_text())
        if (dict(doc.get("meta") or {})).get("scenario") == "judge-normal":
            shutil.copy(path, tmp / path.name)
            copied += 1
    if not copied:
        raise AssertionError("judge-normal recording missing — run `python3 -m app.replay.prime`")

    def build(name, *, strict_replay=False):
        if name == "replay":
            from app.llm.replay_provider import ReplayProvider

            return ReplayProvider(replay_dir=str(tmp), strict=strict_replay)
        raise ProviderUnavailable(f"simulated {name} failure")

    monkeypatch.setattr(llm_factory, "_build", build)
    monkeypatch.setattr(llm_factory, "ollama_reachable", lambda *a, **k: False)

    resp = client.post("/judge/run", json={"provider": "opencode", "scenario": "normal"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["provider_used"] == "replay"
    assert body["replay_mode"] is True
    assert body["decision"] == "ALLOW"
    assert "REPLAY MODE" in body["html"]
    assert "not live inference" in body["html"]


def test_api_replay_provider_clearly_marked(monkeypatch):
    _reset_session()

    def build(name, *, strict_replay=False):
        from app.llm.replay_provider import ReplayProvider

        if name == "replay":
            return ReplayProvider()  # lenient read of the recorded store
        raise ProviderUnavailable(f"simulated {name} failure")

    monkeypatch.setattr(llm_factory, "_build", build)
    monkeypatch.setattr(llm_factory, "ollama_reachable", lambda *a, **k: False)

    resp = client.post("/judge/run", json={"provider": "replay", "scenario": "normal"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider_used"] == "replay"
    assert body["replay_mode"] is True
    assert 'data-replay-mode="true"' in body["html"]
    assert "not live inference" in body["html"]


def test_api_local_outputs_local_label(monkeypatch):
    _reset_session()
    monkeypatch.setattr(
        "app.judge.judge_mode.resolve_llm",
        _api_resolver({"local": "local"}),
    )
    resp = client.post("/judge/run", json={"provider": "local", "scenario": "normal"})
    assert resp.status_code == 200
    assert resp.json()["provider_used"] == "local"
    assert resp.json()["replay_mode"] is False


def test_api_invalid_provider_returns_400():
    _reset_session()
    resp = client.post("/judge/run", json={"provider": "nonsense", "scenario": "normal"})
    assert resp.status_code == 400


def test_api_reset_and_state_and_replay():
    _reset_session()
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        "app.judge.judge_mode.resolve_llm",
        _api_resolver({"opencode": "opencode"}),
    )

    assert client.get("/judge/state").json()["last"] is None

    resp = client.post("/judge/run", json={"provider": "opencode", "scenario": "normal"})
    assert resp.status_code == 200
    first_id = resp.json()["run_id"]

    state = client.get("/judge/state").json()["last"]
    assert state["scenario"] == "normal" and state["provider_used"] == "opencode"

    # Replay re-runs the last request, producing a new run.
    rp = client.post("/judge/replay")
    assert rp.status_code == 200
    assert rp.json()["ok"] is True
    assert rp.json()["run_id"] != first_id
    assert rp.json()["scenario"] == "normal"

    # Replay before any prior run is rejected.
    assert client.post("/judge/reset").json()["ok"] is True
    assert client.get("/judge/state").json()["last"] is None
    assert client.post("/judge/replay").status_code == 400


def test_api_judge_page_served():
    resp = client.get("/judge")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Judge Live Demo" in resp.text
    assert "id=\"btn-run\"" in resp.text


def test_adaptive_panel_verdict_is_the_loops_own_last_verdict():
    """The displayed verdict must be the loop's final iteration outcome, not a
    separate re-run of the same attack (which could differ under sampling)."""
    run = run_judge("replay", "adaptive", llm=None, slot=1)
    assert run.error is None
    assert run.adaptive_trace, "expected a recorded adaptive trace"
    last_step = run.adaptive_trace[-1]
    assert run.decision == last_step.decision
    assert run.result is not None
    assert run.result.decision.decision.value == last_step.decision


def test_adaptive_run_does_not_double_inference(monkeypatch):
    """One pipeline call per iteration: the panel reuses the loop's own result
    instead of paying for (and displaying) a second run of the same attack."""
    from app.judge import judge_mode

    calls = []
    real_pipeline = judge_mode.Pipeline

    class CountingPipeline(real_pipeline):  # type: ignore[misc,valid-type]
        def run(self, *a, **k):
            calls.append(1)
            return super().run(*a, **k)

    monkeypatch.setattr(judge_mode, "Pipeline", CountingPipeline)

    run = judge_mode.run_judge("replay", "adaptive", llm=None, slot=1)

    assert run.error is None
    assert run.adaptive_trace
    # Exactly one pipeline invocation per recorded iteration, no trailing re-run.
    assert len(calls) == len(run.adaptive_trace)
