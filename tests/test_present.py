from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from html.parser import HTMLParser

import pytest

from app.dashboard.dashboard import DashboardData
from app.judge.judge_mode import run_judge
from app.judge.render import render_main_view, run_to_meta
from app.present.evidence import build_evidence_dashboard, load_evidence
from app.present.render import presentation_page


def test_load_evidence_authoritative_facts():
    b = load_evidence()
    assert b is not None
    # Resolver picks the newest LOCKED_VERIFIED run, never the legacy hardcoded id.
    assert b.experiment_id == "authoritative_20260925_zero_degraded"
    assert b.evidence_status == "LOCKED_VERIFIED"
    assert b.locked_at is not None
    assert (b.code_fingerprint_root or "").startswith("15a61346")
    assert b.source_provenance["status"] == "MATCH"
    assert b.n_trials == 135, b.n_trials
    assert b.trials_per_mode == 45
    assert b.modes == ("no_defense", "basic_prompt_defense", "wiener")
    assert b.malicious_total == 105 and b.benign_total == 30
    assert b.duplicate_trial_mode_ids == 0
    assert b.raw_completion_present == 135 and b.raw_completion_total == 135
    assert b.degraded_count == 0
    assert b.provider_counts == {"opencode": 135}
    # The exact defense-path story from the locked artifacts.
    assert b.proposals == 4
    assert b.blocked == 3
    assert b.reviewed == 1
    assert b.executed == 0
    assert (b.blocked + b.reviewed) == b.proposals
    # Stored metrics, shown verbatim.
    assert b.validation_status == "PASS"
    assert b.validation_pass == 16 and b.validation_invariants == 16
    assert b.uapr == 1.0
    w = b.by_mode["wiener"]
    assert w.uar == 0.0 and w.fir == 0.0 and w.attempts == 45
    # Historical block is strictly separate, UAR only.
    assert b.history is not None
    assert b.history.n_trials == 30
    assert b.history.uar_by_mode["wiener"] == 0.0
    assert b.trials_sha256.startswith("a31d69de")


def test_load_evidence_missing_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("WIENER_EXPERIMENT_STORE", str(tmp_path))
    assert load_evidence() is None


def test_build_evidence_dashboard_attaches_bundle():
    b = load_evidence()
    d = build_evidence_dashboard(b)
    assert isinstance(d, DashboardData)
    assert d.evidence is b
    assert len(d.trials) == 135
    assert d.metrics.uapr == 1.0
    assert d.providers == ("opencode",)


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


def test_presentation_page_phrases_and_attrs():
    d = build_evidence_dashboard(load_evidence())
    page = presentation_page(d)
    # Exact competition wording, never "12 attacks blocked".
    assert "Dangerous proposals reaching SOC-agent stage: <b>4</b>" in page
    assert "Unsafe tool executions: <b>0</b>" in page
    assert "3 BLOCK" in page and "1 REVIEW" in page
    assert "FIR 0.0% — 30 benign trials; 0 incorrect interventions" in page
    # Historical demo.json values must be quarantined OUT of the main page.
    assert "HISTORICAL" not in page
    assert "40.0%" not in page and "70.0%" not in page
    assert "demo.json" not in page
    # Locked badge renders from the manifest, not a hardcoded string.
    assert "LOCKED EVIDENCE · 16 / 16 PASS · VERIFIED" in page
    assert "CANDIDATE EVIDENCE" not in page.split('<main')[0]
    # Five areas + evidence + provenance.
    for area in ("RED AI", "SOC AGENT", "BLUE AI", "RISK ENGINE / POLICY GATE", "METRICS"):
        assert area in page
    assert "Provenance" in page and "AUTHORITATIVE DATA LOCKED" in page
    assert "data/experiments/authoritative_20260925_zero_degraded/" in page
    assert (data_attrs := _attrs(page))
    assert data_attrs["authoritative"] == "true"
    assert data_attrs["evidence-proposals"] == "4"
    assert data_attrs["evidence-blocked"] == "3"
    assert data_attrs["evidence-reviewed"] == "1"
    assert data_attrs["unsafe-tool-executions"] == "0"
    assert data_attrs["uapr"] == "1.0"
    assert data_attrs["validation"] == "PASS"
    assert data_attrs["fir-total"] == "0.0"
    assert data_attrs["total-trials"] == "135"
    assert data_attrs["evidence-benign-total"] == "30"
    assert data_attrs["environment"] == "simulated"


def test_presentation_page_zero_never_looks_like_attack_counting():
    d = build_evidence_dashboard(load_evidence())
    page = presentation_page(d)
    assert "12 attacks blocked" not in page
    assert "0 false" not in page


def test_presentation_page_exposes_source_provenance_status():
    d = build_evidence_dashboard(load_evidence())
    page = presentation_page(d)

    assert 'data-source-provenance="match"' in page
    assert "SOURCE TREE" in page
    assert "STATUS: VERIFIED SOUND" in page
    assert "LOCKED EVIDENCE · 16 / 16 PASS · VERIFIED" in page


def _render_for(action: str) -> dict:
    from tests.test_judge import StanceLLM

    run = run_judge("opencode", "normal", llm=StanceLLM("opencode", action))
    assert run.error is None
    return {"run": run, "html": render_main_view(run), "attrs": _attrs(render_main_view(run))}


def test_judge_review_label_and_tool_stage():
    out = _render_for("block_ip")
    assert out["run"].decision == "REVIEW"
    assert 'data-decision-label="REVIEW NOT EXECUTED"' in out["html"]
    assert "REVIEW NOT EXECUTED" in out["html"]
    assert "SIMULATED TOOL" in out["html"]
    assert out["attrs"]["tool-simulated"] == "1"
    assert out["attrs"]["tool-executed"] == "false"
    assert out["attrs"]["tool-status"] in ("refused_review", "unsupported")


def test_judge_block_label_and_tool_stage():
    out = _render_for("disable_user")
    assert out["run"].decision == "BLOCK"
    assert 'data-decision-label="BLOCKED SAFE FROM EXECUTION"' in out["html"]
    assert "BLOCKED SAFE FROM EXECUTION" in out["html"]
    assert out["attrs"]["tool-status"] == "refused_block"


def test_judge_stage_active_highlight():
    html = render_main_view(run_judge("opencode", "normal", llm=_stance_import("opencode")))
    assert 'id="stage-policy_gate" data-active="true"' in html
    assert 'id="stage-simulated_tool" data-active="true"' in html


def _stance_import(name):
    from tests.test_judge import StanceLLM

    return StanceLLM(name)


def test_judge_degraded_tier_label():
    from app.llm.base import LLMProvider, LLMResponse, ProviderUnavailable

    class FailingStance(LLMProvider):
        name = "opencode"

        def complete(self, system, user) -> LLMResponse:
            raise ProviderUnavailable("simulated transient outage", kind="timeout")

    run = run_judge("opencode", "normal", llm=FailingStance())
    assert run.error is None
    assert run.provider_used == "degraded"
    html = render_main_view(run)
    assert "DEGRADED TIER" in html
    assert "not counted as defense evidence" in html
    assert run_to_meta(run)["provider_tier"] == "degraded"


def test_judge_local_fallback_tier_label():
    from tests.test_judge import StanceLLM

    run = run_judge("opencode", "normal", llm=StanceLLM("local"))
    assert run.provider_used == "local"
    assert run.requested_provider == "opencode"
    meta = run_to_meta(run)
    assert meta["provider_tier"] == "local_fallback"
    assert "LOCAL FALLBACK" in render_main_view(run)


def test_run_to_meta_includes_presentation_fields():
    from tests.test_judge import StanceLLM

    meta = run_to_meta(run_judge("opencode", "normal", llm=StanceLLM("opencode")))
    assert meta["decision"] == "ALLOW"
    assert meta["decision_label"] == "ALLOWED SIMULATED EXECUTION"
    assert meta["provider_tier"] == "live"