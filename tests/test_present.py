from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from html.parser import HTMLParser

import pytest
from fastapi import HTTPException

from app.dashboard.dashboard import DashboardData
from app.judge.judge_mode import run_judge
from app.judge.render import render_main_view, run_to_meta
from app.present.evidence import authoritative_dir, build_evidence_dashboard, load_evidence
from app.present.render import presentation_page


def _pct(value):
    return "—" if value is None else f"{value * 100:.1f}%"


def test_load_evidence_authoritative_facts():
    b = load_evidence()
    assert b is not None
    # The resolver picks the newest genuinely LOCKED_VERIFIED run. Asserted
    # against the resolver's own choice rather than a pinned id, so this test
    # keeps meaning something when a newer lock lands.
    assert b.experiment_id == authoritative_dir().name
    assert b.evidence_status == "LOCKED_VERIFIED"
    assert b.locked_at is not None
    assert (b.code_fingerprint_root or "").strip()
    # Provenance is RECOMPUTED against the current tree, never read back from
    # the manifest. The manifest recorded MATCH at lock time; the honest current
    # value depends on how far the code has moved since, so the test asserts the
    # mechanism, not a frozen constant.
    assert b.source_provenance["status"] in {"MATCH", "STALE", "UNKNOWN"}
    assert b.source_provenance["recorded_status"] == "MATCH"
    assert b.source_provenance.get("current_root_hash")
    assert b.n_trials == 135, b.n_trials
    assert b.trials_per_mode == 45
    assert b.modes == ("no_defense", "basic_prompt_defense", "wiener")
    assert b.malicious_total == 105 and b.benign_total == 30
    assert b.duplicate_trial_mode_ids == 0
    assert b.raw_completion_present == 135 and b.raw_completion_total == 135
    assert b.degraded_count == 0
    # Whatever transport the resolved run recorded, over all of its rows.
    assert sum(b.provider_counts.values()) == b.n_trials
    assert len(b.provider_counts) == 1, "a single run is served by one transport"
    # The defense-path story, as a STRUCTURE rather than a run's tallies: every
    # dangerous proposal is accounted for by a gate decision, and none executed.
    assert b.proposals > 0
    assert b.executed == 0, "a locked run must contain no executed dangerous action"
    assert (b.blocked + b.reviewed) == b.proposals
    # Stored metrics, shown verbatim. The invariant COUNT is a property of the
    # checklist, not of the run, so it is read from the bundle.
    assert b.validation_status == "PASS"
    assert b.validation_pass == b.validation_invariants
    assert b.validation_invariants >= 16
    assert b.uapr == 1.0
    w = b.by_mode["wiener"]
    assert w.uar == 0.0 and w.fir == 0.0 and w.attempts == 45
    # Historical block is strictly separate, UAR only.
    assert b.history is not None
    assert b.history.n_trials == 30
    assert b.history.uar_by_mode["wiener"] == 0.0
    # A real content hash of this bundle's own trials file, not a constant.
    assert len(b.trials_sha256) == 64 and all(c in "0123456789abcdef" for c in b.trials_sha256)


def test_load_evidence_missing_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("WIENER_EXPERIMENT_STORE", str(tmp_path))
    assert load_evidence() is None


def test_build_evidence_dashboard_attaches_bundle():
    b = load_evidence()
    d = build_evidence_dashboard(b)
    assert isinstance(d, DashboardData)
    assert d.evidence is b
    # Structure, not frozen values: the trial count and per-mode denominators
    # come from whichever bundle the resolver selected.
    assert len(d.trials) == b.n_trials == 135
    assert d.metrics.uapr == b.uapr
    assert d.providers == tuple(sorted({t.provider for t in d.trials}))


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
    b = d.evidence
    assert b is not None
    # Exact competition wording, never "12 attacks blocked". Every figure is
    # read from the resolved bundle, so this keeps asserting the wording AND
    # that the page sources it from evidence, without freezing a run's numbers.
    assert f"Dangerous proposals reaching SOC-agent stage: <b>{b.proposals}</b>" in page
    assert f"Unsafe tool executions: <b>{b.executed}</b>" in page
    assert f"{b.blocked} BLOCK" in page and f"{b.reviewed} REVIEW" in page
    wiener = b.by_mode["wiener"]
    assert (
        f"FIR {_pct(wiener.fir)} — {b.benign_total} benign trials; "
        f"{wiener.incorrect_interventions} incorrect interventions"
    ) in page
    # Historical demo.json values must be quarantined OUT of the main page.
    assert "HISTORICAL" not in page
    assert "40.0%" not in page and "70.0%" not in page
    assert "demo.json" not in page
    # The header badge states the bundle's OWN recorded verdict, and the
    # current-tree comparison is reported separately in the provenance panel.
    # Neither is a hardcoded string: both follow the resolved bundle.
    assert "CANDIDATE EVIDENCE" not in page
    assert f"LOCKED VERIFIED · {b.validation_pass} / {b.validation_invariants} PASS" in page
    # The provenance panel is where "does this describe the current tree?" lives.
    assert "STATUS: " in page
    # Five areas + evidence + provenance.
    for area in ("RED AI", "SOC AGENT", "BLUE AI", "RISK ENGINE / POLICY GATE", "METRICS"):
        assert area in page
    assert "Provenance" in page
    # The lock phrase follows the recomputed soundness, not a constant.
    assert ("AUTHORITATIVE DATA LOCKED" in page) != ("AUTHORITATIVE DATA NOT VERIFIED" in page)
    assert f"data/experiments/{b.source_dir}/" in page
    assert (data_attrs := _attrs(page))
    assert data_attrs["authoritative"] == "true"
    assert data_attrs["evidence-proposals"] == str(b.proposals)
    assert data_attrs["evidence-blocked"] == str(b.blocked)
    assert data_attrs["evidence-reviewed"] == str(b.reviewed)
    assert data_attrs["unsafe-tool-executions"] == str(b.executed)
    assert data_attrs["uapr"] == str(b.uapr)
    assert data_attrs["validation"] == b.validation_status
    assert data_attrs["fir-total"] == str(wiener.fir)
    assert data_attrs["total-trials"] == str(b.n_trials)
    assert data_attrs["evidence-benign-total"] == str(b.benign_total)
    assert data_attrs["environment"] == "simulated"


def test_presentation_page_zero_never_looks_like_attack_counting():
    d = build_evidence_dashboard(load_evidence())
    page = presentation_page(d)
    assert "12 attacks blocked" not in page
    assert "0 false" not in page


def test_presentation_page_exposes_source_provenance_status():
    bundle = load_evidence()
    d = build_evidence_dashboard(bundle)
    page = presentation_page(d)

    status = bundle.source_provenance["status"]
    assert f'data-source-provenance="{status.lower()}"' in page
    # The row is about the CURRENT tree; the artifacts have their own row.
    assert "CURRENT TREE" in page
    # The headline claim follows the recomputed provenance, not the manifest.
    # Current-tree comparison drives the provenance panel only.
    if status == "match":
        assert "STATUS: VERIFIED SOUND" in page
    else:
        # The verdict keeps the artifacts' integrity explicit, so a moved tree
        # is never read as invalid results.
        assert "STATUS: ARTIFACTS INTACT" in page
        assert "PRODUCED BY AN EARLIER REVISION" in page
    # The header reports the stored lock verdict, which is independent of it.
    assert f"LOCKED VERIFIED · {bundle.validation_pass} / {bundle.validation_invariants} PASS" in page


def test_dashboard_trials_come_from_the_bundles_own_directory():
    """Regression: a supplied bundle must never be paired with another run's
    trials (metrics from one experiment, ledger rows from another)."""
    bundle = load_evidence()
    data = build_evidence_dashboard(bundle)
    assert data.trials, "expected trials for the loaded evidence"
    # The loaded bundle is the locked run; the metrics and the drill-down must
    # come from the same experiment id.
    assert data.experiment_id == bundle.experiment_id
    # Every rendered trial must exist in the bundle's own directory.
    bundle_dir = Path(__file__).resolve().parent.parent / "data" / "experiments" / bundle.source_dir
    assert bundle_dir.exists()
    assert (bundle_dir / "trials.jsonl").exists()


def test_dashboard_renders_stored_evidence_values():
    bundle = load_evidence()
    wiener = replace(bundle.by_mode["wiener"], incorrect_interventions=3)
    altered = replace(
        bundle,
        by_mode={**bundle.by_mode, "wiener": wiener},
        recompute_diffs=("uar mismatch",),
        validation_status="FAIL",
        validation_pass=15,
        duplicate_trial_mode_ids=2,
        evidence_status="CANDIDATE",
    )

    page = presentation_page(build_evidence_dashboard(altered))

    # A degraded bundle must report its own numbers, not the healthy ones.
    assert "3 False Positives" in page
    assert "1 Detected" in page
    assert f"{altered.validation_pass} / {altered.validation_invariants}" in page
    assert "2 Collisions" in page
    assert "CANDIDATE EVIDENCE" in page


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

def test_corrupt_evidence_fails_closed_instead_of_rendering_empty(tmp_path, monkeypatch):
    """A present-but-unparseable evidence directory must not look like an empty run."""
    import app.api.routes as routes
    from app.present.evidence import EvidenceUnavailable, load_evidence, load_errors

    broken = tmp_path / "authoritative_broken"
    broken.mkdir()
    (broken / "trials.jsonl").write_text("{not json}\n", encoding="utf-8")
    (broken / "metrics.json").write_text("{}", encoding="utf-8")

    # Non-strict: recorded, not raised.
    assert load_evidence(broken) is None
    assert load_errors, "failure reason must be recorded"

    # Strict: raised.
    with pytest.raises(EvidenceUnavailable):
        load_evidence(broken, strict=True)

    # And the route surfaces it as 503, not a blank dashboard.
    monkeypatch.setattr(routes, "build_evidence_dashboard", lambda *a, **k: DashboardData.empty())
    with pytest.raises(HTTPException) as ei:
        routes._latest_dashboard(None)
    assert ei.value.status_code == 503
    assert "could not be parsed" in ei.value.detail


def test_missing_evidence_is_not_an_error(tmp_path):
    """Absent evidence is a normal state (fresh clone), not a failure."""
    from app.present.evidence import load_evidence, load_errors

    absent = tmp_path / "does_not_exist"
    assert load_evidence(absent) is None
    assert load_errors == []


def test_source_provenance_is_recomputed_not_read_from_the_manifest(tmp_path):
    """The manifest's `source_provenance: MATCH` was true when the run was
    locked. After any code change it is a historical fact, and the dashboard
    must not present it as the current state."""
    import json
    import shutil
    from dataclasses import replace as dc_replace

    from app.present.evidence import _load

    src = Path(__file__).resolve().parent.parent / "data" / "experiments"
    live = load_evidence()
    assert live is not None
    source_dir = src / live.source_dir
    copy = tmp_path / live.source_dir
    shutil.copytree(source_dir, copy)

    # Tamper with the current tree's fingerprint: the stored one can no longer match.
    fp = json.loads((copy / "code_fingerprint.json").read_text(encoding="utf-8"))
    fp["file_hashes"] = {k: "0" * 64 for k in fp["file_hashes"]}
    fp["root_hash"] = "f" * 64
    (copy / "code_fingerprint.json").write_text(json.dumps(fp), encoding="utf-8")

    bundle = _load(copy)
    # The manifest still says MATCH ...
    manifest = json.loads((copy / "evidence_manifest.json").read_text(encoding="utf-8"))
    assert manifest["source_provenance"]["status"] == "MATCH"
    # ... but the recomputed value does not.
    assert bundle.source_provenance["status"] == "STALE"
    assert bundle.source_provenance["recorded_status"] == "MATCH"
    assert "earlier revision" in bundle.source_provenance["note"]

    # And a locked bundle that is not sound must not claim VERIFIED.
    page = presentation_page(build_evidence_dashboard(bundle))
    assert "VERIFIED SOUND" not in page
    assert "REVIEW REQUIRED" in page


def test_unknown_provenance_when_fingerprint_absent(tmp_path):
    import json
    import shutil

    from app.present.evidence import _load

    live = load_evidence()
    assert live is not None
    src = Path(__file__).resolve().parent.parent / "data" / "experiments" / live.source_dir
    copy = tmp_path / live.source_dir
    shutil.copytree(src, copy)
    (copy / "code_fingerprint.json").unlink()

    bundle = _load(copy)
    assert bundle.source_provenance["status"] == "UNKNOWN"
    assert bundle.source_provenance["recorded_status"] == "MATCH"


def test_dashboard_page_makes_no_external_requests():
    """The dashboard must render identically offline: no webfont, no CDN.

    Both pages previously pulled Google Fonts, which meant a judge's browser
    silently contacted a third party on every view of the evidence page.
    """
    page = presentation_page(build_evidence_dashboard(load_evidence()))
    for banned in ("fonts.googleapis.com", "fonts.gstatic.com", "cdn."):
        assert banned not in page, f"dashboard must not reference {banned}"
    # System stack, declared in-page.
    assert "-apple-system" in page
