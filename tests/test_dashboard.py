from __future__ import annotations

import sys
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from app.dashboard import (
    DashboardData,
    ReportStore,
    build_dashboard,
    render_html,
    render_trial_html,
)
from app.dashboard.store import ReportStoreError
from app.experiment import DANGEROUS_ACTIONS
from app.models import (
    Action,
    AgentEvent,
    AttackCategory,
    BlueAssessment,
    BlueRoute,
    Decision,
    ExperimentConfig,
    ExperimentMode,
    ExperimentReport,
    ExperimentTrial,
    MutationKind,
    MutationMeta,
    PolicyDecision,
    RedAttack,
    RiskResult,
    SOCContext,
    SOCOutput,
    Trajectory,
    TrialOutcome,
)
from tests.fakes import FakeLLM

NO = ExperimentMode.NO_DEFENSE
WIENER = ExperimentMode.WIENER



def full_trial(
    trial_id: str,
    *,
    mode: ExperimentMode,
    action: Action,
    intended: Action | None,
    decision: Decision,
    executed: bool,
    provider: str = "opencode",
    seed: str = "RS-001",
    iteration: int = 0,
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
    error: str | None = None,
    trust: int = 40,
    deviation: int = 55,
    criticality: int = 80,
    privilege: int = 30,
    risk_score: float = 71.0,
    constraints: tuple[str, ...] = ("high_risk",),
    reasons: tuple[str, ...] = ("high_risk",),
    evidence: tuple[str, ...] = ("source:ids",),
    route: BlueRoute = BlueRoute.DETERMINISTIC,
    confidence: float = 0.9,
    latency: float = 22.0,
    generated: float = 0.0,
    detected: float = 8.0,
    intervened: float = 21.0,
    detail: str = "credential misuse reported on host h-7",
) -> ExperimentTrial:
    ctx = SOCContext(
        alert_id=trial_id,
        events=[
            AgentEvent(
                event_id=f"{trial_id}-e1",
                timestamp="0",
                source="ids",
                event_type="alert",
                severity=5,
                detail=detail,
            )
        ],
        notes="c1",
    )
    soc = SOCOutput(action=action, target="h-7", confidence=confidence, reasoning="r")
    traj = Trajectory(
        trial_id=trial_id,
        context=ctx,
        proposed_action=soc,
        provider_used=provider,
    )
    blue = BlueAssessment(
        context_trust=trust,
        behavior_deviation=deviation,
        action_criticality=criticality,
        privilege_impact=privilege,
        evidence_tags=list(evidence),
        route=route,
    )
    risk = RiskResult(risk_score=risk_score, triggered_constraints=list(constraints))
    policy = PolicyDecision(decision=decision, reason_tags=list(reasons), constraint_ids=["R1"])
    outcome = TrialOutcome(
        proposed_action=action.value,
        decision=decision,
        executed=executed,
        dangerous=action.value in DANGEROUS_ACTIONS,
        summary="s",
    )
    mutation = None if iteration == 0 else MutationMeta(kind=MutationKind.URGENCY_BOOST, rng_seed=1)
    attack = RedAttack(
        seed_id=seed,
        category=category,
        iteration=iteration,
        payload="p",
        mutation=mutation,
        intended_action=intended,
    )
    return ExperimentTrial(
        trial_id=trial_id,
        seed_id=seed,
        mode=mode,
        attack=attack,
        soc_output=soc,
        trajectory=traj,
        blue_assessment=blue,
        risk=risk,
        policy_decision=policy,
        latency_ms=latency,
        outcome=outcome,
        error=error,
        provider=provider,
        generated_at_ms=generated,
        detected_at_ms=detected,
        intervened_at_ms=intervened,
    )


def make_report(trials, *, modes=None, experiment_id="dash") -> ExperimentReport:
    cfg = ExperimentConfig(
        experiment_id=experiment_id,
        seed=7,
        provider=trials[0].provider if trials else "replay",
        modes=modes if modes is not None else [NO, WIENER],
    )
    return ExperimentReport(experiment_id=experiment_id, config=cfg, trials=trials)


class _AttrCollector(HTMLParser):
    """Extract every data-* attribute (attribute name -> value)."""

    def __init__(self) -> None:
        super().__init__()
        self.attrs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs) -> None:
        for k, v in attrs:
            if k.startswith("data-"):
                self.attrs[k[len("data-"):]] = v


def collect_attrs(html: str) -> dict[str, str]:
    p = _AttrCollector()
    p.feed(html)
    return p.attrs


def expected_attrs(view) -> dict[str, str]:
    def s(v: object) -> str:
        return "none" if v is None else str(v)

    return {
        "attack-type": s(view.attack_type),
        "seed": s(view.seed),
        "mutation": s(view.mutation),
        "iteration": s(view.iteration),
        "status": view.status,
        "alert": s(view.alert),
        "context": s(view.relevant_context),
        "proposed-action": s(view.proposed_action),
        "provider": s(view.provider),
        "context-trust": s(view.context_trust),
        "behavior-deviation": s(view.behavior_deviation),
        "action-criticality": s(view.action_criticality),
        "privilege-impact": s(view.privilege_impact),
        "route": s(view.route),
        "evidence-tags": ",".join(view.evidence_tags) if view.evidence_tags else "none",
        "risk-score": s(view.risk_score),
        "decision-margin": s(view.decision_margin),
        "triggered-constraints": ",".join(view.triggered_constraints) if view.triggered_constraints else "none",
        "decision": s(view.final_decision),
        "reason-tags": ",".join(view.reason_tags) if view.reason_tags else "none",
        "executed": s(view.executed),
    }



def test_dashboard_from_real_stored_report(tmp_path):
    from app.experiment import ExperimentRunner

    class _Clock:
        def __init__(self) -> None:
            self._t = 0.0

        def __call__(self) -> float:
            self._t += 0.05
            return self._t

    runner = ExperimentRunner(
        ExperimentConfig(experiment_id="dash-real", num_trials=2, seed=1),
        llm=FakeLLM(),
        clock=_Clock(),
    )
    report = runner.run()

    store = ReportStore(root=tmp_path)
    path = store.save(report)
    assert path.exists()
    assert path.name == "dash-real.json"

    reloaded = store.load_latest()
    assert reloaded is not None and reloaded.experiment_id == report.experiment_id
    data = build_dashboard(reloaded)
    assert data.experiment_id == "dash-real"
    assert data.seed == 1
    assert len(data.trials) == 30  # 3 modes x 5 seeds x (baseline + mutation)
    assert data.providers == ("fake",)
    assert data.is_replay_only is False
    assert all(t.mode in ("no_defense", "basic_prompt_defense", "wiener") for t in data.trials)


def test_exact_attribute_match_full_blocked_trial(tmp_path):
    report = make_report(
        [
            full_trial(
                "T-BLOCK",
                mode=WIENER,
                action=Action.ISOLATE_ENDPOINT,
                intended=Action.ISOLATE_ENDPOINT,
                decision=Decision.BLOCK,
                executed=False,
                iteration=1,
                seed="RS-002",
                evidence=("source:ids", "alert:valid"),
                constraints=("critical_action", "risk>70"),
                reasons=("hard_block", "approval_required"),
                intervened=33.0,
            )
        ]
    )
    data = build_dashboard(report)
    view = data.trials[0]
    assert view.status == "blocked"
    assert view.mutation == "urgency_boost"
    assert view.final_decision == "BLOCK"
    assert view.executed is False
    assert view.risk_score == 71.0
    html = render_trial_html(data, "T-BLOCK")
    attrs = collect_attrs(html)
    assert attrs == expected_attrs(view)


def test_review_and_allowed_statuses(tmp_path):
    report = make_report(
        [
            full_trial("T-REVIEW", mode=WIENER, action=Action.CHECK_ENDPOINT, intended=None,
                       decision=Decision.REVIEW, executed=False, provider="local",
                       trust=80, deviation=10, criticality=20, privilege=5, risk_score=55.0),
            full_trial("T-ALLOW", mode=WIENER, action=Action.GET_LOGS, intended=Action.GET_LOGS,
                       decision=Decision.ALLOW, executed=True, provider="opencode",
                       trust=95, deviation=5, criticality=10, privilege=15, risk_score=12.0),
        ]
    )
    data = build_dashboard(report)
    by_id = {t.trial_id: t for t in data.trials}
    assert by_id["T-REVIEW"].status == "review"
    assert by_id["T-REVIEW"].final_decision == "REVIEW"
    assert by_id["T-REVIEW"].executed is False
    assert by_id["T-ALLOW"].status == "allowed"
    assert by_id["T-ALLOW"].final_decision == "ALLOW"
    assert by_id["T-ALLOW"].executed is True
    assert data.providers == ("local", "opencode")
    assert data.is_replay_only is False

    attrs = collect_attrs(render_trial_html(data, "T-REVIEW"))
    assert attrs == expected_attrs(by_id["T-REVIEW"])


def test_no_defense_and_failed_trials_surface(tmp_path):
    report = make_report(
        [
            full_trial("N-PROP", mode=NO, action=Action.BLOCK_IP, intended=Action.BLOCK_IP,
                       decision=Decision.BLOCK, executed=False, provider="local",
                       trust=30, deviation=90, criticality=85, privilege=40, risk_score=88.0),
            full_trial("N-ERR", mode=NO, action=Action.GET_LOGS, intended=None,
                       decision=Decision.ALLOW, executed=False, error="provider boom",
                       provider="opencode", trust=50, deviation=50, criticality=50, privilege=50),
        ]
    )
    data = build_dashboard(report)
    by_id = {t.trial_id: t for t in data.trials}
    assert by_id["N-PROP"].status == "proposed"  # no_defense never blocks/executes
    assert by_id["N-PROP"].proposed_action == "block_ip"
    assert by_id["N-ERR"].status == "error"
    assert by_id["N-ERR"].executed is None or by_id["N-ERR"].executed is False
    assert by_id["N-ERR"].provider == "opencode"


def test_context_and_evidence_escaping(tmp_path):
    report = make_report(
        [
            full_trial(
                "T-XSS",
                mode=WIENER,
                action=Action.GET_LOGS,
                intended=Action.GET_LOGS,
                decision=Decision.ALLOW,
                executed=True,
                evidence=("<script>alert(1)</script>", 'quote"value'),
                detail='<img src=x onerror=alert(2)> & "quoted"',
            )
        ]
    )
    html = render_html(build_dashboard(report), selected="T-XSS")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert '&quot;quoted&quot;' in html
    assert '<img src=x' not in html



def test_replay_only_report_flagged(tmp_path):
    replay = make_report(
        [full_trial("R-1", mode=WIENER, action=Action.GET_LOGS, intended=Action.GET_LOGS,
                    decision=Decision.ALLOW, executed=True, provider="replay")]
    )
    data = build_dashboard(replay)
    assert data.is_replay_only is True
    assert data.providers == ("replay",)
    html = render_html(data)
    assert "REPLAY MODE" in html
    assert 'data-replay-mode="true"' in html


def test_mixed_providers_not_replay_only(tmp_path):
    report = make_report(
        [
            full_trial("A-1", mode=WIENER, action=Action.GET_LOGS, intended=Action.GET_LOGS,
                       decision=Decision.ALLOW, executed=True, provider="opencode"),
            full_trial("A-2", mode=WIENER, action=Action.GET_LOGS, intended=Action.GET_LOGS,
                       decision=Decision.ALLOW, executed=True, provider="replay"),
        ]
    )
    assert build_dashboard(report).is_replay_only is False



def test_metrics_panel_exact_values(tmp_path):
    report = make_report(
        [
            full_trial("M1", mode=WIENER, action=Action.ISOLATE_ENDPOINT, intended=Action.ISOLATE_ENDPOINT,
                       decision=Decision.ALLOW, executed=True, risk_score=75.0),
            full_trial("M2", mode=WIENER, action=Action.BLOCK_IP, intended=Action.BLOCK_IP,
                       decision=Decision.BLOCK, executed=False, risk_score=90.0),
            full_trial("M3", mode=WIENER, action=Action.CHECK_ENDPOINT, intended=None,
                       decision=Decision.REVIEW, executed=False, risk_score=40.0),
            full_trial("N1", mode=NO, action=Action.BLOCK_IP, intended=Action.BLOCK_IP,
                       decision=Decision.BLOCK, executed=False, risk_score=90.0),
        ],
        modes=[NO, WIENER],
    )
    data = build_dashboard(report)
    mv = data.metrics
    def r6(v: float) -> float:
        return round(v, 6)

    assert mv.uapr == r6(2 / 3)  # (1.0 - 1/3) / 1.0: baseline counts the dangerous proposal
    rows = {r.mode: r for r in mv.rows}
    w = rows["wiener"]
    assert (w.attempts, w.asr, w.uar, w.fir) == (3, r6(2 / 3), r6(1 / 3), 1.0)  # M1 adopted+exec, M2 adopted then blocked, M3 benign wrongly reviewed
    assert w.tti_ms == 13.0 and w.e2e_ms == 21.0  # defaults: detected=8, intervened=21, generated=0
    n = rows["no_defense"]
    assert (n.attempts, n.asr, n.uar) == (1, 1.0, 1.0)

    # The rendered metrics table carries identical values.
    html = render_html(data)
    assert f'data-uapr="{r6(2 / 3)}"' in html
    assert 'data-baseline="no_defense"' in html
    assert 'data-defended="wiener"' in html
    assert f'data-asr="{r6(2 / 3)}"' in html
    assert 'data-uar="0.333333"' in html


def test_undefined_metrics_render_as_dash(tmp_path):
    report = make_report([], modes=[WIENER])
    data = build_dashboard(report)
    assert data.metrics.uapr is None
    html = render_html(data)
    assert 'data-uapr="none"' in html
    assert "—" in html  # undefined values never render as a fake 0



def test_empty_store_empty_dashboard(tmp_path):
    store = ReportStore(root=tmp_path)
    assert store.load_latest() is None
    data = DashboardData.empty()
    assert data.experiment_id == "(none)"
    assert data.trials == ()
    html = render_html(data)
    assert 'data-experiment-id="(none)"' in html
    assert "No stored experiment data yet." in html
    assert 'data-provider="none"' in html


def test_corrupt_store_raises_reported_error(tmp_path):
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    store = ReportStore(root=tmp_path)
    with pytest.raises(ReportStoreError):
        store.load_latest()


def test_api_dashboard_endpoint(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.setenv("WIENER_EXPERIMENT_STORE", str(tmp_path))
    store = ReportStore()
    report = make_report(
        [
            full_trial("API-1", mode=WIENER, action=Action.BLOCK_IP, intended=Action.BLOCK_IP,
                       decision=Decision.BLOCK, executed=False, provider="opencode",
                       seed="RS-001", iteration=1),
        ]
    )
    store.save(report)

    c = TestClient(app)
    resp = c.get("/dashboard")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert 'data-experiment-id="dash"' in resp.text
    assert 'href="/dashboard?trial=API-1"' in resp.text

    data = c.get("/dashboard?format=json").json()
    assert "empty" not in data
    assert data["experiment_id"] == "dash"
    assert data["metrics"]["uapr"] is None  # baseline has no attempts
    trial = data["trials"][0]
    assert trial["trial_id"] == "API-1"
    assert trial["risk_score"] == 71.0
    assert trial["final_decision"] == "BLOCK"


def test_api_dashboard_endpoint_empty_store(monkeypatch, tmp_path):
    import os

    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.setenv("WIENER_EXPERIMENT_STORE", str(tmp_path))
    c = TestClient(app)
    resp = c.get("/dashboard")
    assert resp.status_code == 200
    assert "No stored experiment data yet." in resp.text
    assert c.get("/dashboard?format=json").json() == {"empty": True}


def test_report_store_supports_explicit_path_override(tmp_path):
    store = ReportStore(root=tmp_path / "nested" / "dir")
    report = make_report([full_trial("X", mode=WIENER, action=Action.GET_LOGS, intended=Action.GET_LOGS,
                                     decision=Decision.ALLOW, executed=True, provider="replay")])
    path = store.save(report)
    assert path.parent.name == "dir"
    loaded = store.load(path)
    assert loaded.experiment_id == "dash"