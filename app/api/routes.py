from __future__ import annotations

import dataclasses
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from ..dashboard import DashboardData, ReportStore, build_dashboard, render_html
from ..present.evidence import build_evidence_dashboard
from ..present.render import presentation_page
from ..judge import (
    JudgeInputError,
    get_session,
    live_store,
    provider_label,
    render_main_view,
    render_page,
    run_to_meta,
    scenario_label,
    sse_lines,
)
from ..llm.factory import active_provider_name
from ..models import (
    BlueAssessment,
    PolicyDecision,
    RiskResult,
    SOCContext,
    SOCOutput,
    Trajectory,
)
from ..orchestration.pipeline import Pipeline, PipelineResult

router = APIRouter()

_NO_CACHE = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

_LOGO_PATH = Path(__file__).resolve().parent.parent / "judge" / "logo.png"

_pipeline: Pipeline | None = None


def get_pipeline() -> Pipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = Pipeline()
    return _pipeline


class PipelineResponse:
    def __init__(self, res: PipelineResult) -> None:
        self.trajectory = res.trajectory
        self.assessment = res.assessment
        self.risk = res.risk
        self.decision = res.decision
        self.soc_provider = res.soc_provider


@router.post("/analyze")
def analyze(context: SOCContext) -> dict:
    res = get_pipeline().run(context)
    return {
        "trajectory": res.trajectory.model_dump(),
        "soc_output": res.trajectory.proposed_action.model_dump(),
        "assessment": res.assessment.model_dump(),
        "risk": res.risk.model_dump(),
        "decision": res.decision.model_dump(),
        "soc_provider": res.soc_provider,
    }


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "provider": active_provider_name()}


def _latest_dashboard(trial: str | None):
    """Preferred presentation path: the LOCKED authoritative run. Falls back to
    the latest stored generic ExperimentReport only when the locked artifacts
    are missing or unreadable."""
    data = build_evidence_dashboard()
    if data.evidence is not None:
        return data
    report = ReportStore().load_latest()
    return build_dashboard(report) if report is not None else None


@router.get("/dashboard")
def dashboard(trial: str | None = None, format: str = "html"):
    """Render the WIENER dashboard from the stored experiment report.

    The dashboard is a read-only VIEW of persisted ExperimentReport data;
    it never runs the pipeline or fabricates values.

    Served with ``Cache-Control: no-store`` so the page always reflects the
    current evidence artifact (locked run resolution happens per request).
    """
    data = _latest_dashboard(trial)
    if data is None:
        empty = DashboardData.empty()
        if format == "json":
            return JSONResponse({"empty": True}, headers=_NO_CACHE)
        return HTMLResponse(render_html(empty), headers=_NO_CACHE)

    if format == "json":
        return JSONResponse(dataclasses.asdict(data), headers=_NO_CACHE)
    if data.evidence is not None:
        return HTMLResponse(presentation_page(data, selected=trial), headers=_NO_CACHE)
    return HTMLResponse(render_html(data, selected=trial), headers=_NO_CACHE)



class JudgeRunRequest(BaseModel):
    provider: str
    scenario: str


def _judge_payload(run, html: str) -> dict:
    payload = run_to_meta(run)
    payload["ok"] = run.error is None
    payload["html"] = html
    return payload


@router.get("/judge")
def judge_page() -> HTMLResponse:
    """Interactive judge page: provider/scenario selects + Run/Reset/Replay.

    Never cached: the live-pipeline JS is inline, so a cached copy renders the
    pre-transport-fix pipeline (numeric nodes, lost stage events). Serve fresh.
    """
    response = HTMLResponse(render_page())
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@router.get("/judge/logo")
def judge_logo() -> FileResponse:
    """The WIENER wordmark logo shown beside the brand name in the top bar."""
    return FileResponse(_LOGO_PATH, media_type="image/png")


@router.post("/judge/run")
def judge_run(body: JudgeRunRequest, stream: bool = Query(False)) -> dict:
    """Run a judge scenario.

    Default (no ``?stream=1``): synchronous, the response carries the full
    rendered result, exactly as before. With ``?stream=1``: the run begins in
    a background thread and ``{status: "started", run_id}`` returns at once so
    the client can subscribe to ``GET /judge/stream?run_id=`` for real stage
    events as they are produced.
    """
    try:
        if stream:
            slot = get_session().next_slot(body.scenario)
            run_id = live_store.start(body.provider, body.scenario, slot=slot)
            return {
                "ok": True,
                "status": "started",
                "run_id": run_id,
                "requested_provider": body.provider,
                "provider_label": provider_label(body.provider),
                "scenario": body.scenario,
                "scenario_label": scenario_label(body.scenario),
            }
        run = get_session().run(body.provider, body.scenario)
    except JudgeInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _judge_payload(run, render_main_view(run))


@router.get("/judge/stream")
def judge_stream(run_id: int) -> StreamingResponse:
    """Live SSE stream for a started judge run.

    Yields one ``{stage}_{phase}`` lifecycle event per real pipeline stage
    (order and values come from the engine, never from the client) and ends
    with ``run_completed`` or ``run_failed`` carrying the authoritative
    rendered result. Runs are broadcast: every attached viewer sees the same
    full ordered stream, and the run is only purged once no viewer remains.
    """
    try:
        run = live_store.get_run(run_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown run stream: {run_id}")

    def gen():
        for item in live_store.iter_run(run):
            yield sse_lines(item)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/judge/replay")
def judge_replay() -> dict:
    session = get_session()
    if session.last_request is None:
        raise HTTPException(status_code=400, detail="nothing to replay yet — press Run first")
    run = session.replay()
    assert run is not None  # last_request was not None, so replay produced a run
    return _judge_payload(run, render_main_view(run))


@router.post("/judge/reset")
def judge_reset() -> dict:
    get_session().reset()
    return {"ok": True}


@router.get("/judge/state")
def judge_state() -> dict:
    session = get_session()
    if session.last is None:
        return {"last": None}
    return {"last": run_to_meta(session.last)}
