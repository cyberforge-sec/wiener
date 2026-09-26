from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel

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


_JUDGE_CSS_PATH = Path(__file__).resolve().parent.parent / "judge" / "static" / "tailwind.css"


@router.get("/judge/tailwind.css")
def judge_tailwind_css() -> FileResponse:
    """Vendored Judge UI stylesheet.

    Served from the repository instead of cdn.tailwindcss.com so the Judge
    page needs no network access and runs no third-party script. Regenerate
    with ./scripts/build_judge_css.sh.
    """
    return FileResponse(
        _JUDGE_CSS_PATH,
        media_type="text/css",
        headers={"Cache-Control": "public, max-age=3600"},
    )


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
    """Last committed run, so a page reload does not lose the judge's result.

    Returns the rendered view alongside the metadata: the page cannot rebuild
    the panel from summary fields, and re-running the scenario to recover it
    would be a different request (a different slot) and therefore dishonest.
    """
    session = get_session()
    if session.last is None:
        return {"last": None}
    last = session.last
    return {
        "last": {
            **run_to_meta(last),
            "html": render_main_view(last),
            "stopped_reason": last.stopped_reason,
            "risk_score": last.result.risk.risk_score if last.result else None,
            "tool_executed": last.result.tool_result.executed if last.result and last.result.tool_result else None,
            "adaptive_trace": [
                {
                    "iteration": step.iteration,
                    "decision": step.decision,
                    "risk": step.risk,
                    "kind": step.kind,
                }
                for step in last.adaptive_trace
            ],
        }
    }
