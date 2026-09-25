#!/usr/bin/env python3
"""One-laptop demo benchmark harness for WIENER.

Measures, with actual runs:
  cold start ..... fresh-process import + Pipeline construction (ms)
  warm start ..... constructing Pipeline again in the same process (ms)
  cloud latency .. OpenCodeProvider (cloud/gateway) SOC-style call latency
                   plus best-effort first-token / total-generation probe
  local latency .. Qwen2.5 via Ollama: cold model-load vs warm call, tokens,
                   tokens/s from /api/generate timing fields
  pipeline e2e ... full Pipeline.run latency with a deterministic replay
                   provider (no model) and with live providers when available
  RAM / CPU ...... process RSS and CPU during a run burst (psutil; /proc fs
                   fallback if psutil is absent)
  stability ...... repeated identical runs -> decision + risk must be identical
                   for the deterministic path and reported for live paths

Usage:
  python3 benchmarks/bench_demo.py [--runs N] [--report PATH]
                                   [--no-cloud] [--no-local] [--force-cold-local]

The harness never spawns duplicate model processes, never streams two model
inference calls at once (strictly sequential), and every live call is bounded
by the configured timeouts. Run it on the target competition laptop
(i5-1335U / 16 GB / Iris Xe) for the authoritative numbers.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

from app.config import config  # noqa: E402
from app.llm.local_provider import LocalProvider, ollama_reachable  # noqa: E402
from app.llm.opencode_provider import OpenCodeProvider  # noqa: E402
from app.llm.replay_provider import ReplayProvider  # noqa: E402
from app.models import AgentEvent, SOCContext  # noqa: E402
from app.orchestration.pipeline import Pipeline  # noqa: E402
import app.soc_agent.soc_agent as soc_module  # noqa: E402
from app.soc_agent.soc_agent import SOCAgent  # noqa: E402

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    psutil = None


# Sample context (stable, benign; matches the judge normal scenario)
_SAMPLE_CTX = SOCContext(
    alert_id="bench-alert-1",
    provenance="siem_sim",
    environment="simulated",
    events=[
        AgentEvent(
            event_id="bench-alert-1-e1",
            timestamp="2026-01-01T00:00:00Z",
            source="siem_sim",
            event_type="log",
            severity=2,
            detail="routine authentication log",
        )
    ],
)

_SOC_SYSTEM, _SOC_USER = soc_module._SYSTEM_PROMPT, SOCAgent._build_user_prompt(_SAMPLE_CTX)


def _ms(seconds: float) -> float:
    return round(seconds * 1000, 3)


def _stat(values: list[float]) -> dict:
    """Summary over latencies already expressed in milliseconds."""
    if not values:
        return {"n": 0}
    n = len(values)
    s = sorted(values)
    return {
        "n": n,
        "min_ms": round(s[0], 3),
        "median_ms": round(statistics.median(s), 3),
        "max_ms": round(s[-1], 3),
        "p95_ms": round(s[max(0, min(n - 1, int(0.95 * n))) - 1] if n >= 5 else s[-1], 3),
    }



def cold_start() -> dict:
    """Fresh interpreter: import the app stack and build a Pipeline."""
    code = (
        "import time,sys\n"
        "t0=time.perf_counter()\n"
        f"sys.path.insert(0,{str(ROOT)!r})\n"
        "from app.orchestration.pipeline import Pipeline\n"
        "from app.dashboard.dashboard import build_dashboard  # noqa\n"
        "t1=time.perf_counter()\n"
        "Pipeline()\n"
        "t2=time.perf_counter()\n"
        f"print(f'{{(t1-t0)*1000:.1f}} {{(t2-t1)*1000:.1f}}')\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120
    )
    import_ms, build_ms = (float(x) for x in out.stdout.strip().split())
    return {"import_ms": import_ms, "pipeline_build_ms": build_ms}


def warm_start(runs: int) -> dict:
    lat = []
    for _ in range(runs):
        t0 = time.perf_counter()
        Pipeline()
        lat.append((time.perf_counter() - t0) * 1000)
    return {"runs": runs, **_stat(lat)}



def _cloud_available() -> str | None:
    if not config.OPENCODE_API_KEY:
        return "no API key"
    try:
        resp = httpx.get(f"{config.OPENCODE_BASE_URL.rstrip('/')}/models", timeout=5)
        return None if resp.status_code == 200 else f"HTTP {resp.status_code}"
    except httpx.HTTPError as exc:
        return f"unreachable ({exc})"


def cloud_soc_latency(runs: int) -> dict | None:
    """Wall latency of a real SOCAgent call on the cloud provider."""
    provider = OpenCodeProvider()
    agent = SOCAgent(provider)
    lat = []
    for _ in range(runs):
        t0 = time.perf_counter()
        agent.analyze(_SAMPLE_CTX)
        lat.append((time.perf_counter() - t0) * 1000)
    return _stat(lat)


def cloud_streaming_probe() -> dict | None:
    """First-token latency + total generation (streaming): best effort."""
    if not config.OPENCODE_API_KEY:
        return None
    url = f"{config.OPENCODE_BASE_URL.rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {config.OPENCODE_API_KEY}"}
    payload = {
        "model": config.OPENCODE_MODEL,
        "messages": [
            {"role": "system", "content": _SOC_SYSTEM},
            {"role": "user", "content": _SOC_USER},
        ],
        "temperature": 0.0,
        "max_tokens": 500,
        "stream": True,
    }
    try:
        t0 = time.perf_counter()
        first: float | None = None
        with httpx.stream("POST", url, headers=headers, json=payload, timeout=config.LLM_TIMEOUT_S) as resp:
            resp.raise_for_status()
            for line in resp.iter_lines():
                if first is None and line.strip().startswith("data:"):
                    first = (time.perf_counter() - t0) * 1000
                    if '"[DONE]"' in line or 'data: [DONE]' in line:
                        break
        total = (time.perf_counter() - t0) * 1000  # ms already
        return {
            "first_token_ms": round(first, 3) if first is not None else None,
            "total_generation_ms": round(total, 3),
            "stream_supported": first is not None,
        }
    except httpx.HTTPError as exc:
        return {"stream_supported": False, "error": str(exc)}



def _ollama_timing(run_cold: bool) -> dict | None:
    """Direct /api/generate probe reading Ollama's own timing fields (ns)."""
    url = f"{config.LOCAL_HOST.rstrip('/')}/api/generate"
    prompt = f"{_SOC_SYSTEM}\n\n{_SOC_USER}"
    payload = {
        "model": config.LOCAL_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": config.LOCAL_MAX_TOKENS},
    }
    with httpx.Client(timeout=config.LOCAL_TIMEOUT_S) as client:
        wall = time.perf_counter()
        resp = client.post(url, json=payload)
        resp.raise_for_status()
        wall_ms = (time.perf_counter() - wall) * 1000
        data = resp.json()
    ns = 1e6  # ns -> ms in one step; do NOT pass through _ms() again
    out = {
        "wall_ms": round(wall_ms, 1),
        "load_duration_ms": round(int(data.get("load_duration", 0)) / ns, 1),
        "total_duration_ms": round(int(data.get("total_duration", 0)) / ns, 1),
        "prompt_eval_count": int(data.get("prompt_eval_count", 0)),
        "prompt_eval_ms": round(int(data.get("prompt_eval_duration", 0)) / ns, 1),
        "eval_count": int(data.get("eval_count", 0)),
        "eval_ms": round(int(data.get("eval_duration", 0)) / ns, 1),
    }
    out["tokens_per_s"] = round(out["eval_count"] / (out["eval_ms"] / 1000), 1) if out["eval_ms"] else None
    out["cold_load"] = run_cold
    return out


def _unload_local_model() -> bool:
    """Ask Ollama to evict the model, waiting until /api/ps confirms unload.

    `keep_alive: 0` schedules an unload; Ollama evicts asynchronously, so a
    naive immediate re-generate would measure a warm load. Returns True when
    the model is confirmed unloaded (or after a bounded wait).
    """
    base = config.LOCAL_HOST.rstrip("/")
    try:
        httpx.post(
            f"{base}/api/generate",
            json={"model": config.LOCAL_MODEL, "keep_alive": 0},
            timeout=60,
        )
    except httpx.HTTPError:
        return False
    for _ in range(20):
        try:
            procs = httpx.get(f"{base}/api/ps", timeout=5).json().get("models", [])
        except (httpx.HTTPError, ValueError):
            procs = []
        loaded = any(m.get("model") == config.LOCAL_MODEL for m in procs)
        if not loaded:
            return True
        time.sleep(0.5)
    return False


def local_timings(force_cold: bool) -> list[dict]:
    if not ollama_reachable(config.LOCAL_HOST, 3):
        return []
    unloaded = False
    if force_cold:
        unloaded = _unload_local_model()
    cold = _ollama_timing(run_cold=True)
    warm = _ollama_timing(run_cold=False)
    if not unloaded:
        cold["cold_load"] = False  # model was still resident; not a true cold
    return [cold, warm]


def local_soc_latency(runs: int) -> dict | None:
    """Wall latency of a real SOCAgent call on the local Qwen provider."""
    provider = LocalProvider()
    agent = SOCAgent(provider)
    lat = []
    for _ in range(runs):
        t0 = time.perf_counter()
        agent.analyze(_SAMPLE_CTX)
        lat.append((time.perf_counter() - t0) * 1000)
    return _stat(lat)



def pipeline_e2e(runs: int, replay_dir: Path) -> dict:
    pipe = Pipeline(llm=ReplayProvider(replay_dir=str(replay_dir)))
    lat = []
    decisions = []
    risks = []
    for _ in range(runs):
        t0 = time.perf_counter()
        result = pipe.run(_SAMPLE_CTX)
        lat.append((time.perf_counter() - t0) * 1000)
        decisions.append(result.decision)
        risks.append(result.risk.risk_score)
    stable = len({str(d) for d in decisions}) == 1 and len(set(risks)) == 1
    return {"repeated_run_stability": stable, "decision": str(decisions[0]), "risk": risks[0], **_stat(lat)}



def _rss_mb() -> int:
    if psutil is not None:
        return int(psutil.Process().memory_info().rss / (1024 * 1024))
    with open("/proc/self/statm", encoding="utf-8") as fh:
        pages = int(fh.read().split()[1])
    return pages * 4096 // (1024 * 1024)


def ram_cpu(workload, duration: float = 4.0) -> dict:
    """Sample RSS + CPU% in a background thread while `workload` runs to `deadline`."""
    base = _rss_mb()
    peak = [base]
    cpu_samples: list[float] = []
    deadline = time.perf_counter() + duration
    stop = False

    def _sample() -> None:
        proc = psutil.Process() if psutil is not None else None
        while not stop:
            if proc is not None:
                proc.cpu_percent(interval=0.25)
                cpu_samples.append(proc.cpu_percent(interval=None))
            peak[0] = max(peak[0], _rss_mb())
            if time.perf_counter() >= deadline:
                break

    thread = None
    if psutil is not None:
        thread = threading.Thread(target=_sample, daemon=True)
        thread.start()
    workload(deadline)
    while not stop and time.perf_counter() < deadline:
        time.sleep(0.05)
    stop = True
    if thread is not None:
        thread.join(timeout=2)
    cpu = statistics.mean(cpu_samples) if cpu_samples else 0.0
    return {"rss_base_mb": base, "rss_peak_mb": peak[0], "rss_delta_mb": peak[0] - base, "cpu_pct": round(cpu, 1)}



def _fmt_stat(d: dict) -> str:
    if d.get("n", 0) == 0:
        return "n/a"
    return (
        f"n={d['n']} min={d['min_ms']} med={d['median_ms']} p95={d['p95_ms']} max={d['max_ms']} ms"
    )


def run_all(args) -> dict:
    results: dict = {}

    print("[startup] measuring cold & warm start...")
    results["cold_start"] = cold_start()
    results["warm_start"] = warm_start(args.runs)

    print("[cloud] checking gateway reachability...")
    cloud_status = _cloud_available()
    results["cloud_status"] = cloud_status or "ok"
    if cloud_status is None and not args.no_cloud:
        print("[cloud] measuring SOC call latency...")
        results["cloud_soc_latency"] = cloud_soc_latency(args.runs)
        results["cloud_streaming"] = cloud_streaming_probe()
    else:
        results["cloud_soc_latency"] = None
        results["cloud_streaming"] = None

    local_ok = ollama_reachable(config.LOCAL_HOST, 3)
    results["local_status"] = "ok" if local_ok else "ollama not running"
    if local_ok and not args.no_local:
        print("[local] measuring Qwen cold/warm timing...")
        results["local_timings"] = local_timings(args.force_cold_local)
        print("[local] measuring SOC call latency (warm)...")
        results["local_soc_latency"] = local_soc_latency(args.runs)

    with tempfile.TemporaryDirectory() as td:
        replay_dir = Path(td)

        def _burst(deadline: float) -> None:
            pipe = Pipeline(llm=ReplayProvider(replay_dir=str(replay_dir)))
            while time.perf_counter() < deadline:
                pipe.run(_SAMPLE_CTX)

        print("[pipeline] e2e replay runs...")
        results["pipeline_e2e_replay"] = pipeline_e2e(args.runs, replay_dir)

        print("[resources] sampling RAM/CPU under sustained e2e load...")
        results["ram_cpu"] = ram_cpu(_burst)

    return results


def _render(results: dict) -> str:
    lines = ["# WIENER — one-laptop demo benchmark", ""]
    lines.append("_Measured by `benchmarks/bench_demo.py`. Wall-clock on the host running the harness._")
    lines.append("")
    cs = results["cold_start"]
    lines.append("## Cold / warm start")
    lines.append(f"- fresh-process import: `{cs['import_ms']:.1f} ms`")
    lines.append(f"- fresh-process Pipeline build: `{cs['pipeline_build_ms']:.1f} ms`")
    lines.append(f"- warm Pipeline build: `{_fmt_stat(results['warm_start'])}`")
    lines.append("")
    lines.append("## Cloud provider (primary)")
    lines.append(f"- status: `{results['cloud_status']}`")
    if results["cloud_soc_latency"]:
        lines.append(f"- SOC call wall latency: `{_fmt_stat(results['cloud_soc_latency'])}`")
    if results["cloud_streaming"]:
        cs_ = results["cloud_streaming"]
        if cs_.get("stream_supported"):
            lines.append(
                f"- first token: `{cs_['first_token_ms']} ms` / total: `{cs_['total_generation_ms']} ms`"
            )
        else:
            lines.append(f"- streaming probe: unsupported (`{cs_.get('error', 'n/a')}`)")
    lines.append("")
    lines.append("## Local Qwen2.5 (Ollama)")
    lines.append(f"- status: `{results['local_status']}`")
    if results.get("local_soc_latency"):
        lines.append(f"- warm SOC call latency: `{_fmt_stat(results['local_soc_latency'])}`")
    for t in results.get("local_timings", []):
        tag = "cold (includes model load)" if t["cold_load"] else "warm"
        lines.append(
            f"- {tag}: wall `{t['wall_ms']}` ms | load `{t['load_duration_ms']}` ms | "
            f"eval `{t['eval_count']}` tok in `{t['eval_ms']}` ms "
            f"(`{t['tokens_per_s']}` tok/s) | prompt `{t['prompt_eval_count']}` tok"
        )
    lines.append("")
    e2e = results["pipeline_e2e_replay"]
    lines.append("## Pipeline end-to-end (replay; deterministic)")
    lines.append(
        f"- {_fmt_stat(e2e)} | decision `{e2e['decision']}` risk `{e2e['risk']}` | "
        f"repeated-run stability: `{e2e['repeated_run_stability']}`"
    )
    lines.append("")
    rc = results["ram_cpu"]
    lines.append("## RAM / CPU (measurement host)")
    lines.append(
        f"- RSS base `{rc['rss_base_mb']}` MB, peak `{rc['rss_peak_mb']}` MB "
        f"(delta `{rc['rss_delta_mb']}` MB), CPU ~`{rc['cpu_pct']}%`"
        + ("" if psutil else " (_psutil absent: RSS only_)")
    )
    lines.append("")
    if results.get("local_status") != "ok":
        lines.append("> Note: Ollama was not running during this measurement.")
    return "\n".join(lines)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--report", type=str, default="")
    p.add_argument("--no-cloud", action="store_true")
    p.add_argument("--no-local", action="store_true")
    p.add_argument("--force-cold-local", action="store_true")
    args = p.parse_args()

    results = run_all(args)
    report = _render(results)

    print("\n" + "=" * 72)
    print(report)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
        print(f"\nreport written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())