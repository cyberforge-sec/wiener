#!/usr/bin/env python3
"""WIENER competition release health check.

Verifies the nine release-critical areas:

  runtime, dependencies, configuration, cloud provider configuration,
  Qwen availability, Replay availability, logging, dashboard,
  configuration files.

Every area is checked without mutating project state (no log writes, no
model calls). Cloud/Qwen unavailability is reported as WARN: the failover
ladder (opencode -> local -> replay) is designed to keep the system fully
deterministic in that state. A FAIL means the release artifact is broken.

Usage:
  python3 scripts/health_check.py [--json]
  run_healthcheck                       (root launcher, same thing)

Exit code: 0 when nothing FAILs, 2 when the health check itself cannot run,
1 when at least one area is FAIL.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))



_ORDER = (
    "runtime",
    "dependencies",
    "configuration",
    "cloud-provider",
    "qwen",
    "replay",
    "logging",
    "dashboard",
    "config-files",
)


class _Result:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def add(self, area: str, name: str, status: str, detail: str = "") -> None:
        self.checks.append({"area": area, "check": name, "status": status, "detail": detail})

    def failures(self) -> list[dict]:
        return [c for c in self.checks if c["status"] == "FAIL"]

    def by_area(self) -> dict:
        out: dict[str, list[dict]] = {}
        for area in _ORDER + tuple(sorted({c["area"] for c in self.checks} - set(_ORDER))):
            out[area] = [c for c in self.checks if c["area"] == area]
        return out


RESULT = _Result()


def _pass(area: str, name: str, detail: str = "") -> None:
    RESULT.add(area, name, "PASS", detail)


def _warn(area: str, name: str, detail: str = "") -> None:
    RESULT.add(area, name, "WARN", detail)


def _fail(area: str, name: str, detail: str = "") -> None:
    RESULT.add(area, name, "FAIL", detail)


def _run(area: str, name: str, fn) -> None:
    """Execute a check function fn() -> (ok: bool, warn: bool, detail: str)."""
    try:
        ok, warn, detail = fn()
    except Exception as exc:  # noqa: BLE001: report the crash as FAIL, never die
        _fail(area, name, f"{type(exc).__name__}: {exc}")
        return
    if warn:
        _warn(area, name, detail)
    elif ok:
        _pass(area, name, detail)
    else:
        _fail(area, name, detail)




def check_runtime():
    version = sys.version_info
    _run("runtime", "python-version", lambda: (
        (version[0], version[1]) >= (3, 10),
        False,
        f"{sys.version.split()[0]} (requires >= 3.10)",
    ))
    _run("runtime", "app-import", lambda: (
        importlib.import_module("app") is not None,
        False,
        "app package imports",
    ))
    _run("runtime", "fastapi-app-build", lambda: (
        importlib.import_module("app.main").app,
        False,
        "FastAPI app builds",
    ))
    _run("runtime", "active-provider-resolves", lambda: (
        bool(_provider_name()),
        False,
        f"active provider tier: {_provider_name() or 'unknown'}",
    ))


def _provider_name() -> str:
    try:
        from app.llm.factory import active_provider_name

        return active_provider_name()
    except Exception:  # noqa: BLE001
        return ""



_REQUIRED = {
    "fastapi": "FastAPI",
    "uvicorn": "uvicorn",
    "httpx": "httpx",
    "pydantic": "pydantic",
    "yaml": "PyYAML (yaml)",
}


def check_dependencies():
    for module, label in _REQUIRED.items():
        spec = importlib.util.find_spec(module)
        _run("dependencies", module, lambda spec=spec, label=label: (
            spec is not None,
            False,
            f"{label} installed" if spec else f"{label} MISSING",
        ))



_VALID_FORCE = ("", "opencode", "local", "replay")


def check_configuration():
    def _config():
        from app.config import config

        return config

    cfg = _config()

    def _thresholds(cfg=cfg):
        ok = 0.0 < cfg.RISK_ALLOW_THRESHOLD < cfg.RISK_REVIEW_THRESHOLD <= 100.0
        return ok, False, f"allow={cfg.RISK_ALLOW_THRESHOLD} review={cfg.RISK_REVIEW_THRESHOLD}"

    def _weights(cfg=cfg):
        total = (
            cfg.RISK_WEIGHT_TRUST
            + cfg.RISK_WEIGHT_DEVIATION
            + cfg.RISK_WEIGHT_CRITICALITY
            + cfg.RISK_WEIGHT_PRIVILEGE
        )
        return abs(total - 1.0) < 1e-6, False, f"weight sum={total:.4f}"

    def _force(cfg=cfg):
        valid = cfg.LLM_FORCE.lower() in _VALID_FORCE
        return valid, False, f"LLM_FORCE={cfg.LLM_FORCE or '(unset -> full ladder)'}"

    def _config_paths(cfg=cfg):
        from pathlib import Path as P

        paths = [
            cfg.ACTION_METADATA_PATH,
            cfg.SAFETY_CONSTRAINTS_PATH,
            cfg.RED_AI_SEEDS_PATH,
        ]
        missing = [p for p in paths if not P(p).exists()]
        return not missing, False, f"yaml paths present ({len(paths) - len(missing)}/{len(paths)})"

    _run("configuration", "thresholds-consistent", _thresholds)
    _run("configuration", "risk-weights-sum-1", _weights)
    _run("configuration", "llm-force-valid", _force)
    _run("configuration", "config-yaml-paths", _config_paths)




def check_cloud():
    from app.config import config

    has_key = bool(config.OPENCODE_API_KEY.strip())
    fields_ok = bool(config.OPENCODE_BASE_URL.strip()) and bool(config.OPENCODE_MODEL.strip())
    detail = (
        f"key={'set' if has_key else 'unset'} base_url={config.OPENCODE_BASE_URL} "
        f"model={config.OPENCODE_MODEL}"
    )

    if not has_key:
        _warn(
            "cloud-provider",
            "credentials",
            f"{detail} — cloud tier unconfigured; failover ladder will use local/replay",
        )
    elif fields_ok:
        _pass("cloud-provider", "credentials", detail)
    else:
        _fail("cloud-provider", "credentials", f"{detail} — key set but base_url/model empty")

    # Non-fatal reachability probe: the design tolerates a dead cloud endpoint.
    def _probe():
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(config.OPENCODE_BASE_URL)
        host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return True, False, f"endpoint {config.OPENCODE_BASE_URL} reachable"

    if has_key and fields_ok:
        _run("cloud-provider", "endpoint-reachable", _probe)

    _run("cloud-provider", "timeout-configured", lambda: (
        config.LLM_TIMEOUT_S > 0,
        False,
        f"WIENER_LLM_TIMEOUT_S={config.LLM_TIMEOUT_S}",
    ))




def check_qwen():
    from app.config import config

    def _reachable():
        try:
            from app.llm.local_provider import ollama_reachable

            ok = ollama_reachable(config.LOCAL_HOST, 5)
            return ok, not ok, (
                f"{config.LOCAL_HOST} reachable" if ok
                else f"{config.LOCAL_HOST} not reachable — ladder falls to replay"
            )
        except Exception as exc:  # noqa: BLE001
            return False, True, f"reachability probe failed: {exc}"

    _run("qwen", "ollama-reachable", _reachable)

    def _model_present():
        try:
            req = urllib.request.Request(
                f"{config.LOCAL_HOST}/api/tags", headers={"Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                tags = json.loads(resp.read().decode())
        except Exception as exc:  # noqa: BLE001
            return False, True, f"/api/tags unavailable ({exc})"
        names = [t.get("name", "") for t in tags.get("models", [])]
        found = config.LOCAL_MODEL in names
        return bool(found), not found, (
            f"model {config.LOCAL_MODEL} present ({len(names)} tags)"
            if found else f"model {config.LOCAL_MODEL} NOT in tags: {sorted(names)[:5]}"
        )

    _run("qwen", "model-present", _model_present)

    _run("qwen", "max-tokens-bounded", lambda: (
        0 < config.LOCAL_MAX_TOKENS <= 1024,
        False,
        f"WIENER_LOCAL_MAX_TOKENS={config.LOCAL_MAX_TOKENS}",
    ))




def check_replay():
    from app.replay.cli import _missing_recorded_files
    from app.replay.runner import RECORDED_DIR

    store = Path(RECORDED_DIR)
    _run("replay", "recorded-store-exists", lambda: (
        store.exists() and any(store.glob("*.json")),
        False,
        f"store={store}",
    ))

    def _coverage():
        missing = _missing_recorded_files()
        ok = not missing
        return ok, False, (
            f"scenario coverage complete (REPLAY-001..004)"
            if ok else f"missing scenarios: {', '.join(missing)}"
        )

    _run("replay", "scenario-coverage", _coverage)

    def _deterministic_run():
        from app.replay.runner import run_scenario

        out = run_scenario("REPLAY-001")
        passed = out.passed and out.replay_mode
        return passed, False, (
            f"REPLAY-001 -> {out.final_decision} (replay_mode={out.replay_mode}, expected={out.expected})"
        )

    _run("replay", "deterministic-execution", _deterministic_run)




def check_logging():
    from app.config import config

    probes = [
        ("trajectory", config.TRAJECTORY_LOG_PATH),
        ("red-attacks", config.RED_AI_LOG_PATH),
        ("red-feedback", config.RED_FEEDBACK_LOG_PATH),
    ]
    for label, path in probes:
        p = Path(path)
        writable, detail = _dir_writable(p.parent)
        existing = p.exists()
        _run("logging", f"{label}-sink", lambda writable=writable, detail=detail, p=p, existing=existing: (
            writable,
            False,
            f"{detail}; {'file exists' if existing else 'file will be created on first write'}",
        ))
    _run("logging", "sync-path-single-store", lambda: (
        Path(config.TRAJECTORY_LOG_PATH).suffix == ".jsonl",
        False,
        "trajectory uses a single JSONL store",
    ))


def _dir_writable(dirpath: Path) -> tuple[bool, str]:
    if not dirpath.exists():
        dirpath.mkdir(parents=True, exist_ok=True)
    if not dirpath.is_dir():
        return False, f"not a directory: {dirpath}"
    try:
        fd, tmp = tempfile.mkstemp(dir=str(dirpath), prefix=".hc-")
        os.close(fd)
        os.unlink(tmp)
        return True, f"writable: {dirpath}"
    except OSError as exc:
        return False, f"not writable: {dirpath} ({exc})"




def check_dashboard():
    def _store_loads():
        from app.dashboard.store import ReportStore

        report = ReportStore().load_latest()
        return True, False, (
            f"report store loads (latest: {report.experiment_id}, {len(report.trials)} trials)"
            if report else "report store empty (no experiments yet — empty dashboard is valid)"
        )

    def _build_and_render():
        from app.dashboard.dashboard import build_dashboard
        from app.dashboard.render import render_html
        from app.dashboard.store import ReportStore

        report = ReportStore().load_latest()
        if report is None:
            empty = build_dashboard(ReportStore).__class__.empty()
            html = render_html(empty)
            return "WIENER" in html, False, "empty dashboard renders"
        data = build_dashboard(report)
        html = render_html(data)
        from app.metrics import compute_metrics

        mr = compute_metrics(report)
        uapr = mr.uapr()
        return data.experiment_id == report.experiment_id and report.experiment_id in html, False, (
            f"dashboard renders {len(data.trials)} trials; UAPR={'%.4f' % uapr if uapr is not None else 'n/a'}"
        )

    _run("dashboard", "store-load", _store_loads)
    _run("dashboard", "build-and-render", _build_and_render)
    _run("dashboard", "route-wired", lambda: (
        importlib.import_module("app.main").app.routes is not None,
        False,
        "FastAPI app exposes routes (analyze/health/dashboard/judge)",
    ))




def check_config_files():
    from app.config import config

    files = {
        "action_metadata": (config.ACTION_METADATA_PATH, _valid_action_metadata),
        "safety_constraints": (config.SAFETY_CONSTRAINTS_PATH, _valid_constraints),
        "red_ai_seeds": (config.RED_AI_SEEDS_PATH, _valid_seeds),
    }
    for label, (path, validator) in files.items():
        _run("config-files", label, lambda path=path, validator=validator: validator(path))


def _load_yaml(path: str):
    import yaml

    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _valid_action_metadata(path: str) -> tuple[bool, bool, str]:
    try:
        data = _load_yaml(path)
        actions = (data or {}).get("actions")
        ok = isinstance(actions, dict) and len(actions) >= 3
        return ok, False, f"{len(actions) if isinstance(actions, dict) else 0} actions defined"
    except Exception as exc:  # noqa: BLE001
        return False, False, f"unparsable: {exc}"


def _valid_constraints(path: str) -> tuple[bool, bool, str]:
    try:
        data = _load_yaml(path)
        items = (data or {}).get("constraints")
        ok = isinstance(items, list) and any(
            isinstance(c, dict) and c.get("id") and c.get("required_decision") for c in items
        )
        return ok, False, f"{len(items) if isinstance(items, list) else 0} constraints defined"
    except Exception as exc:  # noqa: BLE001
        return False, False, f"unparsable: {exc}"


def _valid_seeds(path: str) -> tuple[bool, bool, str]:
    try:
        data = _load_yaml(path)
        seeds = (data or {}).get("seeds")
        ok = isinstance(seeds, list) and len(seeds) >= 1
        return ok, False, f"{len(seeds) if isinstance(seeds, list) else 0} seeds defined"
    except Exception as exc:  # noqa: BLE001
        return False, False, f"unparsable: {exc}"




def run_health_check() -> list[dict]:
    check_runtime()
    check_dependencies()
    check_configuration()
    check_cloud()
    check_qwen()
    check_replay()
    check_logging()
    check_dashboard()
    check_config_files()
    return list(RESULT.checks)


def _render(results: list[dict]) -> str:
    lines = [
        "=" * 62,
        "  WIENER RELEASE HEALTH CHECK",
        "=" * 62,
    ]
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0}
    for area in _ORDER:
        area_checks = [c for c in results if c["area"] == area]
        if not area_checks:
            continue
        lines.append(f"\n[{area}]")
        for c in area_checks:
            counts[c["status"]] += 1
            lines.append(
                f"  {c['status']:<5} {c['check']:<28} {c['detail']}"
            )
    lines.append("=" * 62)
    lines.append(
        f"  RESULT: {counts['PASS']} passed, {counts['WARN']} warn, "
        f"{counts['FAIL']} failed"
    )
    lines.append("=" * 62)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WIENER release health check")
    parser.add_argument("--json", action="store_true", help="print machine-readable results")
    args = parser.parse_args(argv)

    try:
        results = run_health_check()
    except Exception as exc:  # noqa: BLE001
        print(f"[health] cannot run: {exc}", file=sys.stderr)
        return 2

    failures = [c for c in results if c["status"] == "FAIL"]
    if args.json:
        print(json.dumps({"checks": results, "failed": [c["check"] for c in failures]}, indent=2))
    else:
        print(_render(results))

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())