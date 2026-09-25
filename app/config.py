from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines, no external dependency.

    Does not override variables already present in the environment.
    """
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(_PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class Config:
    LLM_FORCE: str = os.getenv("WIENER_LLM_FORCE", "")  # opencode | local | replay | ""
    LLM_TIMEOUT_S: float = float(os.getenv("WIENER_LLM_TIMEOUT_S", "30"))

    OPENCODE_API_KEY: str = os.getenv("WIENER_OPENCODE_API_KEY", "")
    OPENCODE_BASE_URL: str = os.getenv("WIENER_OPENCODE_BASE_URL", "https://api.openai.com/v1")
    OPENCODE_MODEL: str = os.getenv("WIENER_OPENCODE_MODEL", "gpt-4o-mini")
    # Strict/small models become more predictable at lower temperature.
    OPENCODE_TEMPERATURE: float = float(os.getenv("WIENER_OPENCODE_TEMPERATURE", "0.0"))
    # Force structured JSON decoding when supported; empty disables.
    OPENCODE_RESPONSE_FORMAT: str = os.getenv("WIENER_OPENCODE_RESPONSE_FORMAT", "json_object")
    # Raw provider response diagnostics (null vs truncation vs prose); empty disables.
    # Disabled by default because responses can be sensitive operational data.
    OPENCODE_DIAG_PATH: str = os.getenv("WIENER_OPENCODE_DIAG_PATH", "")

    LOCAL_HOST: str = os.getenv("WIENER_LOCAL_HOST", "http://localhost:11434")
    LOCAL_MODEL: str = os.getenv("WIENER_LOCAL_MODEL", "qwen2.5:1.5b")
    LOCAL_TIMEOUT_S: float = float(os.getenv("WIENER_LOCAL_TIMEOUT_S", "60"))
    # Bound local output: short structured responses, not long reasoning.
    LOCAL_MAX_TOKENS: int = int(os.getenv("WIENER_LOCAL_MAX_TOKENS", "128"))
    # Keep-alive to avoid cold reloads; seconds or "5m"/"30m".
    LOCAL_KEEP_ALIVE: str = os.getenv("WIENER_LOCAL_KEEP_ALIVE", "5m")

    REPLAY_DIR: str = str(_PROJECT_ROOT / "data" / "replays")

    # Risk bands (0-100): below ALLOW → ALLOW, below REVIEW → REVIEW, else BLOCK.
    RISK_ALLOW_THRESHOLD: float = float(os.getenv("WIENER_RISK_ALLOW", "30"))
    RISK_REVIEW_THRESHOLD: float = float(os.getenv("WIENER_RISK_REVIEW", "60"))

    # Weights on the 0-100 scale (trust is inverse-risk); sum to 1.0.
    RISK_WEIGHT_TRUST: float = float(os.getenv("WIENER_RISK_WEIGHT_TRUST", "0.35"))
    RISK_WEIGHT_DEVIATION: float = float(os.getenv("WIENER_RISK_WEIGHT_DEVIATION", "0.30"))
    RISK_WEIGHT_CRITICALITY: float = float(os.getenv("WIENER_RISK_WEIGHT_CRITICALITY", "0.20"))
    RISK_WEIGHT_PRIVILEGE: float = float(os.getenv("WIENER_RISK_WEIGHT_PRIVILEGE", "0.15"))

    ACTION_METADATA_PATH: str = str(_PROJECT_ROOT / "config" / "action_metadata.yaml")
    SAFETY_CONSTRAINTS_PATH: str = str(_PROJECT_ROOT / "config" / "safety_constraints.yaml")
    RED_AI_SEEDS_PATH: str = str(_PROJECT_ROOT / "config" / "red_ai_seeds.yaml")
    # Trajectory logger: single JSONL store for the whole pipeline lifecycle.
    TRAJECTORY_LOG_PATH: str = os.getenv(
        "WIENER_TRAJECTORY_LOG", str(_PROJECT_ROOT / "data" / "logs" / "trajectory.jsonl")
    )
    # Red AI harness: fixed adversarial seeds + per-attack JSONL log.
    RED_AI_LOG_PATH: str = os.getenv(
        "WIENER_RED_AI_LOG", str(_PROJECT_ROOT / "data" / "logs" / "red_attacks.jsonl")
    )
    # Red AI closed loop: structured feedback appended per step.
    RED_FEEDBACK_LOG_PATH: str = os.getenv(
        "WIENER_RED_FEEDBACK_LOG", str(_PROJECT_ROOT / "data" / "logs" / "red_feedback.jsonl")
    )
    # Experiment runner: persisted ExperimentReport JSON store (dashboard input).
    EXPERIMENT_STORE_PATH: str = str(_PROJECT_ROOT / "data" / "experiments")

    API_HOST: str = os.getenv("WIENER_API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("WIENER_API_PORT", "8000"))


config = Config()
