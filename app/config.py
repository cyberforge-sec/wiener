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


def _env(primary: str, legacy: str, default: str = "") -> str:
    """Read the public cloud setting, with a non-breaking legacy fallback.

    ``WIENER_CLOUD_*`` is the documented provider-neutral interface. The
    historical ``WIENER_OPENCODE_*`` spelling remains readable so existing
    local deployments continue to work, but it is never required.
    """
    return os.getenv(primary, os.getenv(legacy, default))


def parse_route_prefixes(raw: str) -> tuple[str, ...]:
    """Parse a trusted model-route namespace list.

    A gateway may route by namespace and report the canonical model id with the
    prefix stripped (``oc/big-pickle`` -> ``big-pickle``). Naming the namespace
    explicitly is what makes that rewrite verifiable, so this list is the ONLY
    thing that can authorize it: it is never inferred from the presence of a
    slash, from a provider or adapter name, or from either model string.

    Rules, all deliberately strict:
      - comma-separated, whitespace trimmed;
      - empty entries ignored;
      - each entry must end with ``/``;
      - each entry must name at least one character before the ``/``, so a bare
        ``/`` cannot authorize a rewrite of everything;
      - case is preserved, because model ids are case-sensitive and folding it
        would let ``OC/x`` match a reported ``oc/x``.

    Invalid entries are dropped rather than raising: a typo in a display-facing
    setting must not stop the service from booting, and dropping one only ever
    makes verification stricter, never looser.
    """
    prefixes: list[str] = []
    for chunk in str(raw or "").split(","):
        entry = chunk.strip()
        if not entry or not entry.endswith("/") or len(entry) < 2:
            continue
        if entry not in prefixes:
            prefixes.append(entry)
    return tuple(prefixes)


@dataclass(frozen=True)
class Config:
    # Tier selection. The cloud tier is provider-neutral; "opencode" is a
    # legacy alias for it. Empty = automatic ladder.
    LLM_FORCE: str = os.getenv("WIENER_LLM_FORCE", "")  # cloud (or "opencode") | local | replay | ""
    LLM_TIMEOUT_S: float = float(os.getenv("WIENER_LLM_TIMEOUT_S", "30"))

    CLOUD_API_KEY: str = _env("WIENER_CLOUD_API_KEY", "WIENER_OPENCODE_API_KEY")
    CLOUD_BASE_URL: str = _env("WIENER_CLOUD_BASE_URL", "WIENER_OPENCODE_BASE_URL", "https://api.openai.com/v1")
    CLOUD_MODEL: str = _env("WIENER_CLOUD_MODEL", "WIENER_OPENCODE_MODEL", "gpt-4o-mini")
    # Which service the CLOUD_* settings address (opencode, openai, groq,
    # openrouter, ...). This is PROVENANCE, recorded in every evidence row: the
    # adapter and the security layer never branch on it.
    CLOUD_PROVIDER_LABEL: str = _env("WIENER_CLOUD_PROVIDER_LABEL", "WIENER_OPENCODE_PROVIDER", "openai_compatible")
    # Which adapter handles the cloud tier: "openai_compatible" (any
    # OpenAI-shaped endpoint) or "anthropic" (native Messages API). The
    # default targets the standard shape so no configuration is needed.
    CLOUD_ADAPTER: str = os.getenv("WIENER_CLOUD_ADAPTER", "openai_compatible")
    # The model id this route is EXPECTED to serve, when the provider reports
    # something other than the requested id. Gateways that route by prefix
    # strip it (`gh/gpt-4o-mini-2024-07-18` -> `gpt-4o-mini-2024-07-18`).
    # Declaring it makes the check auditable: the harness verifies the
    # provider's own answer against it and records both. It must be a PINNED
    # id (dated snapshot or explicit version); a floating alias cannot be
    # declared into existence as a verifiable identity.
    CLOUD_EXPECTED_MODEL: str = os.getenv("WIENER_CLOUD_EXPECTED_MODEL", "")
    # Namespaces this gateway is TRUSTED to strip when it reports a model id,
    # e.g. "oc/" for a route that answers `oc/big-pickle` as `big-pickle`.
    # Naming the namespace is the whole point: without an entry here, a
    # prefix-stripping rewrite stays unverifiable, and with one it is still only
    # accepted when the stripped requested id equals the reported id EXACTLY.
    # This says nothing about the backing model being pinned or immutable.
    CLOUD_MODEL_ROUTE_PREFIXES: tuple[str, ...] = parse_route_prefixes(
        os.getenv("WIENER_CLOUD_MODEL_ROUTE_PREFIXES", "oc/")
    )
    # Native Anthropic rung, used only when CLOUD_ADAPTER=anthropic.
    ANTHROPIC_API_KEY: str = os.getenv("WIENER_ANTHROPIC_API_KEY", "")
    ANTHROPIC_BASE_URL: str = os.getenv("WIENER_ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    ANTHROPIC_MODEL: str = os.getenv("WIENER_ANTHROPIC_MODEL", "claude-sonnet-4-6")
    ANTHROPIC_MAX_TOKENS: int = int(os.getenv("WIENER_ANTHROPIC_MAX_TOKENS", "500"))
    # Strict/small models become more predictable at lower temperature.
    CLOUD_TEMPERATURE: float = float(_env("WIENER_CLOUD_TEMPERATURE", "WIENER_OPENCODE_TEMPERATURE", "0.0"))
    # Force structured JSON decoding when supported; empty disables.
    CLOUD_RESPONSE_FORMAT: str = _env("WIENER_CLOUD_RESPONSE_FORMAT", "WIENER_OPENCODE_RESPONSE_FORMAT", "json_object")
    # Raw provider response diagnostics (null vs truncation vs prose); empty disables.
    # Disabled by default because responses can be sensitive operational data.
    CLOUD_DIAG_PATH: str = _env("WIENER_CLOUD_DIAG_PATH", "WIENER_OPENCODE_DIAG_PATH")

    LOCAL_HOST: str = os.getenv("WIENER_LOCAL_HOST", "http://localhost:11434")
    LOCAL_MODEL: str = os.getenv("WIENER_LOCAL_MODEL", "qwen2.5:1.5b")
    LOCAL_TIMEOUT_S: float = float(os.getenv("WIENER_LOCAL_TIMEOUT_S", "60"))
    # Bound local output: short structured responses, not long reasoning.
    LOCAL_MAX_TOKENS: int = int(os.getenv("WIENER_LOCAL_MAX_TOKENS", "128"))
    # Sampling temperature for the local rung. 0.2 is the historical value; it
    # is configurable and always recorded in provider metadata so no evidence
    # row can imply local determinism that was never requested.
    LOCAL_TEMPERATURE: float = float(os.getenv("WIENER_LOCAL_TEMPERATURE", "0.2"))
    # Keep-alive to avoid cold reloads; seconds or "5m"/"30m".
    LOCAL_KEEP_ALIVE: str = os.getenv("WIENER_LOCAL_KEEP_ALIVE", "5m")

    REPLAY_DIR: str = str(_PROJECT_ROOT / "data" / "replays")

    # Attack-mutation RNG seed for the authoritative experiment. Explicit and
    # configurable (was a `hasattr(config, "seed")` probe that always fell
    # through to the same literal); recorded in experiment_config.json.
    MUTATION_SEED: int = int(os.getenv("WIENER_MUTATION_SEED", "20260708"))

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
    # Red-team STRESS population, in its own file on purpose: the benchmark
    # harness must not be able to read it, so a stress test can never change
    # the authoritative trial count or its provenance inputs.
    STRESS_SEEDS_PATH: str = str(_PROJECT_ROOT / "config" / "stress_seeds.yaml")
    # Instruction-hierarchy study population, again in its own file. Four
    # populations now exist and none reads another.
    STRESS_HIERARCHY_SEEDS_PATH: str = str(
        _PROJECT_ROOT / "config" / "stress_hierarchy_seeds.yaml"
    )
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

    API_HOST: str = os.getenv("WIENER_API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("WIENER_API_PORT", "8000"))


config = Config()
