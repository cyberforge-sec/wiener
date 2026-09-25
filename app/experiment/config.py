from __future__ import annotations

from ..llm.base import LLMProvider


class ExperimentConfigError(ValueError):
    """Raised for invalid experiment configuration or provider names."""


def resolve_provider(name: str, *, replay_dir=None) -> LLMProvider:
    """Build an LLMProvider from a provider name.

    `replay` is the reproducibility-safe default (no live call; deterministic
    fallback when no recorded response exists).
    """
    if name == "replay":
        from ..llm.replay_provider import ReplayProvider

        return ReplayProvider(replay_dir=replay_dir)
    if name == "local":
        from ..llm.local_provider import LocalProvider

        return LocalProvider()
    if name in ("opencode", "openai_compatible", "cloud"):
        # Provider-neutral: the configured cloud adapter, whatever it is.
        from ..llm.factory import build_cloud_provider

        return build_cloud_provider()
    raise ExperimentConfigError(f"unknown provider: {name!r}")