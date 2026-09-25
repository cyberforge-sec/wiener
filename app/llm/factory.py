from __future__ import annotations

import os
import time

from .base import LLMProvider, ProviderUnavailable
from .local_provider import LocalProvider, ollama_reachable
from .opencode_provider import OpenCodeProvider
from .replay_provider import ReplayProvider
from ..config import config


_ACTIVE: LLMProvider | None = None

# Tier-down kinds; "malformed" output is NOT a tier outage.
TRANSIENT_KINDS = frozenset({"timeout", "connection", "auth", "unavailable"})

# Cloud failure triggers a cooldown, so a dead gateway self-heals, not stalls.
_cloud_retry_after: float = 0.0


def _cloud_cooldown_s() -> float:
    try:
        return max(0.0, float(os.environ.get("WIENER_CLOUD_COOLDOWN_S", "30.0")))
    except (TypeError, ValueError):
        return 30.0


def _cloud_in_cooldown() -> bool:
    return time.monotonic() < _cloud_retry_after


def _ladder() -> list[str]:
    """Return the ordered provider names to try, based on config."""
    force = config.LLM_FORCE.lower()
    if force in ("opencode", "local", "replay"):
        return [force, "local", "replay"]
    return ["opencode", "local", "replay"]


def _build(name: str, *, strict_replay: bool = False) -> LLMProvider:
    if name == "opencode":
        provider = OpenCodeProvider()
        # No credentials → skip so the ladder falls through, not to a dead endpoint.
        if not provider._api_key:
            raise ProviderUnavailable("OpenCodeProvider: no API key configured", kind="auth")
        return provider
    if name == "local":
        return LocalProvider()
    if name == "replay":
        # Replay always serves the recorded store; strict_replay never fabricates defaults.
        return ReplayProvider(strict=strict_replay)
    raise ProviderUnavailable(f"Unknown provider: {name}")


# Judge ladder failover is downward-only: opencode → local → replay (never upgrades live).
_STATIC_LADDER = ("opencode", "local", "replay")
_TIER_INDEX = {name: i for i, name in enumerate(_STATIC_LADDER)}


def _order_for(preferred: str) -> list[str]:
    if preferred in _TIER_INDEX:
        return list(_STATIC_LADDER[_TIER_INDEX[preferred]:])
    return list(_STATIC_LADDER)


def resolve_llm(preferred: str = "", *, strict_replay: bool = False) -> LLMProvider:
    """Return a provider for an interactive (judge) run.

    `preferred` ("" | "opencode" | "local" | "replay") is tried first; when it
    is unavailable the ladder falls DOWN from that tier (never back up to a
    higher tier). An empty/unknown preference walks the full ladder
    opencode → local → replay. Availability gates (cloud API key, local
    reachability) ensure a dead endpoint is never selected. Absolute last
    resort: Replay, which is always available because it is deterministic and
    never calls a model.

    The caller can read the ACTUAL tier from the returned provider's `.name`
    (e.g. "replay") and label the UI accordingly; replay is never presented
    as live inference.

    `strict_replay` (judge mode): an unrecorded prompt makes the replay rung
    raise `ProviderUnavailable(kind="replay_missing")` instead of returning
    the neutral default. If NO tier at all can serve, `resolve_llm` raises
    instead of handing back a fabricated neutral answer: fail-loud, never a
    silent benign-looking decision.
    """
    order = _order_for(preferred)
    last_error: Exception | None = None
    for name in order:
        try:
            candidate = _build(name, strict_replay=strict_replay)
            if name == "local" and not ollama_reachable(config.LOCAL_HOST, 5):
                continue
            return candidate
        except ProviderUnavailable as exc:
            last_error = exc
            continue

    if strict_replay:
        raise ProviderUnavailable(
            f"no LLM tier could serve (strict): {last_error or 'all tiers unavailable'}",
            kind="no_provider",
        )
    return ReplayProvider(strict=False)


def get_llm() -> LLMProvider:
    """Return the active provider, walking the failover ladder on use.

    Lazily resolves so the caller does not need to know which provider it is.
    """
    global _ACTIVE
    if _ACTIVE is not None:
        return _ACTIVE

    forced = config.LLM_FORCE.lower()
    for name in _ladder():
        # Skip cloud during cooldown unless explicitly pinned.
        if name == "opencode" and forced != "opencode" and _cloud_in_cooldown():
            continue
        try:
            candidate = _build(name)
            # Local has a reachability gate to avoid hanging on a dead server.
            if name == "local" and not ollama_reachable(config.LOCAL_HOST, 5):
                continue
            _ACTIVE = candidate
            return candidate
        except ProviderUnavailable:
            continue

    # Absolute last resort: Replay (deterministic, no live call).
    _ACTIVE = ReplayProvider()
    return _ACTIVE


def fail_provider(tier: str = "") -> None:
    """Force the active provider to move to the next tier on next call.

    Called when a tier fails with a TRANSIENT kind (timeout / connection /
    auth / unavailable). Resets the cache so a fresh call re-walks the ladder.
    When the failing tier is the cloud ("opencode") a cooldown also skips the
    cloud tier until it recovers, so a dead gateway no longer burns a full
    timeout on every call, and a local fault never quarantines the cloud.
    Model-behavior failures ("malformed", unparseable output) are NOT
    availability problems and must not call this.
    """
    global _ACTIVE, _cloud_retry_after
    _ACTIVE = None
    if tier == "opencode":
        _cloud_retry_after = time.monotonic() + _cloud_cooldown_s()


def active_provider_name() -> str:
    return getattr(get_llm(), "name", "unknown")
