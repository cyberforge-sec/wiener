from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..config import config
from .base import LLMResponse, ProviderUnavailable

_DEFAULT_TEXT = json.dumps({"action": "check_endpoint", "target": "host-a", "confidence": 0.5})

# Single source of truth: "replay" everywhere serves the recorded store.
RECORDED_DIR = Path(__file__).resolve().parent.parent / "replay" / "recorded"


class ReplayProvider:
    """Deterministic provider: no live model call.

    Responses are keyed by a stable hash of the prompt pair, so the same
    logical request always yields the exact same output. Recorded responses
    preserve the recorded tier as provenance metadata.

    The provider ALWAYS reports itself as the serving provider (`name =
    "replay"`): a replay is never presented as live inference, and a
    cloud-recorded answer served through replay still labels the actual rung
    that produced the response. The recorded tier is available in
    `meta["recorded_tier"]` for diagnostics.

    `strict=True` refuses to fabricate: a prompt with no recording raises
    `ProviderUnavailable(kind="replay_missing")` instead of returning the
    neutral default. Judge / interactive flows use strict so an unrecorded
    prompt can never be silently answered with a benign-looking placeholder.
    The lenient path (pipeline last resort) returns the neutral default but
    tags it `meta["replay_neutral"] = True` so no consumer can mistake it for
    a recorded decision.
    """

    name = "replay"

    def __init__(self, replay_dir: str | None = None, *, strict: bool = False) -> None:
        self._replay_dir = Path(replay_dir) if replay_dir else RECORDED_DIR
        self._replay_dir.mkdir(parents=True, exist_ok=True)
        self.strict = strict

    @staticmethod
    def _key(system: str, user: str) -> str:
        """Stable key from a prompt pair so replays are reproducible."""
        digest = hashlib.sha1(f"{system}|{user}".encode("utf-8")).hexdigest()[:16]
        return digest

    def replay_path(self, key: str) -> Path:
        return self._replay_dir / f"{key}.json"

    def save_recorded(
        self,
        key: str,
        text: str,
        meta: dict | None = None,
        provider: str = "replay",
    ) -> None:
        """Store a recorded response (used to build replay fixtures)."""
        doc = {
            "text": text,
            "provider": provider,
            "meta": meta or {},
        }
        self.replay_path(key).write_text(json.dumps(doc))

    def complete(self, system: str, user: str) -> LLMResponse:
        key = self._key(system, user)
        path = self.replay_path(key)
        if not path.exists():
            if self.strict:
                raise ProviderUnavailable(
                    f"ReplayProvider (strict): no recorded response for prompt {key!r} — "
                    "refusing to fabricate a decision (replay_neutral)",
                    kind="replay_missing",
                )
            # Neutral marker tagged replay_neutral so it can't pass as recorded.
            return LLMResponse(
                text=_DEFAULT_TEXT,
                provider=self.name,
                meta={
                    "replay_key": key,
                    "recorded": False,
                    "deterministic": True,
                    "replay_neutral": True,
                },
            )
        try:
            doc = json.loads(path.read_text())
            recorded_tier = str(doc.get("provider", self.name))
            return LLMResponse(
                text=str(doc.get("text", "")),
                provider=self.name,
                meta={
                    "replay_key": key,
                    "recorded": True,
                    "deterministic": True,
                    "recorded_tier": recorded_tier,
                    **dict(doc.get("meta", {})),
                },
            )
        except (json.JSONDecodeError, OSError) as exc:
            raise ProviderUnavailable(f"ReplayProvider: could not read replay: {exc}", kind="malformed") from exc