from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class ProviderUnavailable(Exception):
    """Normalized provider failure.

    `kind` classifies the failure so callers can react without depending on
    provider-specific error classes:

      - "timeout"      request timed out
      - "connection"   could not connect
      - "auth"         authentication rejected (401/403)
      - "malformed"    provider returned an unparseable response
      - "replay_missing"  strict replay: prompt has no recorded response
      - "no_provider"  not a single tier could serve the request
      - "unavailable"  any other provider-level failure
    """

    KINDS = ("timeout", "connection", "auth", "malformed", "replay_missing", "no_provider", "unavailable")

    def __init__(self, message: str, kind: str = "unavailable") -> None:
        if kind not in self.KINDS:
            kind = "unavailable"
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class LLMResponse:
    """The single internal structure returned by every provider.

    Callers must depend ONLY on this shape, never on provider-specific
    payloads. `text` is the normalized generation; `provider` identifies the
    source; `meta` carries bounded, non-secret provider metadata.
    """

    text: str
    provider: str
    meta: dict[str, Any] = field(default_factory=dict)


class LLMProvider(Protocol):
    """Uniform adapter interface that every provider must implement.

    Callers above this layer must NOT know which provider they are using.
    """

    name: str

    @property
    def model(self) -> str | None:
        """The model id this provider is configured to request, if any.

        Presentation metadata only. The security layer never reads this, and
        it is the REQUESTED id, not a provider-reported one: reporting quality
        is decided by the identity preflight, not asserted by an accessor.
        `None` means the tier has no live model (deterministic replay).
        """
        ...

    def complete(self, system: str, user: str) -> LLMResponse:
        """Return a normalized completion given a system and user prompt.

        Raises ProviderUnavailable (with a normalized `kind`) on any
        provider-level failure.
        """
        ...