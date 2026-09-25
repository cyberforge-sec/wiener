"""Provider and model identity, kept as separate facts.

An evidence row has to distinguish four different things, and collapsing any
two of them produces a claim the artifact cannot support:

  provider                 the service on the other end (opencode, anthropic,
                           ollama, ...)
  adapter                  which adapter class spoke to it
                           (openai_compatible, anthropic_messages, ollama)
  requested_model          the model id we asked for
  provider_reported_model  the model id the provider says it served

A gateway may rewrite the third into the fourth (asking for `oc/big-pickle`
and being told `big-pickle`), or report nothing at all. When it reports
nothing, that is recorded as unknown. It is never filled in from the adapter
name or the requested id.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Values that name a TRANSPORT, never a model. Used by the provider layer the
# same way invariant I-13b uses it in the evidence layer: a transport name in a
# model field is a provenance defect, not a shorthand.
TRANSPORT_NAMES = frozenset(
    {"", "opencode", "openai_compatible", "local", "replay", "degraded", "unknown", "none"}
)


def looks_like_transport_name(value: object) -> bool:
    """True when `value` names a transport/adapter rather than a model."""
    return str(value or "").strip().lower() in TRANSPORT_NAMES


@dataclass(frozen=True)
class ProviderIdentity:
    """What we asked for, who answered, and how confident we are.

    `provider_reported_model` is None whenever the provider did not say which
    model served. `model_identity_reliable` is False in that case, and the
    reason travels with the record instead of being papered over.
    """

    provider: str
    adapter: str
    requested_model: str
    provider_reported_model: str | None = None
    temperature: float | None = None
    deterministic_requested: bool = False
    endpoint: str | None = None
    extra: dict[str, Any] | None = None

    @property
    def model_identity_reliable(self) -> bool:
        return bool(self.provider_reported_model) and not looks_like_transport_name(
            self.provider_reported_model
        )

    @property
    def model_identity_note(self) -> str | None:
        if self.model_identity_reliable:
            return None
        if not self.provider_reported_model:
            return (
                "provider did not report which model served; only the requested "
                "id is recorded, so the backing model is unverified"
            )
        return (
            f"provider reported {self.provider_reported_model!r}, which is a "
            "transport name rather than a model id; identity is unverified"
        )

    @property
    def requested_model_is_suspect(self) -> bool:
        return looks_like_transport_name(self.requested_model)

    def as_meta(self) -> dict[str, Any]:
        """Normalized metadata for `LLMResponse.meta`.

        `model` is retained as a convenience alias for the REQUESTED model so
        existing consumers keep working, and it is deliberately never the
        adapter name.
        """
        meta: dict[str, Any] = {
            "provider": self.provider,
            "adapter": self.adapter,
            "requested_model": self.requested_model,
            "provider_reported_model": self.provider_reported_model,
            # Back-compat alias. I-13b treats a transport name here as a
            # failure, so it must be the requested model or nothing.
            "model": self.requested_model,
            "model_identity_reliable": self.model_identity_reliable,
            "deterministic_requested": self.deterministic_requested,
        }
        if self.temperature is not None:
            meta["temperature"] = self.temperature
        if self.endpoint:
            meta["endpoint"] = self.endpoint
        if self.requested_model_is_suspect:
            meta["model_identity_note"] = (
                f"requested_model {self.requested_model!r} is a transport name, "
                "not a model id"
            )
        elif self.model_identity_note:
            meta["model_identity_note"] = self.model_identity_note
        if self.extra:
            meta.update(self.extra)
        return meta
