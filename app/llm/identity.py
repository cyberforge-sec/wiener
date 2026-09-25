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

import re
from dataclasses import dataclass
from typing import Any

# Values that name a TRANSPORT, never a model. Used by the provider layer the
# same way invariant I-13b uses it in the evidence layer: a transport name in a
# model field is a provenance defect, not a shorthand.
TRANSPORT_NAMES = frozenset(
    {"", "opencode", "openai_compatible", "local", "replay", "degraded", "unknown", "none"}
)

# A PINNED model id names exactly one model forever. A floating alias
# ("big-pickle", "default", "gpt-4o-mini", "llama-3.3-70b-versatile") names
# whatever the provider currently points it at, so accepting one as evidence of
# model identity would assert something that can change without the artifact
# changing.
#
# Pinned means one of:
#   - a dated snapshot anywhere:      gpt-4o-mini-2024-07-18, gemini-2.5-pro-20250101
#   - a trailing version number:      claude-sonnet-4-6, llama-3.1-70b-2025
#   - an explicit -vN:                qwen-v2
#   - an immutable content hash:      some-model@a1b2c3d
#
# Note that digits alone are NOT enough: `gpt-4o-mini` contains a digit but is
# a rolling alias, because the version is not at the end.
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_TRAILING_VERSION = re.compile(r"-\d+$")
_EXPLICIT_VERSION = re.compile(r"-v\d+", re.IGNORECASE)
_CONTENT_HASH = re.compile(r"@[0-9a-f]{7,}", re.IGNORECASE)


def is_pinned_model_id(value: object) -> bool:
    """True when the id names one immutable model (snapshot, version or hash)."""
    text = str(value or "").strip()
    if not text:
        return False
    return bool(
        _DATE.search(text)
        or _TRAILING_VERSION.search(text)
        or _EXPLICIT_VERSION.search(text)
        or _CONTENT_HASH.search(text)
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
    # The model id the operator DECLARES this route should serve, when it is not
    # simply the requested id. Gateways that route by prefix strip it
    # (`gh/gpt-4o-mini-2024-07-18` -> `gpt-4o-mini-2024-07-18`), so the reported
    # value legitimately differs from the request. The declaration is checked
    # against the provider's own answer and recorded, rather than assumed.
    declared_model: str | None = None

    @property
    def model_identity_reliable(self) -> bool:
        """True only when the provider named a model we can independently check.

        False when:
          - nothing was reported (we only know what we asked for);
          - what was reported is a transport name, not a model;
          - the reported id is neither the requested id nor a declared one; or
          - the only id offered in its place is a floating alias.

        The last case needs care, because there are two different mismatches.
        A gateway that strips a ROUTING PREFIX off a pinned public id
        (`gh/gpt-4o-mini-2024-07-18` -> `gpt-4o-mini-2024-07-18`) is still
        identifying one immutable model, and declaring the expected id makes
        that auditable. A gateway that maps an opaque alias onto another opaque
        name (`oc/big-pickle` -> `big-pickle`) is not, and no declaration may
        make it so, because the reported value is not pinned to one model.
        """
        reported = self.provider_reported_model
        if not reported or looks_like_transport_name(reported):
            return False
        if reported == self.requested_model:
            return True
        if self.declared_model and reported == self.declared_model:
            return is_pinned_model_id(reported)
        return False

    @property
    def model_identity_note(self) -> str | None:
        if self.model_identity_reliable:
            return None
        reported = self.provider_reported_model
        if not reported:
            return (
                "provider did not report which model served; only the requested "
                "id is recorded, so the backing model is unverified"
            )
        if looks_like_transport_name(reported):
            return (
                f"provider reported {reported!r}, which is a transport name "
                "rather than a model id; identity is unverified"
            )
        if self.declared_model and reported == self.declared_model:
            return (
                f"provider reported {reported!r} as declared, but that id is a "
                "floating alias rather than a pinned model, so it does not "
                "identify one model; a declaration cannot make an alias "
                "verifiable"
            )
        if not is_pinned_model_id(reported):
            return (
                f"provider reported {reported!r} for a request of "
                f"{self.requested_model!r}, and that id is a floating alias "
                "rather than a pinned model, so the backing model behind this "
                "route is not independently evidenced. This is a statement "
                "about identifiability, not an accusation about which model "
                "actually served."
            )
        return (
            f"provider reported {reported!r} for a request of "
            f"{self.requested_model!r}, which matches neither the requested id "
            "nor a declared expected model; the backing model is unverified"
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
            "declared_model": self.declared_model,
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
