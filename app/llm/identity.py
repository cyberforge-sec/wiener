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

A rewrite is only accepted when the operator has named the namespace the
gateway is trusted to strip, and the remainder matches the reported id
exactly. That makes the ROUTE verifiable. It does not make the model pinned:
those are separate facts, reported separately, because a stripped name can
still be a floating alias.
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
# A digit alone does not make an id pinned: `gpt-4o-mini` is a rolling alias
# because its version is not at the end.
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


# How a model identity was established. These are reported verbatim in evidence
# so a reader can tell a provider's own confirmation from an operator's
# declaration, and can tell both from a routing convention.
EXACT_MATCH = "exact_match"
TRUSTED_ROUTE_MATCH = "trusted_route_match"
DECLARED_PINNED_MATCH = "declared_pinned_match"
UNVERIFIED = "unverified"

VERIFICATION_KINDS = (EXACT_MATCH, TRUSTED_ROUTE_MATCH, DECLARED_PINNED_MATCH, UNVERIFIED)


def match_trusted_route_prefix(requested: object, reported: object, prefixes: object) -> str | None:
    """Return the trusted prefix that explains `reported`, or None.

    A prefix authorizes a rewrite only when it accounts for the reported id
    EXACTLY: the requested id must start with the prefix and the remainder must
    equal the reported id character for character. Anything looser — a partial
    suffix, a different namespace, a version that merely looks related — is not
    a routing convention, it is a coincidence, and it is refused.

    The prefix list is the only authority here. It is never derived from the
    slash in the requested id, nor from a provider or adapter name.
    """
    requested_text = str(requested or "")
    reported_text = str(reported or "")
    if not requested_text or not reported_text:
        return None
    for prefix in prefixes or ():
        candidate = str(prefix)
        if not candidate.endswith("/") or len(candidate) < 2:
            continue
        if requested_text.startswith(candidate) and requested_text[len(candidate) :] == reported_text:
            return candidate
    return None


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
    # Namespaces this route is trusted to strip when reporting a model id. Read
    # from configuration, never from the model strings and never from a
    # provider response. Empty means no rewrite is trusted, so an
    # `oc/big-pickle` -> `big-pickle` answer stays unverified.
    trusted_route_prefixes: tuple[str, ...] = ()

    @property
    def trusted_route_prefix(self) -> str | None:
        """The configured prefix that accounts for the reported id, if any."""
        return match_trusted_route_prefix(
            self.requested_model, self.provider_reported_model, self.trusted_route_prefixes
        )

    @property
    def trusted_route_match_detail(self) -> dict[str, str] | None:
        """Structured record of a trusted routing rewrite, for the artifact.

        States only what was observed: what was asked, which configured
        namespace was stripped, and the canonical id the provider reported. It
        makes no claim about the backing model being pinned or immutable.
        """
        prefix = self.trusted_route_prefix
        if prefix is None:
            return None
        return {
            "requested": self.requested_model,
            "prefix": prefix,
            "canonical_reported": str(self.provider_reported_model),
        }

    @property
    def identity_verification(self) -> str:
        """How this identity was established, or `unverified`.

        Ordered so the strongest available evidence is named first:
          exact_match             the provider echoed the requested id;
          trusted_route_match     a configured namespace was stripped and the
                                  remainder equals the reported id exactly;
          declared_pinned_match   the reported id matched an operator
                                  declaration AND is a pinned model id;
          unverified              anything else.

        `trusted_route_match` is explicitly NOT pinning. A gateway can route
        `oc/big-pickle` and the stripped name can still be a floating alias, so
        the two facts are reported separately and never merged.
        """
        reported = self.provider_reported_model
        if not reported or looks_like_transport_name(reported):
            return UNVERIFIED
        if reported == self.requested_model:
            return EXACT_MATCH
        if self.trusted_route_prefix is not None:
            return TRUSTED_ROUTE_MATCH
        if self.declared_model and reported == self.declared_model:
            # A declaration cannot make a floating alias verifiable: only a
            # pinned id names one model.
            return DECLARED_PINNED_MATCH if is_pinned_model_id(reported) else UNVERIFIED
        return UNVERIFIED

    @property
    def model_identity_reliable(self) -> bool:
        """True only when the provider named a model we can independently check.

        False when:
          - nothing was reported (we only know what we asked for);
          - what was reported is a transport name, not a model;
          - the reported id is neither the requested id, nor the exact
            remainder of a configured routing prefix, nor a declared pinned id.

        This says the reported id is trustworthy, NOT that it is pinned. Read
        `identity_verification` and `model_identity_pinned` for those.
        """
        return self.identity_verification != UNVERIFIED

    @property
    def model_identity_pinned(self) -> bool:
        """Whether the canonical model id names one immutable model.

        Reported separately from verification on purpose. A trusted route match
        can be perfectly reliable and still not pinned, and an artifact that
        merged the two would overstate what the gateway evidenced.
        """
        canonical = self.provider_reported_model or self.requested_model
        return is_pinned_model_id(canonical)

    @property
    def model_identity_note(self) -> str | None:
        if self.identity_verification == TRUSTED_ROUTE_MATCH:
            prefix = self.trusted_route_prefix
            pinned = self.model_identity_pinned
            return (
                f"provider reported {self.provider_reported_model!r} for a request of "
                f"{self.requested_model!r}; the gateway stripped the configured routing "
                f"namespace {prefix!r} and the remainder matches the reported id exactly, so "
                f"the route is verified. This confirms the canonical model id the gateway "
                f"reported, and nothing more: the model is "
                f"{'a pinned id' if pinned else 'not established as pinned or immutable'}."
            )
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
        if self.trusted_route_prefixes:
            return (
                f"provider reported {reported!r} for a request of "
                f"{self.requested_model!r}, which is not the requested id, not an exact "
                f"remainder of any trusted routing namespace "
                f"{list(self.trusted_route_prefixes)}, and not a declared expected model; "
                "the backing model is unverified"
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
            # How the identity was established, and separately whether the
            # resulting id is pinned. Readers must not merge the two: a
            # trusted route match is verified without being pinned.
            "identity_verification": self.identity_verification,
            "model_identity_pinned": self.model_identity_pinned,
            "deterministic_requested": self.deterministic_requested,
        }
        route_detail = self.trusted_route_match_detail
        if route_detail is not None:
            meta[TRUSTED_ROUTE_MATCH] = route_detail
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
