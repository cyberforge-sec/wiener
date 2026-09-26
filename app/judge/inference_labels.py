"""Display identity for the inference tiers the Judge page can run.

The Judge page has to answer two questions that are easy to conflate:

1. *What can I choose right now?* — answered by the ACTIVE CONFIGURATION.
2. *What produced the result I am looking at?* — answered by the RUN's OWN
   recorded identity, which must survive later configuration changes.

Keeping those two separate is the whole point of this module. The dropdown
describes the tiers the app is currently configured for; the last-run banner
describes the run that was restored. A user who switches provider after a run
must still see which provider actually produced that run.

Three fields, deliberately not collapsed into one:

- **tier** — which inference tier served the request (`Cloud`/`Local`/`Replay`).
- **provider** — which service supplied inference. For cloud this is a label
  the operator configures (`WIENER_CLOUD_PROVIDER_LABEL`), not a hardcoded
  vendor; for local it is the runtime inferred from the configured host.
- **model** — the model id, read from configuration or from the provider
  object that served a run.

`adapter` (e.g. `openai_compatible`) is implementation metadata. It stays
available for debug surfaces, but it is never the primary identity shown to a
user: it names a wire protocol, not the model that answered.

Nothing here is hardcoded per vendor. A missing value produces an honest
fallback and never a guess.
"""

from __future__ import annotations

from typing import Any

from app.config import config

# Tier keys double as the values posted to /judge/run, so the backend contract
# is unchanged. "opencode" remains a valid backend alias for the cloud tier but
# is deliberately NOT listed here: it is the same tier, and listing both is what
# produced two identical "Cloud" entries in the dropdown.
CLOUD = "cloud"
LOCAL = "local"
REPLAY = "replay"

# The provider key the backend expects for each tier. Cloud uses the canonical
# adapter-agnostic key; "opencode" is still accepted server-side as a legacy
# alias for exactly this tier.
TIER_PROVIDER_KEY = {CLOUD: "openai_compatible", LOCAL: "local", REPLAY: "replay"}

# Only the adapter-shaped default counts as uninformative. "opencode",
# "openai", "groq" and friends are legitimate service names an operator can
# configure, so they are shown as given.
_GENERIC_CLOUD_PROVIDERS = frozenset({"openai_compatible", ""})

_UNSET = "Configured model"


def _clean(value: Any) -> str | None:
    """Normalize a metadata value to a display string, or None when absent."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def cloud_provider_label() -> str | None:
    """The service the cloud tier is configured to address.

    Prefers the operator-configured provenance label, because that is the only
    field that distinguishes one gateway from another. Falls back to a neutral
    "Cloud" rather than naming a vendor nobody configured.
    """
    configured = _clean(config.CLOUD_PROVIDER_LABEL)
    if configured and configured.lower() not in _GENERIC_CLOUD_PROVIDERS:
        return configured
    return None


def local_runtime_label() -> str | None:
    """Runtime that serves the local tier.

    Taken from the adapter that implements the tier, because that is the only
    place the runtime is actually known: a host string like `localhost` names a
    machine, not a runtime. Falls back to the host when the adapter cannot be
    consulted, and to None when neither is available.
    """
    try:
        from app.llm.local_provider import LocalProvider

        declared = _clean(getattr(LocalProvider, "runtime", None))
        if declared:
            return declared
    except Exception:  # noqa: BLE001 - display metadata must never break a page
        pass
    host = _clean(config.LOCAL_HOST)
    if not host:
        return None
    return _clean(host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].strip().lower())


def tier_identity(tier: str) -> dict[str, str | None]:
    """Active configuration for one tier, as display fields.

    `provider` and `model` are None when genuinely unknown. Callers must render
    a fallback rather than inventing a value.
    """
    if tier == LOCAL:
        return {"tier": LOCAL, "provider": local_runtime_label(), "model": _clean(config.LOCAL_MODEL)}
    if tier == REPLAY:
        return {"tier": REPLAY, "provider": None, "model": None}
    return {
        "tier": CLOUD,
        "provider": cloud_provider_label(),
        "model": _clean(config.CLOUD_MODEL),
    }


def format_inference_label(tier: str, provider: Any = None, model: Any = None) -> str:
    """Render one tier as `Tier · provider / model`.

    Missing metadata degrades honestly rather than being invented:
    `Cloud · Configured model`, `Local · Ollama`, `Replay · Deterministic`.
    """
    provider_text = _clean(provider)
    model_text = _clean(model)

    if tier == REPLAY:
        return "Replay · Deterministic"

    title = "Local" if tier == LOCAL else "Cloud"
    if provider_text and model_text:
        return f"{title} · {provider_text} / {model_text}"
    if provider_text:
        return f"{title} · {provider_text}"
    if model_text:
        return f"{title} · {model_text}"
    return f"{title} · {_UNSET}"


def tier_option_label(tier: str) -> str:
    """Dropdown label for a tier, from the ACTIVE configuration."""
    identity = tier_identity(tier)
    return format_inference_label(tier, identity["provider"], identity["model"])


def tier_options() -> list[dict[str, str]]:
    """Exactly one option per tier, in display order.

    Built from a fixed tier list rather than a provider list, so a duplicate
    entry is structurally impossible: adding a backend alias cannot add a row.
    """
    return [{"tier": tier, "value": TIER_PROVIDER_KEY[tier], "label": tier_option_label(tier)} for tier in (CLOUD, LOCAL, REPLAY)]


def option_label_for_key(provider_key: str) -> str | None:
    """Label for a backend provider key, reusing the SAME option list.

    The selected value is looked up in the options rather than formatted a
    second time, so the closed selection can never disagree with the list. A
    legacy alias is normalized to its tier first, so both spellings of the
    cloud key resolve to the one Cloud option instead of one of them going
    blank.
    """
    for option in tier_options():
        if option["value"] == provider_key:
            return option["label"]
    tier = _tier_for_key(provider_key)
    if tier is None:
        return None
    for option in tier_options():
        if option["tier"] == tier:
            return option["label"]
    return None


def describe_llm(llm: Any) -> dict[str, str | None]:
    """Display identity of the provider object that served a run.

    Captured at run time and stored on the run, so a later configuration change
    cannot relabel a result that is already on screen.
    """
    if llm is None:
        return {"tier": None, "provider": None, "model": None}

    name = _clean(getattr(llm, "name", "")) or ""
    if name == REPLAY:
        return {"tier": REPLAY, "provider": None, "model": None}
    if name == LOCAL:
        return {
            "tier": LOCAL,
            "provider": local_runtime_label(),
            "model": _clean(getattr(llm, "model", None)),
        }
    # Cloud: the resolved adapter may be the native Anthropic one or any
    # OpenAI-shaped client. Both are cloud; the configured provider label (not
    # the adapter name) is the user-facing identity.
    return {
        "tier": CLOUD,
        "provider": cloud_provider_label(),
        "model": _clean(getattr(llm, "model", None)),
    }


def format_run_label(run: Any) -> str:
    """Label for a restored run, from that run's OWN recorded identity.

    `run` may be a `JudgeRun` or the metadata dict served by /judge/state. Both
    are supported because the banner is rendered from the API payload. When no
    identity was recorded the label degrades to the active configuration's
    label rather than inventing one, and never to a bare tier name if a real
    provider is configured.
    """
    identity = getattr(run, "inference", None)
    if identity is None and isinstance(run, dict):
        identity = run.get("inference")

    if not identity:
        # A run from before identity capture: fall back to the tier it used.
        requested = getattr(run, "requested_provider", None)
        if requested is None and isinstance(run, dict):
            requested = run.get("requested_provider")
        tier = _tier_for_key(requested)
        if tier is None:
            return ""
        return format_inference_label(tier, None, None)

    tier = _clean(identity.get("tier")) or ""
    return format_inference_label(tier, identity.get("provider"), identity.get("model"))


def _tier_for_key(provider_key: Any) -> str | None:
    """Map a backend provider key back to its tier, aliases included."""
    key = _clean(provider_key)
    if not key:
        return None
    if key in ("opencode", "openai_compatible"):
        return CLOUD
    if key == LOCAL:
        return LOCAL
    if key == REPLAY:
        return REPLAY
    return None
