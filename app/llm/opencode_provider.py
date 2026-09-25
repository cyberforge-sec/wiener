"""Back-compat alias for the historical cloud adapter module name.

The cloud tier used to be implemented as `app.llm.opencode_provider
.OpenCodeProvider`. It is now `app.llm.openai_compatible
.OpenAICompatibleProvider`, because the adapter targets the OpenAI-compatible
chat-completions shape used by many services, not one vendor.

This module exists so existing imports keep working. It will not be removed
while stored evidence and older .env files still refer to the old name.

`OpenCodeProvider.name` is deliberately NOT "opencode": evidence that records
the transport name in the model field is a provenance defect (invariant
I-13b). Configure the service you actually address with
WIENER_CLOUD_PROVIDER_LABEL.
"""

from __future__ import annotations

from .openai_compatible import OpenAICompatibleProvider

# Historical class name, current implementation.
OpenCodeProvider = OpenAICompatibleProvider

__all__ = ["OpenCodeProvider", "OpenAICompatibleProvider"]
