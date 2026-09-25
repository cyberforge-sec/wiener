"""Native Anthropic Messages API adapter.

This adapter exists to prove a specific architectural property rather than to
add a logo to a diagram: the security layer must not depend on the shape of the
provider's API. The Messages API is not OpenAI-shaped:

  - system prompt is a top-level `system` parameter, not a message
  - auth is `x-api-key` plus a version header, not `Authorization: Bearer`
  - the response is a list of typed content blocks, not `choices[0].message`
  - there is no `response_format` / json_object parameter to request
  - usage is `input_tokens` / `output_tokens`

All of that translation happens here, inside the adapter. What leaves this
module is the same normalized `LLMResponse` every other adapter returns, so
the trajectory, Blue AI, Risk Engine, Policy Gate and Tool Executor are
untouched and provider-blind.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from ..config import config
from .base import LLMResponse, ProviderUnavailable
from .identity import ProviderIdentity
from .parsing import extract_json_object

# Anthropic requires an explicit API version header and rejects requests
# without it. Pinned, not configurable: a moving version would make the
# recorded evidence depend on when it was produced.
ANTHROPIC_VERSION = "2023-06-01"

# Matches the OpenAI-shaped adapter: a malformed or empty generation is
# retried a bounded number of times, never silently accepted.
MAX_CONTENT_ATTEMPTS = 3


class AnthropicProvider:
    """Cloud adapter for Anthropic's native Messages API.

    Configuration comes from environment/config, never hardcoded:
      WIENER_ANTHROPIC_API_KEY / BASE_URL / MODEL / MAX_TOKENS, LLM_TIMEOUT_S.

    Raises ProviderUnavailable with a normalized `kind` on failure, so the
    failover ladder treats it exactly like any other cloud tier.
    """

    name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_s: float | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        response_format: str | None = None,
        transport: httpx.BaseTransport | None = None,
        diag_path: str | None = None,
        provider_label: str | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else config.ANTHROPIC_API_KEY
        self._base_url = (base_url if base_url is not None else config.ANTHROPIC_BASE_URL).rstrip("/")
        self._model = model if model is not None else config.ANTHROPIC_MODEL
        self._timeout_s = timeout_s if timeout_s is not None else config.LLM_TIMEOUT_S
        self._temperature = temperature if temperature is not None else config.CLOUD_TEMPERATURE
        self._max_tokens = max_tokens if max_tokens is not None else config.ANTHROPIC_MAX_TOKENS
        # Accepted for interface symmetry with the OpenAI-shaped adapter and
        # deliberately NOT sent: this API has no json_object mode. Structured
        # output is obtained by asking for it in the prompt and validating.
        self._response_format = response_format
        self._transport = transport
        self._provider_label = provider_label if provider_label is not None else "anthropic"
        diag = diag_path if diag_path is not None else config.CLOUD_DIAG_PATH
        self._diag_path = Path(diag).expanduser() if diag else None
        if self._diag_path is not None and not self._diag_path.is_absolute():
            self._diag_path = Path(__file__).resolve().parent.parent.parent / self._diag_path
        if self._diag_path is not None:
            self._diag_path.parent.mkdir(parents=True, exist_ok=True)

    def _client(self) -> httpx.Client:
        kwargs: dict = {"timeout": self._timeout_s}
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return httpx.Client(**kwargs)

    def _diag(self, tag: str, content: bytes) -> None:
        """Opt-in raw-response capture. Disabled by default: responses can be
        sensitive operational data."""
        if self._diag_path is None:
            return
        try:
            with self._diag_path.open("ab") as fh:
                fh.write(f"\n--- {tag} {content.decode('utf-8', errors='replace')[:2000]}\n".encode())
        except OSError:
            pass

    def _payload(self, system: str, user: str) -> dict:
        """Native Messages body. Note: no `response_format`, and the system
        prompt is not smuggled in as a user turn."""
        return {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "temperature": self._temperature,
            "system": system,
            "messages": [{"role": "user", "content": [{"type": "text", "text": user}]}],
        }

    def _headers(self) -> dict:
        return {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    def _classify(self, exc: Exception) -> ProviderUnavailable:
        if isinstance(exc, httpx.TimeoutException):
            return ProviderUnavailable(f"AnthropicProvider: timeout: {exc}", kind="timeout")
        if isinstance(exc, httpx.ConnectError):
            return ProviderUnavailable(f"AnthropicProvider: connection failed: {exc}", kind="connection")
        if isinstance(exc, httpx.HTTPStatusError):
            status = exc.response.status_code
            detail = _error_text(exc.response)
            if status in (401, 403):
                return ProviderUnavailable(
                    f"AnthropicProvider: auth failed (HTTP {status}): {detail}", kind="auth"
                )
            return ProviderUnavailable(
                f"AnthropicProvider: HTTP {status}: {detail}", kind="unavailable"
            )
        if isinstance(exc, httpx.HTTPError):
            return ProviderUnavailable(f"AnthropicProvider: request failed: {exc}", kind="unavailable")
        if isinstance(exc, (ValueError, KeyError, IndexError, TypeError)):
            return ProviderUnavailable(f"AnthropicProvider: malformed response: {exc}", kind="malformed")
        return ProviderUnavailable(f"AnthropicProvider: request failed: {exc}", kind="unavailable")

    def complete(self, system: str, user: str) -> LLMResponse:
        if not self._api_key:
            raise ProviderUnavailable(
                "AnthropicProvider: no API key configured (set WIENER_ANTHROPIC_API_KEY)",
                kind="auth",
            )

        url = f"{self._base_url}/v1/messages"
        request_count = 0
        last_exc: Exception | None = None

        for _ in range(MAX_CONTENT_ATTEMPTS):
            request_count += 1
            try:
                with self._client() as client:
                    resp = client.post(url, headers=self._headers(), json=self._payload(system, user))
                    resp.raise_for_status()
                    body = resp.content
                data = json.loads(body)
                text = _text_from_content(data)
                if not text:
                    self._diag("empty-content", body)
                    raise ProviderUnavailable(
                        "AnthropicProvider: empty content in response", kind="malformed"
                    )
                # The caller decides how to parse; we only refuse a response
                # that contains no JSON object at all when the caller asked for
                # structured output.
                if self._response_format == "json_object":
                    try:
                        extract_json_object(text)
                    except ValueError as exc:
                        raise ProviderUnavailable(
                            f"AnthropicProvider: response contained no JSON object: {exc}",
                            kind="malformed",
                        ) from exc
            except ProviderUnavailable as exc:
                last_exc = exc
                continue
            except Exception as exc:  # noqa: BLE001 - normalized below
                last_exc = exc
                continue
            else:
                identity = ProviderIdentity(
                    provider=self._provider_label,
                    adapter="anthropic_messages",
                    requested_model=self._model,
                    provider_reported_model=_reported_model(data),
                    temperature=self._temperature,
                    deterministic_requested=self._temperature == 0,
                    endpoint="v1/messages",
                    extra={"stop_reason": data.get("stop_reason")},
                )
                return LLMResponse(
                    text=text,
                    provider=self.name,
                    meta={
                        **identity.as_meta(),
                        "request_attempts": request_count,
                        "retry_count": request_count - 1,
                        "usage": _usage(data),
                    },
                )

        if isinstance(last_exc, ProviderUnavailable):
            raise last_exc
        # A raw transport/HTTP error never reached _classify during the loop
        # (it is only raised after the attempts are exhausted), so classify it
        # here. Without this, a 401 would be reported as a generic outage and
        # the ladder would treat a wrong key as a transient fault.
        raise self._classify(last_exc) from last_exc


def _text_from_content(data: dict) -> str:
    """Concatenate the text blocks of a Messages response.

    A response whose `content` is not a list of blocks is malformed, not an
    empty answer: the two must not be conflated.
    """
    content = data.get("content")
    if not isinstance(content, list):
        raise ValueError("content is not a list of content blocks")
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            value = block.get("text")
            if isinstance(value, str):
                parts.append(value)
    return "\n".join(parts).strip()


def _reported_model(data: dict) -> str | None:
    value = data.get("model")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _usage(data: dict) -> dict | None:
    usage = data.get("usage")
    if isinstance(usage, dict) and usage:
        return {k: v for k, v in usage.items() if isinstance(v, (int, float))}
    return None


def _error_text(response: httpx.Response) -> str:
    try:
        payload = response.json()
        error = payload.get("error")
        if isinstance(error, dict) and error.get("message"):
            return str(error["message"])[:200]
    except Exception:  # noqa: BLE001 - diagnostics only
        pass
    return response.text[:200]
