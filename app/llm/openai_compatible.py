from __future__ import annotations

import json
from pathlib import Path

import httpx

from ..config import config
from .base import LLMResponse, ProviderUnavailable
from .identity import ProviderIdentity
from .parsing import extract_json_object


def _strip_stream_sentinel(content: bytes) -> bytes:
    """Some OpenAI-compatible gateways append a trailing
    streaming sentinel (\\n\\ndata: [DONE]\\n) even for non-streaming
    responses. Keep only the JSON object that precedes it."""
    text = content.decode("utf-8", errors="replace")
    marker = "data: [DONE]"
    idx = text.find(marker)
    if idx != -1:
        text = text[:idx]
    return text.strip().encode("utf-8")


MAX_CONTENT_ATTEMPTS = 3


def _reported_model(data: dict) -> str | None:
    """The model id the provider says it served, or None when it says nothing."""
    value = data.get("model")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _usage(data: dict) -> dict | None:
    usage = data.get("usage")
    if isinstance(usage, dict) and usage:
        return {k: v for k, v in usage.items() if isinstance(v, (int, float))}
    return None


class OpenAICompatibleProvider:
    """Generic cloud adapter for any OpenAI-compatible chat completions API.

    This is the provider-neutral cloud path, not an OpenCode client. It targets
    the de-facto standard shape (`POST {base_url}/chat/completions` with
    `messages`), so one tested adapter covers OpenAI and OpenAI-compatible
    gateways, Groq, OpenRouter, and similar services. The service on the other
    end is identified by config, never by this class.

    `provider_label` records WHICH service was addressed. It is provenance, not
    routing: the security layer never branches on it.

    Configuration comes from environment/config, never hardcoded:
      WIENER_CLOUD_API_KEY / BASE_URL / MODEL / TEMPERATURE /
      RESPONSE_FORMAT / PROVIDER_LABEL, LLM_TIMEOUT_S.
    Raises ProviderUnavailable with a normalized `kind` on failure.

    `response_format` (e.g. {"type": "json_object"}) is requested so backends
    that support structured decoding constrain the output at the API level.
    If a backend rejects the parameter, it is retried once without it.
    """

    name = "openai_compatible"

    @property
    def model(self) -> str | None:
        return self._model


    # The transport is not the product: kept as an import alias so existing
    # callers and stored evidence keep resolving.
    def __init_subclass__(cls, **kwargs):  # pragma: no cover - defensive
        super().__init_subclass__(**kwargs)

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_s: float | None = None,
        temperature: float | None = None,
        response_format: str | None = None,
        transport: httpx.BaseTransport | None = None,
        diag_path: str | None = None,
        provider_label: str | None = None,
        expected_model: str | None = None,
        route_prefixes: tuple[str, ...] | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else config.CLOUD_API_KEY
        self._base_url = base_url if base_url is not None else config.CLOUD_BASE_URL
        self._model = model if model is not None else config.CLOUD_MODEL
        self._timeout_s = timeout_s if timeout_s is not None else config.LLM_TIMEOUT_S
        self._temperature = (
            temperature if temperature is not None else config.CLOUD_TEMPERATURE
        )
        self._response_format = (
            response_format
            if response_format is not None
            else config.CLOUD_RESPONSE_FORMAT
        )
        self._transport = transport
        self._provider_label = (
            provider_label if provider_label is not None else config.CLOUD_PROVIDER_LABEL
        )
        self._expected_model = (
            expected_model if expected_model is not None else config.CLOUD_EXPECTED_MODEL
        ) or None
        # Trusted routing namespaces, configuration only. Overridable per
        # instance for tests and for deployments that front more than one
        # gateway; never derived from the model id or a provider response.
        self._route_prefixes = (
            tuple(route_prefixes)
            if route_prefixes is not None
            else config.CLOUD_MODEL_ROUTE_PREFIXES
        )
        diag = diag_path if diag_path is not None else config.CLOUD_DIAG_PATH
        self._diag_path = Path(diag).expanduser() if diag else None
        if self._diag_path is not None and not self._diag_path.is_absolute():
            self._diag_path = Path(__file__).resolve().parent.parent.parent / self._diag_path
        if self._diag_path is not None:
            self._diag_path.parent.mkdir(parents=True, exist_ok=True)

    def _build_client(self) -> httpx.Client:
        kwargs: dict = {"timeout": self._timeout_s}
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return httpx.Client(**kwargs)

    def _normalize_error(self, exc: Exception) -> ProviderUnavailable:
        if isinstance(exc, httpx.TimeoutException):
            return ProviderUnavailable(f"OpenAICompatibleProvider: timeout: {exc}", kind="timeout")
        if isinstance(exc, httpx.ConnectError):
            return ProviderUnavailable(f"OpenAICompatibleProvider: connection failed: {exc}", kind="connection")
        if isinstance(exc, httpx.HTTPStatusError):
            if exc.response.status_code in (401, 403):
                return ProviderUnavailable(f"OpenAICompatibleProvider: auth failed: {exc}", kind="auth")
            return ProviderUnavailable(f"OpenAICompatibleProvider: HTTP {exc.response.status_code}: {exc}", kind="unavailable")
        if isinstance(exc, httpx.HTTPError):
            return ProviderUnavailable(f"OpenAICompatibleProvider: request failed: {exc}", kind="unavailable")
        return ProviderUnavailable(f"OpenAICompatibleProvider: unexpected error: {exc}", kind="unavailable")

    def _diag(self, label: str, body: bytes, limit: int = 1200) -> None:
        """Append raw response for post-mortem (null-vs-truncation-vs-prose)."""
        if self._diag_path is None:
            return
        try:
            with self._diag_path.open("a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"=== {label} ===\n")
                fh.write(body.decode("utf-8", errors="replace")[:limit])
                fh.write("\n")
        except OSError:
            pass

    def _payload(self, system: str, user: str, use_format: bool) -> dict:
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self._temperature,
            "max_tokens": 500,
        }
        if use_format and self._response_format:
            payload["response_format"] = {"type": self._response_format}
        return payload

    def complete(self, system: str, user: str) -> LLMResponse:
        if not self._api_key:
            raise ProviderUnavailable("OpenAICompatibleProvider: no API key configured", kind="auth")

        url = f"{self._base_url.rstrip('/')}/chat/completions"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        format_attempts = [True, False] if self._response_format else [False]
        last_exc: Exception | None = None
        request_count = 0

        for use_format in format_attempts:
            for _ in range(MAX_CONTENT_ATTEMPTS):
                request_count += 1
                try:
                    with self._build_client() as client:
                        resp = client.post(url, headers=headers, json=self._payload(system, user, use_format))
                        if resp.status_code in (400, 422, 501) and use_format:
                            self._diag(f"retry-without-format (HTTP {resp.status_code})", resp.content)
                            last_exc = ProviderUnavailable(
                                f"OpenAICompatibleProvider: response_format rejected (HTTP {resp.status_code})",
                                kind="unavailable",
                            )
                            break
                        resp.raise_for_status()
                        body = resp.content
                    raw = _strip_stream_sentinel(body)
                    data = json.loads(raw)
                    content = data["choices"][0]["message"].get("content")
                    if not isinstance(content, str) or not content.strip():
                        self._diag("null-content", body)
                        raise ProviderUnavailable("OpenAICompatibleProvider: empty content in response", kind="malformed")
                    text = content.strip()
                    if use_format and self._response_format == "json_object":
                        try:
                            extract_json_object(text)
                        except ValueError as exc:
                            raise ProviderUnavailable(
                                "OpenAICompatibleProvider: response_format produced no JSON object",
                                kind="malformed",
                            ) from exc
                except ProviderUnavailable as exc:
                    last_exc = exc
                    continue
                except (httpx.HTTPError, TimeoutError, OSError) as exc:
                    last_exc = exc
                    continue
                except (ValueError, KeyError, IndexError, TypeError) as exc:
                    last_exc = exc
                    continue
                else:
                    identity = ProviderIdentity(
                        provider=self._provider_label,
                        adapter=self.name,
                        requested_model=self._model,
                        # What the gateway says it served. Frequently different
                        # from what we asked for (prefixes get rewritten), and
                        # frequently absent. Recorded, never assumed.
                        provider_reported_model=_reported_model(data),
                        temperature=self._temperature,
                        deterministic_requested=self._temperature == 0,
                        endpoint="chat/completions",
                        declared_model=self._expected_model,
                        # Namespaces this gateway is trusted to strip, from
                        # configuration only. This is what lets a routing
                        # rewrite such as `oc/big-pickle` -> `big-pickle` be
                        # verified; without a configured entry the same
                        # rewrite stays unverified.
                        trusted_route_prefixes=self._route_prefixes,
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
        if isinstance(last_exc, (httpx.HTTPError, TimeoutError, OSError)):
            raise self._normalize_error(last_exc) from last_exc
        if isinstance(last_exc, (ValueError, KeyError, IndexError, TypeError)):
            raise ProviderUnavailable(f"OpenAICompatibleProvider: malformed response: {last_exc}", kind="malformed") from last_exc
        raise ProviderUnavailable("OpenAICompatibleProvider: request failed", kind="unavailable")
