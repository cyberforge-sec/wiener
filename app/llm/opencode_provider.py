from __future__ import annotations

import json
from pathlib import Path

import httpx

from ..config import config
from .base import LLMResponse, ProviderUnavailable


def _strip_stream_sentinel(content: bytes) -> bytes:
    """Some OpenAI-compatible gateways (e.g. 9router) append a trailing
    streaming sentinel (\\n\\ndata: [DONE]\\n) even for non-streaming
    responses. Keep only the JSON object that precedes it."""
    text = content.decode("utf-8", errors="replace")
    marker = "data: [DONE]"
    idx = text.find(marker)
    if idx != -1:
        text = text[:idx]
    return text.strip().encode("utf-8")


class OpenCodeProvider:
    """Cloud LLM provider (OpenAI-compatible chat completions endpoint).

    Configuration comes from environment/config, never hardcoded:
      WIENER_CLOUD_API_KEY / BASE_URL / MODEL / TEMPERATURE /
      RESPONSE_FORMAT, LLM_TIMEOUT_S.
    Raises ProviderUnavailable with a normalized `kind` on failure.

    `response_format` (e.g. {"type": "json_object"}) is requested so backends
    that support structured decoding constrain the output at the API level.
    If a backend rejects the parameter, it is retried once without it.
    """

    name = "opencode"

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
            return ProviderUnavailable(f"OpenCodeProvider: timeout: {exc}", kind="timeout")
        if isinstance(exc, httpx.ConnectError):
            return ProviderUnavailable(f"OpenCodeProvider: connection failed: {exc}", kind="connection")
        if isinstance(exc, httpx.HTTPStatusError):
            if exc.response.status_code in (401, 403):
                return ProviderUnavailable(f"OpenCodeProvider: auth failed: {exc}", kind="auth")
            return ProviderUnavailable(f"OpenCodeProvider: HTTP {exc.response.status_code}: {exc}", kind="unavailable")
        if isinstance(exc, httpx.HTTPError):
            return ProviderUnavailable(f"OpenCodeProvider: request failed: {exc}", kind="unavailable")
        return ProviderUnavailable(f"OpenCodeProvider: unexpected error: {exc}", kind="unavailable")

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
            raise ProviderUnavailable("OpenCodeProvider: no API key configured", kind="auth")

        url = f"{self._base_url.rstrip('/')}/chat/completions"
        headers = {"Authorization": f"Bearer {self._api_key}"}

        # Try with response_format first; retry without on 4xx.
        attempts = [True, False] if self._response_format else [False]
        last_exc: Exception | None = None

        for use_format in attempts:
            try:
                with self._build_client() as client:
                    resp = client.post(url, headers=headers, json=self._payload(system, user, use_format))
                    if resp.status_code in (400, 422, 501) and use_format:
                        self._diag(f"retry-without-format (HTTP {resp.status_code})", resp.content)
                        continue
                    resp.raise_for_status()
                    body = resp.content
                raw = _strip_stream_sentinel(body)
                data = json.loads(raw)
                content = data["choices"][0]["message"].get("content")
                if not content:
                    self._diag("null-content", body)
                    raise ProviderUnavailable("OpenCodeProvider: empty content in response", kind="malformed")
                text = content.strip()
            except (httpx.HTTPError, TimeoutError, OSError) as exc:
                last_exc = exc
                continue
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                last_exc = exc
                continue
            else:
                return LLMResponse(text=text, provider=self.name, meta={"model": self._model})

        if isinstance(last_exc, ProviderUnavailable):
            raise last_exc
        if isinstance(last_exc, (httpx.HTTPError, TimeoutError, OSError)):
            raise self._normalize_error(last_exc) from last_exc
        if isinstance(last_exc, (ValueError, KeyError, IndexError, TypeError)):
            raise ProviderUnavailable(f"OpenCodeProvider: malformed response: {last_exc}", kind="malformed") from last_exc
        raise ProviderUnavailable("OpenCodeProvider: request failed", kind="unavailable")
