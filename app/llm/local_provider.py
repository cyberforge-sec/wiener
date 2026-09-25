from __future__ import annotations

import httpx

from ..config import config
from .base import LLMResponse, ProviderUnavailable


def ollama_reachable(host: str, timeout_s: float) -> bool:
    try:
        url = f"{host.rstrip('/')}/api/tags"
        resp = httpx.get(url, timeout=timeout_s)
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


class LocalProvider:
    """Local Qwen2.5 model via Ollama HTTP API.

    Configuration:
      WIENER_LOCAL_HOST / MODEL / TIMEOUT_S / MAX_TOKENS / KEEP_ALIVE.
    Output is bounded (`max_tokens` → Ollama `num_predict`) so the model
    returns short structured responses, never long reasoning.
    Raises ProviderUnavailable with a normalized `kind` on failure.
    """

    name = "local"

    def __init__(
        self,
        host: str | None = None,
        model: str | None = None,
        timeout_s: float | None = None,
        max_tokens: int | None = None,
        keep_alive: str | None = None,
        temperature: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._host = host if host is not None else config.LOCAL_HOST
        self._model = model if model is not None else config.LOCAL_MODEL
        self._timeout_s = timeout_s if timeout_s is not None else config.LOCAL_TIMEOUT_S
        self._max_tokens = max_tokens if max_tokens is not None else config.LOCAL_MAX_TOKENS
        self._keep_alive = keep_alive if keep_alive is not None else config.LOCAL_KEEP_ALIVE
        self._temperature = temperature if temperature is not None else config.LOCAL_TEMPERATURE
        self._transport = transport

    def complete(self, system: str, user: str) -> LLMResponse:
        url = f"{self._host.rstrip('/')}/api/generate"
        payload = {
            "model": self._model,
            "prompt": f"{system}\n\n{user}",
            "stream": False,
            "keep_alive": self._keep_alive,
            "options": {"temperature": self._temperature, "num_predict": self._max_tokens},
        }

        try:
            kwargs: dict = {"timeout": self._timeout_s}
            if self._transport is not None:
                kwargs["transport"] = self._transport
            with httpx.Client(**kwargs) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
            # Ollama generate returns {"response": "<text>"}.
            text = str(data.get("response", "")).strip()
        except httpx.TimeoutException as exc:
            raise ProviderUnavailable(f"LocalProvider: timeout: {exc}", kind="timeout") from exc
        except httpx.ConnectError as exc:
            raise ProviderUnavailable(f"LocalProvider: connection failed: {exc}", kind="connection") from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                raise ProviderUnavailable(f"LocalProvider: auth failed: {exc}", kind="auth") from exc
            raise ProviderUnavailable(f"LocalProvider: HTTP {exc.response.status_code}: {exc}", kind="unavailable") from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailable(f"LocalProvider: request failed: {exc}", kind="unavailable") from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise ProviderUnavailable(f"LocalProvider: malformed response: {exc}", kind="malformed") from exc

        return LLMResponse(
            text=text,
            provider=self.name,
            meta={
                "model": self._model,
                "max_tokens": self._max_tokens,
                "temperature": self._temperature,
                "deterministic_requested": self._temperature == 0,
            },
        )