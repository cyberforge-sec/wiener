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
        # None = not probed yet; True/False = Ollama supports /api/chat.
        self._chat: bool | None = None

    def complete(self, system: str, user: str) -> LLMResponse:
        """Generate via Ollama.

        Uses the /api/chat endpoint with real system/user roles whenever the
        server supports it, so the system prompt keeps its instruction
        priority instead of being concatenated into a single user turn. Older
        servers (no /api/chat) fall back to /api/generate with the previous
        flattened prompt, and the response records which path was used, so an
        artifact can never imply role separation it did not get.
        """
        if self._chat_supported():
            text = self._complete_chat(system, user)
            path = "api/chat"
        else:
            text = self._complete_generate(f"{system}\n\n{user}")
            path = "api/generate"
        return LLMResponse(
            text=text,
            provider=self.name,
            meta={
                "model": self._model,
                "max_tokens": self._max_tokens,
                "temperature": self._temperature,
                "deterministic_requested": self._temperature == 0,
                "endpoint": path,
                # False means system and user were concatenated into one turn,
                # so the system prompt had no enforced priority.
                "role_separation": path == "api/chat",
            },
        )

    def _post(self, url: str, payload: dict) -> dict:
        try:
            kwargs: dict = {"timeout": self._timeout_s}
            if self._transport is not None:
                kwargs["transport"] = self._transport
            with httpx.Client(**kwargs) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                return resp.json()
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

    def _chat_supported(self) -> bool:
        """Whether this server exposes /api/chat, probed by a real call.

        Only an absent endpoint (404/405) selects the legacy /api/generate
        path. A timeout or a server error propagates: silently downgrading to
        the flattened prompt would change the trust boundary without saying so.
        """
        if self._chat is not None:
            return self._chat
        try:
            self._post(f"{self._host.rstrip('/')}/api/chat", {"model": self._model, "stream": False})
        except ProviderUnavailable as exc:
            message = str(exc)
            if "HTTP 404" in message or "HTTP 405" in message:
                self._chat = False
                return False
            raise
        self._chat = True
        return True

    def _complete_chat(self, system: str, user: str) -> str:
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "keep_alive": self._keep_alive,
            "options": {"temperature": self._temperature, "num_predict": self._max_tokens},
        }
        data = self._post(f"{self._host.rstrip('/')}/api/chat", payload)
        message = data.get("message") or {}
        return str(message.get("content", "")).strip()

    def _complete_generate(self, prompt: str) -> str:
        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": self._keep_alive,
            "options": {"temperature": self._temperature, "num_predict": self._max_tokens},
        }
        data = self._post(f"{self._host.rstrip('/')}/api/generate", payload)
        return str(data.get("response", "")).strip()
