from __future__ import annotations

from app.llm.base import LLMProvider, LLMResponse, ProviderUnavailable


class FakeLLM(LLMProvider):
    """Scripted test double."""

    name = "fake"

    def __init__(self, responses: list[str] | None = None, fail: bool = False) -> None:
        self._responses = list(responses or [])
        self._fail = fail
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> LLMResponse:
        self.calls.append((system, user))
        if self._fail:
            raise ProviderUnavailable("fake failure")
        if self._responses:
            return LLMResponse(text=self._responses.pop(0), provider=self.name)
        return LLMResponse(
            text='{"action": "check_endpoint", "target": "host-a", "confidence": 0.5}',
            provider=self.name,
        )


class FailingLLM(LLMProvider):
    name = "failing"

    def __init__(self, kind: str = "unavailable") -> None:
        self._kind = kind

    def complete(self, system: str, user: str) -> LLMResponse:
        raise ProviderUnavailable("failing provider", kind=self._kind)
