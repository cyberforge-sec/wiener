from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.llm import factory
from app.llm.base import LLMProvider, LLMResponse, ProviderUnavailable
from app.models import Action
from app.soc_agent.soc_agent import SOCAgent

from .test_soc_agent import make_ctx


class _StubProvider(LLMProvider):
    name = "stub"

    def __init__(
        self, name: str, *, fail_kind: str | None = None, valid_text: bool = True
    ) -> None:
        self.name = name
        self._fail_kind = fail_kind
        self._valid_text = valid_text
        self.calls = 0

    def complete(self, system: str, user: str) -> LLMResponse:
        self.calls += 1
        if self._fail_kind:
            raise ProviderUnavailable(f"{self.name} unavailable", kind=self._fail_kind)
        if not self._valid_text:
            return LLMResponse(text="this is not json", provider=self.name)
        return LLMResponse(
            text='{"action": "get_logs", "confidence": 0.6}', provider=self.name
        )


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def monotonic(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(factory, "time", c)
    return c


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Fresh factory state per test: empty cache, no cooldown, default ladder,
    local reachable unless a test overrides it."""
    monkeypatch.setattr(
        factory,
        "config",
        SimpleNamespace(LLM_FORCE="", LOCAL_HOST="http://localhost:11434"),
    )
    monkeypatch.setattr(factory, "ollama_reachable", lambda *a, **k: True)
    factory._ACTIVE = None
    factory._cloud_retry_after = 0.0
    yield
    factory._ACTIVE = None
    factory._cloud_retry_after = 0.0


def test_transient_cloud_failure_demotes_cached_provider_to_local(monkeypatch):
    cloud = _StubProvider("opencode", fail_kind="timeout")

    def fake_build(name, *, strict_replay=False):
        return cloud if name == "opencode" else _StubProvider(name)

    monkeypatch.setattr(factory, "_build", fake_build)

    agent = SOCAgent(factory.get_llm())
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == Action.CHECK_ENDPOINT
    assert provider == "degraded"

    # The outage demoted the cached provider; next resolution skips the cooling cloud.
    assert factory.get_llm().name == "local"


def test_cloud_cooldown_skips_cloud_then_self_heals(monkeypatch, clock):
    built: list[str] = []

    def fake_build(name, *, strict_replay=False):
        built.append(name)
        return _StubProvider(name)

    monkeypatch.setattr(factory, "_build", fake_build)

    # t=100: a cloud outage starts the cloud cooldown.
    factory.fail_provider(tier="opencode")
    assert factory.get_llm().name == "local"
    assert built == ["local"]

    # t=120: inside cooldown, a local fault cannot send us back to a cooling cloud.
    clock.now += 20.0
    factory.fail_provider(tier="local")
    assert factory.get_llm().name == "local"
    assert built == ["local", "local"]

    # t=200: cooldown expired; a local fault retries cloud without restarting the window.
    clock.now += 80.0
    factory.fail_provider(tier="local")
    assert factory.get_llm().name == "opencode"
    assert built == ["local", "local", "opencode"]


def test_malformed_response_keeps_current_tier(monkeypatch):
    cloud = _StubProvider("opencode", fail_kind="malformed")

    def fake_build(name, *, strict_replay=False):
        return cloud if name == "opencode" else _StubProvider(name)

    monkeypatch.setattr(factory, "_build", fake_build)

    agent = SOCAgent(factory.get_llm())
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == Action.CHECK_ENDPOINT
    assert provider == "degraded"

    # malformed is model behavior, not an outage → same tier on next resolve.
    assert factory.get_llm() is cloud


def test_invalid_model_json_keeps_current_tier(monkeypatch):
    cloud = _StubProvider("opencode", valid_text=False)

    def fake_build(name, *, strict_replay=False):
        return cloud if name == "opencode" else _StubProvider(name)

    monkeypatch.setattr(factory, "_build", fake_build)

    agent = SOCAgent(factory.get_llm())
    out, _, provider = agent.analyze(make_ctx())
    assert provider == "degraded"
    assert factory.get_llm() is cloud


def test_sustained_outage_falls_to_replay_without_cloud_retry(monkeypatch):
    cloud = _StubProvider("opencode", fail_kind="timeout")
    local = _StubProvider("local", fail_kind="timeout")

    def fake_build(name, *, strict_replay=False):
        if name == "opencode":
            return cloud
        if name == "local":
            return local
        return _StubProvider("replay")

    monkeypatch.setattr(factory, "_build", fake_build)
    monkeypatch.setattr(factory, "ollama_reachable", lambda *a, **k: False)

    agent = SOCAgent(factory.get_llm())
    assert agent.analyze(make_ctx())[2] == "degraded"

    next_provider = factory.get_llm()
    assert next_provider.name == "replay"
    # The dead cloud was never re-hit during cooldown (avoids a 30 s burn per call).
    assert cloud.calls == 1


def test_sustained_outage_resolves_local_after_cloud_cooldown(monkeypatch):
    cloud = _StubProvider("opencode", fail_kind="timeout")

    def fake_build(name, *, strict_replay=False):
        return cloud if name == "opencode" else _StubProvider(name)

    monkeypatch.setattr(factory, "_build", fake_build)

    agent = SOCAgent(factory.get_llm())
    assert agent.analyze(make_ctx())[2] == "degraded"
    assert factory.get_llm().name == "local"
    assert cloud.calls == 1


def test_forced_cloud_ignores_cooldown(monkeypatch):
    monkeypatch.setattr(
        factory,
        "config",
        SimpleNamespace(LLM_FORCE="opencode", LOCAL_HOST="http://localhost:11434"),
    )

    def fake_build(name, *, strict_replay=False):
        return _StubProvider(name)

    monkeypatch.setattr(factory, "_build", fake_build)

    factory.fail_provider(tier="opencode")
    # Explicit operator pin wins over the cooldown.
    assert factory.get_llm().name == "opencode"


def test_active_instance_is_cached_until_demoted(monkeypatch):
    cloud = _StubProvider("opencode")
    built: list[str] = []

    def fake_build(name, *, strict_replay=False):
        built.append(name)
        return cloud if name == "opencode" else _StubProvider(name)

    monkeypatch.setattr(factory, "_build", fake_build)

    a = factory.get_llm()
    b = factory.get_llm()
    assert a is b is cloud
    assert built == ["opencode"]

    agent = SOCAgent(a)
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == Action.GET_LOGS
    assert provider == "opencode"
    # Success → no demotion, cache stays warm.
    assert factory.get_llm() is cloud
    assert built == ["opencode"]


def test_resolve_llm_demo_path_unaffected_by_cache_and_cooldown(monkeypatch):
    built: list[str] = []

    def fake_build(name, *, strict_replay=False):
        built.append(name)
        return _StubProvider(name)

    monkeypatch.setattr(factory, "_build", fake_build)

    factory.fail_provider(tier="opencode")
    # Judge path is per-request: an active cloud cooldown never drops an explicit preference.
    prov = factory.resolve_llm("opencode")
    assert prov.name == "opencode"
    assert built == ["opencode"]