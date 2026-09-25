from __future__ import annotations

import json
import tempfile

import httpx
import pytest

from app.llm.base import ProviderUnavailable
from app.llm.local_provider import LocalProvider
from app.llm.openai_compatible import OpenAICompatibleProvider
from app.llm.replay_provider import ReplayProvider
from app.models import AgentEvent, SOCContext, SOCOutput
from app.soc_agent.soc_agent import SOCAgent

from .fakes import FakeLLM, FailingLLM

_VALID = '{"action": "block_ip", "target": "10.0.0.5", "confidence": 0.9}'


def test_soc_agent_parses_llm_output():
    llm = FakeLLM(responses=[_VALID])
    agent = SOCAgent(llm)
    ctx = make_ctx(severity=8)
    out, raw, provider = agent.analyze(ctx)
    assert out.action == "block_ip"
    assert out.target == "10.0.0.5"
    assert out.confidence == 0.9
    assert provider == "fake"


def test_soc_agent_suspicious_alert_proposes_isolation():
    llm = FakeLLM(
        responses=['{"action": "isolate_endpoint", "target": "endpoint-e1", "confidence": 0.95}']
    )
    agent = SOCAgent(llm)
    ctx = make_ctx(severity=10, source="ids", event_type="intrusion")
    out, _, provider = agent.analyze(ctx)
    assert out.action == "isolate_endpoint"
    assert provider == "fake"


def test_soc_agent_accepts_padded_action_value():
    llm = FakeLLM(responses=['{"action": " get_logs ", "confidence": 0.8}'])
    agent = SOCAgent(llm)

    out, _, provider = agent.analyze(make_ctx())

    assert out.action == "get_logs"
    assert provider == "fake"


def test_soc_agent_cloud_provider_response():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(200, json={"choices": [{"message": {"content": _VALID}}]})
        return httpx.Response(404)

    provider = OpenAICompatibleProvider(
        api_key="key", base_url="https://example.invalid/v1", model="m",
        transport=httpx.MockTransport(handler),
    )
    agent = SOCAgent(provider)
    out, _, provider_name = agent.analyze(make_ctx())
    assert out.action == "block_ip"
    assert provider_name == "openai_compatible"


def test_soc_agent_local_provider_response():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/generate"):
            return httpx.Response(200, json={"response": _VALID})
        return httpx.Response(404)

    provider = LocalProvider(
        host="http://example.invalid", model="qwen",
        transport=httpx.MockTransport(handler),
    )
    agent = SOCAgent(provider)
    out, _, provider_name = agent.analyze(make_ctx())
    assert out.action == "block_ip"
    assert provider_name == "local"


def test_soc_agent_replay_response():
    with tempfile.TemporaryDirectory() as d:
        agent = SOCAgent(ReplayProvider(replay_dir=d))
        out, _, provider_name = agent.analyze(make_ctx())
        assert out.action == "check_endpoint"
        assert out.target == "host-a"
        assert provider_name == "replay"


def test_soc_agent_strict_replay_never_degrades():
    # Strict replay refuses to fabricate: refusal propagates loud, never a benign check_endpoint.
    with tempfile.TemporaryDirectory() as d:
        agent = SOCAgent(ReplayProvider(replay_dir=d, strict=True))
        with pytest.raises(ProviderUnavailable) as ei:
            agent.analyze(make_ctx())
        assert ei.value.kind == "replay_missing"


def test_soc_agent_rejects_invalid_action():
    llm = FakeLLM(responses=['{"action": "delete_all", "confidence": 1.0}'])
    agent = SOCAgent(llm)
    out, _, provider = agent.analyze(make_ctx())
    # Degraded safe path.
    assert out.action == "check_endpoint"
    assert provider == "degraded"


def test_soc_agent_missing_action_degrades():
    llm = FakeLLM(responses=['{"target": "10.0.0.5", "confidence": 0.9}'])
    agent = SOCAgent(llm)
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == "check_endpoint"
    assert provider == "degraded"


def test_soc_agent_missing_required_target_degrades():
    llm = FakeLLM(responses=['{"action": "block_ip", "confidence": 0.9}'])
    agent = SOCAgent(llm)
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == "check_endpoint"
    assert provider == "degraded"


def test_soc_agent_invalid_json_degrades():
    llm = FakeLLM(responses=["This is not JSON at all"])
    agent = SOCAgent(llm)
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == "check_endpoint"
    assert provider == "degraded"


def test_soc_agent_confidence_out_of_range_degrades():
    llm = FakeLLM(responses=['{"action": "block_ip", "target": "10.0.0.5", "confidence": 1.4}'])
    agent = SOCAgent(llm)
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == "check_endpoint"
    assert provider == "degraded"


def test_soc_agent_confidence_wrong_type_degrades():
    llm = FakeLLM(responses=['{"action": "block_ip", "target": "10.0.0.5", "confidence": "high"}'])
    agent = SOCAgent(llm)
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == "check_endpoint"
    assert provider == "degraded"


def test_soc_agent_unexpected_fields_are_rejected():
    llm = FakeLLM(
        responses=['{"action": "block_ip", "target": "10.0.0.5", "confidence": 0.9, "extra": 1}']
    )
    agent = SOCAgent(llm)
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == "check_endpoint"
    assert provider == "degraded"


def test_soc_agent_fails_safe_on_provider_timeout():
    agent = SOCAgent(FailingLLM(kind="timeout"))
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == "check_endpoint"
    assert provider == "degraded"


def test_soc_agent_fails_safe_on_provider_error():
    agent = SOCAgent(FailingLLM())
    out, _, provider = agent.analyze(make_ctx())
    assert out.action == "check_endpoint"
    assert provider == "degraded"


def make_ctx(
    severity: int = 5,
    source: str = "ids",
    event_type: str = "alert",
) -> SOCContext:
    return SOCContext(
        alert_id="x",
        events=[
            AgentEvent(
                event_id="e1",
                timestamp="2026-01-01T00:00:00Z",
                source=source,
                event_type=event_type,
                severity=severity,
            )
        ],
    )