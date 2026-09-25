from __future__ import annotations

import json
import tempfile

import httpx
import pytest

from app.llm.base import LLMResponse, ProviderUnavailable
from app.llm.local_provider import LocalProvider
from app.llm.opencode_provider import OpenCodeProvider
from app.llm.replay_provider import ReplayProvider

# The same logical request for all providers.
SYSTEM = "system: concise"
USER = "user: request-1"

_GOOD_RESPONSE_TEXT = '{"action": "block_ip", "confidence": 0.8}'



def _cloud_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"content": _GOOD_RESPONSE_TEXT}}],
                },
            )
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def _local_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/generate"):
            return httpx.Response(200, json={"response": _GOOD_RESPONSE_TEXT})
        return httpx.Response(404)
    return httpx.MockTransport(handler)



def test_cloud_provider_contract():
    provider = OpenCodeProvider(
        api_key="key", base_url="https://example.invalid/v1", model="m",
        transport=_cloud_transport(),
    )
    resp = provider.complete(SYSTEM, USER)
    assert isinstance(resp, LLMResponse)
    assert resp.text == _GOOD_RESPONSE_TEXT
    assert resp.provider == "opencode"
    assert resp.meta["model"] == "m"
    assert resp.meta["temperature"] == 0.0
    assert resp.meta["deterministic_requested"] is True


def test_cloud_provider_reports_requested_temperature():
    provider = OpenCodeProvider(
        api_key="key", base_url="https://example.invalid/v1", model="m",
        temperature=0.7, transport=_cloud_transport(),
    )
    resp = provider.complete(SYSTEM, USER)
    assert resp.meta["temperature"] == 0.7
    assert resp.meta["deterministic_requested"] is False


def test_cloud_provider_handles_trailing_stream_done_sentinel():
    body = json.dumps({"choices": [{"message": {"content": _GOOD_RESPONSE_TEXT}}]})
    content = (body + "\n\ndata: [DONE]\n").encode("utf-8")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=content)

    provider = OpenCodeProvider(
        api_key="key", base_url="https://example.invalid/v1", model="m",
        transport=httpx.MockTransport(handler),
    )
    resp = provider.complete(SYSTEM, USER)
    assert resp.text == _GOOD_RESPONSE_TEXT


def test_cloud_provider_null_content_is_controlled():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": None}}]},
        )

    provider = OpenCodeProvider(
        api_key="key", base_url="https://example.invalid/v1", model="m",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderUnavailable) as ei:
        provider.complete(SYSTEM, USER)
    assert ei.value.kind == "malformed"


def test_cloud_provider_retries_empty_content_then_succeeds():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        content = None if calls == 1 else _GOOD_RESPONSE_TEXT
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    provider = OpenCodeProvider(
        api_key="key", base_url="https://example.invalid/v1", model="m",
        response_format="json_object", transport=httpx.MockTransport(handler),
    )

    resp = provider.complete(SYSTEM, USER)

    assert calls == 2
    assert resp.meta["retry_count"] == 1


def test_cloud_provider_retries_non_json_when_format_requested():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        content = "Result: not a JSON object" if calls == 1 else _GOOD_RESPONSE_TEXT
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    provider = OpenCodeProvider(
        api_key="key", base_url="https://example.invalid/v1", model="m",
        response_format="json_object", transport=httpx.MockTransport(handler),
    )

    resp = provider.complete(SYSTEM, USER)

    assert calls == 2
    assert resp.meta["retry_count"] == 1


def test_cloud_provider_sends_response_format_and_retries_when_rejected():
    request_bodies: list[dict] = []
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        body = json.loads(request.content.decode())
        request_bodies.append(body)
        calls += 1
        if body.get("response_format"):
            return httpx.Response(400, json={"error": {"type": "invalid_request_error"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": _GOOD_RESPONSE_TEXT}}]})

    provider = OpenCodeProvider(
        api_key="key", base_url="https://example.invalid/v1", model="m",
        response_format="json_object",
        transport=httpx.MockTransport(handler),
    )
    resp = provider.complete(SYSTEM, USER)
    assert calls == 2
    assert request_bodies[0]["response_format"] == {"type": "json_object"}
    assert "response_format" not in request_bodies[1]
    assert resp.text == _GOOD_RESPONSE_TEXT


def test_cloud_provider_omits_response_format_when_disabled():
    request_bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        request_bodies.append(body)
        return httpx.Response(200, json={"choices": [{"message": {"content": _GOOD_RESPONSE_TEXT}}]})

    provider = OpenCodeProvider(
        api_key="key", base_url="https://example.invalid/v1", model="m",
        response_format="",
        transport=httpx.MockTransport(handler),
    )
    provider.complete(SYSTEM, USER)
    assert "response_format" not in request_bodies[0]


def test_cloud_provider_diag_writes_on_failure():
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        diag = Path(d) / "raw.log"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"choices": [{"message": {"content": None}}]})

        provider = OpenCodeProvider(
            api_key="key", base_url="https://example.invalid/v1", model="m",
            transport=httpx.MockTransport(handler),
            diag_path=str(diag),
        )
        with pytest.raises(ProviderUnavailable) as ei:
            provider.complete(SYSTEM, USER)
        assert ei.value.kind == "malformed"
        assert diag.exists()
        content = diag.read_text()
        assert "null-content" in content


def test_local_provider_contract():
    provider = LocalProvider(
        host="http://example.invalid", model="qwen", max_tokens=64,
        transport=_local_transport(),
    )
    resp = provider.complete(SYSTEM, USER)
    assert isinstance(resp, LLMResponse)
    assert resp.text == _GOOD_RESPONSE_TEXT
    assert resp.provider == "local"
    assert resp.meta["max_tokens"] == 64


def test_local_provider_reports_requested_temperature():
    provider = LocalProvider(
        host="http://example.invalid", model="qwen", temperature=0.2,
        transport=_local_transport(),
    )
    resp = provider.complete(SYSTEM, USER)
    assert resp.meta["model"] == "qwen"
    assert resp.meta["temperature"] == 0.2
    assert resp.meta["deterministic_requested"] is False


def test_replay_provider_contract():
    with tempfile.TemporaryDirectory() as d:
        provider = ReplayProvider(replay_dir=d)
        resp = provider.complete(SYSTEM, USER)
        assert isinstance(resp, LLMResponse)
        assert resp.provider == "replay"
        assert json.loads(resp.text)["action"] == "check_endpoint"
        assert resp.meta["deterministic"] is True



def test_cloud_provider_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")
    provider = OpenCodeProvider(
        api_key="key", base_url="https://x/v1", model="m",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderUnavailable) as ei:
        provider.complete(SYSTEM, USER)
    assert ei.value.kind == "timeout"


def test_local_provider_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")
    provider = LocalProvider(
        host="http://x", model="qwen",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderUnavailable) as ei:
        provider.complete(SYSTEM, USER)
    assert ei.value.kind == "timeout"


def test_cloud_provider_connection_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")
    provider = OpenCodeProvider(
        api_key="key", base_url="https://x/v1", model="m",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProviderUnavailable) as ei:
        provider.complete(SYSTEM, USER)
    assert ei.value.kind == "connection"


def test_cloud_provider_auth_failure():
    provider = OpenCodeProvider(
        api_key="key", base_url="https://x/v1", model="m",
        transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"error": "unauthorized"})),
    )
    with pytest.raises(ProviderUnavailable) as ei:
        provider.complete(SYSTEM, USER)
    assert ei.value.kind == "auth"


def test_cloud_provider_missing_api_key_is_controlled():
    provider = OpenCodeProvider(api_key="", base_url="https://x/v1", model="m")
    with pytest.raises(ProviderUnavailable) as ei:
        provider.complete(SYSTEM, USER)
    assert ei.value.kind == "auth"


def test_cloud_provider_malformed_response():
    provider = OpenCodeProvider(
        api_key="key", base_url="https://x/v1", model="m",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"unexpected": True})),
    )
    with pytest.raises(ProviderUnavailable) as ei:
        provider.complete(SYSTEM, USER)
    assert ei.value.kind == "malformed"


def test_local_provider_malformed_response():
    provider = LocalProvider(
        host="http://x", model="qwen",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"not-json")),
    )
    with pytest.raises(ProviderUnavailable) as ei:
        provider.complete(SYSTEM, USER)
    assert ei.value.kind == "malformed"


def test_replay_provider_works_offline_without_live_model():
    with tempfile.TemporaryDirectory() as d:
        provider = ReplayProvider(replay_dir=d)
        resp = provider.complete(SYSTEM, USER)
        assert resp.provider == "replay"
        assert resp.text

def _local_chat_transport(recorder: list[dict]):
    """Ollama with /api/chat support. Records every request it receives."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        recorder.append({"path": request.url.path, "body": body})
        if request.url.path.endswith("/api/chat"):
            return httpx.Response(200, json={"message": {"content": _GOOD_RESPONSE_TEXT}})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_local_provider_uses_real_role_separation_when_available():
    """System and user must stay separate messages: concatenating them lets
    untrusted alert text share the instruction's position."""
    seen: list[dict] = []
    provider = LocalProvider(
        host="http://example.invalid", model="qwen",
        transport=_local_chat_transport(seen),
    )

    resp = provider.complete(SYSTEM, USER)

    chat_calls = [c for c in seen if c["path"].endswith("/api/chat") and "messages" in c["body"]]
    assert chat_calls, "expected an /api/chat call with messages"
    roles = [m["role"] for m in chat_calls[0]["body"]["messages"]]
    assert roles == ["system", "user"]
    assert chat_calls[0]["body"]["messages"][0]["content"] == SYSTEM
    assert chat_calls[0]["body"]["messages"][1]["content"] == USER
    assert resp.text == _GOOD_RESPONSE_TEXT
    assert resp.meta["role_separation"] is True
    assert resp.meta["endpoint"] == "api/chat"


def test_local_provider_falls_back_to_flattened_prompt_and_says_so():
    """An older server without /api/chat still works, but the response must
    record that role separation was NOT available."""
    provider = LocalProvider(
        host="http://example.invalid", model="qwen",
        transport=_local_transport(),
    )

    resp = provider.complete(SYSTEM, USER)

    assert resp.text == _GOOD_RESPONSE_TEXT
    assert resp.meta["endpoint"] == "api/generate"
    assert resp.meta["role_separation"] is False
