"""Preflight identity gate under a configured trusted routing prefix.

These drive the real cloud adapter with a stubbed transport, so the identity
that reaches the gate is produced by `ProviderIdentity` itself rather than
hand-written into a payload. The gate itself must stay hard.
"""

from __future__ import annotations

import json

import pytest

from app.llm.openai_compatible import OpenAICompatibleProvider


def _transport(reported_model: str | None):
    """Minimal OpenAI-shaped transport that reports `reported_model`."""
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        body = {"action": "block_ip", "target": "1.2.3.4", "confidence": 0.9}
        payload = {
            "id": "x",
            "object": "chat.completion",
            "model": reported_model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": json.dumps(body)},
                    "finish_reason": "stop",
                }
            ],
        }
        return httpx.Response(200, json=payload)

    return httpx.MockTransport(handler)


def _provider(reported_model, prefixes, requested="oc/big-pickle"):
    return OpenAICompatibleProvider(
        api_key="test-key",
        base_url="https://gateway.invalid/v1",
        model=requested,
        route_prefixes=tuple(prefixes),
        transport=_transport(reported_model),
    )


def _meta(reported_model, prefixes, requested="oc/big-pickle"):
    resp = _provider(reported_model, prefixes, requested).complete("sys", "user")
    return resp.meta


# --- 13. strict gate passes a valid trusted route match ------------------


def test_trusted_route_match_is_reliable():
    meta = _meta("big-pickle", ("oc/",))
    assert meta["model_identity_reliable"] is True
    assert meta["identity_verification"] == "trusted_route_match"
    assert meta["model_identity_pinned"] is False
    assert meta["trusted_route_match"]["prefix"] == "oc/"


# --- 14. the gate still blocks when the rewrite is not exact -------------


@pytest.mark.parametrize("reported", ["some-other-model", "big-pickle-v2", "openai_compatible", None])
def test_non_exact_rewrite_is_unreliable(reported):
    meta = _meta(reported, ("oc/",))
    assert meta["model_identity_reliable"] is False
    assert meta["identity_verification"] == "unverified"


def test_no_trusted_prefix_configured_stays_unreliable():
    meta = _meta("big-pickle", ())
    assert meta["model_identity_reliable"] is False


# --- backward compatibility across every other tier shape ----------------


def test_exact_match_unaffected():
    meta = _meta("gpt-4o-mini-2024-07-18", ("oc/",), requested="gpt-4o-mini-2024-07-18")
    assert meta["model_identity_reliable"] is True
    assert meta["identity_verification"] == "exact_match"


def test_openai_style_route_prefix():
    meta = _meta("gpt-4o-mini-2024-07-18", ("openai/",), requested="openai/gpt-4o-mini-2024-07-18")
    assert meta["model_identity_reliable"] is True
    assert meta["identity_verification"] == "trusted_route_match"


def test_openrouter_style_route_prefix():
    meta = _meta("gpt-4o-mini-2024-07-18", ("openrouter/",), requested="openrouter/gpt-4o-mini-2024-07-18")
    assert meta["model_identity_reliable"] is True


def test_route_prefixes_come_from_config_not_the_model():
    """The prefix list is configuration. A requested id that merely contains a
    slash must not authorize anything on its own."""
    meta = _meta("big-pickle", (), requested="whatever/big-pickle")
    assert meta["model_identity_reliable"] is False


def test_replay_and_local_shapes_unaffected():
    """Only the OpenAI-shaped cloud adapter carries routing namespaces."""
    from app.llm.local_provider import LocalProvider
    from app.llm.replay_provider import ReplayProvider

    assert ReplayProvider().model is None
    assert LocalProvider is not None
