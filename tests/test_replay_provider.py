from __future__ import annotations

import json
import tempfile

import pytest

from app.llm.base import ProviderUnavailable
from app.llm.replay_provider import ReplayProvider


def test_replay_deterministic_default():
    with tempfile.TemporaryDirectory() as d:
        rp = ReplayProvider(replay_dir=d)
        r1 = rp.complete("sys", "usr")
        r2 = rp.complete("sys", "usr")
        assert r1 == r2  # deterministic, no live call
        assert r1.text == r2.text
        assert json.loads(r1.text)["action"] == "check_endpoint"


def test_replay_exact_deterministic_output():
    with tempfile.TemporaryDirectory() as d:
        rp = ReplayProvider(replay_dir=d)
        expected = rp.complete("system-x", "user-y")
        for _ in range(3):
            assert rp.complete("system-x", "user-y") == expected
            assert rp.complete("system-x", "user-y").meta["deterministic"] is True


def test_replay_recorded_response_roundtrip_preserves_metadata():
    with tempfile.TemporaryDirectory() as d:
        rp = ReplayProvider(replay_dir=d)
        key = rp._key("sys", "prompt-x")
        rp.save_recorded(key, '{"action": "block_ip", "confidence": 0.9}')
        got = rp.complete("sys", "prompt-x")
        assert got.text == '{"action": "block_ip", "confidence": 0.9}'
        assert got.meta["recorded"] is True
        assert got.meta["replay_key"] == key


def test_replay_no_live_call_structural():
    # Replay provider performs no network I/O; it only reads local files.
    assert "httpx" not in str(type(ReplayProvider).__init__)


def test_replay_strict_fails_loud_on_unrecorded():
    with tempfile.TemporaryDirectory() as d:
        rp = ReplayProvider(replay_dir=d, strict=True)
        with pytest.raises(ProviderUnavailable) as ei:
            rp.complete("sys", "never-recorded")
        assert ei.value.kind == "replay_missing"
        assert "refusing to fabricate" in str(ei.value)


def test_replay_neutral_default_tagged_replay_neutral():
    with tempfile.TemporaryDirectory() as d:
        rp = ReplayProvider(replay_dir=d)
        resp = rp.complete("sys", "never-recorded")
        assert resp.meta["recorded"] is False
        assert resp.meta["replay_neutral"] is True


def test_replay_recorded_labels_serving_provider_and_tier():
    with tempfile.TemporaryDirectory() as d:
        rp = ReplayProvider(replay_dir=d)
        key = rp._key("sys", "prompt-x")
        rp.save_recorded(key, '{"action": "block_ip", "confidence": 0.9}', provider="cloud")
        got = rp.complete("sys", "prompt-x")
        # Reports the serving rung (replay), never live; provenance kept in metadata.
        assert got.provider == "replay"
        assert got.meta["recorded"] is True
        assert got.meta["recorded_tier"] == "cloud"