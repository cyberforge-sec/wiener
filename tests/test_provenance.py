from __future__ import annotations

from copy import deepcopy

from scripts.experiments.lock import code_fingerprint, fingerprint_status, write_evidence_manifest
from scripts.experiments.preflight import response_contains_json


def test_fingerprint_status_matches_current_tree():
    current = code_fingerprint()
    result = fingerprint_status(current)

    assert result["status"] == "MATCH"
    assert result["mismatched_files"] == []
    assert result["added_files"] == []
    assert result["removed_files"] == []
    assert result["note"] == "Fingerprint matches the current source tree."
    assert result["current_root_hash"] == current["root_hash"]


def test_fingerprint_status_reports_changed_source():
    stored = deepcopy(code_fingerprint())
    stored["file_hashes"]["app/main.py"] = "0" * 64

    result = fingerprint_status(stored)

    assert result["status"] == "STALE"
    assert "app/main.py" in result["mismatched_files"]
    assert "predate" in result["note"]


def test_write_evidence_manifest_records_source_provenance(tmp_path):
    manifest = write_evidence_manifest(tmp_path)

    assert manifest["source_provenance"]["status"] == "STALE"
    assert manifest["source_provenance"]["recorded_root_hash"] is None


def test_preflight_accepts_json_wrapped_in_prose():
    assert response_contains_json('Result: {"action": "check_endpoint", "confidence": 0.5}')
    assert not response_contains_json("plain prose only")


def _trial_row(trial_id: str, mode: str, **over):
    """Minimal provenance-complete trial row for the lock gate tests."""
    row = {
        "trial_id": trial_id,
        "experiment_id": "gate_test",
        "mode": mode,
        "scenario_type": "malicious",
        "seed_id": "RS-001",
        "category": "prompt_injection",
        "iteration": 0,
        "attack_payload": "payload",
        "provider_requested": "opencode",
        "provider_used": "opencode",
        "model": "gpt-4o-mini",
        "fallback_used": False,
        "system_prompt_id": "soc_agent._SYSTEM_PROMPT",
        "system_prompt_hash": "0" * 64,
        "raw_completion": '{"action": "block_ip"}',
        "action": "block_ip",
        "duration_ms": 120.0,
        "timestamp_start": "2026-09-25T00:00:00+00:00",
        "timestamp_end": "2026-09-25T00:00:01+00:00",
        "retry_count": 0,
        "provider_meta": {"model": "gpt-4o-mini", "temperature": 0.0},
    }
    row.update(over)
    return row


def test_degraded_trials_block_the_lock(tmp_path):
    """A degraded (synthetic fallback) trial is a fabricated model result: it
    must never be lockable as authoritative evidence."""
    import json

    from scripts.experiments.lock import MANIFEST_NAME

    rows = [
        _trial_row(
            f"t{i}",
            mode,
            benign_trial=(i % 45 == 0),
            **(
                {
                    "fallback_used": True,
                    "fallback_reason": "soc_agent degraded path",
                    "provider_used": "degraded",
                    "raw_completion": None,
                    "provider_meta": {"tier": "degraded"},
                }
                if (i == 7 and mode == "wiener")
                else {}
            ),
        )
        for i in range(45)
        for mode in ("no_defense", "basic_prompt_defense", "wiener")
    ]
    (tmp_path / "trials.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows), encoding="utf-8"
    )
    (tmp_path / "code_fingerprint.json").write_text(
        json.dumps({"root_hash": "a" * 64, "count": 1, "file_hashes": {}}), encoding="utf-8"
    )

    manifest = write_evidence_manifest(tmp_path)

    assert manifest["gates"]["no_degraded_trials"] is False
    assert manifest["gates"]["provenance_clean"] is False
    assert manifest["evidence_status"] == "CANDIDATE"
    assert (tmp_path / MANIFEST_NAME).exists()
