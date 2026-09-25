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


def _record(**over):
    from scripts.experiments.common import TrialRecord

    base = dict(
        trial_id="RS-001-it0", experiment_id="e",
        timestamp_start="2026-01-01T00:00:00+00:00",
        timestamp_end="2026-01-01T00:00:01+00:00", duration_ms=120.0,
        mode="no_defense", scenario_type="malicious", seed_id="RS-001",
        category="prompt_injection", iteration=0, mutation_type=None,
        attack_payload="p", benign_payload_or_context=None,
        provider_requested="opencode", provider_used="opencode",
        model="gpt-4o-mini", provider_tier=None, fallback_used=False,
        fallback_reason=None, system_prompt_id="s", system_prompt_hash="0" * 64,
        user_input="u", SOC_context={}, agent_history=[],
        raw_completion='{"action": "block_ip"}', parsed_output=None,
        action="block_ip", target="1.2.3.4", confidence=0.9,
        blue_assessment=None, blue_route=None, risk_score=None,
        triggered_constraints=[], required_decision=None, final_decision=None,
        tool_name=None, tool_executed=None, tool_result=None,
        tool_refusal_reason=None, unsafe_action_taken=False,
        attack_succeeded=False, benign_trial=False, error=None, retry_count=0,
        request_start_ms=None, request_end_ms=None,
        provider_meta={"temperature": 0.0, "model": "gpt-4o-mini"},
    )
    base.update(over)
    return TrialRecord(**base)


def _one(rec):
    from scripts.experiments.validation import run_validation

    return run_validation([rec], "e")


def test_transport_name_in_model_field_fails_validation():
    """`model: "opencode"` is the adapter name, not evidence of which model
    answered. 90 of 135 rows in the archived run had exactly this defect."""
    res = _one(_record(model="opencode"))
    assert res["validation_status"] == "FAIL"
    assert "I-13b" in res["failing_invariants"]


def test_unrecorded_temperature_fails_validation():
    """Unknown decoding settings are not a pass. A local run at 0.2 is fine
    when recorded; a run that never recorded it is not verifiable."""
    res = _one(_record(provider_meta={"model": "gpt-4o-mini"}))
    assert res["validation_status"] == "FAIL"
    assert "I-09" in res["failing_invariants"]


def test_nonzero_recorded_temperature_is_acceptable():
    res = _one(_record(provider_meta={"temperature": 0.2, "model": "qwen2.5:1.5b"}))
    assert "I-09" not in res["failing_invariants"]


def test_absolute_clock_leak_into_latency_delta_is_caught():
    """generated_at_ms pinned to 0.0 turned a 0.05 ms trial into a 1.7e6 ms
    'latency'. The window must stay inside the trial's own duration."""
    rec = _record(request_start_ms=4_940_025.0, request_end_ms=4_941_666.0, duration_ms=1641.0)
    ok = _one(rec)
    assert "I-06b" not in ok["failing_invariants"]

    rec_bad = _record(request_start_ms=1.0, request_end_ms=4_940_025.0, duration_ms=1641.0)
    bad = _one(rec_bad)
    assert "I-06b" in bad["failing_invariants"]


def test_missing_duration_is_a_failure_not_a_pass():
    res = _one(_record(duration_ms=None))
    assert res["validation_status"] == "FAIL"
    assert "I-06" in res["failing_invariants"]


def test_lock_gate_reads_invariant_count_from_validation_json():
    """Adding an invariant must not leave an older checklist looking locked."""
    import inspect

    from scripts.experiments import lock

    source = inspect.getsource(lock.write_evidence_manifest)
    assert "invariants_total" in source
    assert "pass_count == 16" not in source
    assert "len(inv_list) == 16" not in source
