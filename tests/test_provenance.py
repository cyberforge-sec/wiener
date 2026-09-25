from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

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


# --- fingerprint coverage of experiment-defining inputs -------------------
#
# These tests hash real file content but never touch the working tree: the
# repo root is redirected at a temporary copy, so a crashed or failing test
# cannot leave a tracked config file modified. A repo whose whole point is
# provenance must not be able to corrupt its own inputs in a test run.


def _tmp_source_tree(tmp_path, monkeypatch):
    """A temporary ROOT holding real copies of the experiment inputs.

    Returns the tmp path; patch scripts.experiments.common.ROOT so that
    repo_manifest() (used by lock._source_files) reads from it.
    """
    import shutil

    from scripts.experiments import common

    root = tmp_path / "tree"
    (root / "config").mkdir(parents=True)
    for name in ("action_metadata.yaml", "red_ai_seeds.yaml", "safety_constraints.yaml"):
        shutil.copyfile(
            Path(__file__).resolve().parent.parent / "config" / name,
            root / "config" / name,
        )
    # One code file so the fingerprint is not input-only.
    (root / "app").mkdir()
    (root / "app" / "probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(common, "ROOT", root)
    return root


def test_fingerprint_is_stable_for_an_unchanged_tree(tmp_path, monkeypatch):
    _tmp_source_tree(tmp_path, monkeypatch)
    from scripts.experiments.lock import code_fingerprint

    first = code_fingerprint()
    second = code_fingerprint()
    assert first["root_hash"] == second["root_hash"]
    assert first["count"] == second["count"]


@pytest.mark.parametrize(
    "changed_file",
    [
        "config/red_ai_seeds.yaml",
        "config/action_metadata.yaml",
        "config/safety_constraints.yaml",
    ],
)
def test_changing_an_experiment_input_changes_the_root_hash(tmp_path, monkeypatch, changed_file):
    """Each declared input must move the fingerprint.

    red_ai_seeds decides which attacks run, action_metadata decides the UAR
    numerator, safety_constraints decides what hard-BLOCKs. If any of them can
    change without moving root_hash, then `provenance: MATCH` proves nothing
    about the experiment that produced the evidence.
    """
    root = _tmp_source_tree(tmp_path, monkeypatch)
    from scripts.experiments.lock import code_fingerprint

    before = code_fingerprint()["root_hash"]
    target = root / changed_file
    target.write_text(target.read_text(encoding="utf-8") + "\n# altered\n", encoding="utf-8")
    after = code_fingerprint()["root_hash"]
    assert before != after, f"{changed_file} is not covered by the fingerprint"


def test_missing_experiment_input_is_refused_not_silently_skipped(tmp_path, monkeypatch):
    """A fingerprint over a subset would still be self-consistent and could
    still report MATCH. An absent input must be an error, not a smaller list."""
    root = _tmp_source_tree(tmp_path, monkeypatch)
    from scripts.experiments.lock import code_fingerprint

    (root / "config" / "red_ai_seeds.yaml").unlink()
    with pytest.raises(FileNotFoundError) as ei:
        code_fingerprint()
    assert "red_ai_seeds.yaml" in str(ei.value)
    assert "cannot verify provenance" in str(ei.value)


def test_fingerprint_lists_inputs_explicitly_not_by_glob():
    """A wildcard would make a future presentation-only config file silently
    load-bearing for provenance, so the list must stay enumerated."""
    from scripts.experiments.lock import _EXPERIMENT_SOURCES, _source_files

    assert _EXPERIMENT_SOURCES == (
        "config/action_metadata.yaml",
        "config/red_ai_seeds.yaml",
        "config/safety_constraints.yaml",
    )
    for declared in _EXPERIMENT_SOURCES:
        assert declared in _source_files()
    # No wildcard and nothing outside the declared set.
    assert not any(ch in "".join(_EXPERIMENT_SOURCES) for ch in "*?[]")
    non_code = {
        f
        for f in _source_files()
        if not f.endswith(".py")
    }
    assert non_code == set(_EXPERIMENT_SOURCES)


def test_archived_evidence_is_stale_under_the_wider_fingerprint():
    """The stored fingerprint predates this coverage, so the archived bundle
    must read as STALE with the three inputs listed as added."""
    import json

    from scripts.experiments.lock import fingerprint_status

    stored = json.loads(
        (
            Path(__file__).resolve().parent.parent
            / "data"
            / "experiments"
            / "authoritative_20260925_zero_degraded"
            / "code_fingerprint.json"
        ).read_text(encoding="utf-8")
    )
    stored_files = set(stored["files"])
    assert not stored_files & set(
        (
            "config/action_metadata.yaml",
            "config/red_ai_seeds.yaml",
            "config/safety_constraints.yaml",
        )
    ), "precondition: the archived fingerprint must not already cover the inputs"

    result = fingerprint_status(stored)

    assert result["status"] == "STALE"
    added = set(result["added_files"])
    assert {
        "config/action_metadata.yaml",
        "config/red_ai_seeds.yaml",
        "config/safety_constraints.yaml",
    } <= added


def test_rewritten_model_id_fails_evidence_validation():
    """A gateway that answers with a different id than requested is rewriting
    ids, so the backing model is unverifiable. That must FAIL I-13b and
    therefore block the lock, not ship with a caveat."""
    from scripts.experiments.validation import run_validation

    rec = _record(
        model="oc/big-pickle",
        provider_meta={
            "temperature": 0.0,
            "model": "oc/big-pickle",
            "provider": "opencode",
            "adapter": "openai_compatible",
            "requested_model": "oc/big-pickle",
            "provider_reported_model": "big-pickle",
            "model_identity_reliable": False,
            "model_identity_note": "the gateway rewrites model ids",
        },
    )
    res = run_validation([rec], "e")
    assert res["validation_status"] == "FAIL"
    assert "I-13b" in res["failing_invariants"]
    assert any("unverifiable" in v for v in res["invariants"]["I-13b"]["violations"])


def test_confirmed_model_identity_passes():
    from scripts.experiments.validation import run_validation

    rec = _record(
        model="qwen2.5:1.5b",
        provider_meta={
            "temperature": 0.2,
            "model": "qwen2.5:1.5b",
            "provider": "ollama",
            "adapter": "ollama",
            "requested_model": "qwen2.5:1.5b",
            "provider_reported_model": "qwen2.5:1.5b",
            "model_identity_reliable": True,
        },
    )
    res = run_validation([rec], "e")
    assert "I-13b" not in res["failing_invariants"]
