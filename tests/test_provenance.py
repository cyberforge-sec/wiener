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
