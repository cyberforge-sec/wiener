"""Evidence selection: current defensibility outranks a historical status string.

These tests build synthetic evidence trees so both orderings are pinned:

  1. an OLDER artifact whose stored manifest says LOCKED_VERIFIED but whose
     provenance no longer matches the serving tree, versus
     a NEWER CANDIDATE whose provenance matches and whose invariant coverage is
     higher -> the candidate must be selected, because it is the more
     defensible evidence.

  2. a CURRENTLY locked artifact must outrank a candidate -> the rule is not
     "candidate always wins".

They also pin that selection never promotes status: whichever directory is
chosen, the status shown is the one stored in that artifact.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _fingerprint(root_hash: str, files: dict[str, str]) -> dict:
    return {
        "method": "test",
        "count": len(files),
        "files": sorted(files),
        "file_hashes": files,
        "root_hash": root_hash,
    }


def _write_evidence(
    root: Path,
    name: str,
    *,
    stored_status: str,
    fingerprint: dict,
    validation_status: str,
    passed: int,
    total: int,
    no_degraded: bool | None = True,
    locked_at: str = "2026-01-01T00:00:00+00:00",
) -> Path:
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "code_fingerprint.json").write_text(json.dumps(fingerprint), encoding="utf-8")
    (d / "trials.jsonl").write_text("", encoding="utf-8")
    (d / "metrics.json").write_text("{}", encoding="utf-8")
    (d / "validation.json").write_text(
        json.dumps({"validation_status": validation_status}), encoding="utf-8"
    )
    manifest = {
        "manifest_type": "evidence_manifest",
        "run_id": name,
        "evidence_status": stored_status,
        "locked_at": locked_at,
        "validation_summary": {
            "status": validation_status,
            "invariants_total": total,
            "invariants_passed": passed,
        },
        "gates": {"no_degraded_trials": no_degraded},
    }
    (d / "evidence_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return d


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A fake experiments root plus a fake CURRENT fingerprint."""
    import scripts.experiments.lock as lock

    root = tmp_path / "experiments"
    root.mkdir()
    current_files = {"app/a.py": "current"}
    monkeypatch.setattr(
        lock, "code_fingerprint", lambda: _fingerprint("CURRENT", current_files)
    )
    return root


def test_stale_locked_loses_to_current_candidate(tree):
    from scripts.experiments.lock import best_available_evidence_dir, locked_evidence_dir

    matching = _fingerprint("CURRENT", {"app/a.py": "current"})
    stale = _fingerprint("OLD", {"app/a.py": "old", "app/gone.py": "removed"})

    # Older artifact: says LOCKED_VERIFIED, but its tree no longer matches.
    _write_evidence(
        tree, "authoritative_20260101_0100",
        stored_status="LOCKED_VERIFIED", fingerprint=stale,
        validation_status="PASS", passed=16, total=16,
        locked_at="2026-01-01T01:00:00+00:00",
    )
    # Newer artifact: CANDIDATE, but provenance matches and coverage is higher.
    _write_evidence(
        tree, "authoritative_20260202_0200",
        stored_status="CANDIDATE", fingerprint=matching,
        validation_status="FAIL", passed=17, total=18,
        locked_at="2026-02-02T02:00:00+00:00",
    )

    best = best_available_evidence_dir(tree)
    assert best is not None and best.name == "authoritative_20260202_0200", (
        "a stale LOCKED_VERIFIED must not outrank a provenance-matching CANDIDATE"
    )

    # And nothing is "currently locked", because the stored lock no longer holds.
    assert locked_evidence_dir(tree) is None


def test_currently_locked_outranks_a_candidate(tree):
    from scripts.experiments.lock import best_available_evidence_dir, locked_evidence_dir

    matching = _fingerprint("CURRENT", {"app/a.py": "current"})

    # Candidate with higher raw invariant count, same provenance.
    _write_evidence(
        tree, "authoritative_20260303_0300",
        stored_status="CANDIDATE", fingerprint=matching,
        validation_status="FAIL", passed=17, total=18,
        locked_at="2026-03-03T03:00:00+00:00",
    )
    # Currently locked: stored lock, provenance matches, validation passes.
    _write_evidence(
        tree, "authoritative_20260101_0100",
        stored_status="LOCKED_VERIFIED", fingerprint=matching,
        validation_status="PASS", passed=18, total=18,
        locked_at="2026-01-01T01:00:00+00:00",
    )

    best = best_available_evidence_dir(tree)
    assert best is not None and best.name == "authoritative_20260101_0100", (
        "a currently locked artifact must outrank a candidate; the rule is not "
        "'candidate always wins'"
    )
    locked = locked_evidence_dir(tree)
    assert locked is not None and locked.name == "authoritative_20260101_0100"


def test_no_degraded_gate_breaks_a_tie(tree):
    """With provenance, lock state and validation equal, integrity decides."""
    from scripts.experiments.lock import best_available_evidence_dir

    matching = _fingerprint("CURRENT", {"app/a.py": "current"})
    _write_evidence(
        tree, "authoritative_20260101_0100",
        stored_status="CANDIDATE", fingerprint=matching,
        validation_status="FAIL", passed=17, total=18, no_degraded=False,
        locked_at="2026-01-01T01:00:00+00:00",
    )
    _write_evidence(
        tree, "authoritative_20260102_0100",
        stored_status="CANDIDATE", fingerprint=matching,
        validation_status="FAIL", passed=17, total=18, no_degraded=True,
        locked_at="2026-01-02T01:00:00+00:00",
    )
    best = best_available_evidence_dir(tree)
    assert best is not None and best.name == "authoritative_20260102_0100"


def test_unreadable_directory_is_not_evidence(tree):
    """A directory with no manifest cannot be selected, whatever its name."""
    from scripts.experiments.lock import best_available_evidence_dir

    matching = _fingerprint("CURRENT", {"app/a.py": "current"})
    _write_evidence(
        tree, "authoritative_20260101_0100",
        stored_status="CANDIDATE", fingerprint=matching,
        validation_status="PASS", passed=18, total=18,
    )
    (tree / "enforcement_ablation_20260101_0100").mkdir()
    (tree / "authoritative_broken").mkdir()
    (tree / "authoritative_broken" / "evidence_manifest.json").write_text("{not json", encoding="utf-8")

    best = best_available_evidence_dir(tree)
    assert best is not None and best.name == "authoritative_20260101_0100"


def test_selection_never_promotes_status(tree):
    """Choosing a CANDIDATE must not relabel it. The stored status is what the
    bundle reports, and the presentation layer reads that, unchanged."""
    from scripts.experiments.lock import assess_evidence_dir

    matching = _fingerprint("CURRENT", {"app/a.py": "current"})
    d = _write_evidence(
        tree, "authoritative_20260202_0200",
        stored_status="CANDIDATE", fingerprint=matching,
        validation_status="FAIL", passed=17, total=18,
    )
    a = assess_evidence_dir(d)
    assert a is not None
    assert a["stored_evidence_status"] == "CANDIDATE"
    assert a["currently_locked"] is False
