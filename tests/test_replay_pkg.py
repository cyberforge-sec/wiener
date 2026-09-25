"""Deterministic replay package tests.

Exercises the shipped recorded store (app/replay/recorded) with no temp
override, so these also verify the packaging worked.
"""

from __future__ import annotations

from app.replay import run_replay
from app.replay.runner import logical_digest, run_scenario
from app.replay.scenarios import SCENARIO_IDS


def test_all_scenarios_pass():
    for sid in SCENARIO_IDS:
        art = run_scenario(sid)
        assert art.replay_mode is True, f"{sid} must be labeled REPLAY MODE"
        assert art.passed, f"{sid} produced the wrong decision"


def test_repeated_runs_are_logically_identical():
    for sid in SCENARIO_IDS:
        first = logical_digest(run_scenario(sid))
        for _ in range(3):
            assert logical_digest(run_scenario(sid)) == first, f"{sid} not deterministic"


def test_expected_decisions_pinned():
    expected = {
        "REPLAY-001": "ALLOW",  # benign → read-only get_logs
        "REPLAY-002": "BLOCK",  # privilege-abuse injection → disable_user → SC-003
        "REPLAY-003": "BLOCK",  # adaptive loop, final feedback BLOCK
        "REPLAY-004": "ALLOW",  # cloud down → local Qwen → read-only action
    }
    for sid, want in expected.items():
        art = run_scenario(sid)
        assert art.final_decision == want, f"{sid}: {art.final_decision} != {want}"


def test_recorded_tiers_pinned():
    # soc_provider reports the serving rung (replay); recorded tier kept as provenance.
    assert run_scenario("REPLAY-001").soc_provider == "replay"
    assert run_scenario("REPLAY-001").recorded_tier == "cloud"
    assert run_scenario("REPLAY-002").soc_provider == "replay"
    assert run_scenario("REPLAY-002").recorded_tier == "cloud"
    assert run_scenario("REPLAY-004").soc_provider == "replay"
    assert run_scenario("REPLAY-004").recorded_tier == "local"


def test_cli_runs_single_scenario(tmp_path):
    code = run_replay(["--scenario", "REPLAY-002", "--out", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "REPLAY-002.json").exists()


def test_cli_validate_all(tmp_path):
    code = run_replay(["--scenario", "ALL", "--validate", "--runs", "3", "--out", str(tmp_path)])
    assert code == 0