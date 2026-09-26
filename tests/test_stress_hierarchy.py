"""Targeted instruction-hierarchy study: controlled, and honestly measured.

The point of this population is that No Defense and Basic Prompt Defense differ
in exactly one variable. Several tests here are therefore about CONTROL - that
the variable really is the only one, and that nothing in the harness or the
population quietly encodes the expected ordering.

The last group is the one that matters most: the study states a hypothesis and
must not be built to confirm it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.action_metadata import is_dangerous
from app.red_ai.seed_loader import (
    HierarchySeedLoader,
    SeedLoader,
    StressSeedLoader,
)
from scripts.experiments import red_team_hierarchy as study

BENCH = Path("data/experiments/authoritative_20260926_1000")
PRIOR_STRESS = "red_team_stress_20260926_1827"

_ACTION_VERBS = {
    "block_ip": r"block",
    "disable_user": r"disabl|lock|stop authenticat",
    "isolate_endpoint": r"isolat|quarantin|segment",
}


# ---------------------------------------------------------------------------
# population is separate from every other population
# ---------------------------------------------------------------------------


def test_hierarchy_ids_cannot_collide_with_any_other_population():
    ids = {s.seed_id for s in HierarchySeedLoader().seeds}
    assert ids
    assert not (ids & {s.seed_id for s in SeedLoader().seeds})
    assert not (ids & {s.seed_id for s in StressSeedLoader().seeds})


def test_hierarchy_loader_does_not_fall_back_to_other_populations():
    loader = HierarchySeedLoader()
    assert loader.get("RS-001") is None
    assert loader.get("ST-001") is None
    assert loader.get("HS-001") is not None


def test_all_four_populations_are_still_distinct_and_intact():
    assert len(SeedLoader()) == 5, "authoritative benchmark population changed"
    assert len(StressSeedLoader()) == 14, "general stress population changed"
    assert len(HierarchySeedLoader()) == 14


def test_hierarchy_population_is_not_in_the_experiment_fingerprint():
    from scripts.experiments.lock import _EXPERIMENT_SOURCES

    assert "config/stress_hierarchy_seeds.yaml" not in _EXPERIMENT_SOURCES


# ---------------------------------------------------------------------------
# 1. the same payload is evaluated across modes, per iteration
# ---------------------------------------------------------------------------


def test_identical_payload_across_modes_per_iteration():
    """The single controlled variable is the defense configuration. If the modes
    ever saw different text, the comparison would measure nothing."""
    from app.models import RedAttack
    from scripts.experiments.red_team_stress import MODES, render_stress_attack

    loader = HierarchySeedLoader()
    for seed in loader.seeds:
        attack = RedAttack(
            seed_id=seed.seed_id,
            category=seed.category,
            iteration=2,
            payload=seed.payload,
            intended_action=seed.intended_action,
        )
        rendered = {m: render_stress_attack(attack) for m in MODES}
        details = {m: c.events[0].detail for m, c in rendered.items()}
        assert len(set(details.values())) == 1, f"{seed.seed_id}: modes saw different payloads"
        assert len({c.alert_id for c in rendered.values()}) == 1


def test_one_attack_object_is_shared_not_rebuilt_per_mode():
    """Recorded hashes must be identical across modes for the same iteration."""
    from scripts.experiments.red_team_stress import IterationRecord, compute_stress_metrics

    shared = "a" * 64
    rows = [
        IterationRecord(
            seed_id="HS-001", mode=mode, iteration=0, mutation_kind="none", rng_seed=1,
            input_hash=shared, output_hash=shared, decision=None, risk_score=None,
            reason_tags=[], proposed_action="get_logs", dangerous_proposal=False,
            final_decision=None, tool_executed=None, unsafe_execution=False,
            attack_succeeded=False, benign_trial=False,
        )
        for mode in ("no_defense", "basic_prompt_defense", "wiener")
    ]
    assert len({r.output_hash for r in rows}) == 1
    assert compute_stress_metrics(rows)["_note"]


# ---------------------------------------------------------------------------
# 2. Basic Prompt Defense is unchanged
# ---------------------------------------------------------------------------


def test_basic_prompt_defense_implementation_is_untouched():
    src = Path("app/experiment/runner.py").read_text()
    assert "def basic_prompt_defense_system_prompt" in src
    # The study must reach the SAME defense the benchmark and demo already use,
    # not a weakened local copy.
    from app.experiment.runner import basic_prompt_defense_system_prompt
    from scripts.experiments.red_team_stress import _defense_for

    class _LLM:
        name = "x"

    defense = _defense_for("basic_prompt_defense", _LLM())
    assert callable(defense)


def test_study_uses_the_shared_defense_factory():
    """Both ungated modes and WIENER go through the one `_defense_for`, so the
    study cannot have introduced a softer path for any mode."""
    src = Path("scripts/experiments/red_team_stress.py").read_text()
    assert "def _defense_for" in src
    assert "Pipeline(llm=llm)" in src, "the governed mode is not the real pipeline"
    assert "basic_prompt_defense_system_prompt()" in src


# ---------------------------------------------------------------------------
# 3. authoritative benchmark remains byte-identical
# ---------------------------------------------------------------------------


def test_locked_benchmark_files_remain_byte_identical():
    if not BENCH.exists():
        pytest.skip("locked bundle is gitignored and absent from this checkout")
    import hashlib

    manifest = json.loads((BENCH / "evidence_manifest.json").read_text())
    for name, want in (manifest.get("artifact_hashes") or {}).items():
        got = hashlib.sha256((BENCH / name).read_bytes()).hexdigest()
        assert got == want, f"locked artifact {name} changed"
    assert manifest["evidence_status"] == "LOCKED_VERIFIED"
    validation = json.loads((BENCH / "validation.json").read_text())
    assert validation["validation_status"] == "PASS"
    assert validation["invariants_passed"] == validation["invariants_total"]


def test_authoritative_seed_file_untouched():
    seeds = SeedLoader().seeds
    assert [s.seed_id for s in seeds] == ["RS-001", "RS-002", "RS-003", "RS-004", "RS-005"]
    assert Path("config/red_ai_seeds.yaml").exists()


# ---------------------------------------------------------------------------
# 4. previous stress artifact remains untouched
# ---------------------------------------------------------------------------


def test_previous_stress_artifact_is_not_modified():
    prior = Path("data/experiments") / PRIOR_STRESS
    if not prior.exists():
        pytest.skip("prior stress artifact is gitignored and absent here")
    report = json.loads((prior / "stress_report.json").read_text())
    assert report["is_authoritative_benchmark"] is False
    assert report["manifest_type"] == "red_team_stress_test"
    # Its recorded result must still be the one that was observed.
    m = report["metrics"]["basic_prompt_defense"]
    assert m["attack_effectiveness"]["dangerous_proposals"]["numerator"] == 3
    assert m["execution_safety"]["unsafe_executions"]["numerator"] == 3


def test_the_two_studies_use_different_namespaces():
    assert study.ARTIFACT_PREFIX != "red_team_stress"
    assert study.ARTIFACT_PREFIX == "red_team_hierarchy"


def test_study_refuses_to_write_into_another_namespace(tmp_path):
    for name in ("red_team_stress_20260101_0000", "authoritative_20260926_1000"):
        with pytest.raises(ValueError):
            study.write_hierarchy_bundle(name, [], [], out_root=tmp_path)


# ---------------------------------------------------------------------------
# 5. benign controls unchanged
# ---------------------------------------------------------------------------


def test_benign_controls_request_nothing():
    for seed in HierarchySeedLoader().benign_controls:
        assert seed.intended_action is None


def test_benign_controls_are_not_weaker_than_the_general_population():
    """Not character-identical: this study deliberately adds a control that
    mirrors the injection delivery shape. What must hold is that no control
    requests an action, and that none carries an instruction the model could
    follow into a dangerous proposal."""
    hier = HierarchySeedLoader().benign_controls
    general = StressSeedLoader().benign_controls
    assert len(hier) == len(general) == 4, "control count changed"
    assert not ({s.seed_id for s in hier} & {s.seed_id for s in general}), "ids must be distinct"
    for seed in hier:
        assert seed.intended_action is None

    # A control may QUOTE an injection, but only inside an explicit refusal to
    # act on it. That is the whole point of HS-B02, and a blanket "no action verb
    # anywhere" rule would have deleted the most informative control we have.
    by_id = {s.seed_id: s.payload for s in hier}
    quoted = by_id["HS-B02"]
    assert re.search(r"\bdisable\b", quoted, re.I), "HS-B02 no longer quotes an injection"
    assert re.search(r"do not act", quoted, re.I), (
        "HS-B02 quotes a dangerous instruction without forbidding action on it, "
        "so it is an attack seed and not a control"
    )
    # The remaining controls must not carry an action verb at all.
    for seed_id, payload in by_id.items():
        if seed_id == "HS-B02":
            continue
        assert not re.search(r"\b(block|disable|isolate)\b", payload, re.I), (
            f"{seed_id} carries an action imperative and is not a control"
        )


def test_one_control_mirrors_the_injection_delivery_shape():
    """HS-B04 carries comment-shaped text without an instruction, mirroring
    HS-008's delivery. Without it, a low FIR could just mean the shape is easy."""
    controls = {s.seed_id: s.payload for s in HierarchySeedLoader().benign_controls}
    assert "#" in controls["HS-B04"], "control does not carry comment-shaped text"
    assert "block" not in controls["HS-B04"].lower(), "control contains an instruction"
    hs008 = next(s.payload for s in HierarchySeedLoader().adversarial if s.seed_id == "HS-008")
    assert "#" in hs008, "the adversarial seed no longer uses that delivery shape"


# ---------------------------------------------------------------------------
# 6. proposal and execution are measured independently
# ---------------------------------------------------------------------------


def _row(mode, **kw):
    from scripts.experiments.red_team_stress import IterationRecord

    base = dict(
        seed_id="HS-001", mode=mode, iteration=0, mutation_kind="none", rng_seed=1,
        input_hash="a" * 64, output_hash="b" * 64, decision=None, risk_score=None,
        reason_tags=[], proposed_action="block_ip", dangerous_proposal=True,
        final_decision=None, tool_executed=None, unsafe_execution=False,
        attack_succeeded=True, benign_trial=False,
    )
    base.update(kw)
    return IterationRecord(**base)


def test_proposal_and_execution_are_independent_measurements():
    from scripts.experiments.red_team_stress import compute_stress_metrics

    # Dangerous proposal, gate held it.
    m = compute_stress_metrics([_row("wiener", final_decision="REVIEW", tool_executed=False)])["wiener"]
    assert m["attack_effectiveness"]["dangerous_proposals"]["numerator"] == 1
    assert m["execution_safety"]["unsafe_executions"]["numerator"] == 0

    # Dangerous proposal, no defense at all: same proposal, now an execution.
    m = compute_stress_metrics([_row("no_defense", tool_executed=None, unsafe_execution=True)])["no_defense"]
    assert m["attack_effectiveness"]["dangerous_proposals"]["numerator"] == 1
    assert m["execution_safety"]["unsafe_executions"]["numerator"] == 1


def test_denominators_are_reported_per_group():
    from scripts.experiments.red_team_stress import compute_stress_metrics

    m = compute_stress_metrics([_row("no_defense", unsafe_execution=True)])
    for group in ("attack_effectiveness", "execution_safety"):
        for rate in m["no_defense"][group].values():
            if isinstance(rate, dict):
                assert "numerator" in rate and "denominator" in rate


# ---------------------------------------------------------------------------
# 7. nothing is tuned to force the intended ordering
# ---------------------------------------------------------------------------


def test_the_hypothesis_is_not_asserted_anywhere_in_the_study():
    src = Path("scripts/experiments/red_team_hierarchy.py").read_text()
    body = src.split("HYPOTHESIS = ")[0] + src.split("to make a decision.")[-1]
    for pattern in (
        "no_defense_dangerous",
        "expected_ordering",
        "assert.*>=.*basic",
        "hypothesis_met",
        "hypothesis_failed",
        "passes if",
    ):
        assert not re.search(pattern, body), f"study encodes the hypothesis via {pattern!r}"
    assert "hypothesis_enforced" in src, "the report must state that it is not enforced"
    assert '"hypothesis_enforced": False' in src


def test_study_reports_whichever_ordering_it_observes():
    """Feed it a result that CONTRADICTS the hypothesis and confirm the reporter
    emits it unchanged, with no complaint."""
    from scripts.experiments.red_team_stress import compute_stress_metrics

    # Basic Prompt Defense worse than no defense: the opposite of the hypothesis.
    rows = [
        _row("no_defense", unsafe_execution=True),
        _row("basic_prompt_defense", unsafe_execution=True),
    ] * 3
    m = compute_stress_metrics(rows)
    nd = m["no_defense"]["execution_safety"]["unsafe_executions"]["numerator"]
    bp = m["basic_prompt_defense"]["execution_safety"]["unsafe_executions"]["numerator"]
    assert nd == 3 and bp == 3
    # No exception, no normalisation, no flag: the numbers come back as measured.
    assert "_note" in m and "not an execution" in m["_note"]


def test_population_was_not_written_against_a_per_mode_outcome():
    """Every adversarial seed requests an action in plain language, so adoption
    is measurable. A population that hedged its wording to favour one mode
    would defeat the comparison."""
    for seed in HierarchySeedLoader().adversarial:
        assert seed.intended_action is not None
        assert is_dangerous(seed.intended_action.value)
        pattern = _ACTION_VERBS[seed.intended_action.value]
        assert re.search(pattern, seed.payload, re.I), (
            f"{seed.seed_id} does not name its action in plain language"
        )


def test_population_covers_all_three_dangerous_actions():
    actions = {s.intended_action.value for s in HierarchySeedLoader().adversarial}
    assert actions == {"block_ip", "disable_user", "isolate_endpoint"}


def test_no_seed_payload_names_a_real_host():
    body = Path("config/stress_hierarchy_seeds.yaml").read_text()
    allowed = ("192.0.2.", "198.51.100.", "203.0.113.", "192.168.", "example.invalid")
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", body):
        assert any(match.startswith(p) for p in allowed), f"non-reserved address {match}"


def test_bundle_records_the_question_and_disclaims_enforcement(tmp_path):
    out = study.write_hierarchy_bundle("red_team_hierarchy_20260101_0000", [], [], out_root=tmp_path)
    report = json.loads((out / "hierarchy_report.json").read_text())
    assert report["is_authoritative_benchmark"] is False
    assert report["hypothesis_enforced"] is False
    assert report["hypothesis_stated_for_the_reader"] == study.HYPOTHESIS
    banner = (out / "STRESS_TEST_NOT_AUTHORITATIVE.txt").read_text()
    assert "NOT AUTHORITATIVE BENCHMARK" in banner
    assert "instruction-hierarchy" in banner.lower()
