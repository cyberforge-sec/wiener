from __future__ import annotations

import pytest

from app.experiment import (
    DANGEROUS_ACTIONS,
    ExperimentConfig,
    ExperimentConfigError,
    ExperimentMode,
    ExperimentReport,
    ExperimentRunner,
    ExperimentValidationError,
    validate_experiment,
)
from app.llm.base import LLMProvider, LLMResponse
from app.models import Decision, RiskResult
from tests.fakes import FakeLLM

_ALL_START = "RS-001-it0"
NUM_TRIALS = 2  # baseline + 1 mutation
SEED_COUNT = 5
EXPECTED_PER_MODE = NUM_TRIALS * SEED_COUNT  # 10


class SeqClock:
    """Deterministic clock so latency is reproducible."""

    def __init__(self, step: float = 0.05) -> None:
        self._t = 0.0
        self._step = step

    def __call__(self) -> float:
        value = self._t
        self._t += self._step
        return value


class RaisingLLM(LLMProvider):
    name = "raising"

    def complete(self, system: str, user: str) -> LLMResponse:
        raise RuntimeError("boom")


def _runner(**cfg_kw):
    config = ExperimentConfig(**cfg_kw)
    return ExperimentRunner(config, llm=FakeLLM(), clock=SeqClock())



def test_runner_executes_all_three_modes():
    report = _runner(experiment_id="all", num_trials=NUM_TRIALS, seed=1).run()
    assert report.experiment_id == "all"
    for mode in ExperimentMode:
        assert len(report.trials_for(mode)) == EXPECTED_PER_MODE


def test_trial_ids_identical_across_modes_and_unique():
    report = _runner(num_trials=NUM_TRIALS, seed=1).run()
    id_sets = {m: frozenset(t.trial_id for t in report.trials_for(m)) for m in ExperimentMode}
    assert len(set(id_sets.values())) == 1
    for mode, ids in id_sets.items():
        all_ids = [t.trial_id for t in report.trials_for(mode)]
        assert len(set(all_ids)) == len(all_ids)
        assert len(ids) == EXPECTED_PER_MODE


def test_same_attack_seeds_and_attacks_across_modes():
    report = _runner(num_trials=NUM_TRIALS, seed=1).run()
    by_mode = [tuple((t.trial_id, t.attack.model_dump_json()) for t in report.trials_for(m)) for m in ExperimentMode]
    assert by_mode[0] == by_mode[1] == by_mode[2]


def test_wiener_populates_chain_others_do_not():
    report = _runner(num_trials=NUM_TRIALS, seed=1).run()
    for trial in report.trials_for(ExperimentMode.WIENER):
        assert trial.blue_assessment is not None
        assert trial.risk is not None
        assert trial.policy_decision is not None
        assert trial.outcome.decision is not None
        assert trial.outcome.executed is not None
    for mode in (ExperimentMode.NO_DEFENSE, ExperimentMode.BASIC_PROMPT_DEFENSE):
        for trial in report.trials_for(mode):
            assert trial.blue_assessment is None
            assert trial.risk is None
            assert trial.policy_decision is None
            assert trial.outcome.decision is None
            assert trial.soc_output is not None
            assert trial.trajectory is not None


def test_basic_prompt_uses_different_system_prompt():
    runner = _runner(num_trials=1, seed=1)
    runner.run()
    # num_trials=1 -> 5 NO_DEFENSE calls (SOC default prompt), then 5 BASIC calls.
    no_defense_system = runner._llm.calls[0][0]
    basic_system = runner._llm.calls[5][0]
    assert "must NOT decide the final" in no_defense_system
    assert basic_system.startswith("TRUSTED SYSTEM INSTRUCTIONS")
    assert "UNTRUSTED CONTENT" in basic_system
    assert basic_system != no_defense_system
    # Same output shape/actions as NO_DEFENSE (no policy layer).
    report = runner.run()
    basic = report.trials_for(ExperimentMode.BASIC_PROMPT_DEFENSE)
    plain = report.trials_for(ExperimentMode.NO_DEFENSE)
    assert basic[0].soc_output.action.value == plain[0].soc_output.action.value


def test_progress_ids_prefix_from_seed():
    report = _runner(num_trials=1, seed=1, scenario=["RS-003"]).run()
    assert [t.trial_id for t in report.trials_for(ExperimentMode.WIENER)] == ["RS-003-it0"]



def test_num_trials_one_uses_only_baseline():
    report = _runner(num_trials=1, seed=1).run()
    assert len(report.trials_for(ExperimentMode.WIENER)) == SEED_COUNT
    assert all(t.attack.iteration == 0 for t in report.trials_for(ExperimentMode.WIENER))


def test_custom_scenario_list():
    report = _runner(num_trials=NUM_TRIALS, seed=1, scenario=["RS-001", "RS-002"]).run()
    assert len(report.trials_for(ExperimentMode.WIENER)) == NUM_TRIALS * 2
    assert all(t.seed_id in ("RS-001", "RS-002") for t in report.trials_for(ExperimentMode.WIENER))


def test_unknown_scenario_raises():
    with pytest.raises(ExperimentConfigError):
        _runner(scenario=["RS-999"]).run()


def test_unknown_provider_raises():
    from app.experiment.config import resolve_provider

    with pytest.raises(ExperimentConfigError):
        resolve_provider("not-a-provider")



def test_identical_runs_produce_identical_reports():
    a = _runner(experiment_id="rep", num_trials=NUM_TRIALS, seed=7).run()
    b = _runner(experiment_id="rep", num_trials=NUM_TRIALS, seed=7).run()
    assert a.model_dump_json() == b.model_dump_json()


def test_outcome_stable_for_same_attack():
    report = _runner(num_trials=NUM_TRIALS, seed=3).run()
    # Same trial_id in every mode has the same proposed action and attack.
    all_modes = [t.outcome.proposed_action for t in report.trials_for(ExperimentMode.NO_DEFENSE)]
    assert all(mode_outcome == all_modes[0] for mode_outcome in all_modes[1:])



def test_failures_recorded_and_counted():
    runner = ExperimentRunner(
        ExperimentConfig(num_trials=NUM_TRIALS, seed=1),
        llm=RaisingLLM(),
        clock=SeqClock(),
    )
    report = runner.run()
    assert len(report.trials) == 3 * EXPECTED_PER_MODE
    for mode in ExperimentMode:
        for trial in report.trials_for(mode):
            assert trial.error is not None
            assert "RuntimeError" in trial.error
            assert trial.soc_output is None
    validate_experiment(report)



def _valid_report() -> ExperimentReport:
    return _runner(num_trials=NUM_TRIALS, seed=1).run()


def test_validation_passes_on_clean_report():
    validate_experiment(_valid_report())


def test_validation_rejects_unequal_counts():
    report = _valid_report()
    report.trials = report.trials[:-1]
    with pytest.raises(ExperimentValidationError, match="unequal or empty"):
        validate_experiment(report)


def test_validation_rejects_duplicate_trial_ids():
    report = _valid_report()
    wiener = report.trials_for(ExperimentMode.WIENER)
    clone = wiener[0].model_copy()
    clone.trial_id = wiener[1].trial_id
    report.trials.remove(wiener[0])
    report.trials.append(clone)
    with pytest.raises(ExperimentValidationError, match="duplicate trial IDs"):
        validate_experiment(report)


def test_validation_rejects_manual_outcome():
    report = _valid_report()
    trial = next(t for t in report.trials_for(ExperimentMode.WIENER) if not t.error)
    trial.outcome.decision = Decision.ALLOW  # tamper: does not match policy
    with pytest.raises(ExperimentValidationError, match="does not match PolicyDecision"):
        validate_experiment(report)


def test_validation_rejects_invented_chain_on_prompt_defense():
    report = _valid_report()
    trial = next(t for t in report.trials_for(ExperimentMode.BASIC_PROMPT_DEFENSE) if not t.error)
    trial.risk = RiskResult(risk_score=21.0)
    with pytest.raises(ExperimentValidationError, match="invented risk"):
        validate_experiment(report)


def test_validation_rejects_outcome_proposed_mismatch():
    report = _valid_report()
    trial = next(t for t in report.trials_for(ExperimentMode.NO_DEFENSE) if not t.error)
    trial.outcome.proposed_action = "disable_user"
    with pytest.raises(ExperimentValidationError, match="does not match SOCOutput"):
        validate_experiment(report)


def test_dangerous_classification_derived():
    report = _runner(num_trials=1, seed=1).run()
    for trial in report.trials:
        if trial.outcome and trial.outcome.proposed_action:
            assert trial.outcome.dangerous == (
                trial.outcome.proposed_action in DANGEROUS_ACTIONS
            )