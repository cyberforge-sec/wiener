"""Dashboard presentation: reporting shape, not frozen benchmark numbers.

These assert that the page sources every figure from the resolved evidence
bundle and reports it in the agreed shape. Where a test needs a value it reads
it from the bundle, so a newer locked run does not invalidate the test and a
hardcoded constant can never creep into the renderer unnoticed.
"""

from __future__ import annotations

import re

from app.dashboard.dashboard import DashboardData
from app.present.evidence import (
    authoritative_dir,
    build_evidence_dashboard,
    load_evidence,
)
from app.present.render import presentation_page


def _page() -> tuple[str, object]:
    bundle = load_evidence()
    assert bundle is not None, "expected a resolved evidence bundle"
    return presentation_page(build_evidence_dashboard(bundle)), bundle


# --- 1/2/3. integrity tally and UAR figures come from the bundle ---------


def test_integrity_reports_the_bundles_own_validation_tally():
    page, b = _page()
    assert f'data-validation-pass="{b.validation_pass}"' in page
    assert f'data-validation-total="{b.validation_invariants}"' in page
    assert f"{b.validation_pass} / {b.validation_invariants}" in page
    # A historical bundle validated against a shorter checklist must not leak
    # its tally into the current one.
    assert "16 / 16" not in page or b.validation_invariants == 16


def test_uar_cards_report_each_mode_from_the_bundle():
    page, b = _page()
    cards = re.findall(r'data-uar-mode="([^"]+)"', page)
    assert cards == list(b.modes), "one card per mode, in bundle order"
    for mode in b.modes:
        metric = b.by_mode[mode]
        assert f'data-unsafe-count="{metric.unsafe_actions}"' in page
        assert f'data-unsafe-denominator="{metric.attempts}"' in page
    # The visible fraction is the stored numerator over the stored denominator.
    for mode in b.modes:
        metric = b.by_mode[mode]
        if metric.attempts:
            assert f">{metric.unsafe_actions} / {metric.attempts}</code> unsafe executions" in page


# --- 4. the UAR section must not rank -----------------------------------


def test_uar_section_has_no_ranking_visual():
    page, _ = _page()
    assert "Unsafe Action Rate (UAR) Comparison" not in page
    assert "Comparative Defense Modes" not in page
    assert "Rate of Unsafe Tool Executions" not in page
    assert "Larger bar" not in page
    # No value-derived bar sizing survives anywhere in the markup.
    assert "comparison-track" not in page
    assert not re.search(r'style="width:\s*\d', page)


def test_uar_cards_are_equal_weight():
    """No card may be styled as bigger or bolder because of its value."""
    page, _ = _page()
    assert page.count('class="surface-card uar-card"') == 3
    assert "uar-card--active" not in page
    assert "metric-row--active" not in page


# --- 5. execution summary ------------------------------------------------


def test_execution_summary_matches_the_bundle():
    page, b = _page()
    assert f'data-evidence-proposals="{b.proposals}"' in page
    assert f'data-evidence-blocked="{b.blocked}"' in page
    assert f'data-evidence-reviewed="{b.reviewed}"' in page
    assert f'data-evidence-executed="{b.executed}"' in page
    assert f"{b.n_trials} TOTAL TRIALS" in page
    assert (
        f"{b.trials_per_mode} / MODE · {b.malicious_total} ADVERSARIAL · {b.benign_total} BENIGN"
    ) in page


# --- 6. benign controls use the mode's own denominator -------------------


def test_benign_controls_use_the_defended_modes_denominator():
    page, b = _page()
    wiener = b.by_mode["wiener"]
    if wiener.fir_den:
        assert (
            f'data-benign-interventions="{wiener.incorrect_interventions}" '
            f'data-benign-denominator="{wiener.fir_den}"'
        ) in page
        assert f"{wiener.incorrect_interventions} / {wiener.fir_den} interventions" in page
        # Never the run-wide benign total presented as this mode's controls.
        assert f'data-benign-denominator="{b.benign_total}"' not in page


def test_benign_control_label_is_unambiguous():
    page, _ = _page()
    assert "Benign Sample" not in page, "'0 / 10 trials' reads as a sample, not controls"
    assert "WIENER benign controls" in page
    assert "interventions" in page


# --- 7. evidence status, stored verdict vs current-tree currency --------


def test_header_states_the_stored_lock_verdict():
    page, b = _page()
    if b.evidence_status == "LOCKED_VERIFIED":
        assert f"LOCKED VERIFIED · {b.validation_pass} / {b.validation_invariants} PASS" in page
    else:
        assert "CANDIDATE EVIDENCE" in page


def test_current_tree_comparison_is_reported_separately():
    """The header may not double as the provenance verdict: whether the
    artifacts still describe the current tree is a different claim."""
    page, b = _page()
    assert "STATUS: " in page
    status = b.source_provenance["status"].lower()
    if status == "match":
        assert "STATUS: VERIFIED SOUND" in page
    else:
        assert "PRODUCED BY AN EARLIER REVISION" in page or "NOT COMPARABLE" in page


def test_historical_wording_is_not_used_for_the_current_bundle():
    page, b = _page()
    if b.evidence_status == "LOCKED_VERIFIED":
        assert "ARTIFACTS INTACT · EARLIER REVISION" not in page.split("STATUS")[0]


# --- 8. no hardcoded benchmark values in the renderer --------------------


def test_renderer_source_contains_no_benchmark_constants():
    """The renderer must not contain a literal result. Read the module source
    so a value cannot hide in a rarely-exercised branch."""
    import inspect

    from app.present import render

    source = inspect.getsource(render)
    body = source.split("_CSS = r'''")[0]
    for literal in ("11.11", "18 / 18", "5 / 45", "0 / 45", "0 / 10", "1.0", "135"):
        assert literal not in body, f"renderer contains a benchmark constant: {literal}"


# --- 9. one evidence source for every surface ---------------------------


def test_every_surface_comes_from_the_same_bundle():
    data = build_evidence_dashboard(load_evidence())
    page = presentation_page(data)
    b = data.evidence
    assert b is not None
    # Summary, ledger and focused trial all name the same experiment.
    assert f"data/experiments/{b.source_dir}/" in page
    assert data.experiment_id == b.experiment_id
    assert f'data-total-trials="{b.n_trials}"' in page
    # The ledger is built from this bundle's trials only. Trial ids repeat
    # across modes by design (the same 45 scenarios run in all three), so the
    # identity of a row is (trial_id, mode) and the count must match that.
    pairs = {(t.trial_id, t.mode) for t in data.trials}
    assert len(pairs) == b.n_trials == len(data.trials)
    for trial in data.trials:
        assert f'data-id="{trial.trial_id}"' in page


def test_focused_trial_is_drawn_from_the_ledger():
    data = build_evidence_dashboard(load_evidence())
    page = presentation_page(data)
    inspected = re.search(r'id="inspected-trial-id" data-trial-id="([^"]+)"', page)
    assert inspected, "a trial must be inspected by default"
    assert inspected.group(1) in {t.trial_id for t in data.trials}


def test_selected_trial_overrides_the_default_view():
    data = build_evidence_dashboard(load_evidence())
    target = data.trials[-1]
    page = presentation_page(data, target.trial_id)
    assert f'data-trial-id="{target.trial_id}"' in page
    assert f'id="inspected-gate"' in page


# --- 10. model identity comes from the bundle, not the configuration ----


def test_model_identity_is_read_from_the_recorded_rows():
    page, b = _page()
    identity = b.model_identity
    assert identity and identity["agreed"], "the bundle's rows must agree on a model"
    assert identity["rows"] == b.n_trials
    assert f'data-requested-model="{identity["requested_model"]}"' in page
    assert f'data-identity-verification="{identity["identity_verification"]}"' in page
    assert f'data-model-pinned="{identity["model_identity_pinned"]}"' in page


def test_transport_name_is_not_the_headline_identity():
    page, b = _page()
    identity = b.model_identity or {}
    if identity.get("agreed"):
        label = re.search(r'data-inference-label="([^"]*)"', page)
        assert label, "an inference label is rendered"
        adapter = identity.get("adapter")
        if adapter and adapter in label.group(1):
            pytest_fail(
                f"the wire protocol {adapter!r} is being shown as the model identity"
            )


def pytest_fail(message: str) -> None:
    raise AssertionError(message)


# --- 11. pipeline follows the selected trial ----------------------------


def test_pipeline_renders_the_real_decision_for_a_wiener_trial():
    data = build_evidence_dashboard(load_evidence())
    blocked = next(
        t for t in data.trials if t.mode == "wiener" and t.final_decision == "BLOCK"
    )
    page = presentation_page(data, blocked.trial_id)
    assert 'data-pipeline-stage="POLICY GATE"' in page
    assert blocked.final_decision in page
    assert "NOT EXECUTED" in page or "EXECUTED" in page


def test_ungated_modes_are_labelled_as_such():
    data = build_evidence_dashboard(load_evidence())
    ungated = next(t for t in data.trials if t.mode == "no_defense")
    page = presentation_page(data, ungated.trial_id)
    assert "UNGATED" in page
    assert "NOT SIMULATED" in page


# --- 12. structure preserved --------------------------------------------


def test_all_sections_present_in_the_agreed_order():
    page, _ = _page()
    order = [
        'id="primary-result"',
        'id="uar"',
        'id="operational-safety"',
        'id="integrity"',
        'id="active-trial"',
        'id="audit"',
    ]
    positions = [page.index(token) for token in order]
    assert positions == sorted(positions), "sections must render in the agreed order"


def test_ledger_filters_present():
    page, b = _page()
    assert 'id="trial-search"' in page
    assert f'placeholder="Search Trial ID or Proposal' in page
    assert f'All Modes ({b.n_trials})' in page
    assert "All Decisions" in page


# --- 13. the tree-currency wording must not imply invalid evidence --------


def test_tree_row_names_the_axis_and_the_delta():
    page, b = _page()
    assert "CURRENT TREE" in page
    assert "SOURCE TREE" not in page, "the row is about the current tree, not the artifacts"
    delta = (b.source_provenance or {}).get("mismatched_files") or ()
    if delta:
        assert f'data-tree-delta-changed="{len(delta)}"' in page
        assert "DIFFERS FROM THE LOCKED REVISION" in page
    # The changed files are named, so a reader can judge the change themselves.
    for name in delta:
        assert name in page


def test_stale_tree_does_not_read_as_invalid_evidence():
    page, b = _page()
    if b.source_provenance["status"].lower() == "stale":
        status_line = re.search(r"<span class=\"verified\">([^<]*)</span>", page)
        assert status_line, "the provenance panel states its verdict"
        line = status_line.group(1)
        assert "ARTIFACTS INTACT" in line
        # A bare "STALE" would read as "these results are invalid".
        assert "RESULTS UNCHANGED" in line
        assert "PRODUCED BY AN EARLIER REVISION" in line


def test_delta_count_is_derived_not_written():
    """No hardcoded file count: a different tree must render a different number."""
    import inspect

    from app.present import render

    source = inspect.getsource(render._current_tree_label)
    for literal in ("2 changed", "1 changed", "presentation"):
        assert literal not in source
