"""UI presentation of the inference tier the Judge page shows.

Scope is deliberately narrow: labels, the option list, and run attribution.
Nothing here asserts a security decision, and nothing here may pin a vendor,
because the page must describe whatever the deployment is configured for.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.judge import inference_labels as il
from app.judge.judge_mode import JudgeRun
from app.judge.render import _source_label, provider_label, render_page


# --- option list: one entry per tier, never a duplicate -------------------


def test_tier_options_exactly_one_per_tier():
    options = il.tier_options()
    assert [o["tier"] for o in options] == [il.CLOUD, il.LOCAL, il.REPLAY]
    assert len(options) == 3


def test_tier_option_labels_are_unique():
    """Regression: `openai_compatible` and its `opencode` alias both rendered
    "Cloud (configurable adapter)", so the list showed two identical Cloud rows."""
    labels = [o["label"] for o in il.tier_options()]
    assert len(set(labels)) == len(labels)


def test_backend_alias_resolves_to_the_same_option():
    """The legacy `opencode` key is the same tier, so it must not add a row and
    must not resolve to a different label than the option it aliases."""
    options = il.tier_options()
    assert len([o for o in options if o["value"] == "openai_compatible"]) == 1
    assert provider_label("opencode") == provider_label("openai_compatible")
    assert provider_label("opencode") in {o["label"] for o in options}


def test_selected_label_comes_from_the_option_list():
    """The closed selection is looked up in the same list it renders, so the two
    cannot disagree."""
    for option in il.tier_options():
        assert provider_label(option["value"]) == option["label"]


def test_unknown_provider_key_is_not_echoed():
    assert provider_label("not-a-real-tier") is None


def test_rendered_page_has_no_duplicate_cloud_option():
    page = render_page()
    assert "Cloud (configurable adapter)" not in page
    assert "Local (Ollama)" not in page
    assert page.count('<option value="openai_compatible">') == 1
    assert page.count('<option value="opencode">') == 0


# --- labels follow configuration, nothing is hardcoded -------------------


def test_cloud_label_reflects_configured_provider_and_model(cfg):
    cfg(CLOUD_PROVIDER_LABEL="some-gateway")
    cfg(CLOUD_MODEL="some-model-v2")
    assert il.tier_option_label(il.CLOUD) == "Cloud · some-gateway / some-model-v2"


def test_local_label_reflects_configured_model(cfg):
    cfg(LOCAL_MODEL="some-local-model")
    label = il.tier_option_label(il.LOCAL)
    assert label.startswith("Local · ")
    assert "some-local-model" in label


def test_replay_label_is_deterministic_and_names_no_live_provider():
    label = il.tier_option_label(il.REPLAY)
    assert label == "Replay · Deterministic"
    assert "/" not in label


def test_adapter_name_is_not_used_as_the_primary_identity(cfg):
    """`openai_compatible` names a wire protocol, not who answered."""
    cfg(CLOUD_PROVIDER_LABEL="openai_compatible")
    cfg(CLOUD_MODEL="m")
    assert "openai_compatible" not in il.tier_option_label(il.CLOUD)


# --- missing metadata degrades honestly -----------------------------------


def test_missing_cloud_provider_falls_back_without_inventing_one(cfg):
    cfg(CLOUD_PROVIDER_LABEL="openai_compatible")
    cfg(CLOUD_MODEL="m")
    assert il.tier_option_label(il.CLOUD) == "Cloud · m"


def test_missing_model_falls_back_to_a_honest_placeholder(cfg):
    cfg(CLOUD_PROVIDER_LABEL="some-gateway")
    cfg(CLOUD_MODEL="")
    assert il.tier_option_label(il.CLOUD) == "Cloud · some-gateway"


def test_format_handles_none_everywhere():
    assert il.format_inference_label(il.CLOUD, None, None) == "Cloud · Configured model"
    assert il.format_inference_label(il.LOCAL, None, None) == "Local · Configured model"
    assert il.format_inference_label(il.REPLAY, None, None) == "Replay · Deterministic"


# --- a restored run is attributed to the run, not to current config -------


@pytest.fixture
def cfg(monkeypatch):
    """Swap the frozen config for a stub the label module can read.

    Accumulates across calls, so a test can adjust one setting at a time.
    """
    current = {
        "CLOUD_PROVIDER_LABEL": "openai_compatible",
        "CLOUD_MODEL": "m",
        "LOCAL_MODEL": "qwen2.5:1.5b",
        "LOCAL_HOST": "http://localhost:11434",
    }

    def _set(**kw):
        current.update(kw)
        monkeypatch.setattr(il, "config", SimpleNamespace(**current))
        return current

    return _set


def _run(**kw):
    base = dict(
        run_id=1,
        requested_provider="openai_compatible",
        provider_used="openai_compatible",
        replay_mode=False,
        scenario="adaptive",
    )
    base.update(kw)
    return JudgeRun(**base)


def test_restored_run_keeps_its_own_identity_after_config_changes(cfg):
    """A result on screen must keep naming the model that produced it."""
    recorded = _run(inference={"tier": "cloud", "provider": "provider-a", "model": "model-a"})
    cfg(CLOUD_PROVIDER_LABEL="provider-b")
    cfg(CLOUD_MODEL="model-b")
    assert _source_label(recorded) == "Cloud · provider-a / model-a"
    assert provider_label("openai_compatible") == "Cloud · provider-b / model-b"


def test_run_without_recorded_identity_does_not_crash():
    run = _run(provider_used="local", requested_provider="local", inference=None)
    assert _source_label(run).startswith("Local · ")


def test_failed_run_says_no_provider_served_it():
    run = _run(provider_used="", error="ProviderUnavailable: auth")
    assert _source_label(run) == "No provider served this run"


def test_describe_llm_is_safe_for_none():
    assert il.describe_llm(None) == {"tier": None, "provider": None, "model": None}


# --- the verdict is untouched by any of this ------------------------------


@pytest.mark.parametrize(
    "decision,expected",
    [
        ("BLOCK", "BLOCKED SAFE FROM EXECUTION"),
        ("REVIEW", "REVIEW NOT EXECUTED"),
        ("ALLOW", "ALLOWED SIMULATED EXECUTION"),
    ],
)
def test_decision_labels_unchanged(decision, expected):
    from app.judge.render import _decision_label

    assert _decision_label(decision) == expected


def test_run_meta_exposes_identity_for_the_client():
    run = _run(inference={"tier": "cloud", "provider": "p", "model": "m"})
    from app.judge.render import run_to_meta

    meta = run_to_meta(run)
    assert meta["inference"] == {"tier": "cloud", "provider": "p", "model": "m"}
    assert meta["inference_label"] == "Cloud · p / m"
    # Backend metadata is retained, not deleted, for debug surfaces.
    assert meta["provider_used"] == "openai_compatible"
    assert meta["requested_provider"] == "openai_compatible"
