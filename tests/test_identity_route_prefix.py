"""Model identity verification, including trusted routing prefixes.

The boundary these tests defend: naming a routing namespace makes a prefix
rewrite VERIFIABLE. It never makes the model PINNED, and it never authorizes a
rewrite that the namespace does not exactly explain.
"""

from __future__ import annotations

import pytest

from app.config import parse_route_prefixes
from app.llm.identity import (
    DECLARED_PINNED_MATCH,
    EXACT_MATCH,
    TRUSTED_ROUTE_MATCH,
    UNVERIFIED,
    ProviderIdentity,
    is_pinned_model_id,
    match_trusted_route_prefix,
)


def ident(requested, reported, prefixes=(), declared=None) -> ProviderIdentity:
    return ProviderIdentity(
        provider="gateway",
        adapter="openai_compatible",
        requested_model=requested,
        provider_reported_model=reported,
        declared_model=declared,
        trusted_route_prefixes=tuple(prefixes),
    )


# --- 1. exact match is untouched -----------------------------------------


def test_exact_match_still_passes():
    i = ident("gpt-4o-mini", "gpt-4o-mini")
    assert i.model_identity_reliable is True
    assert i.identity_verification == EXACT_MATCH


# --- 2/3. trusted route match --------------------------------------------


def test_trusted_route_match_for_alias():
    i = ident("oc/big-pickle", "big-pickle", ("oc/",))
    assert i.model_identity_reliable is True
    assert i.identity_verification == TRUSTED_ROUTE_MATCH
    assert i.model_identity_pinned is False, "a trusted route match is not pinning"


def test_trusted_route_match_for_pinned_model():
    i = ident("oc/gpt-4o-mini-2024-07-18", "gpt-4o-mini-2024-07-18", ("oc/",))
    assert i.model_identity_reliable is True
    assert i.identity_verification == TRUSTED_ROUTE_MATCH
    assert i.model_identity_pinned is True


# --- 4. the same rewrite without a configured prefix stays unverified ----


def test_route_match_without_trusted_prefix_is_unverified():
    i = ident("oc/big-pickle", "big-pickle", ())
    assert i.model_identity_reliable is False
    assert i.identity_verification == UNVERIFIED


# --- 5/6. wrong reported value, wrong namespace --------------------------


def test_wrong_reported_model_fails_even_with_trusted_prefix():
    i = ident("oc/big-pickle", "some-other-model", ("oc/",))
    assert i.model_identity_reliable is False
    assert i.identity_verification == UNVERIFIED


def test_wrong_namespace_fails():
    i = ident("wrong/big-pickle", "big-pickle", ("oc/",))
    assert i.model_identity_reliable is False
    assert i.identity_verification == UNVERIFIED


@pytest.mark.parametrize(
    "reported",
    ["big-pickle-v2", "big-pickl", "BIG-PICKLE", "big-pickle/extra", ""],
)
def test_near_miss_reported_values_all_fail(reported):
    """A routing convention is exact. Anything merely similar is a coincidence."""
    i = ident("oc/big-pickle", reported, ("oc/",))
    assert i.model_identity_reliable is False


# --- 7. transport name is never a model ----------------------------------


def test_transport_name_reported_fails():
    i = ident("oc/big-pickle", "openai_compatible", ("oc/",))
    assert i.model_identity_reliable is False
    assert i.identity_verification == UNVERIFIED


# --- 8. a declaration cannot rescue a floating alias --------------------


def test_declared_floating_alias_is_still_unverified():
    i = ident("oc/big-pickle", "big-pickle", (), declared="big-pickle")
    assert i.model_identity_reliable is False
    assert i.identity_verification == UNVERIFIED


def test_declared_pinned_id_still_works():
    i = ident("oc/x", "gpt-4o-mini-2024-07-18", (), declared="gpt-4o-mini-2024-07-18")
    assert i.model_identity_reliable is True
    assert i.identity_verification == DECLARED_PINNED_MATCH


# --- 9. multiple prefixes: only an exact one authorizes ------------------


def test_multiple_prefixes_pick_the_one_that_matches_exactly():
    i = ident("kgw/some-model-2024", "some-model-2024", ("oc/", "kgw/", "gh/"))
    assert i.model_identity_reliable is True
    assert i.trusted_route_prefix == "kgw/"


def test_multiple_prefixes_none_matching_still_fails():
    i = ident("zzz/big-pickle", "big-pickle", ("oc/", "kgw/", "gh/"))
    assert i.model_identity_reliable is False


# --- 10. invalid prefixes are ignored ------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("oc/", ("oc/",)),
        (" oc/ , kgw/ ", ("oc/", "kgw/")),
        ("oc", ()),  # no trailing slash
        ("/", ()),  # bare slash would authorize everything
        ("", ()),
        ("oc/,", ("oc/",)),  # empty entry dropped
        ("OC/", ("OC/",)),  # case preserved, not folded
        ("oc/,oc/", ("oc/",)),  # de-duplicated
    ],
)
def test_parse_route_prefixes(raw, expected):
    assert parse_route_prefixes(raw) == expected


def test_case_sensitive_prefix_does_not_match_wrong_case():
    """Model ids are case-sensitive; folding case would let OC/x match oc/x."""
    i = ident("OC/big-pickle", "big-pickle", ("oc/",))
    assert i.model_identity_reliable is False


def test_invalid_prefix_entries_are_ignored_at_match_time():
    assert match_trusted_route_prefix("oc/big-pickle", "big-pickle", ("oc", "/", "")) is None


# --- pinned semantics preserved, never merged with verification -----------


def test_is_pinned_model_id_semantics_unchanged():
    assert is_pinned_model_id("gpt-4o-mini-2024-07-18") is True
    assert is_pinned_model_id("claude-sonnet-4-6") is True
    assert is_pinned_model_id("qwen-v2") is True
    assert is_pinned_model_id("some-model@a1b2c3d") is True
    assert is_pinned_model_id("gpt-4o-mini") is False
    assert is_pinned_model_id("big-pickle") is False


def test_verified_does_not_imply_pinned():
    """The two facts are independent and must be readable independently."""
    i = ident("oc/big-pickle", "big-pickle", ("oc/",))
    assert i.model_identity_reliable is True
    assert i.model_identity_pinned is False


# --- 11/12. evidence metadata -------------------------------------------


def test_meta_reports_the_route_match_without_claiming_pinning():
    meta = ident("oc/big-pickle", "big-pickle", ("oc/",)).as_meta()
    assert meta["identity_verification"] == TRUSTED_ROUTE_MATCH
    assert meta["model_identity_pinned"] is False
    assert meta["trusted_route_match"] == {
        "requested": "oc/big-pickle",
        "prefix": "oc/",
        "canonical_reported": "big-pickle",
    }
    note = meta["model_identity_note"]
    assert "verified" in note
    assert "not established as pinned" in note
    # Must not assert immutability.
    assert "immutable" not in note or "nothing more" in note


def test_meta_has_no_route_match_block_when_not_a_route_match():
    meta = ident("gpt-4o-mini", "gpt-4o-mini").as_meta()
    assert TRUSTED_ROUTE_MATCH not in meta
    assert "model_identity_note" not in meta


def test_meta_still_carries_backcompat_fields():
    meta = ident("oc/big-pickle", "big-pickle", ("oc/",)).as_meta()
    assert meta["model"] == "oc/big-pickle", "model stays the REQUESTED id"
    assert meta["provider"] == "gateway"
    assert meta["adapter"] == "openai_compatible"


def test_no_transport_name_reaches_the_model_field():
    for reported in ("openai_compatible", "local", "replay", "degraded"):
        assert ident("x", reported, ("x/",)).as_meta()["model"] == "x"
