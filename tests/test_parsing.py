from __future__ import annotations

import pytest

from app.llm.parsing import extract_json_object


def test_direct_parse():
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_prose_preamble_and_trailing():
    text = 'Here is my analysis:\n{"action": "block_ip", "confidence": 0.9}\nHope this helps.'
    assert extract_json_object(text)["action"] == "block_ip"


def test_sentinel_leftover():
    text = '{"a": 1}\n\ndata: [DONE]\n'
    assert extract_json_object(text) == {"a": 1}


def test_picks_first_valid_object_over_junk_before():
    text = 'not json {broken} but {"ok": true}'
    assert extract_json_object(text) == {"ok": True}


def test_braces_inside_strings_are_respected():
    text = '{"desc": "a {b} c", "n": 2}'
    assert extract_json_object(text) == {"desc": "a {b} c", "n": 2}


def test_empty_raises():
    with pytest.raises(ValueError):
        extract_json_object("")


def test_no_json_raises():
    with pytest.raises(ValueError):
        extract_json_object("just prose, no json anywhere")