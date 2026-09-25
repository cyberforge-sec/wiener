from __future__ import annotations

import json


def extract_json_object(text: str) -> dict:
    """Best-effort extraction of the first valid JSON object.

    Handles models that wrap JSON in prose ("Here's the analysis: {...}"),
    trailing junk (sentinel leftovers), or emit a second object after the
    intended one. Tries a direct parse first, then scans the string for the
    balanced-brace window of each candidate object and validates it.
    Never returns a value without a full, valid JSON parse.
    """
    stripped = text.strip()
    if stripped:
        try:
            data = json.loads(stripped)
        except (ValueError, TypeError):
            pass
        else:
            if isinstance(data, dict):
                return data

    start = -1
    depth = 0
    in_string = False
    escaped = False
    for idx, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            if depth == 0:
                start = idx
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                candidate = text[start : idx + 1]
                try:
                    data = json.loads(candidate)
                except (ValueError, TypeError):
                    start = -1
                    continue
                if isinstance(data, dict):
                    return data

    raise ValueError("no valid JSON object found")