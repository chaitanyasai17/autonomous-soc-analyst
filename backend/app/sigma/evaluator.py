"""
Sigma selection evaluator — matches a ParsedLog event against a single
Sigma "selection" block (a dict of `field` or `field|modifier`: value(s)).

Supported per Part 8 spec:
    - equals (exact; case-insensitive for strings, numeric-aware for ports)
    - contains / startswith / endswith (case-insensitive substring checks)
    - re (regular expression, case-insensitive)
    - lists (OR semantics across list items — matches if ANY item matches)

Simplification (documented, not a bug): a selection is a flat dict — every
field key within it is AND'ed together (standard Sigma semantics for a
single selection block). Sigma's more advanced "list of dicts" selection
syntax (representing OR-of-AND-groups within one selection) is not
supported; use multiple named selections combined via the condition string
instead (e.g. `selection1 or selection2`), which covers the same cases.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.models.parsed_log import ParsedLog
from app.sigma.field_mapping import FREE_TEXT_FALLBACK_FIELDS, resolve_field_name


@dataclass
class FieldMatch:
    """One field that contributed to a selection match — persisted in SigmaDetection.matched_fields."""

    field: str
    value: Any
    selection: str = ""


def _values_as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _match_single(actual: Any, expected: Any, modifier: str | None) -> bool:
    if actual is None:
        return False

    if modifier == "contains":
        return str(expected).lower() in str(actual).lower()
    if modifier == "startswith":
        return str(actual).lower().startswith(str(expected).lower())
    if modifier == "endswith":
        return str(actual).lower().endswith(str(expected).lower())
    if modifier == "re":
        try:
            return re.search(str(expected), str(actual), re.IGNORECASE) is not None
        except re.error:
            return False

    # Default: exact equality. Numeric columns (ports) are compared
    # numerically so `destination_port: 22` matches an int column;
    # everything else is case-insensitive string equality.
    if isinstance(actual, (int, float)) and not isinstance(actual, bool):
        try:
            return actual == type(actual)(expected)
        except (TypeError, ValueError):
            return str(actual).lower() == str(expected).lower()
    return str(actual).lower() == str(expected).lower()


def _match_field(event: ParsedLog, field_key: str, expected: Any) -> tuple[bool, FieldMatch | None]:
    field_name, _, modifier = field_key.partition("|")
    modifier = modifier or None

    resolved = resolve_field_name(field_name)
    candidates = [resolved] if resolved else list(FREE_TEXT_FALLBACK_FIELDS)

    for candidate in candidates:
        actual = getattr(event, candidate, None)
        if actual is None:
            continue
        for expected_value in _values_as_list(expected):
            if _match_single(actual, expected_value, modifier):
                return True, FieldMatch(field=field_name, value=actual)
    return False, None


def evaluate_selection(
    event: ParsedLog, selection: dict[str, Any], selection_name: str
) -> tuple[bool, list[FieldMatch]]:
    """
    A selection matches when EVERY field key in it matches (AND across
    fields within one selection). Returns (matched, field_matches) —
    field_matches is empty unless matched is True.
    """
    matches: list[FieldMatch] = []
    for field_key, expected in selection.items():
        matched, field_match = _match_field(event, field_key, expected)
        if not matched:
            return False, []
        if field_match:
            field_match.selection = selection_name
            matches.append(field_match)
    return True, matches
