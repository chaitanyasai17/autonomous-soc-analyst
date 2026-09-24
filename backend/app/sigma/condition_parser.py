"""
Safe Sigma condition expression evaluator.

Supports the common Sigma condition grammar: selection-name identifiers,
`and` / `or` / `not`, parentheses, and the `<N> of <pattern>` / `all of
<pattern>` idioms (pattern may end in `*` as a wildcard, or be the literal
`them` meaning "every selection").

Deliberately does NOT use Python's `eval()` or any dynamic code execution:
the condition string is tokenized and evaluated by a small recursive-descent
parser over a fixed, known grammar, so a malformed or adversarial condition
string can only ever raise ConditionSyntaxError, never execute arbitrary
code — this matters because rule YAML files may originate from less-trusted
sources (a SOC_MANAGER+ uploading/editing rules) than application code.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch

_TOKEN_RE = re.compile(
    r"""
    (?P<lparen>\()
    |(?P<rparen>\))
    |(?P<number>\d+)(?=\s+of\b)
    |(?P<word>[A-Za-z_][A-Za-z0-9_*]*)
    """,
    re.VERBOSE,
)


class ConditionSyntaxError(Exception):
    """Raised when a Sigma condition string cannot be parsed."""


def _tokenize(condition: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    length = len(condition)
    while pos < length:
        if condition[pos].isspace():
            pos += 1
            continue
        match = _TOKEN_RE.match(condition, pos)
        if not match:
            raise ConditionSyntaxError(
                f"Unexpected character in condition at position {pos}: {condition[pos:pos + 10]!r}"
            )
        pos = match.end()
        tokens.append(match.group())
    return tokens


class _Parser:
    """
    Grammar (lowest to highest precedence):
        expr       := or_expr
        or_expr    := and_expr ('or' and_expr)*
        and_expr   := not_expr ('and' not_expr)*
        not_expr   := 'not' not_expr | atom
        atom       := '(' expr ')' | quantifier | IDENTIFIER
        quantifier := (NUMBER | 'all') 'of' PATTERN
    """

    def __init__(self, tokens: list[str], selection_results: dict[str, bool]):
        self.tokens = tokens
        self.pos = 0
        self.selection_results = selection_results

    def parse(self) -> bool:
        result = self._or_expr()
        if self.pos != len(self.tokens):
            raise ConditionSyntaxError(f"Unexpected trailing tokens: {self.tokens[self.pos:]}")
        return result

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _advance(self) -> str:
        token = self._peek()
        if token is None:
            raise ConditionSyntaxError("Unexpected end of condition expression.")
        self.pos += 1
        return token

    def _or_expr(self) -> bool:
        result = self._and_expr()
        while self._peek() == "or":
            self._advance()
            rhs = self._and_expr()
            result = result or rhs
        return result

    def _and_expr(self) -> bool:
        result = self._not_expr()
        while self._peek() == "and":
            self._advance()
            rhs = self._not_expr()
            result = result and rhs
        return result

    def _not_expr(self) -> bool:
        if self._peek() == "not":
            self._advance()
            return not self._not_expr()
        return self._atom()

    def _atom(self) -> bool:
        token = self._peek()
        if token is None:
            raise ConditionSyntaxError("Unexpected end of condition expression.")

        if token == "(":
            self._advance()
            result = self._or_expr()
            if self._peek() != ")":
                raise ConditionSyntaxError("Missing closing parenthesis in condition.")
            self._advance()
            return result

        if token.isdigit():
            return self._quantifier(minimum=int(self._advance()))

        if token == "all":
            self._advance()
            return self._quantifier_of(minimum=None)

        self._advance()
        if token not in self.selection_results:
            raise ConditionSyntaxError(f"Condition references unknown selection {token!r}.")
        return self.selection_results[token]

    def _quantifier(self, minimum: int) -> bool:
        return self._quantifier_of(minimum=minimum)

    def _quantifier_of(self, minimum: int | None) -> bool:
        if self._peek() != "of":
            raise ConditionSyntaxError("Expected 'of' after a quantifier ('1 of ...' / 'all of ...').")
        self._advance()
        pattern = self._advance()
        matching = self._selections_matching(pattern)
        if not matching:
            raise ConditionSyntaxError(f"No selections match pattern {pattern!r}.")
        matched_count = sum(1 for name in matching if self.selection_results[name])
        required = len(matching) if minimum is None else minimum
        return matched_count >= required

    def _selections_matching(self, pattern: str) -> list[str]:
        if pattern == "them":
            return list(self.selection_results.keys())
        return [name for name in self.selection_results if fnmatch(name, pattern)]


def evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    """Evaluate a Sigma `condition` string against pre-computed per-selection boolean results."""
    tokens = _tokenize(condition)
    if not tokens:
        raise ConditionSyntaxError("Condition expression is empty.")
    return _Parser(tokens, selection_results).parse()


def validate_condition_syntax(condition: str, selection_names: list[str]) -> list[str]:
    """
    Dry-run a condition against dummy (all-False) selection results purely
    to surface syntax errors — used by POST /rules/validate. Returns a list
    of error messages (empty if valid).
    """
    dummy_results = {name: False for name in selection_names}
    try:
        evaluate_condition(condition, dummy_results)
        return []
    except ConditionSyntaxError as exc:
        return [str(exc)]
