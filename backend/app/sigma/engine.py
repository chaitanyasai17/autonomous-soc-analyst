"""
Detection engine — evaluates every enabled Sigma rule against a single
ParsedLog event. Pure evaluation logic, no database access — see
app/services/detection_service.py for the DB-facing orchestration layer
that persists results as SigmaDetection rows (mirrors the
app/logs/parsers/ vs. app/services/parser_service.py split from Part 6).
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.parsed_log import ParsedLog
from app.sigma.condition_parser import ConditionSyntaxError, evaluate_condition
from app.sigma.evaluator import FieldMatch, evaluate_selection
from app.sigma.loader import SigmaRuleLoader
from app.sigma.schemas import SigmaRule

_BASE_CONFIDENCE = 0.6
_CONFIDENCE_PER_EXTRA_FIELD = 0.1


@dataclass
class RuleMatchResult:
    rule: SigmaRule
    matched_fields: list[FieldMatch]
    confidence: float


def _calculate_confidence(matched_fields: list[FieldMatch]) -> float:
    """
    Simple, explainable confidence heuristic: each additional distinct
    field contributing to the match increases confidence (capped at 1.0).
    A match pinned down by several independent fields is inherently less
    likely to be coincidental than a single loose `contains` hit.
    """
    distinct_fields = len({m.field for m in matched_fields})
    return min(1.0, _BASE_CONFIDENCE + _CONFIDENCE_PER_EXTRA_FIELD * max(0, distinct_fields - 1))


class DetectionEngine:
    def __init__(self, rule_loader: SigmaRuleLoader):
        self.rule_loader = rule_loader

    @property
    def rules(self) -> list[SigmaRule]:
        if hasattr(self.rule_loader, "get_all_rules"):
            return self.rule_loader.get_all_rules()
        return []


    def evaluate_event(self, event: ParsedLog) -> list[RuleMatchResult]:
        """Evaluate every enabled rule against one event; returns all rules that matched."""
        results: list[RuleMatchResult] = []
        for rule in self.rule_loader.get_enabled_rules():
            result = self._evaluate_rule(rule, event)
            if result is not None:
                results.append(result)
        return results

    def _evaluate_rule(self, rule: SigmaRule, event: ParsedLog) -> RuleMatchResult | None:
        detection = rule.detection
        condition = detection.get("condition", "")
        selections = {key: value for key, value in detection.items() if key != "condition"}

        selection_results: dict[str, bool] = {}
        selection_matches: dict[str, list[FieldMatch]] = {}
        for name, selection in selections.items():
            matched, field_matches = evaluate_selection(event, selection, name)
            selection_results[name] = matched
            selection_matches[name] = field_matches

        try:
            overall_match = evaluate_condition(condition, selection_results)
        except ConditionSyntaxError:
            # Fails closed: a malformed condition produces no detection
            # rather than crashing the whole batch. Rule authors surface
            # this via POST /rules/validate, not during live detection runs.
            return None

        if not overall_match:
            return None

        matched_fields = [
            field_match
            for name, matched in selection_results.items()
            if matched
            for field_match in selection_matches[name]
        ]
        return RuleMatchResult(
            rule=rule, matched_fields=matched_fields, confidence=_calculate_confidence(matched_fields)
        )
