"""Sigma rule loading and detection engine: evaluates normalized logs against Sigma rule sets."""

from app.sigma.condition_parser import ConditionSyntaxError, evaluate_condition, validate_condition_syntax
from app.sigma.engine import DetectionEngine, RuleMatchResult
from app.sigma.evaluator import FieldMatch, evaluate_selection
from app.sigma.loader import RuleLoadError, SigmaRuleLoader
from app.sigma.schemas import SigmaLogSource, SigmaRule

__all__ = [
    "SigmaRule",
    "SigmaLogSource",
    "SigmaRuleLoader",
    "RuleLoadError",
    "DetectionEngine",
    "RuleMatchResult",
    "FieldMatch",
    "evaluate_selection",
    "evaluate_condition",
    "validate_condition_syntax",
    "ConditionSyntaxError",
]
