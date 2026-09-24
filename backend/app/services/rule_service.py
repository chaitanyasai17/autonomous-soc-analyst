"""Rule service — orchestrates SigmaRuleLoader for the rule-management API endpoints."""

from __future__ import annotations

from app.core.exceptions import NotFoundError
from app.models.enums import RiskLevel
from app.schemas.sigma_rule import RuleReloadResult, RuleValidationIssue, RuleValidationResult
from app.sigma.loader import SigmaRuleLoader
from app.sigma.schemas import SigmaRule


class RuleService:
    def __init__(self, rule_loader: SigmaRuleLoader):
        self.rule_loader = rule_loader

    def list_rules(
        self,
        *,
        category: str | None = None,
        enabled: bool | None = None,
        level: RiskLevel | None = None,
    ) -> list[SigmaRule]:
        rules = self.rule_loader.get_all_rules()
        if category is not None:
            rules = [r for r in rules if r.category == category]
        if enabled is not None:
            rules = [r for r in rules if r.enabled == enabled]
        if level is not None:
            rules = [r for r in rules if r.level == level]
        return rules

    def get_rule_or_404(self, rule_id: str) -> SigmaRule:
        rule = self.rule_loader.get_rule(rule_id)
        if rule is None:
            raise NotFoundError(f"Sigma rule with id={rule_id} not found.")
        return rule

    def reload_rules(self) -> RuleReloadResult:
        self.rule_loader.reload()
        errors = self.rule_loader.get_errors()
        return RuleReloadResult(
            rules_loaded=len(self.rule_loader.get_all_rules()),
            errors=[str(e) for e in errors],
        )

    def validate_rules(self) -> RuleValidationResult:
        """Force a fresh re-scan from disk and report every validation issue found."""
        self.rule_loader.reload()
        valid_rules = self.rule_loader.get_all_rules()
        errors = self.rule_loader.get_errors()
        issues = [RuleValidationIssue(rule_id=None, source_path=e.path, message=e.message) for e in errors]
        return RuleValidationResult(valid_count=len(valid_rules), invalid_count=len(issues), issues=issues)

    def enable_rule(self, rule_id: str) -> SigmaRule:
        try:
            return self.rule_loader.set_rule_enabled(rule_id, True)
        except KeyError as exc:
            raise NotFoundError(str(exc)) from exc

    def disable_rule(self, rule_id: str) -> SigmaRule:
        try:
            return self.rule_loader.set_rule_enabled(rule_id, False)
        except KeyError as exc:
            raise NotFoundError(str(exc)) from exc
