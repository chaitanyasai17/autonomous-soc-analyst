"""Sigma rule API response schemas (see app/sigma/schemas.py for the internal engine representation)."""

from __future__ import annotations

from app.models.enums import RiskLevel
from app.schemas.base import BaseSchema


class SigmaRuleOut(BaseSchema):
    """Public representation of one loaded Sigma rule."""

    id: str
    title: str
    description: str | None
    author: str | None
    date: str | None
    modified: str | None
    status: str
    level: RiskLevel
    tags: list[str]
    category: str
    enabled: bool
    fields: list[str]
    falsepositives: list[str]
    references: list[str]


class RuleReloadResult(BaseSchema):
    """Returned by POST /rules/reload."""

    rules_loaded: int
    errors: list[str]


class RuleValidationIssue(BaseSchema):
    rule_id: str | None
    source_path: str
    message: str


class RuleValidationResult(BaseSchema):
    """Returned by POST /rules/validate."""

    valid_count: int
    invalid_count: int
    issues: list[RuleValidationIssue]
