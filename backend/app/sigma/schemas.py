"""
Strongly typed internal representation of a loaded Sigma rule.

Deliberately a `pydantic.BaseModel` (not a `schemas/base.BaseSchema`
API-boundary DTO) — this lives in app/sigma/ alongside the rest of the
rule-loading/evaluation logic (no DB, no HTTP), exactly mirroring how
app/logs/parsers/base.py's NormalizedLogEntry is internal to the parser
layer. app/schemas/sigma_rule.py holds the separate API-facing DTOs.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models.enums import RiskLevel


class SigmaLogSource(BaseModel):
    category: str | None = None
    product: str | None = None
    service: str | None = None


class SigmaRule(BaseModel):
    """One parsed and validated Sigma rule YAML file."""

    id: str
    title: str
    description: str | None = None
    author: str | None = None
    date: str | None = None
    modified: str | None = None
    status: str = "stable"
    level: RiskLevel = RiskLevel.LOW
    tags: list[str] = Field(default_factory=list)
    logsource: SigmaLogSource = Field(default_factory=SigmaLogSource)
    detection: dict[str, Any]
    fields: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    enabled: bool = True

    # --- Loader-populated metadata, not part of the rule's own YAML content ---
    category: str = Field(default="uncategorized", description="Subdirectory name under SIGMA_RULES_DIRECTORY")
    source_path: str = Field(default="", description="Absolute file path this rule was loaded from")

    @field_validator("id")
    @classmethod
    def id_must_be_non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Rule 'id' must be a non-empty string.")
        return value.strip()

    @field_validator("title")
    @classmethod
    def title_must_be_non_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("Rule 'title' must be a non-empty string.")
        return value.strip()

    @field_validator("detection")
    @classmethod
    def detection_must_have_condition_and_selections(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict) or not value:
            raise ValueError("'detection' block must be a non-empty mapping.")
        if "condition" not in value:
            raise ValueError("'detection' block is missing a required 'condition' key.")
        if not isinstance(value["condition"], str) or not value["condition"].strip():
            raise ValueError("'detection.condition' must be a non-empty string.")
        if not any(key != "condition" for key in value):
            raise ValueError("'detection' block has a condition but no selections to evaluate against.")
        for key, selection in value.items():
            if key == "condition":
                continue
            if not isinstance(selection, dict) or not selection:
                raise ValueError(
                    f"Selection {key!r} must be a non-empty mapping of field: value pairs."
                )
        return value
