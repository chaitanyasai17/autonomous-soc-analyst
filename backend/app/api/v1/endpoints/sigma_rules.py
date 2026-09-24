"""Sigma rule management endpoints — list, inspect, reload, validate, enable/disable."""

from fastapi import APIRouter, Depends, Query

from app.dependencies.rbac import require_permissions
from app.dependencies.services import get_rule_service
from app.models.enums import RiskLevel
from app.schemas.base import ResponseSchema
from app.schemas.sigma_rule import RuleReloadResult, RuleValidationResult, SigmaRuleOut
from app.security.permissions import Permission
from app.services.rule_service import RuleService

router = APIRouter(prefix="/rules", tags=["Sigma Rules"])


@router.get(
    "",
    response_model=ResponseSchema[list[SigmaRuleOut]],
    summary="List loaded Sigma rules",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def list_rules(
    category: str | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    level: RiskLevel | None = Query(default=None),
    rule_service: RuleService = Depends(get_rule_service),
) -> ResponseSchema:
    rules = rule_service.list_rules(category=category, enabled=enabled, level=level)
    return ResponseSchema(success=True, data=rules)


@router.post(
    "/reload",
    response_model=ResponseSchema[RuleReloadResult],
    summary="Re-scan the Sigma rules directory from disk, rebuilding the in-memory cache",
    dependencies=[Depends(require_permissions(Permission.SIGMA_RELOAD))],
)
def reload_rules(rule_service: RuleService = Depends(get_rule_service)) -> ResponseSchema:
    result = rule_service.reload_rules()
    return ResponseSchema(
        success=True,
        message=f"{result.rules_loaded} rule(s) loaded, {len(result.errors)} error(s).",
        data=result,
    )


@router.post(
    "/validate",
    response_model=ResponseSchema[RuleValidationResult],
    summary="Validate every rule file in the Sigma rules directory without necessarily having reloaded first",
    dependencies=[Depends(require_permissions(Permission.SIGMA_RELOAD))],
)
def validate_rules(rule_service: RuleService = Depends(get_rule_service)) -> ResponseSchema:
    result = rule_service.validate_rules()
    return ResponseSchema(
        success=True,
        message=f"{result.valid_count} valid, {result.invalid_count} invalid.",
        data=result,
    )


@router.patch(
    "/{rule_id}/enable",
    response_model=ResponseSchema[SigmaRuleOut],
    summary="Enable a Sigma rule (persisted to its YAML file)",
    dependencies=[Depends(require_permissions(Permission.SIGMA_MANAGE))],
)
def enable_rule(rule_id: str, rule_service: RuleService = Depends(get_rule_service)) -> ResponseSchema:
    rule = rule_service.enable_rule(rule_id)
    return ResponseSchema(success=True, message="Rule enabled.", data=rule)


@router.patch(
    "/{rule_id}/disable",
    response_model=ResponseSchema[SigmaRuleOut],
    summary="Disable a Sigma rule (persisted to its YAML file)",
    dependencies=[Depends(require_permissions(Permission.SIGMA_MANAGE))],
)
def disable_rule(rule_id: str, rule_service: RuleService = Depends(get_rule_service)) -> ResponseSchema:
    rule = rule_service.disable_rule(rule_id)
    return ResponseSchema(success=True, message="Rule disabled.", data=rule)


@router.get(
    "/{rule_id}",
    response_model=ResponseSchema[SigmaRuleOut],
    summary="Get a single Sigma rule by id",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def get_rule(rule_id: str, rule_service: RuleService = Depends(get_rule_service)) -> ResponseSchema:
    rule = rule_service.get_rule_or_404(rule_id)
    return ResponseSchema(success=True, data=rule)
