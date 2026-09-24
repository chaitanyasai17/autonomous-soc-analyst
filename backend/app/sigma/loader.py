"""
Sigma rule loader — discovers, parses, validates, and caches rule YAML
files from settings.SIGMA_RULES_DIRECTORY. No database access here — pure
file-system + in-memory cache, mirroring the app/logs/parsers/ split
between "understanding a format" and "persisting the result".
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

import yaml
from pydantic import ValidationError

from app.sigma.condition_parser import validate_condition_syntax
from app.sigma.schemas import SigmaRule

logger = logging.getLogger(__name__)


class RuleLoadError:
    """One rule file's load failure — collected during a directory scan, never raised mid-scan."""

    def __init__(self, path: str, message: str):
        self.path = path
        self.message = message

    def __repr__(self) -> str:
        return f"RuleLoadError(path={self.path!r}, message={self.message!r})"

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


class SigmaRuleLoader:
    """
    Discovers *.yml/*.yaml files under `rules_directory` (recursively — one
    subdirectory per category), parses and validates each into a SigmaRule,
    and caches the resulting registry in memory. `reload()` re-scans from
    disk on demand (see POST /rules/reload); nothing here is DB-aware.
    """

    def __init__(self, rules_directory: str):
        self.rules_directory = Path(rules_directory)
        self._rules: dict[str, SigmaRule] = {}
        self._errors: list[RuleLoadError] = []
        self._loaded = False

    def _iter_rule_files(self) -> Iterator[Path]:
        if not self.rules_directory.exists():
            logger.warning("Sigma rules directory does not exist: %s", self.rules_directory)
            return
        seen: set[Path] = set()
        for pattern in ("*.yml", "*.yaml"):
            for path in sorted(self.rules_directory.rglob(pattern)):
                if path not in seen:
                    seen.add(path)
                    yield path

    def load(self, force: bool = False) -> None:
        """Populate the in-memory cache. No-op if already loaded, unless force=True."""
        if self._loaded and not force:
            return

        rules: dict[str, SigmaRule] = {}
        errors: list[RuleLoadError] = []
        file_count = 0

        for path in self._iter_rule_files():
            file_count += 1
            rule = self._load_one_file(path, rules, errors)
            if rule is not None:
                rules[rule.id] = rule

        self._rules = rules
        self._errors = errors
        self._loaded = True

        logger.info(
            "Sigma rule load complete: %d file(s) scanned, %d rule(s) loaded, %d error(s).",
            file_count,
            len(rules),
            len(errors),
        )
        for error in errors:
            logger.warning("Sigma rule load error: %s", error)

    def _load_one_file(
        self, path: Path, already_loaded: dict[str, SigmaRule], errors: list[RuleLoadError]
    ) -> SigmaRule | None:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            errors.append(RuleLoadError(str(path), f"Invalid YAML: {exc}"))
            return None

        if not isinstance(raw, dict):
            errors.append(RuleLoadError(str(path), "Rule file does not contain a YAML mapping."))
            return None

        raw.setdefault("category", path.parent.name)
        raw["source_path"] = str(path)

        try:
            rule = SigmaRule.model_validate(raw)
        except ValidationError as exc:
            errors.append(RuleLoadError(str(path), f"Schema validation failed: {exc}"))
            return None

        condition_errors = validate_condition_syntax(
            rule.detection.get("condition", ""),
            [key for key in rule.detection if key != "condition"],
        )
        if condition_errors:
            errors.append(RuleLoadError(str(path), f"Condition error: {'; '.join(condition_errors)}"))
            return None

        if rule.id in already_loaded:
            errors.append(
                RuleLoadError(
                    str(path),
                    f"Duplicate rule id {rule.id!r} (already loaded from {already_loaded[rule.id].source_path}).",
                )
            )
            return None

        return rule

    def reload(self) -> None:
        logger.info("Reloading Sigma rules from %s", self.rules_directory)
        self.load(force=True)

    def get_all_rules(self, *, include_disabled: bool = True) -> list[SigmaRule]:
        self.load()
        rules = list(self._rules.values())
        return rules if include_disabled else [r for r in rules if r.enabled]

    def get_enabled_rules(self) -> list[SigmaRule]:
        return self.get_all_rules(include_disabled=False)

    def get_rule(self, rule_id: str) -> SigmaRule | None:
        self.load()
        return self._rules.get(rule_id)

    def get_errors(self) -> list[RuleLoadError]:
        self.load()
        return list(self._errors)

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> SigmaRule:
        """
        Persist enable/disable to the rule's YAML file on disk (the file is
        the source of truth for rule state, not a DB row) and refresh the
        in-memory cache for just this rule.

        Production caveat: writing to the local filesystem is correct for a
        single-instance deployment but is not synchronized across multiple
        worker processes/instances — the same caveat already documented for
        the in-memory refresh-token blacklist (Part 4's
        app/security/token_blacklist.py). A multi-instance deployment would
        move rule enabled/disabled state to a shared store instead.
        """
        self.load()
        rule = self._rules.get(rule_id)
        if rule is None:
            raise KeyError(f"No loaded rule with id {rule_id!r}.")

        path = Path(rule.source_path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw["enabled"] = enabled
        path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

        updated_rule = rule.model_copy(update={"enabled": enabled})
        self._rules[rule_id] = updated_rule
        logger.info("Sigma rule %s (%s) %s", rule_id, rule.title, "enabled" if enabled else "disabled")
        return updated_rule
