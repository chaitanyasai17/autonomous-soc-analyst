"""SigmaDetection repository — data access only, no business rules (see services/detection_service.py)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.models.enums import RiskLevel
from app.models.parsed_log import ParsedLog
from app.models.security_log import SecurityLog
from app.models.sigma_detection import SigmaDetection
from app.repositories.base import BaseRepository


class SigmaDetectionRepository(BaseRepository[SigmaDetection]):
    """Repository encapsulating all direct queries against the sigma_detections table."""

    def __init__(self, db: Session):
        super().__init__(model=SigmaDetection, db=db)

    def bulk_create(self, detections: Sequence[SigmaDetection]) -> None:
        """Insert many rows in one commit — used by DetectionService's batch detection loop."""
        self.db.add_all(detections)
        self.db.commit()

    def get_existing_rule_ids_for_parsed_log(self, parsed_log_id: uuid.UUID) -> set[str]:
        """
        Return the set of rule ids already recorded against this parsed
        log — used to skip already-detected rule matches on re-run,
        enforcing "avoid duplicate detections" without relying solely on
        the DB unique constraint racing a bulk insert.
        """
        stmt = select(SigmaDetection.matched_rule).where(
            SigmaDetection.parsed_log_id == parsed_log_id
        )
        return set(self.db.execute(stmt).scalars().all())

    def delete_by_parsed_log_id(self, parsed_log_id: uuid.UUID) -> int:
        """Remove all detections for a single parsed log (used by re-run detection). Returns rows deleted."""
        stmt = delete(SigmaDetection).where(SigmaDetection.parsed_log_id == parsed_log_id)
        result = self.db.execute(stmt)
        self.db.commit()
        return result.rowcount or 0

    def bulk_delete_by_ids(self, detection_ids: Sequence[uuid.UUID]) -> int:
        stmt = delete(SigmaDetection).where(SigmaDetection.id.in_(detection_ids))
        result = self.db.execute(stmt)
        self.db.commit()
        return result.rowcount or 0

    _SORTABLE_FIELDS = {
        "detection_timestamp": SigmaDetection.detection_timestamp,
        "created_at": SigmaDetection.created_at,
        "severity": SigmaDetection.severity,
        "confidence": SigmaDetection.confidence,
    }

    def search(
        self,
        *,
        uploaded_by_id: uuid.UUID | None = None,
        parsed_log_id: uuid.UUID | None = None,
        security_log_id: uuid.UUID | None = None,
        matched_rule: str | None = None,
        rule_category: str | None = None,
        severity: RiskLevel | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        skip: int = 0,
        limit: int = 20,
        sort_by: str = "detection_timestamp",
        sort_order: str = "desc",
    ) -> tuple[Sequence[SigmaDetection], int]:
        """
        Return (page_of_detections, total_matching_count).

        `uploaded_by_id`/`security_log_id`, when provided, join through
        ParsedLog -> SecurityLog to scope results — used for RBAC
        visibility (own uploads only, unless LOG_READ_ANY) and for
        "detections belonging to one uploaded file" queries respectively.
        The join is only added when actually needed.
        """
        conditions = []
        needs_join = uploaded_by_id is not None or security_log_id is not None

        base_stmt = select(SigmaDetection)
        count_stmt = select(func.count()).select_from(SigmaDetection)

        if needs_join:
            base_stmt = (
                base_stmt.join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
                .join(SecurityLog, ParsedLog.security_log_id == SecurityLog.id)
            )
            count_stmt = (
                count_stmt.join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
                .join(SecurityLog, ParsedLog.security_log_id == SecurityLog.id)
            )
            if uploaded_by_id is not None:
                conditions.append(SecurityLog.uploaded_by_id == uploaded_by_id)
            if security_log_id is not None:
                conditions.append(SecurityLog.id == security_log_id)

        if parsed_log_id is not None:
            conditions.append(SigmaDetection.parsed_log_id == parsed_log_id)
        if matched_rule:
            conditions.append(SigmaDetection.matched_rule == matched_rule)
        if rule_category:
            conditions.append(SigmaDetection.rule_category == rule_category)
        if severity is not None:
            conditions.append(SigmaDetection.severity == severity)
        if date_from is not None:
            conditions.append(SigmaDetection.detection_timestamp >= date_from)
        if date_to is not None:
            conditions.append(SigmaDetection.detection_timestamp <= date_to)

        base_stmt = base_stmt.where(*conditions)
        count_stmt = count_stmt.where(*conditions)

        sort_column = self._SORTABLE_FIELDS.get(sort_by, SigmaDetection.detection_timestamp)
        order_clause = sort_column.desc() if sort_order == "desc" else sort_column.asc()

        page_stmt = base_stmt.order_by(order_clause).offset(skip).limit(limit)

        items = self.db.execute(page_stmt).scalars().all()
        total = self.db.execute(count_stmt).scalar_one()
        return items, total

    def get_statistics(self, uploaded_by_id: uuid.UUID | None = None) -> dict:
        """A handful of small aggregate queries — bounded by distinct enum/category cardinality, not row count."""
        needs_join = uploaded_by_id is not None
        conditions = []

        def _with_join(stmt):
            if needs_join:
                stmt = stmt.join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id).join(
                    SecurityLog, ParsedLog.security_log_id == SecurityLog.id
                )
            return stmt

        if needs_join:
            conditions.append(SecurityLog.uploaded_by_id == uploaded_by_id)

        total_detections = self.db.execute(
            _with_join(select(func.count()).select_from(SigmaDetection)).where(*conditions)
        ).scalar_one()

        severity_rows = self.db.execute(
            _with_join(select(SigmaDetection.severity, func.count()).select_from(SigmaDetection))
            .where(*conditions)
            .group_by(SigmaDetection.severity)
        ).all()
        by_severity = {severity.value: count for severity, count in severity_rows}

        category_rows = self.db.execute(
            _with_join(select(SigmaDetection.rule_category, func.count()).select_from(SigmaDetection))
            .where(*conditions)
            .group_by(SigmaDetection.rule_category)
        ).all()
        by_category = {(category or "uncategorized"): count for category, count in category_rows}

        rule_rows = self.db.execute(
            _with_join(
                select(
                    SigmaDetection.matched_rule,
                    SigmaDetection.rule_title,
                    func.max(SigmaDetection.severity),
                    func.count(),
                )
                .select_from(SigmaDetection)
            )
            .where(*conditions)
            .group_by(SigmaDetection.matched_rule, SigmaDetection.rule_title)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
        top_rules = [
            {
                "rule_id": rule_id,
                "rule_title": title,
                "title": title,
                "severity": (sev.value if hasattr(sev, "value") else str(sev)).lower() if sev else "medium",
                "count": count,
            }
            for rule_id, title, sev, count in rule_rows
        ]

        avg_confidence = self.db.execute(
            _with_join(select(func.avg(SigmaDetection.confidence)).select_from(SigmaDetection)).where(
                *conditions
            )
        ).scalar_one()

        last_detection_at = self.db.execute(
            _with_join(select(func.max(SigmaDetection.detection_timestamp)).select_from(SigmaDetection)).where(
                *conditions
            )
        ).scalar_one()

        return {
            "total_detections": total_detections,
            "by_severity": by_severity,
            "by_category": by_category,
            "top_rules": top_rules,
            "average_confidence": round(float(avg_confidence), 4) if avg_confidence is not None else 0.0,
            "last_detection_at": last_detection_at,
        }
