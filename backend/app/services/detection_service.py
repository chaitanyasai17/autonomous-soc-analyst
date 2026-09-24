"""
Detection service — orchestrates the Sigma detection workflow: fetch
ParsedLog event(s) -> evaluate via DetectionEngine -> skip already-detected
rule matches -> batch-insert SigmaDetection rows.

Async-readiness note (mirrors Part 6's ParserService): every method here
takes plain models/IDs and returns plain data, never Request/Response
objects, so this could be handed to a background task queue later without
redesign.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Sequence

from app.core.exceptions import ForbiddenError, NotFoundError, ValidationFailedError
from app.models.parsed_log import ParsedLog
from app.models.security_log import SecurityLog
from app.models.sigma_detection import SigmaDetection
from app.models.user import User
from app.repositories.parsed_log_repository import ParsedLogRepository
from app.repositories.security_log_repository import SecurityLogRepository
from app.repositories.sigma_detection_repository import SigmaDetectionRepository
from app.schemas.detection import (
    DetectionAnalyticsOut,
    DetectionEvidenceOut,
    DetectionQualityMetricsOut,
    DetectionRunSummary,
    DetectionStatistics,
    SigmaDetectionOut,
)
from app.security.permissions import Permission, role_has_permission
from sqlalchemy import func, select
from app.sigma.engine import DetectionEngine
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

_BULK_INSERT_BATCH_SIZE = 500


class DetectionService:
    def __init__(
        self,
        security_log_repository: SecurityLogRepository,
        parsed_log_repository: ParsedLogRepository,
        sigma_detection_repository: SigmaDetectionRepository,
        detection_engine: DetectionEngine,
        mitre_service: Any | None = None,
    ):
        self.security_log_repository = security_log_repository
        self.parsed_log_repository = parsed_log_repository
        self.sigma_detection_repository = sigma_detection_repository
        self.detection_engine = detection_engine
        self.mitre_service = mitre_service

    # --- Authorization (mirrors ParserService's pattern from Part 6) ---

    def _authorize(self, security_log: SecurityLog, requesting_user: User) -> None:
        is_owner = security_log.uploaded_by_id == requesting_user.id
        if not role_has_permission(requesting_user.role, Permission.SIGMA_RUN):
            raise ForbiddenError("You do not have permission to run Sigma detections.")
        if not is_owner and not role_has_permission(requesting_user.role, Permission.LOG_READ_ANY):
            raise ForbiddenError("You do not have permission to run detections on other users' logs.")

    def _get_owning_security_log(self, parsed_log: ParsedLog) -> SecurityLog:
        security_log = self.security_log_repository.get_by_id(parsed_log.security_log_id)
        if security_log is None:  # pragma: no cover - FK guarantees this in practice
            raise NotFoundError("Parent security log not found.")
        return security_log

    # --- Core evaluation + persistence ---

    def _detect_events(self, events: Sequence[ParsedLog]) -> DetectionRunSummary:
        events_scanned = 0
        detections_created = 0
        detections_skipped_duplicate = 0
        by_severity: dict[str, int] = {}
        batch: list[SigmaDetection] = []

        for event in events:
            events_scanned += 1
            existing_rule_ids = self.sigma_detection_repository.get_existing_rule_ids_for_parsed_log(
                event.id
            )
            for match in self.detection_engine.evaluate_event(event):
                if match.rule.id in existing_rule_ids:
                    detections_skipped_duplicate += 1
                    continue

                detection = SigmaDetection(
                    parsed_log_id=event.id,
                    matched_rule=match.rule.id,
                    rule_title=match.rule.title,
                    rule_category=match.rule.category,
                    rule_tags=match.rule.tags,
                    severity=match.rule.level,
                    confidence=match.confidence,
                    detection_timestamp=utc_now(),
                    matched_fields=[
                        {"field": m.field, "value": str(m.value), "selection": m.selection}
                        for m in match.matched_fields
                    ],
                )
                batch.append(detection)
                detections_created += 1
                by_severity[match.rule.level.value] = by_severity.get(match.rule.level.value, 0) + 1

                if len(batch) >= _BULK_INSERT_BATCH_SIZE:
                    self.sigma_detection_repository.bulk_create(batch)
                    if self.mitre_service:
                        for d in batch:
                            try:
                                self.mitre_service.map_and_link_detection_tags(d, d.rule_tags or [])
                            except Exception as e:
                                logger.warning("Could not link MITRE technique for %s: %s", d.id, e)
                    batch = []

        if batch:
            self.sigma_detection_repository.bulk_create(batch)
            if self.mitre_service:
                for d in batch:
                    try:
                        self.mitre_service.map_and_link_detection_tags(d, d.rule_tags or [])
                    except Exception as e:
                        logger.warning("Could not link MITRE technique for %s: %s", d.id, e)

        logger.info(
            "Detection run complete: %d event(s) scanned, %d detection(s) created, %d duplicate(s) skipped.",
            events_scanned,
            detections_created,
            detections_skipped_duplicate,
        )

        return DetectionRunSummary(
            events_scanned=events_scanned,
            detections_created=detections_created,
            detections_skipped_duplicate=detections_skipped_duplicate,
            by_severity=by_severity,
        )

    # --- Public run methods ---

    def detect_one_log(self, parsed_log_id: uuid.UUID, requesting_user: User) -> DetectionRunSummary:
        parsed_log = self.parsed_log_repository.get_by_id(parsed_log_id)
        if parsed_log is None:
            raise NotFoundError(f"Parsed log with id={parsed_log_id} not found.")
        security_log = self._get_owning_security_log(parsed_log)
        self._authorize(security_log, requesting_user)
        return self._detect_events([parsed_log])

    def detect_uploaded_file(
        self, security_log_id: uuid.UUID, requesting_user: User
    ) -> DetectionRunSummary:
        security_log = self.security_log_repository.get_by_id(security_log_id)
        if security_log is None:
            raise NotFoundError(f"Security log with id={security_log_id} not found.")
        self._authorize(security_log, requesting_user)

        events, _ = self.parsed_log_repository.search(security_log_id=security_log_id, skip=0, limit=1_000_000)
        return self._detect_events(events)

    def detect_all(self, requesting_user: User) -> DetectionRunSummary:
        """Runs detection across every parsed log the requesting user can see (own uploads unless LOG_READ_ANY)."""
        if not role_has_permission(requesting_user.role, Permission.SIGMA_RUN):
            raise ForbiddenError("You do not have permission to run Sigma detections.")

        uploaded_by_id = None
        if not role_has_permission(requesting_user.role, Permission.LOG_READ_ANY):
            uploaded_by_id = requesting_user.id

        events, _ = self.parsed_log_repository.search(
            uploaded_by_id=uploaded_by_id, skip=0, limit=1_000_000
        )
        return self._detect_events(events)

    # --- Read / list ---

    def get_detection_or_404(self, detection_id: uuid.UUID, requesting_user: User) -> SigmaDetection:
        detection = self.sigma_detection_repository.get_by_id(detection_id)
        if detection is None:
            raise NotFoundError(f"Detection with id={detection_id} not found.")

        parsed_log = self.parsed_log_repository.get_by_id(detection.parsed_log_id)
        security_log = self._get_owning_security_log(parsed_log) if parsed_log else None
        is_owner = security_log is not None and security_log.uploaded_by_id == requesting_user.id
        has_visibility = role_has_permission(requesting_user.role, Permission.LOG_READ_ANY)
        if not is_owner and not has_visibility:
            raise NotFoundError(f"Detection with id={detection_id} not found.")

        return detection

    def list_detections(
        self,
        *,
        requesting_user: User,
        parsed_log_id: uuid.UUID | None = None,
        security_log_id: uuid.UUID | None = None,
        matched_rule: str | None = None,
        rule_category: str | None = None,
        severity=None,
        date_from=None,
        date_to=None,
        skip: int = 0,
        limit: int = 20,
        sort_by: str = "detection_timestamp",
        sort_order: str = "desc",
    ):
        uploaded_by_id = None
        if not role_has_permission(requesting_user.role, Permission.LOG_READ_ANY):
            uploaded_by_id = requesting_user.id

        return self.sigma_detection_repository.search(
            uploaded_by_id=uploaded_by_id,
            parsed_log_id=parsed_log_id,
            security_log_id=security_log_id,
            matched_rule=matched_rule,
            rule_category=rule_category,
            severity=severity,
            date_from=date_from,
            date_to=date_to,
            skip=skip,
            limit=limit,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    def get_history(
        self,
        *,
        requesting_user: User,
        security_log_id: uuid.UUID | None = None,
        parsed_log_id: uuid.UUID | None = None,
        skip: int = 0,
        limit: int = 20,
    ):
        """
        Chronological detection history, optionally scoped to one uploaded
        file or one parsed log. Functionally the same underlying query as
        list_detections with a fixed chronological sort — kept as a
        separate service method/endpoint per the Part 8 spec's explicit
        "Detection History" requirement, oriented for audit-trail browsing
        rather than ad-hoc filtering.
        """
        return self.list_detections(
            requesting_user=requesting_user,
            security_log_id=security_log_id,
            parsed_log_id=parsed_log_id,
            skip=skip,
            limit=limit,
            sort_by="detection_timestamp",
            sort_order="desc",
        )

    def get_statistics(self, requesting_user: User) -> DetectionStatistics:
        uploaded_by_id = None
        if not role_has_permission(requesting_user.role, Permission.LOG_READ_ANY):
            uploaded_by_id = requesting_user.id

        raw = self.sigma_detection_repository.get_statistics(uploaded_by_id=uploaded_by_id)
        return DetectionStatistics(**raw)

    def get_evidence(self, detection_id: uuid.UUID) -> DetectionEvidenceOut:
        """Provide detailed 'Why Detected?' evidence for a Sigma rule match."""
        det = self.sigma_detection_repository.get_by_id(detection_id)
        if not det:
            raise NotFoundError(f"Sigma detection '{detection_id}' not found.")

        parsed_log = self.parsed_log_repository.get_by_id(det.parsed_log_id)
        log_payload = None
        if parsed_log:
            log_payload = {
                "id": str(parsed_log.id),
                "timestamp": parsed_log.timestamp.isoformat() if parsed_log.timestamp else None,
                "event_type": parsed_log.event_type,
                "source_ip": parsed_log.source_ip,
                "destination_ip": parsed_log.destination_ip,
                "username": parsed_log.username,
                "hostname": parsed_log.hostname,
                "action": getattr(parsed_log, "action", None),
                "message": getattr(parsed_log, "message", None),
                "raw_log": parsed_log.raw_log,
            }

        rule_obj = next((r for r in self.detection_engine.rules if r.id == det.matched_rule), None)
        rule_condition = getattr(rule_obj, "condition", None) if rule_obj else None

        techniques = [
            {"technique_id": t.technique_id, "name": t.name}
            for t in (det.mitre_techniques or [])
        ]

        matched_count = len(det.matched_fields or [])
        explanation = (
            f"Rule '{det.rule_title}' (Rule ID: {det.matched_rule}) fired with {det.severity.value.upper()} "
            f"severity ({int(det.confidence * 100)}% confidence). Exactly {matched_count} field patterns matched "
            f"the event criteria."
        )

        return DetectionEvidenceOut(
            detection_id=det.id,
            rule_id=det.matched_rule,
            rule_title=det.rule_title,
            severity=det.severity,
            confidence=det.confidence,
            matched_fields=det.matched_fields or [],
            rule_condition=str(rule_condition) if rule_condition else None,
            log_payload=log_payload,
            mitre_techniques=techniques,
            explanation=explanation,
        )

    def record_analyst_feedback(
        self, detection_id: uuid.UUID, verdict: str, note: str | None = None
    ) -> SigmaDetectionOut:
        """Record human analyst feedback / ground truth verdict for a detection."""
        det = self.sigma_detection_repository.get_by_id(detection_id)
        if not det:
            raise NotFoundError(f"Sigma detection '{detection_id}' not found.")

        clean_verdict = verdict.strip().upper()
        if clean_verdict not in ("TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_SUSPICIOUS"):
            raise ValidationFailedError(
                f"Invalid verdict '{verdict}'. Allowed: TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_SUSPICIOUS"
            )

        det.analyst_verdict = clean_verdict
        det.analyst_note = note
        self.sigma_detection_repository.db.commit()

        return SigmaDetectionOut(
            id=det.id,
            parsed_log_id=det.parsed_log_id,
            matched_rule=det.matched_rule,
            rule_title=det.rule_title,
            rule_category=det.rule_category,
            rule_tags=det.rule_tags,
            severity=det.severity,
            confidence=det.confidence,
            matched_fields=det.matched_fields,
            detection_timestamp=det.detection_timestamp,
            created_at=det.created_at,
            analyst_verdict=det.analyst_verdict,
            analyst_note=det.analyst_note,
        )

    def get_quality_metrics(self) -> DetectionQualityMetricsOut:
        """Compute detection quality, precision, and false-positive rates from analyst feedback."""
        db = self.sigma_detection_repository.db
        total = db.execute(select(func.count(SigmaDetection.id))).scalar_one()
        reviewed = db.execute(
            select(func.count(SigmaDetection.id)).where(SigmaDetection.analyst_verdict.is_not(None))
        ).scalar_one()

        tp = db.execute(
            select(func.count(SigmaDetection.id)).where(SigmaDetection.analyst_verdict == "TRUE_POSITIVE")
        ).scalar_one()
        fp = db.execute(
            select(func.count(SigmaDetection.id)).where(SigmaDetection.analyst_verdict == "FALSE_POSITIVE")
        ).scalar_one()
        bs = db.execute(
            select(func.count(SigmaDetection.id)).where(SigmaDetection.analyst_verdict == "BENIGN_SUSPICIOUS")
        ).scalar_one()

        tp_rate = round(tp / reviewed, 3) if reviewed > 0 else 0.0
        fp_rate = round(fp / reviewed, 3) if reviewed > 0 else 0.0
        accuracy = round((tp + bs) / reviewed, 3) if reviewed > 0 else 1.0

        return DetectionQualityMetricsOut(
            total_detections=total,
            reviewed_detections=reviewed,
            true_positives=tp,
            false_positives=fp,
            benign_suspicious=bs,
            tp_rate=tp_rate,
            fp_rate=fp_rate,
            accuracy=accuracy,
        )

    def get_analytics(self, requesting_user: User) -> DetectionAnalyticsOut:
        """Aggregate comprehensive detection analytics: rules, MITRE, endpoints, trends, quality."""
        stats = self.get_statistics(requesting_user)
        quality = self.get_quality_metrics()
        db = self.sigma_detection_repository.db

        # 1. Detections by endpoint (join with ParsedLog)
        ep_rows = db.execute(
            select(
                func.coalesce(ParsedLog.hostname, ParsedLog.source_ip, "unknown").label("endpoint"),
                func.count(SigmaDetection.id).label("count"),
            )
            .join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
            .group_by("endpoint")
            .order_by(func.count(SigmaDetection.id).desc())
            .limit(10)
        ).all()
        detections_by_endpoint = [{"endpoint": str(r[0]), "count": int(r[1])} for r in ep_rows]

        # 2. MITRE Techniques aggregated from rule_tags
        all_tags = db.execute(select(SigmaDetection.rule_tags)).scalars().all()
        tech_counts: dict[str, int] = {}
        for tag_list in all_tags:
            if tag_list:
                for tag in tag_list:
                    clean = tag.strip().lower()
                    if clean.startswith("attack.t"):
                        tid = clean.replace("attack.", "").upper()
                        tech_counts[tid] = tech_counts.get(tid, 0) + 1
                    elif clean.startswith("t1") or clean.startswith("t0"):
                        tid = clean.upper()
                        tech_counts[tid] = tech_counts.get(tid, 0) + 1

        top_mitre_techniques = [
            {"technique_id": tid, "name": f"MITRE {tid}", "count": count}
            for tid, count in sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # 3. Daily trend from recent detections
        recent_records = db.execute(
            select(SigmaDetection.detection_timestamp, SigmaDetection.severity)
            .order_by(SigmaDetection.detection_timestamp.desc())
            .limit(500)
        ).all()

        daily_buckets: dict[str, dict[str, Any]] = {}
        for ts, sev in recent_records:
            if not ts:
                continue
            date_str = ts.strftime("%Y-%m-%d")
            if date_str not in daily_buckets:
                daily_buckets[date_str] = {
                    "date": date_str,
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                }
            sev_str = sev.value.lower() if hasattr(sev, "value") else str(sev).lower()
            daily_buckets[date_str]["total"] += 1
            if sev_str in daily_buckets[date_str]:
                daily_buckets[date_str][sev_str] += 1

        daily_trend = sorted(daily_buckets.values(), key=lambda x: x["date"])

        return DetectionAnalyticsOut(
            total_detections=stats.total_detections,
            by_severity=stats.by_severity,
            by_category=stats.by_category,
            top_rules=stats.top_rules,
            top_mitre_techniques=top_mitre_techniques,
            detections_by_endpoint=detections_by_endpoint,
            daily_trend=daily_trend,
            quality_metrics=quality,
            average_confidence=stats.average_confidence,
            last_detection_at=stats.last_detection_at,
        )


