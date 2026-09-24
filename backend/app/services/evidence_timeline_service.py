"""EvidenceTimelineService — builds chronological investigation evidence from database facts."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.models.parsed_log import ParsedLog
from app.models.risk_assessment import RiskAssessment
from app.models.security_log import SecurityLog
from app.models.sigma_detection import SigmaDetection
from app.schemas.timeline import TimelineEntry, TimelineResponse

logger = logging.getLogger(__name__)


class EvidenceTimelineService:
    def __init__(self, db: Session):
        self.db = db

    def build_timeline(
        self,
        endpoint_id: Optional[uuid.UUID] = None,
        incident_id: Optional[uuid.UUID] = None,
        alert_id: Optional[uuid.UUID] = None,
        detection_id: Optional[uuid.UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 150,
    ) -> TimelineResponse:
        entries: List[TimelineEntry] = []

        # Scoping variables
        target_hostname: Optional[str] = None
        target_ip: Optional[str] = None
        scoped_alert_ids: set[uuid.UUID] = set()
        scoped_detection_ids: set[uuid.UUID] = set()
        scoped_event_ids: set[uuid.UUID] = set()

        # 1. Resolve Endpoint filter
        if endpoint_id:
            ep = self.db.get(Endpoint, endpoint_id)
            if ep:
                target_hostname = ep.hostname
                target_ip = ep.ip_address

        # 2. Resolve Incident filter
        if incident_id:
            inc = self.db.get(Incident, incident_id)
            if inc:
                alerts_for_inc = self.db.execute(
                    select(Alert).where(Alert.incident_id == inc.id)
                ).scalars().all()
                for a in alerts_for_inc:
                    scoped_alert_ids.add(a.id)
                    if a.risk_assessment_id:
                        ra = self.db.get(RiskAssessment, a.risk_assessment_id)
                        if ra:
                            scoped_detection_ids.add(ra.sigma_detection_id)
                            det = self.db.get(SigmaDetection, ra.sigma_detection_id)
                            if det:
                                scoped_event_ids.add(det.parsed_log_id)

        # 3. Resolve Alert filter
        if alert_id:
            a = self.db.get(Alert, alert_id)
            if a:
                scoped_alert_ids.add(a.id)
                if a.risk_assessment_id:
                    ra = self.db.get(RiskAssessment, a.risk_assessment_id)
                    if ra:
                        scoped_detection_ids.add(ra.sigma_detection_id)
                        det = self.db.get(SigmaDetection, ra.sigma_detection_id)
                        if det:
                            scoped_event_ids.add(det.parsed_log_id)

        # 4. Resolve Detection filter
        if detection_id:
            scoped_detection_ids.add(detection_id)
            det = self.db.get(SigmaDetection, detection_id)
            if det:
                scoped_event_ids.add(det.parsed_log_id)

        # --- QUERY DATABASE ENTITIES ---

        # 1. Security Logs (Ingestion)
        log_stmt = select(SecurityLog).order_by(SecurityLog.upload_time.desc()).limit(30)
        sec_logs = self.db.execute(log_stmt).scalars().all()
        for sl in sec_logs:
            if not scoped_event_ids:  # only include generic uploads when not strictly scoped to an event
                entries.append(
                    TimelineEntry(
                        id=f"LOG-{sl.id}",
                        timestamp=sl.upload_time,
                        stage="INGESTION",
                        event_type="telemetry_upload",
                        source=sl.log_source.value if hasattr(sl.log_source, "value") else str(sl.log_source),
                        object_id=str(sl.id),
                        severity="info",
                        description=f"Security telemetry file '{sl.original_filename}' ingested ({sl.file_size} bytes)",
                        details={"filename": sl.original_filename, "checksum": sl.checksum_sha256},
                    )
                )

        # 2. Parsed Logs (Normalization)
        parsed_stmt = select(ParsedLog).order_by(ParsedLog.timestamp.desc()).limit(80)
        if target_hostname:
            parsed_stmt = parsed_stmt.where(ParsedLog.hostname == target_hostname)
        elif target_ip:
            parsed_stmt = parsed_stmt.where(ParsedLog.source_ip == target_ip)
        elif scoped_event_ids:
            parsed_stmt = parsed_stmt.where(ParsedLog.id.in_(scoped_event_ids))

        parsed_events = self.db.execute(parsed_stmt).scalars().all()
        for pe in parsed_events:
            entries.append(
                TimelineEntry(
                    id=f"EVT-{pe.id}",
                    timestamp=pe.timestamp,
                    stage="NORMALIZATION",
                    event_type=pe.event_type,
                    source=pe.hostname or pe.source_ip or "telemetry",
                    object_id=str(pe.id),
                    severity=pe.severity.value if hasattr(pe.severity, "value") else str(pe.severity),
                    description=f"Event normalized: {pe.event_type} from {pe.source_ip or 'unknown'} (User: {pe.username or 'N/A'})",
                    related_endpoint=pe.hostname,
                    details={"message": pe.raw_log[:200] if pe.raw_log else None, "source_ip": pe.source_ip},
                )
            )

        # 3. Sigma Detections (Detection)
        det_stmt = select(SigmaDetection).order_by(SigmaDetection.detection_timestamp.desc()).limit(80)
        if scoped_detection_ids:
            det_stmt = det_stmt.where(SigmaDetection.id.in_(scoped_detection_ids))

        detections = self.db.execute(det_stmt).scalars().all()
        for dt in detections:
            # Check host link
            ep_name = dt.parsed_log.hostname if dt.parsed_log else None
            entries.append(
                TimelineEntry(
                    id=f"DET-{dt.id}",
                    timestamp=dt.detection_timestamp,
                    stage="DETECTION",
                    event_type="sigma_rule_match",
                    source=dt.matched_rule,
                    object_id=str(dt.id),
                    severity=dt.severity.value if hasattr(dt.severity, "value") else str(dt.severity),
                    description=f"Sigma rule matched: '{dt.rule_title}' (Confidence: {int(dt.confidence * 100)}%)",
                    related_endpoint=ep_name,
                    related_detection=dt.rule_title,
                    details={"tags": dt.rule_tags, "verdict": dt.analyst_verdict},
                )
            )

        # 4. Risk Assessments (Risk Calculation)
        risk_stmt = select(RiskAssessment).order_by(RiskAssessment.calculated_at.desc()).limit(80)
        if scoped_detection_ids:
            risk_stmt = risk_stmt.where(RiskAssessment.sigma_detection_id.in_(scoped_detection_ids))

        risks = self.db.execute(risk_stmt).scalars().all()
        for rk in risks:
            entries.append(
                TimelineEntry(
                    id=f"RSK-{rk.id}",
                    timestamp=rk.calculated_at,
                    stage="RISK",
                    event_type="risk_calculated",
                    source="risk_engine",
                    object_id=str(rk.id),
                    severity=rk.risk_level.value if hasattr(rk.risk_level, "value") else str(rk.risk_level),
                    description=f"Risk calculated: {rk.risk_score:.0f}/100 ({(rk.risk_level.value if hasattr(rk.risk_level, 'value') else str(rk.risk_level)).upper()})",
                    details={"score": rk.risk_score, "confidence": rk.confidence},
                )
            )

        # 5. Alerts (Alert Creation)
        alert_stmt = select(Alert).order_by(Alert.created_at.desc()).limit(60)
        if scoped_alert_ids:
            alert_stmt = alert_stmt.where(Alert.id.in_(scoped_alert_ids))

        alerts = self.db.execute(alert_stmt).scalars().all()
        for al in alerts:
            entries.append(
                TimelineEntry(
                    id=f"ALT-{al.id}",
                    timestamp=al.created_at,
                    stage="ALERT",
                    event_type="alert_created",
                    source="alert_engine",
                    object_id=str(al.id),
                    severity=al.severity.value if hasattr(al.severity, "value") else str(al.severity),
                    description=f"Alert created: '{al.title}' (Status: {al.status.value if hasattr(al.status, 'value') else al.status})",
                    related_alert=al.title,
                    details={"status": al.status.value if hasattr(al.status, "value") else str(al.status)},
                )
            )

        # 6. Incidents (Incident Creation & Containment)
        inc_stmt = select(Incident).order_by(Incident.opened_at.desc()).limit(30)
        if incident_id:
            inc_stmt = inc_stmt.where(Incident.id == incident_id)

        incidents = self.db.execute(inc_stmt).scalars().all()
        for inc in incidents:
            entries.append(
                TimelineEntry(
                    id=f"INC-{inc.id}",
                    timestamp=inc.opened_at,
                    stage="INCIDENT",
                    event_type="incident_opened",
                    source="incident_correlation",
                    object_id=str(inc.id),
                    severity=inc.priority.value if hasattr(inc.priority, "value") else str(inc.priority),
                    description=f"Incident opened: [{inc.incident_number}] (Priority: {inc.priority.value.upper() if hasattr(inc.priority, 'value') else inc.priority})",
                    related_incident=inc.incident_number,
                    details={"incident_number": inc.incident_number, "status": inc.status.value if hasattr(inc.status, "value") else str(inc.status)},
                )
            )

        # 7. Audited Actions (Containment, Feedback, Triage)
        audit_stmt = (
            select(AuditLog)
            .where(
                AuditLog.action.in_([
                    "ENDPOINT_ISOLATED",
                    "ENDPOINT_RECONNECTED",
                    "DETECTION_FEEDBACK",
                    "ALERT_STATUS_UPDATE",
                    "INCIDENT_STATUS_UPDATE",
                ])
            )
            .order_by(AuditLog.timestamp.desc())
            .limit(40)
        )
        audits = self.db.execute(audit_stmt).scalars().all()
        for au in audits:
            entries.append(
                TimelineEntry(
                    id=f"AUD-{au.id}",
                    timestamp=au.timestamp,
                    stage="CONTAINMENT" if "ISOLATED" in au.action else "TRIAGE",
                    event_type=au.action.lower(),
                    source=f"User @{au.username or 'system'}",
                    object_id=str(au.object_id or au.id),
                    severity="critical" if "ISOLATED" in au.action else "info",
                    description=f"Action: {au.action.replace('_', ' ')} on {au.object_type} by {au.username or 'system'}",
                    details=au.details or {},
                )
            )

        # Date Filtering if requested
        if start_date:
            entries = [e for e in entries if e.timestamp >= start_date]
        if end_date:
            entries = [e for e in entries if e.timestamp <= end_date]

        # Sort strictly chronologically (or reverse-chronologically)
        entries.sort(key=lambda x: x.timestamp, reverse=True)
        entries = entries[:limit]

        return TimelineResponse(
            total_events=len(entries),
            filter_applied={
                "endpoint_id": str(endpoint_id) if endpoint_id else None,
                "incident_id": str(incident_id) if incident_id else None,
                "alert_id": str(alert_id) if alert_id else None,
                "detection_id": str(detection_id) if detection_id else None,
            },
            timeline=entries,
        )
