"""
PipelineTraceService — Traces the complete provenance graph of security telemetry
and operations across the entire SOC pipeline:
Telemetry File -> Parsed Event -> Detection -> MITRE -> Risk -> Alert -> IOC -> Incident.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.ioc_record import IOCRecord
from app.models.parsed_log import ParsedLog
from app.models.risk_assessment import RiskAssessment
from app.models.security_log import SecurityLog
from app.models.sigma_detection import SigmaDetection
from app.models.web_security_finding import WebSecurityFinding
from app.models.web_security_scan import WebSecurityScan


class PipelineTraceService:
    def __init__(self, db: Session):
        self.db = db

    def trace(self, object_type: str, object_id: uuid.UUID) -> Dict[str, Any]:
        """
        Build the unified multi-stage trace for any given SOC object.
        Supported object types: 'log', 'event', 'detection', 'risk', 'alert', 'incident', 'scan'.
        """
        clean_type = object_type.strip().lower()

        security_log: Optional[SecurityLog] = None
        parsed_log: Optional[ParsedLog] = None
        detection: Optional[SigmaDetection] = None
        risk: Optional[RiskAssessment] = None
        alert: Optional[Alert] = None
        incident: Optional[Incident] = None
        scan: Optional[WebSecurityScan] = None
        finding: Optional[WebSecurityFinding] = None

        if clean_type in ("incident", "incidents"):
            incident = self.db.get(Incident, object_id)
            if not incident:
                raise NotFoundError(f"Incident '{object_id}' not found.")
            # Pick first related alert
            alert = self.db.execute(
                select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.created_at.desc())
            ).scalars().first()
            if alert:
                if alert.risk_assessment_id:
                    risk = self.db.get(RiskAssessment, alert.risk_assessment_id)
                    if risk:
                        detection = self.db.get(SigmaDetection, risk.sigma_detection_id)
                elif alert.web_finding_id:
                    finding = self.db.get(WebSecurityFinding, alert.web_finding_id)
                    if finding:
                        scan = self.db.get(WebSecurityScan, finding.scan_id)

        elif clean_type in ("alert", "alerts"):
            alert = self.db.get(Alert, object_id)
            if not alert:
                raise NotFoundError(f"Alert '{object_id}' not found.")
            if alert.incident_id:
                incident = self.db.get(Incident, alert.incident_id)
            if alert.risk_assessment_id:
                risk = self.db.get(RiskAssessment, alert.risk_assessment_id)
                if risk:
                    detection = self.db.get(SigmaDetection, risk.sigma_detection_id)
            elif alert.web_finding_id:
                finding = self.db.get(WebSecurityFinding, alert.web_finding_id)
                if finding:
                    scan = self.db.get(WebSecurityScan, finding.scan_id)

        elif clean_type in ("detection", "detections"):
            detection = self.db.get(SigmaDetection, object_id)
            if not detection:
                raise NotFoundError(f"Detection '{object_id}' not found.")
            risk = self.db.execute(
                select(RiskAssessment).where(RiskAssessment.sigma_detection_id == detection.id)
            ).scalars().first()
            if risk:
                alert = self.db.execute(
                    select(Alert).where(Alert.risk_assessment_id == risk.id).order_by(Alert.created_at.desc())
                ).scalars().first()
                if alert and alert.incident_id:
                    incident = self.db.get(Incident, alert.incident_id)

        elif clean_type in ("event", "parsed_log", "parsed_logs"):
            parsed_log = self.db.get(ParsedLog, object_id)
            if not parsed_log:
                raise NotFoundError(f"Parsed log event '{object_id}' not found.")
            detection = self.db.execute(
                select(SigmaDetection).where(SigmaDetection.parsed_log_id == parsed_log.id)
            ).scalars().first()
            if detection:
                risk = self.db.execute(
                    select(RiskAssessment).where(RiskAssessment.sigma_detection_id == detection.id)
                ).scalars().first()
                if risk:
                    alert = self.db.execute(
                        select(Alert).where(Alert.risk_assessment_id == risk.id)
                    ).scalars().first()
                    if alert and alert.incident_id:
                        incident = self.db.get(Incident, alert.incident_id)

        elif clean_type in ("log", "file", "security_log"):
            security_log = self.db.get(SecurityLog, object_id)
            if not security_log:
                raise NotFoundError(f"Security log file '{object_id}' not found.")
            parsed_log = self.db.execute(
                select(ParsedLog).where(ParsedLog.security_log_id == security_log.id).limit(1)
            ).scalars().first()
            if parsed_log:
                detection = self.db.execute(
                    select(SigmaDetection).where(SigmaDetection.parsed_log_id == parsed_log.id)
                ).scalars().first()
                if detection:
                    risk = self.db.execute(
                        select(RiskAssessment).where(RiskAssessment.sigma_detection_id == detection.id)
                    ).scalars().first()
                    if risk:
                        alert = self.db.execute(
                            select(Alert).where(Alert.risk_assessment_id == risk.id)
                        ).scalars().first()
                        if alert and alert.incident_id:
                            incident = self.db.get(Incident, alert.incident_id)

        elif clean_type in ("scan", "web_security_scan"):
            scan = self.db.get(WebSecurityScan, object_id)
            if not scan:
                raise NotFoundError(f"Web scan '{object_id}' not found.")
            finding = self.db.execute(
                select(WebSecurityFinding).where(WebSecurityFinding.scan_id == scan.id).limit(1)
            ).scalars().first()
            if finding:
                alert = self.db.execute(
                    select(Alert).where(Alert.web_finding_id == finding.id)
                ).scalars().first()
                if alert and alert.incident_id:
                    incident = self.db.get(Incident, alert.incident_id)

        # Connect backwards from detection to parsed_log and security_log
        if detection and not parsed_log:
            parsed_log = self.db.get(ParsedLog, detection.parsed_log_id)
        if parsed_log and not security_log:
            security_log = self.db.get(SecurityLog, parsed_log.security_log_id)

        # Risk assessment
        if detection and not risk:
            risk = self.db.execute(
                select(RiskAssessment).where(RiskAssessment.sigma_detection_id == detection.id)
            ).scalars().first()

        # Related IOCs
        iocs: List[Dict[str, Any]] = []
        if incident:
            ioc_records = self.db.execute(
                select(IOCRecord).where(IOCRecord.related_incident_id == incident.id)
            ).scalars().all()
            iocs.extend([{"type": i.ioc_type, "value": i.value, "confidence": i.confidence} for i in ioc_records])
        elif alert:
            ioc_records = self.db.execute(
                select(IOCRecord).where(IOCRecord.related_alert_id == alert.id)
            ).scalars().all()
            iocs.extend([{"type": i.ioc_type, "value": i.value, "confidence": i.confidence} for i in ioc_records])

        # Assemble pipeline stages
        stages: List[Dict[str, Any]] = []

        if security_log:
            stages.append({
                "stage": "INGESTION",
                "name": "Telemetry Ingestion",
                "status": "COMPLETED",
                "timestamp": security_log.upload_time.isoformat() if security_log.upload_time else None,
                "summary": f"Uploaded '{security_log.original_filename}' ({security_log.file_size} bytes)",
                "entity_id": str(security_log.id),
                "details": {
                    "filename": security_log.original_filename,
                    "sha256": security_log.checksum_sha256,
                    "event_count": security_log.event_count,
                    "status": security_log.processing_status.value if hasattr(security_log.processing_status, "value") else str(security_log.processing_status),
                },
            })
        elif scan:
            stages.append({
                "stage": "ASSESSMENT",
                "name": "Security Assessment Lab",
                "status": "COMPLETED",
                "timestamp": scan.started_at.isoformat() if scan.started_at else None,
                "summary": f"Scanned target '{scan.target_host}' ({scan.target_url})",
                "entity_id": str(scan.id),
                "details": {
                    "target_host": scan.target_host,
                    "resolved_ip": scan.resolved_ip,
                    "posture_score": scan.posture_score,
                    "findings_count": scan.findings_count,
                },
            })

        if parsed_log:
            stages.append({
                "stage": "PARSING",
                "name": "Log Normalization",
                "status": "COMPLETED",
                "timestamp": parsed_log.timestamp.isoformat() if parsed_log.timestamp else None,
                "summary": f"Normalized {parsed_log.event_type} event from {parsed_log.source_ip or 'unknown host'}",
                "entity_id": str(parsed_log.id),
                "details": {
                    "event_type": parsed_log.event_type,
                    "source_ip": parsed_log.source_ip,
                    "destination_ip": parsed_log.destination_ip,
                    "username": parsed_log.username,
                    "hostname": parsed_log.hostname,
                },
            })

        if detection:
            stages.append({
                "stage": "DETECTION",
                "name": "Sigma AST Detection",
                "status": "DETECTED",
                "timestamp": detection.detection_timestamp.isoformat() if detection.detection_timestamp else None,
                "summary": f"Matched Sigma rule '{detection.rule_title}' ({detection.severity.value.upper()})",
                "entity_id": str(detection.id),
                "details": {
                    "rule_id": detection.matched_rule,
                    "rule_title": detection.rule_title,
                    "severity": detection.severity.value if hasattr(detection.severity, "value") else str(detection.severity),
                    "confidence": detection.confidence,
                    "verdict": detection.analyst_verdict or "UNREVIEWED",
                    "tags": detection.rule_tags or [],
                },
            })
        elif finding:
            stages.append({
                "stage": "DETECTION",
                "name": "Security Finding",
                "status": "DISCOVERED",
                "timestamp": finding.created_at.isoformat() if finding.created_at else None,
                "summary": f"Identified finding '{finding.title}' ({finding.severity.value.upper()})",
                "entity_id": str(finding.id),
                "details": {
                    "title": finding.title,
                    "category": finding.category,
                    "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                    "cwe_id": finding.cwe_id,
                },
            })

        if risk:
            stages.append({
                "stage": "RISK_ASSESSMENT",
                "name": "Deterministic Risk Scoring",
                "status": "EVALUATED",
                "timestamp": risk.calculated_at.isoformat() if risk.calculated_at else None,
                "summary": f"Calculated risk score {risk.risk_score:.0f}/100 ({risk.risk_level.value.upper()})",
                "entity_id": str(risk.id),
                "details": {
                    "score": risk.risk_score,
                    "level": risk.risk_level.value if hasattr(risk.risk_level, "value") else str(risk.risk_level),
                    "confidence": risk.confidence,
                },
            })

        if alert:
            stages.append({
                "stage": "ALERT",
                "name": "SOC Alert Generated",
                "status": alert.status.value.upper() if hasattr(alert.status, "value") else str(alert.status).upper(),
                "timestamp": alert.created_at.isoformat() if alert.created_at else None,
                "summary": f"Raised alert '{alert.title}' ({alert.severity.value.upper()})",
                "entity_id": str(alert.id),
                "details": {
                    "title": alert.title,
                    "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                    "status": alert.status.value if hasattr(alert.status, "value") else str(alert.status),
                    "source": "sigma_detection" if alert.risk_assessment_id else ("web_security" if alert.web_finding_id else "manual"),
                },
            })

        if incident:
            stages.append({
                "stage": "INCIDENT",
                "name": "Incident Correlation & Response",
                "status": incident.status.value.upper() if hasattr(incident.status, "value") else str(incident.status).upper(),
                "timestamp": incident.opened_at.isoformat() if incident.opened_at else None,
                "summary": f"Active Incident [{incident.incident_number}] (Priority: {incident.priority.value.upper() if hasattr(incident.priority, 'value') else incident.priority})",
                "entity_id": str(incident.id),
                "details": {
                    "incident_number": incident.incident_number,
                    "priority": incident.priority.value if hasattr(incident.priority, "value") else str(incident.priority),
                    "status": incident.status.value if hasattr(incident.status, "value") else str(incident.status),
                    "assigned_to": incident.owner.username if getattr(incident, "owner", None) else None,
                    "is_contained": incident.status.value in ("contained", "resolved", "closed") if hasattr(incident.status, "value") else False,
                },
            })

        return {
            "queried_type": clean_type,
            "queried_id": str(object_id),
            "stages_count": len(stages),
            "stages": stages,
            "iocs": iocs,
            "provenance": {
                "has_telemetry_source": bool(security_log or scan),
                "has_normalized_event": bool(parsed_log),
                "has_detection": bool(detection or finding),
                "has_risk_assessment": bool(risk),
                "has_alert": bool(alert),
                "has_incident": bool(incident),
            },
        }
