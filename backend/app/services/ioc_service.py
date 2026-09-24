"""IOC Service — manages Indicators of Compromise extraction, querying, and correlation (Part 9)."""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.alert import Alert
from app.models.endpoint import Endpoint
from app.models.enums import RiskLevel
from app.models.incident import Incident
from app.models.ioc_record import IOCRecord
from app.models.parsed_log import ParsedLog
from app.models.risk_assessment import RiskAssessment
from app.models.sigma_detection import SigmaDetection
from app.repositories.ioc_repository import IOCRepository

logger = logging.getLogger(__name__)

IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
URL_REGEX = re.compile(r"https?://[^\s<>\"']+")
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")


class IOCService:
    def __init__(self, ioc_repo: IOCRepository, db_session: Optional[Session] = None):
        self.ioc_repo = ioc_repo
        self.db = db_session or ioc_repo.session

    def extract_and_register_from_text(
        self,
        text: str,
        source: str,
        confidence: float = 0.8,
        related_alert_id: Optional[uuid.UUID] = None,
        related_incident_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
    ) -> List[IOCRecord]:
        """Extract IP addresses, domains, URLs, and hashes from text and upsert to repository."""
        if not text:
            return []

        created_or_updated: List[IOCRecord] = []

        # 1. Extract IPv4
        for ip in IPV4_REGEX.findall(text):
            if ip not in ("0.0.0.0", "255.255.255.255"):
                rec = self.ioc_repo.upsert_ioc(
                    ioc_type="ipv4",
                    value=ip,
                    source=source,
                    confidence=confidence,
                    related_alert_id=related_alert_id,
                    related_incident_id=related_incident_id,
                    tags=tags,
                )
                created_or_updated.append(rec)

        # 2. Extract IPv6
        for ip6 in IPV6_REGEX.findall(text):
            rec = self.ioc_repo.upsert_ioc(
                ioc_type="ipv6",
                value=ip6.lower(),
                source=source,
                confidence=confidence,
                related_alert_id=related_alert_id,
                related_incident_id=related_incident_id,
                tags=tags,
            )
            created_or_updated.append(rec)

        # 3. Extract SHA256
        for sha in SHA256_REGEX.findall(text):
            rec = self.ioc_repo.upsert_ioc(
                ioc_type="sha256",
                value=sha.lower(),
                source=source,
                confidence=confidence,
                related_alert_id=related_alert_id,
                related_incident_id=related_incident_id,
                tags=tags,
            )
            created_or_updated.append(rec)

        # 4. Extract SHA1
        for sha1 in SHA1_REGEX.findall(text):
            rec = self.ioc_repo.upsert_ioc(
                ioc_type="sha1",
                value=sha1.lower(),
                source=source,
                confidence=confidence,
                related_alert_id=related_alert_id,
                related_incident_id=related_incident_id,
                tags=tags,
            )
            created_or_updated.append(rec)

        # 5. Extract MD5 (excluding sha substrings)
        for md5 in MD5_REGEX.findall(text):
            rec = self.ioc_repo.upsert_ioc(
                ioc_type="md5",
                value=md5.lower(),
                source=source,
                confidence=confidence,
                related_alert_id=related_alert_id,
                related_incident_id=related_incident_id,
                tags=tags,
            )
            created_or_updated.append(rec)

        # 6. Extract URLs
        for url in URL_REGEX.findall(text):
            rec = self.ioc_repo.upsert_ioc(
                ioc_type="url",
                value=url,
                source=source,
                confidence=confidence,
                related_alert_id=related_alert_id,
                related_incident_id=related_incident_id,
                tags=tags,
            )
            created_or_updated.append(rec)

        # 7. Extract Domains
        for domain in DOMAIN_REGEX.findall(text):
            if domain.lower() not in ("localhost", "example.com", "schema.org", "corp.local"):
                rec = self.ioc_repo.upsert_ioc(
                    ioc_type="domain",
                    value=domain.lower(),
                    source=source,
                    confidence=confidence,
                    related_alert_id=related_alert_id,
                    related_incident_id=related_incident_id,
                    tags=tags,
                )
                created_or_updated.append(rec)

        # 8. Extract Emails
        for email in EMAIL_REGEX.findall(text):
            rec = self.ioc_repo.upsert_ioc(
                ioc_type="email",
                value=email.lower(),
                source=source,
                confidence=confidence,
                related_alert_id=related_alert_id,
                related_incident_id=related_incident_id,
                tags=tags,
            )
            created_or_updated.append(rec)

        return created_or_updated

    def register_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str,
        confidence: float = 1.0,
        description: Optional[str] = None,
        related_alert_id: Optional[uuid.UUID] = None,
        related_incident_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
    ) -> IOCRecord:
        return self.ioc_repo.upsert_ioc(
            ioc_type=ioc_type,
            value=value,
            source=source,
            confidence=confidence,
            description=description,
            related_alert_id=related_alert_id,
            related_incident_id=related_incident_id,
            tags=tags,
        )

    def extract_from_telemetry(self) -> int:
        """Scan parsed logs to populate indicators from real observations."""
        logs = self.db.execute(select(ParsedLog).limit(200)).scalars().all()
        extracted = 0
        for pl in logs:
            if pl.source_ip and pl.source_ip not in ("0.0.0.0", "127.0.0.1", "::1"):
                self.register_ioc(
                    ioc_type="ipv4" if "." in pl.source_ip else "ipv6",
                    value=pl.source_ip,
                    source="TELEMETRY_LOG",
                    confidence=0.85,
                )
                extracted += 1
            if pl.destination_ip and pl.destination_ip not in ("0.0.0.0", "127.0.0.1", "::1"):
                self.register_ioc(
                    ioc_type="ipv4" if "." in pl.destination_ip else "ipv6",
                    value=pl.destination_ip,
                    source="TELEMETRY_LOG",
                    confidence=0.85,
                )
                extracted += 1
            if pl.username and pl.username not in ("admin", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                self.register_ioc(
                    ioc_type="username",
                    value=pl.username,
                    source="TELEMETRY_LOG",
                    confidence=0.75,
                )
                extracted += 1
            if pl.hostname:
                self.register_ioc(
                    ioc_type="hostname",
                    value=pl.hostname,
                    source="TELEMETRY_LOG",
                    confidence=0.80,
                )
                extracted += 1
            if pl.raw_log:
                res = self.extract_and_register_from_text(pl.raw_log, source="LOG_PAYLOAD", confidence=0.7)
                extracted += len(res)
        return extracted

    def get_ioc_graph(self, ioc_id: uuid.UUID) -> Dict[str, Any]:
        ioc = self.ioc_repo.get_by_id(ioc_id)
        if not ioc:
            raise NotFoundError(f"IOC with ID '{ioc_id}' not found.")

        term = ioc.value.strip()

        # 1. Related Events
        event_cond = or_(
            ParsedLog.source_ip == term,
            ParsedLog.destination_ip == term,
            ParsedLog.username == term,
            ParsedLog.hostname == term,
            ParsedLog.raw_log.ilike(f"%{term}%"),
        )
        events_rows = self.db.execute(
            select(ParsedLog).where(event_cond).order_by(ParsedLog.timestamp.desc()).limit(30)
        ).scalars().all()
        events = [
            {
                "id": ev.id,
                "timestamp": ev.timestamp,
                "event_type": ev.event_type,
                "source_ip": ev.source_ip,
                "hostname": ev.hostname,
                "raw_snippet": ev.raw_log[:150] if ev.raw_log else None,
            }
            for ev in events_rows
        ]

        # 2. Detections
        det_rows = self.db.execute(
            select(SigmaDetection)
            .join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
            .where(event_cond)
            .order_by(SigmaDetection.detection_timestamp.desc())
            .limit(30)
        ).scalars().all()
        detections = [
            {
                "id": d.id,
                "rule_title": d.rule_title,
                "severity": d.severity.value if hasattr(d.severity, "value") else str(d.severity),
                "timestamp": d.detection_timestamp,
                "verdict": d.analyst_verdict,
            }
            for d in det_rows
        ]

        # 3. Alerts
        alert_rows = self.db.execute(
            select(Alert)
            .outerjoin(RiskAssessment, Alert.risk_assessment_id == RiskAssessment.id)
            .outerjoin(SigmaDetection, RiskAssessment.sigma_detection_id == SigmaDetection.id)
            .outerjoin(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
            .where(
                or_(
                    Alert.id == ioc.related_alert_id,
                    event_cond,
                )
            )
            .order_by(Alert.created_at.desc())
            .limit(30)
        ).scalars().all()
        alerts = [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
                "status": a.status.value if hasattr(a.status, "value") else str(a.status),
                "created_at": a.created_at,
            }
            for a in alert_rows
        ]

        # 4. Incidents
        incident_ids = {a.incident_id for a in alert_rows if a.incident_id}
        if ioc.related_incident_id:
            incident_ids.add(ioc.related_incident_id)
        incidents = []
        if incident_ids:
            inc_rows = self.db.execute(
                select(Incident).where(Incident.id.in_(incident_ids)).order_by(Incident.opened_at.desc())
            ).scalars().all()
            incidents = [
                {
                    "id": inc.id,
                    "incident_number": inc.incident_number,
                    "priority": inc.priority.value if hasattr(inc.priority, "value") else str(inc.priority),
                    "status": inc.status.value if hasattr(inc.status, "value") else str(inc.status),
                    "opened_at": inc.opened_at,
                }
                for inc in inc_rows
            ]

        # 5. Endpoints
        ep_rows = self.db.execute(
            select(Endpoint).where(
                or_(Endpoint.ip_address == term, Endpoint.hostname == term)
            )
        ).scalars().all()
        endpoints = [
            {
                "id": ep.id,
                "hostname": ep.hostname,
                "ip_address": ep.ip_address,
                "status": ep.status,
                "risk_level": ep.risk_level.value if hasattr(ep.risk_level, "value") else str(ep.risk_level),
            }
            for ep in ep_rows
        ]

        # Classification & Risk calculation
        occurrences = max(1, len(events))
        has_malicious_detection = any(
            (d.get("verdict") == "TRUE_POSITIVE" or d.get("severity") in ("CRITICAL", "critical"))
            for d in detections
        )
        has_critical_alert = any(a.get("severity") in ("CRITICAL", "critical", "HIGH", "high") for a in alerts)
        has_incident = len(incidents) > 0

        if has_malicious_detection or has_incident:
            classification = "Confirmed Malicious"
            risk_level = "critical"
        elif len(detections) > 0 or has_critical_alert:
            classification = "Suspicious"
            risk_level = "high"
        elif occurrences >= 5:
            classification = "Observed"
            risk_level = "medium"
        else:
            classification = "Observed"
            risk_level = "low"

        ioc_dict = {
            "id": ioc.id,
            "ioc_type": ioc.ioc_type,
            "value": ioc.value,
            "source": ioc.source,
            "confidence": ioc.confidence,
            "first_seen": ioc.first_seen,
            "last_seen": ioc.last_seen,
            "related_alert_id": ioc.related_alert_id,
            "related_incident_id": ioc.related_incident_id,
            "description": ioc.description,
            "tags": ioc.tags,
            "classification": classification,
            "occurrences": occurrences,
            "risk_level": risk_level,
            "related_detections_count": len(detections),
            "related_alerts_count": len(alerts),
            "related_incidents_count": len(incidents),
        }

        return {
            "ioc": ioc_dict,
            "events": events,
            "detections": detections,
            "alerts": alerts,
            "incidents": incidents,
            "endpoints": endpoints,
        }

    def list_iocs_enriched(
        self,
        ioc_type: Optional[str] = None,
        source: Optional[str] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        total_in_db = self.db.execute(select(func.count(IOCRecord.id))).scalar_one()
        if total_in_db < 5:
            self.extract_from_telemetry()

        raw_items, total = self.ioc_repo.list_iocs(
            ioc_type=ioc_type,
            source=source,
            search=search,
            skip=skip,
            limit=limit,
        )

        results: List[Dict[str, Any]] = []
        for item in raw_items:
            # Check links
            det_count = 0
            if item.related_alert_id:
                det_count = 1
            inc_count = 1 if item.related_incident_id else 0

            # Count occurrences in parsed logs
            term = item.value
            event_count = self.db.execute(
                select(func.count(ParsedLog.id)).where(
                    or_(
                        ParsedLog.source_ip == term,
                        ParsedLog.destination_ip == term,
                        ParsedLog.username == term,
                        ParsedLog.hostname == term,
                    )
                )
            ).scalar_one()
            occurrences = max(1, event_count)

            if inc_count > 0 or item.source == "WEB_SECURITY_ALERT":
                classification = "Confirmed Malicious"
                risk = "critical"
            elif det_count > 0 or item.source == "SIGMA_DETECTION":
                classification = "Suspicious"
                risk = "high"
            elif occurrences >= 5:
                classification = "Observed"
                risk = "medium"
            else:
                classification = "Observed"
                risk = "low"

            results.append({
                "id": item.id,
                "ioc_type": item.ioc_type,
                "value": item.value,
                "source": item.source,
                "confidence": item.confidence,
                "first_seen": item.first_seen,
                "last_seen": item.last_seen,
                "related_alert_id": item.related_alert_id,
                "related_incident_id": item.related_incident_id,
                "description": item.description,
                "tags": item.tags,
                "classification": classification,
                "occurrences": occurrences,
                "risk_level": risk,
                "related_detections_count": det_count,
                "related_alerts_count": 1 if item.related_alert_id else 0,
                "related_incidents_count": inc_count,
            })

        return results, total

    def get_statistics(self) -> Dict[str, Any]:
        stats = self.ioc_repo.get_statistics()
        # Enrich with classification counts
        classes = {"Observed": 0, "Suspicious": 0, "Confirmed Malicious": 0}
        total_items, _ = self.list_iocs_enriched(limit=500)
        for it in total_items:
            c = it.get("classification", "Observed")
            classes[c] = classes.get(c, 0) + 1
        stats["by_classification"] = classes
        return stats

    def get_ioc(self, ioc_id: uuid.UUID) -> Optional[IOCRecord]:
        return self.ioc_repo.get_by_id(ioc_id)

    def list_iocs(
        self,
        ioc_type: Optional[str] = None,
        source: Optional[str] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[Sequence[IOCRecord], int]:
        return self.ioc_repo.list_iocs(
            ioc_type=ioc_type,
            source=source,
            search=search,
            skip=skip,
            limit=limit,
        )
