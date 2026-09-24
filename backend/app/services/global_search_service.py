"""
GlobalSearchService — Fast multi-entity search across SOC intelligence,
telemetry, detections, alerts, incidents, IOCs, and MITRE techniques.
"""

from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.ioc_record import IOCRecord
from app.models.mitre_technique import MitreTechnique
from app.models.parsed_log import ParsedLog
from app.models.sigma_detection import SigmaDetection


class GlobalSearchService:
    def __init__(self, db: Session):
        self.db = db

    def search(self, query_str: str, limit_per_type: int = 5) -> Dict[str, Any]:
        term = query_str.strip()
        if not term:
            return {
                "query": "",
                "total_matches": 0,
                "categories": {},
            }

        pattern = f"%{term}%"
        results: Dict[str, List[Dict[str, Any]]] = {
            "incidents": [],
            "alerts": [],
            "detections": [],
            "iocs": [],
            "events": [],
            "mitre": [],
        }

        # 1. Incidents
        incidents = self.db.execute(
            select(Incident)
            .where(Incident.incident_number.ilike(pattern))
            .limit(limit_per_type)
        ).scalars().all()
        for inc in incidents:
            results["incidents"].append({
                "id": str(inc.id),
                "title": f"Incident {inc.incident_number}",
                "subtitle": f"Status: {inc.status.value if hasattr(inc.status, 'value') else inc.status} • Priority: {inc.priority.value if hasattr(inc.priority, 'value') else inc.priority}",
                "url": f"/incidents/{inc.id}",
                "type": "INCIDENT",
            })

        # 2. Alerts
        alerts = self.db.execute(
            select(Alert)
            .where(
                or_(
                    Alert.title.ilike(pattern),
                    Alert.description.ilike(pattern),
                )
            )
            .limit(limit_per_type)
        ).scalars().all()
        for alt in alerts:
            results["alerts"].append({
                "id": str(alt.id),
                "title": alt.title,
                "subtitle": f"Severity: {alt.severity.value if hasattr(alt.severity, 'value') else alt.severity} • Status: {alt.status.value if hasattr(alt.status, 'value') else alt.status}",
                "url": "/alerts",
                "type": "ALERT",
            })

        # 3. Detections
        detections = self.db.execute(
            select(SigmaDetection)
            .where(
                or_(
                    SigmaDetection.rule_title.ilike(pattern),
                    SigmaDetection.matched_rule.ilike(pattern),
                )
            )
            .limit(limit_per_type)
        ).scalars().all()
        for det in detections:
            results["detections"].append({
                "id": str(det.id),
                "title": det.rule_title,
                "subtitle": f"Rule: {det.matched_rule} • {det.severity.value.upper() if hasattr(det.severity, 'value') else det.severity}",
                "url": "/detections",
                "type": "DETECTION",
            })

        # 4. IOCs
        iocs = self.db.execute(
            select(IOCRecord)
            .where(
                or_(
                    IOCRecord.value.ilike(pattern),
                    IOCRecord.ioc_type.ilike(pattern),
                )
            )
            .limit(limit_per_type)
        ).scalars().all()
        for ioc in iocs:
            results["iocs"].append({
                "id": str(ioc.id),
                "title": ioc.value,
                "subtitle": f"Type: {ioc.ioc_type.upper()} • Source: {ioc.source}",
                "url": "/iocs",
                "type": "IOC",
            })

        # 5. MITRE Techniques
        techniques = self.db.execute(
            select(MitreTechnique)
            .where(
                or_(
                    MitreTechnique.technique_id.ilike(pattern),
                    MitreTechnique.technique_name.ilike(pattern),
                    MitreTechnique.tactic.ilike(pattern),
                )
            )
            .limit(limit_per_type)
        ).scalars().all()
        for t in techniques:
            results["mitre"].append({
                "id": str(t.id),
                "title": f"[{t.technique_id}] {t.technique_name}",
                "subtitle": f"Tactic: {t.tactic}",
                "url": "/mitre",
                "type": "MITRE",
            })

        # 6. Parsed Logs / Events
        events = self.db.execute(
            select(ParsedLog)
            .where(
                or_(
                    ParsedLog.source_ip.ilike(pattern),
                    ParsedLog.destination_ip.ilike(pattern),
                    ParsedLog.username.ilike(pattern),
                    ParsedLog.hostname.ilike(pattern),
                    ParsedLog.event_type.ilike(pattern),
                )
            )
            .limit(limit_per_type)
        ).scalars().all()
        for ev in events:
            results["events"].append({
                "id": str(ev.id),
                "title": f"{ev.event_type} - {ev.source_ip or ev.hostname or 'Event'}",
                "subtitle": f"User: {ev.username or 'N/A'} • Dest: {ev.destination_ip or 'N/A'}",
                "url": f"/logs/{ev.security_log_id}" if ev.security_log_id else "/logs",
                "type": "EVENT",
            })

        total = sum(len(v) for v in results.values())

        return {
            "query": term,
            "total_matches": total,
            "categories": results,
        }
