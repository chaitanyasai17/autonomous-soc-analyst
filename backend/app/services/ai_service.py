"""
AI Threat Analysis Service — orchestrates prompt building, provider dispatch, and safe fallback.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from app.ai.prompt_builder import SYSTEM_PROMPT, build_analysis_prompt
from app.ai.providers import HeuristicAIProvider, get_ai_provider
from app.config import get_settings
from app.core.exceptions import NotFoundError
from app.repositories.alert_repository import AlertRepository
from app.repositories.incident_repository import IncidentRepository
from app.repositories.parsed_log_repository import ParsedLogRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.sigma_detection_repository import SigmaDetectionRepository
from app.schemas.ai import AIProviderStatus, AIThreatAnalysisResponse

logger = logging.getLogger(__name__)


class AIService:
    def __init__(
        self,
        sigma_detection_repository: SigmaDetectionRepository,
        parsed_log_repository: ParsedLogRepository,
        alert_repository: Optional[AlertRepository] = None,
        incident_repository: Optional[IncidentRepository] = None,
        risk_repository: Optional[RiskRepository] = None,
    ):
        self.sigma_detection_repository = sigma_detection_repository
        self.parsed_log_repository = parsed_log_repository
        self.alert_repository = alert_repository
        self.incident_repository = incident_repository
        self.risk_repository = risk_repository
        self.provider = get_ai_provider()
        self.fallback_provider = HeuristicAIProvider()

    async def analyze_detection(self, detection_id: uuid.UUID) -> AIThreatAnalysisResponse:
        detection = self.sigma_detection_repository.get_by_id(detection_id)
        if not detection:
            raise NotFoundError(f"Sigma detection with ID '{detection_id}' not found.")

        parsed_log = self.parsed_log_repository.get_by_id(detection.parsed_log_id)
        context: Dict[str, Any] = {
            "rule_title": detection.rule_title,
            "rule_category": detection.rule_category,
            "severity": detection.severity.value if hasattr(detection.severity, "value") else str(detection.severity),
            "confidence": detection.confidence,
            "timestamp": str(detection.detection_timestamp),
            "mitre_tags": detection.rule_tags or [],
            "matched_fields": detection.matched_fields or [],
            "hostname": parsed_log.hostname if parsed_log else "N/A",
            "username": parsed_log.username if parsed_log else "N/A",
            "source_ip": parsed_log.source_ip if parsed_log else "N/A",
            "destination_ip": parsed_log.destination_ip if parsed_log else "N/A",
            "event_message": parsed_log.message if parsed_log else "N/A",
        }

        prompt = build_analysis_prompt(context)

        # Attempt with configured provider; fallback to heuristic if unavailable
        try:
            raw_result = await self.provider.generate_threat_analysis(
                prompt=prompt, system_prompt=SYSTEM_PROMPT, context=context
            )
        except Exception as exc:
            logger.warning(
                "Primary AI provider failed (%s), falling back to heuristic engine: %s",
                type(self.provider).__name__,
                exc,
            )
            raw_result = await self.fallback_provider.generate_threat_analysis(
                prompt=prompt, system_prompt=SYSTEM_PROMPT, context=context
            )

        return AIThreatAnalysisResponse(
            threat_summary=raw_result.get("threat_summary", "Threat analysis completed."),
            attack_narrative=raw_result.get("attack_narrative", ""),
            confidence=float(raw_result.get("confidence", 0.8)),
            false_positive_likelihood=raw_result.get("false_positive_likelihood", "medium"),
            false_positive_rationale=raw_result.get("false_positive_rationale"),
            recommended_actions=raw_result.get("recommended_actions", []),
            indicators_of_compromise=raw_result.get("indicators_of_compromise", []),
            mitre_alignment=raw_result.get("mitre_alignment", []),
            provider_used=raw_result.get("provider_used", "asoc-engine"),
        )

    async def analyze_alert(self, alert_id: uuid.UUID) -> AIThreatAnalysisResponse:
        """Run AI threat analysis specifically for one Alert."""
        if not self.alert_repository:
            raise NotFoundError("Alert repository is not configured.")
        alert = self.alert_repository.get_by_id(alert_id)
        if not alert:
            raise NotFoundError(f"Alert with ID '{alert_id}' not found.")

        rule_title = alert.title
        rule_category = "alert_investigation"
        severity = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        confidence = 0.85
        timestamp = str(alert.created_at)
        mitre_tags: list[str] = []
        matched_fields: list[Any] = []
        hostname = "N/A"
        username = "N/A"
        source_ip = "N/A"
        destination_ip = "N/A"
        event_message = alert.description or ""

        # Trace back to RiskAssessment -> SigmaDetection -> ParsedLog
        if alert.risk_assessment_id and self.risk_repository:
            ra = self.risk_repository.get_by_id(alert.risk_assessment_id)
            if ra:
                confidence = ra.confidence
                detection = self.sigma_detection_repository.get_by_id(ra.sigma_detection_id)
                if detection:
                    rule_title = detection.rule_title
                    rule_category = detection.rule_category or "threat_detection"
                    mitre_tags = detection.rule_tags or []
                    matched_fields = detection.matched_fields or []
                    parsed_log = self.parsed_log_repository.get_by_id(detection.parsed_log_id)
                    if parsed_log:
                        hostname = parsed_log.hostname or "N/A"
                        username = parsed_log.username or "N/A"
                        source_ip = parsed_log.source_ip or "N/A"
                        destination_ip = parsed_log.destination_ip or "N/A"
                        event_message = parsed_log.message or alert.description or ""

        context: Dict[str, Any] = {
            "rule_title": rule_title,
            "rule_category": rule_category,
            "severity": severity,
            "confidence": confidence,
            "timestamp": timestamp,
            "mitre_tags": mitre_tags,
            "matched_fields": matched_fields,
            "hostname": hostname,
            "username": username,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "event_message": event_message,
        }

        prompt = build_analysis_prompt(context)

        try:
            raw_result = await self.provider.generate_threat_analysis(
                prompt=prompt, system_prompt=SYSTEM_PROMPT, context=context
            )
        except Exception as exc:
            logger.warning("Primary AI provider failed on alert, fallback to heuristic: %s", exc)
            raw_result = await self.fallback_provider.generate_threat_analysis(
                prompt=prompt, system_prompt=SYSTEM_PROMPT, context=context
            )

        return AIThreatAnalysisResponse(
            threat_summary=raw_result.get("threat_summary", f"Threat analysis completed for alert {alert.title}."),
            attack_narrative=raw_result.get("attack_narrative", ""),
            confidence=float(raw_result.get("confidence", 0.85)),
            false_positive_likelihood=raw_result.get("false_positive_likelihood", "medium"),
            false_positive_rationale=raw_result.get("false_positive_rationale"),
            recommended_actions=raw_result.get("recommended_actions", []),
            indicators_of_compromise=raw_result.get("indicators_of_compromise", []),
            mitre_alignment=mitre_tags or raw_result.get("mitre_alignment", []),
            provider_used=raw_result.get("provider_used", "asoc-engine"),
        )

    async def analyze_incident(self, incident_id: uuid.UUID) -> AIThreatAnalysisResponse:
        """Run consolidated AI threat analysis & response playbook for an Incident."""
        if not self.incident_repository:
            raise NotFoundError("Incident repository is not configured.")
        incident = self.incident_repository.get_with_relations(incident_id)
        if not incident:
            raise NotFoundError(f"Incident with ID '{incident_id}' not found.")

        correlated_alerts = incident.alerts or []
        alert_titles = [a.title for a in correlated_alerts]
        all_mitre_tags: set[str] = set()
        all_hosts: set[str] = set()
        all_users: set[str] = set()
        all_src_ips: set[str] = set()
        all_dst_ips: set[str] = set()
        all_matched_fields: list[dict] = []
        messages: list[str] = []

        for a in correlated_alerts:
            if a.risk_assessment_id and self.risk_repository:
                ra = self.risk_repository.get_by_id(a.risk_assessment_id)
                if ra:
                    detection = self.sigma_detection_repository.get_by_id(ra.sigma_detection_id)
                    if detection:
                        for tag in (detection.rule_tags or []):
                            all_mitre_tags.add(tag)
                        for mf in (detection.matched_fields or []):
                            all_matched_fields.append(mf)
                        parsed = self.parsed_log_repository.get_by_id(detection.parsed_log_id)
                        if parsed:
                            if parsed.hostname:
                                all_hosts.add(parsed.hostname)
                            if parsed.username:
                                all_users.add(parsed.username)
                            if parsed.source_ip:
                                all_src_ips.add(parsed.source_ip)
                            if parsed.destination_ip:
                                all_dst_ips.add(parsed.destination_ip)
                            if parsed.message:
                                messages.append(parsed.message)

        host_str = ", ".join(all_hosts) if all_hosts else "N/A"
        user_str = ", ".join(all_users) if all_users else "N/A"
        src_ip_str = ", ".join(all_src_ips) if all_src_ips else "N/A"
        dst_ip_str = ", ".join(all_dst_ips) if all_dst_ips else "N/A"
        mitre_list = sorted(list(all_mitre_tags))

        severity_val = incident.priority.value if hasattr(incident.priority, "value") else str(incident.priority)
        context: Dict[str, Any] = {
            "rule_title": f"Consolidated Incident {incident.incident_number}: {len(correlated_alerts)} Correlated Threat(s)",
            "rule_category": "incident_investigation",
            "severity": severity_val,
            "confidence": 0.92 if len(correlated_alerts) > 1 else 0.85,
            "timestamp": str(incident.opened_at),
            "mitre_tags": mitre_list,
            "matched_fields": all_matched_fields[:10],
            "hostname": host_str,
            "username": user_str,
            "source_ip": src_ip_str,
            "destination_ip": dst_ip_str,
            "event_message": " | ".join(messages[:5]) if messages else f"Incident {incident.incident_number} containing: {', '.join(alert_titles)}",
        }

        prompt = build_analysis_prompt(context)

        try:
            raw_result = await self.provider.generate_threat_analysis(
                prompt=prompt, system_prompt=SYSTEM_PROMPT, context=context
            )
        except Exception as exc:
            logger.warning("Primary AI provider failed on incident, fallback to heuristic: %s", exc)
            raw_result = await self.fallback_provider.generate_threat_analysis(
                prompt=prompt, system_prompt=SYSTEM_PROMPT, context=context
            )

        summary = raw_result.get(
            "threat_summary",
            f"Consolidated analysis for Incident {incident.incident_number} grouping {len(correlated_alerts)} alert(s)."
        )
        if f"Incident {incident.incident_number}" not in summary:
            summary = f"[Incident {incident.incident_number}]: {summary}"

        # Ensure containment steps are tailored to incident assets
        recs = list(raw_result.get("recommended_actions", []))
        if host_str != "N/A" and not any(host_str in r for r in recs):
            recs.insert(0, f"Isolate compromised host endpoint(s): {host_str} from corporate vLAN.")
        if src_ip_str != "N/A" and not any(src_ip_str in r for r in recs):
            recs.insert(1, f"Apply perimeter firewall drop rule for external adversary source: {src_ip_str}.")
        if user_str != "N/A" and not any(user_str in r for r in recs):
            recs.insert(2, f"Revoke active authentication tokens and reset credentials for affected identity: {user_str}.")

        return AIThreatAnalysisResponse(
            threat_summary=summary,
            attack_narrative=raw_result.get("attack_narrative", f"Adversary activity observed in {incident.incident_number}."),
            confidence=float(raw_result.get("confidence", 0.9)),
            false_positive_likelihood=raw_result.get("false_positive_likelihood", "low" if len(correlated_alerts) > 1 else "medium"),
            false_positive_rationale=raw_result.get("false_positive_rationale"),
            recommended_actions=recs,
            indicators_of_compromise=raw_result.get("indicators_of_compromise", []),
            mitre_alignment=mitre_list or raw_result.get("mitre_alignment", []),
            provider_used=raw_result.get("provider_used", "asoc-engine"),
        )

    def get_status(self) -> AIProviderStatus:
        settings = get_settings()
        provider_name = (settings.AI_PROVIDER or "heuristic").lower()
        return AIProviderStatus(
            provider=provider_name,
            model=settings.OLLAMA_MODEL if provider_name == "ollama" else "asoc-cyber-rules",
            status="active",
            is_available=True,
            fallback_available=True,
            message="AI threat analysis engine is active and ready with resilient fallback.",
        )
