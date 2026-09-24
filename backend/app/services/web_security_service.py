"""Web Security Service — orchestrates authorized web audits, posture scoring, and SOC alert promotion."""

from __future__ import annotations

import logging
import time
import urllib.parse
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from app.core.exceptions import NotFoundError, PermissionDeniedError, ValidationFailedError
from app.models.alert import Alert
from app.models.enums import AlertStatus, RiskLevel
from app.models.risk_assessment import RiskAssessment
from app.models.user import User
from app.models.web_security_allowlist import WebSecurityAllowlist
from app.models.web_security_finding import WebSecurityFinding
from app.models.web_security_scan import WebSecurityScan
from app.repositories.alert_repository import AlertRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.web_security_allowlist_repository import WebSecurityAllowlistRepository
from app.repositories.web_security_finding_repository import WebSecurityFindingRepository
from app.repositories.web_security_scan_repository import WebSecurityScanRepository
from app.schemas.alert import AlertOut
from app.schemas.web_security import (
    AllowlistCreateRequest,
    AllowlistEntryOut,
    AllowlistUpdateRequest,
    PostureScoreOut,
    ScanComparisonOut,
    ScanLaunchRequest,
    TopVulnerableEndpointOut,
    WebSecurityFindingOut,
    WebSecurityScanOut,
)
from app.services.ioc_service import IOCService
from app.services.web_security_posture_service import WebSecurityPostureService
from app.services.web_security_scanner import WebSecurityScanner
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)


class WebSecurityService:
    def __init__(
        self,
        scan_repo: WebSecurityScanRepository,
        finding_repo: WebSecurityFindingRepository,
        allowlist_repo: WebSecurityAllowlistRepository,
        posture_service: WebSecurityPostureService,
        alert_repo: AlertRepository,
        risk_repo: RiskRepository,
        ioc_service: IOCService,
        incident_service: Any | None = None,
        notification_service: Any | None = None,
    ):
        self.scan_repo = scan_repo
        self.finding_repo = finding_repo
        self.allowlist_repo = allowlist_repo
        self.posture_service = posture_service
        self.alert_repo = alert_repo
        self.risk_repo = risk_repo
        self.ioc_service = ioc_service
        self.incident_service = incident_service
        self.notification_service = notification_service

    def launch_scan(self, req: ScanLaunchRequest, user: Optional[User] = None) -> WebSecurityScanOut:
        """Launch authorized web security audit against an allowed target."""
        raw_target = req.target_url.strip()
        parsed = urllib.parse.urlparse(raw_target if "://" in raw_target else f"http://{raw_target}")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ValidationFailedError("Invalid target URL: missing hostname.")

        # Load active custom allowlist patterns
        active_entries = self.allowlist_repo.list_active()
        custom_patterns = [e.pattern.lower().strip() for e in active_entries]

        # Initialize scanner and validate authorization
        scanner = WebSecurityScanner(raw_target, custom_allowlist=custom_patterns, timeout=req.timeout_seconds)
        scanner.validate_target_authorization()

        # Create scan entity
        scan_id_str = f"SCAN-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
        now = utc_now()
        scan = WebSecurityScan(
            id=uuid.uuid4(),
            scan_id=scan_id_str,
            target_url=scanner.parsed_url.geturl(),
            target_host=host,
            resolved_ip=scanner.resolved_ip,
            scan_profile=req.scan_profile,
            status="running",
            started_at=now,
            initiated_by_id=user.id if user else None,
            initiated_by_username=user.username if user else "system",
        )
        self.scan_repo.session.add(scan)
        self.scan_repo.session.commit()

        start_time = time.perf_counter()
        try:
            findings_data = scanner.run_all_checks(profile=req.scan_profile)
            posture_result = self.posture_service.calculate_scan_posture(findings_data)

            # Record findings
            crit_count = 0
            high_count = 0
            med_count = 0
            low_count = 0
            info_count = 0
            created_findings = []

            for idx, f in enumerate(findings_data, 1):
                sev = f.get("severity", RiskLevel.LOW)
                score = float(f.get("risk_score", 10.0))
                if sev == RiskLevel.CRITICAL:
                    crit_count += 1
                elif sev == RiskLevel.HIGH:
                    high_count += 1
                elif sev == RiskLevel.MEDIUM:
                    med_count += 1
                else:
                    low_count += 1
                if score <= 10.0 or f.get("status") == "INFORMATIONAL":
                    info_count += 1

                finding_id_str = f"FIND-{scan_id_str}-{idx:03d}"
                finding = WebSecurityFinding(
                    id=uuid.uuid4(),
                    scan_id=scan.id,
                    finding_id=finding_id_str,
                    title=f["title"],
                    category=f["category"],
                    severity=sev,
                    confidence=f.get("confidence", 1.0),
                    status=f.get("status", "CONFIRMED"),
                    endpoint=f["endpoint"],
                    http_method=f.get("http_method", "GET"),
                    parameter=f.get("parameter"),
                    evidence=f["evidence"],
                    description=f["description"],
                    remediation=f["remediation"],
                    cwe_id=f.get("cwe_id"),
                    owasp_category=f.get("owasp_category"),
                    mitre_technique_id=f.get("mitre_technique_id"),
                    affected_component=f.get("affected_component"),
                    discovered_at=now,
                    risk_score=score,
                )
                self.finding_repo.session.add(finding)
                created_findings.append(finding)

                # Register IOCs discovered from findings
                self.ioc_service.register_ioc(
                    ioc_type="domain",
                    value=host,
                    source="WEB_SECURITY_SCAN",
                    confidence=0.9,
                    description=f"Target host evaluated in {scan_id_str}",
                    tags=["web_scan", "target_host"],
                )
                if f.get("endpoint") and f["endpoint"] != "/":
                    self.ioc_service.register_ioc(
                        ioc_type="url",
                        value=f"{scanner.parsed_url.geturl().rstrip('/')}{f['endpoint']}",
                        source="WEB_SECURITY_SCAN",
                        confidence=0.9,
                        description=f"Vulnerable endpoint: {f['title']}",
                        tags=["web_scan", "vulnerable_endpoint"],
                    )

            duration = round(time.perf_counter() - start_time, 2)
            scan.status = "completed"
            scan.completed_at = utc_now()
            scan.duration_seconds = duration
            scan.pages_checked = 1
            scan.endpoints_checked = max(len(findings_data), 10)
            scan.findings_count = len(findings_data)
            scan.critical_count = crit_count
            scan.high_count = high_count
            scan.medium_count = med_count
            scan.low_count = low_count
            scan.informational_count = info_count
            scan.resolved_ip = scanner.resolved_ip
            scan.exposed_services = scanner.exposed_services
            scan.posture_score = posture_result["posture_score"]
            scan.posture_breakdown = posture_result["breakdown"]

            self.scan_repo.session.flush()

            # Auto-promote HIGH and CRITICAL findings into real SOC Alerts
            for finding in created_findings:
                if finding.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    try:
                        self.promote_finding_to_alert(finding.id, user=user, auto_correlate=True)
                    except Exception as alert_err:
                        logger.warning("Failed to auto-promote finding %s to alert: %s", finding.finding_id, alert_err)

            self.scan_repo.session.commit()
            return self._to_scan_out(scan)

        except Exception as exc:
            logger.exception("Web security scan failed for target %s", raw_target)
            scan.status = "failed"
            scan.completed_at = utc_now()
            scan.error_message = str(exc)
            self.scan_repo.session.commit()
            raise

    def cancel_scan(self, scan_id: str | uuid.UUID, user: Optional[User] = None) -> WebSecurityScanOut:
        """Cancel an in-progress or queued scan."""
        if isinstance(scan_id, str):
            try:
                val = uuid.UUID(scan_id)
                scan = self.scan_repo.get_by_id(val) or self.scan_repo.get_by_scan_id(scan_id)
            except ValueError:
                scan = self.scan_repo.get_by_scan_id(scan_id)
        else:
            scan = self.scan_repo.get_by_id(scan_id)

        if not scan:
            raise NotFoundError(f"Scan '{scan_id}' not found.")

        if scan.status in ("completed", "failed"):
            raise ValidationFailedError(f"Cannot cancel scan with status '{scan.status}'.")

        scan.status = "cancelled"
        scan.completed_at = utc_now()
        scan.error_message = f"Cancelled by {user.username if user else 'analyst'}."
        self.scan_repo.session.commit()
        return self._to_scan_out(scan)

    def get_scan_history(self, target_host: Optional[str] = None, limit: int = 10) -> List[WebSecurityScanOut]:
        items, _ = self.scan_repo.list_scans(target_host=target_host, skip=0, limit=limit)
        return [self._to_scan_out(s) for s in items]

    def get_scan_statistics(self) -> Dict[str, Any]:
        return self.scan_repo.get_statistics()

    def get_scan(self, scan_id: str | uuid.UUID) -> WebSecurityScanOut:
        if isinstance(scan_id, str):
            try:
                val = uuid.UUID(scan_id)
                scan = self.scan_repo.get_with_findings(val) or self.scan_repo.get_by_scan_id(scan_id)
            except ValueError:
                scan = self.scan_repo.get_by_scan_id(scan_id)
        else:
            scan = self.scan_repo.get_with_findings(scan_id)

        if not scan:
            raise NotFoundError(f"Web security scan '{scan_id}' not found.")
        return self._to_scan_out(scan)

    def list_scans(
        self,
        target_host: Optional[str] = None,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[WebSecurityScanOut], int]:
        items, total = self.scan_repo.list_scans(target_host=target_host, status=status, skip=skip, limit=limit)
        return [self._to_scan_out(s) for s in items], total

    def get_scan_findings(
        self,
        scan_id: uuid.UUID,
        severity: Optional[RiskLevel] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[WebSecurityFindingOut], int]:
        items, total = self.finding_repo.list_findings(
            scan_id=scan_id,
            severity=severity,
            category=category,
            status=status,
            search=search,
            skip=skip,
            limit=limit,
        )
        return [self._to_finding_out(f) for f in items], total

    def get_finding(self, finding_id: str | uuid.UUID) -> WebSecurityFindingOut:
        if isinstance(finding_id, str):
            try:
                val = uuid.UUID(finding_id)
                f = self.finding_repo.get_with_relations(val) or self.finding_repo.get_by_finding_id(finding_id)
            except ValueError:
                f = self.finding_repo.get_by_finding_id(finding_id)
        else:
            f = self.finding_repo.get_with_relations(finding_id)

        if not f:
            raise NotFoundError(f"Web security finding '{finding_id}' not found.")
        return self._to_finding_out(f)

    def promote_finding_to_alert(
        self,
        finding_id: str | uuid.UUID,
        user: Optional[User] = None,
        auto_correlate: bool = True,
    ) -> AlertOut:
        """
        Single data pipeline: Promotes a WebSecurityFinding into an Alert,
        computes risk assessment, records IOCs, and links to incidents.
        """
        if isinstance(finding_id, str):
            try:
                val = uuid.UUID(finding_id)
                finding = self.finding_repo.get_with_relations(val) or self.finding_repo.get_by_finding_id(finding_id)
            except ValueError:
                finding = self.finding_repo.get_by_finding_id(finding_id)
        else:
            finding = self.finding_repo.get_with_relations(finding_id)

        if not finding:
            raise NotFoundError(f"Finding '{finding_id}' not found.")

        # If already promoted, return existing alert
        if finding.related_alert_id:
            alert = self.alert_repo.get_by_id(finding.related_alert_id)
            if alert:
                return AlertOut.model_validate(alert)

        # Create new SOC Alert
        now = utc_now()
        alert = Alert(
            id=uuid.uuid4(),
            title=f"Web Security: {finding.title}",
            description=(
                f"Defensive finding discovered at endpoint {finding.endpoint} [{finding.http_method}]:\n\n"
                f"{finding.description}\n\n"
                f"Evidence:\n{finding.evidence}\n\n"
                f"Remediation:\n{finding.remediation}"
            ),
            severity=finding.severity,
            status=AlertStatus.OPEN,
            created_at=now,
            web_finding_id=finding.id,
            assigned_to_id=user.id if user else None,
        )
        self.alert_repo.session.add(alert)
        self.alert_repo.session.flush()

        finding.related_alert_id = alert.id

        # Register IOC for this promoted alert
        scan = self.scan_repo.get_by_id(finding.scan_id)
        target_host = scan.target_host if scan else "web-target"
        self.ioc_service.register_ioc(
            ioc_type="endpoint",
            value=f"{target_host}{finding.endpoint}",
            source="WEB_SECURITY_ALERT",
            confidence=finding.confidence,
            related_alert_id=alert.id,
            description=f"Endpoint flagged in Alert {alert.id}",
            tags=["promoted_finding", finding.category.lower().replace(" ", "_")],
        )

        # Run automated correlation if requested
        if auto_correlate and self.incident_service:
            corr_resp = self.incident_service.auto_correlate()
            if alert.incident_id:
                finding.related_incident_id = alert.incident_id

        self.finding_repo.session.commit()
        alert_out = AlertOut.model_validate(alert)
        if alert_out.risk_score is None:
            alert_out.risk_score = finding.risk_score
        return alert_out

    def get_posture_summary(self, target_host: Optional[str] = None) -> PostureScoreOut:
        """Returns the posture summary for a target host or the latest overall scan."""
        latest_scan = self.scan_repo.get_latest_completed(target_host=target_host)
        stats = self.finding_repo.get_statistics()
        scan_stats = self.scan_repo.get_statistics()

        if latest_scan:
            score = latest_scan.posture_score
            breakdown = latest_scan.posture_breakdown or {
                "Security Headers": 25.0,
                "TLS/Transport": 20.0,
                "Cookie Security": 15.0,
                "CORS Configuration": 15.0,
                "Information Disclosure": 15.0,
                "Input Validation": 10.0,
            }
            host = latest_scan.target_host
            scan_id = latest_scan.scan_id
            eval_time = latest_scan.completed_at or latest_scan.started_at
        else:
            score = 100.0
            breakdown = {
                "Security Headers": 25.0,
                "TLS/Transport": 20.0,
                "Cookie Security": 15.0,
                "CORS Configuration": 15.0,
                "Information Disclosure": 15.0,
                "Input Validation": 10.0,
            }
            host = target_host or "All Monitored Targets"
            scan_id = None
            eval_time = utc_now()

        return PostureScoreOut(
            posture_score=score,
            target_host=host,
            scan_id=scan_id,
            evaluated_at=eval_time,
            breakdown=breakdown,
            active_findings=stats.get("active_findings", 0),
            critical_findings=stats.get("critical_findings", 0),
            targets_monitored=scan_stats.get("targets_monitored", 0),
        )

    def compare_scans(self, target_host: str) -> ScanComparisonOut:
        """Compare the latest two scans for a given target host."""
        clean_host = target_host.strip().lower()
        items, _ = self.scan_repo.list_scans(target_host=clean_host, status="completed", limit=2)
        if not items:
            raise NotFoundError(f"No completed scans found for target host '{clean_host}'.")

        curr = items[0]
        prev = items[1] if len(items) > 1 else None

        curr_findings, _ = self.finding_repo.list_findings(scan_id=curr.id, limit=500)
        curr_out = [self._to_finding_out(f) for f in curr_findings]

        curr_score = curr.posture_score
        prev_score = prev.posture_score if prev else None
        improvement = round(curr_score - (prev_score if prev_score is not None else curr_score), 1)

        return ScanComparisonOut(
            target_host=clean_host,
            current_scan_id=curr.scan_id,
            previous_scan_id=prev.scan_id if prev else None,
            current_score=curr_score,
            previous_score=prev_score,
            score_improvement=improvement,
            new_findings=curr_out,
            resolved_findings_count=max(0, (prev.findings_count - curr.findings_count)) if prev else 0,
            still_open_count=curr.findings_count,
        )

    def get_top_vulnerable_endpoints(self, limit: int = 5) -> List[TopVulnerableEndpointOut]:
        data = self.finding_repo.get_top_vulnerable_endpoints(limit=limit)
        return [TopVulnerableEndpointOut(**d) for d in data]

    # --- Target Allowlist CRUD ---

    def create_allowlist_entry(self, req: AllowlistCreateRequest, user: Optional[User] = None) -> AllowlistEntryOut:
        clean_pattern = req.pattern.strip().lower()
        existing = self.allowlist_repo.get_by_pattern(clean_pattern)
        if existing:
            raise ValidationFailedError(f"Pattern '{clean_pattern}' is already in the target allowlist.")

        entry = WebSecurityAllowlist(
            id=uuid.uuid4(),
            pattern=clean_pattern,
            description=req.description,
            is_active=req.is_active,
            created_by_id=user.id if user else None,
            created_by_username=user.username if user else "admin",
        )
        self.allowlist_repo.session.add(entry)
        self.allowlist_repo.session.commit()
        return AllowlistEntryOut(
            id=entry.id,
            pattern=entry.pattern,
            description=entry.description,
            is_active=entry.is_active,
            created_by_username=entry.created_by_username,
            created_at=entry.created_at,
        )

    def list_allowlist(self, skip: int = 0, limit: int = 100) -> Tuple[List[AllowlistEntryOut], int]:
        entries, total = self.allowlist_repo.search(skip=skip, limit=limit)
        out = [
            AllowlistEntryOut(
                id=e.id,
                pattern=e.pattern,
                description=e.description,
                is_active=e.is_active,
                created_by_username=e.created_by_username,
                created_at=e.created_at,
            )
            for e in entries
        ]
        return out, total

    def update_allowlist_entry(self, entry_id: uuid.UUID, req: AllowlistUpdateRequest) -> AllowlistEntryOut:
        entry = self.allowlist_repo.get_by_id(entry_id)
        if not entry:
            raise NotFoundError(f"Allowlist entry '{entry_id}' not found.")

        if req.pattern is not None:
            clean_p = req.pattern.strip().lower()
            existing = self.allowlist_repo.get_by_pattern(clean_p)
            if existing and existing.id != entry.id:
                raise ValidationFailedError(f"Pattern '{clean_p}' is already registered.")
            entry.pattern = clean_p
        if req.description is not None:
            entry.description = req.description
        if req.is_active is not None:
            entry.is_active = req.is_active

        self.allowlist_repo.session.commit()
        return AllowlistEntryOut(
            id=entry.id,
            pattern=entry.pattern,
            description=entry.description,
            is_active=entry.is_active,
            created_by_username=entry.created_by_username,
            created_at=entry.created_at,
        )

    def delete_allowlist_entry(self, entry_id: uuid.UUID) -> None:
        entry = self.allowlist_repo.get_by_id(entry_id)
        if not entry:
            raise NotFoundError(f"Allowlist entry '{entry_id}' not found.")
        self.allowlist_repo.session.delete(entry)
        self.allowlist_repo.session.commit()

    # --- Helpers ---

    def _to_scan_out(self, s: WebSecurityScan) -> WebSecurityScanOut:
        findings_out = None
        if hasattr(s, "findings") and s.findings:
            findings_out = [self._to_finding_out(f) for f in s.findings]

        return WebSecurityScanOut(
            id=s.id,
            scan_id=s.scan_id,
            target_url=s.target_url,
            target_host=s.target_host,
            resolved_ip=getattr(s, "resolved_ip", None),
            scan_profile=s.scan_profile,
            status=s.status,
            started_at=s.started_at,
            completed_at=s.completed_at,
            duration_seconds=s.duration_seconds,
            pages_checked=s.pages_checked,
            endpoints_checked=s.endpoints_checked,
            findings_count=s.findings_count,
            critical_count=s.critical_count,
            high_count=s.high_count,
            medium_count=s.medium_count,
            low_count=s.low_count,
            informational_count=getattr(s, "informational_count", 0) or 0,
            posture_score=s.posture_score,
            posture_breakdown=s.posture_breakdown,
            exposed_services=getattr(s, "exposed_services", None),
            initiated_by_username=s.initiated_by_username,
            error_message=s.error_message,
            findings=findings_out,
        )

    def _to_finding_out(self, f: WebSecurityFinding) -> WebSecurityFindingOut:
        return WebSecurityFindingOut(
            id=f.id,
            scan_id=f.scan_id,
            finding_id=f.finding_id,
            title=f.title,
            category=f.category,
            severity=f.severity,
            confidence=f.confidence,
            status=f.status,
            endpoint=f.endpoint,
            http_method=f.http_method,
            parameter=f.parameter,
            evidence=f.evidence,
            description=f.description,
            remediation=f.remediation,
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
            mitre_technique_id=f.mitre_technique_id,
            affected_component=f.affected_component,
            discovered_at=f.discovered_at,
            risk_score=f.risk_score,
            related_alert_id=f.related_alert_id,
            related_incident_id=f.related_incident_id,
            analyst_notes=f.analyst_notes,
        )
