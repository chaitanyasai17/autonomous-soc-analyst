"""
Service/repository dependency providers.

Every route handler that needs a service gets it via `Depends(get_x_service)`
rather than constructing it directly — keeps object construction wiring in
one place and makes services trivially mockable in tests.
"""

from functools import lru_cache

from fastapi import Depends
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies.database import get_db
from app.repositories.alert_repository import AlertRepository
from app.repositories.incident_repository import IncidentRepository
from app.repositories.mitre_repository import MitreRepository
from app.repositories.notification_repository import NotificationRepository
from app.repositories.parsed_log_repository import ParsedLogRepository
from app.repositories.report_repository import ReportRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.security_log_repository import SecurityLogRepository
from app.repositories.sigma_detection_repository import SigmaDetectionRepository
from app.repositories.user_repository import UserRepository
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.endpoint_repository import EndpointRepository
from app.repositories.ioc_repository import IOCRepository
from app.repositories.web_security_allowlist_repository import WebSecurityAllowlistRepository
from app.repositories.web_security_finding_repository import WebSecurityFindingRepository
from app.repositories.web_security_scan_repository import WebSecurityScanRepository
from app.services.ai_service import AIService
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.detection_service import DetectionService
from app.services.endpoint_service import EndpointService
from app.services.evidence_timeline_service import EvidenceTimelineService
from app.services.global_search_service import GlobalSearchService
from app.services.incident_service import IncidentService
from app.services.ioc_service import IOCService
from app.services.log_management_service import LogManagementService
from app.services.mitre_service import MitreService
from app.services.notification_service import NotificationService
from app.services.parser_service import ParserService
from app.services.pipeline_trace_service import PipelineTraceService
from app.services.report_service import ReportService
from app.services.risk_service import RiskService
from app.services.rule_service import RuleService
from app.services.soc_health_service import SOCHealthService
from app.services.upload_service import UploadService
from app.services.user_service import UserService
from app.services.web_security_posture_service import WebSecurityPostureService
from app.services.web_security_service import WebSecurityService
from app.sigma.engine import DetectionEngine
from app.sigma.loader import SigmaRuleLoader
from app.utils.storage import LocalFileStorage


def get_user_repository(db: Session = Depends(get_db)) -> UserRepository:
    return UserRepository(db)


def get_user_service(
    repository: UserRepository = Depends(get_user_repository),
) -> UserService:
    return UserService(repository)


def get_auth_service(
    repository: UserRepository = Depends(get_user_repository),
) -> AuthService:
    return AuthService(repository)


def get_security_log_repository(db: Session = Depends(get_db)) -> SecurityLogRepository:
    return SecurityLogRepository(db)


@lru_cache
def get_file_storage() -> LocalFileStorage:
    """
    A single LocalFileStorage instance per process — it's stateless aside
    from the (config-derived) base directory, so there's no need to
    reconstruct it (and re-run its directory-creation check) on every request.
    """
    settings = get_settings()
    return LocalFileStorage(settings.UPLOAD_DIRECTORY)


def get_upload_service(
    repository: SecurityLogRepository = Depends(get_security_log_repository),
    storage: LocalFileStorage = Depends(get_file_storage),
) -> UploadService:
    return UploadService(repository, storage)


def get_parsed_log_repository(db: Session = Depends(get_db)) -> ParsedLogRepository:
    return ParsedLogRepository(db)


def get_parser_service(
    security_log_repository: SecurityLogRepository = Depends(get_security_log_repository),
    parsed_log_repository: ParsedLogRepository = Depends(get_parsed_log_repository),
    storage: LocalFileStorage = Depends(get_file_storage),
) -> ParserService:
    return ParserService(security_log_repository, parsed_log_repository, storage)


def get_log_management_service(
    security_log_repository: SecurityLogRepository = Depends(get_security_log_repository),
    upload_service: UploadService = Depends(get_upload_service),
    parser_service: ParserService = Depends(get_parser_service),
) -> LogManagementService:
    return LogManagementService(security_log_repository, upload_service, parser_service)


@lru_cache
def get_rule_loader() -> SigmaRuleLoader:
    """
    A single SigmaRuleLoader instance per process holding the in-memory
    rule cache — mirrors get_file_storage()'s rationale (Part 5): rules are
    re-read from disk only on first use or an explicit reload, not on
    every request.
    """
    settings = get_settings()
    return SigmaRuleLoader(settings.SIGMA_RULES_DIRECTORY)


def get_detection_engine(
    rule_loader: SigmaRuleLoader = Depends(get_rule_loader),
) -> DetectionEngine:
    if not hasattr(rule_loader, "get_all_rules"):
        rule_loader = get_rule_loader()
    return DetectionEngine(rule_loader)



def get_rule_service(
    rule_loader: SigmaRuleLoader = Depends(get_rule_loader),
) -> RuleService:
    return RuleService(rule_loader)


def get_sigma_detection_repository(db: Session = Depends(get_db)) -> SigmaDetectionRepository:
    return SigmaDetectionRepository(db)


# --- MITRE ATT&CK ---
def get_mitre_repository(db: Session = Depends(get_db)) -> MitreRepository:
    return MitreRepository(db)


def get_mitre_service(
    repository: MitreRepository = Depends(get_mitre_repository),
) -> MitreService:
    return MitreService(repository)


def get_detection_service(
    security_log_repository: SecurityLogRepository = Depends(get_security_log_repository),
    parsed_log_repository: ParsedLogRepository = Depends(get_parsed_log_repository),
    sigma_detection_repository: SigmaDetectionRepository = Depends(get_sigma_detection_repository),
    detection_engine: DetectionEngine = Depends(get_detection_engine),
    mitre_service: MitreService = Depends(get_mitre_service),
) -> DetectionService:
    return DetectionService(
        security_log_repository,
        parsed_log_repository,
        sigma_detection_repository,
        detection_engine,
        mitre_service,
    )


# --- Risk Scoring ---
def get_risk_repository(db: Session = Depends(get_db)) -> RiskRepository:
    return RiskRepository(db)


def get_risk_service(
    risk_repository: RiskRepository = Depends(get_risk_repository),
    sigma_detection_repository: SigmaDetectionRepository = Depends(get_sigma_detection_repository),
    parsed_log_repository: ParsedLogRepository = Depends(get_parsed_log_repository),
) -> RiskService:
    return RiskService(risk_repository, sigma_detection_repository, parsed_log_repository)


# --- Notifications ---
def get_notification_repository(db: Session = Depends(get_db)) -> NotificationRepository:
    return NotificationRepository(db)


def get_notification_service(
    repository: NotificationRepository = Depends(get_notification_repository),
) -> NotificationService:
    return NotificationService(repository)


# --- Alerts ---
def get_alert_repository(db: Session = Depends(get_db)) -> AlertRepository:
    return AlertRepository(db)


def get_alert_service(
    alert_repository: AlertRepository = Depends(get_alert_repository),
    risk_repository: RiskRepository = Depends(get_risk_repository),
    sigma_detection_repository: SigmaDetectionRepository = Depends(get_sigma_detection_repository),
    user_repository: UserRepository = Depends(get_user_repository),
    notification_service: NotificationService = Depends(get_notification_service),
) -> AlertService:
    return AlertService(
        alert_repository,
        risk_repository,
        sigma_detection_repository,
        user_repository,
        notification_service,
    )


# --- Incidents ---
def get_incident_repository(db: Session = Depends(get_db)) -> IncidentRepository:
    return IncidentRepository(db)


def get_incident_service(
    incident_repository: IncidentRepository = Depends(get_incident_repository),
    alert_repository: AlertRepository = Depends(get_alert_repository),
    user_repository: UserRepository = Depends(get_user_repository),
    notification_service: NotificationService = Depends(get_notification_service),
) -> IncidentService:
    return IncidentService(
        incident_repository, alert_repository, user_repository, notification_service
    )


# --- AI Threat Analysis ---
def get_ai_service(
    sigma_detection_repository: SigmaDetectionRepository = Depends(get_sigma_detection_repository),
    parsed_log_repository: ParsedLogRepository = Depends(get_parsed_log_repository),
    alert_repository: AlertRepository = Depends(get_alert_repository),
    incident_repository: IncidentRepository = Depends(get_incident_repository),
    risk_repository: RiskRepository = Depends(get_risk_repository),
) -> AIService:
    return AIService(
        sigma_detection_repository,
        parsed_log_repository,
        alert_repository,
        incident_repository,
        risk_repository,
    )



# --- Reports ---
def get_report_repository(db: Session = Depends(get_db)) -> ReportRepository:
    return ReportRepository(db)


def get_report_service(
    report_repository: ReportRepository = Depends(get_report_repository),
    alert_repository: AlertRepository = Depends(get_alert_repository),
    incident_repository: IncidentRepository = Depends(get_incident_repository),
    risk_repository: RiskRepository = Depends(get_risk_repository),
) -> ReportService:
    return ReportService(
        report_repository, alert_repository, incident_repository, risk_repository
    )


# --- IOCs ---
def get_ioc_repository(db: Session = Depends(get_db)) -> IOCRepository:
    return IOCRepository(db)


def get_ioc_service(
    ioc_repository: IOCRepository = Depends(get_ioc_repository),
) -> IOCService:
    return IOCService(ioc_repository)


# --- Web Security Testing Lab ---
def get_web_security_allowlist_repository(db: Session = Depends(get_db)) -> WebSecurityAllowlistRepository:
    return WebSecurityAllowlistRepository(db)


def get_web_security_scan_repository(db: Session = Depends(get_db)) -> WebSecurityScanRepository:
    return WebSecurityScanRepository(db)


def get_web_security_finding_repository(db: Session = Depends(get_db)) -> WebSecurityFindingRepository:
    return WebSecurityFindingRepository(db)


def get_web_security_posture_service() -> WebSecurityPostureService:
    return WebSecurityPostureService()


def get_web_security_service(
    scan_repo: WebSecurityScanRepository = Depends(get_web_security_scan_repository),
    finding_repo: WebSecurityFindingRepository = Depends(get_web_security_finding_repository),
    allowlist_repo: WebSecurityAllowlistRepository = Depends(get_web_security_allowlist_repository),
    posture_service: WebSecurityPostureService = Depends(get_web_security_posture_service),
    alert_repo: AlertRepository = Depends(get_alert_repository),
    risk_repo: RiskRepository = Depends(get_risk_repository),
    ioc_service: IOCService = Depends(get_ioc_service),
    incident_service: IncidentService = Depends(get_incident_service),
    notification_service: NotificationService = Depends(get_notification_service),
) -> WebSecurityService:
    return WebSecurityService(
        scan_repo=scan_repo,
        finding_repo=finding_repo,
        allowlist_repo=allowlist_repo,
        posture_service=posture_service,
        alert_repo=alert_repo,
        risk_repo=risk_repo,
        ioc_service=ioc_service,
        incident_service=incident_service,
        notification_service=notification_service,
    )


# --- SOC Health ---
def get_soc_health_service(
    db: Session = Depends(get_db),
    detection_engine: DetectionEngine = Depends(get_detection_engine),
) -> SOCHealthService:
    return SOCHealthService(db=db, detection_engine=detection_engine)


# --- Audit Log ---
def get_audit_log_repository(db: Session = Depends(get_db)) -> AuditLogRepository:
    return AuditLogRepository(db)


def get_audit_service(
    repo: AuditLogRepository = Depends(get_audit_log_repository),
) -> AuditService:
    return AuditService(repo)


# --- Pipeline Trace ---
def get_pipeline_trace_service(db: Session = Depends(get_db)) -> PipelineTraceService:
    return PipelineTraceService(db)


# --- Global Search ---
def get_global_search_service(db: Session = Depends(get_db)) -> GlobalSearchService:
    return GlobalSearchService(db)


# --- Endpoints ---
def get_endpoint_repository(db: Session = Depends(get_db)) -> EndpointRepository:
    return EndpointRepository(db)


def get_endpoint_service(
    repo: EndpointRepository = Depends(get_endpoint_repository),
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
) -> EndpointService:
    return EndpointService(endpoint_repo=repo, db_session=db, audit_service=audit)


# --- Evidence Timeline ---
def get_evidence_timeline_service(db: Session = Depends(get_db)) -> EvidenceTimelineService:
    return EvidenceTimelineService(db)

