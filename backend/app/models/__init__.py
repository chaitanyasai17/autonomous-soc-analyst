"""
SQLAlchemy ORM table definitions (domain entities as persisted rows).
Structural only, no query logic (see repositories/).

Importing this package registers every model class on Base's mapper
registry — required for Alembic's `--autogenerate` to detect all tables
(see backend/migrations/env.py, which imports `app.models`).
"""

from app.models.alert import Alert
from app.models.associations import sigma_detection_mitre_technique
from app.models.audit_log import AuditLog
from app.models.base import BaseModel, SoftDeleteMixin
from app.models.endpoint import Endpoint
from app.models.enums import (
    AlertStatus,
    IncidentStatus,
    LogSource,
    NotificationType,
    ProcessingStatus,
    ReportType,
    RiskLevel,
    UserRole,
)
from app.models.incident import Incident
from app.models.ioc_record import IOCRecord
from app.models.mitre_technique import MitreTechnique
from app.models.notification import Notification
from app.models.parsed_log import ParsedLog
from app.models.report import Report
from app.models.risk_assessment import RiskAssessment
from app.models.security_log import SecurityLog
from app.models.sigma_detection import SigmaDetection
from app.models.user import User
from app.models.web_security_allowlist import WebSecurityAllowlist
from app.models.web_security_finding import WebSecurityFinding
from app.models.web_security_scan import WebSecurityScan

__all__ = [
    "BaseModel",
    "SoftDeleteMixin",
    "User",
    "AuditLog",
    "SecurityLog",
    "ParsedLog",
    "MitreTechnique",
    "SigmaDetection",
    "RiskAssessment",
    "Alert",
    "Incident",
    "Endpoint",
    "Notification",
    "Report",
    "WebSecurityAllowlist",
    "WebSecurityScan",
    "WebSecurityFinding",
    "IOCRecord",
    "sigma_detection_mitre_technique",
    "UserRole",
    "RiskLevel",
    "LogSource",
    "ProcessingStatus",
    "AlertStatus",
    "IncidentStatus",
    "NotificationType",
    "ReportType",
]

