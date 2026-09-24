"""
Reusable enums for ORM models.

Design note — RiskLevel reuse:
    LogSource/ParsedLog.severity, SigmaDetection.severity, RiskAssessment.risk_level,
    Alert.severity, and Incident.priority all represent the same conceptual
    LOW/MEDIUM/HIGH/CRITICAL scale. Rather than defining a near-duplicate
    "Severity" enum alongside "RiskLevel" (which the Part 3 spec explicitly
    names), a single `RiskLevel` enum is reused everywhere that scale applies.
    This avoids duplicated, potentially-diverging value sets — consistent
    with the normalization requirement in the Part 3 spec.
"""

import enum


class UserRole(str, enum.Enum):
    """
    RBAC roles. Authorization logic (role/permission checks) is implemented
    in Part 4 — see app/security/permissions.py for the role→permission
    mapping, which is the only place that needs updating to add further
    roles/permissions in the future.
    """

    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    SOC_MANAGER = "soc_manager"
    ANALYST = "analyst"
    VIEWER = "viewer"


class RiskLevel(str, enum.Enum):
    """Shared LOW→CRITICAL scale reused across logs, detections, risk, alerts, incidents."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogSource(str, enum.Enum):
    """Origin category of an uploaded security log file."""

    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    ENDPOINT = "endpoint"
    SERVER = "server"
    APPLICATION = "application"
    CLOUD = "cloud"
    NETWORK_DEVICE = "network_device"
    OTHER = "other"


class ProcessingStatus(str, enum.Enum):
    """Lifecycle status of an uploaded log file as it moves through parsing."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class AlertStatus(str, enum.Enum):
    """Lifecycle status of an Alert."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentStatus(str, enum.Enum):
    """Lifecycle status of an Incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class NotificationType(str, enum.Enum):
    """Category of a Notification, used for routing/display in the frontend."""

    ALERT_CREATED = "alert_created"
    INCIDENT_ASSIGNED = "incident_assigned"
    RISK_ESCALATION = "risk_escalation"
    REPORT_READY = "report_ready"
    SYSTEM = "system"


class ReportType(str, enum.Enum):
    """Output format of a generated Report."""

    PDF = "pdf"
    CSV = "csv"
