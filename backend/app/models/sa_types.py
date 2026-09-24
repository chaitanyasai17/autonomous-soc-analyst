"""
Shared SQLAlchemy native-enum type instances.

Each PostgreSQL native ENUM type must be defined exactly once and reused
wherever it's needed — instantiating `sa.Enum(SomeEnum, name="x")` separately
in multiple model files would make SQLAlchemy attempt to `CREATE TYPE x`
more than once. Every model column that uses one of these enums imports the
corresponding instance from this module rather than constructing its own.

CRITICAL — values_callable:
    By default, SQLAlchemy's `Enum(PythonEnum)` sends the enum MEMBER NAME
    (e.g. "ANALYST") to the database, not `.value` (e.g. "analyst"). Since
    every native PostgreSQL enum type in migrations/versions/ was created
    with lowercase `.value` labels (matching app/models/enums.py), every one
    of these types MUST set `values_callable` to use `.value` — otherwise
    every insert/update against an enum column fails with
    "invalid input value for enum ...: <NAME>". This was caught via live
    end-to-end testing against a real PostgreSQL database in Part 4.
"""

from sqlalchemy import Enum as SAEnum

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


def _use_value(enum_cls):
    """Return a values_callable that stores `.value` instead of `.name`."""
    return lambda obj: [member.value for member in obj]


user_role_enum = SAEnum(
    UserRole, name="user_role", native_enum=True, values_callable=_use_value(UserRole)
)
risk_level_enum = SAEnum(
    RiskLevel, name="risk_level", native_enum=True, values_callable=_use_value(RiskLevel)
)
log_source_enum = SAEnum(
    LogSource, name="log_source", native_enum=True, values_callable=_use_value(LogSource)
)
processing_status_enum = SAEnum(
    ProcessingStatus,
    name="processing_status",
    native_enum=True,
    values_callable=_use_value(ProcessingStatus),
)
alert_status_enum = SAEnum(
    AlertStatus, name="alert_status", native_enum=True, values_callable=_use_value(AlertStatus)
)
incident_status_enum = SAEnum(
    IncidentStatus,
    name="incident_status",
    native_enum=True,
    values_callable=_use_value(IncidentStatus),
)
notification_type_enum = SAEnum(
    NotificationType,
    name="notification_type",
    native_enum=True,
    values_callable=_use_value(NotificationType),
)
report_type_enum = SAEnum(
    ReportType, name="report_type", native_enum=True, values_callable=_use_value(ReportType)
)
