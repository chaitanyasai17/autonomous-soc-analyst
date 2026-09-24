"""
Application-wide constants.

Only truly global, non-configurable values belong here (things that are
never expected to change per environment). Anything that *can* vary by
environment belongs in config/settings.py instead.
"""

# --- API metadata ---
API_TITLE = "ASOC — Autonomous SOC Analyst API"
API_DESCRIPTION = (
    "AI-Powered Autonomous SOC Analyst — enterprise SOC platform API. "
    "Provides log ingestion, Sigma/MITRE detection, AI threat analysis, "
    "risk scoring, alert/incident management, and reporting."
)
API_VERSION = "0.1.0"

# --- Request header names ---
HEADER_REQUEST_ID = "X-Request-ID"
HEADER_PROCESS_TIME = "X-Process-Time"

# --- Pagination defaults (used by BaseRepository / BaseService) ---
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100

# --- Misc ---
UTC_TIMEZONE_NAME = "UTC"
