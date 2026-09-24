"""
Field mapping between Sigma rule field names and ParsedLog attributes.

Any field referenced by a rule that isn't in SIGMA_FIELD_MAP falls back to
substring search against `message` and `raw_log` — this keeps rules usable
even for fields our normalizer (Part 6) doesn't have a dedicated column for
(e.g. `CommandLine`, a common Windows-event-log Sigma field), at the cost of
being a heuristic rather than an exact field match in that fallback case.
"""

SIGMA_FIELD_MAP: dict[str, str] = {
    "eventid": "event_id",
    "event_id": "event_id",
    "src_ip": "source_ip",
    "source_ip": "source_ip",
    "sourceip": "source_ip",
    "src": "source_ip",
    "dst_ip": "destination_ip",
    "destination_ip": "destination_ip",
    "destinationip": "destination_ip",
    "dst": "destination_ip",
    "src_port": "source_port",
    "source_port": "source_port",
    "sourceport": "source_port",
    "dst_port": "destination_port",
    "destination_port": "destination_port",
    "destinationport": "destination_port",
    "user": "username",
    "username": "username",
    "accountname": "username",
    "user_name": "username",
    "hostname": "hostname",
    "computername": "hostname",
    "computer": "hostname",
    "host": "hostname",
    "eventtype": "event_type",
    "event_type": "event_type",
    "category": "event_type",
    "protocol": "protocol",
    "proto": "protocol",
    "action": "action",
    "message": "message",
    "commandline": "message",
    "command_line": "message",
    "raw_log": "raw_log",
    "rawlog": "raw_log",
}

# Fields evaluated against free text when no direct column mapping is found.
FREE_TEXT_FALLBACK_FIELDS = ("message", "raw_log")


def resolve_field_name(sigma_field_name: str) -> str | None:
    """Return the ParsedLog attribute name for a Sigma field, or None if unmapped."""
    return SIGMA_FIELD_MAP.get(sigma_field_name.strip().lower())
