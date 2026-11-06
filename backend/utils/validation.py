import ipaddress
from datetime import datetime


def validate_analyse_input(data):
    """
    Validates and cleans the JSON payload for POST /api/analyse.
    Returns (cleaned_entry, errors). If errors is non-empty, the
    caller should return a 400 response and ignore cleaned_entry.
    """
    errors = []

    ip_address = data.get("ip_address", "")
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        errors.append(f"'{ip_address}' is not a valid IP address")

    username = data.get("username", "")
    if not isinstance(username, str) or not username.strip():
        errors.append("username must be a non-empty string")

    status = data.get("status", "")
    if status not in ("Failed", "Accepted"):
        errors.append("status must be either 'Failed' or 'Accepted'")

    try:
        raw_hour = data.get("hour")
        if isinstance(raw_hour, float):
            raise ValueError("fractional float not allowed for hour")
        hour = int(raw_hour)
        if not (0 <= hour <= 23):
            errors.append("hour must be between 0 and 23")
    except (TypeError, ValueError):
        errors.append("hour must be a whole number between 0 and 23")
        hour = None

    try:
        raw_failed = data.get("failed_attempts", 1)
        if isinstance(raw_failed, float):
            raise ValueError("fractional float not allowed for failed_attempts")
        failed_attempts = int(raw_failed)
        if failed_attempts < 0:
            errors.append("failed_attempts cannot be negative")
    except (TypeError, ValueError):
        errors.append("failed_attempts must be a whole number")
        failed_attempts = None

    try:
        raw_port = data.get("port", 22)
        if isinstance(raw_port, float):
            raise ValueError("fractional float not allowed for port")
        port = int(raw_port)
        if not (1 <= port <= 65535):
            errors.append("port must be between 1 and 65535")
    except (TypeError, ValueError):
        errors.append("port must be a whole number between 1 and 65535")
        port = None

    # Guard: if hour is invalid, datetime.replace(hour=None) would raise
    # TypeError/ValueError before the errors check below — return early.
    if errors:
        return None, errors

    raw_timestamp = data.get("timestamp")

    if raw_timestamp is None or (
        isinstance(raw_timestamp, str) and not raw_timestamp.strip()
    ):
        timestamp = datetime.now().replace(
            hour=hour,
            minute=0,
            second=0,
            microsecond=0
        ).isoformat(sep=" ")
    else:
        try:
            timestamp = datetime.fromisoformat(
                str(raw_timestamp).strip()
            ).isoformat(sep=" ")
        except ValueError:
            errors.append("timestamp must be a valid ISO date/time")
            timestamp = None

    if errors:
        return None, errors

    cleaned = {
        "timestamp"      : timestamp,
        "ip_address"     : ip_address,
        "username"       : username,
        "status"         : status,
        "failed_attempts": failed_attempts,
        "port"           : port,
        "hour"           : hour,
    }
    return cleaned, []