"""
Tests B — Input Validation
POST /api/analyse endpoint validation coverage.

All tests use isolated temporary SQLite databases via the shared
`client` fixture. Production database is never touched.
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import create_app
from backend.utils import database


# ─────────────────────────────────────────────────────────────
# Shared fixture — isolated database
# ─────────────────────────────────────────────────────────────
@pytest.fixture
def client(tmp_path, monkeypatch):
    """Isolated Flask test client with a temporary SQLite database."""
    test_db = tmp_path / "test_threats.db"
    monkeypatch.setattr(database, "DB_PATH", str(test_db))

    app = create_app()
    app.config["TESTING"] = True

    database.init_database()
    database.load_scored_logs_to_db()

    with app.test_client() as c:
        yield c


def post_analyse(client, payload, **kwargs):
    """Helper: POST JSON payload to /api/analyse."""
    return client.post(
        "/api/analyse",
        data=json.dumps(payload),
        content_type="application/json",
        **kwargs,
    )


# ─────────────────────────────────────────────────────────────
# Minimal valid payload reused across tests
# ─────────────────────────────────────────────────────────────
VALID = {
    "ip_address": "192.168.1.10",
    "username": "alice",
    "status": "Accepted",
    "hour": 10,
    "failed_attempts": 0,
    "port": 22,
}


# ════════════════════════════════════════════════════════════
# IV-01 — Raw string body (not valid JSON object)
# ════════════════════════════════════════════════════════════
def test_iv01_invalid_json_raw_string(client):
    """Raw string body must return 400 — not a JSON object."""
    res = client.post(
        "/api/analyse",
        data='"this is a string"',
        content_type="application/json",
    )
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-02 — JSON array instead of object
# ════════════════════════════════════════════════════════════
def test_iv02_non_dict_array_payload(client):
    """JSON array body must return 400."""
    res = client.post(
        "/api/analyse",
        data=json.dumps([{"ip_address": "1.2.3.4"}]),
        content_type="application/json",
    )
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-03 — Invalid IP address (bad octet)
# ════════════════════════════════════════════════════════════
def test_iv03_invalid_ip_bad_octet(client):
    """IP address with octet > 255 must return 400."""
    payload = {**VALID, "ip_address": "999.0.0.1"}
    res = post_analyse(client, payload)
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False
    assert any("ip" in d.lower() or "valid" in d.lower() for d in data["details"])


# ════════════════════════════════════════════════════════════
# IV-04 — Hostname string where IP expected
# ════════════════════════════════════════════════════════════
def test_iv04_invalid_ip_hostname_string(client):
    """Hostname string is not a valid IP address — must return 400."""
    payload = {**VALID, "ip_address": "not-an-ip"}
    res = post_analyse(client, payload)
    assert res.status_code == 400


# ════════════════════════════════════════════════════════════
# IV-05 — Empty string username
# ════════════════════════════════════════════════════════════
def test_iv05_empty_username(client):
    """Empty username string must return 400."""
    payload = {**VALID, "username": ""}
    res = post_analyse(client, payload)
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-06 — Whitespace-only username
# ════════════════════════════════════════════════════════════
def test_iv06_whitespace_only_username(client):
    """Username containing only spaces must return 400."""
    payload = {**VALID, "username": "   "}
    res = post_analyse(client, payload)
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-07 — Username as integer (wrong type)
# ════════════════════════════════════════════════════════════
def test_iv07_username_as_integer(client):
    """Integer supplied as username must return 400."""
    payload = {**VALID, "username": 42}
    res = post_analyse(client, payload)
    # username validator checks isinstance(username, str)
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-08 — Invalid status value
# ════════════════════════════════════════════════════════════
def test_iv08_invalid_status_rejected(client):
    """Status 'Rejected' is not in {Failed, Accepted} — must return 400."""
    payload = {**VALID, "status": "Rejected"}
    res = post_analyse(client, payload)
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-09 — Empty status string
# ════════════════════════════════════════════════════════════
def test_iv09_empty_status(client):
    """Empty status string must return 400."""
    payload = {**VALID, "status": ""}
    res = post_analyse(client, payload)
    assert res.status_code == 400


# ════════════════════════════════════════════════════════════
# IV-10 — Hour below valid range
# ════════════════════════════════════════════════════════════
def test_iv10_hour_below_zero(client):
    """hour = -1 is out of range [0, 23] — must return 400."""
    payload = {**VALID, "hour": -1}
    res = post_analyse(client, payload)
    assert res.status_code == 400


# ════════════════════════════════════════════════════════════
# IV-11 — Hour above valid range
# ════════════════════════════════════════════════════════════
def test_iv11_hour_above_max(client):
    """hour = 24 is out of range [0, 23] — must return 400."""
    payload = {**VALID, "hour": 24}
    res = post_analyse(client, payload)
    assert res.status_code == 400


# ════════════════════════════════════════════════════════════
# IV-12 — Fractional hour
# ════════════════════════════════════════════════════════════
def test_iv12_fractional_hour(client):
    """hour = 1.5 (float) must return 400 — only whole numbers permitted."""
    payload = {**VALID, "hour": 1.5}
    res = post_analyse(client, payload)
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-13 — Negative failed_attempts
# ════════════════════════════════════════════════════════════
def test_iv13_negative_failed_attempts(client):
    """failed_attempts = -1 must return 400."""
    payload = {**VALID, "failed_attempts": -1}
    res = post_analyse(client, payload)
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-14 — Fractional failed_attempts
# ════════════════════════════════════════════════════════════
def test_iv14_fractional_failed_attempts(client):
    """failed_attempts = 1.9 (float) must return 400."""
    payload = {**VALID, "failed_attempts": 1.9}
    res = post_analyse(client, payload)
    assert res.status_code == 400


# ════════════════════════════════════════════════════════════
# IV-15 — Port below valid range
# ════════════════════════════════════════════════════════════
def test_iv15_port_zero(client):
    """port = 0 is out of range [1, 65535] — must return 400."""
    payload = {**VALID, "port": 0}
    res = post_analyse(client, payload)
    assert res.status_code == 400


# ════════════════════════════════════════════════════════════
# IV-16 — Port above valid range
# ════════════════════════════════════════════════════════════
def test_iv16_port_above_max(client):
    """port = 65536 is out of range [1, 65535] — must return 400."""
    payload = {**VALID, "port": 65536}
    res = post_analyse(client, payload)
    assert res.status_code == 400


# ════════════════════════════════════════════════════════════
# IV-17 — Boolean True supplied as hour
# ════════════════════════════════════════════════════════════
def test_iv17_boolean_as_hour(client):
    """
    Boolean True coerces to int(1) in Python.
    The validator uses int(), so True → 1 which is in [0,23].
    This is a known accepted behaviour: document it, do not suppress.
    """
    payload = {**VALID, "hour": True}
    res = post_analyse(client, payload)
    # True coerces to 1 — hour=1 is valid; response should be 200.
    # This documents existing coercion behaviour.
    assert res.status_code == 200
    data = json.loads(res.data)
    assert data["input"]["hour"] == 1


# ════════════════════════════════════════════════════════════
# IV-18 — Invalid timestamp string
# ════════════════════════════════════════════════════════════
def test_iv18_invalid_timestamp_string(client):
    """Non-parseable timestamp must return 400."""
    payload = {**VALID, "timestamp": "not-a-timestamp"}
    res = post_analyse(client, payload)
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-19 — Timezone-aware timestamp (Z suffix)
# ════════════════════════════════════════════════════════════
def test_iv19_timezone_aware_timestamp(client):
    """
    Timestamp with 'Z' suffix — Python's datetime.fromisoformat() in
    Python 3.11+ accepts 'Z' as UTC. Verify the system handles it
    without crashing and returns either 200 or a clean 400.
    """
    payload = {**VALID, "timestamp": "2026-10-01T10:00:00Z"}
    res = post_analyse(client, payload)
    data = json.loads(res.data)
    # Must not return 500 — either valid or clean rejection
    assert res.status_code in (200, 400)
    assert "success" in data


# ════════════════════════════════════════════════════════════
# IV-20 to IV-23 — Missing required fields
# ════════════════════════════════════════════════════════════
@pytest.mark.parametrize("missing_field", [
    "ip_address",
    "username",
    "status",
    "hour",
])
def test_iv20_to_iv23_missing_required_fields(client, missing_field):
    """Each required field, when absent, must trigger HTTP 400."""
    payload = {k: v for k, v in VALID.items() if k != missing_field}
    res = post_analyse(client, payload)
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-24 — Empty object body
# ════════════════════════════════════════════════════════════
def test_iv24_empty_object_body(client):
    """Empty JSON object must return 400 (all required fields missing)."""
    res = post_analyse(client, {})
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# IV-25 — Null body (no Content-Type)
# ════════════════════════════════════════════════════════════
def test_iv25_null_body(client):
    """Request with no body/content-type must return 400 — not 500."""
    res = client.post("/api/analyse")
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False

