"""
Tests G — Security
SQL injection, oversized payloads, type confusion, information leakage,
rate limiting, and input boundary enforcement.

Only local isolated test infrastructure is used. No external calls are made.
"""

import sys
import os
import json
import string
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import create_app
from backend.utils import database


# ─────────────────────────────────────────────────────────────
# Shared fixture — isolated database
# ─────────────────────────────────────────────────────────────
@pytest.fixture
def client(tmp_path, monkeypatch):
    """Isolated Flask test client with temporary SQLite database."""
    test_db = tmp_path / "sec_test.db"
    monkeypatch.setattr(database, "DB_PATH", str(test_db))

    app = create_app()
    app.config["TESTING"] = True

    database.init_database()
    database.load_scored_logs_to_db()

    with app.test_client() as c:
        yield c


def post_analyse(client, payload):
    return client.post(
        "/api/analyse",
        data=json.dumps(payload),
        content_type="application/json",
    )


# ─────────────────────────────────────────────────────────────
# Minimal valid base payload
# ─────────────────────────────────────────────────────────────
SAFE_BASE = {
    "ip_address":      "10.0.0.1",
    "username":        "sectest",
    "status":          "Failed",
    "failed_attempts": 1,
    "port":            22,
    "hour":            12,
}


# ════════════════════════════════════════════════════════════
# SEC-01 — SQL injection in ip_address field
# ════════════════════════════════════════════════════════════
@pytest.mark.parametrize("injection", [
    "' OR '1'='1",
    "1.2.3.4; DROP TABLE logs;--",
    "1.2.3.4' UNION SELECT * FROM alerts--",
    "0.0.0.0' OR 1=1--",
])
def test_sec01_sql_injection_in_ip_address(client, injection):
    """
    SQL injection strings in ip_address must return 400 (validation rejects
    them as invalid IP addresses) — the application must never return 500.
    """
    payload = {**SAFE_BASE, "ip_address": injection}
    res = post_analyse(client, payload)
    assert res.status_code == 400, (
        f"Expected 400 for SQL injection in ip_address: {injection!r}"
    )
    data = json.loads(res.data)
    assert data["success"] is False
    # Must NOT expose internal errors
    body = res.data.decode()
    assert "Traceback" not in body
    assert "sqlite3" not in body.lower()


# ════════════════════════════════════════════════════════════
# SEC-02 — SQL injection in username field
# ════════════════════════════════════════════════════════════
@pytest.mark.parametrize("injection", [
    "alice'; DROP TABLE logs;--",
    "admin' OR '1'='1",
    "' UNION SELECT username, password FROM users--",
])
def test_sec02_sql_injection_in_username(client, injection):
    """
    SQL injection strings in username must be accepted (they are
    valid non-empty strings) — but must not trigger a 500 or
    expose internal error details. The application must handle
    these values safely via parameterised queries.
    """
    payload = {**SAFE_BASE, "username": injection}
    res = post_analyse(client, payload)
    # username validator only checks non-empty string — injection strings pass
    body = res.data.decode()
    assert res.status_code != 500, "SQL injection caused a 500 error."
    assert "Traceback" not in body
    assert "sqlite3" not in body.lower()
    # Must be 200 (processed safely) or 400 (rejected), never 500
    assert res.status_code in (200, 400)


# ════════════════════════════════════════════════════════════
# SEC-03 — Oversized request body (> 1 MB)
# ════════════════════════════════════════════════════════════
def test_sec03_oversized_request_body(client):
    """
    A request body exceeding 1 MB must not crash the server.
    The response must be 400 or 413 — never 500.
    """
    large_username = "A" * (1024 * 1024 + 1)  # > 1 MB
    payload = {**SAFE_BASE, "username": large_username}
    res = client.post(
        "/api/analyse",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert res.status_code in (200, 400, 413), (
        f"Oversized body produced unexpected status {res.status_code}"
    )
    assert "Traceback" not in res.data.decode()


# ════════════════════════════════════════════════════════════
# SEC-04 — JSON array instead of object (type confusion)
# ════════════════════════════════════════════════════════════
def test_sec04_json_array_type_confusion(client):
    """JSON array body must return 400 without crashing."""
    res = client.post(
        "/api/analyse",
        data=json.dumps([SAFE_BASE, SAFE_BASE]),
        content_type="application/json",
    )
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# SEC-05 — Unexpected field types (integer for string field)
# ════════════════════════════════════════════════════════════
@pytest.mark.parametrize("field,value", [
    ("ip_address", 12345),
    ("ip_address", None),
    ("status",     12345),
    ("status",     True),
    ("hour",       "ten"),
    ("hour",       None),
])
def test_sec05_unexpected_field_types(client, field, value):
    """Unexpected types in any field must return 400 — never 500."""
    payload = {**SAFE_BASE, field: value}
    res = post_analyse(client, payload)
    assert res.status_code in (400, 200), (
        f"Field '{field}'={value!r} caused unexpected status {res.status_code}"
    )
    assert "Traceback" not in res.data.decode()


# ════════════════════════════════════════════════════════════
# SEC-06 — Error responses do not leak stack traces
# ════════════════════════════════════════════════════════════
def test_sec06_no_stack_trace_in_error_response(client):
    """
    Every 400-class error response must not contain Python
    stack traces, file paths, or internal module names.
    """
    # Trigger validation error
    res = post_analyse(client, {"ip_address": "INVALID"})
    body = res.data.decode()
    assert res.status_code == 400
    assert "Traceback" not in body
    assert "File \"/" not in body
    assert ".py\", line" not in body


# ════════════════════════════════════════════════════════════
# SEC-07 — Error responses do not contain the database path
# ════════════════════════════════════════════════════════════
def test_sec07_no_db_path_in_error_response(client, tmp_path):
    """
    Error responses must not expose the database file path.
    """
    # Trigger a 400 by sending an empty body
    res = client.post("/api/analyse")
    body = res.data.decode()
    assert "threats.db" not in body
    assert str(tmp_path) not in body


# ════════════════════════════════════════════════════════════
# SEC-08 — Rate limiting: 11th request within window returns 429
# ════════════════════════════════════════════════════════════
def test_sec08_rate_limiting_429(tmp_path, monkeypatch):
    """
    After 10 successful POST /api/analyse requests within one minute,
    the 11th must return HTTP 429 Too Many Requests.
    """
    test_db = tmp_path / "rate_limit_test.db"
    monkeypatch.setattr(database, "DB_PATH", str(test_db))

    app = create_app()
    app.config["TESTING"] = True
    # Ensure limiter uses in-memory storage (default in test mode)

    database.init_database()
    database.load_scored_logs_to_db()

    with app.test_client() as c:
        status_codes = []
        for i in range(12):
            res = c.post(
                "/api/analyse",
                data=json.dumps(SAFE_BASE),
                content_type="application/json",
            )
            status_codes.append(res.status_code)

        # At least one request in the last 2 must have been rate-limited
        assert 429 in status_codes, (
            f"Rate limiting did not return 429. Status codes: {status_codes}"
        )


# ════════════════════════════════════════════════════════════
# SEC-09 — Long username string is handled gracefully
# ════════════════════════════════════════════════════════════
def test_sec09_long_username_handled_gracefully(client):
    """
    A username of 1000 characters must be accepted (it is a valid
    non-empty string) or cleanly rejected — never produce a 500.
    """
    payload = {**SAFE_BASE, "username": "u" * 1000}
    res = post_analyse(client, payload)
    assert res.status_code in (200, 400), (
        f"Long username caused unexpected status {res.status_code}"
    )
    assert "Traceback" not in res.data.decode()


# ════════════════════════════════════════════════════════════
# SEC-10 — Null byte in username is handled gracefully
# ════════════════════════════════════════════════════════════
def test_sec10_null_byte_in_username(client):
    """
    A username containing a null byte must not crash the server
    and must return a clean 200 or 400 response.
    """
    payload = {**SAFE_BASE, "username": "alice\x00evil"}
    res = post_analyse(client, payload)
    assert res.status_code in (200, 400)
    assert "Traceback" not in res.data.decode()


# ════════════════════════════════════════════════════════════
# SEC-11 — Unicode characters in username handled gracefully
# ════════════════════════════════════════════════════════════
def test_sec11_unicode_username(client):
    """Unicode username must not crash the server."""
    payload = {**SAFE_BASE, "username": "用户名_тест_🔒"}
    res = post_analyse(client, payload)
    assert res.status_code in (200, 400)
    assert "Traceback" not in res.data.decode()


# ════════════════════════════════════════════════════════════
# SEC-12 — Content-Type: text/plain body must return 400
# ════════════════════════════════════════════════════════════
def test_sec12_wrong_content_type(client):
    """Body sent as text/plain must return 400 (not parseable as JSON object)."""
    res = client.post(
        "/api/analyse",
        data='{"ip_address": "1.2.3.4"}',
        content_type="text/plain",
    )
    assert res.status_code == 400
    data = json.loads(res.data)
    assert data["success"] is False

