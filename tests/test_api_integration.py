"""
Tests F — API Integration
Full-stack integration tests covering all GET/POST endpoints,
error handling, response structure, and the detection+persistence flow.

All tests use isolated temporary SQLite databases.
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import create_app
from backend.utils import database


# ─────────────────────────────────────────────────────────────
# Shared fixture — isolated database with scored log data
# ─────────────────────────────────────────────────────────────
@pytest.fixture
def client(tmp_path, monkeypatch):
    """Isolated Flask test client with temporary SQLite database."""
    test_db = tmp_path / "test_threats.db"
    monkeypatch.setattr(database, "DB_PATH", str(test_db))

    app = create_app()
    app.config["TESTING"] = True

    database.init_database()
    count = database.load_scored_logs_to_db()
    assert count > 0, "No test data loaded."

    with app.test_client() as c:
        yield c


# ─────────────────────────────────────────────────────────────
# Minimal valid POST /api/analyse payload
# ─────────────────────────────────────────────────────────────
VALID_PAYLOAD = {
    "ip_address":      "10.0.0.1",
    "username":        "testuser",
    "status":          "Failed",
    "failed_attempts": 5,
    "port":            22,
    "hour":            3,
}


def post_analyse(client, payload):
    return client.post(
        "/api/analyse",
        data=json.dumps(payload),
        content_type="application/json",
    )


# ════════════════════════════════════════════════════════════
# AI-01 — GET / returns 200 and message
# ════════════════════════════════════════════════════════════
def test_ai01_home_returns_200(client):
    res  = client.get("/")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert "message" in data
    assert "endpoints" in data


# ════════════════════════════════════════════════════════════
# AI-02 — GET /health returns 200
# ════════════════════════════════════════════════════════════
def test_ai02_health_endpoint(client):
    res  = client.get("/health")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data.get("status") == "ok"


# ════════════════════════════════════════════════════════════
# AI-03 — GET /api/stats structure complete
# ════════════════════════════════════════════════════════════
def test_ai03_stats_structure(client):
    res  = client.get("/api/stats")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["success"] is True

    required_keys = {
        "total_logs", "total_anomalies", "total_alerts",
        "suspicious_ips", "avg_threat_score", "max_threat_score",
        "threat_levels",
    }
    assert required_keys.issubset(data["data"].keys())

    level_keys = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert level_keys.issubset(data["data"]["threat_levels"].keys())


# ════════════════════════════════════════════════════════════
# AI-04 — GET /api/logs default limit ≤ 100
# ════════════════════════════════════════════════════════════
def test_ai04_logs_default_limit(client):
    res  = client.get("/api/logs")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert len(data["data"]) <= 100


# ════════════════════════════════════════════════════════════
# AI-05 — GET /api/logs?limit=5 returns ≤ 5 rows
# ════════════════════════════════════════════════════════════
def test_ai05_logs_custom_limit(client):
    res  = client.get("/api/logs?limit=5")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert len(data["data"]) <= 5


# ════════════════════════════════════════════════════════════
# AI-06 — GET /api/logs?limit=0 clamped to 1
# ════════════════════════════════════════════════════════════
def test_ai06_logs_limit_zero_clamped_to_one(client):
    res  = client.get("/api/logs?limit=0")
    data = json.loads(res.data)
    assert res.status_code == 200
    # limit clamped to max(1, min(0, 500)) = 1
    assert 1 <= len(data["data"]) <= 1


# ════════════════════════════════════════════════════════════
# AI-07 — GET /api/logs?limit=9999 clamped to 500
# ════════════════════════════════════════════════════════════
def test_ai07_logs_oversized_limit_clamped(client):
    res  = client.get("/api/logs?limit=9999")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert len(data["data"]) <= 500


# ════════════════════════════════════════════════════════════
# AI-08 — GET /api/logs?level=CRITICAL filters correctly
# ════════════════════════════════════════════════════════════
def test_ai08_logs_level_filter(client):
    res  = client.get("/api/logs?level=CRITICAL")
    data = json.loads(res.data)
    assert res.status_code == 200
    for log in data["data"]:
        assert log["threat_level"] == "CRITICAL"


# ════════════════════════════════════════════════════════════
# AI-09 — GET /api/alerts only returns HIGH and CRITICAL
# ════════════════════════════════════════════════════════════
def test_ai09_alerts_only_high_critical(client):
    res  = client.get("/api/alerts")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["success"] is True
    for alert in data["data"]:
        assert alert["threat_level"] in ("HIGH", "CRITICAL")


# ════════════════════════════════════════════════════════════
# AI-10 — GET /api/threats/timeline returns exactly 24 entries
# ════════════════════════════════════════════════════════════
def test_ai10_timeline_has_24_hours(client):
    res  = client.get("/api/threats/timeline")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["success"] is True
    assert len(data["data"]) == 24
    # Every hour 0–23 must be present
    hours = [entry["hour"] for entry in data["data"]]
    assert hours == list(range(24))


# ════════════════════════════════════════════════════════════
# AI-11 — GET /api/threats/top-ips returns ≤ 10 entries
# ════════════════════════════════════════════════════════════
def test_ai11_top_ips_at_most_ten(client):
    res  = client.get("/api/threats/top-ips")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["success"] is True
    assert len(data["data"]) <= 10


# ════════════════════════════════════════════════════════════
# AI-12 — POST /api/analyse returns 200 success
# ════════════════════════════════════════════════════════════
def test_ai12_analyse_success(client):
    res  = post_analyse(client, VALID_PAYLOAD)
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["success"] is True


# ════════════════════════════════════════════════════════════
# AI-13 — POST /api/analyse returns 400 on missing required fields
# ════════════════════════════════════════════════════════════
def test_ai13_analyse_missing_fields(client):
    res  = post_analyse(client, {"ip_address": "1.2.3.4"})
    data = json.loads(res.data)
    assert res.status_code == 400
    assert data["success"] is False
    assert "error" in data


# ════════════════════════════════════════════════════════════
# AI-14 — POST /api/reload returns 410 Gone
# ════════════════════════════════════════════════════════════
def test_ai14_reload_endpoint_retired(client):
    res  = client.post("/api/reload")
    data = json.loads(res.data)
    assert res.status_code == 410
    assert data["success"] is False
    assert "retired" in data["error"].lower()


# ════════════════════════════════════════════════════════════
# AI-15 — Detection response contains all expected result fields
# ════════════════════════════════════════════════════════════
def test_ai15_response_contains_required_result_fields(client):
    res  = post_analyse(client, VALID_PAYLOAD)
    data = json.loads(res.data)
    assert res.status_code == 200
    result = data["result"]
    assert "threat_score"  in result
    assert "threat_level"  in result
    assert "threat_color"  in result
    assert "is_anomaly"    in result


# ════════════════════════════════════════════════════════════
# AI-16 — Threat score is in [0, 100], level is a known string
# ════════════════════════════════════════════════════════════
def test_ai16_threat_score_range_and_level(client):
    res  = post_analyse(client, VALID_PAYLOAD)
    data = json.loads(res.data)
    assert res.status_code == 200
    result = data["result"]
    assert 0 <= result["threat_score"] <= 100
    assert result["threat_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert result["is_anomaly"] in (0, 1)


# ════════════════════════════════════════════════════════════
# AI-17 — 404 on unknown endpoint
# ════════════════════════════════════════════════════════════
def test_ai17_unknown_endpoint_returns_404(client):
    res  = client.get("/api/nonexistent")
    data = json.loads(res.data)
    assert res.status_code == 404
    assert data["success"] is False


# ════════════════════════════════════════════════════════════
# AI-18 — Brute-force pattern correctly scored HIGH or CRITICAL
# ════════════════════════════════════════════════════════════
def test_ai18_brute_force_high_or_critical(client):
    payload = {
        "ip_address":      "1.2.3.4",
        "username":        "root",
        "status":          "Failed",
        "failed_attempts": 40,
        "port":            22,
        "hour":            3,
    }
    res  = post_analyse(client, payload)
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["result"]["threat_level"] in ("HIGH", "CRITICAL")
    assert data["result"]["threat_score"] >= 51


# ════════════════════════════════════════════════════════════
# AI-19 — Normal login correctly scored LOW or MEDIUM
# ════════════════════════════════════════════════════════════
def test_ai19_normal_login_low_or_medium(client):
    payload = {
        "ip_address":      "192.168.1.5",
        "username":        "alice",
        "status":          "Accepted",
        "failed_attempts": 0,
        "port":            52341,
        "hour":            10,
    }
    res  = post_analyse(client, payload)
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["result"]["threat_score"] <= 50


# ════════════════════════════════════════════════════════════
# AI-20 — Timeline entries have correct structure
# ════════════════════════════════════════════════════════════
def test_ai20_timeline_entry_structure(client):
    res  = client.get("/api/threats/timeline")
    data = json.loads(res.data)
    assert res.status_code == 200
    for entry in data["data"]:
        assert "hour"      in entry
        assert "label"     in entry
        assert "total"     in entry
        assert "anomalies" in entry
        assert "avg_score" in entry
        assert entry["label"] == f"{entry['hour']:02d}:00"


# ════════════════════════════════════════════════════════════
# AI-21 — Top-IPs entries contain required fields
# ════════════════════════════════════════════════════════════
def test_ai21_top_ips_entry_structure(client):
    res  = client.get("/api/threats/top-ips")
    data = json.loads(res.data)
    assert res.status_code == 200
    for entry in data["data"]:
        assert "ip_address"      in entry
        assert "total_attempts"  in entry
        assert "max_score"       in entry
        assert "highest_level"   in entry

