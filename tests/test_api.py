import sys
import os
import pytest
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import create_app
from backend.utils import database


@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Creates an isolated Flask test client with a temporary SQLite database.
    Production database records are never modified by this fixture.
    """
    test_db = tmp_path / "test_threats.db"

    monkeypatch.setattr(database, "DB_PATH", str(test_db))

    app = create_app()
    app.config["TESTING"] = True

    database.init_database()

    count = database.load_scored_logs_to_db()
    assert count > 0, "Test dataset was not loaded."

    with app.test_client() as test_client:
        yield test_client


# ════════════════════════════════════════════════════════════
# TEST 1 — Home endpoint
# ════════════════════════════════════════════════════════════
def test_home(client):
    """API home endpoint should return 200 and a message."""
    res  = client.get("/")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert "message" in data
    print("✅ Test 1 passed: Home endpoint works")


# ════════════════════════════════════════════════════════════
# TEST 2 — Stats endpoint
# ════════════════════════════════════════════════════════════
def test_stats(client):
    """Stats endpoint should return all required fields."""
    res  = client.get("/api/stats")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["success"] == True
    assert "total_logs"      in data["data"]
    assert "total_anomalies" in data["data"]
    assert "threat_levels"   in data["data"]
    assert data["data"]["total_logs"] > 0
    print("✅ Test 2 passed: Stats endpoint works")


# ════════════════════════════════════════════════════════════
# TEST 3 — Logs endpoint
# ════════════════════════════════════════════════════════════
def test_get_logs(client):
    """Logs endpoint should return a list of log entries."""
    res  = client.get("/api/logs")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["success"] == True
    assert isinstance(data["data"], list)
    assert len(data["data"]) > 0
    print("✅ Test 3 passed: Logs endpoint works")


# ════════════════════════════════════════════════════════════
# TEST 4 — Logs filter by level
# ════════════════════════════════════════════════════════════
def test_get_logs_filtered(client):
    """Logs endpoint should correctly filter by threat level."""
    res  = client.get("/api/logs?level=HIGH")
    data = json.loads(res.data)
    assert res.status_code == 200
    for log in data["data"]:
        assert log["threat_level"] == "HIGH"
    print("✅ Test 4 passed: Log filtering works")


# ════════════════════════════════════════════════════════════
# TEST 5 — Alerts endpoint
# ════════════════════════════════════════════════════════════
def test_get_alerts(client):
    """Alerts endpoint should only return HIGH and CRITICAL alerts."""
    res  = client.get("/api/alerts")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["success"] == True
    for alert in data["data"]:
        assert alert["threat_level"] in ["HIGH", "CRITICAL"]
    print("✅ Test 5 passed: Alerts endpoint works")


# ════════════════════════════════════════════════════════════
# TEST 6 — Timeline endpoint
# ════════════════════════════════════════════════════════════
def test_get_timeline(client):
    """Timeline endpoint should return exactly 24 hour entries."""
    res  = client.get("/api/threats/timeline")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert len(data["data"]) == 24
    print("✅ Test 6 passed: Timeline has 24 hours")


# ════════════════════════════════════════════════════════════
# TEST 7 — Top IPs endpoint
# ════════════════════════════════════════════════════════════
def test_get_top_ips(client):
    """Top IPs endpoint should return at most 10 IPs."""
    res  = client.get("/api/threats/top-ips")
    data = json.loads(res.data)
    assert res.status_code == 200
    assert len(data["data"]) <= 10
    print("✅ Test 7 passed: Top IPs endpoint works")


# ════════════════════════════════════════════════════════════
# TEST 8 — Analyse endpoint with CRITICAL input
# ════════════════════════════════════════════════════════════
def test_analyse_critical(client):
    """A brute force attack should score as HIGH or CRITICAL."""
    payload = {
        "ip_address"     : "1.2.3.4",
        "username"       : "root",
        "status"         : "Failed",
        "failed_attempts": 40,
        "port"           : 22,
        "hour"           : 3
    }
    res  = client.post(
        "/api/analyse",
        data        = json.dumps(payload),
        content_type= "application/json"
    )
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["success"]  == True
    assert data["result"]["threat_score"] >= 50
    assert data["result"]["threat_level"] in ["HIGH", "CRITICAL"]
    print("✅ Test 8 passed: Brute force correctly flagged as HIGH/CRITICAL")


# ════════════════════════════════════════════════════════════
# TEST 9 — Analyse endpoint with safe input
# ════════════════════════════════════════════════════════════
def test_analyse_safe(client):
    """A normal login should score LOW."""
    payload = {
        "ip_address"     : "192.168.1.5",
        "username"       : "alice",
        "status"         : "Accepted",
        "failed_attempts": 1,
        "port"           : 52341,
        "hour"           : 10
    }
    res  = client.post(
        "/api/analyse",
        data        = json.dumps(payload),
        content_type= "application/json"
    )
    data = json.loads(res.data)
    assert res.status_code == 200
    assert data["result"]["threat_score"] <= 50
    print("✅ Test 9 passed: Normal login correctly scored as LOW/MEDIUM")


# ════════════════════════════════════════════════════════════
# TEST 10 — Analyse endpoint with missing fields
# ════════════════════════════════════════════════════════════
def test_analyse_missing_fields(client):
    """Analyse endpoint should return 400 if required fields are missing."""
    payload = {"ip_address": "1.2.3.4"}  # missing username, status, hour
    res     = client.post(
        "/api/analyse",
        data        = json.dumps(payload),
        content_type= "application/json"
    )
    assert res.status_code == 400
    print("✅ Test 10 passed: Missing fields correctly rejected")


# ════════════════════════════════════════════════════════════
# TEST 11 — Threat scorer unit test
# ════════════════════════════════════════════════════════════
def test_threat_scorer():
    """Threat scorer should return correct levels for known inputs."""
    from ml.threat_scorer import calculate_threat_score, get_threat_level

    # Brute force should score high
    brute_force = {
        "failed_attempts" : 40,
        "is_night_hour"   : 1,
        "is_root_attempt" : 1,
        "ip_attempt_count": 80,
        "status_numeric"  : 1,
        "combo_score"     : 4
    }
    score = calculate_threat_score(brute_force, anomaly_score=-0.4)
    assert score >= 70
    assert get_threat_level(score) in ["HIGH", "CRITICAL"]

    # Normal login should score low
    normal = {
        "failed_attempts" : 1,
        "is_night_hour"   : 0,
        "is_root_attempt" : 0,
        "ip_attempt_count": 2,
        "status_numeric"  : 0,
        "combo_score"     : 0
    }
    score = calculate_threat_score(normal, anomaly_score=0.3)
    assert score < 40
    assert get_threat_level(score) in ["LOW", "MEDIUM"]
    print("✅ Test 11 passed: Threat scorer working correctly")


# ════════════════════════════════════════════════════════════
# TEST 12 — Log parser unit test
# ════════════════════════════════════════════════════════════
def test_log_parser():
    """Log parser should load data correctly from CSV."""
    from backend.utils.log_parser import load_and_prepare
    df = load_and_prepare("csv")
    assert len(df) > 0
    assert "ip_address"      in df.columns
    assert "username"        in df.columns
    assert "failed_attempts" in df.columns
    assert "threat_score"    not in df.columns  # scores added later by ML


# ════════════════════════════════════════════════════════════
# TEST 13 — Model quality regression guard
# ════════════════════════════════════════════════════════════
def test_model_quality_does_not_regress():
    """
    Guards against silent degradation of detection quality.
    If a future change to features, training, or scoring quietly
    breaks the model, this test fails instead of letting it slip
    through unnoticed.
    """
    from ml.train_model import train
    from sklearn.metrics import precision_score, recall_score

    _, _, results = train(source="csv")

    y_true = results["is_suspicious"]
    y_pred = (results["threat_score"] >= 51).astype(int)

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)

    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    assert recall >= 0.85, f"Recall dropped to {recall:.2f}, expected at least 0.85"
    assert precision >= 0.25, f"Precision dropped to {precision:.2f}, expected at least 0.25"
    
