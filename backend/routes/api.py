from flask import Blueprint, jsonify, request
from backend.utils.validation import validate_analyse_input
import sys
import os
from backend.utils.limiter import limiter

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.utils.database import query
from ml.detector import detector

# Blueprint = a mini Flask app we plug into the main app
api = Blueprint("api", __name__)


# ─────────────────────────────────────────────────────────────
# GET /api/logs
# Returns paginated log entries with threat scores (maximum 500).
# Optional: ?limit=50&level=HIGH
# ─────────────────────────────────────────────────────────────
@api.route("/logs", methods=["GET"])
def get_logs():
    limit = request.args.get("limit", 100, type=int)
    level = request.args.get("level", None)

    limit = max(1, min(limit, 500))

    if level:
        rows = query(
            """
            SELECT *
            FROM logs
            WHERE threat_level = ?
            ORDER BY threat_score DESC
            LIMIT ?
            """,
            (level.upper(), limit)
        )
    else:
        rows = query(
            """
            SELECT *
            FROM logs
            ORDER BY threat_score DESC
            LIMIT ?
            """,
            (limit,)
        )

    return jsonify({
        "success": True,
        "count": len(rows),
        "data": rows
    })


# ─────────────────────────────────────────────────────────────
# GET /api/alerts
# Returns only HIGH and CRITICAL alerts
# ─────────────────────────────────────────────────────────────
@api.route("/alerts", methods=["GET"])
def get_alerts():
    limit = request.args.get("limit", 50, type=int)

    limit = max(1, min(limit, 500))

    rows = query(
        """
        SELECT *
        FROM alerts
        WHERE threat_level IN ('HIGH', 'CRITICAL')
        ORDER BY threat_score DESC, created_at DESC
        LIMIT ?
        """,
        (limit,)
    )

    return jsonify({
        "success": True,
        "count": len(rows),
        "data": rows
    })


# ─────────────────────────────────────────────────────────────
# GET /api/stats
# Returns summary statistics for the dashboard cards
# ─────────────────────────────────────────────────────────────
@api.route("/stats", methods=["GET"])
def get_stats():

    # Total logs
    total = query("SELECT COUNT(*) as count FROM logs")[0]["count"]

    # Anomalies
    anomalies = query(
        "SELECT COUNT(*) as count FROM logs WHERE is_anomaly = 1"
    )[0]["count"]

    # Threat level breakdown
    levels = query("""
        SELECT threat_level, COUNT(*) as count
        FROM logs GROUP BY threat_level
    """)
    level_map = {r["threat_level"]: r["count"] for r in levels}

    # Average threat score
    avg_score = query(
        "SELECT AVG(threat_score) as avg FROM logs"
    )[0]["avg"]

    # Highest threat score
    max_score = query(
        "SELECT MAX(threat_score) as max FROM logs"
    )[0]["max"]

    # Total alerts
    total_alerts = query("SELECT COUNT(*) as count FROM alerts")[0]["count"]

    # Unique suspicious IPs
    suspicious_ips = query("""
        SELECT COUNT(DISTINCT ip_address) as count
        FROM logs WHERE threat_level IN ('HIGH','CRITICAL')
    """)[0]["count"]

    return jsonify({
        "success": True,
        "data": {
            "total_logs"     : total,
            "total_anomalies": anomalies,
            "total_alerts"   : total_alerts,
            "suspicious_ips" : suspicious_ips,
            "avg_threat_score": round(avg_score or 0, 1),
            "max_threat_score": max_score or 0,
            "threat_levels"  : {
                "LOW"     : level_map.get("LOW", 0),
                "MEDIUM"  : level_map.get("MEDIUM", 0),
                "HIGH"    : level_map.get("HIGH", 0),
                "CRITICAL": level_map.get("CRITICAL", 0)
            }
        }
    })


# ─────────────────────────────────────────────────────────────
# GET /api/threats/timeline
# Returns threat counts grouped by hour of day (for line chart)
# ─────────────────────────────────────────────────────────────
@api.route("/threats/timeline", methods=["GET"])
def get_timeline():
    rows = query("""
        SELECT hour,
               COUNT(*) as total,
               SUM(is_anomaly) as anomalies,
               AVG(threat_score) as avg_score
        FROM logs
        GROUP BY hour
        ORDER BY hour
    """)

    # Make sure all 24 hours are represented
    hour_map = {r["hour"]: r for r in rows}
    timeline = []
    for h in range(24):
        entry = hour_map.get(h, {
            "hour"     : h,
            "total"    : 0,
            "anomalies": 0,
            "avg_score": 0
        })
        timeline.append({
            "hour"      : h,
            "label"     : f"{h:02d}:00",
            "total"     : entry["total"],
            "anomalies" : int(entry["anomalies"] or 0),
            "avg_score" : round(float(entry["avg_score"] or 0), 1)
        })

    return jsonify({
        "success": True,
        "data"   : timeline
    })


# ─────────────────────────────────────────────────────────────
# GET /api/threats/top-ips
# Returns the most suspicious IP addresses
# ─────────────────────────────────────────────────────────────
@api.route("/threats/top-ips", methods=["GET"])
def get_top_ips():
    rows = query("""
        SELECT
            ip_address,
            COUNT(*) AS total_attempts,
            MAX(threat_score) AS max_score,
            SUM(is_anomaly) AS anomaly_count,
            CASE MAX(
                CASE threat_level
                    WHEN 'CRITICAL' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END
            )
                WHEN 4 THEN 'CRITICAL'
                WHEN 3 THEN 'HIGH'
                WHEN 2 THEN 'MEDIUM'
                WHEN 1 THEN 'LOW'
                ELSE 'UNKNOWN'
            END AS highest_level
        FROM logs
        GROUP BY ip_address
        ORDER BY max_score DESC, total_attempts DESC
        LIMIT 10
    """)

    return jsonify({
        "success": True,
        "data": rows
    })


# ─────────────────────────────────────────────────────────────
# POST /api/analyse
# Accepts a single log entry JSON and returns threat assessment
# ─────────────────────────────────────────────────────────────
@api.route("/analyse", methods=["POST"])
@limiter.limit("10 per minute")
def analyse_log():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Request body must be a valid JSON object."
    }), 400

    required = ["ip_address", "username", "status", "hour"]
    missing  = [f for f in required if f not in data]
    if missing:
        return jsonify({
            "success": False,
            "error"  : f"Missing fields: {missing}"
        }), 400

    # Fill in defaults for optional fields
    entry, validation_errors = validate_analyse_input(data)
    if validation_errors:
        return jsonify({
            "success": False,
            "error"  : "Invalid input",
            "details": validation_errors
        }), 400

    result = detector.analyse_single(entry)

    return jsonify({
        "success" : True,
        "input"   : entry,
        "result"  : result
    })


# ─────────────────────────────────────────────────────────────
# POST /api/reload
# Reloads data from CSV into database (useful after retraining)
# ─────────────────────────────────────────────────────────────
# Retired endpoint: database reload is no longer available through the API.
@api.route("/reload", methods=["POST"])
def reload_data():
    return jsonify({
        "success": False,
        "error": "Database reload endpoint has been retired.",
        "message": "Use a controlled administrative import procedure."
    }), 410