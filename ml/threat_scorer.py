import numpy as np
import pandas as pd

def calculate_threat_score(row, anomaly_score):
    """
    Calculate a threat score from 0 to 100 for a single log entry.

    Inputs:
        row           : one row of the features DataFrame
        anomaly_score : the raw score from Isolation Forest
                        (more negative = more anomalous)

    Output:
        An integer from 0 (completely safe) to 100 (critical threat)

    How scoring works:
        - We start with a base score from the ML model
        - Then add bonus points for specific dangerous behaviours
        - Cap the final result at 100
    """

    # ── Step 1: Convert ML anomaly score to 0–50 base ────────
    # Isolation Forest gives scores roughly between -0.5 and 0.5
    # More negative = more anomalous
    # We flip and scale it to get a 0–50 base score
    base_score = max(0, min(50, (-anomaly_score + 0.5) * 100))

    bonus = 0

    # ── Step 2: Add bonus for brute force ────────────────────
    failed = row.get(
        "reported_failed_attempts",
        row.get("failed_attempts_15m", row.get("failed_attempts", 0)),
    )
    if failed >= 20:
        bonus += 30       # Critical: massive brute force
    elif failed >= 10:
        bonus += 20       # High: significant brute force
    elif failed >= 5:
        bonus += 10       # Medium: some failed attempts
    elif failed >= 3:
        bonus += 5        # Low: a few failures

    # ── Step 3: Add bonus for night-time login ────────────────
    if row.get("is_night_hour", 0) == 1:
        bonus += 10

    # ── Step 4: Add bonus for targeting root/admin ───────────
    if row.get("is_privileged_account", row.get("is_root_attempt", 0)) == 1:
        bonus += 15

    # ── Step 5: Add bonus for high IP activity ───────────────
    ip_count = row.get("ip_events_15m", row.get("ip_attempt_count", 1))
    if ip_count >= 50:
        bonus += 15
    elif ip_count >= 20:
        bonus += 8
    elif ip_count >= 10:
        bonus += 4

    # ── Step 6: Add bonus for failed login ───────────────────
    if row.get("is_failed_event", row.get("status_numeric", 0)) == 1:
        bonus += 5

    # ── Step 7: Add bonus for dangerous combo ─────────────────
    combo = row.get("combo_score", 0)
    if combo >= 3:
        bonus += 20       # Multiple red flags at once
    elif combo >= 2:
        bonus += 10

    # ── Final score ───────────────────────────────────────────
    final_score = min(100, int(base_score + bonus))
    return final_score


def get_threat_level(score):
    """
    Convert a numeric score to a human-readable threat level.

    0–25   → LOW
    26–50  → MEDIUM
    51–75  → HIGH
    76–100 → CRITICAL
    """
    if score >= 76:
        return "CRITICAL"
    elif score >= 51:
        return "HIGH"
    elif score >= 26:
        return "MEDIUM"
    else:
        return "LOW"


def get_threat_color(level):
    """Return a colour for the dashboard based on threat level."""
    colors = {
        "LOW"     : "#22c55e",   # green
        "MEDIUM"  : "#f59e0b",   # amber
        "HIGH"    : "#ef4444",   # red
        "CRITICAL": "#7c3aed"    # purple
    }
    return colors.get(level, "#6b7280")


def score_dataframe(df_features, anomaly_scores):
    """
    Score an entire DataFrame at once.

    Inputs:
        df_features    : features DataFrame from features.py
        anomaly_scores : array of scores from model.decision_function()

    Returns a DataFrame with threat_score and threat_level columns added.
    """
    scores = []
    levels = []
    colors = []

    for i, (_, row) in enumerate(df_features.iterrows()):
        score = calculate_threat_score(row.to_dict(), anomaly_scores[i])
        level = get_threat_level(score)
        color = get_threat_color(level)
        scores.append(score)
        levels.append(level)
        colors.append(color)

    result = df_features.copy()
    result["threat_score"] = scores
    result["threat_level"] = levels
    result["threat_color"] = colors

    return result


if __name__ == "__main__":
    # Quick test with fake data
    print("Testing threat scorer …")

    test_cases = [
        {
            "name"            : "Normal login",
            "failed_attempts" : 1,
            "is_night_hour"   : 0,
            "is_root_attempt" : 0,
            "ip_attempt_count": 2,
            "status_numeric"  : 0,
            "combo_score"     : 0
        },
        {
            "name"            : "Brute force attack",
            "failed_attempts" : 35,
            "is_night_hour"   : 1,
            "is_root_attempt" : 1,
            "ip_attempt_count": 80,
            "status_numeric"  : 1,
            "combo_score"     : 4
        },
        {
            "name"            : "Suspicious night login",
            "failed_attempts" : 3,
            "is_night_hour"   : 1,
            "is_root_attempt" : 0,
            "ip_attempt_count": 5,
            "status_numeric"  : 0,
            "combo_score"     : 1
        }
    ]

    for case in test_cases:
        name = case.pop("name")
        score = calculate_threat_score(case, anomaly_score=-0.3)
        level = get_threat_level(score)
        color = get_threat_color(level)
        print(f"\n  {name}")
        print(f"    Score : {score}/100")
        print(f"    Level : {level}")
        print(f"    Color : {color}")

    print("\n✅ Threat scorer working correctly!")