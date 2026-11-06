"""
Tests C — Temporal Detection
Extended rule engine scenarios not covered by test_rule_engine.py.

Exercises: boundary conditions, cross-IP isolation, missing IPs,
out-of-order events, 15-minute window expiry, duplicate submissions,
and password-spray exact threshold boundary.
"""

import sys
import os
import pytest
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.utils.rule_engine import evaluate_rules


# ─────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────
def make_events(rows):
    """Build a minimal events DataFrame from (timestamp, ip, user, status) tuples."""
    return pd.DataFrame(
        [
            {
                "timestamp": ts,
                "ip_address": ip,
                "username": username,
                "status": status,
            }
            for ts, ip, username, status in rows
        ]
    )


# ════════════════════════════════════════════════════════════
# TD-01 — 7 failures within 5 minutes → no brute_force (re-verify)
# ════════════════════════════════════════════════════════════
def test_td01_seven_failures_no_brute_force():
    """
    7 failures within 5 minutes must NOT trigger brute_force.
    Re-verified in isolation from the baseline suite.
    """
    start = pd.Timestamp("2026-11-01 08:00:00")
    rows = [
        (start + pd.Timedelta(seconds=30 * i), "10.0.0.1", "carol", "Failed")
        for i in range(7)
    ]
    result = evaluate_rules(make_events(rows))
    assert all("brute_force" not in m for m in result["rule_matches"])


# ════════════════════════════════════════════════════════════
# TD-02 — 8 failures within 5 minutes → brute_force
# ════════════════════════════════════════════════════════════
def test_td02_eight_failures_trigger_brute_force():
    """8 failures within 5 minutes must trigger brute_force."""
    start = pd.Timestamp("2026-11-01 08:00:00")
    rows = [
        (start + pd.Timedelta(seconds=30 * i), "10.0.0.2", "carol", "Failed")
        for i in range(8)
    ]
    result = evaluate_rules(make_events(rows))
    assert "brute_force" in result.iloc[-1]["rule_matches"]
    assert result.iloc[-1]["rule_severity"] == "HIGH"


# ════════════════════════════════════════════════════════════
# TD-03 — 8 failures spread across 6 minutes → no brute_force
# ════════════════════════════════════════════════════════════
def test_td03_eight_failures_six_minutes_no_brute_force():
    """8 failures with the first event > 5 minutes before the last must NOT trigger."""
    start = pd.Timestamp("2026-11-01 08:00:00")
    offsets = [0, 50, 100, 150, 200, 250, 300, 360]  # last - first = 360s = 6 min
    rows = [
        (start + pd.Timedelta(seconds=s), "10.0.0.3", "dave", "Failed")
        for s in offsets
    ]
    result = evaluate_rules(make_events(rows))
    assert all("brute_force" not in m for m in result["rule_matches"])


# ════════════════════════════════════════════════════════════
# TD-04 — Exact 5-minute boundary event is included in window
# ════════════════════════════════════════════════════════════
def test_td04_exact_five_minute_boundary_included():
    """An event exactly 5 minutes before the trigger is within the window."""
    start = pd.Timestamp("2026-11-01 08:00:00")
    # First event at t=0, last at t=300 (exactly 5 min later)
    offsets = [0, 40, 80, 120, 160, 200, 260, 300]
    rows = [
        (start + pd.Timedelta(seconds=s), "10.0.0.4", "eve", "Failed")
        for s in offsets
    ]
    result = evaluate_rules(make_events(rows))
    assert "brute_force" in result.iloc[-1]["rule_matches"]


# ════════════════════════════════════════════════════════════
# TD-05 — Password spray — 10 distinct usernames triggers rule
# ════════════════════════════════════════════════════════════
def test_td05_password_spray_ten_usernames():
    """10 distinct failed usernames within 15 minutes must trigger password_spray."""
    start = pd.Timestamp("2026-11-01 09:00:00")
    rows = [
        (start + pd.Timedelta(minutes=i), "10.1.1.1", f"user{i}", "Failed")
        for i in range(10)
    ]
    result = evaluate_rules(make_events(rows))
    assert "password_spray" in result.iloc[-1]["rule_matches"]


# ════════════════════════════════════════════════════════════
# TD-06 — Password spray — only 9 distinct usernames → no trigger
# ════════════════════════════════════════════════════════════
def test_td06_password_spray_nine_usernames_no_trigger():
    """9 distinct failed usernames must NOT trigger password_spray (threshold is 10)."""
    start = pd.Timestamp("2026-11-01 09:00:00")
    rows = [
        (start + pd.Timedelta(minutes=i), "10.1.1.2", f"spray_user{i}", "Failed")
        for i in range(9)
    ]
    result = evaluate_rules(make_events(rows))
    assert all("password_spray" not in m for m in result["rule_matches"])


# ════════════════════════════════════════════════════════════
# TD-07 — Successful login after repeated failures (ordinary)
# ════════════════════════════════════════════════════════════
def test_td07_successful_login_after_failures_ordinary():
    """Ordinary account: 5 failures then Accepted → suspicious_success, severity HIGH."""
    start = pd.Timestamp("2026-11-01 10:00:00")
    rows = [
        (start + pd.Timedelta(minutes=i), "10.2.0.1", "frank", "Failed")
        for i in range(5)
    ]
    rows.append((start + pd.Timedelta(minutes=6), "10.2.0.1", "frank", "Accepted"))
    result = evaluate_rules(make_events(rows))
    final = result.iloc[-1]
    assert "suspicious_success" in final["rule_matches"]
    assert final["rule_severity"] == "HIGH"


# ════════════════════════════════════════════════════════════
# TD-08 — Privileged account success after 4 failures → CRITICAL
# ════════════════════════════════════════════════════════════
def test_td08_privileged_account_success_threshold():
    """Privileged account: 4 failures then Accepted → suspicious_success, severity CRITICAL."""
    start = pd.Timestamp("2026-11-01 10:00:00")
    rows = [
        (start + pd.Timedelta(minutes=i), "10.2.0.2", "root", "Failed")
        for i in range(4)
    ]
    rows.append((start + pd.Timedelta(minutes=5), "10.2.0.2", "root", "Accepted"))
    result = evaluate_rules(make_events(rows))
    final = result.iloc[-1]
    assert "suspicious_success" in final["rule_matches"]
    assert final["rule_severity"] == "CRITICAL"


# ════════════════════════════════════════════════════════════
# TD-09 — Simultaneous events do not influence each other
# ════════════════════════════════════════════════════════════
def test_td09_simultaneous_events_no_cross_influence():
    """
    8 events at the exact same timestamp must not trigger brute_force
    (simultaneous events cannot build on each other's history).
    After adding one more event at t+1m, brute_force fires.
    """
    ts = "2026-11-01 11:00:00"
    rows = [(ts, "10.3.0.1", "grace", "Failed")] * 8
    result = evaluate_rules(make_events(rows))
    # All simultaneous — none should trigger brute_force
    assert all("brute_force" not in m for m in result["rule_matches"])

    # Extend: one event 1 minute later — now has 8 in history
    rows_extended = rows + [("2026-11-01 11:01:00", "10.3.0.1", "grace", "Failed")]
    result2 = evaluate_rules(make_events(rows_extended))
    assert "brute_force" in result2.iloc[-1]["rule_matches"]


# ════════════════════════════════════════════════════════════
# TD-10 — Out-of-order event submission (earlier timestamp appended)
# ════════════════════════════════════════════════════════════
def test_td10_out_of_order_events():
    """
    Events submitted out of chronological order are sorted
    before evaluation and produce identical results to ordered input.
    """
    ordered_rows = [
        ("2026-11-01 12:00:00", "10.4.0.1", "henry", "Failed"),
        ("2026-11-01 12:01:00", "10.4.0.1", "henry", "Failed"),
        ("2026-11-01 12:02:00", "10.4.0.1", "henry", "Failed"),
    ]
    unordered_rows = [
        ("2026-11-01 12:02:00", "10.4.0.1", "henry", "Failed"),
        ("2026-11-01 12:00:00", "10.4.0.1", "henry", "Failed"),
        ("2026-11-01 12:01:00", "10.4.0.1", "henry", "Failed"),
    ]
    ordered_result = evaluate_rules(make_events(ordered_rows))
    unordered_result = evaluate_rules(make_events(unordered_rows))

    # Rule matches should be the same regardless of input order
    # (rule engine sorts internally)
    ordered_matches = set(
        tuple(m) for m in ordered_result["rule_matches"]
    )
    unordered_matches = set(
        tuple(m) for m in unordered_result["rule_matches"]
    )
    assert ordered_matches == unordered_matches


# ════════════════════════════════════════════════════════════
# TD-11 — Events from different IPs are isolated
# ════════════════════════════════════════════════════════════
def test_td11_different_ip_isolation():
    """
    8 failures split across 2 IP addresses (4 each) must NOT trigger
    brute_force — the rule is per-IP.
    """
    start = pd.Timestamp("2026-11-01 13:00:00")
    rows = []
    for i in range(4):
        rows.append((start + pd.Timedelta(seconds=30 * i), "10.5.0.1", "ivan", "Failed"))
        rows.append((start + pd.Timedelta(seconds=30 * i + 15), "10.5.0.2", "ivan", "Failed"))

    result = evaluate_rules(make_events(rows))
    assert all("brute_force" not in m for m in result["rule_matches"])


# ════════════════════════════════════════════════════════════
# TD-12 — Missing IP addresses are isolated from each other
# ════════════════════════════════════════════════════════════
def test_td12_missing_ip_events_not_grouped():
    """
    Events with empty-string IP addresses must each be treated
    as a separate source — 8 such events must NOT trigger brute_force.
    """
    start = pd.Timestamp("2026-11-01 14:00:00")
    rows = [
        (start + pd.Timedelta(seconds=30 * i), "", "jake", "Failed")
        for i in range(8)
    ]
    result = evaluate_rules(make_events(rows))
    assert all("brute_force" not in m for m in result["rule_matches"])


# ════════════════════════════════════════════════════════════
# TD-13 — Events older than 15 minutes expire from window
# ════════════════════════════════════════════════════════════
def test_td13_events_outside_15_minute_window_expire():
    """
    7 failures 20 minutes before the 8th failure should NOT contribute
    to the 5-minute brute_force window, so no alert fires.
    """
    rows = [
        ("2026-11-01 15:00:00", "10.6.0.1", "kate", "Failed"),  # 20 min old
        ("2026-11-01 15:01:00", "10.6.0.1", "kate", "Failed"),
        ("2026-11-01 15:02:00", "10.6.0.1", "kate", "Failed"),
        ("2026-11-01 15:03:00", "10.6.0.1", "kate", "Failed"),
        ("2026-11-01 15:04:00", "10.6.0.1", "kate", "Failed"),
        ("2026-11-01 15:05:00", "10.6.0.1", "kate", "Failed"),
        ("2026-11-01 15:06:00", "10.6.0.1", "kate", "Failed"),
        # Gap of 20 minutes — previous events all expire from 15m window
        ("2026-11-01 15:26:00", "10.6.0.1", "kate", "Failed"),
    ]
    result = evaluate_rules(make_events(rows))
    # The 8th event's 5-minute window contains only itself
    assert "brute_force" not in result.iloc[-1]["rule_matches"]


# ════════════════════════════════════════════════════════════
# TD-14 — Duplicate event submissions
# ════════════════════════════════════════════════════════════
def test_td14_duplicate_event_submissions():
    """
    Submitting the same event data twice counts as two separate events.
    8 identical events (same timestamp) remain simultaneous and
    should NOT trigger brute_force on their own.
    """
    ts = "2026-11-01 16:00:00"
    rows = [(ts, "10.7.0.1", "leo", "Failed")] * 8
    result = evaluate_rules(make_events(rows))
    # All at same timestamp — simultaneous, so no brute_force
    assert all("brute_force" not in m for m in result["rule_matches"])


# ════════════════════════════════════════════════════════════
# TD-15 — Brute force window resets after 15 minutes of silence
# ════════════════════════════════════════════════════════════
def test_td15_window_resets_after_silence():
    """
    After 15 minutes of silence, the history window is empty.
    A new burst starting from scratch must not carry over old failures.
    """
    start = pd.Timestamp("2026-11-01 17:00:00")
    # 7 failures — not enough to trigger
    phase1 = [
        (start + pd.Timedelta(seconds=30 * i), "10.8.0.1", "mia", "Failed")
        for i in range(7)
    ]
    # 20-minute gap — all history expires
    gap_start = start + pd.Timedelta(minutes=20)
    # Only 1 new failure — definitely not enough
    phase2 = [
        (gap_start + pd.Timedelta(seconds=10), "10.8.0.1", "mia", "Failed")
    ]
    result = evaluate_rules(make_events(phase1 + phase2))
    assert "brute_force" not in result.iloc[-1]["rule_matches"]

