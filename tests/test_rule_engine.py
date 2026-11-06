import pandas as pd
import pytest

from backend.utils.rule_engine import evaluate_rules


def make_events(rows):
    return pd.DataFrame([
        {
            "timestamp": timestamp,
            "ip_address": ip,
            "username": username,
            "status": status,
        }
        for timestamp, ip, username, status in rows
    ])


def test_brute_force_detection():
    rows = [
        (
            f"2026-10-01 10:00:{i:02d}",
            "198.51.100.10",
            "alice",
            "Failed",
        )
        for i in range(8)
    ]

    result = evaluate_rules(make_events(rows))

    assert "brute_force" in result.iloc[-1]["rule_matches"]
    assert result.iloc[-1]["rule_severity"] == "HIGH"


def test_password_spray_detection():
    rows = [
        (
            f"2026-10-01 10:{i:02d}:00",
            "198.51.100.20",
            f"user{i}",
            "Failed",
        )
        for i in range(10)
    ]

    result = evaluate_rules(make_events(rows))

    assert "password_spray" in result.iloc[-1]["rule_matches"]


def test_suspicious_success_detection():
    rows = [
        (
            f"2026-10-01 10:0{i}:00",
            "198.51.100.30",
            "alice",
            "Failed",
        )
        for i in range(5)
    ]

    rows.append((
        "2026-10-01 10:06:00",
        "198.51.100.30",
        "alice",
        "Accepted",
    ))

    result = evaluate_rules(make_events(rows))

    assert (
        "suspicious_success"
        in result.iloc[-1]["rule_matches"]
    )
    assert result.iloc[-1]["rule_severity"] == "HIGH"


def test_privileged_account_targeting():
    rows = [
        (
            f"2026-10-01 10:0{i}:00",
            "198.51.100.40",
            "root",
            "Failed",
        )
        for i in range(3)
    ]

    result = evaluate_rules(make_events(rows))

    assert (
        "privileged_targeting"
        in result.iloc[-1]["rule_matches"]
    )
    assert result.iloc[-1]["rule_severity"] == "MEDIUM"


def test_nighttime_alone_does_not_trigger_alert():
    events = make_events([
        (
            "2026-10-01 02:00:00",
            "10.20.0.10",
            "alice",
            "Accepted",
        )
    ])

    result = evaluate_rules(events)

    assert result.iloc[0]["context_flags"] == [
        "nighttime_activity"
    ]
    assert result.iloc[0]["rule_matches"] == []
    assert not bool(result.iloc[0]["is_rule_alert"])


def test_simultaneous_events_do_not_influence_each_other():
    rows = [
        (
            "2026-10-01 10:00:00",
            "198.51.100.50",
            "alice",
            "Failed",
        )
        for _ in range(8)
    ]

    result = evaluate_rules(make_events(rows))

    assert all(
        "brute_force" not in matches
        for matches in result["rule_matches"]
    )

    next_event = make_events(rows + [
        (
            "2026-10-01 10:01:00",
            "198.51.100.50",
            "alice",
            "Failed",
        )
    ])

    extended_result = evaluate_rules(next_event)

    assert (
        "brute_force"
        in extended_result.iloc[-1]["rule_matches"]
    )


def test_future_events_do_not_change_past_results():
    base = make_events([
        (
            "2026-10-01 10:00:00",
            "198.51.100.60",
            "alice",
            "Failed",
        ),
        (
            "2026-10-01 10:01:00",
            "198.51.100.60",
            "alice",
            "Failed",
        ),
    ])

    extended = make_events([
        (
            "2026-10-01 10:00:00",
            "198.51.100.60",
            "alice",
            "Failed",
        ),
        (
            "2026-10-01 10:01:00",
            "198.51.100.60",
            "alice",
            "Failed",
        ),
        (
            "2026-10-01 10:02:00",
            "198.51.100.60",
            "root",
            "Failed",
        ),
    ])

    original_result = evaluate_rules(base)
    extended_result = evaluate_rules(extended)

    pd.testing.assert_frame_equal(
        original_result.reset_index(drop=True),
        extended_result.iloc[:2].reset_index(drop=True),
    )


def test_invalid_status_is_rejected():
    events = make_events([
        (
            "2026-10-01 10:00:00",
            "198.51.100.70",
            "alice",
            "Unknown",
        )
    ])

    with pytest.raises(ValueError):
        evaluate_rules(events)


def test_missing_required_column_is_rejected():
    events = pd.DataFrame([
        {
            "timestamp": "2026-10-01 10:00:00",
            "ip_address": "198.51.100.80",
            "status": "Failed",
        }
    ])

    with pytest.raises(ValueError):
        evaluate_rules(events)


def test_privileged_success_after_four_failures_is_critical():
    rows = [
        (
            f"2026-10-01 10:0{i}:00",
            "198.51.100.60",
            "root",
            "Failed",
        )
        for i in range(4)
    ]

    rows.append((
        "2026-10-01 10:05:00",
        "198.51.100.60",
        "root",
        "Accepted",
    ))

    result = evaluate_rules(make_events(rows))
    final = result.iloc[-1]

    assert "suspicious_success" in final["rule_matches"]
    assert final["rule_severity"] == "CRITICAL"


def test_ordinary_account_four_failures_does_not_trigger_success_rule():
    rows = [
        (
            f"2026-10-01 10:0{i}:00",
            "198.51.100.61",
            "alice",
            "Failed",
        )
        for i in range(4)
    ]

    rows.append((
        "2026-10-01 10:05:00",
        "198.51.100.61",
        "alice",
        "Accepted",
    ))

    result = evaluate_rules(make_events(rows))

    assert "suspicious_success" not in result.iloc[-1]["rule_matches"]


def test_ordinary_account_five_failures_triggers_success_rule():
    rows = [
        (
            f"2026-10-01 10:0{i}:00",
            "198.51.100.62",
            "alice",
            "Failed",
        )
        for i in range(5)
    ]

    rows.append((
        "2026-10-01 10:06:00",
        "198.51.100.62",
        "alice",
        "Accepted",
    ))

    result = evaluate_rules(make_events(rows))

    assert "suspicious_success" in result.iloc[-1]["rule_matches"]
    assert result.iloc[-1]["rule_severity"] == "HIGH"


def test_privileged_success_after_three_failures_does_not_trigger_success_rule():
    rows = [
        (
            f"2026-10-01 10:0{i}:00",
            "198.51.100.63",
            "administrator",
            "Failed",
        )
        for i in range(3)
    ]

    rows.append((
        "2026-10-01 10:04:00",
        "198.51.100.63",
        "administrator",
        "Accepted",
    ))

    result = evaluate_rules(make_events(rows))

    assert "suspicious_success" not in result.iloc[-1]["rule_matches"]


def test_seven_failures_within_five_minutes_do_not_trigger_brute_force():
    start = pd.Timestamp("2026-10-01 10:00:00")
    rows = [
        (
            start + pd.Timedelta(seconds=30 * i),
            "198.51.100.90",
            "alice",
            "Failed",
        )
        for i in range(7)
    ]

    result = evaluate_rules(make_events(rows))

    assert all(
        "brute_force" not in matches
        for matches in result["rule_matches"]
    )


def test_eight_failures_within_five_minutes_trigger_brute_force():
    start = pd.Timestamp("2026-10-01 10:00:00")
    rows = [
        (
            start + pd.Timedelta(seconds=30 * i),
            "198.51.100.91",
            "alice",
            "Failed",
        )
        for i in range(8)
    ]

    result = evaluate_rules(make_events(rows))

    assert "brute_force" in result.iloc[-1]["rule_matches"]
    assert result.iloc[-1]["rule_severity"] == "HIGH"
    assert "8 failed login attempts" in (
        result.iloc[-1]["rule_evidence"][0]["description"]
    )


def test_eight_failures_spread_over_six_minutes_do_not_trigger_brute_force():
    start = pd.Timestamp("2026-10-01 10:00:00")
    offsets = [0, 50, 100, 150, 200, 250, 300, 360]

    rows = [
        (
            start + pd.Timedelta(seconds=offset),
            "198.51.100.92",
            "alice",
            "Failed",
        )
        for offset in offsets
    ]

    result = evaluate_rules(make_events(rows))

    assert all(
        "brute_force" not in matches
        for matches in result["rule_matches"]
    )


def test_failure_exactly_five_minutes_old_is_included():
    start = pd.Timestamp("2026-10-01 10:00:00")
    offsets = [0, 40, 80, 120, 160, 200, 260, 300]

    rows = [
        (
            start + pd.Timedelta(seconds=offset),
            "198.51.100.93",
            "alice",
            "Failed",
        )
        for offset in offsets
    ]

    result = evaluate_rules(make_events(rows))

    assert "brute_force" in result.iloc[-1]["rule_matches"]
    assert "8 failed login attempts" in (
        result.iloc[-1]["rule_evidence"][0]["description"]
    )

