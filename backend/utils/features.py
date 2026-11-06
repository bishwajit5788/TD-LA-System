
from collections import defaultdict, deque

import pandas as pd


FEATURE_COLUMNS = [
    "failed_attempts_5m",
    "failed_attempts_15m",
    "ip_events_5m",
    "ip_events_15m",
    "unique_usernames_15m",
    "failure_rate_15m",
    "is_privileged_account",
    "is_night_hour",
    "time_since_previous_event",
    "success_after_failures_15m",
    "is_failed_event",
]

PRIVILEGED_USERS = {
    "root",
    "admin",
    "administrator",
}


def engineer_features(df):
    """
    Generate causal, time-aware authentication features.

    Only events strictly earlier than the current event timestamp
    contribute to historical features.

    Events sharing the same timestamp are processed together, so
    they cannot influence one another.

    Ground-truth labels and scenario identifiers are never used.
    The original row order and index are preserved.
    """

    required = {
        "timestamp",
        "ip_address",
        "username",
        "status",
    }

    missing = required.difference(df.columns)

    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    if df.empty:
        return pd.DataFrame(
            index=df.index,
            columns=FEATURE_COLUMNS
        ).astype(float)

    work = df[
        ["timestamp", "ip_address", "username", "status"]
    ].copy()

    work["_position"] = range(len(work))

    work["_timestamp"] = pd.to_datetime(
        work["timestamp"],
        errors="coerce"
    )

    if work["_timestamp"].isna().any():
        raise ValueError(
            "Invalid or missing timestamps found in input data."
        )

    # Normalize identifiers and authentication status.
    work["_ip"] = work["ip_address"].fillna("").astype(str).str.strip()
    work["_username"] = (
        work["username"].fillna("unknown").astype(str).str.strip().str.lower()
    )
    work["_status"] = (
        work["status"].fillna("").astype(str).str.strip().str.lower()
    )

    if not work["_status"].isin({"accepted", "failed"}).all():
        raise ValueError(
            "Status must contain only Accepted or Failed events."
        )

    # Missing IPs must not be grouped into one artificial source.
    work["_ip_key"] = work["_ip"]

    missing_ip = work["_ip_key"] == ""

    work.loc[missing_ip, "_ip_key"] = (
        "__MISSING_IP_" +
        work.loc[missing_ip, "_position"].astype(str)
    )

    # Stable sorting makes processing deterministic.
    work = work.sort_values(
        ["_timestamp", "_position"],
        kind="stable"
    )

    # Each history item: (timestamp, username, is_failed).
    histories = defaultdict(deque)

    results = [None] * len(work)

    five_minutes = pd.Timedelta(minutes=5)
    fifteen_minutes = pd.Timedelta(minutes=15)

    # Process all events sharing a timestamp as a batch.
    for timestamp, timestamp_group in work.groupby(
        "_timestamp",
        sort=True
    ):

        pending_history = defaultdict(list)

        for _, row in timestamp_group.iterrows():

            ip = row["_ip_key"]
            username = row["_username"]
            status = row["_status"]

            history = histories[ip]

            cutoff_15m = timestamp - fifteen_minutes
            cutoff_5m = timestamp - five_minutes

            # Remove events outside the 15-minute history window.
            while history and history[0][0] < cutoff_15m:
                history.popleft()

            previous_15m = list(history)

            previous_5m = [
                item for item in previous_15m
                if item[0] >= cutoff_5m
            ]

            failed_5m = sum(
                item[2] for item in previous_5m
            )

            failed_15m = sum(
                item[2] for item in previous_15m
            )

            events_5m = len(previous_5m)
            events_15m = len(previous_15m)

            unique_users = len({
                item[1] for item in previous_15m
            })

            failure_rate = (
                failed_15m / events_15m
                if events_15m else 0.0
            )

            previous_event_time = (
                history[-1][0] if history else None
            )

            elapsed = (
                (timestamp - previous_event_time).total_seconds()
                if previous_event_time is not None
                else -1.0
            )

            is_failed = int(status == "failed")

            is_privileged = int(
                username in PRIVILEGED_USERS
            )

            is_night = int(
                timestamp.hour < 5
            )

            # A successful event following at least five
            # previous failures from this same IP.
            success_after_failures = int(
                status == "accepted" and failed_15m >= 5
            )

            results[row["_position"]] = {
                "failed_attempts_5m": failed_5m,
                "failed_attempts_15m": failed_15m,
                "ip_events_5m": events_5m,
                "ip_events_15m": events_15m,
                "unique_usernames_15m": unique_users,
                "failure_rate_15m": failure_rate,
                "is_privileged_account": is_privileged,
                "is_night_hour": is_night,
                "time_since_previous_event": elapsed,
                "success_after_failures_15m": success_after_failures,
                "is_failed_event": is_failed,
            }

            pending_history[ip].append(
                (timestamp, username, is_failed)
            )

        # Update history only after every event at this timestamp
        # has been evaluated.
        for ip, entries in pending_history.items():
            histories[ip].extend(entries)

    result = pd.DataFrame(
        results,
        index=range(len(results)),
        columns=FEATURE_COLUMNS
    )

    result.index = df.index

    return result


def get_feature_names():
    """Return the exact feature order used by the ML model."""
    return FEATURE_COLUMNS.copy()
