"""Causal, evidence-based rules for authentication threat detection."""

from collections import defaultdict, deque

import pandas as pd


RULE_THRESHOLDS = {
    "brute_force": 8,
    "password_spray": 10,
    "suspicious_success": 5,
    "privileged_suspicious_success": 4,
    "privileged_targeting": 3,
}

PRIVILEGED_USERS = {"root", "admin", "administrator"}

RULE_SEVERITY = {
    "brute_force": ("HIGH", 75),
    "password_spray": ("HIGH", 80),
    "suspicious_success": ("CRITICAL", 90),
    "privileged_targeting": ("MEDIUM", 60),
}


def evaluate_rules(events):
    """
    Evaluate authentication events using causal, per-IP history.

    Required columns:
        timestamp, ip_address, username, status

    Ground-truth labels and scenario identifiers are never used.

    Returns one result row per input event, preserving input order.
    Events sharing a timestamp cannot influence one another.
    """

    required = {"timestamp", "ip_address", "username", "status"}
    missing = required.difference(events.columns)

    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    output_columns = [
        "rule_matches",
        "rule_evidence",
        "context_flags",
        "rule_score",
        "rule_severity",
        "is_rule_alert",
    ]

    if events.empty:
        return pd.DataFrame(index=events.index, columns=output_columns)

    work = events[
        ["timestamp", "ip_address", "username", "status"]
    ].copy()

    work["_position"] = range(len(work))
    work["_timestamp"] = pd.to_datetime(
        work["timestamp"], errors="coerce"
    )

    if work["_timestamp"].isna().any():
        raise ValueError("Invalid or missing timestamps found.")

    work["_ip"] = (
        work["ip_address"].fillna("").astype(str).str.strip()
    )
    work["_username"] = (
        work["username"].fillna("unknown")
        .astype(str).str.strip().str.lower()
    )
    work["_status"] = (
        work["status"].fillna("")
        .astype(str).str.strip().str.lower()
    )

    if not work["_status"].isin({"accepted", "failed"}).all():
        raise ValueError("Status must contain only Accepted or Failed.")

    # Keep missing IP events isolated from one another.
    work["_ip_key"] = work["_ip"]
    missing_ip = work["_ip_key"] == ""
    work.loc[missing_ip, "_ip_key"] = (
        "__MISSING_IP_" + work.loc[missing_ip, "_position"].astype(str)
    )

    work = work.sort_values(
        ["_timestamp", "_position"], kind="stable"
    )

    # History entry: (timestamp, username, is_failed)
    histories = defaultdict(deque)
    results = [None] * len(work)

    window_5m = pd.Timedelta(minutes=5)
    window_15m = pd.Timedelta(minutes=15)

    for timestamp, group in work.groupby("_timestamp", sort=True):
        pending = defaultdict(list)

        for _, row in group.iterrows():
            ip = row["_ip_key"]
            username = row["_username"]
            status = row["_status"]
            is_failed = status == "failed"

            history = histories[ip]

            cutoff_5m = timestamp - window_5m
            cutoff_15m = timestamp - window_15m

            while history and history[0][0] < cutoff_15m:
                history.popleft()

            previous_15m = list(history)

            previous_5m = [
                item for item in previous_15m
                if item[0] >= cutoff_5m
            ]

            previous_failed_5m = sum(
                item[2] for item in previous_5m
            )

            previous_failed_15m = sum(
                item[2] for item in previous_15m
            )

            # Current failed event counts toward attempt thresholds.
            current_failed = int(is_failed)

            failed_5m = previous_failed_5m + current_failed
            failed_15m = previous_failed_15m + current_failed

            failed_usernames = {
                item[1]
                for item in previous_15m
                if item[2]
            }

            if is_failed:
                failed_usernames.add(username)

            same_user_failures_5m = sum(
                1 for item in previous_5m
                if item[1] == username and item[2]
            ) + current_failed

            same_user_failures_15m = sum(
                1 for item in previous_15m
                if item[1] == username and item[2]
            ) + current_failed

            matches = []
            evidence = []
            context_flags = []

            match_severities = []

            def add_rule(
                rule_id,
                details,
                severity_override=None,
                score_override=None,
            ):
                default_severity, default_score = RULE_SEVERITY[rule_id]

                severity = severity_override or default_severity
                score = (
                    score_override
                    if score_override is not None
                    else default_score
                )

                matches.append(rule_id)
                evidence.append({
                    "rule": rule_id,
                    "severity": severity,
                    "description": details,
                })
                match_severities.append((score, severity))

            # Rule 1: repeated failures against the same username.
            if same_user_failures_5m >= RULE_THRESHOLDS["brute_force"]:
                add_rule(
                    "brute_force",
                    f"{same_user_failures_5m} failed login attempts against "
                    f"account '{username}' within 5 minutes."
                )

            # Rule 2: failures targeting multiple usernames.
            if len(failed_usernames) >= RULE_THRESHOLDS["password_spray"]:
                add_rule(
                    "password_spray",
                    f"{len(failed_usernames)} distinct usernames "
                    "received failed logins within 15 minutes."
                )

            # Rule 3: successful login after repeated failures.
            # Privileged accounts use a stricter detection threshold.
            is_privileged = username in PRIVILEGED_USERS

            success_threshold = (
                RULE_THRESHOLDS["privileged_suspicious_success"]
                if is_privileged
                else RULE_THRESHOLDS["suspicious_success"]
            )

            if (
                status == "accepted"
                and same_user_failures_15m >= success_threshold
            ):
                if is_privileged:
                    success_severity = "CRITICAL"
                    success_score = 90
                else:
                    success_severity = "HIGH"
                    success_score = 75

                add_rule(
                    "suspicious_success",
                    f"Successful login to account '{username}' followed "
                    f"{same_user_failures_15m} failures against the same account "
                    f"within 15 minutes. Account category: "
                    f"{'privileged' if is_privileged else 'ordinary'}.",
                    severity_override=success_severity,
                    score_override=success_score,
                )

            # Rule 4: repeated failures against the same privileged user.
            if (
                is_failed
                and username in PRIVILEGED_USERS
                and same_user_failures_15m
                >= RULE_THRESHOLDS["privileged_targeting"]
            ):
                add_rule(
                    "privileged_targeting",
                    f"{same_user_failures_15m} failures against "
                    f"privileged account '{username}' within 15 minutes."
                )

            # Context is recorded separately, never treated as an attack.
            if timestamp.hour < 5:
                context_flags.append("nighttime_activity")

            score, severity_label = max(
                match_severities,
                key=lambda item: item[0],
                default=(0, "NONE"),
            )

            results[row["_position"]] = {
                "rule_matches": matches,
                "rule_evidence": evidence,
                "context_flags": context_flags,
                "rule_score": score,
                "rule_severity": severity_label,
                "is_rule_alert": bool(matches),
            }

            # Do not update history until all simultaneous events
            # have been evaluated.
            pending[ip].append(
                (timestamp, username, current_failed)
            )

        for ip, entries in pending.items():
            histories[ip].extend(entries)

    result = pd.DataFrame(
        results,
        columns=output_columns,
    )
    result.index = events.index

    return result
