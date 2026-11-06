
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# ============================================================
# Synthetic SSH Authentication Dataset Generator
# Version: 2.0
# ============================================================

SEED = 42
DAYS = 7
NORMAL_EVENTS = 7000

OUTPUT_CSV = Path("data/sample_logs.csv")
OUTPUT_LOG = Path("data/auth.log")

START_TIME = datetime(2026, 10, 1, 0, 0, 0)

NORMAL_USERS = [
    "alice", "bob", "charlie", "diana", "eve",
    "frank", "grace", "henry", "iris", "jack"
]

PRIVILEGED_USERS = [
    "root", "admin", "administrator", "test", "guest"
]

# RFC1918 private addresses for simulated internal users.
TRUSTED_IPS = [
    f"10.20.0.{i}" for i in range(10, 50)
]

# Documentation-only IP ranges, not real attack infrastructure.
ATTACKER_IPS = [
    f"198.51.100.{i}" for i in range(10, 40)
]

CONTEXT_IPS = [
    f"10.30.0.{i}" for i in range(10, 20)
]

rng = random.Random(SEED)

events = []
scenario_counter = 0


def random_time():
    """Return a timestamp within the seven-day simulation."""

    offset = rng.randint(0, DAYS * 24 * 60 * 60 - 1)
    return START_TIME + timedelta(seconds=offset)


def new_scenario_id():
    global scenario_counter
    scenario_counter += 1
    return f"SCN-{scenario_counter:05d}"


def add_event(timestamp, ip, username, status,
              attack_type="normal", scenario_id=None):

    events.append({
        "timestamp": timestamp,
        "ip_address": ip,
        "username": username,
        "status": status,
        "source_port": rng.randint(40000, 65000),
        "service": "ssh",
        "service_port": 22,
        "attack_type": attack_type,
        "scenario_id": scenario_id or "",
        "is_suspicious": int(attack_type in {
            "brute_force",
            "password_spray",
            "suspicious_success"
        })
    })


def generate_normal_traffic():
    """Generate ordinary SSH activity."""

    for _ in range(NORMAL_EVENTS):
        timestamp = random_time()
        ip = rng.choice(TRUSTED_IPS)
        username = rng.choice(NORMAL_USERS)

        # Mostly successful logins, with occasional legitimate failures.
        status = "Accepted" if rng.random() < 0.97 else "Failed"

        add_event(
            timestamp,
            ip,
            username,
            status,
            attack_type="normal"
        )


def generate_brute_force():
    """Generate individual failures from one source IP."""

    timestamp = random_time()
    ip = rng.choice(ATTACKER_IPS)
    username = rng.choice(PRIVILEGED_USERS)
    scenario = new_scenario_id()

    attempts = rng.randint(8, 16)

    for _ in range(attempts):
        timestamp += timedelta(seconds=rng.randint(3, 20))

        add_event(
            timestamp,
            ip,
            username,
            "Failed",
            attack_type="brute_force",
            scenario_id=scenario
        )


def generate_password_spray():
    """Generate failures against multiple accounts from one IP."""

    timestamp = random_time()
    ip = rng.choice(ATTACKER_IPS)
    scenario = new_scenario_id()

    targets = rng.sample(
        NORMAL_USERS + PRIVILEGED_USERS,
        rng.randint(10, 14)
    )

    for username in targets:
        timestamp += timedelta(seconds=rng.randint(5, 30))

        add_event(
            timestamp,
            ip,
            username,
            "Failed",
            attack_type="password_spray",
            scenario_id=scenario
        )


def generate_suspicious_success():
    """Generate repeated failures followed by successful login."""

    timestamp = random_time()
    ip = rng.choice(ATTACKER_IPS)
    username = rng.choice(PRIVILEGED_USERS)
    scenario = new_scenario_id()

    for _ in range(rng.randint(4, 8)):
        timestamp += timedelta(seconds=rng.randint(5, 25))

        add_event(
            timestamp,
            ip,
            username,
            "Failed",
            attack_type="suspicious_success",
            scenario_id=scenario
        )

    timestamp += timedelta(seconds=rng.randint(5, 20))

    add_event(
        timestamp,
        ip,
        username,
        "Accepted",
        attack_type="suspicious_success",
        scenario_id=scenario
    )


def generate_context_only_events():
    """
    Generate benign events at unusual hours.

    These are intentionally labelled normal. Night-time activity
    alone must not automatically be treated as malicious.
    """

    for _ in range(35):
        day = rng.randint(0, DAYS - 1)
        hour = rng.choice([0, 1, 2, 3, 4])

        timestamp = START_TIME + timedelta(
            days=day,
            hours=hour,
            minutes=rng.randint(0, 59),
            seconds=rng.randint(0, 59)
        )

        add_event(
            timestamp,
            rng.choice(CONTEXT_IPS),
            rng.choice(NORMAL_USERS),
            "Accepted",
            attack_type="context_only"
        )


def generate_dataset():
    """Generate all scenarios and return chronologically sorted events."""

    generate_normal_traffic()

    # Generate multiple attack sequences across the simulation period.
    for _ in range(45):
        generate_brute_force()

    for _ in range(25):
        generate_password_spray()

    for _ in range(15):
        generate_suspicious_success()

    generate_context_only_events()

    # Sort before assigning stable event identifiers.
    events.sort(key=lambda event: event["timestamp"])

    for index, event in enumerate(events, start=1):
        event["event_id"] = f"EVT-{index:07d}"
        event["hour"] = event["timestamp"].hour
        event["timestamp"] = event["timestamp"].strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    return events


def save_csv(records):
    """Save structured events and ground-truth labels."""

    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)

    columns = [
        "event_id",
        "timestamp",
        "ip_address",
        "username",
        "status",
        "source_port",
        "service",
        "service_port",
        "hour",
        "attack_type",
        "scenario_id",
        "is_suspicious"
    ]

    with OUTPUT_CSV.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)

    print(f"CSV saved: {OUTPUT_CSV} ({len(records)} records)")


def save_auth_log(records):
    """
    Save individual SSH authentication events.

    The port in the auth.log message is the client source port.
    Ground-truth labels remain in the CSV, not the raw log.
    """

    OUTPUT_LOG.parent.mkdir(parents=True, exist_ok=True)

    lines = []

    for index, event in enumerate(records, start=1):
        timestamp = event["timestamp"]
        ip = event["ip_address"]
        username = event["username"]
        port = event["source_port"]

        if event["status"] == "Failed":
            message = (
                f"{timestamp} server sshd[{1000 + index}]: "
                f"Failed password for {username} "
                f"from {ip} port {port} ssh2"
            )
        else:
            message = (
                f"{timestamp} server sshd[{1000 + index}]: "
                f"Accepted password for {username} "
                f"from {ip} port {port} ssh2"
            )

        lines.append(message)

    OUTPUT_LOG.write_text("\n".join(lines) + "\n")

    print(f"Auth log saved: {OUTPUT_LOG} ({len(lines)} lines)")


def print_summary(records):
    """Print generation statistics."""

    total = len(records)
    attacks = sum(event["is_suspicious"] for event in records)
    normal = total - attacks

    print("\n" + "=" * 55)
    print("SYNTHETIC DATASET SUMMARY")
    print("=" * 55)

    print(f"Total events       : {total}")
    print(f"Normal events      : {normal}")
    print(f"Attack-labelled    : {attacks}")
    print(f"Attack proportion  : {attacks / total * 100:.2f}%")

    print("\nScenario distribution:")

    counts = {}

    for event in records:
        name = event["attack_type"]
        counts[name] = counts.get(name, 0) + 1

    for name, count in sorted(counts.items()):
        print(f"{name:<22}: {count}")

    print("\nTimestamp range:")
    print(f"First: {records[0]['timestamp']}")
    print(f"Last : {records[-1]['timestamp']}")

    print("=" * 55)


if __name__ == "__main__":
    print("Generating reproducible SSH authentication dataset...")

    dataset = generate_dataset()

    save_csv(dataset)
    save_auth_log(dataset)
    print_summary(dataset)

    print("\nDataset generation complete.")
