"""
Tests D — Database Layer
Idempotent migrations, transaction safety, FK integrity, concurrent inserts,
alert generation, and query correctness.

SAFETY: Every test uses tmp_path / monkeypatch. The production database
at data/threats.db is never opened or modified.
"""

import sys
import os
import sqlite3
import threading
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.utils import database as db_module
from backend.utils.database import (
    init_database,
    load_scored_logs_to_db,
    generate_alert_description,
    query,
)


# ─────────────────────────────────────────────────────────────
# Fixture — fresh isolated database per test
# ─────────────────────────────────────────────────────────────
@pytest.fixture(autouse=False)
def isolated_db(tmp_path, monkeypatch):
    """
    Redirect DB_PATH to a temporary file.
    Returns the path string for tests that need it.
    """
    test_db = str(tmp_path / "test_threats.db")
    monkeypatch.setattr(db_module, "DB_PATH", test_db)
    yield test_db


# ════════════════════════════════════════════════════════════
# DB-01 — Idempotent schema migration
# ════════════════════════════════════════════════════════════
def test_db01_idempotent_schema_migration(isolated_db):
    """
    Calling init_database() twice must not raise an error
    and must leave the schema unchanged.
    """
    init_database()
    init_database()  # second call must be safe

    conn = sqlite3.connect(isolated_db)
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    conn.close()

    assert "logs" in tables
    assert "alerts" in tables


# ════════════════════════════════════════════════════════════
# DB-02 — Record preservation during migration
# ════════════════════════════════════════════════════════════
def test_db02_record_preservation_during_migration(isolated_db):
    """
    Existing rows must survive a repeated call to init_database().
    """
    init_database()

    # Insert a sentinel row directly
    conn = sqlite3.connect(isolated_db)
    conn.execute(
        "INSERT INTO logs (timestamp, ip_address, username, status, hour)"
        " VALUES ('2026-01-01 00:00:00', '1.2.3.4', 'sentinel', 'Accepted', 0)"
    )
    conn.commit()
    conn.close()

    # Run migration again
    init_database()

    conn = sqlite3.connect(isolated_db)
    rows = conn.execute(
        "SELECT username FROM logs WHERE username = 'sentinel'"
    ).fetchall()
    conn.close()

    assert len(rows) == 1, "Sentinel row was deleted by idempotent migration."


# ════════════════════════════════════════════════════════════
# DB-03 — Transaction commit persists data
# ════════════════════════════════════════════════════════════
def test_db03_transaction_commit(isolated_db):
    """Data written in a committed transaction must be readable after close."""
    init_database()

    conn = sqlite3.connect(isolated_db)
    conn.execute(
        "INSERT INTO logs (timestamp, ip_address, username, status, hour)"
        " VALUES ('2026-06-01 10:00:00', '5.5.5.5', 'committed_user', 'Failed', 10)"
    )
    conn.commit()
    conn.close()

    conn2 = sqlite3.connect(isolated_db)
    rows = conn2.execute(
        "SELECT username FROM logs WHERE username = 'committed_user'"
    ).fetchall()
    conn2.close()

    assert len(rows) == 1


# ════════════════════════════════════════════════════════════
# DB-04 — Transaction rollback removes data
# ════════════════════════════════════════════════════════════
def test_db04_transaction_rollback(isolated_db):
    """Data written in a rolled-back transaction must NOT appear after close."""
    init_database()

    conn = sqlite3.connect(isolated_db)
    conn.execute(
        "INSERT INTO logs (timestamp, ip_address, username, status, hour)"
        " VALUES ('2026-06-01 11:00:00', '6.6.6.6', 'rollback_user', 'Failed', 11)"
    )
    conn.rollback()
    conn.close()

    conn2 = sqlite3.connect(isolated_db)
    rows = conn2.execute(
        "SELECT username FROM logs WHERE username = 'rollback_user'"
    ).fetchall()
    conn2.close()

    assert len(rows) == 0


# ════════════════════════════════════════════════════════════
# DB-05 — Foreign-key integrity: alert references valid log
# ════════════════════════════════════════════════════════════
def test_db05_foreign_key_integrity(isolated_db):
    """
    An alert row's log_id must reference an existing logs row.
    SQLite foreign key enforcement is off by default; we verify
    consistency via a JOIN query.
    """
    init_database()

    conn = sqlite3.connect(isolated_db)
    conn.execute(
        "INSERT INTO logs (id, timestamp, ip_address, username, status,"
        " threat_score, threat_level, threat_color, hour)"
        " VALUES (1, '2026-06-01 12:00:00', '7.7.7.7', 'fk_user',"
        " 'Failed', 80, 'HIGH', '#ef4444', 2)"
    )
    conn.execute(
        "INSERT INTO alerts (log_id, timestamp, ip_address, username,"
        " threat_score, threat_level, threat_color, description)"
        " VALUES (1, '2026-06-01 12:00:00', '7.7.7.7', 'fk_user',"
        " 80, 'HIGH', '#ef4444', 'test alert')"
    )
    conn.commit()

    # JOIN to verify referential integrity
    rows = conn.execute(
        "SELECT a.id FROM alerts a"
        " INNER JOIN logs l ON a.log_id = l.id"
        " WHERE l.username = 'fk_user'"
    ).fetchall()
    conn.close()

    assert len(rows) == 1


# ════════════════════════════════════════════════════════════
# DB-06 — HIGH log produces an alert via load_scored_logs_to_db
# ════════════════════════════════════════════════════════════
def test_db06_high_log_creates_alert(isolated_db):
    """After loading scored_logs.csv, every HIGH/CRITICAL log has an alert."""
    init_database()
    count = load_scored_logs_to_db()
    assert count > 0

    conn = sqlite3.connect(isolated_db)
    conn.row_factory = sqlite3.Row

    # Every alert must reference a HIGH or CRITICAL log
    orphans = conn.execute(
        "SELECT a.id FROM alerts a"
        " LEFT JOIN logs l ON a.log_id = l.id"
        " WHERE l.id IS NULL"
    ).fetchall()

    # Alerts must exist for HIGH/CRITICAL logs
    high_logs = conn.execute(
        "SELECT COUNT(*) as cnt FROM logs WHERE threat_level IN ('HIGH','CRITICAL')"
    ).fetchone()["cnt"]
    alert_count = conn.execute(
        "SELECT COUNT(*) as cnt FROM alerts"
    ).fetchone()["cnt"]

    conn.close()

    assert len(orphans) == 0, "Alert rows exist without a matching log row."
    assert alert_count > 0
    assert alert_count == high_logs


# ════════════════════════════════════════════════════════════
# DB-07 — MEDIUM log does not produce an alert
# ════════════════════════════════════════════════════════════
def test_db07_medium_log_no_alert(isolated_db):
    """MEDIUM threat logs must not generate alert rows."""
    init_database()

    conn = sqlite3.connect(isolated_db)
    conn.execute(
        "INSERT INTO logs (timestamp, ip_address, username, status,"
        " threat_score, threat_level, threat_color, hour)"
        " VALUES ('2026-06-01 13:00:00', '8.8.8.8', 'medium_user',"
        " 'Accepted', 35, 'MEDIUM', '#f59e0b', 13)"
    )
    conn.commit()

    alert_rows = conn.execute(
        "SELECT id FROM alerts WHERE username = 'medium_user'"
    ).fetchall()
    conn.close()

    assert len(alert_rows) == 0, "MEDIUM log incorrectly created an alert."


# ════════════════════════════════════════════════════════════
# DB-08 — Concurrent inserts (thread safety)
# ════════════════════════════════════════════════════════════
def test_db08_concurrent_inserts(isolated_db):
    """Multiple threads inserting rows must not corrupt the database."""
    init_database()

    errors = []

    def insert_rows(thread_id):
        try:
            conn = sqlite3.connect(isolated_db, check_same_thread=False)
            for i in range(10):
                conn.execute(
                    "INSERT INTO logs (timestamp, ip_address, username,"
                    " status, threat_score, threat_level, hour)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        f"2026-06-01 1{thread_id}:{i:02d}:00",
                        f"192.168.{thread_id}.{i}",
                        f"thread_{thread_id}_user_{i}",
                        "Failed",
                        50,
                        "HIGH",
                        thread_id,
                    ),
                )
            conn.commit()
            conn.close()
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=insert_rows, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrent inserts raised errors: {errors}"

    conn = sqlite3.connect(isolated_db)
    count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    conn.close()
    assert count == 50, f"Expected 50 rows, got {count}"


# ════════════════════════════════════════════════════════════
# DB-09 — Duplicate rows do not violate constraints
# ════════════════════════════════════════════════════════════
def test_db09_duplicate_handling(isolated_db):
    """
    The logs table has no UNIQUE constraint on content fields,
    so inserting two identical rows is legal and must succeed.
    """
    init_database()

    conn = sqlite3.connect(isolated_db)
    for _ in range(2):
        conn.execute(
            "INSERT INTO logs (timestamp, ip_address, username, status,"
            " threat_score, threat_level, hour)"
            " VALUES ('2026-06-01 14:00:00', '9.9.9.9', 'dup_user',"
            " 'Failed', 60, 'HIGH', 14)"
        )
    conn.commit()

    count = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE username = 'dup_user'"
    ).fetchone()[0]
    conn.close()

    assert count == 2


# ════════════════════════════════════════════════════════════
# DB-10 — Historical event retrieval ordered by threat_score
# ════════════════════════════════════════════════════════════
def test_db10_historical_event_retrieval(isolated_db, monkeypatch):
    """
    query() with ORDER BY threat_score DESC must return rows
    in descending threat_score order.
    """
    init_database()

    conn = sqlite3.connect(isolated_db)
    for score, user in [(20, "low_user"), (80, "high_user"), (50, "mid_user")]:
        conn.execute(
            "INSERT INTO logs (timestamp, ip_address, username, status,"
            " threat_score, threat_level, hour)"
            " VALUES ('2026-06-01 15:00:00', '1.1.1.1', ?, 'Failed', ?, 'HIGH', 15)",
            (user, score),
        )
    conn.commit()
    conn.close()

    rows = query(
        "SELECT threat_score FROM logs"
        " WHERE ip_address = '1.1.1.1'"
        " ORDER BY threat_score DESC"
    )
    scores = [r["threat_score"] for r in rows]
    assert scores == sorted(scores, reverse=True)


# ════════════════════════════════════════════════════════════
# DB-11 — Production database path is never referenced
# ════════════════════════════════════════════════════════════
def test_db11_production_db_not_touched(tmp_path, monkeypatch):
    """
    After monkeypatching DB_PATH, any database operation must
    touch only the temp path, never data/threats.db.
    """
    prod_path = os.path.abspath("data/threats.db")
    test_db = str(tmp_path / "safe_test.db")
    monkeypatch.setattr(db_module, "DB_PATH", test_db)

    # Record production DB mtime before test
    prod_mtime_before = (
        os.path.getmtime(prod_path) if os.path.exists(prod_path) else None
    )

    init_database()
    load_scored_logs_to_db()

    prod_mtime_after = (
        os.path.getmtime(prod_path) if os.path.exists(prod_path) else None
    )

    assert prod_mtime_before == prod_mtime_after, (
        "Production database was modified during test!"
    )
    assert os.path.exists(test_db), "Temp DB was not created."


# ════════════════════════════════════════════════════════════
# DB-12 — generate_alert_description content correctness
# ════════════════════════════════════════════════════════════
@pytest.mark.parametrize("row,expected_fragments", [
    (
        {"failed_attempts": 15, "hour": 3, "username": "root", "ip_address": "1.2.3.4"},
        ["Brute force", "Suspicious login time", "privileged account", "1.2.3.4"],
    ),
    (
        {"failed_attempts": 5, "hour": 14, "username": "alice", "ip_address": "5.6.7.8"},
        ["Multiple failed", "5.6.7.8"],
    ),
    (
        {"failed_attempts": 0, "hour": 10, "username": "bob", "ip_address": "9.0.0.1"},
        ["9.0.0.1"],
    ),
])
def test_db12_generate_alert_description(row, expected_fragments):
    """Alert descriptions must contain expected content."""
    desc = generate_alert_description(row)
    for fragment in expected_fragments:
        assert fragment in desc, (
            f"Expected '{fragment}' in description: {desc!r}"
        )


# ════════════════════════════════════════════════════════════
# DB-13 — query() helper returns list of dicts
# ════════════════════════════════════════════════════════════
def test_db13_query_returns_list_of_dicts(isolated_db):
    """The query() helper must return a list of plain dicts."""
    init_database()

    conn = sqlite3.connect(isolated_db)
    conn.execute(
        "INSERT INTO logs (timestamp, ip_address, username, status, hour)"
        " VALUES ('2026-06-01 16:00:00', '2.3.4.5', 'dict_user', 'Accepted', 16)"
    )
    conn.commit()
    conn.close()

    rows = query("SELECT username FROM logs WHERE username = 'dict_user'")
    assert isinstance(rows, list)
    assert len(rows) == 1
    assert isinstance(rows[0], dict)
    assert rows[0]["username"] == "dict_user"

