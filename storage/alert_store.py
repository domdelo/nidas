import json
import sqlite3
from pathlib import Path

from models.alert import SecurityAlert


DEFAULT_DB_PATH = Path("data/nidas.db")


def initialize_database(db_path=DEFAULT_DB_PATH):
    db_path = Path(db_path)

    db_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(db_path)

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            alert_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,

            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,

            severity TEXT NOT NULL,

            source_ip TEXT,
            destination_ip TEXT,

            protocol TEXT,

            description TEXT,

            evidence TEXT,

            tactic TEXT,
            technique TEXT,
            technique_id TEXT,

            status TEXT NOT NULL DEFAULT 'New'
        )
        """
    )

    connection.commit()
    connection.close()


def save_alert(alert, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)

    connection = sqlite3.connect(db_path)

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT or IGNORE INTO alerts (
            alert_id,
            timestamp,
            rule_id,
            rule_name,
            severity,
            source_ip,
            destination_ip,
            protocol,
            description,
            evidence,
            tactic,
            technique,
            technique_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.alert_id,
            alert.timestamp.isoformat(),
            alert.rule_id,
            alert.rule_name,
            alert.severity,
            alert.source_ip,
            alert.destination_ip,
            alert.protocol,
            alert.description,
            json.dumps(alert.evidence),
            alert.tactic,
            alert.technique,
            alert.technique_id
        )
    )

    connection.commit()
    connection.close()


def save_alerts(alerts, db_path=DEFAULT_DB_PATH):

    for alert in alerts:
        save_alert(
            alert,
            db_path
        )
def get_alerts(db_path=DEFAULT_DB_PATH):

    initialize_database(db_path)

    connection = sqlite3.connect(db_path)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY timestamp DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()

    alerts = []

    for row in rows:
        alert = dict(row)

        if alert["evidence"]:
            alert["evidence"] = json.loads(
                alert["evidence"]
            )

        alerts.append(alert)

    return alerts
def update_alert_status(
    alert_id,
    status,
    db_path=DEFAULT_DB_PATH
):
    allowed_statuses = [
        "New",
        "Investigating",
        "Resolved"
    ]

    if status not in allowed_statuses:
        raise ValueError(
            f"Invalid alert status: {status}"
        )

    initialize_database(db_path)

    connection = sqlite3.connect(db_path)

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE alerts
        SET status = ?
        WHERE alert_id = ?
        """,
        (
            status,
            alert_id
        )
    )

    connection.commit()
    connection.close()