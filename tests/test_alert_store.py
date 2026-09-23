from datetime import datetime

from models.alert import SecurityAlert
from storage.alert_store import (
    save_alert,
    get_alerts
)


def test_save_and_get_alert(tmp_path):

    database = tmp_path / "test.db"

    alert = SecurityAlert(
        alert_id="TEST-0001",
        timestamp=datetime.now(),

        rule_id="TEST-001",
        rule_name="Test Alert",

        severity="medium",

        source_ip="192.168.1.50",
        destination_ip="192.168.1.100",

        protocol="TCP",

        description="Test security alert.",

        evidence={
            "test_value": 123
        },

        tactic="Testing",
        technique="Test Technique",
        technique_id="T0000"
    )

    save_alert(
        alert,
        database
    )

    alerts = get_alerts(
        database
    )

    assert len(alerts) == 1

    saved_alert = alerts[0]

    assert saved_alert["alert_id"] == "TEST-0001"
    assert saved_alert["rule_id"] == "TEST-001"
    assert saved_alert["severity"] == "medium"

    assert (
        saved_alert["evidence"]["test_value"]
        == 123
    )