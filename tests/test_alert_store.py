from datetime import datetime

from models.alert import SecurityAlert
from storage.alert_store import (
    save_alert,
    get_alerts,
    save_alerts,
    update_alert_status
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
def test_save_pcap_alert_source(tmp_path):

    db_path = (
        tmp_path
        / "test_alerts.db"
    )

    alert = SecurityAlert(
        alert_id="TEST-PCAP-001",
        timestamp=datetime.now(),
        rule_id="NET-001",
        rule_name="Port Scan Detected",
        severity="medium",
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="TCP"
    )

    save_alerts(
        [alert],
        db_path,
        alert_source="PCAP"
    )

    alerts = get_alerts(
        db_path
    )

    assert len(alerts) == 1

    assert (
        alerts[0]["alert_source"]
        == "PCAP"
    )


def test_save_live_alert_source(tmp_path):

    db_path = (
        tmp_path
        / "test_alerts.db"
    )

    alert = SecurityAlert(
        alert_id="TEST-LIVE-001",
        timestamp=datetime.now(),
        rule_id="DNS-001",
        rule_name="Possible DNS Exfiltration",
        severity="high",
        source_ip="192.168.1.30",
        destination_ip="8.8.8.8",
        protocol="UDP"
    )

    save_alerts(
        [alert],
        db_path,
        alert_source="Live"
    )

    alerts = get_alerts(
        db_path
    )

    assert len(alerts) == 1

    assert (
        alerts[0]["alert_source"]
        == "Live"
    )
def test_same_rule_alerts_are_stored_separately(
    tmp_path
):
    from datetime import datetime

    from models.alert import SecurityAlert

    db_path = (
        tmp_path
        / "test_alerts.db"
    )

    first_alert = SecurityAlert(
        timestamp=datetime.now(),
        rule_id="NET-001",
        rule_name="Port Scan Detected",
        severity="medium",
        source_ip="192.168.1.50",
        destination_ip="192.168.1.100",
        protocol="TCP"
    )

    second_alert = SecurityAlert(
        timestamp=datetime.now(),
        rule_id="NET-001",
        rule_name="Port Scan Detected",
        severity="medium",
        source_ip="192.168.1.50",
        destination_ip="192.168.1.100",
        protocol="TCP"
    )

    save_alerts(
        [
            first_alert,
            second_alert
        ],
        db_path,
        alert_source="Live"
    )

    stored_alerts = get_alerts(
        db_path
    )

    assert len(stored_alerts) == 2

    assert (
        first_alert.alert_id
        != second_alert.alert_id
    )

    stored_ids = [
        alert["alert_id"]
        for alert in stored_alerts
    ]

    assert (
        first_alert.alert_id
        in stored_ids
    )

    assert (
        second_alert.alert_id
        in stored_ids
    )