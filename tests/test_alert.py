from datetime import datetime

from models.alert import SecurityAlert


def test_alert_generates_unique_id():

    alert_one = SecurityAlert(
        timestamp=datetime.now(),
        rule_id="NET-001",
        rule_name="Port Scan Detected",
        severity="medium"
    )

    alert_two = SecurityAlert(
        timestamp=datetime.now(),
        rule_id="NET-001",
        rule_name="Port Scan Detected",
        severity="medium"
    )

    assert alert_one.alert_id
    assert alert_two.alert_id

    assert (
        alert_one.alert_id
        != alert_two.alert_id
    )


def test_custom_alert_id_is_preserved():

    alert = SecurityAlert(
        alert_id="TEST-001",
        timestamp=datetime.now(),
        rule_id="NET-001",
        rule_name="Port Scan Detected",
        severity="medium"
    )

    assert (
        alert.alert_id
        == "TEST-001"
    )