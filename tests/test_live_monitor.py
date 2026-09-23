from datetime import datetime, timedelta

from detection.live_monitor import (
    trim_packet_buffer,
    get_new_alerts
)

from models.packet import NetworkPacket
from models.alert import SecurityAlert


def test_trim_packet_buffer():

    now = datetime.now()

    recent_packet = NetworkPacket(
        timestamp=(
            now
            - timedelta(seconds=20)
        ),
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        protocol="TCP"
    )

    old_packet = NetworkPacket(
        timestamp=(
            now
            - timedelta(seconds=90)
        ),
        source_ip="192.168.1.30",
        destination_ip="192.168.1.40",
        protocol="TCP"
    )

    packets = [
        recent_packet,
        old_packet
    ]

    result = trim_packet_buffer(
        packets,
        window_seconds=60,
        current_time=now
    )

    assert len(result) == 1

    assert (
        result[0].source_ip
        == "192.168.1.10"
    )


def test_duplicate_alert_is_filtered():

    now = datetime.now()

    alert = SecurityAlert(
        alert_id="TEST-0001",
        timestamp=now,
        rule_id="NET-001",
        rule_name="Port Scan Detected",
        severity="medium",
        source_ip="192.168.1.50",
        destination_ip="192.168.1.100"
    )

    alert_history = {}

    first_result = get_new_alerts(
        [alert],
        alert_history,
        cooldown_seconds=60,
        current_time=now
    )

    second_result = get_new_alerts(
        [alert],
        alert_history,
        cooldown_seconds=60,
        current_time=(
            now
            + timedelta(seconds=30)
        )
    )

    assert len(first_result) == 1
    assert len(second_result) == 0


def test_alert_allowed_after_cooldown():

    now = datetime.now()

    alert = SecurityAlert(
        alert_id="TEST-0001",
        timestamp=now,
        rule_id="NET-001",
        rule_name="Port Scan Detected",
        severity="medium",
        source_ip="192.168.1.50",
        destination_ip="192.168.1.100"
    )

    alert_history = {}

    first_result = get_new_alerts(
        [alert],
        alert_history,
        cooldown_seconds=60,
        current_time=now
    )

    second_result = get_new_alerts(
        [alert],
        alert_history,
        cooldown_seconds=60,
        current_time=(
            now
            + timedelta(seconds=61)
        )
    )

    assert len(first_result) == 1
    assert len(second_result) == 1


def test_different_alerts_are_allowed():

    now = datetime.now()

    alert_one = SecurityAlert(
        alert_id="TEST-0001",
        timestamp=now,
        rule_id="NET-001",
        rule_name="Port Scan Detected",
        severity="medium",
        source_ip="192.168.1.50",
        destination_ip="192.168.1.100"
    )

    alert_two = SecurityAlert(
        alert_id="TEST-0002",
        timestamp=now,
        rule_id="DNS-001",
        rule_name="Possible DNS Exfiltration",
        severity="high",
        source_ip="192.168.1.50",
        destination_ip="8.8.8.8"
    )

    alert_history = {}

    result = get_new_alerts(
        [
            alert_one,
            alert_two
        ],
        alert_history,
        cooldown_seconds=60,
        current_time=now
    )

    assert len(result) == 2