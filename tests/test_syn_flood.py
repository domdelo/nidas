from datetime import datetime, timedelta

from models.packet import NetworkPacket
from detection.syn_flood import detect_syn_floods


def test_syn_flood_detection():

    packets = []

    start_time = datetime.now()

    # Simulate 120 SYN packets within a few seconds
    for i in range(120):

        packet = NetworkPacket(
            timestamp=start_time + timedelta(milliseconds=i * 50),
            source_ip="192.168.1.75",
            destination_ip="192.168.1.100",
            protocol="TCP",
            source_port=40000 + i,
            destination_port=80,
            tcp_flags="S"
        )

        packets.append(packet)

    alerts = detect_syn_floods(packets)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "DOS-001"
    assert alert.rule_name == "Possible SYN Flood Detected"
    assert alert.severity == "high"

    assert alert.source_ip == "192.168.1.75"
    assert alert.destination_ip == "192.168.1.100"

    assert alert.evidence["syn_count"] == 120
def test_normal_syn_traffic():

    packets = []

    start_time = datetime.now()

    # A small number of connection attempts
    for i in range(10):

        packet = NetworkPacket(
            timestamp=start_time + timedelta(milliseconds=i * 100),
            source_ip="192.168.1.75",
            destination_ip="192.168.1.100",
            protocol="TCP",
            source_port=40000 + i,
            destination_port=443,
            tcp_flags="S"
        )

        packets.append(packet)

    alerts = detect_syn_floods(packets)

    assert len(alerts) == 0
def test_syn_ack_not_counted():

    packets = []

    start_time = datetime.now()

    for i in range(120):

        packet = NetworkPacket(
            timestamp=start_time + timedelta(milliseconds=i * 50),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.75",
            protocol="TCP",
            source_port=443,
            destination_port=40000 + i,
            tcp_flags="SA"
        )

        packets.append(packet)

    alerts = detect_syn_floods(packets)

    assert len(alerts) == 0