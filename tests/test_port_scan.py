from datetime import datetime, timedelta

from models.packet import NetworkPacket
from detection.port_scan import detect_port_scans


def test_port_scan_detection():

    packets = []

    start_time = datetime.now()

    # Simulate one host scanning 25 ports
    for i in range(25):

        packet = NetworkPacket(
            timestamp=start_time + timedelta(milliseconds=i * 100),
            source_ip="192.168.1.50",
            destination_ip="192.168.1.100",
            protocol="TCP",
            source_port=50000 + i,
            destination_port=20 + i,
            tcp_flags="S"
        )

        packets.append(packet)

    alerts = detect_port_scans(packets)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "NET-001"
    assert alert.rule_name == "Port Scan Detected"

    assert alert.source_ip == "192.168.1.50"
    assert alert.destination_ip == "192.168.1.100"

    assert alert.evidence["unique_port_count"] == 25

def test_normal_traffic_no_port_scan():

    packets = []

    start_time = datetime.now()

    normal_ports = [
        80,
        443,
        22,
        53
    ]

    for i, port in enumerate(normal_ports):

        packet = NetworkPacket(
            timestamp=start_time + timedelta(seconds=i),
            source_ip="192.168.1.50",
            destination_ip="192.168.1.100",
            protocol="TCP",
            source_port=50000 + i,
            destination_port=port,
            tcp_flags="S"
        )

        packets.append(packet)

    alerts = detect_port_scans(packets)

    assert len(alerts) == 0