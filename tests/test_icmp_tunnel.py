from datetime import datetime, timedelta

from models.packet import NetworkPacket
from detection.icmp_tunnel import detect_icmp_tunneling


def test_icmp_tunneling_detection():

    packets = []

    start_time = datetime.now()

    for i in range(15):

        packet = NetworkPacket(
            timestamp=start_time + timedelta(seconds=i),

            source_ip="192.168.1.50",
            destination_ip="192.168.1.100",

            protocol="ICMP",

            packet_size=250,

            icmp_type=8,
            icmp_code=0,

            icmp_payload_size=200
        )

        packets.append(packet)

    alerts = detect_icmp_tunneling(packets)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "ICMP-001"
    assert alert.rule_name == "Possible ICMP Tunneling"
    assert alert.severity == "high"

    assert alert.source_ip == "192.168.1.50"
    assert alert.destination_ip == "192.168.1.100"

    assert alert.evidence["packet_count"] == 15
    assert alert.evidence["average_payload_size"] == 200
def test_normal_icmp_traffic():

    packets = []

    start_time = datetime.now()

    for i in range(5):

        packet = NetworkPacket(
            timestamp=start_time + timedelta(seconds=i),

            source_ip="192.168.1.50",
            destination_ip="192.168.1.100",

            protocol="ICMP",

            packet_size=84,

            icmp_type=8,
            icmp_code=0,

            icmp_payload_size=56
        )

        packets.append(packet)

    alerts = detect_icmp_tunneling(packets)

    assert len(alerts) == 0
def test_single_large_icmp_packet():

    packet = NetworkPacket(
        timestamp=datetime.now(),

        source_ip="192.168.1.50",
        destination_ip="192.168.1.100",

        protocol="ICMP",

        packet_size=550,

        icmp_type=8,
        icmp_code=0,

        icmp_payload_size=500
    )

    alerts = detect_icmp_tunneling([packet])

    assert len(alerts) == 0