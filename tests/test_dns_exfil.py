from datetime import datetime

from models.packet import NetworkPacket
from datetime import datetime, timedelta
from detection.dns_exfil import (
    calculate_entropy,
    detect_dns_exfiltration
)


def test_entropy():

    low_entropy = calculate_entropy(
        "aaaaaaaaaaaaaaaaaaaa"
    )

    high_entropy = calculate_entropy(
        "a8dk29flm92kx7qp4mnz"
    )

    assert high_entropy > low_entropy


def test_suspicious_dns_query():

    packet = NetworkPacket(
        timestamp=datetime.now(),

        source_ip="192.168.1.50",
        destination_ip="8.8.8.8",

        protocol="UDP",

        source_port=53000,
        destination_port=53,

        dns_query=(
            "a8dk29flm92kx7qp4mnz7q2w9e8r5t6y"
            "u3i4o7p8a1s2d3f4.example.com"
        )
    )

    alerts = detect_dns_exfiltration([packet])

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "DNS-001"
    assert alert.severity == "high"
    assert alert.source_ip == "192.168.1.50"
def test_normal_dns_query():

    packet = NetworkPacket(
        timestamp=datetime.now(),

        source_ip="192.168.1.50",
        destination_ip="8.8.8.8",

        protocol="UDP",

        source_port=53000,
        destination_port=53,

        dns_query="www.example.com"
    )

    alerts = detect_dns_exfiltration([packet])

    assert len(alerts) == 0
def test_high_dns_frequency():

    packets = []

    start_time = datetime.now()

    for i in range(25):

        packet = NetworkPacket(
            timestamp=start_time + timedelta(seconds=i),

            source_ip="192.168.1.75",
            destination_ip="8.8.8.8",

            protocol="UDP",

            source_port=53000 + i,
            destination_port=53,

            dns_query=f"host{i}.example.com"
        )

        packets.append(packet)

    alerts = detect_dns_exfiltration(packets)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "DNS-001"
    assert alert.evidence["query_count"] >= 20