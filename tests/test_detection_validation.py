from datetime import datetime, timedelta

from detection.engine import run_detection
from models.packet import NetworkPacket


def test_benign_tcp_traffic_no_alerts():

    start_time = datetime.now()

    packets = []

    # Simulate a small amount of normal TCP traffic.
    for i in range(5):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=i)
            ),
            source_ip="192.168.1.10",
            destination_ip="192.168.1.20",
            protocol="TCP",
            source_port=50000 + i,
            destination_port=443,
            tcp_flags="PA",
            packet_size=100
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0


def test_benign_port_activity_no_alerts():

    start_time = datetime.now()

    packets = []

    # Contact several ports, but remain below
    # the port-scan detection threshold.
    for i in range(10):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(
                    milliseconds=100 * i
                )
            ),
            source_ip="192.168.1.10",
            destination_ip="192.168.1.20",
            protocol="TCP",
            source_port=50000 + i,
            destination_port=1000 + i,
            tcp_flags="S",
            packet_size=60
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0


def test_benign_syn_activity_no_alerts():

    start_time = datetime.now()

    packets = []

    # Generate SYN activity below the
    # SYN flood threshold.
    for i in range(20):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(
                    milliseconds=100 * i
                )
            ),
            source_ip="192.168.1.30",
            destination_ip="192.168.1.40",
            protocol="TCP",
            source_port=40000 + i,
            destination_port=443,
            tcp_flags="S",
            packet_size=60
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0


def test_benign_dns_queries_no_alerts():

    start_time = datetime.now()

    domains = [
        "google.com",
        "github.com",
        "microsoft.com",
        "python.org",
        "example.com"
    ]

    packets = []

    for i, domain in enumerate(domains):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=i)
            ),
            source_ip="192.168.1.50",
            destination_ip="8.8.8.8",
            protocol="UDP",
            source_port=53000 + i,
            destination_port=53,
            packet_size=80,
            dns_query=domain
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0


def test_benign_icmp_traffic_no_alerts():

    start_time = datetime.now()

    packets = []

    # Normal small ICMP echo requests.
    for i in range(5):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=i)
            ),
            source_ip="192.168.1.60",
            destination_ip="192.168.1.1",
            protocol="ICMP",
            packet_size=64,
            icmp_type=8,
            icmp_code=0,
            icmp_payload_size=32
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0


def test_port_scan_triggers_correct_rule():

    start_time = datetime.now()

    packets = []

    for i in range(20):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(
                    milliseconds=100 * i
                )
            ),
            source_ip="192.168.1.100",
            destination_ip="192.168.1.200",
            protocol="TCP",
            source_port=50000 + i,
            destination_port=1000 + i,
            tcp_flags="S",
            packet_size=60
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    rule_ids = [
        alert.rule_id
        for alert in alerts
    ]

    assert rule_ids == [
        "NET-001"
    ]


def test_syn_flood_triggers_correct_rule():

    start_time = datetime.now()

    packets = []

    for i in range(100):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(
                    milliseconds=50 * i
                )
            ),
            source_ip="192.168.1.110",
            destination_ip="192.168.1.210",
            protocol="TCP",
            source_port=40000 + i,
            destination_port=443,
            tcp_flags="S",
            packet_size=60
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    rule_ids = [
        alert.rule_id
        for alert in alerts
    ]

    assert rule_ids == [
        "DOS-001"
    ]


def test_dns_exfiltration_triggers_correct_rule():

    start_time = datetime.now()

    suspicious_query = (
        "a8f3d9e7c2b6f1a4d8e3c7b2"
        "f9a6d1e8c4b7f2a9d6e3c8b1"
        "f7a4d9e2.example.com"
    )

    packet = NetworkPacket(
        timestamp=start_time,
        source_ip="192.168.1.120",
        destination_ip="8.8.8.8",
        protocol="UDP",
        source_port=53000,
        destination_port=53,
        packet_size=150,
        dns_query=suspicious_query
    )

    alerts = run_detection(
        [packet]
    )

    rule_ids = [
        alert.rule_id
        for alert in alerts
    ]

    assert rule_ids == [
        "DNS-001"
    ]


def test_icmp_tunneling_triggers_correct_rule():

    start_time = datetime.now()

    packets = []

    for i in range(10):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=i)
            ),
            source_ip="192.168.1.130",
            destination_ip="192.168.1.230",
            protocol="ICMP",
            packet_size=200,
            icmp_type=8,
            icmp_code=0,
            icmp_payload_size=150
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    rule_ids = [
        alert.rule_id
        for alert in alerts
    ]

    assert rule_ids == [
        "ICMP-001"
    ]
def test_port_scan_below_threshold_no_alert():

    start_time = datetime.now()

    packets = []

    for i in range(19):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(
                    milliseconds=100 * i
                )
            ),
            source_ip="192.168.1.140",
            destination_ip="192.168.1.240",
            protocol="TCP",
            source_port=50000 + i,
            destination_port=2000 + i,
            tcp_flags="S",
            packet_size=60
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0


def test_port_scan_outside_window_no_alert():

    start_time = datetime.now()

    packets = []

    for i in range(20):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=i)
            ),
            source_ip="192.168.1.150",
            destination_ip="192.168.1.250",
            protocol="TCP",
            source_port=51000 + i,
            destination_port=3000 + i,
            tcp_flags="S",
            packet_size=60
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0
def test_syn_flood_below_threshold_no_alert():

    start_time = datetime.now()

    packets = []

    for i in range(99):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(
                    milliseconds=50 * i
                )
            ),
            source_ip="192.168.1.160",
            destination_ip="192.168.1.200",
            protocol="TCP",
            source_port=40000 + i,
            destination_port=443,
            tcp_flags="S",
            packet_size=60
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0


def test_syn_flood_outside_window_no_alert():

    start_time = datetime.now()

    packets = []

    for i in range(100):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=i)
            ),
            source_ip="192.168.1.170",
            destination_ip="192.168.1.210",
            protocol="TCP",
            source_port=41000 + i,
            destination_port=443,
            tcp_flags="S",
            packet_size=60
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0
def test_dns_frequency_below_threshold_no_alert():

    start_time = datetime.now()

    packets = []

    for i in range(19):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=i)
            ),
            source_ip="192.168.1.180",
            destination_ip="8.8.8.8",
            protocol="UDP",
            source_port=53000 + i,
            destination_port=53,
            packet_size=80,
            dns_query=(
                f"host{i}.example.com"
            )
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0


def test_dns_frequency_at_threshold_alerts():

    start_time = datetime.now()

    packets = []

    for i in range(20):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=i)
            ),
            source_ip="192.168.1.181",
            destination_ip="8.8.8.8",
            protocol="UDP",
            source_port=54000 + i,
            destination_port=53,
            packet_size=80,
            dns_query=(
                f"host{i}.example.com"
            )
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    rule_ids = [
        alert.rule_id
        for alert in alerts
    ]

    assert rule_ids == [
        "DNS-001"
    ]


def test_dns_frequency_outside_window_no_alert():

    start_time = datetime.now()

    packets = []

    for i in range(20):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=4 * i)
            ),
            source_ip="192.168.1.182",
            destination_ip="8.8.8.8",
            protocol="UDP",
            source_port=55000 + i,
            destination_port=53,
            packet_size=80,
            dns_query=(
                f"host{i}.example.com"
            )
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0
def test_icmp_below_threshold_no_alert():

    start_time = datetime.now()

    packets = []

    for i in range(9):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=i)
            ),
            source_ip="192.168.1.190",
            destination_ip="192.168.1.220",
            protocol="ICMP",
            packet_size=200,
            icmp_type=8,
            icmp_code=0,
            icmp_payload_size=150
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0


def test_icmp_outside_window_no_alert():

    start_time = datetime.now()

    packets = []

    for i in range(10):

        packet = NetworkPacket(
            timestamp=(
                start_time
                + timedelta(seconds=4 * i)
            ),
            source_ip="192.168.1.191",
            destination_ip="192.168.1.221",
            protocol="ICMP",
            packet_size=200,
            icmp_type=8,
            icmp_code=0,
            icmp_payload_size=150
        )

        packets.append(packet)

    alerts = run_detection(
        packets
    )

    assert len(alerts) == 0