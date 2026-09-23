from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from capture.parser import parse_packet


def test_tcp_packet():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S")
    )

    parsed = parse_packet(packet)

    assert parsed is not None
    assert parsed.source_ip == "192.168.1.10"
    assert parsed.destination_ip == "192.168.1.20"
    assert parsed.protocol == "TCP"
    assert parsed.source_port == 50000
    assert parsed.destination_port == 443
    assert parsed.tcp_flags == "S"


def test_dns_packet():
    packet = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(qname="example.com")
        )
    )

    parsed = parse_packet(packet)

    assert parsed is not None
    assert parsed.source_ip == "192.168.1.10"
    assert parsed.destination_ip == "8.8.8.8"
    assert parsed.protocol == "UDP"
    assert parsed.destination_port == 53
    assert parsed.dns_query == "example.com"


def test_icmp_packet():
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / ICMP(type=8, code=0)
        / Raw(load=b"Hello NIDAS")
    )

    parsed = parse_packet(packet)

    assert parsed is not None
    assert parsed.protocol == "ICMP"
    assert parsed.icmp_type == 8
    assert parsed.icmp_code == 0
    assert parsed.icmp_payload_size == 11