from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.utils import wrpcap

from capture.sniffer import read_pcap


def test_read_pcap(tmp_path):
    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=443, flags="S"),

        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(qname="example.com")
        ),

        IP(src="192.168.1.10", dst="192.168.1.20")
        / ICMP(type=8, code=0)
        / Raw(load=b"Hello NIDAS")
    ]

    pcap_file = tmp_path / "test.pcap"

    wrpcap(str(pcap_file), packets)

    parsed_packets = read_pcap(str(pcap_file))

    assert len(parsed_packets) == 3

    assert parsed_packets[0].protocol == "TCP"
    assert parsed_packets[1].protocol == "UDP"
    assert parsed_packets[2].protocol == "ICMP"