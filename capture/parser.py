from datetime import datetime

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNSQR
from scapy.packet import Raw

from models.packet import NetworkPacket


def parse_packet(packet):
    # Ignore packets that do not contain an IPv4 layer
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    # Convert the raw Scapy packet into our standard NetworkPacket
    network_packet = NetworkPacket(
        timestamp=datetime.fromtimestamp(float(packet.time)),
        source_ip=ip_layer.src,
        destination_ip=ip_layer.dst,
        packet_size=len(packet)
    )

    # -------------------------
    # TCP
    # -------------------------
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]

        network_packet.protocol = "TCP"
        network_packet.source_port = tcp_layer.sport
        network_packet.destination_port = tcp_layer.dport
        network_packet.tcp_flags = str(tcp_layer.flags)

    # -------------------------
    # UDP
    # -------------------------
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]

        network_packet.protocol = "UDP"
        network_packet.source_port = udp_layer.sport
        network_packet.destination_port = udp_layer.dport

    # -------------------------
    # ICMP
    # -------------------------
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]

        network_packet.protocol = "ICMP"
        network_packet.icmp_type = icmp_layer.type
        network_packet.icmp_code = icmp_layer.code

        # Record the size of the ICMP payload
        if packet.haslayer(Raw):
            network_packet.icmp_payload_size = len(packet[Raw].load)
        else:
            network_packet.icmp_payload_size = 0

    # -------------------------
    # Other IPv4 protocols
    # -------------------------
    else:
        network_packet.protocol = str(ip_layer.proto)

    # -------------------------
    # DNS
    # -------------------------
    if packet.haslayer(DNSQR):
        dns_layer = packet[DNSQR]

        query = dns_layer.qname

        # Scapy normally stores DNS names as bytes
        if isinstance(query, bytes):
            query = query.decode(errors="ignore")

        # Remove trailing period from DNS name
        network_packet.dns_query = query.rstrip(".")

    return network_packet