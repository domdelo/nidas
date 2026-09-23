from scapy.all import AsyncSniffer, rdpcap

from capture.parser import parse_packet


def read_pcap(file_path):
    packets = rdpcap(file_path)

    parsed_packets = []

    for packet in packets:
        parsed = parse_packet(packet)

        if parsed is not None:
            parsed_packets.append(parsed)

    return parsed_packets


def capture_live(
    interface,
    packet_count=50,
    timeout=30
):
    from scapy.all import sniff

    parsed_packets = []

    def handle_packet(packet):
        parsed = parse_packet(packet)

        if parsed is not None:
            parsed_packets.append(parsed)

    sniff(
        iface=interface,
        prn=handle_packet,
        store=False,
        count=packet_count,
        timeout=timeout
    )

    return parsed_packets


def start_live_sniffer(
    interface,
    packet_handler
):

    def handle_packet(packet):
        parsed = parse_packet(packet)

        if parsed is not None:
            packet_handler(parsed)

    sniffer = AsyncSniffer(
        iface=interface,
        prn=handle_packet,
        store=False
    )

    sniffer.start()

    return sniffer