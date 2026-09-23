from scapy.all import rdpcap

from capture.parser import parse_packet


def read_pcap(file_path):
    packets = rdpcap(file_path)

    parsed_packets = []

    for packet in packets:
        parsed = parse_packet(packet)

        if parsed is not None:
            parsed_packets.append(parsed)

    return parsed_packets