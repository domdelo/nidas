import argparse

from capture.sniffer import read_pcap
from detection.engine import run_detection


def main():
    parser = argparse.ArgumentParser(
        description="NIDAS - Network Intrusion Detection & Alert System"
    )

    parser.add_argument(
        "--pcap",
        type=str,
        help="Path to a PCAP file to analyze"
    )

    args = parser.parse_args()

    if args.pcap:
        packets = read_pcap(args.pcap)

        alerts = run_detection(packets)

        print("\nNIDAS - Network Intrusion Detection & Alert System")
        print("-----------------------------------------------")

        print(f"Packets analyzed: {len(packets)}")
        print(f"Alerts generated: {len(alerts)}\n")

        for alert in alerts:
            print(f"[{alert.severity.upper()}] {alert.rule_name}")
            print(f"Rule: {alert.rule_id}")
            print(f"Source: {alert.source_ip}")
            print(f"Destination: {alert.destination_ip}")
            print(f"Description: {alert.description}")
            print(f"Evidence: {alert.evidence}")
            print()

    else:
        print("No PCAP file provided.")
        print("Usage: python main.py --pcap <file>")


if __name__ == "__main__":
    main()