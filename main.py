import argparse
import time
from threading import Lock

from capture.sniffer import (
    read_pcap,
    start_live_sniffer
)

from detection.engine import run_detection

from detection.live_monitor import (
    trim_packet_buffer,
    get_new_alerts
)

from storage.alert_store import save_alerts


def print_alert(alert):
    print(
        f"[{alert.severity.upper()}] "
        f"{alert.rule_name}"
    )

    print(
        f"Rule: {alert.rule_id}"
    )

    print(
        f"Source: {alert.source_ip}"
    )

    print(
        f"Destination: "
        f"{alert.destination_ip}"
    )

    print(
        f"Description: "
        f"{alert.description}"
    )

    print(
        f"Evidence: {alert.evidence}"
    )

    print()


def run_pcap_analysis(file_path):

    packets = read_pcap(
        file_path
    )

    alerts = run_detection(
        packets
    )

    save_alerts(
        alerts
    )

    print()

    print(
        "NIDAS - Network Intrusion "
        "Detection & Alert System"
    )

    print(
        "--------------------------------"
    )

    print(
        f"Packets analyzed: "
        f"{len(packets)}"
    )

    print(
        f"Alerts generated: "
        f"{len(alerts)}"
    )

    print()

    for alert in alerts:
        print_alert(alert)


def run_live_monitor(interface):

    packet_buffer = []
    buffer_lock = Lock()

    detection_window_seconds = 60
    analysis_interval_seconds = 10

    seen_alerts = set()

    def receive_packet(packet):

        with buffer_lock:
            packet_buffer.append(packet)

    print()

    print(
        "NIDAS Live Network Monitoring"
    )

    print(
        "-----------------------------"
    )

    print(
        f"Interface: {interface}"
    )

    print(
        "Mode: Passive"
    )

    print(
        f"Detection window: "
        f"{detection_window_seconds} seconds"
    )

    print(
        f"Analysis interval: "
        f"{analysis_interval_seconds} seconds"
    )

    print(
        "Press Control+C to stop."
    )

    print()

    sniffer = start_live_sniffer(
        interface,
        receive_packet
    )

    try:

        while True:

            time.sleep(
                analysis_interval_seconds
            )

            # Keep only packets inside
            # the rolling detection window
            with buffer_lock:

                packet_buffer[:] = (
                    trim_packet_buffer(
                        packet_buffer,
                        window_seconds=(
                            detection_window_seconds
                        )
                    )
                )

                packets = list(
                    packet_buffer
                )

            print(
                f"Packets in rolling window: "
                f"{len(packets)}"
            )

            if not packets:

                print(
                    "No IPv4 packets captured."
                )

                print()

                continue

            # Run all NIDAS detection rules
            alerts = run_detection(
                packets
            )

            # Remove alerts that have already
            # been reported during this session
            new_alerts = get_new_alerts(
                alerts,
                seen_alerts
            )

            if new_alerts:

                save_alerts(
                    new_alerts
                )

                print(
                    f"New alerts generated: "
                    f"{len(new_alerts)}"
                )

                print()

                for alert in new_alerts:
                    print_alert(alert)

            else:

                print(
                    "No new threats detected."
                )

            print()

    except KeyboardInterrupt:

        print()

        print(
            "Stopping NIDAS "
            "live monitoring..."
        )

    finally:

        if sniffer.running:
            sniffer.stop()

        print(
            "NIDAS live monitoring stopped."
        )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "NIDAS - Network Intrusion "
            "Detection & Alert System"
        )
    )

    parser.add_argument(
        "--pcap",
        type=str,
        help=(
            "Path to a PCAP file "
            "to analyze"
        )
    )

    parser.add_argument(
        "--live",
        action="store_true",
        help=(
            "Start passive live "
            "network monitoring"
        )
    )

    parser.add_argument(
        "--interface",
        type=str,
        help=(
            "Network interface used "
            "for live capture"
        )
    )

    args = parser.parse_args()

    if args.pcap:

        run_pcap_analysis(
            args.pcap
        )

    elif args.live:

        if not args.interface:

            parser.error(
                "--interface is required "
                "when using --live"
            )

        run_live_monitor(
            args.interface
        )

    else:

        parser.print_help()


if __name__ == "__main__":
    main()