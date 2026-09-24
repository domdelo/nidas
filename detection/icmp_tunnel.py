from collections import defaultdict
from datetime import timedelta

from models.alert import SecurityAlert


def detect_icmp_tunneling(
    packets,
    payload_threshold=100,
    packet_threshold=10,
    window_seconds=30
):
    alerts = []

    icmp_by_source = defaultdict(list)

    # Collect suspiciously large ICMP Echo packets.
    for packet in packets:

        if packet.protocol != "ICMP":
            continue

        if packet.source_ip is None:
            continue

        if packet.destination_ip is None:
            continue

        if packet.icmp_type is None:
            continue

        # Only analyze ICMP Echo Request and
        # Echo Reply traffic for tunneling.
        if packet.icmp_type not in (0, 8):
            continue

        if packet.icmp_payload_size is None:
            continue

        if (
            packet.icmp_payload_size
            < payload_threshold
        ):
            continue

        key = (
            packet.source_ip,
            packet.destination_ip
        )

        icmp_by_source[key].append(
            packet
        )

    # Analyze ICMP activity over time.
    for (
        source_ip,
        destination_ip
    ), group in icmp_by_source.items():

        group.sort(
            key=lambda packet: packet.timestamp
        )

        for start_index in range(
            len(group)
        ):

            start_time = (
                group[
                    start_index
                ].timestamp
            )

            suspicious_packets = []

            for packet in group[
                start_index:
            ]:

                difference = (
                    packet.timestamp
                    - start_time
                )

                if (
                    difference
                    > timedelta(
                        seconds=window_seconds
                    )
                ):
                    break

                suspicious_packets.append(
                    packet
                )

            if (
                len(suspicious_packets)
                >= packet_threshold
            ):

                payload_sizes = [
                    packet.icmp_payload_size
                    for packet
                    in suspicious_packets
                ]

                average_payload_size = (
                    sum(payload_sizes)
                    / len(payload_sizes)
                )

                alert = SecurityAlert(
                    timestamp=start_time,

                    rule_id="ICMP-001",
                    rule_name=(
                        "Possible ICMP Tunneling"
                    ),

                    severity="high",

                    source_ip=source_ip,
                    destination_ip=(
                        destination_ip
                    ),

                    protocol="ICMP",

                    description=(
                        f"{source_ip} sent "
                        f"{len(suspicious_packets)} "
                        f"large ICMP Echo packets to "
                        f"{destination_ip} within "
                        f"{window_seconds} seconds."
                    ),

                    evidence={
                        "packet_count": (
                            len(
                                suspicious_packets
                            )
                        ),
                        "average_payload_size": (
                            round(
                                average_payload_size,
                                2
                            )
                        ),
                        "payload_threshold": (
                            payload_threshold
                        ),
                        "window_seconds": (
                            window_seconds
                        ),
                        "icmp_types": (
                            "Echo Request/Reply"
                        )
                    },

                    tactic=(
                        "Command and Control"
                    ),

                    technique=(
                        "Non-Application "
                        "Layer Protocol"
                    ),

                    technique_id="T1095"
                )

                alerts.append(
                    alert
                )

                # Prevent duplicate alerts
                # during this detection run.
                break

    return alerts