from collections import defaultdict
from datetime import timedelta

from models.alert import SecurityAlert


def detect_port_scans(
    packets,
    port_threshold=20,
    window_seconds=10
):
    alerts = []

    connections = defaultdict(list)

    # Collect TCP connection attempts.
    for packet in packets:

        if packet.protocol != "TCP":
            continue

        if packet.source_ip is None:
            continue

        if packet.destination_ip is None:
            continue

        if packet.destination_port is None:
            continue

        if packet.tcp_flags is None:
            continue

        flags = packet.tcp_flags

        # Only count SYN connection attempts.
        if "S" not in flags:
            continue

        # Ignore SYN-ACK responses.
        if "A" in flags:
            continue

        key = (
            packet.source_ip,
            packet.destination_ip
        )

        connections[key].append(
            packet
        )

    # Analyze each source/destination pair.
    for (
        source_ip,
        destination_ip
    ), group in connections.items():

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

            ports = set()

            for packet in group[
                start_index:
            ]:

                time_difference = (
                    packet.timestamp
                    - start_time
                )

                if (
                    time_difference
                    > timedelta(
                        seconds=window_seconds
                    )
                ):
                    break

                ports.add(
                    packet.destination_port
                )

            if (
                len(ports)
                >= port_threshold
            ):

                alert = SecurityAlert(
                    timestamp=start_time,

                    rule_id="NET-001",
                    rule_name=(
                        "Port Scan Detected"
                    ),

                    severity="medium",

                    source_ip=source_ip,
                    destination_ip=(
                        destination_ip
                    ),

                    protocol="TCP",

                    description=(
                        f"{source_ip} attempted "
                        f"connections to "
                        f"{len(ports)} unique ports on "
                        f"{destination_ip} within "
                        f"{window_seconds} seconds."
                    ),

                    evidence={
                        "unique_port_count": (
                            len(ports)
                        ),
                        "ports": sorted(
                            ports
                        ),
                        "window_seconds": (
                            window_seconds
                        ),
                        "tcp_pattern": (
                            "SYN without ACK"
                        )
                    },

                    tactic="Reconnaissance",

                    technique=(
                        "Network Service Scanning"
                    ),

                    technique_id="T1046"
                )

                alerts.append(
                    alert
                )

                break

    return alerts