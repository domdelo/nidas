from collections import defaultdict
from datetime import timedelta

from models.alert import SecurityAlert


def detect_syn_floods(
    packets,
    syn_threshold=100,
    window_seconds=10
):
    alerts = []

    connections = defaultdict(list)

    # Collect SYN packets that are not SYN-ACK packets
    for packet in packets:
        if packet.protocol != "TCP":
            continue

        if packet.source_ip is None:
            continue

        if packet.destination_ip is None:
            continue

        if packet.tcp_flags is None:
            continue

        flags = packet.tcp_flags

        if "S" not in flags:
            continue

        if "A" in flags:
            continue

        key = (
            packet.source_ip,
            packet.destination_ip
        )

        connections[key].append(packet)

    # Analyze each source/destination pair
    for (source_ip, destination_ip), group in connections.items():

        group.sort(key=lambda packet: packet.timestamp)

        for start_index in range(len(group)):
            start_time = group[start_index].timestamp

            syn_count = 0

            for packet in group[start_index:]:

                time_difference = (
                    packet.timestamp - start_time
                )

                if time_difference > timedelta(seconds=window_seconds):
                    break

                syn_count += 1

            if syn_count >= syn_threshold:

                alert = SecurityAlert(
                    alert_id=f"SYNFLOOD-{len(alerts) + 1:04d}",
                    timestamp=start_time,

                    rule_id="DOS-001",
                    rule_name="Possible SYN Flood Detected",

                    severity="high",

                    source_ip=source_ip,
                    destination_ip=destination_ip,

                    protocol="TCP",

                    description=(
                        f"{source_ip} sent {syn_count} TCP SYN packets "
                        f"to {destination_ip} within "
                        f"{window_seconds} seconds."
                    ),

                    evidence={
                        "syn_count": syn_count,
                        "window_seconds": window_seconds
                    },

                    tactic="Impact",
                    technique="Network Denial of Service",
                    technique_id="T1498"
                )

                alerts.append(alert)

                break

    return alerts