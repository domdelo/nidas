import math
from collections import Counter, defaultdict
from datetime import timedelta

from models.alert import SecurityAlert


def calculate_entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= (
            probability
            * math.log2(probability)
        )

    return entropy


def detect_dns_exfiltration(
    packets,
    query_length_threshold=60,
    label_length_threshold=40,
    entropy_threshold=4.0,
    query_count_threshold=20,
    unique_label_ratio_threshold=0.75,
    window_seconds=60
):
    alerts = []

    dns_packets = []

    # Only keep packets containing DNS queries.
    for packet in packets:

        if packet.dns_query is None:
            continue

        if packet.source_ip is None:
            continue

        dns_packets.append(
            packet
        )

    # --------------------------------------------------
    # Analyze individual DNS queries
    # --------------------------------------------------

    alerted_sources = set()

    for packet in dns_packets:

        query = packet.dns_query

        labels = query.split(".")

        if labels:

            longest_label = max(
                len(label)
                for label in labels
            )

        else:
            longest_label = 0

        entropy = calculate_entropy(
            query
        )

        indicators = []

        if (
            len(query)
            >= query_length_threshold
        ):
            indicators.append(
                "long_query"
            )

        if (
            longest_label
            >= label_length_threshold
        ):
            indicators.append(
                "long_label"
            )

        if (
            entropy
            >= entropy_threshold
        ):
            indicators.append(
                "high_entropy"
            )

        # Require multiple suspicious characteristics.
        if len(indicators) >= 2:

            alert = SecurityAlert(
                timestamp=packet.timestamp,

                rule_id="DNS-001",
                rule_name=(
                    "Possible DNS Exfiltration"
                ),

                severity="high",

                source_ip=(
                    packet.source_ip
                ),

                destination_ip=(
                    packet.destination_ip
                ),

                protocol="DNS",

                description=(
                    f"Suspicious DNS query from "
                    f"{packet.source_ip}: "
                    f"{query}"
                ),

                evidence={
                    "query": query,
                    "query_length": (
                        len(query)
                    ),
                    "longest_label": (
                        longest_label
                    ),
                    "entropy": round(
                        entropy,
                        2
                    ),
                    "indicators": indicators
                },

                tactic="Exfiltration",

                technique=(
                    "Exfiltration Over "
                    "Alternative Protocol"
                ),

                technique_id="T1048"
            )

            alerts.append(
                alert
            )

            alerted_sources.add(
                packet.source_ip
            )

    # --------------------------------------------------
    # Analyze DNS query frequency
    # --------------------------------------------------

    queries_by_source = defaultdict(
        list
    )

    for packet in dns_packets:

        queries_by_source[
            packet.source_ip
        ].append(
            packet
        )

    for (
        source_ip,
        group
    ) in queries_by_source.items():

        if source_ip in alerted_sources:
            continue

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

            window_packets = []

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

                window_packets.append(
                    packet
                )

            query_count = len(
                window_packets
            )

            if (
                query_count
                < query_count_threshold
            ):
                continue

            unique_labels = set()

            for packet in window_packets:

                query = packet.dns_query

                labels = query.split(".")

                if labels:
                    unique_labels.add(
                        labels[0]
                    )

            unique_label_count = len(
                unique_labels
            )

            unique_label_ratio = (
                unique_label_count
                / query_count
            )

            # High DNS volume alone is not enough.
            # Require substantial variation in the
            # first DNS label as an additional signal.
            if (
                unique_label_ratio
                < unique_label_ratio_threshold
            ):
                continue

            alert = SecurityAlert(
                timestamp=start_time,

                rule_id="DNS-001",

                rule_name=(
                    "Possible DNS Exfiltration"
                ),

                severity="medium",

                source_ip=source_ip,

                protocol="DNS",

                description=(
                    f"{source_ip} generated "
                    f"{query_count} DNS queries "
                    f"with {unique_label_count} "
                    f"unique first labels within "
                    f"{window_seconds} seconds."
                ),

                evidence={
                    "query_count": (
                        query_count
                    ),
                    "unique_label_count": (
                        unique_label_count
                    ),
                    "unique_label_ratio": round(
                        unique_label_ratio,
                        2
                    ),
                    "window_seconds": (
                        window_seconds
                    ),
                    "indicators": [
                        "high_query_frequency",
                        "high_unique_label_ratio"
                    ]
                },

                tactic="Exfiltration",

                technique=(
                    "Exfiltration Over "
                    "Alternative Protocol"
                ),

                technique_id="T1048"
            )

            alerts.append(
                alert
            )

            break

    return alerts