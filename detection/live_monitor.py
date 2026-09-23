from datetime import datetime, timedelta


def trim_packet_buffer(
    packets,
    window_seconds=60,
    current_time=None
):
    if current_time is None:
        current_time = datetime.now()

    cutoff_time = (
        current_time
        - timedelta(
            seconds=window_seconds
        )
    )

    recent_packets = []

    for packet in packets:

        if packet.timestamp >= cutoff_time:
            recent_packets.append(packet)

    return recent_packets


def get_new_alerts(
    alerts,
    seen_alerts
):
    new_alerts = []

    for alert in alerts:

        fingerprint = (
            alert.rule_id,
            alert.source_ip,
            alert.destination_ip
        )

        if fingerprint not in seen_alerts:

            seen_alerts.add(
                fingerprint
            )

            new_alerts.append(
                alert
            )

    return new_alerts