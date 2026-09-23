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
            recent_packets.append(
                packet
            )

    return recent_packets


def get_new_alerts(
    alerts,
    alert_history,
    cooldown_seconds=60,
    current_time=None
):
    if current_time is None:
        current_time = datetime.now()

    new_alerts = []

    for alert in alerts:

        fingerprint = (
            alert.rule_id,
            alert.source_ip,
            alert.destination_ip
        )

        last_alert_time = (
            alert_history.get(
                fingerprint
            )
        )

        if last_alert_time is None:

            alert_history[
                fingerprint
            ] = current_time

            new_alerts.append(
                alert
            )

            continue

        time_since_last_alert = (
            current_time
            - last_alert_time
        ).total_seconds()

        if (
            time_since_last_alert
            >= cooldown_seconds
        ):

            alert_history[
                fingerprint
            ] = current_time

            new_alerts.append(
                alert
            )

    return new_alerts