from detection.port_scan import detect_port_scans
from detection.syn_flood import detect_syn_floods
from detection.dns_exfil import detect_dns_exfiltration
from detection.icmp_tunnel import detect_icmp_tunneling


def run_detection(packets):
    alerts = []

    alerts.extend(
        detect_port_scans(packets)
    )

    alerts.extend(
        detect_syn_floods(packets)
    )

    alerts.extend(
        detect_dns_exfiltration(packets)
    )

    alerts.extend(
        detect_icmp_tunneling(packets)
    )

    alerts.sort(
        key=lambda alert: alert.timestamp
    )

    return alerts