from capture.sniffer import read_pcap
from detection.engine import run_detection


def test_full_detection_engine():

    packets = read_pcap(
        "samples/nidas_demo.pcap"
    )

    alerts = run_detection(packets)

    rule_ids = {
        alert.rule_id
        for alert in alerts
    }

    assert "NET-001" in rule_ids
    assert "DOS-001" in rule_ids
    assert "DNS-001" in rule_ids
    assert "ICMP-001" in rule_ids