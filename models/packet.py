from dataclasses import dataclass
from datetime import datetime


@dataclass
class NetworkPacket:
    timestamp: datetime

    source_ip: str | None = None
    destination_ip: str | None = None

    protocol: str | None = None

    source_port: int | None = None
    destination_port: int | None = None

    packet_size: int = 0

    tcp_flags: str | None = None

    dns_query: str | None = None

    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_payload_size: int | None = None
