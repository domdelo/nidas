from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


def generate_alert_id():
    return str(uuid4())


@dataclass
class SecurityAlert:
    timestamp: datetime

    rule_id: str
    rule_name: str

    severity: str

    alert_id: str = field(
        default_factory=generate_alert_id
    )

    source_ip: str | None = None
    destination_ip: str | None = None

    protocol: str | None = None

    description: str = ""

    evidence: dict[str, Any] = field(
        default_factory=dict
    )

    tactic: str | None = None
    technique: str | None = None
    technique_id: str | None = None