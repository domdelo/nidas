from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class SecurityAlert:
    alert_id: str
    timestamp: datetime

    rule_id: str
    rule_name: str

    severity: str

    source_ip: str | None = None
    destination_ip: str | None = None

    protocol: str | None = None

    description: str = ""

    evidence: dict[str, Any] = field(default_factory=dict)

    tactic: str | None = None
    technique: str | None = None
    technique_id: str | None = None