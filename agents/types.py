from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ThreatFinding:
    agent_name: str
    threat_type: str
    description: str
    severity: str = "MEDIUM"
    source_ip: Optional[str] = "Unknown"
    metadata: dict = field(default_factory=dict)

    def __str__(self):
        return f"[{self.severity}] {self.agent_name} -> {self.threat_type} ({self.source_ip}): {self.description}"
