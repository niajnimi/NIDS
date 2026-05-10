from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional
import uuid


def utc_ts() -> str:
    return datetime.utcnow().isoformat() + "Z"


@dataclass
class EventRecord:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_ts)
    src_ip: str = ""
    dst_ip: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "OTHER"
    packet_size: int = 0
    direction: str = "OUTBOUND"
    flags: str = ""
    status: str = "normal"

    def to_dict(self):
        return asdict(self)


@dataclass
class AlertRecord:
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_ts)
    src_ip: str = ""
    threat_type: str = ""
    severity: str = "LOW"
    risk_score: int = 0
    detail_message: str = ""
    affected_ports: List[int] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)
