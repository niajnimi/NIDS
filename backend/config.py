from dataclasses import dataclass, asdict
from typing import Dict


@dataclass
class DetectionConfig:
    slow_port_scan_window: int = 300
    slow_port_scan_threshold: int = 15
    rapid_port_scan_window: int = 60
    rapid_port_scan_threshold: int = 50
    brute_force_window: int = 300
    brute_force_threshold: int = 5
    ping_sweep_window: int = 30
    ping_sweep_threshold: int = 20
    anomalous_volume_window: int = 60
    anomalous_volume_threshold: int = 500
    composite_score_threshold: int = 70
    max_live_packets: int = 200
    bpf_filter: str = ""
    enabled_slow_scan: bool = True
    enabled_rapid_scan: bool = True
    enabled_brute_force: bool = True
    enabled_ping_sweep: bool = True
    enabled_anomalous_volume: bool = True
    enabled_composite: bool = True
    window_seconds: int = 300

    def to_dict(self) -> Dict:
        return asdict(self)

    def update(self, payload: Dict) -> None:
        for key, value in payload.items():
            if hasattr(self, key):
                setattr(self, key, value)


DEFAULT_CONFIG = DetectionConfig()
THREAT_PORTS = {21, 22, 23, 3389}
