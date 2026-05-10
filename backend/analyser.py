from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Deque

from backend.correlator import compute_risk_score, elevate_if_composite


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


class BehaviourAnalyser:
    def __init__(self, config):
        self.config = config
        self.events_by_src: Dict[str, Deque] = defaultdict(deque)

    def _prune(self, src_ip: str, now: datetime):
        dq = self.events_by_src[src_ip]
        cutoff = now - timedelta(seconds=max(self.config.window_seconds, self.config.slow_port_scan_window))
        while dq and parse_ts(dq[0].timestamp) < cutoff:
            dq.popleft()

    def update(self, event):
        now = parse_ts(event.timestamp)
        src = event.src_ip or "unknown"
        self.events_by_src[src].append(event)
        self._prune(src, now)

        events = list(self.events_by_src[src])
        in_60 = [e for e in events if parse_ts(e.timestamp) >= now - timedelta(seconds=60)]
        in_30 = [e for e in events if parse_ts(e.timestamp) >= now - timedelta(seconds=30)]
        ports_all = {e.dst_port for e in events if e.dst_port is not None}
        ports_60 = {e.dst_port for e in in_60 if e.dst_port is not None}
        auth_failures = sum(1 for e in events if e.status == "failed_auth")
        icmp_distinct = {e.dst_ip for e in in_30 if e.protocol == "ICMP" and e.dst_ip}
        volume_60 = len(in_60)

        risk = compute_risk_score(len(ports_all), auth_failures, volume_60, self.config.window_seconds)
        composite = elevate_if_composite(len(ports_all), auth_failures)

        return {
            "src_ip": src,
            "distinct_ports": ports_all,
            "ports_60": ports_60,
            "ports_60_count": len(ports_60),
            "auth_failures": auth_failures,
            "icmp_distinct_ips": len(icmp_distinct),
            "volume_60": volume_60,
            "risk_score": risk,
            "composite_attack": composite,
        }