from typing import Dict, List
from backend.models import AlertRecord


def severity_for_score(score: int) -> str:
    if score <= 30:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    if score <= 85:
        return "HIGH"
    return "CRITICAL"


def make_alert(src_ip: str, threat_type: str, score: int, detail: str, ports: List[int]) -> AlertRecord:
    return AlertRecord(
        src_ip=src_ip,
        threat_type=threat_type,
        risk_score=score,
        severity=severity_for_score(score),
        detail_message=detail,
        affected_ports=sorted(list(set(ports))),
    )


def build_alerts_for_metrics(src_ip: str, metrics: Dict, cfg) -> List[AlertRecord]:
    alerts = []
    ports = metrics["distinct_ports"]
    auth_fail = metrics["auth_failures"]
    icmp_distinct = metrics["icmp_distinct_ips"]
    volume_60 = metrics["volume_60"]
    risk = metrics["risk_score"]

    if cfg.enabled_slow_scan and len(ports) >= cfg.slow_port_scan_threshold:
        alerts.append(make_alert(src_ip, "SLOW_PORT_SCAN", max(risk, 70), f"{len(ports)} distinct ports in {cfg.slow_port_scan_window}s", list(ports)))
    if cfg.enabled_rapid_scan and metrics["ports_60_count"] >= cfg.rapid_port_scan_threshold:
        alerts.append(make_alert(src_ip, "RAPID_PORT_SCAN", 95, f"{metrics['ports_60_count']} distinct ports in {cfg.rapid_port_scan_window}s", list(metrics["ports_60"])))
    if cfg.enabled_brute_force and auth_fail >= cfg.brute_force_threshold:
        alerts.append(make_alert(src_ip, "BRUTE_FORCE", max(risk, 75), f"{auth_fail} failed auth attempts in {cfg.brute_force_window}s", list(ports)))
    if cfg.enabled_ping_sweep and icmp_distinct >= cfg.ping_sweep_threshold:
        alerts.append(make_alert(src_ip, "PING_SWEEP", max(risk, 45), f"ICMP to {icmp_distinct} distinct targets in {cfg.ping_sweep_window}s", []))
    if cfg.enabled_anomalous_volume and volume_60 >= cfg.anomalous_volume_threshold:
        alerts.append(make_alert(src_ip, "ANOMALOUS_VOLUME", max(risk, 50), f"{volume_60} packets in {cfg.anomalous_volume_window}s", list(ports)))
    if cfg.enabled_composite and metrics["composite_attack"]:
        alerts.append(make_alert(src_ip, "COMPOSITE_ATTACK", max(risk, cfg.composite_score_threshold), "Correlated scan + auth failure behavior", list(ports)))
    return alerts