from scapy.layers.inet import IP, TCP, UDP, ICMP
from backend.config import THREAT_PORTS
from backend.models import EventRecord


def classify_failed_auth(event: EventRecord) -> bool:
    if event.protocol != "TCP" or not event.dst_port:
        return False
    if event.dst_port not in THREAT_PORTS:
        return False
    # SYN without ACK or explicit RST are common failure indicators.
    flags = event.flags or ""
    return "R" in flags or ("S" in flags and "A" not in flags)


def packet_to_event(packet, local_ips) -> EventRecord:
    event = EventRecord(packet_size=len(packet))
    if IP not in packet:
        event.protocol = "OTHER"
        return event

    ip = packet[IP]
    event.src_ip = ip.src
    event.dst_ip = ip.dst
    event.direction = "INBOUND" if ip.dst in local_ips else "OUTBOUND"

    if TCP in packet:
        tcp = packet[TCP]
        event.protocol = "TCP"
        event.src_port = int(tcp.sport)
        event.dst_port = int(tcp.dport)
        event.flags = str(tcp.flags)
    elif UDP in packet:
        udp = packet[UDP]
        event.protocol = "UDP"
        event.src_port = int(udp.sport)
        event.dst_port = int(udp.dport)
    elif ICMP in packet:
        event.protocol = "ICMP"
    else:
        event.protocol = "OTHER"

    if classify_failed_auth(event):
        event.status = "failed_auth"
    return event
