import queue
import threading
from typing import List

import netifaces
from scapy.all import sniff


def list_interfaces() -> List[str]:
    return list(netifaces.interfaces())


def local_ips() -> List[str]:
    ips = []
    for iface in netifaces.interfaces():
        for family_data in netifaces.ifaddresses(iface).values():
            for item in family_data:
                if "addr" in item:
                    ips.append(item["addr"])
    return ips


class PacketCaptureService:
    def __init__(self):
        self.running = False
        self.thread = None
        self.packet_queue = queue.Queue(maxsize=10000)
        self.stop_event = threading.Event()

    def _safe_enqueue(self, packet):
        try:
            self.packet_queue.put(packet, block=False)
        except queue.Full:
            # Drop packet when queue is saturated to keep capture thread responsive.
            return

    def start(self, iface: str, bpf_filter: str = ""):
        if self.running:
            return
        self.running = True
        self.stop_event.clear()

        def _run():
            sniff(
                iface=iface,
                prn=self._safe_enqueue,
                store=False,
                filter=bpf_filter or None,
                promisc=True,
                stop_filter=lambda _: self.stop_event.is_set(),
            )

        self.thread = threading.Thread(target=_run, daemon=True)
        self.thread.start()

    def stop(self):
        if not self.running:
            return
        self.stop_event.set()
        self.running = False