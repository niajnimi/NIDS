import csv
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable, List, Optional


class NIDSLogger:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.packet_buffer = []
        self.alert_buffer = []
        self.last_flush = time.time()
        self.flush_every_packets = 50
        self.flush_every_seconds = 2
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS packets(
            id TEXT PRIMARY KEY,
            timestamp TEXT, src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
            protocol TEXT, packet_size INTEGER, direction TEXT, flags TEXT, status TEXT
            )"""
        )
        cur.execute(
            """CREATE TABLE IF NOT EXISTS alerts(
            id TEXT PRIMARY KEY,
            timestamp TEXT, src_ip TEXT, threat_type TEXT, severity TEXT, risk_score INTEGER,
            detail TEXT, affected_ports TEXT
            )"""
        )
        conn.commit()
        conn.close()

    def log_packet(self, packet_dict):
        with self.lock:
            self.packet_buffer.append(packet_dict)
            self._maybe_flush()

    def log_alert(self, alert_dict):
        with self.lock:
            self.alert_buffer.append(alert_dict)
            self._maybe_flush()

    def _maybe_flush(self):
        now = time.time()
        if len(self.packet_buffer) >= self.flush_every_packets or (now - self.last_flush) >= self.flush_every_seconds:
            self.flush()

    def flush(self):
        conn = self._conn()
        cur = conn.cursor()
        if self.packet_buffer:
            cur.executemany(
                "INSERT OR REPLACE INTO packets VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        p["id"], p["timestamp"], p["src_ip"], p["dst_ip"], p.get("src_port"), p.get("dst_port"),
                        p["protocol"], p["packet_size"], p["direction"], p.get("flags", ""), p.get("status", "normal"),
                    )
                    for p in self.packet_buffer
                ],
            )
            self.packet_buffer.clear()
        if self.alert_buffer:
            cur.executemany(
                "INSERT OR REPLACE INTO alerts VALUES(?,?,?,?,?,?,?,?)",
                [
                    (
                        a["alert_id"], a["timestamp"], a["src_ip"], a["threat_type"], a["severity"],
                        a["risk_score"], a["detail_message"], json.dumps(a.get("affected_ports", [])),
                    )
                    for a in self.alert_buffer
                ],
            )
            self.alert_buffer.clear()
        conn.commit()
        conn.close()
        self.last_flush = time.time()

    def query(self, table: str, where: Optional[str] = None, params: Iterable = (), limit: int = 50, offset: int = 0):
        conn = self._conn()
        cur = conn.cursor()
        base = f"SELECT * FROM {table}"
        if where:
            base += f" WHERE {where}"
        base += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        cur.execute(base, [*params, limit, offset])
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def export(self, packets: List[dict], alerts: List[dict], fmt: str, output_path: str, summary: dict):
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        if fmt == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump({"summary": summary, "packets": packets, "alerts": alerts}, f, indent=2)
            return
        if fmt == "csv":
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["session_summary", json.dumps(summary)])
                writer.writerow([])
                writer.writerow(["packets"])
                if packets:
                    writer.writerow(list(packets[0].keys()))
                    for p in packets:
                        writer.writerow([p.get(k) for k in packets[0].keys()])
                writer.writerow([])
                writer.writerow(["alerts"])
                if alerts:
                    writer.writerow(list(alerts[0].keys()))
                    for a in alerts:
                        writer.writerow([a.get(k) for k in alerts[0].keys()])
            return
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("==== NIDS SESSION LOG ====\n")
            f.write(json.dumps(summary) + "\n")
            f.write("\n-- PACKETS --\n")
            for p in packets:
                f.write(json.dumps(p) + "\n")
            f.write("\n-- ALERTS --\n")
            for a in alerts:
                f.write(json.dumps(a) + "\n")