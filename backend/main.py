import os
import threading
import time
from collections import Counter, deque
from datetime import datetime

import psutil
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO

from backend.alert_generator import build_alerts_for_metrics
from backend.analyser import BehaviourAnalyser
from backend.capture import PacketCaptureService, list_interfaces, local_ips
from backend.config import DEFAULT_CONFIG
from backend.extractor import packet_to_event
from backend.logger import NIDSLogger


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "nids.db")
EXPORT_DIR = os.path.join(BASE_DIR, "exports")

app = Flask(__name__, static_folder=os.path.join(BASE_DIR, "frontend", "dist"))
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

capture = PacketCaptureService()
config = DEFAULT_CONFIG
analyser = BehaviourAnalyser(config)
logger = NIDSLogger(DB_PATH)
locals_cache = local_ips()

state = {
    "session_start": None,
    "interface": None,
    "packet_count": 0,
    "threat_count": 0,
    "inbound": 0,
    "outbound": 0,
    "unread_alerts": 0,
    "running": False,
}

recent_packets = deque(maxlen=2000)
recent_alerts = deque(maxlen=500)
rate_bucket = deque(maxlen=300)
seen_alert_keys = {}
top_sources = Counter()
state_lock = threading.Lock()


def process_loop():
    while True:
        try:
            packet = capture.packet_queue.get(timeout=0.2)
        except Exception:
            time.sleep(0.05)
            continue
        event = packet_to_event(packet, locals_cache)
        event_dict = event.to_dict()
        logger.log_packet(event_dict)

        with state_lock:
            state["packet_count"] += 1
            if event.direction == "INBOUND":
                state["inbound"] += 1
            else:
                state["outbound"] += 1
            top_sources[event.src_ip] += 1
            recent_packets.append(event_dict)

        socketio.emit("packet", event_dict)
        metrics = analyser.update(event)
        alerts = build_alerts_for_metrics(metrics["src_ip"], metrics, config)
        for alert in alerts:
            dedupe_key = (alert.src_ip, alert.threat_type)
            now_ts = time.time()
            if dedupe_key in seen_alert_keys and now_ts - seen_alert_keys[dedupe_key] < 8:
                continue
            seen_alert_keys[dedupe_key] = now_ts
            payload = alert.to_dict()
            logger.log_alert(payload)
            with state_lock:
                state["threat_count"] += 1
                state["unread_alerts"] += 1
                recent_alerts.append(payload)
            socketio.emit("alert", payload)


def stats_loop():
    process = psutil.Process(os.getpid())
    prev_inbound = 0
    prev_outbound = 0
    while True:
        time.sleep(1)
        with state_lock:
            now = datetime.utcnow().isoformat() + "Z"
            inbound = state["inbound"]
            outbound = state["outbound"]
            inbound_ps = max(0, inbound - prev_inbound)
            outbound_ps = max(0, outbound - prev_outbound)
            total_ps = inbound_ps + outbound_ps
            prev_inbound = inbound
            prev_outbound = outbound
            point = {"timestamp": now, "inbound": inbound_ps, "outbound": outbound_ps, "total": total_ps}
            rate_bucket.append(point)
            payload = {
                "timestamp": now,
                "packets_total": state["packet_count"],
                "packets_per_sec": total_ps,
                "inbound_per_sec": inbound_ps,
                "outbound_per_sec": outbound_ps,
                "inbound": inbound,
                "outbound": outbound,
                "active_threats": len(recent_alerts),
                "threats_total": state["threat_count"],
                "top_sources": top_sources.most_common(5),
                "unread_alerts": state["unread_alerts"],
                "session_seconds": int((datetime.utcnow() - state["session_start"]).total_seconds()) if state["session_start"] else 0,
                "cpu_percent": process.cpu_percent(interval=None),
                "memory_percent": process.memory_percent(),
            }
        socketio.emit("stats", payload)


@app.route("/api/interfaces")
def interfaces():
    return jsonify({"interfaces": list_interfaces()})


@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    payload = request.get_json(force=True)
    iface = payload.get("interface")
    if not iface:
        return jsonify({"error": "interface required"}), 400
    capture.start(iface, config.bpf_filter)
    with state_lock:
        state["running"] = True
        state["interface"] = iface
        if not state["session_start"]:
            state["session_start"] = datetime.utcnow()
    return jsonify({"ok": True})


@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    capture.stop()
    logger.flush()
    with state_lock:
        state["running"] = False
    return jsonify({"ok": True})


@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "GET":
        return jsonify(config.to_dict())
    payload = request.get_json(force=True)
    config.update(payload)
    return jsonify({"ok": True, "config": config.to_dict()})


@app.route("/api/logs/packets")
def logs_packets():
    severity_only = request.args.get("threats_only") == "true"
    where = []
    params = []
    if request.args.get("protocol"):
        where.append("protocol = ?")
        params.append(request.args["protocol"])
    if request.args.get("direction"):
        where.append("direction = ?")
        params.append(request.args["direction"])
    if request.args.get("src_ip"):
        where.append("src_ip = ?")
        params.append(request.args["src_ip"])
    if severity_only:
        where.append("status != 'normal'")
    return jsonify(logger.query("packets", " AND ".join(where) if where else None, params, limit=int(request.args.get("limit", 50)), offset=int(request.args.get("offset", 0))))


@app.route("/api/logs/alerts")
def logs_alerts():
    where = []
    params = []
    if request.args.get("severity"):
        where.append("severity = ?")
        params.append(request.args["severity"])
    if request.args.get("threat_type"):
        where.append("threat_type = ?")
        params.append(request.args["threat_type"])
    if request.args.get("src_ip"):
        where.append("src_ip = ?")
        params.append(request.args["src_ip"])
    return jsonify(logger.query("alerts", " AND ".join(where) if where else None, params, limit=int(request.args.get("limit", 50)), offset=int(request.args.get("offset", 0))))


@app.route("/api/export", methods=["POST"])
def export_logs():
    payload = request.get_json(force=True)
    fmt = payload.get("format", "json")
    mode = payload.get("mode", "full")
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    ext = "txt" if fmt == "pcap" else fmt
    file_path = os.path.join(EXPORT_DIR, f"nids_{mode}_{timestamp}.{ext}")
    packets = logger.query("packets", limit=100000, offset=0) if mode in ("packets", "full") else []
    alerts = logger.query("alerts", limit=100000, offset=0) if mode in ("alerts", "full") else []
    summary = {
        "session_start": state["session_start"].isoformat() + "Z" if state["session_start"] else None,
        "interface": state["interface"],
        "total_packets": state["packet_count"],
        "total_alerts": state["threat_count"],
    }
    logger.export(packets, alerts, "txt" if fmt == "pcap" else fmt, file_path, summary)
    return jsonify({"ok": True, "file": file_path})


@app.route("/api/state")
def session_state():
    return jsonify(state)


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    dist = app.static_folder
    target = os.path.join(dist, path)
    if path and os.path.exists(target):
        return send_from_directory(dist, path)
    return send_from_directory(dist, "index.html")


if __name__ == "__main__":
    threading.Thread(target=process_loop, daemon=True).start()
    threading.Thread(target=stats_loop, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5000)