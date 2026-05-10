import { useEffect, useState } from "react";

const API = "http://localhost:5000";

export default function LogViewer() {
  const [tab, setTab] = useState("packets");
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadData = async () => {
    try {
      setLoading(true);
      setError("");

      const [packetsRes, alertsRes] = await Promise.all([
        fetch(`${API}/api/logs/packets?limit=50`),
        fetch(`${API}/api/logs/alerts?limit=50`)
      ]);

      if (!packetsRes.ok || !alertsRes.ok) {
        throw new Error("Failed to fetch logs from backend.");
      }

      const packetsData = await packetsRes.json();
      const alertsData = await alertsRes.json();

      setPackets(Array.isArray(packetsData) ? packetsData : []);
      setAlerts(Array.isArray(alertsData) ? alertsData : []);
    } catch (e) {
      setError(e.message || "Unexpected error while loading logs.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const doExport = async (mode, format) => {
    try {
      setError("");
      const resp = await fetch(`${API}/api/export`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, format })
      });

      if (!resp.ok) {
        throw new Error("Export request failed.");
      }

      const out = await resp.json();
      alert(`Exported: ${out.file}`);
    } catch (e) {
      setError(e.message || "Export failed.");
    }
  };

  return (
    <section className="logs-pane">
      <div className="tabs">
        <button onClick={() => setTab("packets")}>Packet Logs</button>
        <button onClick={() => setTab("alerts")}>Alert Logs</button>
        <button onClick={() => setTab("export")}>Export</button>
        <button onClick={loadData}>Refresh</button>
      </div>

      {loading && <div>Loading logs...</div>}
      {error && <div style={{ color: "#ff6b6b" }}>{error}</div>}

      {!loading && tab === "packets" && (
        <div className="simple-table">
          {packets.length === 0 ? (
            <div>No packet logs yet.</div>
          ) : (
            packets.map((p) => (
              <div key={p.id}>
                {p.timestamp} | {p.src_ip}:{p.src_port ?? "-"} {"->"} {p.dst_ip}:{p.dst_port ?? "-"} | {p.protocol} | {p.packet_size} bytes | {p.direction} | {p.status}
              </div>
            ))
          )}
        </div>
      )}

      {!loading && tab === "alerts" && (
        <div className="simple-table">
          {alerts.length === 0 ? (
            <div>No alert logs yet.</div>
          ) : (
            alerts.map((a) => (
              <div key={a.id || a.alert_id}>
                {a.timestamp} | {a.severity} | {a.threat_type} | {a.src_ip} | {a.detail || a.detail_message} | score: {a.risk_score}
              </div>
            ))
          )}
        </div>
      )}

      {tab === "export" && (
        <div className="export">
          <button onClick={() => doExport("packets", "csv")}>Export Packet Capture (CSV)</button>
          <button onClick={() => doExport("packets", "json")}>Export Packet Capture (JSON)</button>
          <button onClick={() => doExport("alerts", "csv")}>Export Alert Log (CSV)</button>
          <button onClick={() => doExport("alerts", "json")}>Export Alert Log (JSON)</button>
          <button onClick={() => doExport("full", "pcap")}>Save Full Session Log</button>
        </div>
      )}
    </section>
  );
}