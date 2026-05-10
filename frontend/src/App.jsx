import { useEffect, useMemo, useState } from "react";
import Header from "./components/Header";
import StatsCards from "./components/StatsCards";
import PacketGraph from "./components/PacketGraph";
import PacketTable from "./components/PacketTable";
import AlertsFeed from "./components/AlertsFeed";
import LogViewer from "./components/LogViewer";
import SettingsModal from "./components/SettingsModal";
import useSocket from "./hooks/useSocket";

const API = "http://localhost:5000";

function secToHMS(sec) {
  const h = String(Math.floor(sec / 3600)).padStart(2, "0");
  const m = String(Math.floor((sec % 3600) / 60)).padStart(2, "0");
  const s = String(sec % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

export default function App() {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [running, setRunning] = useState(false);
  const [stats, setStats] = useState({});
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [graph, setGraph] = useState([]);
  const [filters, setFilters] = useState({});
  const [settingsOpen, setSettingsOpen] = useState(false);

  useEffect(() => {
    fetch(`${API}/api/interfaces`).then((r) => r.json()).then((d) => {
      setInterfaces(d.interfaces || []);
      setSelectedInterface((d.interfaces || [])[0] || "");
    });
    fetch(`${API}/api/state`).then((r) => r.json()).then((s) => setRunning(Boolean(s.running)));
  }, []);

  const handlers = useMemo(() => ({
    packet: (p) => setPackets((prev) => [...prev.slice(-199), p]),
    alert: (a) => setAlerts((prev) => [a, ...prev.slice(0, 199)]),
    stats: (s) => {
      setStats(s);
      setGraph((prev) => [...prev.slice(-299), { time: new Date(s.timestamp).toLocaleTimeString(), inbound: s.inbound_per_sec || 0, outbound: s.outbound_per_sec || 0, total: s.packets_per_sec || 0 }]);
    }
  }), []);
  useSocket(API, handlers);

  const onStartStop = async () => {
    if (!running) {
      await fetch(`${API}/api/capture/start`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ interface: selectedInterface }) });
      setRunning(true);
    } else {
      await fetch(`${API}/api/capture/stop`, { method: "POST" });
      setRunning(false);
    }
  };

  return (
    <div className="app">
      <Header
        interfaces={interfaces}
        selectedInterface={selectedInterface}
        setSelectedInterface={setSelectedInterface}
        running={running}
        onStartStop={onStartStop}
        timer={secToHMS(stats.session_seconds || 0)}
        stats={stats}
        unreadAlerts={stats.unread_alerts || 0}
        onOpenSettings={() => setSettingsOpen(true)}
      />
      <main className="layout">
        <section className="p1"><StatsCards stats={stats} /></section>
        <section className="p2"><PacketGraph points={graph} alerts={alerts} /></section>
        <section className="p3"><PacketTable packets={packets} filters={filters} setFilters={setFilters} /></section>
        <section className="p4"><AlertsFeed alerts={alerts} onViewPackets={(ip) => setFilters((f) => ({ ...f, src_ip: ip }))} /></section>
        <section className="p5"><LogViewer /></section>
      </main>
      <SettingsModal open={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </div>
  );
}