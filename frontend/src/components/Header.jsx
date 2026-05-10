import { Bell, Play, Square, Shield, Settings } from "lucide-react";

export default function Header({
  interfaces,
  selectedInterface,
  setSelectedInterface,
  running,
  onStartStop,
  timer,
  stats,
  unreadAlerts,
  onOpenSettings
}) {
  return (
    <header className="header">
      <div className="brand"><Shield size={18} /> NIDS - Network Intrusion Detection System</div>
      <select value={selectedInterface} onChange={(e) => setSelectedInterface(e.target.value)}>
        {interfaces.map((iface) => <option key={iface}>{iface}</option>)}
      </select>
      <button className={running ? "btn stop" : "btn start"} onClick={onStartStop}>
        {running ? <Square size={16} /> : <Play size={16} />} {running ? "STOP CAPTURE" : "START CAPTURE"}
      </button>
      <div className="status">{running ? "RUNNING" : "STOPPED"} {timer}</div>
      <div className="status">CPU {Math.round(stats.cpu_percent || 0)}% | MEM {Math.round(stats.memory_percent || 0)}%</div>
      <button className="icon-btn" onClick={onOpenSettings}><Settings size={16} /></button>
      <div className="bell"><Bell size={16} /><span>{unreadAlerts}</span></div>
    </header>
  );
}