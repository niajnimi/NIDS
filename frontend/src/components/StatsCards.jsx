const CARD_KEYS = [
  ["Total Packets Captured", "packets_total"],
  ["Packets/sec", "packets_per_sec"],
  ["Inbound Packets", "inbound"],
  ["Outbound Packets", "outbound"],
  ["Active Alerts", "active_threats"],
  ["Threats Detected", "threats_total"]
];

export default function StatsCards({ stats }) {
  return (
    <div className="stats-pane">
      <div className="cards-grid">
        {CARD_KEYS.map(([label, key]) => (
          <div className="card" key={key}>
            <div className="label">{label}</div>
            <div className="value">{stats[key] || 0}</div>
          </div>
        ))}
      </div>
      <div className="top-sources">
        <h4>Top 5 Source IPs</h4>
        {(stats.top_sources || []).map(([ip, count]) => (
          <div key={ip} className="source-row">
            <span>{ip}</span>
            <span>{count}</span>
            <div className="spark"><div style={{ width: `${Math.min(100, count / 5)}%` }} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}